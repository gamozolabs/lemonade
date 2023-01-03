mod ptrace;

use std::ffi::CString;
use std::mem::MaybeUninit;
use std::collections::BTreeMap;
use ptrace::{Pid, Ptrace, Status, ptrace};

/// Wrapper around [`Error`]
type Result<T> = std::result::Result<T, Error>;

/// Errors for the [`Debugger`]
#[derive(Debug)]
enum Error {
    /// Failed to convert program name to a C string
    ConvertProgram(std::ffi::NulError),

    /// Failed to convert program argument to a C string
    ConvertArg(std::ffi::NulError),

    /// `waitid()` returned an error
    WaitId(std::io::Error),

    /// `waitpid()` returned an error
    WaitPid(std::io::Error),

    /// Failed to set ptrace options on a tracee
    SetOptions(std::io::Error),

    /// Failed to continue execution of a tracee
    Continue(std::io::Error),

    /// Failed to query the PID of the newly forked process
    GetNewPid(std::io::Error),
}

/// Debugger of a group of tracees
///
/// Debuggers maintain the state of the tracees in their group. It is possible
/// to have multiple [`Debugger`]s in a single process, allowing separated
/// sets of tracees to be debugged.
///
/// A debugger doesn't particularly manage a group of threads identical to a
/// process group or a thread group, instead it's an arbitrary collection of
/// tracees that the user specifies.
///
/// A [`Debugger`] will only consume events from its set of tracees. It also
/// will not manage tracees unless they are known about ahead of time. For
/// example, if a `waitpid()` returns a PID that we are not aware of, the tool
/// will throw an error, rather than silently adding it to the pool of tracees.
///
/// To make this all work requires that we have a coherent state machine of
/// processes we expect to be showing up. This is a hard problem with
/// `ptrace()` but if we can solve it, hopefully the debugger will be
/// significantly more reliable than GDB and LLDB which are a bit more
/// handwavey about unexpected states.
///
/// ```
/// +---------------------------------------------------------+
/// | Your debugger process                                   |
/// |                                                         |
/// | +------------------+ +------------------+ +-----------+ |
/// | | Debugger         | | Debugger         | | ...       | |
/// | |                  | |                  | |           | |
/// | | +--------------+ | | +--------------+ | |           | |
/// | | | Tracee       | | | | Tracee       | | |           | |
/// | | |              | | | |              | | |           | |
/// | | +--------------+ | | +--------------+ | |           | |
/// | | +--------------+ | | +--------------+ | |           | |
/// | | | Tracee       | | | | ...          | | |           | |
/// | | |              | | | |              | | |           | |
/// | | +--------------+ | | +--------------+ | |           | |
/// | | +--------------+ | |                  | |           | |
/// | | | ...          | | |                  | |           | |
/// | | |              | | |                  | |           | |
/// | | +--------------+ | |                  | |           | |
/// | +------------------+ +------------------+ +-----------+ |
/// +---------------------------------------------------------+
/// ```
struct Debugger {
    /// States of the tracees under the debugger
    tracees: BTreeMap<Pid, TraceeState>,
}

impl Debugger {
    /// Create a new debugger debugging a newly launched process
    pub fn spawn<T: AsRef<[u8]>>(
            proc: impl Into<Vec<u8>>, args: impl AsRef<[T]>) -> Result<Self> {
        // Convert the program name into a C string
        let proc = CString::new(proc).map_err(Error::ConvertProgram)?;

        // Convert arguments into C strings
        let mut c_args = Vec::new();
        for arg in args.as_ref() {
            c_args.push(CString::new(arg.as_ref().to_vec())
                .map_err(Error::ConvertArg)?);
        }

        // Create a thread to `exec()` in
        let pid = unsafe { libc::fork() };

        if pid == 0 {
            // Child

            // Convert arguments into array
            let mut raw_args = Vec::new();

            // Push program name (argv[0])
            let proc = proc.into_raw();
            raw_args.push(proc as *const _);

            // Push arguments
            for arg in c_args.into_iter() {
                raw_args.push(arg.into_raw() as *const _);
            }

            // Null terminate the argument array
            raw_args.push(std::ptr::null());

            // Request to be debugged
            ptrace(Ptrace::TraceMe).expect("Failed to request to be traced");

            // Stop fully before we exec, giving the parent an opportunity
            // to introspect
            if unsafe { libc::raise(libc::SIGSTOP) } != 0 {
                panic!("Failed to raise(SIGSTOP) at process start: {:?}",
                    std::io::Error::last_os_error());
            }

            // Execute the program!
            let ret = unsafe {
                libc::execvp(proc, raw_args.as_ptr())
            };

            // Make sure `exec()` worked
            if ret == -1 {
                panic!("Failed to execute child program: {:?}",
                    std::io::Error::last_os_error());
            } else {
                unreachable!("Exec returned!?");
            }
        }

        // Wrap up the child's PID
        let child = Pid(pid);

        // Register the child in the database
        let mut tracees = BTreeMap::new();
        tracees.insert(child, TraceeState::WaitForInitialStop);

        Ok(Self {
            tracees,
        })
    }

    /// Wait for events
    pub fn event_loop(&mut self) -> Result<()> {
        // Loop while we have something to debug
        'next_event: while !self.tracees.is_empty() {
            // First, block until any child has signaled
            //
            // We pass in `WNOWAIT` which causes `waitid()` to behave like
            // a peek, thus this will not consume the event yet. This just lets
            // us block on all children and use no CPU.
            let mut siginfo = MaybeUninit::<libc::siginfo_t>::uninit();
            let ret = unsafe {
                libc::waitid(libc::P_ALL, 0,
                    siginfo.as_mut_ptr(),
                    libc::WEXITED    |
                    libc::WSTOPPED   |
                    libc::WCONTINUED |
                    libc::WNOWAIT)
            };

            // Make sure `waitid()` was successful
            if ret == -1 {
                return Err(Error::WaitId(std::io::Error::last_os_error()));
            }

            // Get the PID that caused `waitid()` to return
            let pid = Pid(unsafe { (*siginfo.as_ptr()).si_pid() });

            // We use `waitid()` to filter the amount of time we spend polling
            // for events. It is possible that `waitid()` returned a PID that
            // is under our management, and thus we can directly consume the
            // event from that PID and continue.
            let (pid, state, event) = if let Some(state) =
                    self.tracees.get_mut(&pid) {
                // Already tracing this PID, handle it right away!
                (pid, state, ptrace::waitpid(pid).map_err(Error::WaitPid)?
                    .expect("Whoa, waitpid() didn't have an event for a \
                             waitid() signalled PID?"))
            } else {
                // It is possible that this PID is not under our management,
                // so now we have to check if any of our tracees have an
                // event for us. We are no longer going to receieve signal from
                // the `waitid()` as that may infinitely give us the same PID.
                // However, the PID that it is reporting could be a child from
                // a `fork()` event from one of our debuggees, and to get that
                // `fork()` event we have to "look ahead" in the signal queue
                // by non-blocking checking for signals from all of our
                // tracees.
                //
                // This is designed for the very real case as such:
                //
                // signal_queue = [
                //    STOP event from new child,
                //    TRAP event from tracee telling us it forked the child,
                // ]
                //
                // If we do not do this look ahead, the debugger will just
                // infinitely loop on `waitid()` and never observe a PID
                // under our control.
                //
                // It is also possible that we got a spurious `waitid()`
                // indicating the PID of _another_ [`Debugger`] instance had
                // an event. In this case, none of our tracees will have a
                // signal, and we'll just go back to `waitid()` without doing
                // anything. There's non-zero overhead to this, but I don't
                // think there is any other way to implement this without pidfd
                // which we are not using as it is too modern of a feature for
                // the targets we want to support.

                // Go through all known tracees looking for events
                let mut result = None;
                for (&pid, state) in self.tracees.iter_mut() {
                    // Check for an event
                    if let Some(event) =
                            ptrace::waitpid(pid).map_err(Error::WaitPid)? {
                        result = Some((pid, state, event));
                        break;
                    }
                }

                // If we got any event, pass it out
                if let Some(result) = result {
                    result
                } else {
                    // Nothing to do, go back to `waitid()`
                    continue 'next_event;
                }
            };

            // Check for detailed status information on specific trap events
            let trap_reason = if let
                    Status::Stopped { signal: libc::SIGTRAP, status } = event {
                if (status >> 16) == libc::PTRACE_EVENT_CLONE {
                    // Get the PID of the new process
                    let mut new_pid = 0;
                    ptrace(Ptrace::GetEventMsg { pid, message: &mut new_pid })
                        .map_err(Error::GetNewPid)?;
                    Some(TrapReason::Clone(Pid(new_pid as _)))
                } else if (status >> 16) == libc::PTRACE_EVENT_EXEC {
                    Some(TrapReason::Exec)
                } else if (status >> 16) == libc::PTRACE_EVENT_EXIT {
                    Some(TrapReason::Exit)
                } else if (status >> 16) == libc::PTRACE_EVENT_FORK {
                    // Get the PID of the new process
                    let mut new_pid = 0;
                    ptrace(Ptrace::GetEventMsg { pid, message: &mut new_pid })
                        .map_err(Error::GetNewPid)?;
                    Some(TrapReason::Fork(Pid(new_pid as _)))
                } else if (status >> 16) == libc::PTRACE_EVENT_VFORK {
                    // Get the PID of the new process
                    let mut new_pid = 0;
                    ptrace(Ptrace::GetEventMsg { pid, message: &mut new_pid })
                        .map_err(Error::GetNewPid)?;
                    Some(TrapReason::VFork(Pid(new_pid as _)))
                } else {
                    None
                }
            } else {
                None
            };

            /*
            println!("PID {:5} | State {state:?} | Event {event:?} | {trap_reason:?}",
                pid.0);*/

            match state {
                TraceeState::WaitForInitialStop => {
                    // Make sure we got the stop that we expected
                    assert!(matches!(event,
                        Status::Stopped { signal: libc::SIGSTOP, .. }),
                        "Whoa, expected initial stop, got different code");

                    // This is the first time a new child has checked in. Lets
                    // set the ptrace options we want on it, and let it
                    // continue!
                    ptrace(Ptrace::SetOptions {
                        pid,
                        options: libc::PTRACE_O_TRACECLONE |
                                 libc::PTRACE_O_TRACEEXEC  |
                                 libc::PTRACE_O_TRACEEXIT  |
                                 libc::PTRACE_O_TRACEFORK  |
                                 libc::PTRACE_O_TRACEVFORK,
                    }).map_err(Error::SetOptions)?;

                    // Resume execution of the tracee, discarding the inital
                    // stop signal
                    ptrace(Ptrace::Continue { pid, signal: 0 })
                        .map_err(Error::Continue)?;

                    // Update that the tracee is now running
                    *state = TraceeState::Running;
                }
                TraceeState::Running => {
                    // Determine why we stopped
                    match event {
                        Status::Exited { .. } => {
                            // Process terminated normally
                            self.tracees.remove(&pid);
                        }
                        Status::Signaled { .. } => {
                            // Processed terminated by a signal
                            self.tracees.remove(&pid);
                        }
                        Status::Stopped { signal, .. } => {
                            match trap_reason {
                                Some(TrapReason::Clone(new_pid) |
                                     TrapReason::Fork(new_pid)  |
                                     TrapReason::VFork(new_pid)) => {
                                    // Okay, the tracee spawned a new PID which
                                    // has automatically been attached to.
                                    // Register it in our database
                                    self.tracees.insert(new_pid,
                                        TraceeState::WaitForInitialStop);

                                    // Resume execution, discard the trap
                                    ptrace(Ptrace::Continue { pid, signal: 0 })
                                        .map_err(Error::Continue)?;
                                }
                                Some(TrapReason::Exec | TrapReason::Exit) => {
                                    // Resume execution, discard the trap
                                    ptrace(Ptrace::Continue { pid, signal: 0 })
                                        .map_err(Error::Continue)?;
                                }
                                None => {
                                    // Unknown signal, pass it through
                                    ptrace(Ptrace::Continue { pid, signal })
                                        .map_err(Error::Continue)?;
                                }
                            }
                        }
                        Status::Continued => {
                            // Should never happen
                            unreachable!();
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

/// Different detailed reasons why we got a SIGTRAP from a tracee when it was
/// explicitly requested via a ptrace option
#[derive(Debug)]
enum TrapReason {
    /// Process invoked `clone()`
    Clone(Pid),

    /// Process invoked `execve()`
    Exec,

    /// Process invoked `exit()`
    Exit,

    /// Process invoked `fork()`
    Fork(Pid),

    /// Process invoked `vfork()`
    VFork(Pid),
}

/// States of a tracee
#[derive(Debug)]
enum TraceeState {
    /// We spawned a new program and we're waiting for the debugger to check
    /// in with an initial stop before it invokes `exec()`
    ///
    /// Also used when a tracee forked and we are waiting for the new PID to
    /// check in which will automatically be stopped.
    WaitForInitialStop,

    /// Tracee is running normally
    Running,
}

fn main() -> Result<()> {
    let mut debugger = Debugger::spawn("/bin/echo", &["Hello [B]orld"])?;
    debugger.event_loop()?;

    Ok(())
}

