//! Safe wrappers around `ptrace()`

/// A Linux PID (we use the kernel description thus each thread is a PID)
#[derive(Clone, Copy, Debug, PartialOrd, Ord, PartialEq, Eq)]
pub(crate) struct Pid(pub(crate) libc::pid_t);

/// Ptrace operations
///
/// Not a complete set, implemented as needed
pub(crate) enum Ptrace<'a> {
    /// Indicate that we are to be traced by our parent
    TraceMe,

    /// Set options on a given PID
    SetOptions {
        /// PID to set options on
        pid: Pid,

        /// Options to set
        options: i32
    },

    /// Continue execution of a PID
    Continue {
        /// PID to continue
        pid: Pid,

        /// Signal to deliver to continue (0 means no signal)
        signal: i32,
    },

    /// Gets the event message from the most recent ptrace event
    GetEventMsg {
        /// PID to query event info from
        pid: Pid,

        /// Message event
        message: &'a mut usize,
    }
}

/// Safe wrapper around `ptrace()`
pub(crate) fn ptrace<'a>(request: Ptrace<'a>) -> std::io::Result<()> {
    let res = match request {
        Ptrace::TraceMe => {
            // Request to be traced by the parent
            unsafe {
                libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0)
            }
        }
        Ptrace::SetOptions { pid, options } => {
            unsafe {
                libc::ptrace(libc::PTRACE_SETOPTIONS, pid.0, 0, options)
            }
        }
        Ptrace::Continue { pid, signal } => {
            unsafe {
                libc::ptrace(libc::PTRACE_CONT, pid.0, 0, signal)
            }
        }
        Ptrace::GetEventMsg { pid, message } => {
            unsafe {
                libc::ptrace(libc::PTRACE_GETEVENTMSG, pid.0, 0, message)
            }
        }
    };

    // Check the result from `ptrace`
    if res != -1 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Status codes from `waitpid()`
#[derive(Debug)]
pub enum Status {
    /// Process terminated normally
    Exited {
        /// Least significant 8-bits of the argument to `exit()`
        status: i32,
    },

    /// Processed terminated by a signal
    Signaled {
        /// Signal that caused the process to terminate
        signal: i32,

        /// Set if the child produced a core dump
        dumped: bool,
    },

    /// Child stopped by delivery of a signal
    Stopped {
        /// Signal that caused the stop
        signal: i32,

        /// Raw status code from `waitpid()`
        status: i32,
    },

    /// Child resumed execution
    Continued,
}

/// Safe wrapper around non-blocking `waitpid()`
pub(crate) fn waitpid(pid: Pid) -> std::io::Result<Option<Status>> {
    // Check the status on `pid`, non-blocking
    let mut status = 0;
    let ret = unsafe {
        libc::waitpid(pid.0, &mut status, libc::WNOHANG | libc::WCONTINUED)
    };

    // Check return value
    if ret == 0 {
        // No status
        return Ok(None);
    } else if ret == -1 {
        // Error
        return Err(std::io::Error::last_os_error());
    }

    // Convert status into Rust status
    let status = if libc::WIFEXITED(status) {
        Status::Exited { status: libc::WEXITSTATUS(status) }
    } else if libc::WIFSIGNALED(status) {
        Status::Signaled {
            signal: libc::WTERMSIG(status),
            dumped: libc::WCOREDUMP(status),
        }
    } else if libc::WIFSTOPPED(status) {
        Status::Stopped { signal: libc::WSTOPSIG(status), status }
    } else if libc::WIFCONTINUED(status) {
        Status::Continued
    } else {
        unreachable!("Unknown waitpid() status");
    };

    Ok(Some(status))
}

