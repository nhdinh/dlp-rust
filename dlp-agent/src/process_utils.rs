//! Shared Windows process utility helpers.
//!
//! Provides synchronous wrappers around process-querying Win32 APIs that are
//! needed by multiple subsystems (e.g. service sweeps and the bypass correlator).
//! All helpers are `pub(crate)` and compile to no-ops on non-Windows targets so
//! cross-platform `cargo check` continues to work.

/// Returns the raw 64-bit FILETIME creation time for `pid`, or `None` if the
/// process cannot be opened or queried.
///
/// The returned value is the same raw FILETIME used by the hook DLL's
/// `PollControl` frame and by [`ProcessKey`], so matching registry keys to
/// injected processes is PID-reuse safe.
#[cfg(windows)]
pub(crate) fn get_process_creation_time(pid: u32) -> Option<u64> {
    use windows::Win32::Foundation::{CloseHandle, FILETIME};
    use windows::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    // SAFETY: Win32 handle API. `OpenProcess` returns a handle that must be
    // closed with `CloseHandle`. `GetProcessTimes` only reads into the provided
    // stack buffers.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();

        let result =
            GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user).is_ok();
        let _ = CloseHandle(handle);

        if result {
            Some(((creation.dwHighDateTime as u64) << 32) | (creation.dwLowDateTime as u64))
        } else {
            None
        }
    }
}

/// Non-Windows stub: process creation time is unavailable.
#[cfg(not(windows))]
pub(crate) fn get_process_creation_time(_pid: u32) -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The current process can always be queried.
    #[test]
    #[cfg(windows)]
    fn get_process_creation_time_returns_some_for_current_process() {
        let creation_time = get_process_creation_time(std::process::id());
        assert!(
            creation_time.is_some(),
            "current process creation time should be queryable"
        );
        assert!(creation_time.unwrap() > 0, "creation time should be non-zero");
    }

    /// Invalid PIDs yield `None` rather than panicking.
    #[test]
    fn get_process_creation_time_returns_none_for_invalid_pid() {
        // PID 0 is the System Idle Process; on Windows it cannot be opened with
        // PROCESS_QUERY_LIMITED_INFORMATION from user mode.
        assert!(get_process_creation_time(0).is_none());
    }
}
