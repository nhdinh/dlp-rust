//! Multi-session UI spawner (T-30).
//!
//! Enumerates active Windows sessions on startup via `WTSEnumerateSessionsW` and
//! spawns a DLP UI process in each session using `CreateProcessAsUser`.
//! It also registers for session change notifications so new sessions get a UI
//! automatically.
//!
//! ## UI Process
//!
//! The UI is launched from `dlp-agent/src-tauri/` (Tauri 2.x). In development
//! builds the spawner launches the Tauri dev server; in production it launches
//! the installed UI binary.

use std::collections::HashMap;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use parking_lot::Mutex;
use tracing::{debug, info, warn};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security {
    DuplicateTokenEx, SecurityImpersonation, SECURITY_IMPERSONATION_LEVEL, TOKEN_ALL_ACCESS,
    TOKEN_DUPLICATE, TOKEN_QUERY,
};
use windows::Win32::System::RemoteDesktop::{
    WTSActive, WTSEnumerateSessionsW, WTSFreeMemory, WTSQueryUserToken, WTS_CURRENT_SERVER_HANDLE,
    WTS_SESSION_INFOW,
};
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW,
};

/// Wrapper that makes `HANDLE` `Send + Sync` for storage in statics.
///
/// `windows::HANDLE` is `*mut c_void` which is not `Send` by default.
/// This wrapper does NOT provide safety guarantees about the handle —
/// it is only safe because we never send the handle value between threads;
/// the mutex ensures all access is single-threaded.
struct SendableHandle(HANDLE);

impl SendableHandle {
    fn new(h: HANDLE) -> Self {
        Self(h)
    }
    fn as_handle(&self) -> HANDLE {
        self.0
    }
}

unsafe impl Send for SendableHandle {}
unsafe impl Sync for SendableHandle {}

/// Handle to a UI process running in a specific session.
pub(crate) struct UiHandle {
    /// Win32 process ID.
    pub(crate) pid: u32,
    /// Session ID the process belongs to.
    #[allow(dead_code)]
    session_id: u32,
    /// Process handle wrapped as `SendableHandle` so the static map is `Sync`.
    handle: SendableHandle,
}

/// Stores handles to all active UI processes, keyed by session ID.
static UI_HANDLES: once_cell::sync::Lazy<Mutex<HashMap<u32, UiHandle>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(HashMap::new()));

/// Path to the UI binary.
///
/// In development: `cargo run -p dlp-agent-ui` or the Tauri dev URL.
/// In production: the installed UI binary path.
static UI_BINARY: once_cell::sync::Lazy<Mutex<Option<PathBuf>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(None));

/// Returns the UI binary path, if configured.
pub fn ui_binary() -> Option<PathBuf> {
    UI_BINARY.lock().clone()
}

/// Sets the UI binary path (called from `main.rs` or service startup).
pub fn set_ui_binary(path: PathBuf) {
    *UI_BINARY.lock() = Some(path);
}

/// Initialises the UI spawner.
///
/// Enumerates all active sessions and spawns a UI in each.
/// This is called once during service startup.
pub fn init() -> Result<()> {
    let binary = UI_BINARY
        .lock()
        .clone()
        .context("UI binary not configured")?;
    info!(path = %binary.display(), "initialising UI spawner");

    let session_ids = enumerate_active_sessions()?;
    info!(count = session_ids.len(), "enumerated active sessions");

    for session_id in &session_ids {
        match spawn_ui_in_session(*session_id, &binary) {
            Ok(handle) => {
                UI_HANDLES.lock().insert(*session_id, handle);
            }
            Err(e) => {
                warn!(session_id, error = %e, "failed to spawn UI in session");
            }
        }
    }

    Ok(())
}

/// Enumerates all active Windows sessions via `WTSEnumerateSessionsW`.
fn enumerate_active_sessions() -> Result<Vec<u32>> {
    unsafe {
        let mut session_info: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
        let mut session_count: u32 = 0;

        let result = WTSEnumerateSessionsW(
            WTS_CURRENT_SERVER_HANDLE,
            0,
            1,
            &mut session_info,
            &mut session_count,
        );

        if result.is_err() {
            return Err(anyhow::anyhow!("WTSEnumerateSessionsW failed"));
        }

        if session_info.is_null() {
            return Ok(vec![]);
        }

        let mut ids = Vec::with_capacity(session_count as usize);
        let session_slice = std::slice::from_raw_parts(session_info, session_count as usize);

        for si in session_slice {
            // WTS_SESSION_INFOW.State is WTS_CONNECTSTATE_CLASS; compare against
            // the WTSActive constant which is also WTS_CONNECTSTATE_CLASS(0).
            if si.State == WTSActive {
                ids.push(si.SessionId);
            }
        }

        // Free the allocated array — WTSFreeMemory takes *mut c_void.
        WTSFreeMemory(session_info.cast());

        Ok(ids)
    }
}

/// Spawns a UI process in the given session using `CreateProcessAsUserW`.
pub(crate) fn spawn_ui_in_session(session_id: u32, binary: &Path) -> Result<UiHandle> {
    info!(session_id, path = %binary.display(), "spawning UI process");

    // Get the user token for the session.
    let user_token = get_session_user_token(session_id)?;

    // Build the command line.
    let binary_wide: Vec<u16> = binary
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // Build a null-terminated "WinSta0\\Default" desktop name.
    let desktop_wide: Vec<u16> = "WinSta0\\Default\0".encode_utf16().collect();

    let startup_info = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        lpDesktop: windows::core::PWSTR::from_raw(desktop_wide.as_ptr() as _),
        ..Default::default()
    };

    let mut process_info = PROCESS_INFORMATION::default();

    unsafe {
        let create_result = CreateProcessAsUserW(
            user_token,
            PCWSTR::null(),
            windows::core::PWSTR::from_raw(binary_wide.as_ptr() as _),
            None,
            None,
            false,
            PROCESS_CREATION_FLAGS(0),
            None,
            PCWSTR::null(),
            &startup_info,
            &mut process_info,
        );

        let _ = CloseHandle(user_token);

        if create_result.is_err() {
            return Err(anyhow::anyhow!(
                "CreateProcessAsUserW failed for session {}",
                session_id
            ));
        }

        // Close the main thread handle — we only care about the process.
        let _ = CloseHandle(process_info.hThread);

        info!(
            session_id,
            pid = process_info.dwProcessId,
            "UI process spawned"
        );

        Ok(UiHandle {
            pid: process_info.dwProcessId,
            session_id,
            handle: SendableHandle::new(process_info.hProcess),
        })
    }
}

/// Gets a primary impersonation token for the given session's active user.
///
/// Calls `WTSQueryUserToken` to obtain the user's logon token for the session,
/// then `DuplicateTokenEx` with `SecurityImpersonation` level so that
/// `CreateProcessAsUserW` can use it.
fn get_session_user_token(session_id: u32) -> Result<HANDLE> {
    // Step 1: query the user token for this session.
    // WTSQueryUserToken returns the primary token of the logged-on user.
    let mut raw_token = HANDLE::default();

    // SAFETY: WTSQueryUserToken writes exactly one HANDLE to raw_token and
    // returns NTSTATUS-style success/failure.  session_id is a valid u32
    // previously obtained from WTSEnumerateSessionsW.
    let ok = unsafe {
        WTSQueryUserToken(session_id, &mut raw_token).ok()
    };

    if !ok {
        return Err(anyhow::anyhow!(
            "WTSQueryUserToken failed for session {}",
            session_id
        ));
    }

    // Step 2: duplicate the token with impersonation level so CreateProcessAsUserW
    // can use it.  We request the default set of access rights; DuplicateTokenEx
    // applies sensible filtering.
    let mut impersonation_token = HANDLE::default();

    // SAFETY: raw_token is a valid open handle obtained just above.
    // SecurityImpersonation is a valid SECURITY_IMPERSONATION_LEVEL value.
    // The resulting impersonation_token is a new handle we own and must close.
    let dup_ok = unsafe {
        DuplicateTokenEx(
            raw_token,
            TOKEN_ALL_ACCESS.0,
            None,
            SecurityImpersonation,
            windows::Win32::System::Threading::TokenPrimary,
            &mut impersonation_token,
        )
        .ok()
    };

    // Always close the original token obtained from WTSQueryUserToken.
    // SAFETY: raw_token is a valid handle we received from WTSQueryUserToken.
    let _ = unsafe { CloseHandle(raw_token) };

    if !dup_ok {
        return Err(anyhow::anyhow!(
            "DuplicateTokenEx failed for session {}",
            session_id
        ));
    }

    debug!(session_id, "user token obtained and duplicated");
    Ok(impersonation_token)
}

/// Terminates a UI process by session ID.
pub fn kill_session(session_id: u32) {
    if let Some(handle) = UI_HANDLES.lock().remove(&session_id) {
        unsafe {
            let _ =
                windows::Win32::System::Threading::TerminateProcess(handle.handle.as_handle(), 1);
            let _ = CloseHandle(handle.handle.as_handle());
        }
        debug!(session_id, pid = handle.pid, "UI process terminated");
    }
}

/// Terminates all UI processes.
pub fn kill_all() {
    for (session_id, handle) in UI_HANDLES.lock().drain() {
        unsafe {
            let _ =
                windows::Win32::System::Threading::TerminateProcess(handle.handle.as_handle(), 1);
            let _ = CloseHandle(handle.handle.as_handle());
        }
        debug!(session_id, pid = handle.pid, "UI process terminated");
    }
}
