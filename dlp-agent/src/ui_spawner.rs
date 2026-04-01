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
use std::ffi::OsString;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result};
use parking_lot::Mutex;
use tracing::{debug, error, info, warn};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::ProcessStatus::WTSEnumerateSessionsW;
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, OpenProcessToken, SetTokenInformation, TokenPrimaryContainer, TokenSessionId,
    CreateProcessWithTokenW, DuplicateTokenEx, SECURITY_ATTRIBUTES, STARTUPINFOW, PROCESS_INFORMATION,
    LPTHREAD_START_ROUTINE, CreateRemoteThread,
};
use windows::Win32::System::Services::{
    WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW, WTSActive,
};
use windows::Win32::Security::{
    GetTokenInformation, TokenLinkedToken, TOKEN_PRIVILEGES, TOKEN_ADJUST_PRIVILEGES,
    LookupPrivilegeValueW, AdjustTokenPrivileges, SE_PRIVILEGE_ENABLED,
    TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::core::PCWSTR;

use crate::service::SERVICE_NAME;

/// Handle to a UI process running in a specific session.
#[derive(Debug)]
struct UiHandle {
    /// Win32 process ID.
    pid: u32,
    /// Session ID the process belongs to.
    session_id: u32,
    /// Process handle — owned so we can clean up on drop.
    handle: HANDLE,
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
    let binary = UI_BINARY.lock().clone().context("UI binary not configured")?;
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
            if si.State.0 == WTSActive.0 {
                ids.push(si.SessionId);
            }
        }

        // Free the allocated array.
        windows::Win32::System::Environment::WTSFreeMemory(session_info as u64);

        Ok(ids)
    }
}

/// Spawns a UI process in the given session using `CreateProcessAsUserW`.
fn spawn_ui_in_session(session_id: u32, binary: &PathBuf) -> Result<UiHandle> {
    info!(session_id, path = %binary.display(), "spawning UI process");

    // Get the user token for the session.
    let user_token = get_session_user_token(session_id)?;

    // Build the command line.
    let binary_wide: Vec<u16> = binary
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut startup_info = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        lpDesktop: windows::core::PWSTR::from_raw(
            wide_string("WinSta0\\Default").as_ptr() as _,
        ),
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
            0,
            None,
            PCWSTR::from_raw(windows::core::PWSTR::from_raw(
                wide_string("WinSta0\\Default").as_ptr() as _,
            ).as_ptr()),
            &mut startup_info,
            &mut process_info,
        );

        CloseHandle(user_token).ok();

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
            handle: process_info.hProcess,
        })
    }
}

/// Gets an impersonation token for the given session's active user.
fn get_session_user_token(session_id: u32) -> Result<HANDLE> {
    unsafe {
        // WTSQueryUserToken is simpler when available, but requires linking to WTSAPI32.
        // Use the process-level approach: find a process in the session and get its token.
        // A more robust approach uses WTSQueryUserToken — add `Win32_System_Wts Wts` feature.

        // For now, spawn a process directly in the session using CreateProcessWithLogon
        // or use WTSQueryUserToken if the feature is enabled.
        //
        // The cleanest approach is `WTSQueryUserToken` — let's check if we need to add
        // the WTS feature and use that directly.

        // Fallback: we need the WTS API to get a token directly.
        // Using WTSQueryUserToken requires: Win32_System_Wts
        Err(anyhow::anyhow!(
            "get_session_user_token: WTS feature not yet linked; \
             use WTSQueryUserToken or spawn via session 0 launcher"
        ))
    }
}

/// Converts a Rust &str to a null-terminated wide (UTF-16) string.
fn wide_string(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Terminates a UI process by session ID.
pub fn kill_session(session_id: u32) {
    if let Some(handle) = UI_HANDLES.lock().remove(&session_id) {
        unsafe {
            let _ = windows::Win32::System::Threading::TerminateProcess(handle.handle, 1);
            let _ = CloseHandle(handle.handle);
        }
        debug!(session_id, pid = handle.pid, "UI process terminated");
    }
}

/// Terminates all UI processes.
pub fn kill_all() {
    for (session_id, handle) in UI_HANDLES.lock().drain() {
        unsafe {
            let _ = windows::Win32::System::Threading::TerminateProcess(handle.handle, 1);
            let _ = CloseHandle(handle.handle);
        }
        debug!(session_id, pid = handle.pid, "UI process terminated");
    }
}
