//! Pipe 3 client — connects to `\\.\pipe\DLPEventUI2Agent` (T-42).
//!
//! Sends UI-to-agent events: `UiReady`.

use anyhow::Result;
use tracing::info;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_NO_BUFFERING, FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows::Win32::Storage::FileSystem::{OPEN_EXISTING, PIPE_ACCESS_OUTBOUND};

use super::frame::{flush, write_frame};
use super::messages::Pipe3UiMsg;

/// The default Win32 pipe name.
///
/// Tests may override this via the `DLP_PIPE3_NAME` environment variable
/// so they can point Pipe 3 at a mock named-pipe server on a unique name.
const PIPE_NAME_DEFAULT: &str = r"\\.\pipe\DLPEventUI2Agent";

/// Resolves the Pipe 3 name, allowing tests to override via `DLP_PIPE3_NAME`.
///
/// In production this always returns [`PIPE_NAME_DEFAULT`]. Integration
/// tests set `DLP_PIPE3_NAME` to a unique per-run name so they can spin
/// up a mock server without colliding with other tests or the real agent.
fn pipe_name() -> String {
    // Env var lookup is cheap (a single syscall) and only happens on the
    // short-lived connection open path — not inside any hot loop.
    std::env::var("DLP_PIPE3_NAME").unwrap_or_else(|_| PIPE_NAME_DEFAULT.to_string())
}

/// Opens a handle to Pipe 3.
fn open_pipe() -> Result<HANDLE> {
    let name = pipe_name();
    // Windows named-pipe paths are passed to Win32 as UTF-16 with a
    // trailing NUL terminator. Encode once here and keep the buffer
    // alive for the duration of the CreateFileW call.
    let name_wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

    let handle = unsafe {
        CreateFileW(
            PCWSTR::from_raw(name_wide.as_ptr()),
            PIPE_ACCESS_OUTBOUND.0,
            FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0),
            None,
            OPEN_EXISTING,
            FILE_FLAG_NO_BUFFERING,
            None,
        )
    };

    handle.map_err(|e| anyhow::anyhow!("CreateFileW on Pipe 3 failed: {}", e))
}

/// Connects to Pipe 3 and sends UiReady on the given session.
pub async fn send_ui_ready(session_id: u32) -> Result<()> {
    let handle = open_pipe()?;
    info!(session_id, "Pipe 3: connected, sending UiReady");

    let msg = Pipe3UiMsg::UiReady { session_id };
    let json = serde_json::to_vec(&msg).map_err(|e| anyhow::anyhow!("serialise UiReady: {}", e))?;
    write_frame(handle, &json)?;
    flush(handle)?;

    unsafe {
        let _ = CloseHandle(handle);
    }

    Ok(())
}

/// Sends a clipboard alert to the agent via Pipe 3.
///
/// Opens a new Pipe 3 connection for each alert (short-lived).
pub fn send_clipboard_alert(
    session_id: u32,
    classification: &str,
    preview: &str,
    text_length: usize,
) -> Result<()> {
    let handle = open_pipe()?;

    let msg = Pipe3UiMsg::ClipboardAlert {
        session_id,
        classification: classification.to_string(),
        preview: preview.to_string(),
        text_length,
        // Phase 25 will populate these; for now the UI sends None until the
        // source-resolver is wired up.
        source_application: None,
        destination_application: None,
    };
    let json =
        serde_json::to_vec(&msg).map_err(|e| anyhow::anyhow!("serialise ClipboardAlert: {}", e))?;
    write_frame(handle, &json)?;
    flush(handle)?;

    unsafe {
        let _ = CloseHandle(handle);
    }

    Ok(())
}
