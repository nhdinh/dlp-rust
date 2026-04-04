//! Pipe 3 client — connects to `\.\pipe\DLPEventUI2Agent` (T-42).
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

/// The Win32 pipe name.
const PIPE_NAME: &str = r"\.\pipe\DLPEventUI2Agent";

/// Opens a handle to Pipe 3.
fn open_pipe() -> Result<HANDLE> {
    let name_wide: Vec<u16> = PIPE_NAME.encode_utf16().chain(std::iter::once(0)).collect();

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
