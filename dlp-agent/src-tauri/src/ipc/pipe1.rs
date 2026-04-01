//! Pipe 1 client — connects to `\\.\pipe\DLPCommand` (T-40).
//!
//! Sends `RegisterSession` immediately on connect, then handles incoming
//! agent messages: `BlockNotify`, `OverrideRequest`, `ClipboardRead`,
//! `PasswordDialog`.  Responds with `UserConfirmed`, `UserCancelled`,
//! `ClipboardData`, `PasswordSubmit`, `PasswordCancel`.

use anyhow::Result;
use tracing::{debug, error, info};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{CreateFileW, FILE_FLAG_NO_BUFFERING, FILE_SHARE_MODE};
use windows::Win32::Storage::FileSystem::{OPEN_EXISTING, PIPE_ACCESS_DUPLEX};

use super::frame::{read_frame, write_frame};
use super::messages::{Pipe1AgentMsg, Pipe1UiMsg};

/// The Win32 pipe name.
const PIPE_NAME: &str = r"\\.\pipe\DLPCommand";

/// `HANDLE` is `*mut c_void` — not `Send + Sync`.  Named-pipe handles are safe
/// to move between threads, so we re-expose them with the correct trait impls.
#[derive(Clone, Copy)]
struct SendableHandle(HANDLE);

unsafe impl Send for SendableHandle {}
unsafe impl Sync for SendableHandle {}

impl SendableHandle {
    fn into_inner(self) -> HANDLE {
        self.0
    }
}

/// Opens a handle to an existing Pipe 1 instance.
fn open_pipe() -> Result<HANDLE> {
    let name_wide: Vec<u16> = PIPE_NAME.encode_utf16().chain(std::iter::once(0)).collect();

    let handle = unsafe {
        CreateFileW(
            PCWSTR::from_raw(name_wide.as_ptr()),
            PIPE_ACCESS_DUPLEX.0,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_FLAG_NO_BUFFERING,
            None,
        )
    };

    handle.map_err(|e| anyhow::anyhow!("CreateFileW on Pipe 1 failed: {}", e))
}

/// Runs the Pipe 1 client for the given session.
///
/// Connects to Pipe 1, sends `RegisterSession`, then processes incoming
/// agent messages in a loop until the pipe is closed.
pub async fn connect_and_run(session_id: u32) -> Result<()> {
    let handle = open_pipe()?;
    info!(session_id, "Pipe 1: connected to agent");

    // Send RegisterSession immediately as the first frame.
    {
        let msg = Pipe1UiMsg::RegisterSession { session_id };
        let json = serde_json::to_vec(&msg)
            .map_err(|e| anyhow::anyhow!("serialise RegisterSession: {}", e))?;
        write_frame(handle, &json)?;
    }

    // Read loop — run on a Tokio background task so it doesn't block Tauri.
    let handle = SendableHandle(handle);
    let result = tokio::task::spawn_blocking(move || client_loop(handle.into_inner(), session_id))
        .await
        .map_err(|e| anyhow::anyhow!("join error: {}", e))?;

    result
}

/// The blocking read loop for a Pipe 1 client.
fn client_loop(pipe: HANDLE, session_id: u32) -> Result<()> {
    loop {
        match read_frame(pipe) {
            Ok(frame) => {
                let msg: Pipe1AgentMsg = match serde_json::from_slice(&frame) {
                    Ok(m) => m,
                    Err(e) => {
                        error!(error = %e, "Pipe 1: failed to deserialise agent message");
                        continue;
                    }
                };

                debug!(?msg, "Pipe 1: received from agent");

                // Handle the message and optionally send a response.
                if let Some(response) = handle_agent_msg(msg, session_id) {
                    if let Err(e) = write_frame(pipe, &response) {
                        error!(error = %e, "Pipe 1: failed to write response");
                        break;
                    }
                }
            }
            Err(e) => {
                debug!(error = %e, "Pipe 1: read error — disconnecting");
                break;
            }
        }
    }

    unsafe {
        let _ = CloseHandle(pipe);
    }

    Ok(())
}

/// Handles an incoming agent message and returns an optional response.
fn handle_agent_msg(msg: Pipe1AgentMsg, session_id: u32) -> Option<Vec<u8>> {
    match msg {
        Pipe1AgentMsg::BlockNotify {
            reason,
            classification,
            resource_path,
            policy_id,
        } => {
            info!(
                session_id,
                classification,
                resource_path = %resource_path,
                "Pipe 1: BlockNotify received"
            );
            // Show the block notification dialog.
            crate::dialogs::show_block_dialog(&classification, &resource_path, &policy_id, &reason);
            None
        }
        Pipe1AgentMsg::OverrideRequest {
            request_id,
            reason: _,
            classification: _,
            resource_path: _,
        } => {
            info!(session_id, request_id, "Pipe 1: OverrideRequest received");
            // TODO (Sprint 11): show override justification dialog.
            None
        }
        Pipe1AgentMsg::ClipboardRead { request_id } => {
            info!(session_id, request_id, "Pipe 1: ClipboardRead received");
            // TODO (Sprint 12): read clipboard and return ClipboardData.
            None
        }
        Pipe1AgentMsg::PasswordDialog { request_id } => {
            info!(session_id, request_id, "Pipe 1: PasswordDialog received");
            // TODO (Sprint 12): show password prompt and return PasswordSubmit/PasswordCancel.
            None
        }
    }
}
