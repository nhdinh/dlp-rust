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

/// Opens a handle to an existing Pipe 1 instance (public for stop-password mode).
pub fn open_pipe_pub() -> Result<HANDLE> {
    open_pipe()
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
    debug!("Pipe 1: attempting to connect to {}", PIPE_NAME);
    let handle = open_pipe()?;
    info!(session_id, "Pipe 1: connected to agent");

    // Send RegisterSession immediately as the first frame.
    let msg = Pipe1UiMsg::RegisterSession { session_id };
    let json = serde_json::to_vec(&msg)
        .map_err(|e| anyhow::anyhow!("serialise RegisterSession: {}", e))?;
    write_frame(handle, &json)?;
    debug!("Pipe 1: RegisterSession sent, entering read loop");

    // Read loop — run on a Tokio background task so it doesn't block iced.
    let handle = SendableHandle(handle);
    tokio::task::spawn_blocking(move || client_loop(handle.into_inner(), session_id))
        .await
        .map_err(|e| anyhow::anyhow!("join error: {}", e))?
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
            // Show the block notification dialog and relay the user's choice back.
            let request_id = format!("block-{}", session_id);
            let dialog_result = crate::dialogs::show_block_dialog_with_result(
                &classification,
                &resource_path,
                &policy_id,
                &reason,
            );
            let msg = match dialog_result {
                crate::dialogs::BlockDialogResult::Confirmed => {
                    Pipe1UiMsg::UserConfirmed { request_id }
                }
                crate::dialogs::BlockDialogResult::Close => {
                    Pipe1UiMsg::UserCancelled { request_id }
                }
            };
            match serde_json::to_vec(&msg) {
                Ok(json) => Some(json),
                Err(e) => {
                    error!(session_id, "serialise BlockNotify response failed: {e}");
                    None
                }
            }
        }
        Pipe1AgentMsg::OverrideRequest {
            request_id,
            reason: _,
            classification: _,
            resource_path: _,
        } => {
            info!(session_id, request_id, "Pipe 1: OverrideRequest received");
            // TODO (Phase 2): show override justification dialog.
            None
        }
        Pipe1AgentMsg::ClipboardRead { request_id } => {
            info!(session_id, request_id, "Pipe 1: ClipboardRead received");
            match crate::dialogs::clipboard::read_clipboard() {
                Ok(Some(data)) => {
                    let msg = Pipe1UiMsg::ClipboardData { request_id, data };
                    match serde_json::to_vec(&msg) {
                        Ok(json) => Some(json),
                        Err(e) => {
                            error!(session_id, "serialise ClipboardData failed: {e}");
                            None
                        }
                    }
                }
                Ok(None) => {
                    info!(session_id, request_id, "clipboard empty or not text");
                    None
                }
                Err(e) => {
                    error!(session_id, request_id, error = %e, "failed to read clipboard");
                    None
                }
            }
        }
        Pipe1AgentMsg::PasswordDialog { request_id } => {
            info!(session_id, request_id, "Pipe 1: PasswordDialog received");
            let msg = match crate::dialogs::stop_password::show_password_dialog(&request_id) {
                Ok(m) => m,
                Err(e) => {
                    error!(session_id, request_id, error = %e, "password dialog failed");
                    Pipe1UiMsg::PasswordCancel { request_id }
                }
            };
            match serde_json::to_vec(&msg) {
                Ok(json) => Some(json),
                Err(e) => {
                    error!(session_id, "serialise password message failed: {e}");
                    None
                }
            }
        }
    }
}
