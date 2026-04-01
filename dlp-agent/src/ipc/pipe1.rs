//! Pipe 1 — `\\.\pipe\DLPCommand` — bidirectional command pipe (T-32).
//!
//! The agent accepts BLOCK_NOTIFY, OVERRIDE_REQUEST, CLIPBOARD_READ,
//! and PASSWORD_DIALOG from the UI and responds with USER_CONFIRMED,
//! USER_CANCELLED, CLIPBOARD_DATA, PASSWORD_SUBMIT.
//!
//! ## Server-initiated messages
//!
//! The agent can also send messages to connected UI clients (e.g. PASSWORD_DIALOG
//! when `sc stop` is issued).  Connected client handles are tracked by session ID
//! so server-initiated messages can be routed to the correct UI process.

use std::collections::HashMap;

use anyhow::{Context, Result};
use parking_lot::RwLock;
use tracing::{debug, error, info};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, NAMED_PIPE_MODE,
    PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE, PIPE_WAIT,
};

use super::frame::{read_frame, write_frame};
use super::messages::{Pipe1AgentMsg, Pipe1UiMsg};

/// Makes `HANDLE` `Send + Sync` so it can be stored in a static `HashMap`.
///
/// Safety: all mutations go through `RwLock` and are confined to the
/// single-threaded pipe server.
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

/// The Win32 pipe name.
const PIPE_NAME: &str = r"\\.\pipe\DLPCommand";

/// The number of pipe instances to create.
const NUM_INSTANCES: u32 = 4;

/// Tracks connected Pipe 1 client handles by session ID.
///
/// A Pipe 1 connection is session-scoped (one UI per session connects to
/// Pipe 1 when it starts).  The agent uses this map to send server-initiated
/// messages (e.g. PASSWORD_DIALOG) to the correct session's UI.
static CLIENTS: std::sync::LazyLock<RwLock<HashMap<u32, SendableHandle>>> =
    std::sync::LazyLock::new(|| RwLock::new(HashMap::new()));

/// Combines the pipe-mode flags into a single `NAMED_PIPE_MODE` value.
fn pipe_mode() -> NAMED_PIPE_MODE {
    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT
}

/// Serves Pipe 1, accepting multiple client connections sequentially.
pub fn serve() -> Result<()> {
    info!(pipe = PIPE_NAME, "Pipe 1 server starting");

    loop {
        let pipe = create_pipe()?;

        // Wait for a client to connect.
        if unsafe { ConnectNamedPipe(pipe, None) }.is_err() {
            let _ = unsafe { CloseHandle(pipe) };
            continue;
        }

        info!(pipe = PIPE_NAME, "client connected to Pipe 1");
        let _ = handle_client(pipe);
        // Client disconnected — remove from client map.
    }
}

/// Creates a new named pipe instance.
fn create_pipe() -> Result<HANDLE> {
    let name_wide: Vec<u16> = PIPE_NAME.encode_utf16().chain(std::iter::once(0)).collect();

    // windows-rs 0.58 CreateNamedPipeW returns HANDLE directly (not Result).
    // Check for INVALID_HANDLE_VALUE using .is_invalid().
    let pipe = unsafe {
        CreateNamedPipeW(
            PCWSTR::from_raw(name_wide.as_ptr()),
            PIPE_ACCESS_DUPLEX,
            pipe_mode(),
            NUM_INSTANCES,
            65536, // output buffer
            65536, // input buffer
            5000,  // default timeout ms
            None,  // default security
        )
    };

    if pipe.is_invalid() {
        return Err(anyhow::anyhow!(
            "CreateNamedPipeW returned INVALID_HANDLE_VALUE"
        ));
    }

    Ok(pipe)
}

/// Handles a single client connection.
fn handle_client(pipe: HANDLE) -> Result<()> {
    // The first message MUST be RegisterSession so we know which session owns this pipe.
    let frame = match read_frame(pipe) {
        Ok(f) => f,
        Err(e) => {
            debug!(error = %e, "Pipe 1: first-frame read error — disconnecting");
            return cleanup_pipe(pipe);
        }
    };

    let msg: Pipe1UiMsg = match serde_json::from_slice(&frame) {
        Ok(m) => m,
        Err(e) => {
            error!(error = %e, "Pipe 1: failed to deserialise first message");
            return cleanup_pipe(pipe);
        }
    };

    // Extract session ID from the registration message.
    let Pipe1UiMsg::RegisterSession { session_id } = msg else {
        error!("Pipe 1: first message must be RegisterSession");
        return cleanup_pipe(pipe);
    };

    info!(session_id, "Pipe 1: UI registered");
    CLIENTS
        .write()
        .insert(session_id, SendableHandle::new(pipe));

    let result = client_loop(session_id, pipe);

    // Remove from client map on disconnect.
    CLIENTS.write().remove(&session_id);
    cleanup_pipe(pipe)?;

    result
}

/// The read loop for a connected Pipe 1 client.
fn client_loop(session_id: u32, pipe: HANDLE) -> Result<()> {
    loop {
        let frame = match read_frame(pipe) {
            Ok(f) => f,
            Err(e) => {
                debug!(session_id, error = %e, "Pipe 1: read error — disconnecting");
                break;
            }
        };

        let msg: Pipe1UiMsg = match serde_json::from_slice(&frame) {
            Ok(m) => m,
            Err(e) => {
                error!(error = %e, "Pipe 1: failed to deserialise message");
                continue;
            }
        };

        debug!(?msg, "Pipe 1: received from UI");

        // Dispatch the message (skip RegisterSession — already handled).
        if !matches!(msg, Pipe1UiMsg::RegisterSession { .. }) {
            let response = dispatch(msg);
            if let Some(resp) = response {
                if let Err(e) = write_frame(pipe, &resp) {
                    error!(session_id, error = %e, "Pipe 1: failed to write response");
                    break;
                }
            }
        }
    }

    Ok(())
}

/// Closes and disconnects a pipe handle.
fn cleanup_pipe(pipe: HANDLE) -> Result<()> {
    unsafe {
        let _ = DisconnectNamedPipe(pipe);
        let _ = CloseHandle(pipe);
    }
    Ok(())
}

/// Dispatches an incoming UI message and returns an optional JSON response.
fn dispatch(msg: Pipe1UiMsg) -> Option<Vec<u8>> {
    match msg {
        Pipe1UiMsg::RegisterSession { .. } => {
            // Already handled in handle_client — should not reach dispatch.
            None
        }
        Pipe1UiMsg::UserConfirmed { request_id } => {
            info!(request_id, "Pipe 1: UI confirmed action");
            // TODO (Sprint 11): route to engine/override handler.
            None
        }
        Pipe1UiMsg::UserCancelled { request_id } => {
            info!(request_id, "Pipe 1: UI cancelled action");
            // TODO (Sprint 11): route to engine/override handler.
            None
        }
        Pipe1UiMsg::ClipboardData { request_id, data } => {
            info!(
                request_id,
                data_len = data.len(),
                "Pipe 1: clipboard data received"
            );
            // TODO (Sprint 12): route to clipboard handler.
            None
        }
        Pipe1UiMsg::PasswordSubmit {
            request_id,
            password,
        } => {
            info!(request_id, "Pipe 1: password submitted");
            crate::password_stop::handle_password_submit(&request_id, password);
            None
        }
        Pipe1UiMsg::PasswordCancel { request_id } => {
            info!(request_id, "Pipe 1: password dialog cancelled");
            crate::password_stop::handle_password_cancel(&request_id);
            None
        }
    }
}

/// Sends a Pipe1AgentMsg to the UI in a specific session (fire-and-forget).
///
/// The session ID determines which connected UI client receives the message.
/// If no client is registered for that session the message is silently dropped.
pub fn send_to_ui(session_id: u32, msg: &Pipe1AgentMsg) -> Result<()> {
    let pipe = match CLIENTS.read().get(&session_id).map(|h| h.as_handle()) {
        Some(h) => h,
        None => {
            debug!(
                session_id,
                "Pipe 1: no client for session — dropping message"
            );
            return Ok(());
        }
    };

    let json = serde_json::to_vec(msg).context("serialise Pipe1AgentMsg")?;
    write_frame(pipe, &json).inspect_err(|e| debug!(session_id, error = %e, "Pipe 1: write failed"))
}

/// Sends a PASSWORD_DIALOG to the UI in a specific session.
///
/// Used by [`crate::password_stop`] when the service receives `sc stop`.
pub fn send_password_dialog(request_id: &str) -> Result<()> {
    let msg = Pipe1AgentMsg::PasswordDialog {
        request_id: request_id.to_string(),
    };

    // PASSWORD_DIALOG is always sent to the interactive session (session 1)
    // or the session that initiated the stop.  We broadcast to all sessions
    // to ensure the dialog reaches the right user.
    let json = serde_json::to_vec(&msg).context("serialise PASSWORD_DIALOG")?;

    let clients = CLIENTS.read();
    let count = clients.len();
    let mut ok_count = 0;

    for (sid, handle) in clients.iter() {
        match write_frame(handle.as_handle(), &json) {
            Ok(()) => ok_count += 1,
            Err(e) => {
                debug!(session_id = sid, error = %e, "Pipe 1: PASSWORD_DIALOG write failed");
            }
        }
    }

    if count == 0 {
        debug!("Pipe 1: no UI clients connected — PASSWORD_DIALOG not sent");
    } else {
        info!(
            sessions_contacted = count,
            sessions_reached = ok_count,
            "Pipe 1: PASSWORD_DIALOG sent"
        );
    }

    Ok(())
}
