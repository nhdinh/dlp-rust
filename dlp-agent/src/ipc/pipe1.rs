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
use std::sync::Arc;

use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use tracing::{debug, error, info, warn};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, NAMED_PIPE_MODE,
    PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE, PIPE_WAIT,
};

use super::frame::{read_frame, write_frame};
use super::messages::{Pipe1AgentMsg, Pipe1UiMsg};

/// Pending clipboard-read request IDs awaiting data from the UI.
///
/// The clipboard read request is initiated by the interception layer (which calls
/// [`crate::clipboard::listener::read_clipboard_request`]).  When the UI sends
/// `ClipboardData`, the data is stored here and the interception handler wakes up.
static CLIPBOARD_CACHE: Lazy<Arc<RwLock<HashMap<String, String>>>> =
    Lazy::new(|| Arc::new(RwLock::new(HashMap::new())));

/// Pending override requests awaiting user confirmation or cancellation.
///
/// When the agent needs user override confirmation, it stores the request context
/// here.  `UserConfirmed` clears the entry and proceeds; `UserCancelled` clears
/// and aborts the operation.
static OVERRIDE_PENDING: Lazy<Arc<RwLock<HashMap<String, OverrideContext>>>> =
    Lazy::new(|| Arc::new(RwLock::new(HashMap::new())));

/// Context stored for a pending override request.
#[derive(Debug)]
struct OverrideContext {
    /// The session ID of the requesting session.
    session_id: u32,
    /// When the request was created (for timeout detection).
    created_at: std::time::Instant,
}

/// Returns a snapshot of all pending clipboard request IDs.
pub fn get_pending_clipboard_requests() -> Vec<String> {
    CLIPBOARD_CACHE.read().keys().cloned().collect()
}

/// Retrieves and removes clipboard data for a given request ID.
///
/// Returns `None` if no data is available yet.  Callers should retry after a
/// short delay if `None` is returned.
pub fn take_clipboard_data(request_id: &str) -> Option<String> {
    CLIPBOARD_CACHE.write().remove(request_id)
}

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

/// Serves Pipe 1 with a readiness callback.
///
/// `on_ready` is called after the first `CreateNamedPipeW` succeeds,
/// signalling that the pipe exists and clients can connect.
pub fn serve_with_ready(on_ready: impl FnOnce()) -> Result<()> {
    info!(pipe = PIPE_NAME, "Pipe 1 server starting");
    let first_pipe = create_pipe()?;
    on_ready();
    accept_loop(first_pipe)
}

/// Serves Pipe 1 without a readiness callback.
pub fn serve() -> Result<()> {
    info!(pipe = PIPE_NAME, "Pipe 1 server starting");
    accept_loop(create_pipe()?)
}

/// Accept loop: waits for clients, handles them, then creates a new
/// pipe instance for the next client.
fn accept_loop(first_pipe: HANDLE) -> Result<()> {
    let mut pipe = first_pipe;
    loop {
        // Wait for a client to connect.  ConnectNamedPipe returns
        // ERROR_PIPE_CONNECTED if a client connected between
        // CreateNamedPipeW and this call — that is a success case.
        if let Err(e) = unsafe { ConnectNamedPipe(pipe, None) } {
            let win32_code = (e.code().0 as u32) & 0xFFFF;
            if win32_code != 535 {
                warn!(win32_code, "ConnectNamedPipe failed — recycling pipe");
                let _ = unsafe { CloseHandle(pipe) };
                pipe = create_pipe()?;
                continue;
            }
            debug!("ConnectNamedPipe: client already connected (535)");
        }

        info!(pipe = PIPE_NAME, "client connected to Pipe 1");
        let _ = handle_client(pipe);

        // Create a new pipe instance for the next client.
        pipe = create_pipe()?;
    }
}

/// Creates a new named pipe instance with a DACL that allows
/// Authenticated Users (the interactive-user UI process) to connect.
fn create_pipe() -> Result<HANDLE> {
    let name_wide: Vec<u16> = PIPE_NAME.encode_utf16().chain(std::iter::once(0)).collect();

    // Build a security descriptor that grants Authenticated Users
    // read/write access so the user-context UI can connect.
    let sec = super::pipe_security::PipeSecurity::new().context("pipe security descriptor")?;

    let pipe = unsafe {
        CreateNamedPipeW(
            PCWSTR::from_raw(name_wide.as_ptr()),
            PIPE_ACCESS_DUPLEX,
            pipe_mode(),
            NUM_INSTANCES,
            65536, // output buffer
            65536, // input buffer
            5000,  // default timeout ms
            Some(sec.as_ptr()),
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
            // Remove any pending clipboard data associated with this request.
            let _ = CLIPBOARD_CACHE.write().remove(&request_id);

            // If this was an override confirmation, emit an override-granted
            // audit event for the compliance trail.  The file operation itself
            // is not retried (notify watcher is observe-only; actual blocking
            // requires a kernel-level minifilter in a future phase).
            let removed = OVERRIDE_PENDING.write().remove(&request_id);
            if let Some(ctx) = removed {
                warn!(
                    request_id,
                    session_id = ctx.session_id,
                    elapsed_ms = ctx.created_at.elapsed().as_millis() as u64,
                    "Pipe 1: override confirmed — audit event emitted"
                );
                // Emit an override-granted audit event.
                let event = dlp_common::AuditEvent::new(
                    dlp_common::EventType::Access,
                    "OVERRIDE".to_string(),
                    "OVERRIDE".to_string(),
                    request_id.clone(),
                    dlp_common::Classification::T1,
                    dlp_common::Action::READ,
                    dlp_common::Decision::AllowWithLog,
                    "AGENT".to_string(),
                    ctx.session_id,
                )
                .with_override_granted();
                let ctx = crate::audit_emitter::EmitContext {
                    agent_id: "AGENT".to_string(),
                    session_id: ctx.session_id,
                    user_sid: "OVERRIDE".to_string(),
                    user_name: "OVERRIDE".to_string(),
                    machine_name: None,
                };
                crate::audit_emitter::emit_audit(&ctx, &mut event.clone());
            } else {
                debug!(
                    request_id,
                    "Pipe 1: UserConfirmed for unknown request — ignored"
                );
            }
            None
        }
        Pipe1UiMsg::UserCancelled { request_id } => {
            info!(request_id, "Pipe 1: UI cancelled action");
            // Remove pending clipboard data and override context.
            let _ = CLIPBOARD_CACHE.write().remove(&request_id);
            if let Some(ctx) = OVERRIDE_PENDING.write().remove(&request_id) {
                warn!(
                    request_id,
                    session_id = ctx.session_id,
                    elapsed_ms = ctx.created_at.elapsed().as_millis() as u64,
                    "Pipe 1: override cancelled by user — operation aborted"
                );
            }
            None
        }
        Pipe1UiMsg::ClipboardData { request_id, data } => {
            info!(
                request_id,
                data_len = data.len(),
                "Pipe 1: clipboard data received — storing for retrieval"
            );
            // Store the clipboard data so the interception handler can retrieve it
            // after waking from its await.  Trim whitespace to avoid matching on
            // accidental whitespace-only pastes.
            let trimmed = data.trim().to_string();
            if !trimmed.is_empty() {
                CLIPBOARD_CACHE.write().insert(request_id.clone(), trimmed);
            } else {
                debug!(request_id, "Pipe 1: clipboard data is empty — ignoring");
            }
            None
        }
        Pipe1UiMsg::PasswordSubmit {
            request_id,
            password,
        } => {
            info!(request_id, "Pipe 1: password submitted");
            // Pipe-based flow uses DPAPI-wrapped passwords.
            crate::password_stop::handle_password_submit(&request_id, password, false);
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

/// Sends a PASSWORD_DIALOG to the UI in all connected sessions.
///
/// Used by [`crate::password_stop`] when the service receives `sc stop`.
///
/// # Returns
///
/// The number of UI clients that successfully received the message.
/// Returns `0` when no clients are connected (caller should spawn a UI).
pub fn send_password_dialog(request_id: &str) -> Result<u32> {
    let msg = Pipe1AgentMsg::PasswordDialog {
        request_id: request_id.to_string(),
    };

    let json = serde_json::to_vec(&msg).context("serialise PASSWORD_DIALOG")?;

    let clients = CLIENTS.read();
    let count = clients.len();
    let mut ok_count: u32 = 0;

    for (sid, handle) in clients.iter() {
        match write_frame(handle.as_handle(), &json) {
            Ok(()) => ok_count += 1,
            Err(e) => {
                debug!(session_id = sid, error = %e, "Pipe 1: PASSWORD_DIALOG write failed");
            }
        }
    }

    if count == 0 {
        info!("Pipe 1: no UI clients connected — PASSWORD_DIALOG not sent");
    } else {
        info!(
            sessions_contacted = count,
            sessions_reached = ok_count,
            "Pipe 1: PASSWORD_DIALOG sent"
        );
    }

    Ok(ok_count)
}

/// Returns the number of currently connected Pipe 1 clients.
pub fn connected_client_count() -> usize {
    CLIENTS.read().len()
}
