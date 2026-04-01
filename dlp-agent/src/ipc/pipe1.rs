//! Pipe 1 — `\\.\pipe\DLPCommand` — bidirectional command pipe (T-32).
//!
//! The agent accepts BLOCK_NOTIFY, OVERRIDE_REQUEST, CLIPBOARD_READ,
//! and PASSWORD_DIALOG from the UI and responds with USER_CONFIRMED,
//! USER_CANCELLED, CLIPBOARD_DATA, PASSWORD_SUBMIT.

use anyhow::{Context, Result};
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

/// The Win32 pipe name.
const PIPE_NAME: &str = r"\\.\pipe\DLPCommand";

/// The number of pipe instances to create.
const NUM_INSTANCES: u32 = 4;

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
        // Client disconnected — loop and wait for next connection.
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
    loop {
        // Read a JSON frame from the client.
        let frame = match read_frame(pipe) {
            Ok(f) => f,
            Err(e) => {
                debug!(error = %e, "Pipe 1: read error — disconnecting");
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

        debug!(msg_type = ?msg, "Pipe 1: received from UI");

        // Dispatch the message.
        let response = dispatch(msg);
        if let Some(resp) = response {
            if let Err(e) = write_frame(pipe, &resp) {
                error!(error = %e, "Pipe 1: failed to write response");
                break;
            }
        }
    }

    unsafe {
        let _ = DisconnectNamedPipe(pipe);
        let _ = CloseHandle(pipe);
    }
    Ok(())
}

/// Dispatches an incoming UI message and returns an optional JSON response.
fn dispatch(msg: Pipe1UiMsg) -> Option<Vec<u8>> {
    match msg {
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
            password: _,
        } => {
            info!(request_id, "Pipe 1: password submitted");
            // TODO (Sprint 9): route to password stop handler.
            None
        }
        Pipe1UiMsg::PasswordCancel { request_id } => {
            info!(request_id, "Pipe 1: password dialog cancelled");
            // TODO (Sprint 9): route to password stop handler.
            None
        }
    }
}

/// Sends an agent message to the pipe client (blocking).
///
/// TODO (Sprint 7): wire into the health monitor so `send_to_ui` knows
/// which active client handle to use.
pub fn send_to_ui(msg: &Pipe1AgentMsg) -> Result<()> {
    let _json = serde_json::to_vec(msg).context("serialise Pipe1AgentMsg")?;
    info!(msg_type = ?msg, "Pipe 1: send_to_ui called (not yet connected)");
    Ok(())
}
