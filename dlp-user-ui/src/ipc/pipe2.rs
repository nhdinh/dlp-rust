//! Pipe 2 client — connects to `\\.\pipe\DLPEventAgent2UI` (T-41).
//!
//! Receives agent-to-UI events: `Toast`, `StatusUpdate`, `HealthPing`,
//! `UiRespawn`, `UiClosingSequence`.  The first four are fire-and-forget;
//! `UiClosingSequence` triggers the UI close sequence and exits.

use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use tracing::{debug, error, info};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{CreateFileW, FILE_FLAG_NO_BUFFERING, FILE_SHARE_MODE};
use windows::Win32::Storage::FileSystem::{OPEN_EXISTING, PIPE_ACCESS_INBOUND};

use super::frame::read_frame;
use super::messages::Pipe2AgentMsg;

/// The Win32 pipe name.
const PIPE_NAME: &str = r"\\.\pipe\DLPEventAgent2UI";

/// Tracks the last known Agent->Server connection state received via IPC.
/// Initialized to false (unknown/disconnected) until the agent broadcasts.
static AGENT_SERVER_CONNECTED: AtomicBool = AtomicBool::new(false);

/// Returns the last known Agent->Server connection state.
///
/// Returns `false` until the agent broadcasts a `ServerConnected { connected: true }` message.
/// Updated atomically with `Relaxed` ordering — callers read a recent but not necessarily
/// instantaneous value, which is acceptable for UI display purposes.
pub fn agent_server_connected() -> bool {
    AGENT_SERVER_CONNECTED.load(Ordering::Relaxed)
}

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

/// Opens a handle to an existing Pipe 2 instance.
fn open_pipe() -> Result<HANDLE> {
    let name_wide: Vec<u16> = PIPE_NAME.encode_utf16().chain(std::iter::once(0)).collect();

    let handle = unsafe {
        CreateFileW(
            PCWSTR::from_raw(name_wide.as_ptr()),
            PIPE_ACCESS_INBOUND.0,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_FLAG_NO_BUFFERING,
            None,
        )
    };

    handle.map_err(|e| anyhow::anyhow!("CreateFileW on Pipe 2 failed: {}", e))
}

/// Runs the Pipe 2 listener.
///
/// Connects to Pipe 2 and processes incoming agent-to-UI messages in a loop
/// until the pipe is closed.
pub async fn run_listener() -> Result<()> {
    let handle = open_pipe()?;
    info!("Pipe 2: connected to agent");

    let handle = SendableHandle(handle);
    let result = tokio::task::spawn_blocking(move || read_loop(handle.into_inner()))
        .await
        .map_err(|e| anyhow::anyhow!("join error: {}", e))?;

    result
}

/// The blocking read loop for Pipe 2.
fn read_loop(pipe: HANDLE) -> Result<()> {
    loop {
        match read_frame(pipe) {
            Ok(frame) => {
                let msg: Pipe2AgentMsg = match serde_json::from_slice(&frame) {
                    Ok(m) => m,
                    Err(e) => {
                        error!(error = %e, "Pipe 2: failed to deserialise agent message");
                        continue;
                    }
                };

                debug!(?msg, "Pipe 2: received from agent");
                handle_agent_msg(msg);
            }
            Err(e) => {
                debug!(error = %e, "Pipe 2: read error — disconnecting");
                break;
            }
        }
    }

    unsafe {
        let _ = CloseHandle(pipe);
    }

    Ok(())
}

/// Handles an incoming agent-to-UI message.
fn handle_agent_msg(msg: Pipe2AgentMsg) {
    match msg {
        Pipe2AgentMsg::Toast { title, body } => {
            info!(title, body, "Pipe 2: Toast received");
            crate::notifications::show_toast(&title, &body);
        }
        Pipe2AgentMsg::StatusUpdate { status } => {
            info!(status, "Pipe 2: StatusUpdate received");
            crate::tray::update_status(&status);
        }
        Pipe2AgentMsg::HealthPing => {
            debug!("Pipe 2: HealthPing received");
        }
        Pipe2AgentMsg::UiRespawn { session_id } => {
            info!(session_id, "Pipe 2: UiRespawn — UI will exit for respawn");
            std::process::exit(0);
        }
        Pipe2AgentMsg::UiClosingSequence { session_id } => {
            info!(session_id, "Pipe 2: UiClosingSequence received");
            crate::dialogs::show_closing_sequence();
            std::process::exit(0);
        }
        Pipe2AgentMsg::ServerConnected { connected } => {
            AGENT_SERVER_CONNECTED.store(connected, Ordering::Relaxed);
        }
    }
}
