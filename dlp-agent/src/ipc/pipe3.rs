//! Pipe 3 — `\\.\pipe\DLPEventUI2Agent` — UI-to-agent event pipe (T-34).
//!
//! The UI sends HEALTH_PONG, UI_READY, and UI_CLOSING to the agent.
//! These events are routed to the health monitor and session monitor.

use std::sync::Arc;

use anyhow::Result;
use parking_lot::RwLock;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use windows::core::PCWSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, NAMED_PIPE_MODE,
    PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE, PIPE_WAIT,
};

use super::frame::read_frame;
use super::messages::Pipe3UiMsg;

/// The Win32 pipe name.
const PIPE_NAME: &str = r"\\.\pipe\DLPEventUI2Agent";

/// The number of pipe instances to create.
const NUM_INSTANCES: u32 = 4;

/// Combines the pipe-mode flags into a single `NAMED_PIPE_MODE` value.
fn pipe_mode() -> NAMED_PIPE_MODE {
    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT
}

/// Route table for incoming UI events.
///
/// Callers (health monitor, session monitor) register receivers here.
/// Each new Pipe 3 client session gets its own channel.
#[derive(Default)]
pub struct Router {
    /// Channels for each UI event category.
    health_tx: Arc<RwLock<Option<mpsc::Sender<UiHealthEvent>>>>,
    session_tx: Arc<RwLock<Option<mpsc::Sender<UiSessionEvent>>>>,
}

impl Router {
    /// Registers the health event channel.
    pub fn set_health_sender(&self, tx: mpsc::Sender<UiHealthEvent>) {
        *self.health_tx.write() = Some(tx);
    }

    /// Registers the session event channel.
    pub fn set_session_sender(&self, tx: mpsc::Sender<UiSessionEvent>) {
        *self.session_tx.write() = Some(tx);
    }
}

/// Events extracted from Pipe 3 messages and forwarded to the health monitor.
#[derive(Debug, Clone)]
pub enum UiHealthEvent {
    /// The UI is alive and responding.
    Pong,
}

/// Events extracted from Pipe 3 messages and forwarded to the session monitor.
#[derive(Debug, Clone)]
pub enum UiSessionEvent {
    /// The UI has started and is ready for interaction.
    Ready { session_id: u32 },
    /// The UI is closing (user logged out or closed voluntarily).
    Closing { session_id: u32 },
}

/// Global router shared across the crate.
pub static ROUTER: std::sync::LazyLock<Router> = std::sync::LazyLock::new(Router::default);

/// Serves Pipe 3 with a readiness callback.
pub fn serve_with_ready(on_ready: impl FnOnce()) -> Result<()> {
    info!(pipe = PIPE_NAME, "Pipe 3 server starting");
    let first_pipe = create_pipe()?;
    on_ready();
    accept_loop(first_pipe)
}

/// Serves Pipe 3 without a readiness callback.
#[allow(dead_code)]
pub fn serve() -> Result<()> {
    info!(pipe = PIPE_NAME, "Pipe 3 server starting");
    accept_loop(create_pipe()?)
}

fn accept_loop(first_pipe: HANDLE) -> Result<()> {
    let mut pipe = first_pipe;
    loop {
        if let Err(e) = unsafe { ConnectNamedPipe(pipe, None) } {
            let win32_code = (e.code().0 as u32) & 0xFFFF;
            if win32_code != 535 {
                warn!(
                    win32_code,
                    "ConnectNamedPipe failed — recycling pipe"
                );
                unsafe {
                    let _ = CloseHandle(pipe);
                }
                pipe = create_pipe()?;
                continue;
            }
        }

        info!(pipe = PIPE_NAME, "UI client connected to Pipe 3");
        let _ = handle_client(pipe);
        pipe = create_pipe()?;
    }
}

/// Creates a new named pipe instance with a DACL that allows
/// Authenticated Users (the interactive-user UI process) to connect.
fn create_pipe() -> Result<HANDLE> {
    let name_wide: Vec<u16> =
        PIPE_NAME.encode_utf16().chain(std::iter::once(0)).collect();

    let sec = super::pipe_security::PipeSecurity::new()
        .map_err(|e| anyhow::anyhow!("pipe security: {e}"))?;

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

/// Handles a single UI client connection.
fn handle_client(pipe: HANDLE) -> Result<()> {
    loop {
        let frame = match read_frame(pipe) {
            Ok(f) => f,
            Err(e) => {
                debug!(error = %e, "Pipe 3: read error — disconnecting");
                break;
            }
        };

        let msg: Pipe3UiMsg = match serde_json::from_slice(&frame) {
            Ok(m) => m,
            Err(e) => {
                error!(error = %e, "Pipe 3: failed to deserialise message");
                continue;
            }
        };

        debug!(msg_type = ?msg, "Pipe 3: received from UI");
        route(msg);
    }

    unsafe {
        let _ = DisconnectNamedPipe(pipe);
        let _ = CloseHandle(pipe);
    }
    Ok(())
}

/// Routes a deserialised UI message to the appropriate channel.
fn route(msg: Pipe3UiMsg) {
    match msg {
        Pipe3UiMsg::HealthPong => {
            if let Some(tx) = ROUTER.health_tx.read().as_ref() {
                let _ = tx.try_send(UiHealthEvent::Pong);
            }
        }
        Pipe3UiMsg::UiReady { session_id } => {
            info!(session_id, "Pipe 3: UI is ready");
            if let Some(tx) = ROUTER.session_tx.read().as_ref() {
                let _ = tx.try_send(UiSessionEvent::Ready { session_id });
            }
        }
        Pipe3UiMsg::UiClosing { session_id } => {
            info!(session_id, "Pipe 3: UI is closing");
            if let Some(tx) = ROUTER.session_tx.read().as_ref() {
                let _ = tx.try_send(UiSessionEvent::Closing { session_id });
            }
        }
    }
}
