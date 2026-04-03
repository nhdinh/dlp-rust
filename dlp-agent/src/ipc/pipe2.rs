//! Pipe 2 — `\\.\pipe\DLPEventAgent2UI` — agent-to-UI fire-and-forget (T-33).
//!
//! The agent sends TOAST, STATUS_UPDATE, HEALTH_PING, UI_RESPAWN,
//! and UI_CLOSING_SEQUENCE to the UI via the [`Broadcaster`].  Each connected
//! UI client drains a `tokio::sync::mpsc` channel and writes frames to the
//! pipe.  Pipe 2 carries no session-specific routing — the broadcaster fans
//! out to every registered client.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use parking_lot::RwLock;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{ReadFile, PIPE_ACCESS_DUPLEX};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, NAMED_PIPE_MODE,
    PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE, PIPE_WAIT,
};

use super::frame::{read_frame, write_frame};
use super::messages::Pipe2AgentMsg;

/// The Win32 pipe name.
const PIPE_NAME: &str = r"\\.\pipe\DLPEventAgent2UI";

/// Maximum frames held in a per-client send buffer.
const CLIENT_QUEUE_DEPTH: usize = 64;

/// The number of pipe instances to create.
const NUM_INSTANCES: u32 = 4;

/// Combines the pipe-mode flags into a single `NAMED_PIPE_MODE` value.
fn pipe_mode() -> NAMED_PIPE_MODE {
    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT
}

/// Shared broadcaster: callers (health monitor, interception engine, etc.)
/// call [`Broadcaster::broadcast`] to queue a serialised `Pipe2AgentMsg` for
/// every connected UI client.  Clients with a full send buffer silently drop
/// the frame (fire-and-forget semantics).
///
/// Session association is the caller's responsibility.  The broadcaster does
/// not interpret or store session IDs — it simply fans out to all registered
/// transmitters.
#[derive(Default)]
pub struct Broadcaster {
    /// All active client transmitters.
    clients: Arc<RwLock<HashMap<usize, mpsc::Sender<Vec<u8>>>>>,
    /// Monotonically increasing counter used as a transient client key.
    next_id: Arc<RwLock<usize>>,
}

impl Broadcaster {
    /// Registers a new client transmitter.
    ///
    /// Returns a client key that the caller must use in [`remove_client`]
    /// when the client disconnects.
    pub fn add_client(&self, tx: mpsc::Sender<Vec<u8>>) -> usize {
        let id = {
            let mut n = self.next_id.write();
            let id = *n;
            *n = id.wrapping_add(1);
            id
        };
        self.clients.write().insert(id, tx);
        id
    }

    /// Removes a client transmitter by its key.
    pub fn remove_client(&self, id: usize) {
        self.clients.write().remove(&id);
    }

    /// Broadcasts a serialised message to all connected clients.
    ///
    /// Returns the number of clients the message was queued for.
    pub fn broadcast(&self, msg: &Pipe2AgentMsg) -> usize {
        let json = match serde_json::to_vec(msg) {
            Ok(j) => j,
            Err(e) => {
                error!(error = %e, "Pipe 2: failed to serialise broadcast message");
                return 0;
            }
        };

        let clients = self.clients.read();
        let count = clients.len();

        for (client_id, tx) in clients.iter() {
            if tx.try_send(json.clone()).is_err() {
                debug!(client_id, "Pipe 2: client queue full — dropping frame");
            }
        }

        count
    }

    /// Returns the number of currently registered clients.
    #[allow(dead_code)]
    pub fn client_count(&self) -> usize {
        self.clients.read().len()
    }

    /// Returns an iterator over all client IDs and their senders.
    ///
    /// Returns owned copies so the caller can use them after releasing the lock.
    pub fn clients(&self) -> HashMap<usize, mpsc::Sender<Vec<u8>>> {
        self.clients.read().clone()
    }

    /// Returns an iterator over all client IDs.
    #[allow(dead_code)]
    pub fn client_ids(&self) -> impl Iterator<Item = usize> + '_ {
        self.clients
            .read()
            .keys()
            .copied()
            .collect::<Vec<_>>()
            .into_iter()
    }
}

/// Global broadcaster instance shared across the crate.
pub static BROADCASTER: std::sync::LazyLock<Broadcaster> =
    std::sync::LazyLock::new(Broadcaster::default);

/// Serves Pipe 2, broadcasting agent messages to all connected UI clients.
pub fn serve() -> Result<()> {
    info!(pipe = PIPE_NAME, "Pipe 2 server starting");

    loop {
        let pipe = create_pipe()?;

        // Wait for a client to connect.  ERROR_PIPE_CONNECTED
        // (Win32 535, HRESULT 0x80070217) means the client connected
        // before this call — that is a success case.
        if let Err(e) = unsafe { ConnectNamedPipe(pipe, None) } {
            let win32_code = (e.code().0 as u32) & 0xFFFF;
            if win32_code != 535 {
                warn!(
                    win32_code,
                    "ConnectNamedPipe failed — recycling pipe"
                );
                unsafe {
                    let _ = windows::Win32::Foundation::CloseHandle(
                        pipe,
                    );
                }
                continue;
            }
        }

        info!(pipe = PIPE_NAME, "UI client connected to Pipe 2");
        let _ = handle_client(pipe);
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
    // Tokio current-thread runtime so we can use async channels in a std thread.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Tokio current-thread runtime must succeed");

    // Bounded channel: broadcaster queues outbound frames; if the queue fills
    // the broadcaster drops the frame (fire-and-forget).
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(CLIENT_QUEUE_DEPTH);

    // Register with the broadcaster and get a transient client key.
    let client_id = BROADCASTER.add_client(tx);

    rt.block_on(async {
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(());

        tokio::join!(
            drain_queue(&mut rx, pipe, cancel_rx),
            poll_disconnect(pipe, cancel_tx),
        );
    });

    BROADCASTER.remove_client(client_id);

    unsafe {
        let _ = DisconnectNamedPipe(pipe);
        let _ = CloseHandle(pipe);
    }
    Ok(())
}

/// Drains the broadcaster channel and writes frames to the pipe.
async fn drain_queue(
    rx: &mut mpsc::Receiver<Vec<u8>>,
    pipe: HANDLE,
    mut cancel_rx: tokio::sync::watch::Receiver<()>,
) {
    loop {
        tokio::select! {
            biased;

            _ = cancel_rx.changed() => {
                // Sender cancelled — broadcaster removed us.
                debug!("Pipe 2: drain cancelled");
                break;
            }
            payload = rx.recv() => {
                match payload {
                    Some(bytes) => {
                        if let Err(e) = write_frame(pipe, &bytes) {
                            debug!(error = %e, "Pipe 2: write failed");
                            break;
                        }
                    }
                    None => {
                        // Sender dropped — broadcaster removed us.
                        debug!("Pipe 2: broadcaster sender dropped");
                        break;
                    }
                }
            }
        }
    }
}

/// Polls the pipe for inbound data.  Pipe 2 is agent → UI only, so any
/// inbound data is unexpected — we use it as a disconnect detector.
async fn poll_disconnect(pipe: HANDLE, cancel_tx: tokio::sync::watch::Sender<()>) {
    let mut scratch = [0u8; 64];

    loop {
        tokio::select! {
            biased;

            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                // Poll the pipe for data or disconnect.
                let mut bytes_read = 0u32;

                let result = unsafe {
                    ReadFile(
                        pipe,
                        Some(&mut scratch),
                        Some(&mut bytes_read),
                        None,
                    )
                };

                if result.is_err() || bytes_read == 0 {
                    // Client gone — cancel the drain task.
                    let _ = cancel_tx.send(());
                    break;
                }

                // Unexpected inbound frame — discard and continue polling.
                let _ = read_frame(pipe);
                debug!("Pipe 2: discarding unexpected inbound frame");
            }
        }
    }

    debug!("Pipe 2: disconnect detected");
}
