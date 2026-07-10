//! Pipe 1 client — connects to `\\.\pipe\DLPCommand` (T-40).
//!
//! Sends `RegisterSession` immediately on connect, then handles incoming
//! agent messages: `BlockNotify`, `OverrideRequest`, `ClipboardRead`,
//! `PasswordDialog`.  Responds with `UserConfirmed`, `UserCancelled`,
//! `ClipboardData`, `PasswordSubmit`, `PasswordCancel`.

use std::sync::atomic::{AtomicU64, Ordering};

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

/// Monotonic sequence used to mint a unique `request_id` per `BlockNotify`.
///
/// The previous `format!("block-{session_id}")` reused the same id for every
/// block in a session, so concurrent `BlockNotify`s produced indistinguishable
/// `UserConfirmed`/`UserCancelled` responses (WR-10). A process-wide counter
/// guarantees uniqueness within the UI lifetime; cross-restart collisions are
/// irrelevant because the id only correlates events within one run.
static BLOCK_NOTIFY_SEQ: AtomicU64 = AtomicU64::new(0);

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
pub async fn connect_and_run(
    session_id: u32,
    connected: Option<std::sync::Arc<parking_lot::RwLock<bool>>>,
) -> Result<()> {
    debug!("Pipe 1: attempting to connect to {}", PIPE_NAME);
    let handle = open_pipe()?;
    info!(session_id, "Pipe 1: connected to agent");

    if let Some(ref c) = connected {
        *c.write() = true;
    }

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

/// Maximum time between agent messages before assuming the agent is dead.
///
/// Measured from connection (and reset on every received frame) so a
/// live-but-silent agent — one that holds the pipe open but never writes —
/// is detected even when no frame has arrived yet (WR-06).
const HEARTBEAT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Poll interval for the read channel. Bounds how often the main loop wakes
/// to check the heartbeat clock while a read is pending.
const PIPE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

/// The blocking read loop for a Pipe 1 client.
///
/// A dedicated reader thread owns the blocking `read_frame` call for the
/// lifetime of this loop and forwards each result over a channel. The main
/// thread waits with a bounded `recv_timeout` so it can wake periodically
/// and detect a live-but-silent agent (no frames within
/// [`HEARTBEAT_TIMEOUT`]) instead of blocking forever inside `read_frame`
/// (WR-06). On exit the pipe handle is closed from this thread, which
/// unblocks the reader's pending read so it terminates cleanly.
fn client_loop(pipe: HANDLE, session_id: u32) -> Result<()> {
    let (tx, rx) = std::sync::mpsc::channel::<Result<Vec<u8>>>();
    let reader_handle = SendableHandle(pipe);
    let reader = std::thread::spawn(move || {
        loop {
            let result = read_frame(reader_handle.into_inner());
            let stop = result.is_err();
            if tx.send(result).is_err() {
                // Receiver dropped — the main loop has exited.
                return;
            }
            if stop {
                // Pipe closed or errored — nothing more to read.
                return;
            }
        }
    });

    // Start the clock at connect time: an agent that never writes a single
    // frame must still be detected within HEARTBEAT_TIMEOUT.
    let mut last_message = std::time::Instant::now();

    // WR-02: modal dialog results are produced off the read loop and delivered
    // back over this channel, so the loop never blocks on user input. The
    // blocking Win32 dialogs run on dedicated threads; the loop keeps
    // servicing Ping/Pong and the heartbeat clock and only writes the
    // `UserConfirmed`/`UserCancelled` response once a dialog resolves.
    let (dialog_tx, dialog_rx) = std::sync::mpsc::channel::<Vec<u8>>();

    let outcome: Result<()> = loop {
        // Write any dialog responses that resolved while we were reading or
        // sleeping before checking for the next frame / heartbeat.
        if let Err(e) = drain_dialog_responses(pipe, &dialog_rx) {
            error!(error = %e, "Pipe 1: dialog response write failed");
            break Ok(());
        }

        match rx.recv_timeout(PIPE_POLL_INTERVAL) {
            Ok(Ok(frame)) => {
                last_message = std::time::Instant::now();
                let msg: Pipe1AgentMsg = match serde_json::from_slice(&frame) {
                    Ok(m) => m,
                    Err(e) => {
                        error!(error = %e, "Pipe 1: failed to deserialise agent message");
                        continue;
                    }
                };

                debug!(?msg, "Pipe 1: received from agent");

                // Handle the message and optionally send a response.
                if let Some(response) = handle_agent_msg(msg, session_id, pipe, &dialog_tx) {
                    if let Err(e) = write_frame(pipe, &response) {
                        error!(error = %e, "Pipe 1: failed to write response");
                        break Ok(());
                    }
                }
            }
            Ok(Err(e)) => {
                debug!(error = %e, "Pipe 1: read error — disconnecting");
                break Ok(());
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if last_message.elapsed() > HEARTBEAT_TIMEOUT {
                    error!(session_id, "Pipe 1: heartbeat timeout — agent appears dead");
                    break Err(anyhow::anyhow!("Pipe 1: agent heartbeat timeout"));
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                debug!("Pipe 1: reader thread exited — disconnecting");
                break Ok(());
            }
        }
    };

    // Close the handle from this thread to unblock the reader's pending
    // read_frame, then wait for the reader thread to drain.
    unsafe {
        let _ = CloseHandle(pipe);
    }
    drop(rx);
    let _ = reader.join();

    outcome
}

/// Serialises a UI response message into JSON bytes.
///
/// Returns `None` and logs an error if serialisation fails.
fn serialize_response(msg: &Pipe1UiMsg, session_id: u32, label: &str) -> Option<Vec<u8>> {
    serde_json::to_vec(msg)
        .map_err(|e| error!(session_id, "serialise {label} failed: {e}"))
        .ok()
}

/// Drains every dialog response that resolved while the read loop was reading
/// or sleeping and writes them to the pipe.
///
/// Non-blocking: an empty or disconnected channel is harmless. Returns `Err`
/// only if a `write_frame` fails, which the read loop treats as a graceful
/// disconnect. Keeping modal dialogs off the read loop (WR-02) means this is
/// the single, synchronous point where dialog outcomes reach the pipe.
fn drain_dialog_responses(
    pipe: HANDLE,
    dialog_rx: &std::sync::mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    loop {
        match dialog_rx.try_recv() {
            Ok(bytes) => {
                write_frame(pipe, &bytes)
                    .map_err(|e| anyhow::anyhow!("failed to write dialog response: {e}"))?;
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => return Ok(()),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => return Ok(()),
        }
    }
}

/// Handles a `ClipboardRead` request by reading the clipboard and building
/// a response message.
///
/// Returns `None` when the clipboard is empty, not text, or unreadable.
fn handle_clipboard_read(request_id: String, session_id: u32) -> Option<Pipe1UiMsg> {
    match crate::dialogs::clipboard::read_clipboard() {
        Ok(Some(data)) => Some(Pipe1UiMsg::ClipboardData { request_id, data }),
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

/// Mints a unique `request_id` for a single `BlockNotify` event.
///
/// Format: `block-{session_id}-{seq}` where `seq` is a process-wide monotonic
/// counter, so two near-simultaneous blocks (common when the hook DLL bursts)
/// produce distinct, correlatable ids instead of the previous shared
/// `block-{session_id}` (WR-10).
fn mint_block_request_id(session_id: u32) -> String {
    let seq = BLOCK_NOTIFY_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("block-{session_id}-{seq}")
}

/// Handles a `BlockNotify` message by running the modal dialog off the read
/// loop and delivering the response over `dialog_tx` (WR-02).
///
/// Returns `None` immediately: the read loop must not block on the modal. The
/// spawned thread owns the cloned `dialog_tx` and sends the serialised
/// `UserConfirmed`/`UserCancelled` bytes once the user decides; the read loop
/// writes them via [`drain_dialog_responses`] on its next poll.
fn handle_block_notify(
    reason: String,
    classification: String,
    resource_path: String,
    policy_id: String,
    session_id: u32,
    dialog_tx: std::sync::mpsc::Sender<Vec<u8>>,
) -> Option<Vec<u8>> {
    info!(
        session_id,
        classification,
        resource_path = %resource_path,
        "Pipe 1: BlockNotify received"
    );
    let request_id = mint_block_request_id(session_id);
    // Run the blocking Win32 modal on a dedicated thread so the pipe read loop
    // keeps answering Ping/Pong and advancing the heartbeat clock (WR-02).
    std::thread::spawn(move || {
        let dialog_result = crate::dialogs::show_block_dialog_with_result(
            &classification,
            &resource_path,
            &policy_id,
            &reason,
        );
        let msg = match dialog_result {
            crate::dialogs::BlockDialogResult::Confirmed => Pipe1UiMsg::UserConfirmed {
                request_id,
                justification: String::new(),
            },
            crate::dialogs::BlockDialogResult::Close => Pipe1UiMsg::UserCancelled { request_id },
        };
        if let Some(bytes) = serialize_response(&msg, session_id, "BlockNotify response") {
            // If the read loop has exited, the receiver is dropped and the send
            // fails harmlessly — the pipe is being torn down anyway.
            let _ = dialog_tx.send(bytes);
        }
    });
    None
}

/// Handles an `OverrideRequest` message by running the modal dialog off the
/// read loop and delivering the response over `dialog_tx` (WR-02).
///
/// Returns `None` immediately so the read loop never blocks on the modal; the
/// spawned thread sends the serialised response once the user decides.
fn handle_override_request(
    msg: Pipe1AgentMsg,
    session_id: u32,
    dialog_tx: std::sync::mpsc::Sender<Vec<u8>>,
) -> Option<Vec<u8>> {
    let Pipe1AgentMsg::OverrideRequest {
        request_id,
        reason,
        classification,
        resource_path,
        ..
    } = msg
    else {
        error!(session_id, "Pipe 1: expected OverrideRequest");
        return None;
    };

    info!(session_id, request_id, "Pipe 1: OverrideRequest received");
    // Run the blocking Win32 modal on a dedicated thread so the pipe read loop
    // keeps answering Ping/Pong and advancing the heartbeat clock (WR-02).
    std::thread::spawn(move || {
        let result = crate::dialogs::override_request::show_override_dialog(
            &classification,
            &resource_path,
            &reason,
        );
        let msg = match result {
            crate::dialogs::override_request::OverrideDialogResult::Approved { justification } => {
                info!(
                    session_id,
                    request_id,
                    justification = %justification,
                    "override approved by user"
                );
                Pipe1UiMsg::UserConfirmed {
                    request_id,
                    justification,
                }
            }
            crate::dialogs::override_request::OverrideDialogResult::Cancelled => {
                info!(session_id, request_id, "override cancelled by user");
                Pipe1UiMsg::UserCancelled { request_id }
            }
        };
        if let Some(bytes) = serialize_response(&msg, session_id, "override response") {
            let _ = dialog_tx.send(bytes);
        }
    });
    None
}

/// Handles a `PasswordDialog` message and returns the user's response.
fn handle_password_dialog(request_id: String, session_id: u32) -> Option<Vec<u8>> {
    info!(session_id, request_id, "Pipe 1: PasswordDialog received");
    let msg = match crate::dialogs::stop_password::show_password_dialog(&request_id) {
        Ok(m) => m,
        Err(e) => {
            error!(session_id, request_id, error = %e, "password dialog failed");
            Pipe1UiMsg::PasswordCancel { request_id }
        }
    };
    serialize_response(&msg, session_id, "password message")
}

/// Handles a `Ping` message by sending a `Pong` response directly.
fn handle_ping(session_id: u32, pipe: HANDLE) {
    debug!(session_id, "Pipe 1: Ping received — sending Pong");
    let pong = Pipe1UiMsg::Pong;
    if let Ok(json) = serde_json::to_vec(&pong) {
        if write_frame(pipe, &json).is_err() {
            debug!(session_id, "Pipe 1: failed to write Pong");
        }
    }
}

/// Handles an incoming agent message and returns an optional response.
///
/// `BlockNotify` and `OverrideRequest` are modal and are dispatched off-thread
/// via `dialog_tx` (WR-02); they return `None` here and the read loop writes
/// their responses once the dialog resolves. All other messages are handled
/// inline and may return a serialised response to write immediately.
fn handle_agent_msg(
    msg: Pipe1AgentMsg,
    session_id: u32,
    pipe: HANDLE,
    dialog_tx: &std::sync::mpsc::Sender<Vec<u8>>,
) -> Option<Vec<u8>> {
    match msg {
        Pipe1AgentMsg::BlockNotify {
            reason,
            classification,
            resource_path,
            policy_id,
        } => handle_block_notify(
            reason,
            classification,
            resource_path,
            policy_id,
            session_id,
            dialog_tx.clone(),
        ),
        Pipe1AgentMsg::OverrideRequest { .. } => {
            handle_override_request(msg, session_id, dialog_tx.clone())
        }
        Pipe1AgentMsg::ClipboardRead { request_id } => {
            info!(session_id, request_id, "Pipe 1: ClipboardRead received");
            let msg = handle_clipboard_read(request_id, session_id)?;
            serialize_response(&msg, session_id, "ClipboardData")
        }
        Pipe1AgentMsg::PasswordDialog { request_id } => {
            handle_password_dialog(request_id, session_id)
        }
        Pipe1AgentMsg::Ping => {
            handle_ping(session_id, pipe);
            None
        }
        // Approval outcomes are server-originated notifications: the agent has
        // already cached the granted token (or recorded the rejection). The UI
        // surfaces the outcome via structured logging rather than a blocking
        // modal — popping a modal dialog inside the pipe read loop would stall
        // heartbeat responses and trip the agent's UI watchdog. No response is
        // sent back to the agent (WR-01: previously these frames failed to
        // deserialize and were silently dropped).
        Pipe1AgentMsg::ApprovalGranted {
            request_id,
            token: _,
            valid_until,
        } => {
            info!(
                session_id,
                request_id,
                valid_until = %valid_until,
                "Pipe 1: override approval granted by server"
            );
            None
        }
        Pipe1AgentMsg::ApprovalRejected { request_id, reason } => {
            info!(
                session_id,
                request_id,
                reason = ?reason,
                "Pipe 1: override approval rejected by server"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mint_block_request_id;
    use std::collections::HashSet;

    /// WR-10: every `BlockNotify` must receive a unique `request_id` so
    /// concurrent blocks do not produce colliding `UserConfirmed`/
    /// `UserCancelled` responses.
    #[test]
    fn block_request_ids_are_unique_per_event() {
        let session_id = 7;
        let mut seen = HashSet::new();
        for _ in 0..256 {
            let id = mint_block_request_id(session_id);
            assert!(
                id.starts_with("block-7-"),
                "request_id must keep the block-<session>-<seq> shape, got: {id}"
            );
            assert!(seen.insert(id.clone()), "duplicate request_id: {id}");
        }
    }
}
