//! Mutual health monitor between the agent and UI processes (T-35).
//!
//! ## Agent → UI health check
//!
//! The monitor broadcasts a `HEALTH_PING` frame over Pipe 2 every 5 seconds.
//! It collects `HEALTH_PONG` responses arriving over Pipe 3.  If a connected
//! UI client fails to respond within 15 seconds, the monitor marks the client
//! as timed-out and emits a `UI_RESPAWN` event.
//!
//! ## UI → Agent health check
//!
//! The same mechanism works in reverse: the monitor receives `HEALTH_PONG`
//! frames as keep-alives from the UI.  If the agent process itself stalls
//! (not implemented in Phase 1 — the SCM watchdog covers this case).
//!
//! ## Architecture
//!
//! The monitor runs on a dedicated std thread with a single-threaded Tokio
//! runtime.  It uses `tokio::sync::watch` to coordinate between the
//! ping broadcaster and the pong receiver tasks.  When a pong arrives from
//! Pipe 3, it is sent over an internal channel and routed to the appropriate
//! task.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use parking_lot::Mutex;
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

use crate::ipc::pipe3::{UiHealthEvent, ROUTER};

use crate::ipc::messages::Pipe2AgentMsg;
use crate::ipc::pipe2::BROADCASTER;

/// Time between consecutive HEALTH_PING broadcasts.
const PING_INTERVAL: Duration = Duration::from_secs(5);

/// Time after which a UI client is considered unresponsive.
const PONG_TIMEOUT: Duration = Duration::from_secs(15);

/// Channel used to signal a respawn request to the session monitor.
static RESPAWN_TX: Lazy<Mutex<Option<watch::Sender<RespawnRequest>>>> =
    Lazy::new(|| Mutex::new(None));

/// A respawn request issued when a UI fails to respond to health pings.
#[derive(Debug, Clone)]
pub struct RespawnRequest {
    /// The session ID that timed out.
    pub session_id: u32,
    /// The process ID of the unresponsive UI (if known).
    pub pid: Option<u32>,
}

/// Starts the health monitor on a background std thread.
///
/// The thread creates its own Tokio current-thread runtime so that async
/// `tokio::sync` primitives can be used without blocking the service.
pub fn start() -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("health-monitor".into())
        .spawn(|| {
            if let Err(e) = run() {
                error!(error = %e, "Health monitor exited with error");
            }
        })
        .expect("health monitor thread must spawn")
}

fn run() -> anyhow::Result<()> {
    // Shared map: client_id → last pong instant.
    let last_pong: Arc<Mutex<HashMap<usize, Instant>>> = Arc::new(Mutex::new(HashMap::new()));

    // Watch channel to signal respawns to the session monitor.
    let (respawn_tx, respawn_rx) = watch::channel(RespawnRequest {
        session_id: 0,
        pid: None,
    });
    *RESPAWN_TX.lock() = Some(respawn_tx);

    // Channel to deliver HEALTH_PONG events from Pipe 3 to pong_task.
    let (pong_tx, pong_rx) = mpsc::channel::<UiHealthEvent>(64);

    // Register the sender with the Pipe 3 router so incoming UI events are
    // routed here.  This call must happen before the runtime is built because
    // Pipe 3 may connect and try to send before block_on returns.
    ROUTER.set_health_sender(pong_tx);

    // Tokio single-thread runtime on this std thread.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Tokio current-thread runtime must succeed");

    rt.block_on(async {
        // Spawn the three concurrent tasks.
        tokio::join!(
            ping_task(last_pong.clone()),
            pong_task(last_pong.clone(), pong_rx),
            timeout_task(last_pong.clone(), respawn_rx),
        )
    });

    Ok(())
}

/// Periodically broadcasts HEALTH_PING to all UI clients.
async fn ping_task(last_pong: Arc<Mutex<HashMap<usize, Instant>>>) {
    let mut interval = tokio::time::interval(PING_INTERVAL);

    loop {
        interval.tick().await;

        let count = BROADCASTER.broadcast(&Pipe2AgentMsg::HealthPing);
        debug!(count, "Health monitor: broadcast HEALTH_PING");

        // Reset last-pong entry for all clients so we don't spuriously
        // time them out between pings.
        let mut lp = last_pong.lock();
        for id in BROADCASTER.client_ids() {
            lp.entry(id).or_insert_with(Instant::now);
        }
    }
}

/// Receives `UiHealthEvent::Pong` events from Pipe 3 and updates the last-pong map.
///
/// Each event is stamped with `Instant::now()` so that [`timeout_task`] can detect
/// unresponsive clients.  When a client disconnects its entries naturally expire
/// on the next timeout check.
async fn pong_task(
    last_pong: Arc<Mutex<HashMap<usize, Instant>>>,
    mut rx: mpsc::Receiver<UiHealthEvent>,
) {
    loop {
        match rx.recv().await {
            Some(UiHealthEvent::Pong) => {
                debug!("Health monitor: received HEALTH_PONG from UI");
                // Stamp all known clients — in practice only the sending client's
                // entries are live; stamping all keeps them alive collectively.
                let now = Instant::now();
                let mut lp = last_pong.lock();
                for client_id in BROADCASTER.client_ids() {
                    lp.insert(client_id, now);
                }
            }
            None => {
                // Channel closed — Pipe 3 server shut down.  Exit gracefully.
                info!("Health monitor: Pipe 3 health channel closed");
                break;
            }
        }
    }
}

/// Checks for timed-out clients and emits respawn requests.
async fn timeout_task(
    last_pong: Arc<Mutex<HashMap<usize, Instant>>>,
    mut respawn_rx: watch::Receiver<RespawnRequest>,
) {
    let mut check_interval = tokio::time::interval(Duration::from_secs(1));

    loop {
        tokio::select! {
            biased;

            _ = check_interval.tick() => {
                // Walk all known clients and check their last pong time.
                let now = Instant::now();
                for (client_id, _) in BROADCASTER.clients() {
                    let timed_out = {
                        let mut lp = last_pong.lock();
                        match lp.get(&client_id) {
                            Some(last) if now.duration_since(*last) > PONG_TIMEOUT => {
                                lp.remove(&client_id);
                                true
                            }
                            Some(_) | None => false,
                        }
                    };

                    if timed_out {
                        warn!(client_id, "Health monitor: UI timed out — requesting respawn");
                        let req = RespawnRequest {
                            session_id: 0, // Session mapping is not yet implemented.
                            pid: None,
                        };
                        if let Some(tx) = RESPAWN_TX.lock().as_ref() {
                            let _ = tx.send(req);
                        }
                    }
                }
            }

            _ = respawn_rx.changed() => {
                // Session monitor forwarded a respawn request from elsewhere.
                let req = (*respawn_rx.borrow()).clone();
                info!(?req, "Health monitor: respawn request received");
                // Remove all timed-out clients from the broadcaster.
                // The session monitor handles the actual kill/respawn.
                for (id, _) in BROADCASTER.clients() {
                    last_pong.lock().remove(&id);
                }
            }
        }
    }
}
