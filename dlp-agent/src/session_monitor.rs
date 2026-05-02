//! Session change handler — detects logon/logoff and manages UI lifetimes (T-36).
//!
//! ## Responsibilities
//!
//! - Detects when users log on and spawns a DLP UI in the new session.
//! - Detects when a user logs off and terminates the associated UI.
//! - Runs a dedicated std thread that periodically calls `WTSEnumerateSessionsW`
//!   to detect session state changes.  This avoids the need for a message-only
//!   window, which is difficult to set up correctly in a Windows Service.
//!
//! ## Session state tracking
//!
//! The monitor keeps a `HashSet<u32>` of session IDs known to have a UI.
//! On each poll it compares the current active sessions against this set:
//! - New session ID → spawn UI.
//! - Missing session ID → UI_CLOSING_SEQUENCE + kill.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use parking_lot::Mutex;
use tracing::{debug, error, info, warn};

use crate::ipc::messages::Pipe2AgentMsg;
use crate::ipc::pipe2::BROADCASTER;
use crate::ui_spawner::{self, kill_session, ui_binary};

/// Polling interval between session state checks.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Grace period between sending UI_CLOSING_SEQUENCE and force-killing.
const GRACEFUL_WAIT: Duration = Duration::from_secs(5);

/// Starts the session monitor on a background std thread.
pub fn start() -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("session-monitor".into())
        .spawn(|| {
            if let Err(e) = run() {
                error!(error = %e, "Session monitor exited with error");
            }
        })
        .expect("session monitor thread must spawn")
}

fn run() -> anyhow::Result<()> {
    // Session IDs that currently have a live UI process.
    let active_sessions: Arc<Mutex<HashSet<u32>>> = Arc::new(Mutex::new(HashSet::new()));

    // Seed with sessions that already have UIs at startup.
    if ui_binary().is_some() {
        match ui_spawner::init() {
            Ok(()) => {
                // Walk UI_HANDLES to populate active_sessions.
                // Since UI_HANDLES is a static, we query it directly.
                // The init() call already spawned UIs — capture their session IDs.
                // We use a snapshot approach: enumerate sessions after init.
                let sessions = enumerate_active_sessions().unwrap_or_default();
                let mut set = active_sessions.lock();
                for sid in sessions {
                    set.insert(sid);
                }
                info!(count = set.len(), "Session monitor: initialised");
            }
            Err(e) => {
                warn!(error = %e, "Session monitor: failed to init UI spawner");
            }
        }
    }

    // Tokio runtime on this std thread for async operations.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Tokio current-thread runtime must succeed");

    rt.block_on(async {
        let active_sessions_clone = active_sessions.clone();
        session_loop(active_sessions_clone).await;
    });

    Ok(())
}

/// The main session-polling loop.
async fn session_loop(active_sessions: Arc<Mutex<HashSet<u32>>>) {
    let mut interval = tokio::time::interval(POLL_INTERVAL);

    loop {
        interval.tick().await;

        let current_sessions = match enumerate_active_sessions() {
            Ok(s) => s,
            Err(e) => {
                debug!(error = %e, "Session monitor: failed to enumerate sessions");
                continue;
            }
        };

        let current = HashSet::from_iter(current_sessions.clone());
        let mut active = active_sessions.lock();

        // Check liveness of existing UIs and respawn any that crashed while
        // the session is still active.
        let active_snapshot: Vec<u32> = active.iter().copied().collect();
        for session_id in active_snapshot {
            if !ui_spawner::is_ui_alive(session_id) {
                warn!(session_id, "Session monitor: UI process died — respawning");
                active.remove(&session_id);
                let _ = handle_session_start(session_id);
                active.insert(session_id);
            }
        }

        // Sessions that disappeared → user logged off.
        let gone: Vec<u32> = active.difference(&current).copied().collect();
        for session_id in gone {
            info!(
                session_id,
                "Session monitor: session ended — cleaning up UI"
            );
            let _ = handle_session_end(session_id);
            active.remove(&session_id);
        }

        // New sessions → user logged on.
        let arrived: Vec<u32> = current.difference(&active).copied().collect();
        for session_id in arrived {
            info!(
                session_id,
                "Session monitor: new session detected — spawning UI"
            );
            let _ = handle_session_start(session_id);
            active.insert(session_id);
        }
    }
}

/// Handles a new session by spawning a UI process and registering
/// the session's user identity in the global map.
fn handle_session_start(session_id: u32) -> anyhow::Result<()> {
    // Register the session's user identity for audit attribution.
    if let Some(map) = crate::session_identity::global_map() {
        if let Err(e) = map.add_session(session_id) {
            debug!(
                session_id,
                error = %e,
                "Session monitor: identity resolution failed"
            );
        }
    }

    let binary = ui_binary().context("UI binary not configured")?;

    match ui_spawner::spawn_ui_in_session(session_id, &binary) {
        Ok(handle) => {
            info!(session_id, pid = handle.pid, "Session monitor: UI spawned");
            ui_spawner::insert_handle(session_id, handle);
            Ok(())
        }
        Err(e) => {
            warn!(session_id, error = %e, "Session monitor: failed to spawn UI");
            Err(e)
        }
    }
}

/// Handles a session ending by sending UI_CLOSING_SEQUENCE, force-killing,
/// and removing the session's identity from the global map.
fn handle_session_end(session_id: u32) -> anyhow::Result<()> {
    // Step 1: broadcast UI_CLOSING_SEQUENCE to the session's UI.
    let msg = Pipe2AgentMsg::UiClosingSequence { session_id };
    let count = BROADCASTER.broadcast(&msg);
    info!(
        session_id,
        clients_notified = count,
        "Session monitor: UI_CLOSING_SEQUENCE sent"
    );

    // Step 2: wait for graceful shutdown.
    std::thread::sleep(GRACEFUL_WAIT);

    // Step 3: force-kill any remaining UI process in this session.
    kill_session(session_id);
    info!(session_id, "Session monitor: UI process terminated");

    // Step 4: remove the session's identity from the global map.
    if let Some(map) = crate::session_identity::global_map() {
        map.remove_session(session_id);
    }

    Ok(())
}

/// Enumerates all active (WTSActive) session IDs.
fn enumerate_active_sessions() -> anyhow::Result<Vec<u32>> {
    use windows::Win32::System::RemoteDesktop::{
        WTSActive, WTSEnumerateSessionsW, WTSFreeMemory, WTS_CURRENT_SERVER_HANDLE,
        WTS_SESSION_INFOW,
    };

    unsafe {
        let mut session_info: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
        let mut session_count: u32 = 0;

        let result = WTSEnumerateSessionsW(
            Some(WTS_CURRENT_SERVER_HANDLE),
            0,
            1,
            &mut session_info,
            &mut session_count,
        );

        if result.is_err() {
            return Err(anyhow::anyhow!("WTSEnumerateSessionsW failed"));
        }

        if session_info.is_null() {
            return Ok(vec![]);
        }

        let mut ids = Vec::with_capacity(session_count as usize);
        let slice = std::slice::from_raw_parts(session_info, session_count as usize);

        for si in slice {
            if si.State == WTSActive {
                ids.push(si.SessionId);
            }
        }

        WTSFreeMemory(session_info.cast());
        Ok(ids)
    }
}
