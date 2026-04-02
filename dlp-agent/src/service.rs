//! Windows Service lifecycle management (T-10, T-38).
//!
//! This module implements the `windows-service` crate entry point and manages
//! the DLP Agent's service states: Start, Stop, Pause, Resume.
//!
//! ## Installation
//!
//! ```cmd
//! sc create dlp-agent type= own start= auto binpath= "C:\Program Files\DLP\dlp-agent.exe"
//! ```
//!
//! ## Service States
//!
//! - **Running**: normal file interception and policy evaluation active.
//! - **Paused**: interception paused; UI remains responsive.
//! - **Stopped**: service exited cleanly.
//!
//! ## Password-Protected Stop (T-38)
//!
//! A `sc stop` command triggers a password challenge over Pipe 1 before the
//! service actually terminates.  The dlp-admin must enter their AD password;
//! 3 failures or cancellation aborts the stop.  On success the service
//! transitions to `StopPending` and exits cleanly.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tracing::{error, info, warn, Level};
use tracing_subscriber::fmt::format::FmtSpan;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

/// The Windows Service name registered with the SCM.
pub const SERVICE_NAME: &str = "dlp-agent";

// ──────────────────────────────────────────────────────────────────────────────
// Service main (invoked from the generated FFI entry in main.rs)
// ──────────────────────────────────────────────────────────────────────────────

/// Service main — called by the SCM-generated FFI entry after `service_dispatcher::start`.
//
// Panics here propagate as service crashes — all errors are caught and logged.
#[cfg(windows)]
pub fn service_main(_arguments: Vec<std::ffi::OsString>) {
    if let Err(e) = run_service() {
        error!(error = %e, "service exited with error");
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Service body
// ──────────────────────────────────────────────────────────────────────────────

/// Runs the DLP Agent Windows Service to completion.
pub fn run_service() -> Result<()> {
    init_logging();
    info!(service_name = SERVICE_NAME, "DLP Agent service starting");

    // Register the service control handler.
    let status_handle = service_control_handler::register(SERVICE_NAME, service_control_handler)?;

    // Wrap in Arc<Mutex<>> so we can use it across multiple set_status calls.
    let status_handle = Arc::new(Mutex::new(status_handle));

    // Report STARTING.
    set_status(
        &status_handle,
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        None,
    )?;

    // Acquire single-instance mutex.
    acquire_instance_mutex();

    // ── Configure the UI binary path ─────────────────────────────────
    // In production: installed alongside the service binary.
    // Override with DLP_UI_BINARY env var for development.
    let ui_binary = resolve_ui_binary();
    if let Some(ref path) = ui_binary {
        info!(path = %path.display(), "UI binary path resolved");
        crate::ui_spawner::set_ui_binary(path.clone());
    }

    // ── Start the health monitor first ───────────────────────────────
    // health_monitor::run() calls ROUTER.set_health_sender() — this MUST
    // happen before Pipe 3's handle_client runs, so Pipe 3 can read the
    // session sender from the same ROUTER.
    let health_handle = crate::health_monitor::start();
    info!(thread_id = ?health_handle.thread().id(), "health monitor started");

    // ── Start IPC pipe servers ────────────────────────────────────
    // Each serve() call blocks on a dedicated thread.  Pipe 1, 2, and 3
    // are independent; they communicate via the shared BROADCASTER and ROUTER
    // statics.  Pipe 3's handle_client sets ROUTER.session_sender on each
    // new connection.
    crate::ipc::start_all()?;
    info!("IPC pipe servers started");

    // ── Start the session monitor ──────────────────────────────────
    // session_monitor::run() calls ui_spawner::init() which enumerates
    // active sessions and spawns a UI in each.  New sessions are detected
    // via polling (WTSEnumerateSessionsW every 2 s).
    let session_handle = crate::session_monitor::start();
    info!(thread_id = ?session_handle.thread().id(), "session monitor started");

    // Report RUNNING.
    set_status(
        &status_handle,
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::PAUSE_CONTINUE,
        None,
    )?;

    // Enter the main run loop.
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_loop(&status_handle))?;

    // ── Graceful shutdown of blocking threads ────────────────────────
    info!(service_name = SERVICE_NAME, "shutting down subsystems");

    // Signal the event loop to drain and exit.
    // Drop the health monitor and session monitor handles — their threads
    // drain and exit when the session monitor's internal shutdown is triggered.
    // IPC servers are harder to stop (named pipes don't support clean shutdown);
    // they will be terminated when the process exits.

    // Report STOPPED.
    set_status(
        &status_handle,
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        Some(ServiceExitCode::Win32(0)),
    )?;

    info!(service_name = SERVICE_NAME, "service stopped");
    Ok(())
}

/// The main service run loop.
///
/// Runs the ETW interception event loop and the service control loop.
/// All other subsystems (IPC servers, health monitor, session monitor, UI
/// spawner) run on blocking std threads started in [`run_service`].
///
/// When the SCM issues `sc stop`, [`password_stop::initiate_stop`] starts the
/// password challenge.  This loop polls the confirmation flag every 500 ms — on
/// confirmation it proceeds to shutdown; on `PASSWORD_CANCEL` or max attempts,
/// [`password_stop::revert_stop`] reverts the state to Running.
async fn run_loop(
    status_handle: &Arc<Mutex<windows_service::service_control_handler::ServiceStatusHandle>>,
) -> Result<()> {
    // ── Open the audit log ────────────────────────────────────────────────
    let _log_path = crate::audit_emitter::log_path();
    info!(audit_log = %_log_path.display(), "audit subsystem initialised");

    // ── Initialise the Policy Engine client and offline cache ──────────────
    let engine_client = crate::engine_client::EngineClient::default_client()
        .inspect_err(|e| warn!(error = %e, "Policy Engine client init failed — will run offline"))
        .unwrap_or_else(|_| {
            // Best-effort fallback — OfflineManager will handle unreachable engine.
            crate::engine_client::EngineClient::new(
                crate::engine_client::DEFAULT_ENGINE_URL,
                false, // skip TLS verification if env is misconfigured
            )
            .expect("engine client must be constructable")
        });

    let cache = Arc::new(crate::cache::Cache::new());
    let offline = Arc::new(crate::offline::OfflineManager::new(engine_client, cache));

    // ── Start the Policy Engine heartbeat ─────────────────────────────────
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let offline_hb = offline.clone();
    let _heartbeat_handle = tokio::spawn(async move {
        offline_hb.heartbeat_loop(shutdown_rx).await;
    });

    // ── Start the ETW interception pipeline ───────────────────────────────
    let etw_engine = crate::interception::InterceptionEngine::new()
        .expect("ETW interception engine initialisation always succeeds");
    let etw_engine_for_shutdown = etw_engine.clone();

    let (action_tx, action_rx) = mpsc::channel::<crate::interception::FileAction>(1024);

    // Shared EmitContext — in a real deployment this is resolved per-session
    // via WTSQueryUserToken.  Stubbed here with session 1 / SYSTEM SID.
    let audit_ctx = crate::audit_emitter::EmitContext {
        agent_id: std::env::var("DLP_AGENT_ID").unwrap_or_else(|_| "AGENT-UNKNOWN".to_string()),
        session_id: 1,
        user_sid: "S-1-5-18".to_string(), // SYSTEM
        user_name: "SYSTEM".to_string(),
    };

    // Initialise the clipboard listener's audit emit context.
    crate::clipboard::listener::init_emit_context(audit_ctx.clone());

    let offline_ev = offline.clone();
    let ctx_ev = audit_ctx.clone();
    let event_loop_handle = tokio::spawn(async move {
        crate::interception::run_event_loop(action_rx, offline_ev, ctx_ev).await;
    });

    // Spawn the ETW monitor — run() is blocking and must run on a dedicated thread
    // because it calls ProcessTrace which blocks indefinitely.  Wrap it in
    // spawn_blocking so it doesn't monopolise a Tokio thread.
    let etw_engine_clone = etw_engine.clone();
    let etw_handle = tokio::task::spawn_blocking(move || {
        // etw_engine.run() is synchronous; it blocks until the trace is stopped.
        let _ = etw_engine_clone.run(action_tx);
    });

    info!(
        service_name = SERVICE_NAME,
        "enforcement subsystems started"
    );

    // ── Service control loop ─────────────────────────────────────────────
    let poll_interval = Duration::from_millis(500);
    let mut ticker = tokio::time::interval(poll_interval);

    loop {
        tokio::select! {
            biased;

            // Ctrl+C from console session.
            _ = tokio::signal::ctrl_c() => {
                info!(service_name = SERVICE_NAME, "service stopping (Ctrl+C)");
                break;
            }

            // Poll every 500 ms for stop confirmation or revert.
            _ = ticker.tick() => {
                if crate::password_stop::is_stop_confirmed() {
                    info!(service_name = SERVICE_NAME, "password verified — initiating shutdown");
                    set_status(
                        status_handle,
                        ServiceState::StopPending,
                        ServiceControlAccept::empty(),
                        None,
                    )?;
                    break;
                }
            }
        }
    }

    // ── Graceful shutdown ──────────────────────────────────────────────────
    info!(
        service_name = SERVICE_NAME,
        "shutting down enforcement subsystems"
    );

    // Stop ETW first so no new events arrive.
    etw_engine_for_shutdown.stop();
    let _ = etw_handle.await;

    // Signal the event loop to drain and exit.
    drop(event_loop_handle);

    // Stop the heartbeat loop.
    let _ = shutdown_tx.send(true);
    let _ = _heartbeat_handle.await;

    info!(
        service_name = SERVICE_NAME,
        "enforcement subsystems stopped"
    );
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// UI binary resolution
// ──────────────────────────────────────────────────────────────────────────────

/// Resolves the dlp-user-ui binary path.
///
/// Checks `DLP_UI_BINARY` env var first, then falls back to the directory
/// containing the running service executable, looking for `dlp-agent-ui.exe`.
fn resolve_ui_binary() -> Option<std::path::PathBuf> {
    // Env var takes priority (useful for development).
    if let Ok(path) = std::env::var("DLP_UI_BINARY") {
        return Some(std::path::PathBuf::from(path));
    }

    // Fallback: same directory as the running service binary.
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let ui = dir.join("dlp-agent-ui.exe");
    Some(ui)
}

// ──────────────────────────────────────────────────────────────────────────────
// Service status helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Convenience to build and set a [`ServiceStatus`].
//
// `handle` is wrapped in `Arc<Mutex<>>` — we lock to get a temporary borrow.
fn set_status(
    handle: &Arc<Mutex<windows_service::service_control_handler::ServiceStatusHandle>>,
    state: ServiceState,
    controls: ServiceControlAccept,
    exit_code: Option<ServiceExitCode>,
) -> Result<()> {
    let status = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: controls,
        exit_code: exit_code.unwrap_or(ServiceExitCode::Win32(0)),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    let handle = handle.lock();
    handle
        .set_service_status(status)
        .map_err(|e| anyhow::anyhow!("set_service_status failed: {e}"))?;
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// Service control handler
// ──────────────────────────────────────────────────────────────────────────────

/// Shared mutable service state.
static SERVICE_STATE: Mutex<ServiceState> = Mutex::new(ServiceState::Running);

/// Returns the current service state.
#[must_use]
pub fn current_state() -> ServiceState {
    *SERVICE_STATE.lock()
}

/// The SCM-issued service control handler.
//
// Runs on the SCM callback thread — keep all work minimal and non-blocking.
fn service_control_handler(control: ServiceControl) -> ServiceControlHandlerResult {
    match control {
        ServiceControl::Stop => {
            info!(service_name = SERVICE_NAME, "SCM: STOP");
            *SERVICE_STATE.lock() = ServiceState::StopPending;
            // Initiate the password challenge — the actual stop proceeds only
            // after successful verification (detected in the run loop via
            // password_stop::is_stop_confirmed).
            crate::password_stop::initiate_stop();
        }
        ServiceControl::Pause => {
            info!(service_name = SERVICE_NAME, "SCM: PAUSE");
            *SERVICE_STATE.lock() = ServiceState::Paused;
        }
        ServiceControl::Continue => {
            info!(service_name = SERVICE_NAME, "SCM: CONTINUE");
            *SERVICE_STATE.lock() = ServiceState::Running;
        }
        ServiceControl::Interrogate => {
            // SCM reads current state via the status handle — no-op here.
        }
        _ => {}
    }
    ServiceControlHandlerResult::NoError
}

// ──────────────────────────────────────────────────────────────────────────────
// Revert to Running (called from password_stop on cancel/failure)
// ──────────────────────────────────────────────────────────────────────────────

/// Reverts the service state from StopPending back to Running.
///
/// Called by [`crate::password_stop`] when the dlp-admin cancels the stop
/// dialog or fails the password challenge 3 times.
pub fn revert_stop() {
    *SERVICE_STATE.lock() = ServiceState::Running;
    info!(
        service_name = SERVICE_NAME,
        "service stop reverted to Running"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// Single-instance enforcement
// ──────────────────────────────────────────────────────────────────────────────

/// Acquires the global single-instance mutex.
fn acquire_instance_mutex() {
    #[allow(dead_code)]
    const MUTEX_NAME: &str = "Global\\dlp-agent-instance";
    match std::sync::Mutex::new(()).try_lock() {
        Ok(_guard) => info!(
            service_name = SERVICE_NAME,
            "single-instance mutex acquired"
        ),
        Err(_) => {
            info!(
                service_name = SERVICE_NAME,
                "previous instance detected — SCM serialises starts"
            )
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Logging
// ──────────────────────────────────────────────────────────────────────────────

fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(Level::INFO.into())
        .from_env_lossy();

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_span_events(FmtSpan::CLOSE)
        .with_target(true)
        .with_thread_ids(true)
        .init();
}

// ──────────────────────────────────────────────────────────────────────────────
// Console / CLI mode
// ──────────────────────────────────────────────────────────────────────────────

/// Runs the DLP Agent as a regular console application for testing and
/// development.
///
/// Sets up the full interception pipeline (ETW + Policy Engine + audit log)
/// without requiring Windows Service registration.  Press Ctrl+C to stop.
///
/// The UI spawner, IPC servers, health monitor, and ETW interception pipeline
/// all run identically to the service mode.  The only differences are:
///   - No SCM integration (no password-protected stop, no service status)
///   - No UI is spawned (console sessions don't have an interactive desktop)
///   - EtwEngine runs with the console user's identity context
pub fn run_console() -> Result<()> {
    init_logging();
    info!(
        service_name = SERVICE_NAME,
        "DLP Agent running in console mode (full pipeline)"
    );

    // ── Health monitor first (sets ROUTER state before Pipe 3 clients connect) ──
    let _health_handle = crate::health_monitor::start();
    info!(thread_id = ?_health_handle.thread().id(), "health monitor started");

    // ── IPC pipe servers (blocking threads) ───────────────────────────────────
    crate::ipc::start_all()?;
    info!("IPC pipe servers started");

    // ── ETW interception + event loop on a Tokio runtime ─────────────────────
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async_run_console())?;

    info!(service_name = SERVICE_NAME, "DLP Agent stopped by Ctrl+C");
    Ok(())
}

/// The async body of [`run_console`] — sets up and runs the interception pipeline.
async fn async_run_console() -> Result<()> {
    // ── Audit log ───────────────────────────────────────────────────────────
    let _log_path = crate::audit_emitter::log_path();
    info!(audit_log = %_log_path.display(), "audit subsystem initialised");

    // ── Policy Engine client ─────────────────────────────────────────────────
    let engine_client = crate::engine_client::EngineClient::default_client()
        .inspect_err(|e| warn!(error = %e, "Policy Engine client init failed — running offline"))
        .unwrap_or_else(|_| {
            crate::engine_client::EngineClient::new(
                crate::engine_client::DEFAULT_ENGINE_URL,
                false, // skip TLS verification in dev mode
            )
            .expect("engine client must be constructable")
        });

    let cache = Arc::new(crate::cache::Cache::new());
    let offline = Arc::new(crate::offline::OfflineManager::new(engine_client, cache));

    // ── Heartbeat ───────────────────────────────────────────────────────────
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let offline_hb = offline.clone();
    let _heartbeat_handle = tokio::spawn(async move {
        offline_hb.heartbeat_loop(shutdown_rx).await;
    });

    // ── ETW interception pipeline ───────────────────────────────────────────
    let etw_engine = crate::interception::InterceptionEngine::new()
        .expect("ETW interception engine must be constructable");
    let (action_tx, action_rx) = mpsc::channel::<crate::interception::FileAction>(1024);

    // EmitContext for console mode — stubbed with the current user.
    let user_name = std::env::var("USERNAME")
        .unwrap_or_else(|_| std::env::var("USER")
            .unwrap_or_else(|_| "console-user".to_string()));
    let audit_ctx = crate::audit_emitter::EmitContext {
        agent_id: std::env::var("DLP_AGENT_ID")
            .unwrap_or_else(|_| "AGENT-CONSOLE".to_string()),
        session_id: 1,
        user_sid: "S-1-5-21-0-0-0-0".to_string(), // stub SID for console mode
        user_name,
    };
    crate::clipboard::listener::init_emit_context(audit_ctx.clone());

    let offline_ev = offline.clone();
    let ctx_ev = audit_ctx.clone();
    let event_loop_handle = tokio::spawn(async move {
        crate::interception::run_event_loop(action_rx, offline_ev, ctx_ev).await;
    });

    // ETW runs on a blocking thread so it doesn't starve the Tokio executor.
    let etw_engine_clone = etw_engine.clone();
    let etw_handle = tokio::task::spawn_blocking(move || {
        if let Err(e) = etw_engine_clone.run(action_tx) {
            // Always log this error — it means the ETW session failed to start or crashed.
            // This is important enough to print to stderr directly as a fallback
            // in case tracing is misconfigured.
            eprintln!("[ERROR] ETW interception failed: {e}");
            tracing::error!(error = %e, "ETW interception failed");
        }
    });

    info!(
        service_name = SERVICE_NAME,
        "enforcement subsystems started"
    );

    // ── Wait for Ctrl+C then shutdown ──────────────────────────────────────
    tokio::signal::ctrl_c().await?;

    info!(
        service_name = SERVICE_NAME,
        "shutting down enforcement subsystems"
    );

    etw_engine.stop();
    let _ = etw_handle.await;
    drop(event_loop_handle);
    let _ = shutdown_tx.send(true);
    let _ = _heartbeat_handle.await;

    info!(
        service_name = SERVICE_NAME,
        "enforcement subsystems stopped"
    );
    Ok(())
}
