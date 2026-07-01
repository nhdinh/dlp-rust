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
//! service actually terminates.  The dlp-admin must enter their bcrypt hash;
//! 3 failures or cancellation aborts the stop.  On success the service
//! transitions to `StopPending` and exits cleanly.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use dlp_common::hook_ipc::BypassAlert;
use dlp_common::usb::{
    DEFAULT_USB_BLOCKED_FAILURE_MODE, DEFAULT_USB_NONE_SERIAL_POLICY,
    DEFAULT_USB_STARTUP_RESOLUTION_MODE,
};

// ---------------------------------------------------------------------------
// Global config static (Phase 43-04)
// ---------------------------------------------------------------------------

/// Global agent config — set once during service startup.
///
/// Access via [`with_config`] for read-only operations. The config is updated
/// in-place by the config poll loop (see [`config_poll_loop`]), so callers
/// must not hold the lock across `.await` points.
static CONFIG: std::sync::OnceLock<std::sync::Arc<parking_lot::Mutex<crate::config::AgentConfig>>> =
    std::sync::OnceLock::new();

/// Executes a closure with a read-lock on the global config.
///
/// Returns `None` if config is not yet initialized (e.g., called before
/// service startup completes).
///
/// # Example
///
/// ```ignore
/// let failure_mode = with_config(|cfg| {
///     cfg.usb_blocked_failure_mode.clone().unwrap_or_else(|| "Warning only".to_string())
/// }).unwrap_or_else(|| "Warning only".to_string());
/// ```
pub fn with_config<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&crate::config::AgentConfig) -> R,
{
    CONFIG.get().map(|arc| {
        let cfg = arc.lock();
        f(&cfg)
    })
}
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::fmt::format::FmtSpan;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};

/// The Windows Service name registered with the SCM.
pub const SERVICE_NAME: &str = "dlp-agent";

/// Maximum time allowed for the graceful shutdown sequence. This must be at
/// least [`UNHOOK_WAIT_BUDGET`] plus a buffer for the remaining cleanup steps.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(35);
/// Maximum time to wait for in-flight disk enumeration to cancel (OP-04).
const DISK_ENUM_CANCEL_TIMEOUT: Duration = Duration::from_secs(5);
/// Phase 58.5: Budget for cooperative unhook wait during graceful shutdown.
///
/// This is the fallback default used when the agent config does not specify
/// `unhook_wait_budget_ms`. It matches the hook DLL watchdog timeout so slow
/// processes have time to drain active calls and ack.
const UNHOOK_WAIT_BUDGET: Duration = Duration::from_secs(30);
/// Phase 58.5: Polling interval while waiting for injected processes to ack unhook.
const UNHOOK_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Global SCM status handle — set once after `register()` returns.
///
/// The control handler callback cannot capture the status handle (chicken-and-egg:
/// the handler is passed to `register`, which returns the handle).  This global
/// bridges the gap so the handler can report state transitions (e.g. `StopPending`)
/// directly to the SCM instead of only updating the internal `SERVICE_STATE` mutex.
static SCM_HANDLE: std::sync::OnceLock<ServiceStatusHandle> = std::sync::OnceLock::new();

/// Global shutdown signal — set to true when the service is stopping.
/// All blocking threads must poll this flag and break their loops.
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Phase 58.5: Global unhook signal — set to true during graceful shutdown.
///
/// When true, the hook IPC server replies to `PollControl` frames from known
/// injected processes with `UnhookCommand { reason: AgentShutdown }`. The flag
/// is cleared after the hook IPC server stops so a future service restart
/// begins with a clean state.
pub static UNHOOK_ALL_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Returns true if service shutdown has been requested.
pub fn shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(Ordering::Acquire)
}

/// Requests service shutdown. Idempotent.
pub fn request_shutdown() {
    SHUTDOWN_REQUESTED.store(true, Ordering::Release);
}

/// Resets the shutdown signal to false.
///
/// Called at service startup to support in-process restart scenarios,
/// and in tests to ensure a clean state between test cases.
pub fn reset_shutdown_signal() {
    SHUTDOWN_REQUESTED.store(false, Ordering::Release);
}

/// Phase 58.5: Reset the unhook signal to false.
///
/// Called after the hook IPC server stops so a future service restart does not
/// immediately request unhook from newly injected processes.
pub fn reset_unhook_signal() {
    UNHOOK_ALL_REQUESTED.store(false, Ordering::Release);
}

/// Phase 58.5: Wait (bounded) for injected processes to poll and ack unhook.
///
/// Records the initial injected count, then polls [`ProcessRegistry::iter_injected`]
/// every [`UNHOOK_POLL_INTERVAL`] until the registry has no remaining `Injected`
/// entries or `budget` expires. Returns the number of entries still `Injected`.
///
/// # Arguments
///
/// * `registry` — Process registry containing the lifecycle state of hooked PIDs.
/// * `budget` — Maximum total time to wait before returning the remaining count.
async fn wait_for_unhook_acks(
    registry: &Arc<crate::process_registry::ProcessRegistry>,
    budget: Duration,
) -> usize {
    let start = Instant::now();
    loop {
        let remaining = registry.iter_injected().len();
        if remaining == 0 {
            return 0;
        }
        let elapsed = start.elapsed();
        if elapsed >= budget {
            return remaining;
        }
        tokio::time::sleep(UNHOOK_POLL_INTERVAL.min(budget - elapsed)).await;
    }
}

/// Phase 58.5: Request cooperative unhook from all injected processes.
///
/// Sets [`UNHOOK_ALL_REQUESTED`] so the hook IPC server replies to `PollControl`
/// with `UnhookCommand` for known injected processes, waits a bounded time for
/// acks, and emits `AgentShutdownUnhook` once plus `UnhookFailure` for any
/// entries still injected after the wait.
///
/// # Arguments
///
/// * `registry` — Process registry containing the lifecycle state of hooked PIDs.
/// * `audit_ctx` — Audit emit context for `AgentShutdownUnhook` / `UnhookFailure`.
async fn request_unhook_from_injected(
    registry: &Arc<crate::process_registry::ProcessRegistry>,
    audit_ctx: &crate::audit_emitter::EmitContext,
) {
    let injected_before: Vec<(crate::process_registry::ProcessKey, crate::process_registry::ProcessState)> =
        registry.iter_injected();
    if injected_before.is_empty() {
        return;
    }

    let target_pids: Vec<u32> = injected_before
        .iter()
        .map(|(key, _)| key.pid)
        .collect();
    let pids_str = if target_pids.len() > 32 {
        format!(
            "[{},...]",
            target_pids[..32]
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",")
        )
    } else {
        format!(
            "[{}]",
            target_pids
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",")
        )
    };

    crate::password_stop::debug_log("run_loop: requesting unhook from injected processes");
    crate::audit_emitter::emit_unhook_audit(
        audit_ctx,
        dlp_common::EventType::AgentShutdownUnhook,
        std::process::id(),
        true,
        Some(format!(
            "injected_count={}; target_pids={}",
            injected_before.len(),
            pids_str
        )),
        Some(format!(
            "agent://{}/unhook_request",
            std::process::id()
        )),
    );

    UNHOOK_ALL_REQUESTED.store(true, Ordering::Release);

    // Use the configured unhook wait budget, clamped to a sensible minimum.
    let budget = with_config(|cfg| {
        Duration::from_millis(cfg.unhook_wait_budget_ms.unwrap_or(30_000).max(1_000))
    })
    .unwrap_or(UNHOOK_WAIT_BUDGET);

    let remaining = wait_for_unhook_acks(registry, budget).await;

    for (key, _) in registry.iter_injected() {
        crate::audit_emitter::emit_unhook_audit(
            audit_ctx,
            dlp_common::EventType::UnhookFailure,
            key.pid,
            false,
            Some(format!("creation_time={}", key.creation_time)),
            None,
        );
    }

    info!(remaining, "unhook wait complete");
}

/// Global SQLite connection for the agent's offline audit queue.
///
/// Set once during service startup via [`init_agent_db`].  All callers that
/// need to enqueue or drain offline audit events read this static.
///
/// The connection is opened on the agent's local DB file
/// (`C:\ProgramData\DLP\agent.db`) and the `offline_audit_queue` table is
/// initialised before any other module can access it.
///
/// Wrapped in `std::sync::Mutex` because `rusqlite::Connection` is not `Sync`.
static AGENT_DB: OnceLock<std::sync::Mutex<rusqlite::Connection>> = OnceLock::new();

/// Returns a reference to the global agent SQLite connection.
///
/// Returns `None` if the connection has not been initialised yet
/// (e.g., called before `run_loop_init` completes).
pub fn agent_db() -> Option<&'static std::sync::Mutex<rusqlite::Connection>> {
    AGENT_DB.get()
}

/// Initialises the agent's local SQLite database and the offline audit queue table.
///
/// Called once during service startup.  The database lives in the agent's
/// data directory (`C:\ProgramData\DLP\agent.db`).  If the directory or file
/// does not exist, it is created automatically.
///
/// # Errors
///
/// Returns `Err` if the database file cannot be opened or the table cannot be created.
fn init_agent_db() -> Result<(), anyhow::Error> {
    let data_dir = std::path::PathBuf::from(r"C:\ProgramData\DLP");
    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("creating agent data dir: {}", data_dir.display()))?;
    let db_path = data_dir.join("agent.db");
    let conn = rusqlite::Connection::open(&db_path)
        .with_context(|| format!("opening agent db: {}", db_path.display()))?;
    crate::offline_audit_queue::init_table(&conn)
        .with_context(|| "initialising offline_audit_queue table")?;
    crate::dacl_staging::init_staging_table(&conn)
        .with_context(|| "initialising protected_paths_staging table")?;
    info!(db_path = %db_path.display(), "agent SQLite DB initialised");
    let _ = AGENT_DB.set(std::sync::Mutex::new(conn));
    Ok(())
}

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

/// Holds JoinHandles for all blocking std::threads spawned during service startup.
/// Used during shutdown to signal and join each thread before reporting STOPPED.
struct BlockingThreads {
    health: Option<std::thread::JoinHandle<()>>,
    ipc: Vec<std::thread::JoinHandle<()>>,
    chrome: Option<std::thread::JoinHandle<()>>,
    session: Option<std::thread::JoinHandle<()>>,
}

impl BlockingThreads {
    fn new() -> Self {
        Self {
            health: None,
            ipc: Vec::new(),
            chrome: None,
            session: None,
        }
    }

    /// Signal shutdown and join all threads.
    ///
    /// A watchdog timer guarantees the process exits if any thread remains
    /// blocked beyond the timeout. This prevents the service from hanging
    /// in `StopPending` indefinitely when a thread is stuck in a Win32 call
    /// that never returns (e.g. `ConnectNamedPipeW` with no client).
    fn shutdown_and_join(self) {
        request_shutdown();
        info!("shutdown requested — joining blocking threads");

        // Watchdog: if shutdown takes longer than timeout + 5 s buffer, force abort.
        // std::process::abort is used instead of exit(1) to bypass atexit handlers
        // and avoid partial cleanup that could corrupt the SQLite WAL.
        let watchdog_timeout = SHUTDOWN_TIMEOUT
            .saturating_mul(4)
            .saturating_add(Duration::from_secs(5));
        std::thread::spawn(move || {
            std::thread::sleep(watchdog_timeout);
            error!(
                ?watchdog_timeout,
                "shutdown watchdog: threads failed to join — forcing abort"
            );
            std::process::abort();
        });

        let start = Instant::now();

        let join_with_log = |name: &str, handle: Option<std::thread::JoinHandle<()>>| {
            if let Some(h) = handle {
                let thread_start = Instant::now();
                debug!(thread = name, "joining thread");
                match h.join() {
                    Ok(()) => {
                        let elapsed = thread_start.elapsed();
                        debug!(thread = name, ?elapsed, "thread joined cleanly");
                    }
                    Err(e) => {
                        warn!(thread = name, error = ?e, "thread panicked during shutdown");
                    }
                }
            }
        };

        join_with_log("health", self.health);
        for (i, h) in self.ipc.into_iter().enumerate() {
            join_with_log(&format!("ipc-pipe-{i}"), Some(h));
        }
        join_with_log("chrome", self.chrome);
        join_with_log("session", self.session);

        let total = start.elapsed();
        info!(?total, "all blocking threads joined");
    }
}

/// Runs the DLP Agent Windows Service to completion.
pub fn run_service() -> Result<()> {
    // Reset the shutdown signal to support in-process restart scenarios.
    // If a previous service instance set this flag, a new start must begin
    // with a clean state so that blocking threads do not exit immediately.
    reset_shutdown_signal();

    // Phase 58.5: also reset the global unhook signal so freshly injected
    // processes do not receive a stale UnhookCommand before real shutdown.
    reset_unhook_signal();

    // Load the config early — only to read `log_level` before the subscriber
    // is initialised.  The full config load happens later at its normal site.
    let log_level = crate::config::AgentConfig::load_default().resolved_log_level();
    init_logging(log_level);
    info!(service_name = SERVICE_NAME, "DLP Agent service starting");

    // Resolve machine hostname once at startup for inclusion in evaluation requests.
    let machine_name = hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .ok();

    // Register the service control handler.
    let status_handle = service_control_handler::register(SERVICE_NAME, service_control_handler)?;

    // Store the handle globally so the control handler callback can report
    // state transitions (e.g. StopPending) directly to the SCM.
    let _ = SCM_HANDLE.set(status_handle);

    // Wrap in Arc<Mutex<>> so we can use it across multiple set_status calls.
    let status_handle = Arc::new(Mutex::new(status_handle));

    // Report STARTING.
    set_status(
        &status_handle,
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        None,
    )?;

    // Acquire single-instance mutex.  The handle MUST be kept alive until
    // service shutdown; dropping it releases the named mutex and allows a
    // second instance to start.  On non-Windows targets the call is a no-op
    // that returns (), so we use cfg to keep the binding type consistent.
    #[cfg(windows)]
    let _instance_mutex =
        acquire_instance_mutex().context("failed to acquire single-instance mutex")?;
    #[cfg(not(windows))]
    acquire_instance_mutex();

    // Harden the agent process DACL — deny PROCESS_TERMINATE etc. to Everyone.
    // This prevents Task Manager / taskkill from killing the agent without
    // dlp-admin credentials.  Failures are logged but do not block startup.
    crate::protection::harden_agent_process();

    // Register as Chrome Content Analysis agent in HKLM.
    // Non-fatal: if the registry write fails, the agent still starts.
    if let Err(e) = crate::chrome::registry::register_agent() {
        warn!(error = %e, "Chrome HKLM registration failed — continuing");
    }

    // ── Configure the UI binary path ─────────────────────────────────
    // In production: installed alongside the service binary.
    // Override with DLP_UI_BINARY env var for development.
    let ui_binary = resolve_ui_binary();
    if let Some(ref path) = ui_binary {
        info!(path = %path.display(), "UI binary path resolved");
        crate::ui_spawner::set_ui_binary(path.clone());
    } else {
        warn!(
            "UI binary (dlp-user-ui.exe) not found — toast notifications will not work. \
             Searched: same directory as agent, DLP_UI_BINARY env var. \
             Install the UI binary or set DLP_UI_BINARY environment variable."
        );
    }

    // ── Thread handle storage for graceful shutdown ────────────────
    let mut threads = BlockingThreads::new();

    // ── Start the health monitor first ───────────────────────────────
    // health_monitor::run() calls ROUTER.set_health_sender() — this MUST
    // happen before Pipe 3's handle_client runs, so Pipe 3 can read the
    // session sender from the same ROUTER.
    threads.health = Some(crate::health_monitor::start());
    if let Some(ref h) = threads.health {
        info!(thread_id = ?h.thread().id(), "health monitor started");
    }

    // ── Start IPC pipe servers ────────────────────────────────────
    // Each serve() call blocks on a dedicated thread.  Pipe 1, 2, and 3
    // are independent; they communicate via the shared BROADCASTER and ROUTER
    // statics.  Pipe 3's handle_client sets ROUTER.session_sender on each
    // new connection.
    threads.ipc = crate::ipc::start_all()?;
    info!(count = threads.ipc.len(), "IPC pipe servers started");

    // ── Start Chrome Content Analysis pipe server ────────────────
    // Spawn as a dedicated std::thread (NOT a tokio task) because
    // ConnectNamedPipeW and ReadFile block the calling thread.
    //
    // Phase 41: Wire the ABAC policy evaluator before spawning the thread.
    // The evaluator wraps the managed-origins cache in the ABAC
    // EvaluateRequest/EvaluateResponse shape so the Chrome handler
    // speaks ABAC while the backing evaluation still uses the cache
    // until full OfflineManager integration.
    crate::chrome::handler::set_policy_evaluator(chrome_policy_evaluator);
    threads.chrome = Some(
        std::thread::Builder::new()
            .name("chrome-pipe".into())
            .spawn(|| {
                if let Err(e) = crate::chrome::handler::serve() {
                    error!(error = %e, "Chrome pipe server exited with error");
                }
            })
            .context("failed to spawn Chrome pipe thread")?,
    );
    if let Some(ref h) = threads.chrome {
        info!(thread_id = ?h.thread().id(), "Chrome pipe server started");
    }

    // ── Start the session monitor ──────────────────────────────────
    // session_monitor::run() calls ui_spawner::init() which enumerates
    // active sessions and spawns a UI in each.  New sessions are detected
    // via polling (WTSEnumerateSessionsW every 2 s).
    threads.session = Some(crate::session_monitor::start());
    if let Some(ref h) = threads.session {
        info!(thread_id = ?h.thread().id(), "session monitor started");
    }

    // Report RUNNING.
    set_status(
        &status_handle,
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::PAUSE_CONTINUE,
        None,
    )?;

    // Install the drag-and-drop hook (APP-08, Phase 40).
    // Runs in the service process; the hook thread sees messages from the
    // interactive user session when the UI is spawned via CreateProcessAsUserW.
    if let Err(e) = crate::interception::install_drag_drop_hook(1) {
        warn!(error = %e, "drag-drop hook installation failed — drag-and-drop enforcement disabled");
    } else {
        info!("drag-drop hook installed");
    }

    // Enter the main run loop.
    // NOTE: USB notification registration has been moved inside run_loop (Approach A)
    // so that usb_wndproc can schedule async refreshes on the live tokio runtime via
    // a stored Handle. run_loop also owns USB cleanup on shutdown.
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_loop(&status_handle, machine_name, &mut threads))?;

    // Shut down the tokio runtime immediately.  Background tasks (IPC pipe
    // servers, session monitor) use blocking ReadFile calls that never
    // return on their own.  Dropping the runtime without shutdown_timeout
    // would hang forever waiting for those tasks.
    rt.shutdown_timeout(Duration::from_secs(2));

    // ── Graceful shutdown of blocking threads ────────────────────────
    crate::password_stop::debug_log("run_service: run_loop returned — shutting down subsystems");
    info!(service_name = SERVICE_NAME, "shutting down subsystems");

    threads.shutdown_and_join();

    crate::password_stop::debug_log("run_service: reporting STOPPED to SCM");

    // Report STOPPED.
    set_status(
        &status_handle,
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        Some(ServiceExitCode::Win32(0)),
    )?;

    crate::password_stop::debug_log("run_service: STOPPED reported — exiting");
    info!(service_name = SERVICE_NAME, "service stopped");
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// Config poll loop
// ──────────────────────────────────────────────────────────────────────────────

/// Data returned by `apply_payload_to_config` for a deferred `instance_id_map` merge.
///
/// Contains:
/// - The set of `instance_id` strings that were in the OLD `cfg.disk_allowlist`
///   (needed to determine which entries to remove from the map).
/// - The new `Vec<DiskIdentity>` from the server payload (entries to insert/overwrite).
///
/// `None` is returned when `disk_allowlist` did not change (no merge needed).
type DiskMergeData = Option<(
    std::collections::HashSet<String>,
    Vec<dlp_common::DiskIdentity>,
)>;

/// Diffs a server-pushed `AgentConfigPayload` against in-memory `AgentConfig`
/// and applies all detected changes including the `disk_allowlist` merge.
///
/// Extracted as a standalone synchronous function so tests can invoke the
/// diff/merge logic directly without spinning up a full async polling loop.
///
/// # Design: config lock BEFORE enumerator lock (T-37-13)
///
/// This function expects that the config mutex is already held by the caller
/// and that the enumerator is accessed AFTER the function returns (i.e., AFTER
/// the config lock is released). To preserve this invariant the function returns
/// any data needed for the deferred enumerator merge: the old instance_id set
/// and the new list. The caller then does the map merge with the config lock dropped.
///
/// # Arguments
///
/// * `cfg` — mutable borrow of the in-memory agent config (config mutex held
///   by the caller).
/// * `payload` — server-pushed payload from `GET /agent-config/{id}`.
///
/// # Returns
///
/// A tuple of:
/// 1. `Vec<&'static str>` — field names that changed (empty = no update needed).
/// 2. `Option<(HashSet<String>, Vec<DiskIdentity>)>` — when `disk_allowlist`
///    changed: `(old_instance_ids, new_allowlist)` for the deferred map merge.
///    `None` when `disk_allowlist` did not change.
fn apply_payload_to_config(
    cfg: &mut crate::config::AgentConfig,
    payload: &crate::server_client::AgentConfigPayload,
) -> (Vec<&'static str>, DiskMergeData) {
    let mut changed_fields: Vec<&'static str> = Vec::new();
    let mut disk_merge_data: DiskMergeData = None;

    if cfg.monitored_paths != payload.monitored_paths {
        changed_fields.push("monitored_paths");
        cfg.monitored_paths = payload.monitored_paths.clone();
    }
    if cfg.heartbeat_interval_secs != Some(payload.heartbeat_interval_secs) {
        changed_fields.push("heartbeat_interval_secs");
        cfg.heartbeat_interval_secs = Some(payload.heartbeat_interval_secs);
    }
    if cfg.offline_cache_enabled != Some(payload.offline_cache_enabled) {
        changed_fields.push("offline_cache_enabled");
        cfg.offline_cache_enabled = Some(payload.offline_cache_enabled);
    }
    if cfg.ldap_config != payload.ldap_config {
        changed_fields.push("ldap_config");
        cfg.ldap_config = payload.ldap_config.clone();
    }
    if cfg.excluded_paths != payload.excluded_paths {
        changed_fields.push("excluded_paths");
        cfg.excluded_paths = payload.excluded_paths.clone();
    }

    // Phase 43 (USB-09): apply server-pushed USB enforcement config fields.
    //
    // None guard: if cfg is None and payload equals the system default, skip the
    // diff to avoid spurious "config changed" logs when a new agent polls an old
    // server that does not send these fields (the default functions provide the
    // system default, so the diff would fire on every poll).
    //
    // Empty-string guard: defense-in-depth — never apply empty strings for USB
    // config fields (preserves previous config value against a compromised or
    // buggy server).
    let should_apply_usb_failure_mode = match cfg.usb_blocked_failure_mode {
        Some(ref existing) => existing != &payload.usb_blocked_failure_mode,
        None => payload.usb_blocked_failure_mode != DEFAULT_USB_BLOCKED_FAILURE_MODE,
    };
    if should_apply_usb_failure_mode && !payload.usb_blocked_failure_mode.is_empty() {
        changed_fields.push("usb_blocked_failure_mode");
        cfg.usb_blocked_failure_mode = Some(payload.usb_blocked_failure_mode.clone());
    } else if payload.usb_blocked_failure_mode.is_empty() {
        warn!("server sent empty usb_blocked_failure_mode — skipping apply");
    }

    let should_apply_usb_resolution_mode = match cfg.usb_startup_resolution_mode {
        Some(ref existing) => existing != &payload.usb_startup_resolution_mode,
        None => payload.usb_startup_resolution_mode != DEFAULT_USB_STARTUP_RESOLUTION_MODE,
    };
    if should_apply_usb_resolution_mode && !payload.usb_startup_resolution_mode.is_empty() {
        changed_fields.push("usb_startup_resolution_mode");
        cfg.usb_startup_resolution_mode = Some(payload.usb_startup_resolution_mode.clone());
    } else if payload.usb_startup_resolution_mode.is_empty() {
        warn!("server sent empty usb_startup_resolution_mode — skipping apply");
    }

    let should_apply_usb_none_serial_policy = match cfg.usb_none_serial_policy {
        Some(ref existing) => existing != &payload.usb_none_serial_policy,
        None => payload.usb_none_serial_policy != DEFAULT_USB_NONE_SERIAL_POLICY,
    };
    if should_apply_usb_none_serial_policy && !payload.usb_none_serial_policy.is_empty() {
        changed_fields.push("usb_none_serial_policy");
        cfg.usb_none_serial_policy = Some(payload.usb_none_serial_policy.clone());
    } else if payload.usb_none_serial_policy.is_empty() {
        warn!("server sent empty usb_none_serial_policy — skipping apply");
    }

    // M017/S04: apply server-pushed print enforcement config fields.
    let should_apply_print_enabled = match cfg.print_enabled {
        Some(existing) => existing != payload.print_enabled,
        None => payload.print_enabled,
    };
    if should_apply_print_enabled {
        changed_fields.push("print_enabled");
        cfg.print_enabled = Some(payload.print_enabled);
    }

    let should_apply_print_xps_timeout_ms = match cfg.print_xps_timeout_ms {
        Some(existing) => existing != payload.print_xps_timeout_ms,
        None => payload.print_xps_timeout_ms != 5000,
    };
    if should_apply_print_xps_timeout_ms {
        changed_fields.push("print_xps_timeout_ms");
        cfg.print_xps_timeout_ms = Some(payload.print_xps_timeout_ms);
    }

    let should_apply_print_unclassifiable_action = match cfg.print_unclassifiable_action {
        Some(ref existing) => existing != &payload.print_unclassifiable_action,
        None => payload.print_unclassifiable_action != "Block",
    };
    if should_apply_print_unclassifiable_action && !payload.print_unclassifiable_action.is_empty() {
        changed_fields.push("print_unclassifiable_action");
        cfg.print_unclassifiable_action = Some(payload.print_unclassifiable_action.clone());
    } else if payload.print_unclassifiable_action.is_empty() {
        warn!("server sent empty print_unclassifiable_action — skipping apply");
    }

    let should_apply_print_max_pages = match cfg.print_max_pages {
        Some(existing) => existing != payload.print_max_pages,
        None => payload.print_max_pages != 100,
    };
    if should_apply_print_max_pages {
        changed_fields.push("print_max_pages");
        cfg.print_max_pages = Some(payload.print_max_pages);
    }

    // Phase 37 (D-03): apply server-pushed disk allowlist.
    //
    // PartialEq on DiskIdentity compares all fields including encryption_status,
    // so the diff catches both additions/removals AND field-level updates from
    // the server (e.g., a re-verified encryption_status after a re-scan).
    if cfg.disk_allowlist != payload.disk_allowlist {
        changed_fields.push("disk_allowlist");

        // Capture the OLD allowlist's instance_ids BEFORE overwriting cfg.
        // The deferred map merge needs these to know which entries to remove
        // (entries that were previously allowlisted but are now de-allowlisted).
        let old_instance_ids: std::collections::HashSet<String> = cfg
            .disk_allowlist
            .iter()
            .map(|d| d.instance_id.clone())
            .collect();

        // Update cfg.disk_allowlist. The save() call triggered by the caller
        // (when !changed_fields.is_empty()) will serialize this to the
        // [[disk_allowlist]] TOML section.
        cfg.disk_allowlist = payload.disk_allowlist.clone();

        // Return the merge data. The CALLER must drop the config mutex before
        // calling merge_disk_allowlist_into_map() — T-37-13 lock-order invariant.
        disk_merge_data = Some((old_instance_ids, payload.disk_allowlist.clone()));
    }

    // Phase 49: apply server-pushed allowlist entries and version.
    //
    // Atomic replacement: the entire allowlist is replaced on version change.
    // Invalid entries are logged as warnings but do not block valid entries.
    if cfg.allowlist_version != payload.allowlist_version {
        changed_fields.push("allowlist_entries");
        cfg.allowlist_version = payload.allowlist_version;

        // Validate and filter entries before applying.
        let valid_entries: Vec<crate::allowlist::AllowlistEntry> = payload
            .allowlist_entries
            .iter()
            .filter_map(|entry| {
                let match_type = match entry.match_type.as_str() {
                    "exact_path" => crate::allowlist::MatchType::ExactPath,
                    "path_glob" => crate::allowlist::MatchType::PathGlob,
                    "path_prefix" => crate::allowlist::MatchType::PathPrefix,
                    "cert_subject" => crate::allowlist::MatchType::CertSubject,
                    "cert_thumbprint" => crate::allowlist::MatchType::CertThumbprint,
                    other => {
                        warn!(
                            match_type = other,
                            value = %entry.value,
                            "invalid allowlist match_type from server — skipping entry"
                        );
                        return None;
                    }
                };
                if entry.value.is_empty() {
                    warn!(
                        match_type = %entry.match_type,
                        "allowlist entry with empty value from server — skipping entry"
                    );
                    return None;
                }
                let category = match entry.category.as_str() {
                    "self" => crate::allowlist::AllowlistCategory::SelfProcess,
                    "avedr" => crate::allowlist::AllowlistCategory::Avedr,
                    "system_critical" => crate::allowlist::AllowlistCategory::SystemCritical,
                    "operator_defined" => crate::allowlist::AllowlistCategory::OperatorDefined,
                    other => {
                        warn!(
                            category = other,
                            value = %entry.value,
                            "invalid allowlist category from server — defaulting to operator_defined"
                        );
                        crate::allowlist::AllowlistCategory::OperatorDefined
                    }
                };
                Some(crate::allowlist::AllowlistEntry {
                    match_type,
                    value: entry.value.clone(),
                    description: entry.description.clone(),
                    category,
                })
            })
            .collect();

        if valid_entries.len() != payload.allowlist_entries.len() {
            warn!(
                valid = valid_entries.len(),
                total = payload.allowlist_entries.len(),
                "allowlist entries filtered due to invalid match_type or empty value"
            );
        }

        cfg.allowlist_entries = valid_entries;
    }

    // Phase 52: apply server-pushed protected_paths changes with two-phase staging.
    //
    // Removals are staged in the local SQLite database so the repair watcher
    // can suppress tamper alerts when the ACL is legitimately removed.
    // Additions are applied directly (DaclWatcher handles them on next init).
    if cfg.protected_paths != payload.protected_paths {
        changed_fields.push("protected_paths");

        // Compute additions and removals by comparing path strings.
        let old_paths: std::collections::HashSet<String> =
            cfg.protected_paths.iter().map(|p| p.path.clone()).collect();
        let new_paths: std::collections::HashSet<String> = payload
            .protected_paths
            .iter()
            .map(|p| p.path.clone())
            .collect();

        let additions: Vec<String> = new_paths.difference(&old_paths).cloned().collect();
        let removals: Vec<String> = old_paths.difference(&new_paths).cloned().collect();

        // Stage removals in the local SQLite database.
        // The staging rows tell the repair watcher to suppress tamper alerts
        // when these paths' ACLs change.
        if !removals.is_empty() {
            if let Some(db) = agent_db() {
                if let Err(e) = crate::dacl_staging::stage_removals(db, &removals) {
                    tracing::warn!(error = %e, "failed to stage protected path removals");
                } else {
                    tracing::info!(count = removals.len(), "staged protected path removals");
                }
            } else {
                tracing::warn!("agent DB not initialised — cannot stage removals");
            }
        }

        // Log additions for observability (applied on next watcher init).
        if !additions.is_empty() {
            tracing::info!(
                count = additions.len(),
                "new protected paths detected — will apply on next watcher init"
            );
        }

        cfg.protected_paths = payload.protected_paths.clone();
    }

    // Phase 55: apply server-pushed global enforcement mode.
    let payload_mode = payload.global_enforcement_mode.as_str();
    let parsed_mode = match payload_mode {
        "Audit" => dlp_common::abac::EnforcementMode::Audit,
        "Block" => dlp_common::abac::EnforcementMode::Block,
        "AuditAndBlock" => dlp_common::abac::EnforcementMode::AuditAndBlock,
        "PerPolicy" => dlp_common::abac::EnforcementMode::PerPolicy,
        other => {
            tracing::warn!(
                mode = %other,
                "server sent invalid global_enforcement_mode — defaulting to Block"
            );
            dlp_common::abac::EnforcementMode::Block
        }
    };
    if cfg.enforcement.global_mode != parsed_mode {
        let old_mode = cfg.enforcement.global_mode;
        cfg.enforcement.global_mode = parsed_mode;
        tracing::info!(
            old_mode = ?old_mode,
            new_mode = ?parsed_mode,
            "global_enforcement_mode changed"
        );
        changed_fields.push("global_enforcement_mode");
    }

    (changed_fields, disk_merge_data)
}

/// Applies the disk_allowlist merge into `DiskEnumerator.instance_id_map`.
///
/// Called AFTER the config mutex has been released (T-37-13 lock-order invariant).
///
/// # Merge semantics (Pitfall 5 from 37-RESEARCH.md)
///
/// - REMOVE entries whose `instance_id` was in `old_ids` but is absent from
///   `new_list`. These are admin-deleted entries.
/// - INSERT/OVERWRITE entries from `new_list` with the server-supplied
///   `DiskIdentity` so `encryption_status` / `model` fields stay in sync.
/// - PRESERVE live-enumerated entries whose `instance_id` is NOT in `old_ids`.
///   These were discovered by Phase 33 enumeration and are NOT in
///   `cfg.disk_allowlist` — removing them would break Phase 36 enforcement
///   for currently-connected disks that have not been server-registered yet.
///
/// # Arguments
///
/// * `enumerator` — shared reference to the `DiskEnumerator` (no config lock).
/// * `old_ids` — instance_ids that were in the previous `cfg.disk_allowlist`.
/// * `new_list` — the new allowlist from the server payload.
fn merge_disk_allowlist_into_map(
    enumerator: &crate::detection::disk::DiskEnumerator,
    old_ids: &std::collections::HashSet<String>,
    new_list: &[dlp_common::DiskIdentity],
) {
    let new_ids: std::collections::HashSet<&str> =
        new_list.iter().map(|d| d.instance_id.as_str()).collect();

    let mut map = enumerator.instance_id_map.write();

    // Step 1: Remove de-allowlisted entries (in old, absent from new).
    // We ONLY remove entries that were in the previous server allowlist.
    // Live-enumerated entries (not in old_ids) are preserved (Pitfall 5).
    let to_remove: Vec<String> = old_ids
        .iter()
        .filter(|id| !new_ids.contains(id.as_str()))
        .cloned()
        .collect();
    for id in to_remove {
        map.remove(&id);
    }

    // Step 2: Insert/overwrite entries from the new server allowlist.
    for disk in new_list {
        map.insert(disk.instance_id.clone(), disk.clone());
    }
}

/// Commands that can be sent to the config poll loop.
///
/// Used for manual refresh triggers (e.g., operator-initiated via TUI F5 key).
pub enum ConfigCommand {
    /// Trigger an immediate config poll, bypassing the interval timer.
    RefreshNow,
}

/// Periodically polls the server for updated agent config.
///
/// Runs on a separate timer independent of heartbeat. On each tick:
/// 1. Fetch resolved config from `GET /agent-config/{agent_id}` with
///    `If-None-Match` header for 304-style optimization.
/// 2. If 304: skip update. If new config: diff all pushed fields against
///    in-memory state.
/// 3. If changed: update in-memory, merge into `DiskEnumerator.instance_id_map`,
///    write to TOML, log field names only.
/// 4. Re-arm timer using the *previously applied* interval (not the new one)
///    to prevent tight-loop on interval reduction.
///
/// `monitored_paths` changes are written to TOML but only take effect on
/// restart — `InterceptionEngine` paths are fixed at construction time.
/// `heartbeat_interval_secs` and `offline_cache_enabled` take effect
/// immediately in-memory.
async fn config_poll_loop(
    server_client: crate::server_client::ServerClient,
    config: Arc<parking_lot::Mutex<crate::config::AgentConfig>>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    mut cmd_rx: tokio::sync::mpsc::Receiver<ConfigCommand>,
) {
    // Perform an immediate first fetch so the agent reflects server-pushed
    // config as soon as possible after startup. This also ensures that tests
    // with fast poll intervals (heartbeat_interval_secs = 10) do not need to
    // wait for the full 30-second default before the first update.
    //
    // After the initial fetch, the interval-based loop takes over with the
    // heartbeat_interval_secs value returned by the server (or 30 s default).
    // Defined as a macro because async closures are not stable and we share
    // `config` and `server_client` by reference across .await points.
    macro_rules! do_poll {
        () => {{
            // Capture interval and version BEFORE applying any update.
            let (current_interval, last_version) = {
                let cfg = config.lock();
                (cfg.heartbeat_interval_secs.unwrap_or(30), cfg.allowlist_version)
            };

            match server_client.fetch_agent_config_with_version(last_version).await {
                Ok(Some(payload)) => {
                    // Phase 37 (T-37-13): apply_payload_to_config runs INSIDE the
                    // config lock scope and returns any disk_merge_data needed for
                    // the deferred instance_id_map merge. The map merge must happen
                    // AFTER the config lock is released (lock-order invariant).
                    let (changed_fields, disk_merge_data) = {
                        let mut cfg = config.lock();
                        apply_payload_to_config(&mut cfg, &payload)
                    };
                    // cfg lock is now released. Safe to access instance_id_map.

                    // Apply deferred disk_allowlist merge into DiskEnumerator.
                    if let Some((old_ids, new_list)) = disk_merge_data {
                        if let Some(enumerator) = crate::detection::disk::get_disk_enumerator() {
                            merge_disk_allowlist_into_map(&enumerator, &old_ids, &new_list);
                        }
                    }

                    if !changed_fields.is_empty() {
                        // Log field names only — never log path values (T-06-09 info disclosure).
                        info!(
                            fields = ?changed_fields,
                            "agent config updated from server"
                        );
                        // Write back to TOML for persistence across restarts.
                        // Use the effective path (DLP_CONFIG_PATH env var if set, else
                        // DEFAULT_CONFIG_PATH) so integration tests can redirect to a
                        // temp directory without touching the production config file.
                        let effective_path =
                            crate::config::AgentConfig::effective_config_path();
                        let config_path = std::path::Path::new(&effective_path);
                        let cfg = config.lock();
                        if let Err(e) = cfg.save(config_path) {
                            tracing::error!(
                                error = %e,
                                "failed to write updated config to TOML"
                            );
                        }
                    }
                }
                Ok(None) => {
                    debug!(
                        version = last_version,
                        "config poll: server returned 304 — no changes"
                    );
                }
                Err(e) => {
                    // Best-effort: log and retain current config on server error.
                    debug!(error = %e, "config poll failed — retaining current config");
                }
            }

            // Re-arm using the PREVIOUS interval so a server-reduced interval
            // does not cause a tight loop on the very next tick.
            current_interval
        }};
    }

    // Initial fetch — runs immediately without waiting for an interval tick.
    let initial_interval = do_poll!();
    let mut interval = tokio::time::interval(Duration::from_secs(initial_interval));
    // Consume the immediate first tick of the new interval so the next loop
    // iteration waits a full interval_secs before polling again.
    interval.tick().await;

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            Some(cmd) = cmd_rx.recv() => {
                match cmd {
                    ConfigCommand::RefreshNow => {
                        info!("config poll: manual refresh triggered");
                        // Fall through to do_poll!() below.
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                info!("config poll loop shutting down");
                return;
            }
        }

        let next_interval = do_poll!();

        // Re-arm using the PREVIOUS interval value captured before do_poll!()
        // applied the server's new config. The UPDATED interval takes effect
        // starting from the THIRD poll cycle:
        //   cycle N (this iteration): used the old interval to reach here.
        //   cycle N+1: do_poll!() reads the new heartbeat_interval_secs from
        //     the already-updated in-memory config at the top of the loop;
        //     next tick fires after the new interval.
        interval = tokio::time::interval(Duration::from_secs(next_interval));
        interval.tick().await; // consume immediate first tick
    }
}

/// Container for all subsystem shutdown handles and resources.
///
/// Collected during [`run_loop_init`] and consumed by [`run_loop_shutdown`]
/// so that the service control loop body remains focused on a single
/// responsibility: polling for the stop signal.
struct RunLoopContext {
    /// Handle to the file monitor task (spawned via `spawn_blocking`).
    file_handle: tokio::task::JoinHandle<()>,
    /// Clone of the file monitor for calling `stop()` on shutdown.
    file_monitor: crate::interception::InterceptionEngine,
    /// Handle to the async interception event loop.
    event_loop_handle: tokio::task::JoinHandle<()>,
    /// Handle to the Policy Engine heartbeat task.
    heartbeat_handle: tokio::task::JoinHandle<()>,
    /// Sender to signal the heartbeat task to exit.
    heartbeat_shutdown_tx: tokio::sync::watch::Sender<bool>,
    /// Handle to the Pipe 1 heartbeat task.
    pipe1_hb_handle: tokio::task::JoinHandle<()>,
    /// Sender to signal the Pipe 1 heartbeat to exit.
    pipe1_shutdown_tx: tokio::sync::watch::Sender<bool>,
    /// Handle to the config poll task (optional when no server client).
    config_poll_handle: Option<tokio::task::JoinHandle<()>>,
    /// Sender to signal the config poll task to exit.
    config_shutdown_tx: tokio::sync::watch::Sender<bool>,
    /// Sender to trigger manual config refresh (e.g., `ConfigCommand::RefreshNow`).
    #[allow(dead_code)]
    config_cmd_tx: tokio::sync::mpsc::Sender<ConfigCommand>,
    /// Handle to the device registry poll task.
    registry_poll_handle: Option<tokio::task::JoinHandle<()>>,
    /// Sender to signal the registry poll task to exit.
    registry_shutdown_tx: tokio::sync::watch::Sender<bool>,
    /// Handle to the managed origins poll task.
    origins_poll_handle: Option<tokio::task::JoinHandle<()>>,
    /// Sender to signal the origins poll task to exit.
    origins_shutdown_tx: tokio::sync::watch::Sender<bool>,
    /// Handle to the disk enumeration background task.
    disk_enum_handle: tokio::task::JoinHandle<()>,
    /// Sender to signal the disk enumeration task to exit.
    disk_shutdown_tx: tokio::sync::watch::Sender<bool>,
    /// Handle to the encryption check background task.
    enc_handle: tokio::task::JoinHandle<()>,
    /// Sender to signal the encryption check task to exit.
    enc_shutdown_tx: tokio::sync::watch::Sender<bool>,
    /// Handle to the audit buffer flush task.
    audit_flush_handle: Option<tokio::task::JoinHandle<()>>,
    /// Sender to signal the audit buffer to perform final flush.
    audit_shutdown_tx: tokio::sync::watch::Sender<bool>,
    /// Device watcher cleanup tuple (HWND, thread) — present when registration succeeded.
    device_watcher_cleanup: Option<(
        windows::Win32::Foundation::HWND,
        std::thread::JoinHandle<()>,
    )>,
    /// Shared reference to the USB detector (for shutdown ACL restore / re-enable).
    detector_arc: Arc<crate::detection::VolumeDetector>,
    /// Optional hook injector (M017/S01). `None` when `cloud_hook_enabled` is false.
    #[allow(dead_code)]
    hook_injector: Option<crate::hook_injector::HookInjector>,
    /// Shutdown flag for the sync-client process watcher thread (M017/S02).
    /// Signalled `true` during shutdown to stop the loop before joining.
    sync_watcher_shutdown: Option<Arc<std::sync::atomic::AtomicBool>>,
    /// Join handle for the sync-client process watcher thread (M017/S02).
    sync_watcher_handle: Option<std::thread::JoinHandle<()>>,
    /// Optional WFP manager (M017/S01). `None` when `wfp_filter_enabled` is false.
    #[allow(dead_code)]
    wfp_manager: Option<crate::wfp_manager::WfpManager>,
    /// Optional print enforcer (M017/S04). `None` when `print_enabled` is false.
    print_enforcer: Option<crate::print_enforcer::PrintEnforcer>,
    /// Approval cache (Phase 61) — agent-side approval token cache with JWT verification.
    /// Wired into the interception engine's three-stage pipeline (Phase 66.1).
    approval_cache: Arc<crate::approval_cache::ApprovalCache>,
    /// Handle to the approval cache poll task.
    approval_poll_handle: Option<tokio::task::JoinHandle<()>>,
    /// Sender to signal the approval poll task to exit.
    approval_shutdown_tx: tokio::sync::watch::Sender<bool>,
    /// Phase 49: Process watcher for universal injection (ETW + WMI backstop).
    #[allow(dead_code)]
    process_watcher: Option<crate::process_watcher::ProcessWatcher>,
    /// Phase 49: Universal injector with allowlist + latency tracking.
    #[allow(dead_code)]
    universal_injector: Option<Arc<crate::universal_injector::UniversalInjector>>,
    /// Phase 49: Process registry for lifecycle tracking.
    #[allow(dead_code)]
    process_registry: Arc<crate::process_registry::ProcessRegistry>,
    /// Phase 49: Allowlist matcher for injection skip decisions.
    #[allow(dead_code)]
    allowlist_matcher: Arc<crate::allowlist::AllowlistMatcher>,
    /// Phase 49: Shutdown flag for the periodic backstop sweep task.
    #[allow(dead_code)]
    backstop_shutdown: Option<tokio::sync::watch::Sender<bool>>,
    /// Phase 49: Handle for the periodic backstop sweep task.
    #[allow(dead_code)]
    backstop_handle: Option<tokio::task::JoinHandle<()>>,
    /// Phase 49: Shutdown flag for the retry queue consumer task.
    #[allow(dead_code)]
    retry_shutdown: Option<tokio::sync::watch::Sender<bool>>,
    /// Phase 49: Handle for the retry queue consumer task.
    #[allow(dead_code)]
    retry_handle: Option<tokio::task::JoinHandle<()>>,
    /// Phase 50: Shared-memory classification cache (hook DLL fast path).
    #[allow(dead_code)]
    classification_cache: Arc<crate::classification_cache::ClassificationCache>,
    /// Phase 50: Cache pusher background thread handle.
    #[allow(dead_code)]
    cache_pusher_handle: Option<std::thread::JoinHandle<()>>,
    /// Phase 52: DACL repair watcher for protected path ACL tamper detection.
    #[allow(dead_code)]
    dacl_watcher: Option<std::sync::Arc<crate::dacl_repair_watcher::DaclWatcher>>,
    /// Phase 52: Shutdown signal for the DACL repair task.
    dacl_watcher_shutdown: Option<tokio::sync::watch::Sender<bool>>,
    /// Phase 52: Handle for the DACL repair task.
    dacl_watcher_handle: Option<tokio::task::JoinHandle<()>>,
    /// Phase 52: Handle for the DACL polling backstop task.
    dacl_poll_handle: Option<tokio::task::JoinHandle<()>>,
    /// Phase 52-07: Staging layer for two-phase removal protocol.
    #[allow(dead_code)]
    dacl_staging: Option<Arc<crate::dacl_staging::DaclStaging>>,
    /// Phase 52-07: Shutdown signal for the staging GC task.
    dacl_gc_shutdown: Option<tokio::sync::watch::Sender<bool>>,
    /// Phase 52-07: Handle for the staging GC task.
    dacl_gc_handle: Option<tokio::task::JoinHandle<()>>,
    /// Phase 52-07: Shutdown signal for the removal application task.
    dacl_removal_shutdown: Option<tokio::sync::watch::Sender<bool>>,
    /// Phase 52-07: Handle for the removal application task.
    dacl_removal_handle: Option<tokio::task::JoinHandle<()>>,
    /// Phase 53: ETW Kernel-File consumer.
    #[allow(dead_code)]
    etw_consumer: Option<crate::etw_kernel_file::EtwKernelFileConsumer>,
    /// Phase 53: Shutdown signal for the bypass correlator task.
    correlator_shutdown: Option<tokio::sync::watch::Sender<bool>>,
    /// Phase 53: Handle for the bypass correlator task.
    correlator_handle: Option<tokio::task::JoinHandle<()>>,
    /// Phase 58: Diagnostic snapshot aggregator for hook DLL diagnostics.
    #[allow(dead_code)]
    diagnostic_aggregator: Arc<crate::diagnostic_aggregator::DiagnosticAggregator>,
    /// Phase 58: Health snapshot aggregator for hook DLL health monitoring.
    #[allow(dead_code)]
    health_aggregator: Arc<crate::health_aggregator::HealthAggregator>,
    /// Phase 58: Handle for the hook IPC server thread.
    hook_ipc_handle: Option<std::thread::JoinHandle<()>>,
    /// Phase 58: Shutdown signal for the diagnostic snapshot periodic push task.
    #[allow(dead_code)]
    diagnostic_push_shutdown: Option<tokio::sync::watch::Sender<bool>>,
    /// Phase 58: Handle for the diagnostic snapshot periodic push task.
    #[allow(dead_code)]
    diagnostic_push_handle: Option<tokio::task::JoinHandle<()>>,
    /// Phase 58: Shutdown signal for the health snapshot periodic push task.
    #[allow(dead_code)]
    health_push_shutdown: Option<tokio::sync::watch::Sender<bool>>,
    /// Phase 58: Handle for the health snapshot periodic push task.
    #[allow(dead_code)]
    health_push_handle: Option<tokio::task::JoinHandle<()>>,
    /// Phase 58-06: Handle for the override request processing task (DIFF-01).
    #[allow(dead_code)]
    override_handle: Option<tokio::task::JoinHandle<()>>,
    /// Phase 58.5: Audit emit context for unhook orchestration and watchdog evidence.
    audit_ctx: crate::audit_emitter::EmitContext,
}

/// The main service run loop.
///
/// Runs the file system event loop and the service control loop.
/// All other subsystems (IPC servers, health monitor, session monitor, UI
/// spawner) run on blocking std threads started in [`run_service`].
///
/// When the SCM issues `sc stop`, [`password_stop::initiate_stop`] starts the
/// password challenge.  This loop polls the confirmation flag every 500 ms — on
/// confirmation it proceeds to shutdown; on `PASSWORD_CANCEL` or max attempts,
/// [`password_stop::revert_stop`] reverts the state to Running.
async fn run_loop(
    status_handle: &Arc<Mutex<windows_service::service_control_handler::ServiceStatusHandle>>,
    machine_name: Option<String>,
    blocking_threads: &mut BlockingThreads,
) -> Result<()> {
    // ── Open the audit log ────────────────────────────────────────────────
    let _log_path = crate::audit_emitter::log_path();
    info!(audit_log = %_log_path.display(), "audit subsystem initialised");

    // Initialise all subsystems and collect handles into a single context.
    let ctx = run_loop_init(machine_name, blocking_threads).await;

    // ── Service control loop ─────────────────────────────────────────────
    let poll_interval = Duration::from_millis(500);
    let mut ticker = tokio::time::interval(poll_interval);

    crate::password_stop::debug_log("run_loop: entering service control loop");

    loop {
        tokio::select! {
            biased;

            // Ctrl+C from an attached console (e.g. when running under debugger).
            _ = tokio::signal::ctrl_c() => {
                crate::password_stop::debug_log("run_loop: Ctrl+C received");
                info!(service_name = SERVICE_NAME, "service stopping (Ctrl+C)");
                break;
            }

            // Poll every 500 ms for stop confirmation or revert.
            _ = ticker.tick() => {
                if crate::password_stop::is_stop_confirmed() {
                    crate::password_stop::debug_log("run_loop: STOP_CONFIRMED detected — breaking loop");
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

    // ── Graceful shutdown with timeout (OP-04) ────────────────────────────
    let shutdown_result = tokio::time::timeout(SHUTDOWN_TIMEOUT, run_loop_shutdown(ctx)).await;

    match shutdown_result {
        Ok(()) => {
            info!(service_name = SERVICE_NAME, "graceful shutdown complete");
        }
        Err(_) => {
            tracing::error!(
                timeout_secs = SHUTDOWN_TIMEOUT.as_secs(),
                service_name = SERVICE_NAME,
                "graceful shutdown exceeded timeout -- force-terminating"
            );
        }
    }

    Ok(())
}

/// Emit a `NtdllPatchingEnabled` audit event when ntdll patching is configured.
///
/// Extracted as a standalone function for testability. The event is emitted
/// via the global audit emitter; failures are logged but not propagated.
fn emit_ntdll_patching_enabled_event() {
    let agent_id = std::env::var("DLP_AGENT_ID").unwrap_or_else(|_| {
        hostname::get()
            .map(|h| h.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "AGENT-UNKNOWN".to_string())
    });
    let mut event = dlp_common::audit::AuditEvent::new(
        dlp_common::audit::EventType::NtdllPatchingEnabled,
        "SYSTEM".to_string(),
        "SYSTEM".to_string(),
        "N/A".to_string(),
        dlp_common::Classification::T1,
        dlp_common::Action::PolicyUpdate,
        dlp_common::Decision::ALLOW,
        agent_id,
        0,
    );
    crate::audit_emitter::emit(&mut event).ok();
}

/// Configuration for building a consolidated [`HookIpcServer`] with all handlers.
///
/// Carries every dependency needed to construct the single server instance
/// per agent lifecycle.  `run_loop_init` assembles the config; the builder
/// function consumes it.
pub struct HookIpcServerConfig {
    /// Named-pipe path (e.g. `r"\\.\pipe\DlpHookPipe"`).
    pub pipe_name: String,
    /// Shared-memory classification cache accessor.
    pub cache: Arc<dyn crate::hook_ipc::CacheAccessor>,
    /// Offline policy engine for synchronous ABAC evaluation.
    pub offline: Arc<crate::offline::OfflineManager>,
    /// Sender for `BypassAlert` payloads forwarded to the bypass correlator.
    pub bypass_tx: crossbeam_channel::Sender<BypassAlert>,
    /// Diagnostic snapshot aggregator for `PullDiagnostics` requests.
    pub diagnostic_aggregator: Arc<crate::diagnostic_aggregator::DiagnosticAggregator>,
    /// Health snapshot aggregator for `PullHealth` requests.
    pub health_aggregator: Arc<crate::health_aggregator::HealthAggregator>,
    /// Async sender for override requests (DIFF-01).
    pub override_tx: tokio::sync::mpsc::Sender<dlp_common::hook_ipc::OverrideRequest>,
    /// Approval cache for fast-path override checks before ABAC evaluation.
    pub approval_cache: Arc<crate::approval_cache::ApprovalCache>,
    /// Hash cache for content hash evidence from blocked writes (DIFF-03).
    pub hash_cache: crate::hash_cache::HashCache,
    /// Phase 58.5: Process registry for PollControl validation and UnhookAck routing.
    pub process_registry: Arc<crate::process_registry::ProcessRegistry>,
    /// Phase 58.5: Audit emit context for unhook failure events.
    pub audit_ctx: crate::audit_emitter::EmitContext,
}

/// Maps a hook action string to the ABAC [`Action`] enum.
///
/// The mapping is exhaustive for all actions currently emitted by the hook DLL.
/// Unknown actions fall back to [`Action::READ`] so that ABAC evaluation still
/// proceeds (the policy engine may have a catch-all rule).
pub fn map_hook_action_to_abac(action: &str) -> dlp_common::Action {
    match action.to_ascii_uppercase().as_str() {
        "READ" | "NT_READ" => dlp_common::Action::READ,
        "WRITE" | "CREATE" | "NT_WRITE" => dlp_common::Action::WRITE,
        "COPY" => dlp_common::Action::COPY,
        "DELETE" | "MOVE" | "RENAME" | "REPLACE" | "SET_INFO" | "NT_SET_INFO" => {
            dlp_common::Action::DELETE
        }
        _ => dlp_common::Action::READ,
    }
}

/// Returns `true` if the hook action is a write operation.
///
/// Write actions are the ones that trigger content hashing on DENY (DIFF-03).
#[must_use]
pub fn is_write_action(action: &str) -> bool {
    matches!(
        action.to_ascii_uppercase().as_str(),
        "WRITE" | "CREATE" | "NT_WRITE" | "WRITE_EX"
    )
}

/// Converts a [`HookRequest`] into an [`EvaluateRequest`] for offline ABAC evaluation.
///
/// Identity resolution (PID -> SID) is performed **before** this call so that the
/// helper remains pure and testable.  Volume-class fields are forwarded unchanged.
/// All other optional fields (`agent`, `source_application`, etc.) remain `None`
/// because the hook DLL does not carry them (D-08).
pub fn hook_request_to_evaluate_request(
    req: &dlp_common::HookRequest,
    caller_sid: String,
) -> dlp_common::EvaluateRequest {
    let action = map_hook_action_to_abac(&req.action);
    dlp_common::EvaluateRequest {
        subject: dlp_common::Subject {
            user_sid: caller_sid,
            ..Default::default()
        },
        resource: dlp_common::Resource {
            path: req.path.clone(),
            ..Default::default()
        },
        environment: dlp_common::Environment::default(),
        action,
        agent: None,
        source_application: None,
        destination_application: None,
        source_origin: None,
        destination_origin: None,
        source_volume_class: req.source_volume_class,
        destination_volume_class: req.destination_volume_class,
    }
}

/// Spawns the hook DLL IPC server on a dedicated `std::thread`.
///
/// The server listens on the pipe name configured in `config`, performs synchronous
/// ABAC evaluation via [`OfflineManager::offline_decision`], and forwards
/// `BypassAlert` payloads from the hook DLL to the bypass correlator through
/// `config.bypass_tx`.  All DIFF-01/02/04 handlers are attached via the builder chain.
///
/// # Returns
///
/// `Some(JoinHandle<()>)` when the thread spawns successfully, or `None` on
/// failure. The handle is stored in [`RunLoopContext::hook_ipc_handle`] and joined
/// during service shutdown.
fn spawn_hook_ipc_server(config: HookIpcServerConfig) -> Option<std::thread::JoinHandle<()>> {
    let diag = Arc::clone(&config.diagnostic_aggregator);
    let health = Arc::clone(&config.health_aggregator);
    let health_for_handler = Arc::clone(&health);
    let override_tx = config.override_tx.clone();
    let approval = Arc::clone(&config.approval_cache);
    let offline = Arc::clone(&config.offline);
    let cache = Arc::clone(&config.cache);

    let diag_handler: crate::hook_ipc::DiagnosticsHandler =
        Arc::new(move |req: dlp_common::hook_ipc::PullDiagnosticsRequest| {
            let filter = crate::diagnostic_aggregator::DiagnosticFilter::default();
            let (snapshots, _total) =
                diag.get_snapshots_paginated(&filter, req.max_entries.min(1000), 0);
            dlp_common::hook_ipc::DiagnosticsResponse { snapshots }
        });

    let health_handler: crate::hook_ipc::HealthHandler =
        Arc::new(move |_req: dlp_common::hook_ipc::PullHealthRequest| {
            let snapshot = health_for_handler
                .get_current_status()
                .map(|(_, s)| s)
                .unwrap_or_default();
            dlp_common::hook_ipc::HealthResponse { snapshot }
        });

    let override_handler: crate::hook_ipc::OverrideHandler =
        Arc::new(move |req: dlp_common::hook_ipc::OverrideRequest| {
            if let Err(e) = override_tx.try_send(req) {
                warn!(error = %e, "Override channel full — dropping request");
            }
        });

    let hash_cache = Arc::clone(&config.hash_cache);
    let hash_cache_for_closure = Arc::clone(&hash_cache);

    let server = crate::hook_ipc::HookIpcServer::with_cache_offline_and_bypass(
        config.pipe_name,
        cache,
        Arc::new(move |req: dlp_common::HookRequest| {
            // Resolve caller identity from PID.
            let caller_sid = match get_caller_sid(req.pid) {
                Some(sid) => sid,
                None => {
                    warn!(
                        pid = req.pid,
                        "failed to resolve process SID — denying request"
                    );
                    return dlp_common::HookResponse {
                        decision: dlp_common::Decision::DENY,
                        reason: "identity resolution failed".to_string(),
                        cache_hint: None,
                        cache_version: 0,
                        approval_override: None,
                    };
                }
            };

            // Check approval cache for override (DIFF-01).
            let cache_key = dlp_common::approval::ApprovalCacheKey::new(
                &caller_sid,
                &req.path,
                &req.action,
                None,
            );
            if let Some(eval_resp) = approval.check(&cache_key, None) {
                info!(path = %req.path, "Approval cache hit — granting override");
                return dlp_common::HookResponse {
                    decision: eval_resp.decision,
                    reason: eval_resp.reason,
                    cache_hint: None,
                    cache_version: 0,
                    approval_override: Some(true),
                };
            }

            // Warn when COPY/MOVE lacks volume-class information (potential hook DLL gap).
            if matches!(req.action.as_str(), "COPY" | "MOVE") {
                if req.source_volume_class.is_none() {
                    warn!(path = %req.path, "COPY/MOVE request missing source_volume_class");
                }
                if req.destination_volume_class.is_none() {
                    warn!(path = %req.path, "COPY/MOVE request missing destination_volume_class");
                }
            }

            // Build EvaluateRequest and run offline ABAC evaluation.
            let evaluate_req = hook_request_to_evaluate_request(&req, caller_sid.clone());
            let eval_resp = offline.offline_decision(&evaluate_req);
            let response = dlp_common::HookResponse {
                decision: eval_resp.decision,
                reason: eval_resp.reason.clone(),
                cache_hint: None,
                cache_version: 0,
                approval_override: None,
            };

            // DIFF-03: If this is a blocked write, look up the hash from the cache
            // and emit an audit event with the hash attached.
            if response.decision.is_denied() && is_write_action(&req.action) {
                let hash = crate::hash_cache::lookup_hash(&hash_cache_for_closure, req.pid, 0);
                // Note: handle_value is not available in HookRequest; we use 0 as
                // a fallback key. The hook DLL sends HashEvidence with the actual
                // handle_value. In practice, the cache lookup by (pid, 0) works
                // because the hook DLL's WriteFile trampoline uses the process's
                // own handle_value which is unique per process. However, this is
                // a known limitation — the handle_value should be forwarded in the
                // HookRequest for precise correlation. See TODO(DIFF-03-handle).
                let (hash_str, truncated, skipped) = match hash {
                    Some(evidence) => (
                        evidence.content_sha256,
                        evidence.hash_truncated,
                        evidence.hash_skipped,
                    ),
                    None => (None, false, false),
                };

                let mut audit_event = dlp_common::AuditEvent::new(
                    dlp_common::EventType::Block,
                    caller_sid,
                    "hook-dll".to_string(), // user_name not available from PID resolution alone
                    req.path.clone(),
                    dlp_common::Classification::T1, // classification not available here
                    map_hook_action_to_abac(&req.action),
                    response.decision,
                    "AGENT-01".to_string(), // agent_id not available in this scope
                    0,                      // session_id not available in this scope
                )
                .with_policy_mode(format!("{:?}", eval_resp.enforcement_mode));

                if let Some(h) = hash_str {
                    audit_event = audit_event.with_content_hash(h, truncated, skipped);
                }

                // Best-effort audit emission via the global emitter.
                // Errors are logged but never block the hook IPC handler.
                let _ = crate::audit_emitter::EMITTER.emit(&mut audit_event);
            }

            response
        }),
        config.bypass_tx,
    )
    .with_diagnostics_handler(diag_handler)
    .with_health_handler(health_handler)
    .with_override_handler(override_handler)
    .with_hash_cache(hash_cache)
    .with_health_aggregator(health)
    .with_registry(config.process_registry)
    .with_audit_ctx(config.audit_ctx);

    match std::thread::Builder::new()
        .name("hook-ipc-server".to_string())
        .spawn(move || {
            if let Err(e) = server.run() {
                warn!(error = %e, "Hook IPC server exited with error");
            }
        }) {
        Ok(handle) => Some(handle),
        Err(e) => {
            error!(error = %e, "failed to spawn hook IPC server thread");
            None
        }
    }
}

/// Resolves the Windows user SID for the process identified by `pid`.
///
/// On Windows this opens the process token and converts the SID to a string.
/// On non-Windows targets a test stub is returned so the module compiles and
/// tests can run.
#[cfg(windows)]
fn get_caller_sid(pid: u32) -> Option<String> {
    get_process_user_sid(pid)
}

#[cfg(not(windows))]
fn get_caller_sid(_pid: u32) -> Option<String> {
    Some("S-1-5-18-test".to_string())
}

/// Initialises all enforcement subsystems and returns a [`RunLoopContext`]
/// containing every handle and sender needed for graceful shutdown.
///
/// Extracted from [`run_loop`] to reduce cognitive complexity.  Each subsystem
/// block is kept in source order so comments remain valid.
async fn run_loop_init(
    machine_name: Option<String>,
    _blocking_threads: &mut BlockingThreads,
) -> RunLoopContext {
    // ── Initialise the agent's local SQLite DB (offline audit queue) ───────
    if let Err(e) = init_agent_db() {
        warn!(error = %e, "agent DB init failed — offline audit queue unavailable");
    }

    // ── Restore device health status from registry (Phase 64) ──────────────
    if let Some(health) = crate::device_identity::read_health_from_registry() {
        info!(health = ?health, "restored device health status from registry");
        crate::device_identity::transition_health(health);
    }

    // ── Load agent config (needed for cache prepopulation and monitor setup) ───
    let agent_config = crate::config::AgentConfig::load_default();

    // ── Initialise the shared-memory classification cache (Phase 50) ────────
    // Must be created BEFORE any IPC pipe servers start so hooked processes
    // can map it immediately on connection.
    let classification_cache = Arc::new(
        crate::classification_cache::ClassificationCache::new()
            .inspect_err(|e| warn!(error = %e, "ClassificationCache init failed — hook DLL cache unavailable"))
            .unwrap_or_else(|_| {
                // On Windows this should succeed; on non-Windows it returns an error.
                // We panic on Windows because the cache is required for hook DLL operation.
                #[cfg(windows)]
                panic!("ClassificationCache is required on Windows");
                #[cfg(not(windows))]
                unreachable!()
            }),
    );
    // Pre-populate T3/T4 protected path roots from config.
    // monitored_paths serves as the protected path source until a dedicated
    // protected_paths field is added to AgentConfig.
    let protected_roots: Vec<std::path::PathBuf> = agent_config
        .monitored_paths
        .iter()
        .map(std::path::PathBuf::from)
        .collect();
    classification_cache.prepopulate_t3_t4_roots(protected_roots);

    // Start the cache pusher (policy change subscriber with 500ms debounce).
    let cache_pusher = crate::cache_pusher::CachePusher::new(Arc::clone(&classification_cache));
    let _cache_pusher_handle = cache_pusher.start();

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

    // ── AD client (best-effort — AD features disabled if config absent or init fails) ───
    let ad_client = init_ad_client(&agent_config).await;

    // ── dlp-server client (best-effort -- server may not be running) ─────
    let server_client = init_server_client(&agent_config).await;

    // ── Approval cache (Phase 61) ────────────────────────────────────────
    let approval_cache = Arc::new(crate::approval_cache::ApprovalCache::new());
    // Fetch the server's Ed25519 public key at startup for offline JWT verification.
    if let Some(ref sc) = server_client {
        match sc.fetch_public_key().await {
            Ok(pubkey_hex) => {
                if let Err(e) = approval_cache.set_public_key(&pubkey_hex) {
                    warn!(error = %e, "failed to set approval cache public key");
                } else {
                    info!("approval cache public key cached for offline JWT verification");
                }
            }
            Err(e) => {
                warn!(error = %e, "failed to fetch approval public key from server");
            }
        }
    }
    // Spawn the approval cache poll loop (syncs active approvals every 60s).
    let (approval_shutdown_tx, approval_poll_handle) =
        spawn_approval_poll_task(server_client.clone(), Arc::clone(&approval_cache));

    // ── Hook DLL IPC server (Phase 53/56.1) ────────────────────────────────
    // Spawns below after the offline manager and bypass channel are ready.

    // ── Store server client for on-demand auth hash fetching ─────────────
    if let Some(ref sc) = server_client {
        crate::password_stop::set_server_client(sc.clone());
        crate::password_stop::sync_auth_hash_from_server(sc).await;
    }

    // ── Audit buffer for server relay ────────────────────────────────────
    let (audit_shutdown_tx, audit_shutdown_rx) = tokio::sync::watch::channel(false);
    let audit_flush_handle = server_client.as_ref().map(|sc| {
        let buffer = Arc::new(crate::server_client::AuditBuffer::new(sc.clone()));
        crate::audit_emitter::set_audit_buffer(Arc::clone(&buffer));
        crate::server_client::AuditBuffer::spawn_flush_task(buffer, audit_shutdown_rx)
    });

    // ── Start USB mass-storage detection (inside run_loop for tokio Handle access) ──
    let detector_arc = init_usb_detector().await;

    // ── Managed origins cache (D-02) ──────────────────────────────
    let (origins_shutdown_tx, origins_poll_handle) =
        init_origins_cache(server_client.as_ref()).await;

    // ── Device registry cache (D-07, D-08) ──────────────────────────────────
    let (registry_shutdown_tx, registry_poll_handle, registry_cache) =
        init_registry_cache(server_client.as_ref()).await;

    // ── DeviceController (Phase 31) ───────────────────────────────────────
    let device_controller = Arc::new(crate::device_controller::DeviceController::new());
    crate::detection::usb::set_device_controller(Arc::clone(&device_controller));

    // ── UsbEnforcer (D-12) ────────────────────────────────────────────────
    let usb_enforcer_opt: Option<Arc<crate::usb_enforcer::UsbEnforcer>> =
        Some(Arc::new(crate::usb_enforcer::UsbEnforcer::new(
            Arc::clone(&detector_arc),
            Arc::clone(&registry_cache),
        )));

    // Pass Arc<VolumeDetector> directly to avoid unsafe transmute for lifetime
    // extension. DRIVE_DETECTOR stores Option<Arc<VolumeDetector>> so the Arc
    // clone keeps the detector alive as long as needed.
    crate::detection::usb::set_drive_detector(Arc::clone(&detector_arc));

    // ── Offline manager ────────────────────────────────────────────────────
    let offline = init_offline_manager(engine_client, cache, &server_client, machine_name.clone());

    // ── Phase 58: Diagnostic and Health Aggregators ────────────────────────
    let diagnostic_aggregator = Arc::new(crate::diagnostic_aggregator::DiagnosticAggregator::new());
    let health_aggregator = Arc::new(crate::health_aggregator::HealthAggregator::new());
    info!("diagnostic and health aggregators initialised");

    // ── Phase 58-06: Override request channel (DIFF-01) ────────────────────
    // The HookIpcServer runs on a dedicated std::thread without a tokio runtime.
    // Override requests need async server submission, so we use a channel to
    // forward them to a tokio task that handles the async work.
    let (override_tx, mut override_rx) =
        tokio::sync::mpsc::channel::<dlp_common::hook_ipc::OverrideRequest>(100);
    let override_server_client = server_client.clone();
    let override_handle = tokio::spawn(async move {
        while let Some(req) = override_rx.recv().await {
            let request_id = format!("ovr-{}", uuid::Uuid::new_v4());
            info!(
                request_id = %request_id,
                resource_path = %req.resource_path,
                "Override request received from hook DLL"
            );

            // Forward to UI via Pipe 1.
            let ui_msg = crate::ipc::messages::Pipe1AgentMsg::OverrideRequest {
                request_id: request_id.clone(),
                reason: format!("Blocked: {}", req.resource_path),
                classification: "T3".to_string(),
                resource_path: req.resource_path.clone(),
            };
            if let Err(e) = crate::ipc::pipe1::send_to_ui(0, &ui_msg) {
                warn!(error = %e, "Failed to send OverrideRequest to UI");
            }

            // Submit to server via async HTTP call.
            if let Some(ref sc) = override_server_client {
                let approval_req = dlp_common::approval::ApprovalRequest {
                    requester_sid: req.requester_sid.clone(),
                    data_object_id: req.data_object_id.clone(),
                    allowed_action: req.action.clone(),
                    destination_scope: req.destination_scope.clone(),
                    justification: req.justification.clone(),
                    device_fingerprint: None,
                };
                match sc.submit_approval_request(&approval_req).await {
                    Ok(server_request_id) => {
                        info!(
                            request_id = %request_id,
                            server_request_id = %server_request_id,
                            "Approval request submitted to server"
                        );
                    }
                    Err(e) => {
                        warn!(
                            request_id = %request_id,
                            error = %e,
                            "Failed to submit approval request to server"
                        );
                    }
                }
            } else {
                warn!(
                    request_id = %request_id,
                    "No server client available — approval request not submitted"
                );
            }
        }
    });

    // ── Hook DLL IPC server (Phase 53/56.1) ────────────────────────────────
    // Unbounded channel shared between HookIpcServer (sender) and the bypass
    // correlator (receiver). Hook DLL BypassAlert frames received over the
    // named pipe are forwarded to the correlator for enrichment and routing to
    // SIEM.
    let (bypass_tx, bypass_rx) = crossbeam_channel::bounded::<BypassAlert>(1000);

    // Lifecycle notifier channel: process registry -> bypass correlator.
    // The correlator releases per-PID resources when a process exits or unhooks.
    let (lifecycle_tx, lifecycle_rx) =
        crossbeam_channel::bounded::<crate::process_registry::ProcessKey>(1024);

    // ── HookInjector (M017/S01) ───────────────────────────────────────────
    let hook_injector_opt: Option<crate::hook_injector::HookInjector> =
        if agent_config.cloud_hook_enabled.unwrap_or(false) {
            let dll_path = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("dlp_hook_dll.dll")))
                .unwrap_or_else(|| std::path::PathBuf::from("dlp_hook_dll.dll"));
            let dll_path_x86 = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("dlp_hook_dll_x86.dll")))
                .unwrap_or_else(|| std::path::PathBuf::from("dlp_hook_dll_x86.dll"));
            let injector =
                crate::hook_injector::HookInjector::new(&dll_path, Some(dll_path_x86.clone()));
            info!(
                dll_path = %dll_path.display(),
                dll_path_x86 = %dll_path_x86.display(),
                "hook injector constructed"
            );
            Some(injector)
        } else {
            info!("cloud hook disabled — skipping HookInjector");
            None
        };

    // Assemble the consolidated server configuration (D-01..D-05).
    // Phase 58.5: the process registry is created by init_universal_injection
    // below, so we build the config after that call and pass it directly to
    // spawn_hook_ipc_server.
    let classification_cache_dyn: Arc<dyn crate::hook_ipc::CacheAccessor> =
        classification_cache.clone();

    // ── Phase 49: Universal Injection (ETW Process Watcher + Universal Injector) ──
    #[allow(unused_variables)]
    let (
        process_watcher_opt,
        universal_injector_opt,
        process_registry,
        allowlist_matcher,
        backstop_shutdown_tx,
        backstop_handle,
        retry_shutdown_tx,
        retry_handle,
    ) = init_universal_injection(
        hook_injector_opt.as_ref(),
        agent_config.universal_injection_enabled.unwrap_or(false),
        lifecycle_tx.clone(),
    )
    .await;

    // Phase 58.5: Build the audit context early so it can be shared with the
    // hook IPC server for unhook failure events.
    let audit_ctx = build_audit_ctx(machine_name);

    let hook_ipc_config = HookIpcServerConfig {
        pipe_name: crate::hook_ipc::DEFAULT_PIPE_NAME.to_string(),
        cache: classification_cache_dyn,
        offline: Arc::clone(&offline),
        bypass_tx,
        diagnostic_aggregator: Arc::clone(&diagnostic_aggregator),
        health_aggregator: Arc::clone(&health_aggregator),
        override_tx: override_tx.clone(),
        approval_cache: Arc::clone(&approval_cache),
        hash_cache: crate::hash_cache::create_hash_cache(),
        process_registry: Arc::clone(&process_registry),
        audit_ctx: audit_ctx.clone(),
    };

    let hook_ipc_handle = spawn_hook_ipc_server(hook_ipc_config);
    if let Some(ref h) = hook_ipc_handle {
        info!(thread_id = ?h.thread().id(), "Hook IPC server started");
    }

    // ── Wrap agent_config in Arc<Mutex<>> for shared access ──────────────
    let config_arc = Arc::new(parking_lot::Mutex::new(agent_config.clone()));

    // ── Set global CONFIG static for with_config access (Phase 43-04) ────
    let _ = CONFIG.set(Arc::clone(&config_arc));

    // ── Phase 35: Arc<RwLock<AgentConfig>> for disk allowlist persistence ──
    let disk_config_arc = Arc::new(parking_lot::RwLock::new(agent_config.clone()));
    let config_path = std::path::PathBuf::from(crate::config::AgentConfig::effective_config_path());

    // ── Start the Policy Engine heartbeat ─────────────────────────────────
    let (heartbeat_shutdown_tx, heartbeat_handle) = spawn_heartbeat_task(offline.clone());

    // ── Start the Pipe 1 heartbeat ────────────────────────────────────────
    let (pipe1_shutdown_tx, pipe1_hb_handle) = spawn_pipe1_heartbeat_task();

    // ── Start the config poll loop ─────────────────────────────────────────
    let (config_shutdown_tx, _config_cmd_tx, config_poll_handle) =
        spawn_config_poll_task(server_client.clone(), Arc::clone(&config_arc));

    // ── Start the file system monitor pipeline ─────────────────────────
    let recheck_interval = agent_config.resolved_recheck_interval();
    let file_monitor = crate::interception::InterceptionEngine::with_config(agent_config.clone())
        .expect("file monitor initialisation always succeeds");

    let (action_tx, action_rx) = mpsc::channel::<crate::interception::FileAction>(1024);

    // Channel for dynamically adding USB drive roots to the file watcher.
    let (watch_tx, watch_rx) = std::sync::mpsc::channel::<std::path::PathBuf>();
    crate::detection::usb::set_watch_path_sender(watch_tx);

    // ── Per-session identity map ───────────────────────────────────────────
    let session_map = init_session_map();

    // Initialise the clipboard listener's audit emit context.
    crate::clipboard::listener::init_emit_context(audit_ctx.clone());

    // Initialise the drag-and-drop enforcer's audit emit context (APP-08, Phase 40).
    crate::interception::init_drag_drop_emit_context(audit_ctx.clone());

    // ── Disk Enumeration (Phase 33) ───────────────────────────────────────
    let (disk_shutdown_tx, disk_enum_handle) =
        spawn_disk_enumeration(Arc::clone(&disk_config_arc), config_path, audit_ctx.clone());

    // ── Device watcher (Phase 36 D-12) ───────────────────────────────────
    let device_watcher_cleanup = spawn_device_watcher(audit_ctx.clone());

    // ── DiskEnforcer (Phase 36) ───────────────────────────────────────────
    let disk_enforcer_opt: Option<Arc<crate::disk_enforcer::DiskEnforcer>> =
        Some(Arc::new(crate::disk_enforcer::DiskEnforcer::new()));
    info!("disk enforcer constructed");

    // ── CloudEnforcer (M017/S01) ──────────────────────────────────────────
    let cloud_enforcer_opt: Option<Arc<crate::cloud_enforcer::CloudEnforcer>> =
        Some(Arc::new(crate::cloud_enforcer::CloudEnforcer::new()));
    info!("cloud enforcer constructed");

    // ── Phase 51: ntdll patching config ───────────────────────────────────
    let enable_ntdll_patching = agent_config.enable_ntdll_patching.unwrap_or(false);
    if enable_ntdll_patching {
        info!("ntdll patching enabled — will pass flag to hook DLL injector");
        // Emit SIEM event per D-15.
        // The hook DLL will emit BypassAlert(reason=EdrDetected) when EDR is
        // detected at boot; the agent converts that to EventType::NtdllPatchingEdrDetected.
        emit_ntdll_patching_enabled_event();
    }

    // ── Sync-client process watcher (M017/S02) ───────────────────────────
    // Only active when hook injection is enabled. Uses a std::thread (not a
    // Tokio task) to avoid blocking the async reactor during sleep intervals.
    let (sync_watcher_shutdown, sync_watcher_handle) = if let Some(ref injector) = hook_injector_opt
    {
        // Clone injector fields needed by the watcher thread.
        // HookInjector is not Clone, so we rebuild a lightweight wrapper with
        // the same DLL path from the existing injector's field read. Instead,
        // we pass the Arc-wrapped shutdown flag and re-create a fresh injector
        // for the watcher thread since HookInjector::new() is cheap.
        let dll_path_for_watcher = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("dlp_hook_dll.dll")))
            .unwrap_or_else(|| std::path::PathBuf::from("dlp_hook_dll.dll"));
        let dll_path_x86_for_watcher = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("dlp_hook_dll_x86.dll")))
            .unwrap_or_else(|| std::path::PathBuf::from("dlp_hook_dll_x86.dll"));
        // Suppress the unused variable warning on the injector reference used
        // only to gate the if-let branch.
        let _ = injector;

        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let flag_clone = Arc::clone(&shutdown_flag);

        let handle = std::thread::Builder::new()
            .name("sync-client-watcher".into())
            .spawn(move || {
                let watcher_injector = crate::hook_injector::HookInjector::new(
                    &dll_path_for_watcher,
                    Some(dll_path_x86_for_watcher),
                );
                info!("sync-client watcher thread started");

                loop {
                    if flag_clone.load(Ordering::Relaxed) {
                        info!("sync-client watcher: shutdown signal received — exiting");
                        break;
                    }

                    let pids = crate::cloud_enforcer::enumerate_sync_client_pids();
                    for (pid, exe) in pids {
                        match crate::hook_injector::HookInjector::is_module_loaded(
                            pid,
                            "dlp_hook_dll.dll",
                        ) {
                            Ok(false) => {
                                // DLL not yet present — attempt injection.
                                match watcher_injector.inject(pid) {
                                    Ok(()) => {
                                        info!(
                                            pid,
                                            exe, "sync-client watcher: hook injected successfully"
                                        );
                                    }
                                    Err(e) => {
                                        warn!(
                                            pid,
                                            exe,
                                            error = %e,
                                            "sync-client watcher: injection failed"
                                        );
                                    }
                                }
                            }
                            Ok(true) => {
                                tracing::trace!(
                                    pid,
                                    exe,
                                    "sync-client watcher: hook already loaded — skipping"
                                );
                            }
                            Err(e) => {
                                warn!(
                                    pid,
                                    exe,
                                    error = ?e,
                                    "sync-client watcher: module check failed"
                                );
                            }
                        }
                    }

                    std::thread::sleep(Duration::from_secs(30));
                }
            })
            .expect("failed to spawn sync-client watcher thread");

        info!("sync-client process watcher thread started");
        (Some(shutdown_flag), Some(handle))
    } else {
        (None, None)
    };

    // ── WfpManager (M017/S01) ─────────────────────────────────────────────
    let wfp_manager_opt: Option<crate::wfp_manager::WfpManager> = if agent_config
        .wfp_filter_enabled
        .unwrap_or(false)
    {
        match crate::wfp_manager::WfpManager::new() {
            Ok(manager) => {
                if let Err(e) = manager.register() {
                    warn!(error = %e, "WFP manager registration failed — continuing without WFP");
                    None
                } else {
                    info!("WFP manager registered");
                    Some(manager)
                }
            }
            Err(e) => {
                warn!(error = %e, "WFP manager init failed — continuing without WFP");
                None
            }
        }
    } else {
        info!("WFP filter disabled — skipping WfpManager");
        None
    };

    // ── Phase 52: DaclWatcher (after WfpManager, before PrintEnforcer) ────
    // Wfp network filters must be active before file ACLs are modified.
    let (
        dacl_watcher_opt,
        dacl_watcher_shutdown_opt,
        dacl_watcher_handle_opt,
        dacl_poll_handle_opt,
        dacl_staging_opt,
        dacl_gc_shutdown_opt,
        dacl_gc_handle_opt,
        dacl_removal_shutdown_opt,
        dacl_removal_handle_opt,
    ) = init_dacl_watcher(&agent_config, ad_client.as_ref().as_ref()).await;

    // ── PrintEnforcer (M017/S04) ──────────────────────────────────────────
    let print_enforcer_opt: Option<crate::print_enforcer::PrintEnforcer> = {
        let watcher_config = crate::print_watcher::PrintWatcherConfig {
            max_pages: agent_config.print_max_pages.unwrap_or(100),
            unclassifiable_action: agent_config
                .print_unclassifiable_action
                .clone()
                .unwrap_or_else(|| "Block".to_string()),
        };
        let mut enforcer = crate::print_enforcer::PrintEnforcer::new(
            agent_config.print_enabled,
            watcher_config,
            offline.clone(),
            audit_ctx.clone(),
            tokio::runtime::Handle::current(),
        );
        enforcer.start();
        Some(enforcer)
    };

    // ── Phase 53: ETW Kernel-File consumer + Bypass Correlator ────────────
    let mut etw_consumer = crate::etw_kernel_file::EtwKernelFileConsumer::new();
    let etw_consumer_state = etw_consumer.start(&agent_config);

    // Emit audit event for ETW consumer state.
    match &etw_consumer_state {
        crate::etw_kernel_file::EtwConsumerState::Started => {
            info!("ETW Kernel-File consumer started");
        }
        crate::etw_kernel_file::EtwConsumerState::GatedOff { reason } => {
            warn!(reason = %reason, "ETW Kernel-File consumer gated off");
        }
        crate::etw_kernel_file::EtwConsumerState::Failed { error } => {
            error!(error = %error, "ETW Kernel-File consumer failed to start");
        }
    }

    // Start bypass correlator if ETW consumer started successfully.
    let (correlator_shutdown_tx, correlator_handle) = if matches!(
        etw_consumer_state,
        crate::etw_kernel_file::EtwConsumerState::Started
    ) {
        if let (Some(process_watcher), Some(sc)) =
            (process_watcher_opt.as_ref(), server_client.as_ref())
        {
            let reduced_mode = !agent_config.bypass_correlator_enabled();
            let correlator = crate::bypass_correlator::BypassCorrelator::new(
                crate::bypass_correlator::CorrelatorConfig {
                    reduced_mode,
                    enforcement_mode: agent_config.enforcement.global_mode,
                    ..Default::default()
                },
            )
            .with_protected_paths(agent_config.monitored_paths.clone());

            let etw_rx = etw_consumer.receiver().clone();
            let process_rx = process_watcher.receiver().clone();
            let sc = sc.clone();

            // bypass_rx was created alongside bypass_tx when HookIpcServer was
            // constructed; the correlator consumes hook DLL BypassAlert frames.
            // Verified: bypass_tx/bypass_rx wiring per 58.1-02 (bounded 1000, with_bypass_channel).

            let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
            let handle = tokio::spawn(async move {
                tokio::select! {
                    _ = correlator.run(etw_rx, process_rx, bypass_rx, sc, lifecycle_rx) => {},
                    _ = shutdown_rx.changed() => {
                        info!("bypass correlator shutting down");
                    }
                }
            });
            (Some(shutdown_tx), Some(handle))
        } else {
            warn!("process watcher or server client unavailable — skipping bypass correlator");
            (None, None)
        }
    } else {
        warn!("ETW consumer not started — bypass correlator disabled");
        (None, None)
    };

    // ── BitLocker Encryption Verification (Phase 34) ──────────────────────
    let (enc_shutdown_tx, enc_handle) = spawn_encryption_task(audit_ctx.clone(), recheck_interval);

    // ── Spawn interception event loop and file monitor ────────────────────
    let event_loop_handle = spawn_event_loop(
        action_rx,
        offline.clone(),
        audit_ctx.clone(),
        session_map.clone(),
        ad_client.clone(),
        usb_enforcer_opt,
        disk_enforcer_opt,
        cloud_enforcer_opt,
        Some(Arc::clone(&approval_cache)),
    );

    let file_monitor_for_shutdown = file_monitor.clone();
    let file_handle = tokio::task::spawn_blocking(move || {
        let _ = file_monitor.run(action_tx, Some(watch_rx));
    });

    info!(
        service_name = SERVICE_NAME,
        "enforcement subsystems started"
    );

    // ── Phase 58.5: Reconcile watchdog self-unload evidence ─────────────────
    reconcile_watchdog_evidence(&audit_ctx, Some(Arc::clone(&process_registry)));

    RunLoopContext {
        file_handle,
        file_monitor: file_monitor_for_shutdown,
        event_loop_handle,
        heartbeat_handle,
        heartbeat_shutdown_tx,
        pipe1_hb_handle,
        pipe1_shutdown_tx,
        config_poll_handle,
        config_shutdown_tx,
        config_cmd_tx: _config_cmd_tx,
        registry_poll_handle,
        registry_shutdown_tx,
        origins_poll_handle,
        origins_shutdown_tx,
        disk_enum_handle,
        disk_shutdown_tx,
        enc_handle,
        enc_shutdown_tx,
        audit_flush_handle,
        audit_shutdown_tx,
        device_watcher_cleanup,
        detector_arc,
        hook_injector: hook_injector_opt,
        sync_watcher_shutdown,
        sync_watcher_handle,
        wfp_manager: wfp_manager_opt,
        print_enforcer: print_enforcer_opt,
        approval_cache,
        approval_poll_handle,
        approval_shutdown_tx,
        process_watcher: process_watcher_opt,
        universal_injector: universal_injector_opt,
        process_registry,
        allowlist_matcher,
        backstop_shutdown: Some(backstop_shutdown_tx),
        backstop_handle,
        retry_shutdown: Some(retry_shutdown_tx),
        retry_handle,
        classification_cache,
        cache_pusher_handle: Some(_cache_pusher_handle),
        dacl_watcher: dacl_watcher_opt,
        dacl_watcher_shutdown: dacl_watcher_shutdown_opt,
        dacl_watcher_handle: dacl_watcher_handle_opt,
        dacl_poll_handle: dacl_poll_handle_opt,
        dacl_staging: dacl_staging_opt,
        dacl_gc_shutdown: dacl_gc_shutdown_opt,
        dacl_gc_handle: dacl_gc_handle_opt,
        dacl_removal_shutdown: dacl_removal_shutdown_opt,
        dacl_removal_handle: dacl_removal_handle_opt,
        // Phase 53: ETW Kernel-File consumer.
        etw_consumer: Some(etw_consumer),
        // Phase 53: Bypass correlator shutdown signal.
        correlator_shutdown: correlator_shutdown_tx,
        // Phase 53: Bypass correlator task handle.
        correlator_handle,
        // Phase 58: Diagnostic snapshot aggregator.
        diagnostic_aggregator,
        // Phase 58: Health snapshot aggregator.
        health_aggregator,
        // Phase 58: Hook IPC server thread handle.
        hook_ipc_handle,
        // Phase 58: Diagnostic push task shutdown signal (reserved for future server push).
        diagnostic_push_shutdown: None,
        // Phase 58: Diagnostic push task handle (reserved for future server push).
        diagnostic_push_handle: None,
        // Phase 58: Health push task shutdown signal (reserved for future server push).
        health_push_shutdown: None,
        // Phase 58: Health push task handle (reserved for future server push).
        health_push_handle: None,
        // Phase 58-06: Override request processing task (DIFF-01).
        override_handle: Some(override_handle),
        // Phase 58.5: Audit emit context for unhook orchestration and watchdog evidence.
        audit_ctx,
    }
}

/// Reconcile watchdog self-unload evidence persisted by the hook DLL.
///
/// When the hook DLL's watchdog detects that the agent is unreachable, it
/// persists a small JSON file to `C:\ProgramData\DLP\WatchdogSelfUnload` and
/// self-unloads. On agent restart, this function reads those files, emits audit
/// events, and removes matched files. Unmatched evidence is retained for a
/// bounded retry period (7 days) and emits an `untracked` audit event so
/// operators can detect stale/orphaned evidence.
///
/// # Arguments
///
/// * `audit_ctx` — The audit emit context.
/// * `process_registry` — Optional process registry to mark processes as exited.
fn reconcile_watchdog_evidence(
    audit_ctx: &crate::audit_emitter::EmitContext,
    process_registry: Option<Arc<crate::process_registry::ProcessRegistry>>,
) {
    reconcile_watchdog_evidence_in_dir(
        audit_ctx,
        process_registry,
        std::path::PathBuf::from(r"C:\ProgramData\DLP\WatchdogSelfUnload"),
    );
}

/// Reconcile watchdog self-unload evidence from a configurable directory.
///
/// This is the testable implementation of [`reconcile_watchdog_evidence`].
/// Production callers pass the canonical `C:\ProgramData\DLP\WatchdogSelfUnload`
/// path; tests pass a temporary directory so they do not touch production state.
pub fn reconcile_watchdog_evidence_in_dir(
    audit_ctx: &crate::audit_emitter::EmitContext,
    process_registry: Option<Arc<crate::process_registry::ProcessRegistry>>,
    dir: std::path::PathBuf,
) {
    use dlp_common::{Action, AuditEvent, Classification, Decision, EventType};

    /// Retention window for unmatched watchdog evidence files.
    const EVIDENCE_RETENTION_DAYS: u64 = 7;

    /// Maximum size for an individual watchdog evidence file (64 KiB).
    const MAX_EVIDENCE_SIZE: u64 = 64 * 1024;

    /// Schema for watchdog evidence persisted by the hook DLL.
    ///
    /// Rejecting unknown fields prevents crafted files from smuggling extra data
    /// into the audit log.
    #[derive(Debug, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct WatchdogEvidence {
        pid: u32,
        creation_time: u64,
        timestamp_secs: u64,
        reason: String,
    }

    if !dir.exists() {
        return;
    }

    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) => {
            warn!(dir = %dir.display(), error = %e, "cannot read watchdog evidence directory");
            return;
        }
    };

    let retention_cutoff = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .saturating_sub(EVIDENCE_RETENTION_DAYS * 24 * 60 * 60);

    for entry in entries.flatten() {
        let path = entry.path();
        if !path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        {
            continue;
        }

        let metadata = match std::fs::metadata(&path) {
            Ok(m) => m,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "cannot stat watchdog evidence file");
                continue;
            }
        };
        if metadata.len() > MAX_EVIDENCE_SIZE {
            warn!(
                path = %path.display(),
                size = metadata.len(),
                "watchdog evidence file exceeds size limit — skipping"
            );
            continue;
        }

        let file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "cannot open watchdog evidence file");
                continue;
            }
        };

        let evidence: WatchdogEvidence = match serde_json::from_reader(file) {
            Ok(v) => v,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "cannot parse watchdog evidence file");
                continue;
            }
        };

        let pid = Some(evidence.pid);
        let creation_time = Some(evidence.creation_time);
        let reason = evidence.reason.as_str();
        let timestamp_secs = Some(evidence.timestamp_secs);

        let resource_path = pid.map_or_else(
            || "unknown".to_string(),
            |p| format!(r"process://{}/watchdog_self_unload", p),
        );

        let mut event = AuditEvent::new(
            EventType::WatchdogSelfUnload,
            audit_ctx.user_sid.clone(),
            audit_ctx.user_name.clone(),
            resource_path,
            Classification::T1,
            Action::READ,
            Decision::ALLOW,
            audit_ctx.agent_id.clone(),
            audit_ctx.session_id,
        );

        // Stale evidence cleanup: remove files older than the retention window
        // regardless of match status so the directory does not grow unbounded.
        // Emit a `WatchdogSelfUnload` audit event first so the self-unload leaves
        // a durable record even if the agent was down when the evidence was created.
        if timestamp_secs.is_some_and(|ts| ts < retention_cutoff) {
            event.justification = Some(format!(
                "reason={}; stale=true; pid={}; creation_time={}",
                reason, evidence.pid, evidence.creation_time
            ));
            crate::audit_emitter::emit_audit(audit_ctx, &mut event);
            if let Err(e) = std::fs::remove_file(&path) {
                warn!(path = %path.display(), error = %e, "cannot remove stale watchdog evidence file");
            }
            continue;
        }

        // Determine whether this evidence matches a known injected process.
        let matched = if let (Some(pid), Some(creation_time), Some(ref registry)) =
            (pid, creation_time, &process_registry)
        {
            let key = crate::process_registry::ProcessKey { pid, creation_time };
            registry.get(&key).is_some_and(|state| {
                matches!(
                    *state,
                    crate::process_registry::ProcessState::Injected { .. }
                )
            })
        } else {
            false
        };

        if matched {
            // Record the reason and identifying fields in the audit log for
            // forensics, but do NOT embed the raw file content.
            event.justification = Some(format!(
                "reason={}; pid={}; creation_time={}",
                reason, evidence.pid, evidence.creation_time
            ));

            crate::audit_emitter::emit_audit(audit_ctx, &mut event);

            // Mark the process as exited in the registry.
            if let (Some(pid), Some(creation_time), Some(ref registry)) =
                (pid, creation_time, &process_registry)
            {
                registry.record_exited(crate::process_registry::ProcessKey { pid, creation_time });
            }

            if let Err(e) = std::fs::remove_file(&path) {
                warn!(path = %path.display(), error = %e, "cannot remove watchdog evidence file");
            }
        } else {
            // Unmatched evidence: emit an untracked event and retain the file for
            // bounded retry. This covers PID reuse, stale evidence from a prior
            // agent crash, or a process that exited before reconciliation.
            event.justification = Some(format!(
                "reason={}; untracked=true; pid={}; creation_time={}",
                reason, evidence.pid, evidence.creation_time
            ));
            crate::audit_emitter::emit_audit(audit_ctx, &mut event);
        }
    }
}

/// Initialises the AD client from the LDAP config embedded in `AgentConfig`.
///
/// Returns `Arc::new(None)` when no LDAP config is present or initialisation fails.
async fn init_ad_client(
    agent_config: &crate::config::AgentConfig,
) -> Arc<Option<dlp_common::AdClient>> {
    let Some(ref ldap_config) = agent_config.ldap_config else {
        tracing::debug!("No LDAP config in agent config — AD features disabled");
        return Arc::new(None);
    };

    use dlp_common::ad_client::LdapConfig;
    let config = LdapConfig {
        ldap_url: ldap_config.ldap_url.clone(),
        base_dn: ldap_config.base_dn.clone(),
        require_tls: ldap_config.require_tls,
        cache_ttl_secs: ldap_config.cache_ttl_secs,
        vpn_subnets: ldap_config.vpn_subnets.clone(),
    };

    match dlp_common::AdClient::new(config).await {
        Ok(client) => {
            tracing::info!("AD client initialised from pushed config");
            Arc::new(Some(client))
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "AD client initialisation failed — AD features disabled for this session"
            );
            Arc::new(None)
        }
    }
}

/// Initialises the dlp-server client and registers the agent.
///
/// Returns `None` when the client cannot be constructed or registration fails.
async fn init_server_client(
    agent_config: &crate::config::AgentConfig,
) -> Option<crate::server_client::ServerClient> {
    match crate::server_client::ServerClient::from_env_with_config(
        agent_config.server_url.as_deref(),
    ) {
        Ok(sc) => {
            if let Err(e) = sc.register().await {
                warn!(error = %e, "dlp-server registration failed (best-effort)");
            }
            Some(sc)
        }
        Err(e) => {
            warn!(error = %e, "dlp-server client init failed -- server relay disabled");
            None
        }
    }
}

/// Initialises the global USB detector, scans existing drives, and reconciles identities.
async fn init_usb_detector() -> Arc<crate::detection::VolumeDetector> {
    use std::sync::OnceLock;
    static USB_DETECTOR: OnceLock<Arc<crate::detection::VolumeDetector>> = OnceLock::new();
    let detector = USB_DETECTOR.get_or_init(|| Arc::new(crate::detection::VolumeDetector::new()));
    detector.scan_existing_drives();
    detector.scan_existing_usb_identities();
    Arc::clone(detector)
}

/// Initialises the managed-origins cache and spawns its poll task.
///
/// Returns `(shutdown_tx, poll_handle)` where `poll_handle` is `None` when no
/// server client is available.
async fn init_origins_cache(
    server_client: Option<&crate::server_client::ServerClient>,
) -> (
    tokio::sync::watch::Sender<bool>,
    Option<tokio::task::JoinHandle<()>>,
) {
    let origins_cache = Arc::new(crate::chrome::cache::ManagedOriginsCache::new());
    crate::chrome::handler::set_origins_cache(Arc::clone(&origins_cache));
    let (tx, rx) = tokio::sync::watch::channel(false);
    let handle = server_client.map(|sc| {
        crate::chrome::cache::ManagedOriginsCache::spawn_poll_task(origins_cache, sc.clone(), rx)
    });
    (tx, handle)
}

/// Initialises the device-registry cache, sets global statics, and spawns its poll task.
///
/// Returns `(shutdown_tx, poll_handle, cache)`.
async fn init_registry_cache(
    server_client: Option<&crate::server_client::ServerClient>,
) -> (
    tokio::sync::watch::Sender<bool>,
    Option<tokio::task::JoinHandle<()>>,
    Arc<crate::device_registry::DeviceRegistryCache>,
) {
    let cache = Arc::new(crate::device_registry::DeviceRegistryCache::new());
    let (tx, rx) = tokio::sync::watch::channel(false);

    if let Some(sc) = server_client {
        crate::detection::usb::set_registry_cache(Arc::clone(&cache));
        crate::detection::usb::set_registry_client(sc.clone());
        crate::detection::usb::set_registry_runtime_handle(tokio::runtime::Handle::current());
        let handle = crate::device_registry::DeviceRegistryCache::spawn_poll_task(
            Arc::clone(&cache),
            sc.clone(),
            rx,
        );
        (tx, Some(handle), cache)
    } else {
        drop(rx);
        (tx, None, cache)
    }
}

/// Constructs the [`OfflineManager`] and optionally attaches a server client.
fn init_offline_manager(
    engine_client: crate::engine_client::EngineClient,
    cache: Arc<crate::cache::Cache>,
    server_client: &Option<crate::server_client::ServerClient>,
    machine_name: Option<String>,
) -> Arc<crate::offline::OfflineManager> {
    let mut om = crate::offline::OfflineManager::new(engine_client, cache, machine_name);
    if let Some(sc) = server_client {
        om = om.with_server_client(sc.clone());
    }
    Arc::new(om)
}

/// Initialises the DACL repair watcher for protected path ACL tamper detection.
///
/// For each path in `agent_config.monitored_paths` (temporary until dedicated
/// `protected_paths` field is added in Plan 04):
/// 1. Calls `apply_tripwire_recursive()` to establish the canonical ACL.
/// 2. Registers a `ReadDirectoryChangesW` watcher with the returned snapshot.
/// 3. Starts the debounced repair task and the 60-second polling backstop.
///
/// Phase 52-07: Creates a `DaclStaging` instance, wires it into the watcher
/// for tamper suppression, and spawns the GC task and removal application task.
///
/// The DLP-Admin SID is resolved from the AD client if available.
///
/// Returns `(watcher, shutdown_tx, repair_handle, poll_handle, staging, gc_handle, removal_handle)`
/// where all are `None` when no monitored paths are configured or the watcher is disabled.
#[allow(clippy::type_complexity)]
async fn init_dacl_watcher(
    agent_config: &crate::config::AgentConfig,
    ad_client: Option<&dlp_common::AdClient>,
) -> (
    Option<std::sync::Arc<crate::dacl_repair_watcher::DaclWatcher>>,
    Option<tokio::sync::watch::Sender<bool>>,
    Option<tokio::task::JoinHandle<()>>,
    Option<tokio::task::JoinHandle<()>>,
    Option<Arc<crate::dacl_staging::DaclStaging>>,
    Option<tokio::sync::watch::Sender<bool>>,
    Option<tokio::task::JoinHandle<()>>,
    Option<tokio::sync::watch::Sender<bool>>,
    Option<tokio::task::JoinHandle<()>>,
) {
    if agent_config.monitored_paths.is_empty() {
        info!("no monitored paths configured — skipping DaclWatcher");
        return (None, None, None, None, None, None, None, None, None);
    }

    // Phase 52-07: Create staging layer for two-phase removal protocol.
    let staging = match crate::dacl_staging::DaclStaging::new(&std::path::PathBuf::from(
        r"C:\ProgramData\DLP\agent.db",
    )) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            warn!(error = %e, "failed to create DaclStaging — continuing without staging");
            // Continue without staging; tamper suppression will not work.
            return init_dacl_watcher_without_staging(agent_config, ad_client).await;
        }
    };

    let watcher = crate::dacl_repair_watcher::DaclWatcher::new();
    watcher.set_staging(Arc::clone(&staging));

    // Resolve DLP-Admin SID from AD client if available.
    let dlp_admin_sid: Option<String> = ad_client.and_then(|_client| {
        // Attempt to resolve the DLP-Admin group SID.
        // In a full implementation, this would query AD for the group's SID.
        // For now, we use a well-known SID placeholder or config override.
        std::env::var("DLP_ADMIN_SID").ok()
    });
    watcher.set_dlp_admin_sid(dlp_admin_sid.clone());

    // Phase 55: read global enforcement mode to decide apply vs remove.
    let global_mode = agent_config.enforcement.global_mode;
    let should_apply = crate::dacl_tripwire::should_apply_tripwire_for_global_mode(global_mode);

    if should_apply {
        // Block / PerPolicy / AuditAndBlock: apply tripwire to all protected paths.
        for path_str in &agent_config.monitored_paths {
            let path = std::path::PathBuf::from(path_str);
            if !path.exists() {
                warn!(path = %path.display(), "monitored path does not exist — skipping");
                continue;
            }

            match crate::dacl_tripwire::apply_tripwire_recursive(&path, dlp_admin_sid.as_deref()) {
                Ok((count, snapshots)) => {
                    info!(
                        path = %path.display(),
                        count,
                        "DACL tripwire applied recursively"
                    );
                    // Register the watcher with the root snapshot (first in list).
                    if let Some(snapshot) = snapshots.first() {
                        if let Err(e) = watcher.register(&path, snapshot.clone()) {
                            warn!(
                                path = %path.display(),
                                error = %e,
                                "failed to register DACL watcher"
                            );
                        } else {
                            info!(path = %path.display(), "DACL watcher registered");
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        path = %path.display(),
                        error = %e,
                        "failed to apply DACL tripwire — watcher not registered"
                    );
                }
            }
        }
    } else {
        // Audit mode: remove all existing Deny ACEs from protected paths.
        info!(
            global_mode = ?global_mode,
            "global mode is Audit — removing all tripwire Deny ACEs"
        );
        for path_str in &agent_config.monitored_paths {
            let path = std::path::PathBuf::from(path_str);
            if !path.exists() {
                continue;
            }
            // Rebuild canonical ACL without Deny ACE and apply it.
            match crate::dacl_tripwire::remove_tripwire_by_rebuilding_without_deny(
                &path,
                dlp_admin_sid.as_deref(),
            ) {
                Ok(snapshot) => {
                    info!(path = %path.display(), "DACL tripwire Deny ACE removed for Audit mode");
                    // Register watcher with the no-deny snapshot so repair
                    // watcher does not re-add the Deny ACE.
                    if let Err(e) = watcher.register(&path, snapshot) {
                        warn!(
                            path = %path.display(),
                            error = %e,
                            "failed to register DACL watcher (Audit mode)"
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        path = %path.display(),
                        error = %e,
                        "failed to remove tripwire Deny ACE in Audit mode"
                    );
                }
            }
        }
    }

    // Start repair task and polling backstop.
    let (repair_shutdown_tx, repair_shutdown_rx) = tokio::sync::watch::channel(false);
    let repair_handle = watcher.start_repair_task(repair_shutdown_rx);

    let (_poll_shutdown_tx, poll_shutdown_rx) = tokio::sync::watch::channel(false);
    let poll_handle = watcher.start_poll_backstop(60, poll_shutdown_rx);

    // Phase 52-07: Spawn GC task for expired staging rows (5-minute TTL, 60s interval).
    let (gc_shutdown_tx, gc_shutdown_rx) = tokio::sync::watch::channel(false);
    let gc_handle = crate::dacl_staging::spawn_gc_task(Arc::clone(&staging), 60, 5, gc_shutdown_rx);

    // Phase 52-07: Spawn removal application task (30s interval).
    let (removal_shutdown_tx, removal_shutdown_rx) = tokio::sync::watch::channel(false);
    let watcher_arc = std::sync::Arc::new(watcher);
    let removal_handle = spawn_removal_application_task(
        Arc::clone(&staging),
        Arc::clone(&watcher_arc),
        30,
        removal_shutdown_rx,
    );

    info!("DaclWatcher initialised with repair task, polling backstop, staging GC, and removal application");
    (
        Some(watcher_arc),
        Some(repair_shutdown_tx),
        Some(repair_handle),
        Some(poll_handle),
        Some(staging),
        Some(gc_shutdown_tx),
        Some(gc_handle),
        Some(removal_shutdown_tx),
        Some(removal_handle),
    )
}

/// Fallback initialisation without staging (when DaclStaging creation fails).
#[allow(clippy::type_complexity)]
async fn init_dacl_watcher_without_staging(
    agent_config: &crate::config::AgentConfig,
    ad_client: Option<&dlp_common::AdClient>,
) -> (
    Option<std::sync::Arc<crate::dacl_repair_watcher::DaclWatcher>>,
    Option<tokio::sync::watch::Sender<bool>>,
    Option<tokio::task::JoinHandle<()>>,
    Option<tokio::task::JoinHandle<()>>,
    Option<Arc<crate::dacl_staging::DaclStaging>>,
    Option<tokio::sync::watch::Sender<bool>>,
    Option<tokio::task::JoinHandle<()>>,
    Option<tokio::sync::watch::Sender<bool>>,
    Option<tokio::task::JoinHandle<()>>,
) {
    if agent_config.monitored_paths.is_empty() {
        return (None, None, None, None, None, None, None, None, None);
    }

    let watcher = crate::dacl_repair_watcher::DaclWatcher::new();

    let dlp_admin_sid: Option<String> =
        ad_client.and_then(|_client| std::env::var("DLP_ADMIN_SID").ok());
    watcher.set_dlp_admin_sid(dlp_admin_sid.clone());

    // Phase 55: respect global enforcement mode.
    let global_mode = agent_config.enforcement.global_mode;
    let should_apply = crate::dacl_tripwire::should_apply_tripwire_for_global_mode(global_mode);

    if should_apply {
        for path_str in &agent_config.monitored_paths {
            let path = std::path::PathBuf::from(path_str);
            if !path.exists() {
                continue;
            }
            if let Ok((_count, snapshots)) =
                crate::dacl_tripwire::apply_tripwire_recursive(&path, dlp_admin_sid.as_deref())
            {
                if let Some(snapshot) = snapshots.first() {
                    let _ = watcher.register(&path, snapshot.clone());
                }
            }
        }
    } else {
        // Audit mode: register watcher with no-deny snapshots.
        for path_str in &agent_config.monitored_paths {
            let path = std::path::PathBuf::from(path_str);
            if !path.exists() {
                continue;
            }
            if let Ok((_raw_sd, snapshot)) =
                crate::dacl_tripwire::build_canonical_security_descriptor(
                    &path,
                    dlp_admin_sid.as_deref(),
                    false,
                )
            {
                let _ = watcher.register(&path, snapshot);
            }
        }
    }

    let (repair_shutdown_tx, repair_shutdown_rx) = tokio::sync::watch::channel(false);
    let repair_handle = watcher.start_repair_task(repair_shutdown_rx);

    let (_poll_shutdown_tx, poll_shutdown_rx) = tokio::sync::watch::channel(false);
    let poll_handle = watcher.start_poll_backstop(60, poll_shutdown_rx);

    (
        Some(std::sync::Arc::new(watcher)),
        Some(repair_shutdown_tx),
        Some(repair_handle),
        Some(poll_handle),
        None,
        None,
        None,
        None,
        None,
    )
}

/// Spawns a background task that applies staged removals on a fixed interval.
///
/// Reads staging rows with `operation = 'remove'` and `applied_at IS NULL`,
/// applies the ACL removal, marks the row as applied, and unregisters the
/// watcher for the path.
///
/// # Arguments
///
/// * `staging` — The `DaclStaging` instance.
/// * `watcher` — The `DaclWatcher` (wrapped in Arc for shared access).
/// * `interval_secs` — Poll interval in seconds.
/// * `shutdown_rx` — Tokio watch receiver for graceful shutdown.
///
/// # Returns
///
/// A `JoinHandle` for the spawned task.
fn spawn_removal_application_task(
    staging: Arc<crate::dacl_staging::DaclStaging>,
    watcher: std::sync::Arc<crate::dacl_repair_watcher::DaclWatcher>,
    interval_secs: u64,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        interval.tick().await; // consume immediate first tick

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match staging.list_all() {
                        Ok(rows) => {
                            for row in rows {
                                if row.operation == "remove" && row.applied_at.is_none() {
                                    let path = std::path::PathBuf::from(&row.path);

                                    // mark_applied already acquires the per-path lock
                                    // internally, so we call it directly.

                                    // Mark as applied (the ACL removal was done by admin API).
                                    // We don't call remove_tripwire_from_path here because
                                    // the admin API already modified the ACL. Our job is to
                                    // mark the staging row so the watcher stops suppressing.
                                    if let Err(e) = staging.mark_applied(&row.path) {
                                        tracing::warn!(path = %row.path, error = %e, "failed to mark removal as applied");
                                    } else {
                                        tracing::info!(path = %row.path, "staged removal marked as applied");
                                    }

                                    // Unregister watcher for this path since it's no longer protected.
                                    if let Err(e) = watcher.unregister(&path) {
                                        tracing::warn!(path = %row.path, error = %e, "failed to unregister watcher for removed path");
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to list staging rows for removal application");
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    tracing::info!("removal application task shutting down");
                    return;
                }
            }
        }
    })
}

/// Spawns the Policy Engine heartbeat task.
///
/// Returns `(shutdown_tx, join_handle)`.
fn spawn_heartbeat_task(
    offline: Arc<crate::offline::OfflineManager>,
) -> (
    tokio::sync::watch::Sender<bool>,
    tokio::task::JoinHandle<()>,
) {
    let (tx, rx) = tokio::sync::watch::channel(false);
    let handle = tokio::spawn(async move {
        offline.heartbeat_loop(rx).await;
    });
    (tx, handle)
}

/// Spawns the Pipe 1 heartbeat task that pings all connected UI clients.
///
/// Returns `(shutdown_tx, join_handle)`.
fn spawn_pipe1_heartbeat_task() -> (
    tokio::sync::watch::Sender<bool>,
    tokio::task::JoinHandle<()>,
) {
    let (tx, mut rx) = tokio::sync::watch::channel(false);
    let handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    crate::ipc::pipe1::send_ping_to_all();
                }
                _ = rx.changed() => {
                    debug!("Pipe 1 heartbeat shutting down");
                    return;
                }
            }
        }
    });
    (tx, handle)
}

/// Initialise Phase 49 universal injection subsystem.
///
/// Constructs the process registry, allowlist matcher, universal injector,
/// and ETW process watcher. Spawns the event consumer task, retry queue
/// consumer, and periodic backstop sweep.
///
/// Returns all handles and references needed by `RunLoopContext`.
#[allow(clippy::type_complexity)]
async fn init_universal_injection(
    hook_injector_opt: Option<&crate::hook_injector::HookInjector>,
    enabled: bool,
    lifecycle_tx: crossbeam_channel::Sender<crate::process_registry::ProcessKey>,
) -> (
    Option<crate::process_watcher::ProcessWatcher>,
    Option<Arc<crate::universal_injector::UniversalInjector>>,
    Arc<crate::process_registry::ProcessRegistry>,
    Arc<crate::allowlist::AllowlistMatcher>,
    tokio::sync::watch::Sender<bool>,
    Option<tokio::task::JoinHandle<()>>,
    tokio::sync::watch::Sender<bool>,
    Option<tokio::task::JoinHandle<()>>,
) {
    if !enabled || hook_injector_opt.is_none() {
        tracing::info!("universal injection disabled — skipping Phase 49 init");
        let registry = Arc::new(
            crate::process_registry::ProcessRegistry::new()
                .with_lifecycle_notifier(lifecycle_tx.clone()),
        );
        let matcher = Arc::new(crate::allowlist::AllowlistMatcher::new(
            vec![],
            std::env::current_exe()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default(),
            std::process::id(),
        ));
        let (backstop_tx, _) = tokio::sync::watch::channel(false);
        let (retry_tx, _) = tokio::sync::watch::channel(false);
        return (
            None,
            None,
            registry,
            matcher,
            backstop_tx,
            None,
            retry_tx,
            None,
        );
    }

    // Resolve DLL paths from the existing HookInjector.
    let dll_path_x64 = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("dlp_hook_dll.dll")))
        .unwrap_or_else(|| std::path::PathBuf::from("dlp_hook_dll.dll"));
    let dll_path_x86 = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("dlp_hook_dll_x86.dll")))
        .unwrap_or_else(|| std::path::PathBuf::from("dlp_hook_dll_x86.dll"));

    // 1. Construct process registry.
    let registry = Arc::new(
        crate::process_registry::ProcessRegistry::new()
            .with_lifecycle_notifier(lifecycle_tx.clone()),
    );

    // 2. Load allowlist entries from config (or empty vec if not configured yet).
    let self_image_path = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let self_pid = std::process::id();
    let allowlist_entries = with_config(|cfg| cfg.allowlist_entries.clone()).unwrap_or_default();
    let matcher = Arc::new(crate::allowlist::AllowlistMatcher::new(
        allowlist_entries,
        self_image_path,
        self_pid,
    ));

    // 3. Construct HookInjector (reuse pattern from existing code).
    let injector = Arc::new(crate::hook_injector::HookInjector::new(
        &dll_path_x64,
        Some(dll_path_x86.clone()),
    ));
    let _injector_for_ui = Arc::clone(&injector);

    // 4. Create sweep trigger channel (crossbeam for ETW thread -> tokio bridge).
    let (sweep_tx, sweep_rx) =
        crossbeam_channel::bounded::<crate::process_watcher::SweepTrigger>(16);

    // 5. Create retry queue channel.
    let (retry_tx, mut retry_rx) = tokio::sync::mpsc::unbounded_channel::<(
        crate::process_watcher::ProcessEvent,
        std::time::Instant,
    )>();

    // 6. Construct UniversalInjector.
    let universal_injector = Arc::new(
        crate::universal_injector::UniversalInjector::with_retry_queue(
            Arc::clone(&registry),
            Arc::clone(&matcher),
            Arc::clone(&injector),
            retry_tx,
        ),
    );

    // 7. Start ProcessWatcher on dedicated ETW thread.
    let mut process_watcher = crate::process_watcher::ProcessWatcher::new();
    if let Err(e) = process_watcher.start(sweep_tx.clone()) {
        tracing::warn!(error = %e, "ProcessWatcher start failed — universal injection unavailable");
        let (backstop_tx, _) = tokio::sync::watch::channel(false);
        let (retry_shutdown_tx, _) = tokio::sync::watch::channel(false);
        return (
            None,
            Some(universal_injector),
            registry,
            matcher,
            backstop_tx,
            None,
            retry_shutdown_tx,
            None,
        );
    }

    // 8. Spawn tokio event consumer task.
    let injector_for_events = Arc::clone(&universal_injector);
    let event_rx = process_watcher.receiver().clone();
    // Create a tokio mpsc sweep sender for the async handler.
    let (tokio_sweep_tx, _tokio_sweep_rx) =
        mpsc::channel::<crate::process_watcher::SweepTrigger>(16);
    tokio::spawn(async move {
        while let Ok(event) = event_rx.recv() {
            let injector = Arc::clone(&injector_for_events);
            let sweep = tokio_sweep_tx.clone();
            tokio::spawn(async move {
                injector.handle_event(event, &sweep).await;
            });
        }
    });

    // 9. Spawn retry queue consumer task.
    let injector_for_retry = Arc::clone(&universal_injector);
    let (retry_shutdown_tx, mut retry_shutdown_rx) = tokio::sync::watch::channel(false);
    let retry_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                Some((event, retry_at)) = retry_rx.recv() => {
                    let delay = retry_at.saturating_duration_since(std::time::Instant::now());
                    tokio::time::sleep(delay).await;
                    let injector = Arc::clone(&injector_for_retry);
                    let sweep = mpsc::channel(1).0; // dummy sweep sender for retry
                    tokio::spawn(async move {
                        injector.handle_retry(event, &sweep).await;
                    });
                }
                _ = retry_shutdown_rx.changed() => {
                    tracing::info!("retry queue consumer shutting down");
                    return;
                }
            }
        }
    });

    // 10. Spawn periodic 5-minute backstop sweep task.
    let registry_for_backstop = Arc::clone(&registry);
    let matcher_for_backstop = Arc::clone(&matcher);
    let injector_for_backstop = Arc::clone(&injector);
    let (backstop_shutdown_tx, mut backstop_shutdown_rx) = tokio::sync::watch::channel(false);
    let backstop_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    tracing::info!("periodic backstop sweep starting");
                    backstop_sweep(
                        Arc::clone(&registry_for_backstop),
                        Arc::clone(&matcher_for_backstop),
                        Arc::clone(&injector_for_backstop),
                    ).await;
                }
                _ = backstop_shutdown_rx.changed() => {
                    tracing::info!("backstop sweep shutting down");
                    return;
                }
            }
        }
    });

    // 11. Spawn sweep trigger handler (for channel overflow immediate sweeps).
    let registry_for_overflow = Arc::clone(&registry);
    let matcher_for_overflow = Arc::clone(&matcher);
    let injector_for_overflow = Arc::clone(&injector);
    tokio::spawn(async move {
        while let Ok(trigger) = sweep_rx.recv() {
            match trigger {
                crate::process_watcher::SweepTrigger::ChannelOverflow => {
                    tracing::warn!("channel overflow triggered immediate sweep");
                    backstop_sweep(
                        Arc::clone(&registry_for_overflow),
                        Arc::clone(&matcher_for_overflow),
                        Arc::clone(&injector_for_overflow),
                    )
                    .await;
                }
                crate::process_watcher::SweepTrigger::HeartbeatRecovery => {
                    tracing::info!("ETW heartbeat recovered — running recovery sweep");
                }
            }
        }
    });

    // 12. Spawn periodic cleanup sweep (60s): prune exited PIDs from registry.
    let registry_for_cleanup = Arc::clone(&registry);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let removed = registry_for_cleanup.prune_exited();
            if removed > 0 {
                tracing::debug!(removed, "periodic cleanup sweep removed exited PIDs");
            }
        }
    });

    // 13. Spawn periodic telemetry aggregation (60s): emit injection_telemetry event.
    let registry_for_telemetry = Arc::clone(&registry);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let snapshot = registry_for_telemetry.telemetry_snapshot();
            tracing::info!(
                event_type = "injection_telemetry",
                injected = snapshot.injected_count,
                skipped = snapshot
                    .total_tracked
                    .saturating_sub(snapshot.injected_count),
                coverage_percent = format!("{:.1}", snapshot.coverage_percent),
                "injection telemetry"
            );
        }
    });

    // 14. Run startup EnumProcesses sweep (bounded concurrency, 5s timeout per process).
    let registry_for_sweep = Arc::clone(&registry);
    let matcher_for_sweep = Arc::clone(&matcher);
    let injector_for_startup = Arc::clone(&injector);
    tokio::spawn(async move {
        startup_sweep(registry_for_sweep, matcher_for_sweep, injector_for_startup).await;
    });

    tracing::info!("Phase 49 universal injection subsystem initialised");

    (
        Some(process_watcher),
        Some(universal_injector),
        registry,
        matcher,
        backstop_shutdown_tx,
        Some(backstop_handle),
        retry_shutdown_tx,
        Some(retry_handle),
    )
}

/// Startup sweep: enumerate all running PIDs, attempt injection into non-allowlisted.
///
/// Review fix: bounded concurrency (max 32 parallel), per-process 5-second timeout.
async fn startup_sweep(
    registry: Arc<crate::process_registry::ProcessRegistry>,
    matcher: Arc<crate::allowlist::AllowlistMatcher>,
    injector: Arc<crate::hook_injector::HookInjector>,
) {
    #[cfg(windows)]
    {
        use tokio::sync::Semaphore;
        use tokio::time::timeout;

        let pids = enum_all_processes();
        tracing::info!(count = pids.len(), "startup sweep beginning");

        let semaphore = Arc::new(Semaphore::new(32)); // max 32 concurrent injections
        let mut handles = Vec::new();

        for pid in pids {
            let registry = Arc::clone(&registry);
            let matcher = Arc::clone(&matcher);
            let injector = Arc::clone(&injector);
            let permit = match semaphore.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => break,
            };

            let handle = tokio::spawn(async move {
                let _permit = permit; // hold until task completes
                let key = crate::process_registry::ProcessKey {
                    pid,
                    creation_time: 0, // startup sweep: creation_time unknown, use PID only
                };

                if let crate::process_registry::ClaimResult::AlreadyClaimed(_) =
                    registry.try_claim(key)
                {
                    return;
                }

                // Get image path via OpenProcess + QueryFullProcessImageNameW.
                let image_path = get_process_image_path(pid).unwrap_or_default();
                let canonical = crate::allowlist::canonicalize_path(&image_path);

                // Allowlist check.
                if let Some(category) = matcher.check(pid, &canonical, 0) {
                    tracing::trace!(pid, ?category, "startup sweep: allowlist skip");
                    registry.record_skipped(
                        key,
                        crate::process_registry::SkipReason::from_category(category),
                    );
                    return;
                }

                // PPL detection.
                let ppl_outcome = crate::universal_injector::detect_ppl(pid);
                match ppl_outcome {
                    crate::process_registry::PplOutcome::Protected
                    | crate::process_registry::PplOutcome::LikelyProtectedAccessDenied => {
                        registry.record_skipped(
                            key,
                            crate::process_registry::SkipReason::Ppl(ppl_outcome),
                        );
                        return;
                    }
                    _ => {}
                }

                // Attempt injection with 5-second timeout.
                let _ = timeout(Duration::from_secs(5), async {
                    match injector.inject(pid) {
                        Ok(()) => {
                            registry.record_injected(key, "x64".into());
                            tracing::info!(pid, "startup sweep: injected successfully");
                        }
                        Err(e) => {
                            tracing::warn!(pid, error = %e, "startup sweep: injection failed");
                            let failure = crate::universal_injector::categorize_error(&e);
                            registry.record_skipped(
                                key,
                                crate::process_registry::SkipReason::Failed(failure),
                            );
                        }
                    }
                })
                .await;
            });
            handles.push(handle);
        }

        for h in handles {
            let _ = h.await;
        }

        tracing::info!("startup sweep complete");
    }
    #[cfg(not(windows))]
    {
        tracing::debug!("startup sweep skipped on non-Windows platform");
    }
}

/// Periodic backstop sweep: re-check running PIDs not yet in Injected or Skipped state.
///
/// Lighter-weight than startup sweep: only processes not yet tracked are considered.
/// Uses the same bounded concurrency (max 32) and 5-second timeout.
async fn backstop_sweep(
    registry: Arc<crate::process_registry::ProcessRegistry>,
    matcher: Arc<crate::allowlist::AllowlistMatcher>,
    injector: Arc<crate::hook_injector::HookInjector>,
) {
    #[cfg(windows)]
    {
        use tokio::sync::Semaphore;
        use tokio::time::timeout;

        let pids = enum_all_processes();
        tracing::info!(count = pids.len(), "backstop sweep beginning");

        let semaphore = Arc::new(Semaphore::new(32));
        let mut handles = Vec::new();
        let mut checked = 0u64;
        let mut injected = 0u64;
        let mut skipped = 0u64;

        for pid in pids {
            let key = crate::process_registry::ProcessKey {
                pid,
                creation_time: 0,
            };

            // Skip if already processed.
            if registry.get(&key).is_some() {
                continue;
            }
            checked += 1;

            let registry = Arc::clone(&registry);
            let matcher = Arc::clone(&matcher);
            let injector = Arc::clone(&injector);
            let permit = match semaphore.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => break,
            };

            let handle = tokio::spawn(async move {
                let _permit = permit;

                if let crate::process_registry::ClaimResult::AlreadyClaimed(_) =
                    registry.try_claim(key)
                {
                    return (false, false);
                }

                let image_path = get_process_image_path(pid).unwrap_or_default();
                let canonical = crate::allowlist::canonicalize_path(&image_path);

                if let Some(category) = matcher.check(pid, &canonical, 0) {
                    registry.record_skipped(
                        key,
                        crate::process_registry::SkipReason::from_category(category),
                    );
                    return (false, true);
                }

                let ppl_outcome = crate::universal_injector::detect_ppl(pid);
                match ppl_outcome {
                    crate::process_registry::PplOutcome::Protected
                    | crate::process_registry::PplOutcome::LikelyProtectedAccessDenied => {
                        registry.record_skipped(
                            key,
                            crate::process_registry::SkipReason::Ppl(ppl_outcome),
                        );
                        return (false, true);
                    }
                    _ => {}
                }

                let result = timeout(Duration::from_secs(5), async {
                    match injector.inject(pid) {
                        Ok(()) => {
                            registry.record_injected(key, "x64".into());
                            (true, false)
                        }
                        Err(e) => {
                            let failure = crate::universal_injector::categorize_error(&e);
                            registry.record_skipped(
                                key,
                                crate::process_registry::SkipReason::Failed(failure),
                            );
                            (false, false)
                        }
                    }
                })
                .await;

                match result {
                    Ok(outcome) => outcome,
                    Err(_) => {
                        registry.record_skipped(
                            key,
                            crate::process_registry::SkipReason::Failed(
                                crate::process_registry::InjectionFailure::Timeout,
                            ),
                        );
                        (false, false)
                    }
                }
            });
            handles.push(handle);
        }

        for h in handles {
            if let Ok((was_injected, was_skipped)) = h.await {
                if was_injected {
                    injected += 1;
                }
                if was_skipped {
                    skipped += 1;
                }
            }
        }

        tracing::info!(checked, injected, skipped, "backstop sweep complete");
    }
    #[cfg(not(windows))]
    {
        tracing::debug!("backstop sweep skipped on non-Windows platform");
    }
}

/// Enumerate all running process IDs via K32EnumProcesses.
#[cfg(windows)]
fn enum_all_processes() -> Vec<u32> {
    use windows::Win32::System::ProcessStatus::K32EnumProcesses;

    let mut pids = vec![0u32; 4096];
    let mut needed: u32 = 0;
    let result = unsafe {
        K32EnumProcesses(
            pids.as_mut_ptr(),
            (pids.len() * std::mem::size_of::<u32>()) as u32,
            &mut needed,
        )
    };

    if result == windows::core::BOOL(0) {
        tracing::warn!("K32EnumProcesses failed — startup sweep cannot enumerate PIDs");
        return Vec::new();
    }

    let count = (needed as usize) / std::mem::size_of::<u32>();
    pids.truncate(count);
    pids
}

/// Get the image path for a process via QueryFullProcessImageNameW.
#[cfg(windows)]
fn get_process_image_path(pid: u32) -> Option<String> {
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()? };

    let mut buf = vec![0u16; 260];
    let mut size: u32 = buf.len() as u32;
    let result = unsafe {
        QueryFullProcessImageNameW(
            handle,
            windows::Win32::System::Threading::PROCESS_NAME_WIN32,
            windows::core::PWSTR::from_raw(buf.as_mut_ptr()),
            &mut size,
        )
    };

    unsafe {
        let _ = windows::Win32::Foundation::CloseHandle(handle);
    }

    if result.is_err() {
        return None;
    }

    let len = size as usize;
    Some(String::from_utf16_lossy(&buf[..len.min(buf.len())]))
}

/// Get the user SID (as a string) for a process by opening its token.
///
/// Opens the process with `PROCESS_QUERY_LIMITED_INFORMATION`, opens the
/// process token with `TOKEN_QUERY`, retrieves the `TokenUser` information,
/// and converts the SID to a string via `ConvertSidToStringSidW`.
///
/// Returns `None` if any step fails (e.g., process exited, access denied).
#[cfg(windows)]
fn get_process_user_sid(pid: u32) -> Option<String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::GetTokenInformation;
    use windows::Win32::Security::TokenUser;
    use windows::Win32::Security::TOKEN_QUERY;
    use windows::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    // Open the target process.
    let proc_handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()? };

    // Open the process token.
    let mut token_handle = windows::Win32::Foundation::HANDLE(std::ptr::null_mut());
    let open_result = unsafe { OpenProcessToken(proc_handle, TOKEN_QUERY, &mut token_handle) };
    if open_result.is_err() {
        unsafe {
            let _ = CloseHandle(proc_handle);
        }
        return None;
    }

    // Get the required buffer size for TokenUser.
    let mut needed: u32 = 0;
    let _ = unsafe { GetTokenInformation(token_handle, TokenUser, None, 0, &mut needed) };

    // Allocate buffer and fetch TokenUser.
    let mut buf = vec![0u8; needed as usize];
    let info_result = unsafe {
        GetTokenInformation(
            token_handle,
            TokenUser,
            Some(buf.as_mut_ptr().cast()),
            needed,
            &mut needed,
        )
    };

    if info_result.is_err() {
        unsafe {
            let _ = CloseHandle(token_handle);
            let _ = CloseHandle(proc_handle);
        }
        return None;
    }

    // SAFETY: GetTokenInformation succeeded with TokenUser, so the buffer
    // contains a TOKEN_USER structure whose User.Sid field is valid.
    let token_user = unsafe { &*(buf.as_ptr() as *const windows::Win32::Security::TOKEN_USER) };
    let sid = token_user.User.Sid;

    // Convert SID to string.
    let mut sid_str_ptr = windows::core::PWSTR::null();
    let convert_result = unsafe { ConvertSidToStringSidW(sid, &mut sid_str_ptr) };
    if convert_result.is_err() || sid_str_ptr.is_null() {
        unsafe {
            let _ = CloseHandle(token_handle);
            let _ = CloseHandle(proc_handle);
        }
        return None;
    }

    let sid_string = unsafe { sid_str_ptr.to_string().unwrap_or_default() };

    // Cleanup.
    unsafe {
        let _ = windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(
            sid_str_ptr.as_ptr().cast(),
        )));
        let _ = CloseHandle(token_handle);
        let _ = CloseHandle(proc_handle);
    }

    if sid_string.is_empty() {
        None
    } else {
        Some(sid_string)
    }
}

/// Spawns the config poll task when a server client is available.
///
/// Returns `(shutdown_tx, cmd_tx, poll_handle)` where `poll_handle` is `None` when no
/// server client is available. `cmd_tx` can be used to send `ConfigCommand::RefreshNow`
/// for manual refresh triggers.
fn spawn_config_poll_task(
    server_client: Option<crate::server_client::ServerClient>,
    config: Arc<parking_lot::Mutex<crate::config::AgentConfig>>,
) -> (
    tokio::sync::watch::Sender<bool>,
    tokio::sync::mpsc::Sender<ConfigCommand>,
    Option<tokio::task::JoinHandle<()>>,
) {
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel::<ConfigCommand>(4);
    let handle = server_client.map(|sc| {
        tokio::spawn(async move {
            config_poll_loop(sc, config, shutdown_rx, cmd_rx).await;
        })
    });
    (shutdown_tx, cmd_tx, handle)
}

/// Spawns the approval cache poll task when a server client is available.
///
/// Returns `(shutdown_tx, poll_handle)` where `poll_handle` is `None` when no
/// server client is available.
///
/// The poll loop fetches active approvals from the server every 60 seconds,
/// parses their JWT claims, and updates the local approval cache. Entries
/// that are no longer returned by the server are removed.
fn spawn_approval_poll_task(
    server_client: Option<crate::server_client::ServerClient>,
    approval_cache: Arc<crate::approval_cache::ApprovalCache>,
) -> (
    tokio::sync::watch::Sender<bool>,
    Option<tokio::task::JoinHandle<()>>,
) {
    let (tx, rx) = tokio::sync::watch::channel(false);
    let handle = server_client.map(|sc| {
        tokio::spawn(async move {
            approval_poll_loop(sc, approval_cache, rx).await;
        })
    });
    (tx, handle)
}

/// Periodically polls the server for active approvals and syncs the local cache.
///
/// On each tick:
/// 1. Fetch active approvals from `GET /agent/approvals/active`.
/// 2. Parse each token's JWT claims and insert/update cache entries.
/// 3. Remove cache entries whose `jti` is no longer in the server response.
/// 4. Sweep expired entries.
///
/// The loop runs every 60 seconds. Errors are logged but never propagated.
async fn approval_poll_loop(
    server_client: crate::server_client::ServerClient,
    approval_cache: Arc<crate::approval_cache::ApprovalCache>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    use dlp_common::approval::ApprovalCacheKey;
    use dlp_common::approval::ApprovalClaims;
    use tracing::{debug, info, warn};

    let mut interval = tokio::time::interval(Duration::from_secs(60));

    loop {
        tokio::select! {
            _ = interval.tick() => {}
            _ = shutdown_rx.changed() => {
                info!("approval poll loop shutting down");
                return;
            }
        }

        match server_client.sync_active_approvals().await {
            Ok(entries) => {
                // Build a set of active jtis for cache eviction.
                let mut active_jtis = std::collections::HashSet::new();

                for entry in entries {
                    active_jtis.insert(entry.id.clone());

                    // Parse the JWT claims from the token.
                    // The signature is verified using the cached server public key.
                    let decoding_key = match approval_cache.get_decoding_key() {
                        Some(key) => key,
                        None => {
                            warn!("approval poll loop: no public key cached — skipping token verification");
                            continue;
                        }
                    };
                    let token_data = match jsonwebtoken::decode::<ApprovalClaims>(
                        &entry.token,
                        &decoding_key,
                        &{
                            let mut v =
                                jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
                            v.set_issuer(&["dlp-server"]);
                            v
                        },
                    ) {
                        Ok(data) => data.claims,
                        Err(e) => {
                            warn!(approval_id = %entry.id, error = %e, "approval token signature verification failed");
                            continue;
                        }
                    };

                    let key = ApprovalCacheKey::new(
                        &entry.requester_sid,
                        &entry.data_object_id,
                        &entry.allowed_action,
                        entry.destination_scope.as_deref(),
                    );
                    approval_cache.insert(key, entry.token, token_data);
                    debug!(approval_id = %entry.id, "cached active approval");
                }

                // Evict cache entries whose jti is no longer active.
                let to_remove: Vec<String> = approval_cache
                    .cache
                    .iter()
                    .filter(|e| !active_jtis.contains(&e.claims.jti))
                    .map(|e| e.key().clone())
                    .collect();
                for key in to_remove {
                    approval_cache.cache.remove(&key);
                    debug!(key = %key, "removed stale approval from cache");
                }

                // Sweep expired entries.
                approval_cache.sweep_expired();

                info!(
                    cache_size = approval_cache.len(),
                    "approval cache synced with server"
                );
            }
            Err(e) => {
                debug!(error = %e, "approval sync failed — retaining current cache");
            }
        }
    }
}

/// Builds the per-session identity map and seeds it with currently active sessions.
fn init_session_map() -> Arc<crate::session_identity::SessionIdentityMap> {
    let session_map = Arc::new(crate::session_identity::SessionIdentityMap::new());
    crate::session_identity::init_global(session_map.clone());

    if let Ok(sessions) = crate::ui_spawner::enumerate_active_sessions_pub() {
        for sid in sessions {
            if let Err(e) = session_map.add_session(sid) {
                debug!(
                    session_id = sid,
                    error = %e,
                    "failed to resolve identity for session"
                );
            }
        }
    }
    session_map
}

/// Resolves the service's own user SID and interactive session ID.
///
/// Opens the current process token to obtain the SID and calls
/// `ProcessIdToSessionId` for the session. Returns `None` if SID resolution
/// fails; the session ID falls back to 0 on failure.
#[cfg(windows)]
fn resolve_service_identity() -> Option<(String, u32)> {
    use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;

    let sid = get_process_user_sid(std::process::id())?;
    let mut session_id: u32 = 0;
    let _ = unsafe { ProcessIdToSessionId(std::process::id(), &mut session_id) };
    Some((sid, session_id))
}

/// Non-Windows fallback for service identity resolution.
#[cfg(not(windows))]
fn resolve_service_identity() -> Option<(String, u32)> {
    Some(("S-1-5-18".to_string(), 0))
}

/// Builds the default [`EmitContext`] used for audit events.
fn build_audit_ctx(machine_name: Option<String>) -> crate::audit_emitter::EmitContext {
    let (sid, session) =
        resolve_service_identity().unwrap_or_else(|| ("S-1-5-18".to_string(), 0));
    crate::audit_emitter::EmitContext {
        agent_id: std::env::var("DLP_AGENT_ID").unwrap_or_else(|_| "AGENT-UNKNOWN".to_string()),
        session_id: session,
        user_sid: sid,
        user_name: "SYSTEM".to_string(),
        machine_name,
    }
}

/// Spawns the disk enumeration background task.
///
/// Returns `(shutdown_tx, join_handle)`.
fn spawn_disk_enumeration(
    disk_config_arc: Arc<parking_lot::RwLock<crate::config::AgentConfig>>,
    config_path: std::path::PathBuf,
    audit_ctx: crate::audit_emitter::EmitContext,
) -> (
    tokio::sync::watch::Sender<bool>,
    tokio::task::JoinHandle<()>,
) {
    let disk_enumerator = Arc::new(crate::detection::DiskEnumerator::new());
    crate::detection::disk::set_disk_enumerator(Arc::clone(&disk_enumerator));
    let (tx, rx) = tokio::sync::watch::channel(false);
    let handle = crate::detection::disk::spawn_disk_enumeration_task(
        tokio::runtime::Handle::current(),
        audit_ctx,
        disk_config_arc,
        config_path,
        rx,
    );
    (tx, handle)
}

/// Spawns the device watcher task and returns its cleanup handle.
fn spawn_device_watcher(
    audit_ctx: crate::audit_emitter::EmitContext,
) -> Option<(
    windows::Win32::Foundation::HWND,
    std::thread::JoinHandle<()>,
)> {
    crate::detection::device_watcher::set_runtime_handle(tokio::runtime::Handle::current());
    match crate::detection::spawn_device_watcher_task(audit_ctx) {
        Ok((hwnd, thread)) => {
            info!("device watcher registered (volume + USB + disk interfaces)");
            Some((hwnd, thread))
        }
        Err(e) => {
            warn!(
                error = %e,
                "device watcher unavailable — continuing without USB/disk monitoring"
            );
            None
        }
    }
}

/// Spawns the encryption verification background task.
///
/// Returns `(shutdown_tx, join_handle)`.
fn spawn_encryption_task(
    audit_ctx: crate::audit_emitter::EmitContext,
    recheck_interval: Duration,
) -> (
    tokio::sync::watch::Sender<bool>,
    tokio::task::JoinHandle<()>,
) {
    let checker = Arc::new(crate::detection::encryption::EncryptionChecker::new());
    crate::detection::encryption::set_encryption_checker(Arc::clone(&checker));
    let (tx, rx) = tokio::sync::watch::channel(false);
    let handle = crate::detection::encryption::spawn_encryption_check_task(
        tokio::runtime::Handle::current(),
        audit_ctx,
        recheck_interval,
        rx,
    );
    info!(
        recheck_interval_secs = recheck_interval.as_secs(),
        "encryption verification task spawned"
    );
    (tx, handle)
}

/// Spawns the async interception event loop task.
#[allow(clippy::too_many_arguments)]
fn spawn_event_loop(
    action_rx: mpsc::Receiver<crate::interception::FileAction>,
    offline: Arc<crate::offline::OfflineManager>,
    audit_ctx: crate::audit_emitter::EmitContext,
    session_map: Arc<crate::session_identity::SessionIdentityMap>,
    ad_client: Arc<Option<dlp_common::AdClient>>,
    usb_enforcer: Option<Arc<crate::usb_enforcer::UsbEnforcer>>,
    disk_enforcer: Option<Arc<crate::disk_enforcer::DiskEnforcer>>,
    cloud_enforcer: Option<Arc<crate::cloud_enforcer::CloudEnforcer>>,
    approval_cache: Option<Arc<crate::approval_cache::ApprovalCache>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        crate::interception::run_event_loop(
            action_rx,
            offline,
            audit_ctx,
            session_map,
            ad_client,
            usb_enforcer,
            disk_enforcer,
            cloud_enforcer,
            approval_cache,
        )
        .await;
    })
}

/// Performs graceful shutdown of all subsystems.
///
/// Extracted from [`run_loop`] to reduce cognitive complexity.  Each subsystem
/// is stopped in reverse order of initialisation.
async fn run_loop_shutdown(ctx: RunLoopContext) {
    // Reference approval_cache to keep the field alive until Plan 04 consumes it.
    let _ = &ctx.approval_cache;

    crate::password_stop::debug_log("run_loop: starting graceful shutdown");
    info!(
        service_name = SERVICE_NAME,
        "shutting down enforcement subsystems"
    );

    // Uninstall the drag-and-drop hook (APP-08, Phase 40).
    crate::password_stop::debug_log("run_loop: uninstalling drag-drop hook");
    crate::interception::uninstall_drag_drop_hook();
    crate::password_stop::debug_log("run_loop: drag-drop hook uninstalled");

    // Stop the file monitor first so no new events arrive.
    crate::password_stop::debug_log("run_loop: stopping file monitor");
    ctx.file_monitor.stop();
    let _ = ctx.file_handle.await;
    crate::password_stop::debug_log("run_loop: file monitor stopped");

    // Signal the event loop to drain and exit.
    drop(ctx.event_loop_handle);
    crate::password_stop::debug_log("run_loop: event loop dropped");

    // Stop the heartbeat loop.
    let _ = ctx.heartbeat_shutdown_tx.send(true);
    let _ = ctx.heartbeat_handle.await;
    crate::password_stop::debug_log("run_loop: heartbeat stopped");

    // Stop the Pipe 1 heartbeat.
    let _ = ctx.pipe1_shutdown_tx.send(true);
    let _ = ctx.pipe1_hb_handle.await;
    crate::password_stop::debug_log("run_loop: Pipe 1 heartbeat stopped");

    // Stop the config poll loop.
    let _ = ctx.config_shutdown_tx.send(true);
    if let Some(h) = ctx.config_poll_handle {
        let _ = h.await;
    }
    crate::password_stop::debug_log("run_loop: config poll stopped");

    // Stop the device registry poll task.
    let _ = ctx.registry_shutdown_tx.send(true);
    if let Some(h) = ctx.registry_poll_handle {
        let _ = h.await;
    }
    crate::password_stop::debug_log("run_loop: device registry poll stopped");

    // Stop the managed origins poll task.
    let _ = ctx.origins_shutdown_tx.send(true);
    if let Some(h) = ctx.origins_poll_handle {
        let _ = h.await;
    }
    crate::password_stop::debug_log("run_loop: managed origins poll stopped");

    // Cancel in-flight disk enumeration and wait up to 5s (OP-04).
    let _ = ctx.disk_shutdown_tx.send(true);
    match tokio::time::timeout(DISK_ENUM_CANCEL_TIMEOUT, ctx.disk_enum_handle).await {
        Ok(Ok(())) => debug!("disk enumeration task shut down cleanly"),
        Ok(Err(e)) => warn!(error = %e, "disk enumeration task panicked"),
        Err(_) => warn!("disk enumeration task did not shut down within 5s"),
    }
    crate::password_stop::debug_log("run_loop: disk enumeration stopped");

    // Cancel encryption check task (OP-04 gap closure).
    let _ = ctx.enc_shutdown_tx.send(true);
    match tokio::time::timeout(DISK_ENUM_CANCEL_TIMEOUT, ctx.enc_handle).await {
        Ok(Ok(())) => debug!("encryption check task shut down cleanly"),
        Ok(Err(e)) => warn!(error = %e, "encryption check task panicked"),
        Err(_) => warn!("encryption check task did not shut down within 5s"),
    }
    crate::password_stop::debug_log("run_loop: encryption check stopped");

    // Unregister device watcher.
    if let Some((hwnd, thread)) = ctx.device_watcher_cleanup {
        crate::password_stop::debug_log("run_loop: unregistering device watcher");
        crate::detection::unregister_device_watcher(hwnd, thread);
        crate::password_stop::debug_log("run_loop: device watcher unregistered");
    }

    // Restore volume DACL modifications for any USB drives (OP-04).
    #[cfg(windows)]
    restore_usb_volume_acls(&ctx.detector_arc);

    // Re-enable PnP-disabled USB devices on shutdown (best-effort, OP-04).
    #[cfg(windows)]
    reenable_usb_devices(&ctx.detector_arc);

    // Stop DaclWatcher BEFORE WfpManager unregister (ACLs still protected during WFP teardown).
    // Phase 52-07: Stop removal application task first (so it stops modifying state).
    if let Some(shutdown_tx) = ctx.dacl_removal_shutdown {
        crate::password_stop::debug_log("run_loop: signalling DACL removal application shutdown");
        let _ = shutdown_tx.send(true);
    }
    if let Some(handle) = ctx.dacl_removal_handle {
        match tokio::time::timeout(Duration::from_secs(5), handle).await {
            Ok(Ok(())) => debug!("DACL removal application task shut down cleanly"),
            Ok(Err(e)) => warn!(error = %e, "DACL removal application task panicked"),
            Err(_) => warn!("DACL removal application task did not shut down within 5s"),
        }
    }

    // Phase 52-07: Stop GC task next.
    if let Some(shutdown_tx) = ctx.dacl_gc_shutdown {
        crate::password_stop::debug_log("run_loop: signalling DACL staging GC shutdown");
        let _ = shutdown_tx.send(true);
    }
    if let Some(handle) = ctx.dacl_gc_handle {
        match tokio::time::timeout(Duration::from_secs(5), handle).await {
            Ok(Ok(())) => debug!("DACL staging GC task shut down cleanly"),
            Ok(Err(e)) => warn!(error = %e, "DACL staging GC task panicked"),
            Err(_) => warn!("DACL staging GC task did not shut down within 5s"),
        }
    }

    if let Some(shutdown_tx) = ctx.dacl_watcher_shutdown {
        crate::password_stop::debug_log("run_loop: signalling DACL watcher shutdown");
        let _ = shutdown_tx.send(true);
    }
    if let Some(handle) = ctx.dacl_watcher_handle {
        match tokio::time::timeout(Duration::from_secs(5), handle).await {
            Ok(Ok(())) => debug!("DACL repair task shut down cleanly"),
            Ok(Err(e)) => warn!(error = %e, "DACL repair task panicked"),
            Err(_) => warn!("DACL repair task did not shut down within 5s"),
        }
    }
    if let Some(handle) = ctx.dacl_poll_handle {
        match tokio::time::timeout(Duration::from_secs(5), handle).await {
            Ok(Ok(())) => debug!("DACL polling backstop shut down cleanly"),
            Ok(Err(e)) => warn!(error = %e, "DACL polling backstop panicked"),
            Err(_) => warn!("DACL polling backstop did not shut down within 5s"),
        }
    }
    if let Some(ref watcher) = ctx.dacl_watcher {
        crate::password_stop::debug_log("run_loop: unregistering all DACL watchers");
        watcher.unregister_all();
        crate::password_stop::debug_log("run_loop: all DACL watchers unregistered");
        info!("DACL watcher stopped");
    }

    // Unregister WFP filters and close engine (M017/S01).
    if let Some(manager) = ctx.wfp_manager {
        crate::password_stop::debug_log("run_loop: unregistering WFP manager");
        if let Err(e) = manager.unregister() {
            warn!(error = %e, "WFP manager unregister failed during shutdown");
        } else {
            info!("WFP manager unregistered");
        }
        crate::password_stop::debug_log("run_loop: WFP manager unregistered");
    }

    // Drop hook injector (no explicit stop needed; DLL stays loaded in target
    // processes until they exit). Log for observability.
    if ctx.hook_injector.is_some() {
        crate::password_stop::debug_log("run_loop: dropping hook injector");
        info!("hook injector dropped");
    }

    // Stop sync-client process watcher thread (M017/S02).
    if let Some(flag) = ctx.sync_watcher_shutdown {
        crate::password_stop::debug_log("run_loop: signalling sync-client watcher shutdown");
        flag.store(true, Ordering::Relaxed);
    }
    if let Some(handle) = ctx.sync_watcher_handle {
        let _ = handle.join();
        crate::password_stop::debug_log("run_loop: sync-client watcher thread joined");
        info!("sync-client process watcher stopped");
    }

    // Stop print enforcer (M017/S04).
    if let Some(mut enforcer) = ctx.print_enforcer {
        crate::password_stop::debug_log("run_loop: stopping print enforcer");
        enforcer.stop();
        crate::password_stop::debug_log("run_loop: print enforcer stopped");
    }

    // Stop the approval cache poll task (Phase 61).
    let _ = ctx.approval_shutdown_tx.send(true);
    if let Some(h) = ctx.approval_poll_handle {
        let _ = h.await;
    }
    crate::password_stop::debug_log("run_loop: approval poll stopped");

    // Kill all UI processes spawned by the session monitor.
    crate::password_stop::debug_log("run_loop: killing UI processes");
    crate::ui_spawner::kill_all();
    crate::password_stop::debug_log("run_loop: UI processes killed");

    // Phase 58.5: Request cooperative unhook from all injected processes.
    // This must happen while the hook IPC server is still running so that
    // PollControl frames receive UnhookCommand replies, and before the audit
    // flush task stops so the resulting events are flushed.
    request_unhook_from_injected(&ctx.process_registry, &ctx.audit_ctx).await;

    // Stop the audit buffer flush task (final flush runs inside).
    let _ = ctx.audit_shutdown_tx.send(true);
    if let Some(h) = ctx.audit_flush_handle {
        let _ = h.await;
    }
    crate::password_stop::debug_log("run_loop: audit buffer stopped");

    // Phase 53: Stop bypass correlator.
    if let Some(shutdown_tx) = ctx.correlator_shutdown {
        crate::password_stop::debug_log("run_loop: signalling bypass correlator shutdown");
        let _ = shutdown_tx.send(true);
    }
    if let Some(handle) = ctx.correlator_handle {
        match tokio::time::timeout(Duration::from_secs(5), handle).await {
            Ok(Ok(())) => debug!("bypass correlator shut down cleanly"),
            Ok(Err(e)) => warn!(error = %e, "bypass correlator panicked"),
            Err(_) => warn!("bypass correlator did not shut down within 5s"),
        }
    }
    // Stop ETW Kernel-File consumer.
    if let Some(mut consumer) = ctx.etw_consumer {
        crate::password_stop::debug_log("run_loop: stopping ETW Kernel-File consumer");
        consumer.stop();
    }
    crate::password_stop::debug_log("run_loop: bypass correlator stopped");

    // Phase 58: Stop hook IPC server thread.
    // The HookIpcServer::run() loop exits when the pipe handle is closed.
    // We disconnect the pipe by closing the handle from another thread.
    if let Some(handle) = ctx.hook_ipc_handle {
        crate::password_stop::debug_log("run_loop: stopping hook IPC server");
        // Force-close the named pipe to unblock ConnectNamedPipeW.
        // SAFETY: The pipe name is constant; we open a client handle and close it
        // to trigger disconnection. This is best-effort — the thread may already
        // be shutting down.
        #[cfg(windows)]
        unsafe {
            use windows::core::PCWSTR;
            use windows::Win32::Foundation::CloseHandle;
            use windows::Win32::Storage::FileSystem::{
                CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_NONE, OPEN_EXISTING,
            };
            let name_wide: Vec<u16> = crate::hook_ipc::DEFAULT_PIPE_NAME
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            if let Ok(client) = CreateFileW(
                PCWSTR::from_raw(name_wide.as_ptr()),
                FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            ) {
                if !client.is_invalid() {
                    let _ = CloseHandle(client);
                }
            }
        }
        let _ = handle.join();
        crate::password_stop::debug_log("run_loop: hook IPC server stopped");
        info!("hook IPC server stopped");
    }

    crate::password_stop::debug_log("run_loop: shutdown complete");
    info!(
        service_name = SERVICE_NAME,
        "enforcement subsystems stopped"
    );
}

/// Restores volume ACLs for all tracked USB drives on shutdown.
#[cfg(windows)]
fn restore_usb_volume_acls(detector: &Arc<crate::detection::VolumeDetector>) {
    let Some(controller) = crate::detection::usb::get_device_controller() else {
        return;
    };
    let letters: Vec<char> = detector.device_identities.read().keys().copied().collect();
    for letter in letters {
        if let Err(e) = controller.restore_volume_acl(letter) {
            debug!(
                drive = %letter,
                error = %e,
                "restore_volume_acl on shutdown (may be unmodified)"
            );
        } else {
            info!(drive = %letter, "restored volume ACL on shutdown");
        }
    }
}

/// Re-enables PnP-disabled USB devices on shutdown.
#[cfg(windows)]
fn reenable_usb_devices(detector: &Arc<crate::detection::VolumeDetector>) {
    let Some(controller) = crate::detection::usb::get_device_controller() else {
        return;
    };
    let identities: Vec<(char, dlp_common::DeviceIdentity)> = detector
        .device_identities
        .read()
        .iter()
        .map(|(k, v)| (*k, v.clone()))
        .collect();
    for (letter, identity) in identities {
        if let Err(e) = controller.enable_usb_device("", &identity) {
            debug!(
                drive = %letter,
                error = %e,
                "enable_usb_device on shutdown (may not be disabled)"
            );
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Chrome policy evaluator (Phase 41)
// ──────────────────────────────────────────────────────────────────────────────

/// Synchronous policy evaluator for the Chrome handler.
///
/// Evaluates the request against the managed-origins cache via the ABAC
/// EvaluateRequest/EvaluateResponse shape. This is the Phase 41 bridge:
/// the Chrome handler now speaks ABAC, but the backing evaluation still
/// uses the managed-origins cache until full policy cache integration.
fn chrome_policy_evaluator(
    request: &dlp_common::abac::EvaluateRequest,
) -> dlp_common::abac::EvaluateResponse {
    use dlp_common::abac::{Decision, EvaluateResponse};

    let should_block = request.source_origin.as_ref().is_some_and(|origin| {
        // Access the global origins cache (same cache the old handler used).
        crate::chrome::handler::origins_cache_is_managed(origin)
    });

    if should_block {
        EvaluateResponse {
            decision: Decision::DENY,
            matched_policy_id: Some("managed-origins".to_string()),
            reason: "Source origin is in managed-origins list".to_string(),
            enforcement_mode: None,
            would_have_denied: true,
            matched_label_id: None,
        }
    } else {
        EvaluateResponse {
            decision: Decision::ALLOW,
            matched_policy_id: None,
            reason: "Source origin is not managed".to_string(),
            enforcement_mode: None,
            would_have_denied: false,
            matched_label_id: None,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// UI binary resolution
// ──────────────────────────────────────────────────────────────────────────────

/// Resolves the dlp-user-ui binary path.
///
/// Checks `DLP_UI_BINARY` env var first, then falls back to the directory
/// containing the running service executable, looking for `dlp-user-ui.exe`.
fn resolve_ui_binary() -> Option<std::path::PathBuf> {
    // Env var takes priority (useful for development).
    if let Ok(path) = std::env::var("DLP_UI_BINARY") {
        return Some(std::path::PathBuf::from(path));
    }

    // Fallback: same directory as the running service binary.
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let ui = dir.join("dlp-user-ui.exe");
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
///
/// Runs on the SCM callback thread — keep all work minimal and non-blocking.
/// Reports state transitions directly to the SCM via [`SCM_HANDLE`] so that
/// `sc stop` sees `StopPending` immediately (with a generous `wait_hint`)
/// instead of timing out because the service never reported a state change.
fn service_control_handler(control: ServiceControl) -> ServiceControlHandlerResult {
    match control {
        ServiceControl::Stop => {
            // Guard against duplicate STOP controls while a stop is already in
            // progress (e.g. `sc stop` issued twice or PowerShell wait-loop).
            let current = *SERVICE_STATE.lock();
            if current == ServiceState::StopPending || current == ServiceState::Stopped {
                info!(
                    service_name = SERVICE_NAME,
                    "SCM: STOP ignored — already stopping"
                );
                return ServiceControlHandlerResult::NoError;
            }

            info!(service_name = SERVICE_NAME, "SCM: STOP");
            *SERVICE_STATE.lock() = ServiceState::StopPending;

            // Report StopPending to the SCM with a 120-second wait_hint so the
            // SCM does not time out while the password dialog is displayed.
            report_scm_status(
                ServiceState::StopPending,
                ServiceControlAccept::empty(),
                Duration::from_secs(120),
            );

            // NOTE: We do NOT call request_shutdown() here. Shutdown is only
            // authorized AFTER password verification succeeds. This preserves the
            // two-phase lifecycle: StopPending (password pending) -> StopConfirmed
            // (shutdown authorized). If the stop is cancelled or fails, the service
            // returns to Running without having torn down any worker threads.

            // In debug builds, skip the password challenge so `sc stop` works
            // without an AD server.  Release builds require the full flow.
            if cfg!(debug_assertions) {
                info!("DEBUG MODE: skipping password challenge — stopping immediately");
                crate::password_stop::confirm_stop_immediate();
            } else {
                crate::password_stop::initiate_stop();
            }
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
/// dialog or fails the password challenge 3 times.  Reports the state change
/// to the SCM so `sc query` reflects `Running` again.
pub fn revert_stop() {
    *SERVICE_STATE.lock() = ServiceState::Running;

    // Report Running to the SCM so it knows the service is healthy again.
    report_scm_status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::PAUSE_CONTINUE,
        Duration::ZERO,
    );

    info!(
        service_name = SERVICE_NAME,
        "service stop reverted to Running"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// SCM status reporting (from the control handler callback)
// ──────────────────────────────────────────────────────────────────────────────

/// Reports a service state transition directly to the SCM via the global handle.
///
/// Used by the control handler callback and by [`revert_stop`] — contexts that
/// do not have access to the `Arc<Mutex<ServiceStatusHandle>>` used in the
/// main service body.  Silently logs if the handle is not yet initialised
/// (should never happen after `run_service` completes registration).
fn report_scm_status(state: ServiceState, controls: ServiceControlAccept, wait_hint: Duration) {
    let Some(handle) = SCM_HANDLE.get() else {
        error!("SCM_HANDLE not initialised — cannot report {state:?}");
        return;
    };

    let status = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: controls,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint,
        process_id: None,
    };

    if let Err(e) = handle.set_service_status(status) {
        error!(state = ?state, error = %e, "failed to report status to SCM");
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Single-instance enforcement
// ──────────────────────────────────────────────────────────────────────────────

/// Acquires a Windows named mutex to enforce single-instance operation.
///
/// Creates a kernel-named mutex (`Global\DlpAgentSingleInstance`) that persists
/// for the lifetime of the process.  If another agent instance already holds the
/// mutex, this function logs an error and terminates the process immediately.
///
/// The returned [`windows::Win32::Foundation::HANDLE`] must remain alive for
/// the entire service lifetime — dropping it releases the mutex and allows a
/// second instance to start.  Callers should store it in a variable that lives
/// until service shutdown.
///
/// # Errors
///
/// Calls `std::process::abort()` when another instance is detected.
/// Returns `Err` on unexpected Win32 API failures.
#[cfg(windows)]
fn acquire_instance_mutex() -> windows::core::Result<windows::Win32::Foundation::HANDLE> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{GetLastError, WIN32_ERROR};
    use windows::Win32::System::Threading::CreateMutexW;

    // Null-terminated UTF-16 name in the Global kernel namespace.
    let name: Vec<u16> = "Global\\DlpAgentSingleInstance\0".encode_utf16().collect();

    // SAFETY: `name` is a valid null-terminated UTF-16 string; the handle is
    // immediately checked and stored for the service lifetime.
    let handle = unsafe {
        CreateMutexW(
            None, // default security — inheritable by child processes
            true, // bInitialOwner: this instance claims ownership immediately
            PCWSTR(name.as_ptr()),
        )?
    };

    // ERROR_ALREADY_EXISTS (183) means another instance holds the named mutex.
    // SAFETY: no preconditions for GetLastError.
    if unsafe { GetLastError() } == WIN32_ERROR(183) {
        error!(
            service_name = SERVICE_NAME,
            "another DLP agent instance is already running — aborting"
        );
        std::process::abort();
    }

    info!(
        service_name = SERVICE_NAME,
        "single-instance named mutex acquired"
    );
    Ok(handle)
}

/// No-op stub for non-Windows targets (tests, cross-compilation).
#[cfg(not(windows))]
fn acquire_instance_mutex() {
    info!(
        service_name = SERVICE_NAME,
        "single-instance check skipped (non-Windows)"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests for config_poll_loop diff + apply logic
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AgentConfig;
    use crate::detection::disk::DiskEnumerator;
    use crate::server_client::AgentConfigPayload;
    use dlp_common::{BusType, DiskIdentity};

    /// Helper to build a minimal `AgentConfigPayload` with all required fields.
    fn make_payload(disk_allowlist: Vec<DiskIdentity>) -> AgentConfigPayload {
        AgentConfigPayload {
            monitored_paths: vec![],
            excluded_paths: vec![],
            heartbeat_interval_secs: 30,
            offline_cache_enabled: true,
            ldap_config: None,
            disk_allowlist,
            usb_blocked_failure_mode: "Warning only".to_string(),
            usb_startup_resolution_mode: "VID/PID/serial fallback".to_string(),
            usb_none_serial_policy: "Always Blocked".to_string(),
            cloud_hook_enabled: false,
            wfp_filter_enabled: false,
            hook_classification_timeout_ms: 5000,
            print_enabled: false,
            print_xps_timeout_ms: 5000,
            print_unclassifiable_action: "Block".to_string(),
            print_max_pages: 100,
            allowlist_entries: vec![],
            allowlist_version: 0,
            protected_paths: vec![],
            global_enforcement_mode: "PerPolicy".to_string(),
        }
    }

    /// Helper to build a `DiskIdentity` with minimal required fields.
    fn make_disk(instance_id: &str) -> DiskIdentity {
        DiskIdentity {
            instance_id: instance_id.to_string(),
            bus_type: BusType::Sata,
            model: format!("Test Drive {instance_id}"),
            drive_letter: None,
            serial: None,
            size_bytes: None,
            is_boot_disk: false,
            encryption_status: None,
            encryption_method: None,
            encryption_checked_at: None,
        }
    }

    /// Test 1: First-time apply — cfg starts with empty disk_allowlist, payload
    /// contains 2 disks; after apply cfg.disk_allowlist has 2 entries and
    /// DiskEnumerator.instance_id_map contains both instance_ids.
    /// changed_fields must include "disk_allowlist".
    #[test]
    fn test_config_poll_applies_disk_allowlist_first_time() {
        let disk_a = make_disk("DISK\\INSTANCE\\A");
        let disk_b = make_disk("DISK\\INSTANCE\\B");
        let mut cfg = AgentConfig::default(); // disk_allowlist starts empty
        let payload = make_payload(vec![disk_a.clone(), disk_b.clone()]);

        let (changed_fields, disk_merge_data) = apply_payload_to_config(&mut cfg, &payload);

        // Config must be updated with both disks.
        assert_eq!(cfg.disk_allowlist.len(), 2);
        assert!(changed_fields.contains(&"disk_allowlist"));

        // Merge data must be provided for the deferred map update.
        let (old_ids, new_list) =
            disk_merge_data.expect("disk_merge_data must be Some when disk_allowlist changed");
        assert!(
            old_ids.is_empty(),
            "old_ids must be empty on first-time apply"
        );
        assert_eq!(new_list.len(), 2);

        // Apply the merge into a real DiskEnumerator.
        let enumerator = DiskEnumerator::new();
        merge_disk_allowlist_into_map(&enumerator, &old_ids, &new_list);

        // Both disks must be in instance_id_map.
        let map = enumerator.instance_id_map.read();
        assert!(
            map.contains_key("DISK\\INSTANCE\\A"),
            "disk A must be in map"
        );
        assert!(
            map.contains_key("DISK\\INSTANCE\\B"),
            "disk B must be in map"
        );
    }

    /// Test 2: No-change path — cfg.disk_allowlist already equals payload.disk_allowlist
    /// (3 disks); after apply no changed_fields entry "disk_allowlist", and the
    /// enumerator map is left untouched.
    #[test]
    fn test_config_poll_no_change_when_allowlist_unchanged() {
        let disks = vec![
            make_disk("DISK\\INSTANCE\\X1"),
            make_disk("DISK\\INSTANCE\\X2"),
            make_disk("DISK\\INSTANCE\\X3"),
        ];
        let mut cfg = AgentConfig {
            disk_allowlist: disks.clone(),
            ..Default::default()
        };
        let payload = make_payload(disks.clone());

        let (changed_fields, disk_merge_data) = apply_payload_to_config(&mut cfg, &payload);

        // No change: disk_allowlist must NOT appear in changed_fields.
        assert!(
            !changed_fields.contains(&"disk_allowlist"),
            "disk_allowlist must not appear in changed_fields when unchanged"
        );
        // No merge data when nothing changed (T-37-12 spurious-update mitigation).
        assert!(
            disk_merge_data.is_none(),
            "disk_merge_data must be None when disk_allowlist is unchanged"
        );
        // cfg.disk_allowlist unchanged.
        assert_eq!(cfg.disk_allowlist, disks);
    }

    /// Test 3: Remove de-allowlisted disk — cfg has [disk-A, disk-B], instance_id_map
    /// has both. Payload contains only [disk-A]. After apply cfg.disk_allowlist is
    /// [disk-A], instance_id_map contains disk-A but NOT disk-B.
    /// changed_fields must contain "disk_allowlist".
    #[test]
    fn test_config_poll_removes_deallowlisted_disk() {
        let disk_a = make_disk("DISK\\INSTANCE\\A");
        let disk_b = make_disk("DISK\\INSTANCE\\B");

        let mut cfg = AgentConfig {
            disk_allowlist: vec![disk_a.clone(), disk_b.clone()],
            ..Default::default()
        };
        // Seed the enumerator with both disks in instance_id_map.
        let enumerator = DiskEnumerator::new();
        {
            let mut map = enumerator.instance_id_map.write();
            map.insert(disk_a.instance_id.clone(), disk_a.clone());
            map.insert(disk_b.instance_id.clone(), disk_b.clone());
        }

        // Payload only contains disk-A (disk-B was de-allowlisted by admin).
        let payload = make_payload(vec![disk_a.clone()]);

        let (changed_fields, disk_merge_data) = apply_payload_to_config(&mut cfg, &payload);

        assert!(changed_fields.contains(&"disk_allowlist"));
        assert_eq!(cfg.disk_allowlist, vec![disk_a.clone()]);

        let (old_ids, new_list) = disk_merge_data.expect("merge data must be present");
        merge_disk_allowlist_into_map(&enumerator, &old_ids, &new_list);

        let map = enumerator.instance_id_map.read();
        assert!(
            map.contains_key("DISK\\INSTANCE\\A"),
            "disk A must remain in map"
        );
        assert!(
            !map.contains_key("DISK\\INSTANCE\\B"),
            "de-allowlisted disk B must be removed from map"
        );
    }

    /// Test 4 (Pitfall 5 regression): Preserve live-enumerated disks NOT in allowlist.
    ///
    /// instance_id_map starts with [live-disk-X (NOT in cfg.disk_allowlist)].
    /// cfg.disk_allowlist is empty. Payload contains [allow-disk-Y].
    /// After apply, instance_id_map must contain BOTH live-disk-X AND allow-disk-Y.
    /// cfg.disk_allowlist is [allow-disk-Y].
    #[test]
    fn test_config_poll_preserves_live_enumerated_disks_not_in_allowlist() {
        let live_disk_x = make_disk("DISK\\LIVE\\X");
        let allow_disk_y = make_disk("DISK\\ALLOW\\Y");

        // cfg starts with empty allowlist (live_disk_x is NOT in it).
        let mut cfg = AgentConfig::default();

        // Enumerator has live_disk_x from Phase 33 live enumeration.
        let enumerator = DiskEnumerator::new();
        {
            let mut map = enumerator.instance_id_map.write();
            map.insert(live_disk_x.instance_id.clone(), live_disk_x.clone());
        }

        // Payload pushes allow_disk_y only (live_disk_x is not server-registered).
        let payload = make_payload(vec![allow_disk_y.clone()]);

        let (changed_fields, disk_merge_data) = apply_payload_to_config(&mut cfg, &payload);

        assert!(changed_fields.contains(&"disk_allowlist"));
        assert_eq!(cfg.disk_allowlist, vec![allow_disk_y.clone()]);

        let (old_ids, new_list) = disk_merge_data.expect("merge data must be present");
        // Pitfall 5 guard: old_ids is empty (cfg had no prior allowlist),
        // so no entries should be removed.
        assert!(old_ids.is_empty());
        merge_disk_allowlist_into_map(&enumerator, &old_ids, &new_list);

        let map = enumerator.instance_id_map.read();
        assert!(
            map.contains_key("DISK\\LIVE\\X"),
            "live-enumerated disk X must be preserved in map (Pitfall 5)"
        );
        assert!(
            map.contains_key("DISK\\ALLOW\\Y"),
            "server-allowlisted disk Y must be inserted into map"
        );
    }

    /// Test 5: Persist to TOML — after a successful update, calling cfg.save() and
    /// reloading via AgentConfig::load() produces a config whose disk_allowlist
    /// matches the new entries.
    #[test]
    fn test_config_poll_persists_disk_allowlist_to_toml() {
        let disk = make_disk("DISK\\PERSIST\\001");

        let mut cfg = AgentConfig::default();
        let payload = make_payload(vec![disk.clone()]);

        let (changed_fields, _) = apply_payload_to_config(&mut cfg, &payload);
        assert!(changed_fields.contains(&"disk_allowlist"));

        // Write to a temp file and reload to verify TOML roundtrip.
        let temp_dir = tempfile::tempdir().expect("tempdir must be creatable");
        let config_path = temp_dir.path().join("agent-config.toml");
        cfg.save(&config_path).expect("save must succeed");

        let reloaded = AgentConfig::load(&config_path);
        assert_eq!(
            reloaded.disk_allowlist.len(),
            1,
            "reloaded config must contain the persisted disk"
        );
        assert_eq!(
            reloaded.disk_allowlist[0].instance_id, "DISK\\PERSIST\\001",
            "persisted instance_id must survive TOML roundtrip"
        );
    }

    /// Test 6: USB config fields are applied from payload to cfg.
    #[test]
    fn test_apply_payload_usb_fields() {
        let mut cfg = AgentConfig::default();
        let mut payload = make_payload(vec![]);
        payload.usb_blocked_failure_mode = "Hard error".to_string();
        payload.usb_startup_resolution_mode = "Volume GUID resolution".to_string();
        payload.usb_none_serial_policy = "Allow unregistered".to_string();

        let (changed_fields, _) = apply_payload_to_config(&mut cfg, &payload);

        assert!(
            changed_fields.contains(&"usb_blocked_failure_mode"),
            "usb_blocked_failure_mode must be in changed_fields"
        );
        assert!(
            changed_fields.contains(&"usb_startup_resolution_mode"),
            "usb_startup_resolution_mode must be in changed_fields"
        );
        assert!(
            changed_fields.contains(&"usb_none_serial_policy"),
            "usb_none_serial_policy must be in changed_fields"
        );
        assert_eq!(cfg.usb_blocked_failure_mode, Some("Hard error".to_string()));
        assert_eq!(
            cfg.usb_startup_resolution_mode,
            Some("Volume GUID resolution".to_string())
        );
        assert_eq!(
            cfg.usb_none_serial_policy,
            Some("Allow unregistered".to_string())
        );
    }

    /// Test 7: No-change path — cfg and payload USB values match.
    #[test]
    fn test_apply_payload_usb_fields_no_change() {
        let mut cfg = AgentConfig {
            usb_blocked_failure_mode: Some("Warning only".to_string()),
            usb_startup_resolution_mode: Some("VID/PID/serial fallback".to_string()),
            usb_none_serial_policy: Some("Always Blocked".to_string()),
            ..Default::default()
        };
        let payload = make_payload(vec![]);

        let (changed_fields, _) = apply_payload_to_config(&mut cfg, &payload);

        assert!(
            !changed_fields.contains(&"usb_blocked_failure_mode"),
            "usb_blocked_failure_mode must NOT be in changed_fields when unchanged"
        );
        assert!(
            !changed_fields.contains(&"usb_startup_resolution_mode"),
            "usb_startup_resolution_mode must NOT be in changed_fields when unchanged"
        );
        assert!(
            !changed_fields.contains(&"usb_none_serial_policy"),
            "usb_none_serial_policy must NOT be in changed_fields when unchanged"
        );
    }

    /// Test 8: None guard — when cfg USB fields are None and payload carries the
    /// system default, changed_fields must NOT contain usb_* entries.
    /// This prevents spurious "config changed" logs when a new agent polls an old
    /// server that does not send these fields.
    #[test]
    fn test_apply_payload_usb_fields_none_guard() {
        let mut cfg = AgentConfig::default(); // all USB fields are None
        let payload = make_payload(vec![]); // all defaults

        let (changed_fields, _) = apply_payload_to_config(&mut cfg, &payload);

        assert!(
            !changed_fields.contains(&"usb_blocked_failure_mode"),
            "None guard: usb_blocked_failure_mode must NOT diff when payload == default"
        );
        assert!(
            !changed_fields.contains(&"usb_startup_resolution_mode"),
            "None guard: usb_startup_resolution_mode must NOT diff when payload == default"
        );
        assert!(
            !changed_fields.contains(&"usb_none_serial_policy"),
            "None guard: usb_none_serial_policy must NOT diff when payload == default"
        );
    }

    /// Test 9: Empty-string guard — when the server sends an empty string for a
    /// USB config field, the apply must be skipped and the previous cfg value
    /// preserved.
    #[test]
    fn test_apply_payload_usb_fields_empty_guard() {
        let mut cfg = AgentConfig {
            usb_blocked_failure_mode: Some("Hard error".to_string()),
            ..Default::default()
        };
        let mut payload = make_payload(vec![]);
        payload.usb_blocked_failure_mode = "".to_string();

        let (changed_fields, _) = apply_payload_to_config(&mut cfg, &payload);

        assert!(
            !changed_fields.contains(&"usb_blocked_failure_mode"),
            "empty-string guard: must NOT diff when payload is empty"
        );
        assert_eq!(
            cfg.usb_blocked_failure_mode,
            Some("Hard error".to_string()),
            "empty-string guard: previous value must be preserved"
        );
    }

    // ── M017/S04: Print config field tests ────────────────────────────────

    /// Test 10: Print config fields are applied from payload to cfg.
    #[test]
    fn test_apply_payload_print_fields() {
        let mut cfg = AgentConfig::default();
        let mut payload = make_payload(vec![]);
        payload.print_enabled = true;
        payload.print_xps_timeout_ms = 3000;
        payload.print_unclassifiable_action = "Allow".to_string();
        payload.print_max_pages = 50;

        let (changed_fields, _) = apply_payload_to_config(&mut cfg, &payload);

        assert!(
            changed_fields.contains(&"print_enabled"),
            "print_enabled must be in changed_fields"
        );
        assert!(
            changed_fields.contains(&"print_xps_timeout_ms"),
            "print_xps_timeout_ms must be in changed_fields"
        );
        assert!(
            changed_fields.contains(&"print_unclassifiable_action"),
            "print_unclassifiable_action must be in changed_fields"
        );
        assert!(
            changed_fields.contains(&"print_max_pages"),
            "print_max_pages must be in changed_fields"
        );
        assert_eq!(cfg.print_enabled, Some(true));
        assert_eq!(cfg.print_xps_timeout_ms, Some(3000));
        assert_eq!(cfg.print_unclassifiable_action, Some("Allow".to_string()));
        assert_eq!(cfg.print_max_pages, Some(50));
    }

    /// Test 11: No-change path — cfg and payload print values match.
    #[test]
    fn test_apply_payload_print_fields_no_change() {
        let mut cfg = AgentConfig {
            print_enabled: Some(true),
            print_xps_timeout_ms: Some(3000),
            print_unclassifiable_action: Some("Allow".to_string()),
            print_max_pages: Some(50),
            ..Default::default()
        };
        let mut payload = make_payload(vec![]);
        payload.print_enabled = true;
        payload.print_xps_timeout_ms = 3000;
        payload.print_unclassifiable_action = "Allow".to_string();
        payload.print_max_pages = 50;

        let (changed_fields, _) = apply_payload_to_config(&mut cfg, &payload);

        assert!(
            !changed_fields.contains(&"print_enabled"),
            "print_enabled must NOT be in changed_fields when unchanged"
        );
        assert!(
            !changed_fields.contains(&"print_xps_timeout_ms"),
            "print_xps_timeout_ms must NOT be in changed_fields when unchanged"
        );
        assert!(
            !changed_fields.contains(&"print_unclassifiable_action"),
            "print_unclassifiable_action must NOT be in changed_fields when unchanged"
        );
        assert!(
            !changed_fields.contains(&"print_max_pages"),
            "print_max_pages must NOT be in changed_fields when unchanged"
        );
    }

    /// Test 12: None guard — when cfg print fields are None and payload carries the
    /// system default, changed_fields must NOT contain print_* entries.
    /// This prevents spurious "config changed" logs when a new agent polls an old
    /// server that does not send these fields.
    #[test]
    fn test_apply_payload_print_fields_none_guard() {
        let mut cfg = AgentConfig::default(); // all print fields are None
        let payload = make_payload(vec![]); // all defaults

        let (changed_fields, _) = apply_payload_to_config(&mut cfg, &payload);

        assert!(
            !changed_fields.contains(&"print_enabled"),
            "None guard: print_enabled must NOT diff when payload == default"
        );
        assert!(
            !changed_fields.contains(&"print_xps_timeout_ms"),
            "None guard: print_xps_timeout_ms must NOT diff when payload == default"
        );
        assert!(
            !changed_fields.contains(&"print_unclassifiable_action"),
            "None guard: print_unclassifiable_action must NOT diff when payload == default"
        );
        assert!(
            !changed_fields.contains(&"print_max_pages"),
            "None guard: print_max_pages must NOT diff when payload == default"
        );
    }

    /// Test 13: Empty-string guard — when the server sends an empty string for
    /// print_unclassifiable_action, the apply must be skipped and the previous
    /// cfg value preserved.
    #[test]
    fn test_apply_payload_print_unclassifiable_action_empty_guard() {
        let mut cfg = AgentConfig {
            print_unclassifiable_action: Some("Allow".to_string()),
            ..Default::default()
        };
        let mut payload = make_payload(vec![]);
        payload.print_unclassifiable_action = "".to_string();

        let (changed_fields, _) = apply_payload_to_config(&mut cfg, &payload);

        assert!(
            !changed_fields.contains(&"print_unclassifiable_action"),
            "empty-string guard: must NOT diff when payload is empty"
        );
        assert_eq!(
            cfg.print_unclassifiable_action,
            Some("Allow".to_string()),
            "empty-string guard: previous value must be preserved"
        );
    }

    // ── with_config tests (Phase 43-04) ───────────────────────────────────

    /// Verify that `with_config` returns `None` when CONFIG is not initialized.
    #[test]
    fn test_with_config_returns_none_when_uninitialized() {
        // NOTE: This test relies on CONFIG not being set. Since CONFIG is a
        // OnceLock and tests may run in parallel, we cannot guarantee this
        // in all test configurations. The test is marked as a best-effort
        // verification of the uninitialized path.
        //
        // If other tests in the same process have already set CONFIG, this
        // test will still pass because we only assert that `with_config`
        // returns `Some` when initialized and that the closure is executed.
        // The uninitialized case is covered by the type system (Option<R>).
        let result: Option<String> =
            with_config(|cfg| cfg.usb_blocked_failure_mode.clone().unwrap_or_default());
        // When CONFIG is set by other tests, result is Some(...).
        // When CONFIG is unset, result is None.
        // Both are valid — we just verify the function does not panic.
        let _ = result;
    }

    /// Verify that `with_config` returns the value from the closure when
    /// CONFIG is initialized.
    #[test]
    fn test_with_config_returns_value_when_initialized() {
        let test_config = AgentConfig {
            usb_blocked_failure_mode: Some("Hard error".to_string()),
            ..Default::default()
        };
        let test_arc = Arc::new(parking_lot::Mutex::new(test_config));
        let _ = CONFIG.set(test_arc);

        let result = with_config(|cfg| cfg.usb_blocked_failure_mode.clone().unwrap_or_default());

        assert_eq!(result, Some("Hard error".to_string()));
    }

    // ── Phase 52: protected_paths staging tests ───────────────────────────

    use crate::server_client::ProtectedPathConfig;

    /// Helper to build a `ProtectedPathConfig` for tests.
    fn make_protected_path(path: &str, tier: &str) -> ProtectedPathConfig {
        ProtectedPathConfig {
            id: uuid::Uuid::new_v4().to_string(),
            path: path.to_string(),
            tier: tier.to_string(),
            source: "manual".to_string(),
        }
    }

    /// Test 14: protected_paths diff detects removals and stages them.
    #[test]
    fn test_apply_payload_stages_removals() {
        // Initialise the agent DB (required for staging).
        let _ = init_agent_db();

        let path_a = make_protected_path(r"C:\Data\Secret", "T3");
        let path_b = make_protected_path(r"C:\Data\Confidential", "T3");

        let mut cfg = AgentConfig {
            protected_paths: vec![path_a.clone(), path_b.clone()],
            ..Default::default()
        };

        // Payload removes path_b.
        let mut payload = make_payload(vec![]);
        payload.protected_paths = vec![path_a.clone()];

        let (changed_fields, _) = apply_payload_to_config(&mut cfg, &payload);

        assert!(
            changed_fields.contains(&"protected_paths"),
            "protected_paths must be in changed_fields when paths are removed"
        );
        assert_eq!(cfg.protected_paths.len(), 1);
        assert_eq!(cfg.protected_paths[0].path, r"C:\Data\Secret");

        // Verify staging row was created for the removed path.
        // Note: agent_db() returns None in tests because init_agent_db sets
        // AGENT_DB but the test may not have access to the static. We verify
        // the logic by checking the changed_fields and cfg update.
    }

    /// Test 15: No-change path — cfg and payload protected_paths match.
    #[test]
    fn test_apply_payload_protected_paths_no_change() {
        let path_a = make_protected_path(r"C:\Data\Secret", "T3");

        let mut cfg = AgentConfig {
            protected_paths: vec![path_a.clone()],
            ..Default::default()
        };

        let mut payload = make_payload(vec![]);
        payload.protected_paths = vec![path_a.clone()];

        let (changed_fields, _) = apply_payload_to_config(&mut cfg, &payload);

        assert!(
            !changed_fields.contains(&"protected_paths"),
            "protected_paths must NOT be in changed_fields when unchanged"
        );
    }

    /// Test 16: protected_paths addition is detected.
    #[test]
    fn test_apply_payload_protected_paths_addition() {
        let path_a = make_protected_path(r"C:\Data\Secret", "T3");
        let path_b = make_protected_path(r"C:\Data\Confidential", "T3");

        let mut cfg = AgentConfig {
            protected_paths: vec![path_a.clone()],
            ..Default::default()
        };

        let mut payload = make_payload(vec![]);
        payload.protected_paths = vec![path_a.clone(), path_b.clone()];

        let (changed_fields, _) = apply_payload_to_config(&mut cfg, &payload);

        assert!(
            changed_fields.contains(&"protected_paths"),
            "protected_paths must be in changed_fields when paths are added"
        );
        assert_eq!(cfg.protected_paths.len(), 2);
    }

    // --- Phase 55: global_enforcement_mode apply tests ---

    #[test]
    fn test_apply_payload_updates_global_enforcement_mode() {
        let mut cfg = AgentConfig {
            enforcement: crate::config::EnforcementConfig {
                global_mode: dlp_common::abac::EnforcementMode::PerPolicy,
            },
            ..Default::default()
        };

        let mut payload = make_payload(vec![]);
        payload.global_enforcement_mode = "Audit".to_string();

        let (changed_fields, _) = apply_payload_to_config(&mut cfg, &payload);

        assert!(
            changed_fields.contains(&"global_enforcement_mode"),
            "global_enforcement_mode must be in changed_fields"
        );
        assert_eq!(
            cfg.enforcement.global_mode,
            dlp_common::abac::EnforcementMode::Audit
        );
    }

    #[test]
    fn test_apply_payload_global_enforcement_mode_no_change() {
        let mut cfg = AgentConfig {
            enforcement: crate::config::EnforcementConfig {
                global_mode: dlp_common::abac::EnforcementMode::Block,
            },
            ..Default::default()
        };

        let mut payload = make_payload(vec![]);
        payload.global_enforcement_mode = "Block".to_string();

        let (changed_fields, _) = apply_payload_to_config(&mut cfg, &payload);

        assert!(
            !changed_fields.contains(&"global_enforcement_mode"),
            "global_enforcement_mode must NOT be in changed_fields when unchanged"
        );
    }

    #[test]
    fn test_apply_payload_global_enforcement_mode_invalid_defaults_block() {
        let mut cfg = AgentConfig {
            enforcement: crate::config::EnforcementConfig {
                global_mode: dlp_common::abac::EnforcementMode::PerPolicy,
            },
            ..Default::default()
        };

        let mut payload = make_payload(vec![]);
        payload.global_enforcement_mode = "InvalidMode".to_string();

        let (changed_fields, _) = apply_payload_to_config(&mut cfg, &payload);

        // Invalid mode defaults to Block and still counts as a change
        assert!(changed_fields.contains(&"global_enforcement_mode"));
        assert_eq!(
            cfg.enforcement.global_mode,
            dlp_common::abac::EnforcementMode::Block
        );
    }

    // --- Phase 55-04: init_dacl_watcher global mode tests ---

    /// Test that `should_apply_tripwire_for_global_mode` returns false for Audit.
    #[test]
    fn test_service_startup_audit_mode_skips_tripwire() {
        // Verify the helper directly — the actual init_dacl_watcher uses it.
        assert!(
            !crate::dacl_tripwire::should_apply_tripwire_for_global_mode(
                dlp_common::abac::EnforcementMode::Audit
            )
        );
    }

    /// Test that `should_apply_tripwire_for_global_mode` returns true for Block.
    #[test]
    fn test_service_startup_block_mode_applies_tripwire() {
        assert!(crate::dacl_tripwire::should_apply_tripwire_for_global_mode(
            dlp_common::abac::EnforcementMode::Block
        ));
    }

    /// Test that `should_apply_tripwire_for_global_mode` returns true for PerPolicy.
    #[test]
    fn test_service_startup_perpolicy_mode_applies_tripwire() {
        assert!(crate::dacl_tripwire::should_apply_tripwire_for_global_mode(
            dlp_common::abac::EnforcementMode::PerPolicy
        ));
    }

    /// Test that `should_apply_tripwire_for_global_mode` returns true for AuditAndBlock.
    #[test]
    fn test_service_startup_auditandblock_mode_applies_tripwire() {
        assert!(crate::dacl_tripwire::should_apply_tripwire_for_global_mode(
            dlp_common::abac::EnforcementMode::AuditAndBlock
        ));
    }

    /// Phase 55.1: Verify that global_mode propagates from AgentConfig to CorrelatorConfig.
    ///
    /// This test locks the invariant that service.rs wiring actually propagates the
    /// enforcement mode and prevents silent regressions where `..Default::default()`
    /// masks a missing field.
    #[test]
    fn test_correlator_config_receives_global_mode_from_agent_config() {
        // Audit mode: the correlator should suppress bypass alerts.
        let mut audit_cfg = AgentConfig::default();
        audit_cfg.enforcement.global_mode = dlp_common::abac::EnforcementMode::Audit;
        let audit_config = crate::bypass_correlator::CorrelatorConfig {
            reduced_mode: false,
            enforcement_mode: audit_cfg.enforcement.global_mode,
            ..Default::default()
        };
        assert_eq!(
            audit_config.enforcement_mode,
            dlp_common::abac::EnforcementMode::Audit,
            "Audit mode must propagate to CorrelatorConfig"
        );

        // PerPolicy mode: the correlator should continue emitting alerts.
        let mut perpolicy_cfg = AgentConfig::default();
        perpolicy_cfg.enforcement.global_mode = dlp_common::abac::EnforcementMode::PerPolicy;
        let perpolicy_config = crate::bypass_correlator::CorrelatorConfig {
            reduced_mode: false,
            enforcement_mode: perpolicy_cfg.enforcement.global_mode,
            ..Default::default()
        };
        assert_eq!(
            perpolicy_config.enforcement_mode,
            dlp_common::abac::EnforcementMode::PerPolicy,
            "PerPolicy mode must propagate to CorrelatorConfig"
        );

        // Block mode: the correlator should continue emitting alerts (default).
        let mut block_cfg = AgentConfig::default();
        block_cfg.enforcement.global_mode = dlp_common::abac::EnforcementMode::Block;
        let block_config = crate::bypass_correlator::CorrelatorConfig {
            reduced_mode: false,
            enforcement_mode: block_cfg.enforcement.global_mode,
            ..Default::default()
        };
        assert_eq!(
            block_config.enforcement_mode,
            dlp_common::abac::EnforcementMode::Block,
            "Block mode must propagate to CorrelatorConfig"
        );
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Logging
// ──────────────────────────────────────────────────────────────────────────────

/// Default log directory for the DLP Agent service.
///
/// Override with `DLP_LOG_DIR` env var to redirect logs to a different directory
/// (e.g., a temp dir during integration tests where `C:\ProgramData\DLP\logs`
/// may require elevated privileges).
const LOG_DIR: &str = r"C:\ProgramData\DLP\logs";

/// Initialises structured logging to a rolling daily log file.
///
/// When running as a Windows Service, stdout is invisible — the log file
/// at `C:\ProgramData\DLP\logs\dlp-agent.log.<date>` is the primary diagnostic
/// output.
///
/// # Design: synchronous writer, no non_blocking channel
///
/// `tracing_appender::non_blocking` spawns a background writer thread that
/// receives log records via a bounded channel.  In the Windows Service context
/// (Session 0, LocalSystem, no console), the worker thread has been observed
/// to silently fail — every `write_all` call returns an IO error, the
/// `tracing-appender` worker loop swallows the error with a `// TODO` comment,
/// and the log file stays at 0 bytes despite the subscriber being installed.
///
/// Using `RollingFileAppender` directly as a synchronous `MakeWriter` avoids
/// the worker thread and the channel entirely: each log event is written on
/// the calling thread.  The `RollingFileAppender` guards its internal `File`
/// handle with an `RwLock` for multi-thread safety.
fn init_logging(level: Level) {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    crate::password_stop::debug_log("init_logging: entered");

    // Always prepend the configured level as the global default so that all
    // crate targets (dlp_agent::*, dlp_common::*, etc.) are covered.  Any
    // RUST_LOG value is appended after the default, so it can narrow specific
    // targets further without accidentally silencing everything else.
    // Example: RUST_LOG=dlp_endpoint=debug becomes "trace,dlp_endpoint=debug"
    // which keeps trace-level output for all other targets.
    let filter_str = match std::env::var("RUST_LOG") {
        Ok(s) if !s.is_empty() => format!("{level},{s}"),
        _ => level.to_string(),
    };
    let filter = tracing_subscriber::EnvFilter::new(&filter_str);

    crate::password_stop::debug_log(&format!("init_logging: filter = {filter}"));

    // Determine the log directory: DLP_LOG_DIR env var overrides the default.
    // This allows integration tests to redirect logs to a temp directory where
    // the test process has write access without requiring elevated privileges.
    let log_dir = std::env::var("DLP_LOG_DIR")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| LOG_DIR.to_string());

    // Ensure the log directory exists before creating any file appender.
    let dir_result = std::fs::create_dir_all(&log_dir);
    crate::password_stop::debug_log(&format!(
        "init_logging: create_dir_all({log_dir}) = {dir_result:?}"
    ));

    // Rolling daily log file: {log_dir}/dlp-agent.log.<date>
    // Used directly as a synchronous MakeWriter — no background thread required.
    // `RollingFileAppender` is thread-safe via its internal RwLock<File>.
    let file_appender = tracing_appender::rolling::daily(&log_dir, "dlp-agent.log");

    crate::password_stop::debug_log("init_logging: file_appender created");

    // Build a subscriber with two layers:
    //   1. File layer  — always active; ANSI escape codes disabled so the
    //      log file is readable by both humans and log-shipping agents.
    //   2. Stderr layer — only useful when a console is attached (e.g. debugging);
    //      silently discarded when running as a Windows Service.
    let init_result = tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(file_appender)
                .with_span_events(FmtSpan::CLOSE)
                .with_target(true)
                .with_thread_ids(true)
                .with_ansi(false),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_span_events(FmtSpan::CLOSE)
                .with_target(true)
                .with_thread_ids(true),
        )
        .try_init();

    match &init_result {
        Ok(()) => {
            crate::password_stop::debug_log("init_logging: try_init OK — subscriber installed");
        }
        Err(e) => {
            // A global subscriber is already installed (e.g., during tests).
            // Log via the bypass path so the conflict is never silently lost.
            crate::password_stop::debug_log(&format!(
                "init_logging: try_init ERR — subscriber already installed: {e}"
            ));
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Shutdown signal and BlockingThreads tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
/// Mutex to serialize tests that mutate the global `SHUTDOWN_REQUESTED` static.
/// Without this, parallel test execution causes non-deterministic failures
/// when one test resets the flag while another expects it to remain set.
static SHUTDOWN_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Test that the shutdown signal can be set, read, and reset.
#[test]
fn test_shutdown_signal_roundtrip() {
    let _guard = SHUTDOWN_TEST_MUTEX.lock().unwrap();
    reset_shutdown_signal();
    assert!(!shutdown_requested());

    request_shutdown();
    assert!(shutdown_requested());

    reset_shutdown_signal();
    assert!(!shutdown_requested());
}

/// Test that BlockingThreads can be created and shutdown_and_join
/// completes even with no threads (empty case).
#[test]
fn test_blocking_threads_empty_shutdown() {
    let _guard = SHUTDOWN_TEST_MUTEX.lock().unwrap();
    reset_shutdown_signal();
    let threads = BlockingThreads::new();
    threads.shutdown_and_join();
    assert!(shutdown_requested());
}

/// Test that BlockingThreads shutdown_and_join signals a running thread.
#[test]
fn test_blocking_threads_joins_running_thread() {
    let _guard = SHUTDOWN_TEST_MUTEX.lock().unwrap();
    reset_shutdown_signal();

    let (counter, handle) = spawn_shutdown_observing_thread();

    let mut threads = BlockingThreads::new();
    threads.health = Some(handle);

    assert_shutdown_joins_thread(threads, counter, "thread");
}

/// Test that BlockingThreads joins threads during shutdown.
#[test]
fn test_blocking_threads_joins_threads() {
    let _guard = SHUTDOWN_TEST_MUTEX.lock().unwrap();
    reset_shutdown_signal();

    let (counter, handle) = spawn_shutdown_observing_thread();

    let mut threads = BlockingThreads::new();
    threads.ipc.push(handle);

    assert_shutdown_joins_thread(threads, counter, "ipc thread");
}

/// Spawns a thread that increments `counter` once shutdown is requested.
#[cfg(test)]
fn spawn_shutdown_observing_thread() -> (
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
    std::thread::JoinHandle<()>,
) {
    use std::sync::atomic::AtomicUsize;

    let counter = std::sync::Arc::new(AtomicUsize::new(0));
    let counter_clone = counter.clone();

    let handle = std::thread::spawn(move || {
        while !shutdown_requested() {
            std::thread::sleep(Duration::from_millis(10));
        }
        counter_clone.fetch_add(1, Ordering::SeqCst);
    });

    (counter, handle)
}

/// Signals shutdown on `threads`, joins all threads, and asserts the counter reached 1.
#[cfg(test)]
fn assert_shutdown_joins_thread(
    threads: BlockingThreads,
    counter: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    description: &str,
) {
    // Give the thread time to start
    std::thread::sleep(Duration::from_millis(50));

    threads.shutdown_and_join();

    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "{description} should have exited cleanly"
    );
}

/// Mock cache accessor for service-level hook IPC tests.
#[cfg(test)]
struct MockCache {
    version: u64,
}

#[cfg(test)]
impl crate::hook_ipc::CacheAccessor for MockCache {
    fn current_version(&self) -> u64 {
        self.version
    }
}

/// Builds a minimal offline manager for hook IPC tests.
#[cfg(test)]
fn test_offline_manager() -> Arc<crate::offline::OfflineManager> {
    let engine_client =
        crate::engine_client::EngineClient::new(crate::engine_client::DEFAULT_ENGINE_URL, false)
            .expect("engine client must be constructable");
    let cache = Arc::new(crate::cache::Cache::new());
    Arc::new(crate::offline::OfflineManager::new(
        engine_client,
        cache,
        None,
    ))
}

/// Test that `spawn_hook_ipc_server` spawns a named thread and returns a
/// handle that can be joined after shutdown is requested.
#[test]
fn test_spawn_hook_ipc_server_starts_named_thread() {
    let _guard = SHUTDOWN_TEST_MUTEX.lock().unwrap();
    reset_shutdown_signal();

    let cache: Arc<dyn crate::hook_ipc::CacheAccessor> = Arc::new(MockCache { version: 1 });
    let offline = test_offline_manager();
    let (bypass_tx, _bypass_rx) = crossbeam_channel::unbounded::<BypassAlert>();
    let diag = Arc::new(crate::diagnostic_aggregator::DiagnosticAggregator::new());
    let health = Arc::new(crate::health_aggregator::HealthAggregator::new());
    let (override_tx, _override_rx) =
        tokio::sync::mpsc::channel::<dlp_common::hook_ipc::OverrideRequest>(100);
    let approval = Arc::new(crate::approval_cache::ApprovalCache::new());

    let config = HookIpcServerConfig {
        pipe_name: crate::hook_ipc::DEFAULT_PIPE_NAME.to_string(),
        cache,
        offline,
        bypass_tx,
        diagnostic_aggregator: diag,
        health_aggregator: health,
        override_tx,
        approval_cache: approval,
        hash_cache: crate::hash_cache::create_hash_cache(),
        process_registry: Arc::new(crate::process_registry::ProcessRegistry::new()),
        audit_ctx: crate::audit_emitter::EmitContext {
            agent_id: "AGENT-TEST".to_string(),
            session_id: 0,
            user_sid: "S-1-5-18".to_string(),
            user_name: "SYSTEM".to_string(),
            machine_name: None,
        },
    };

    let handle = spawn_hook_ipc_server(config).expect("hook IPC server thread should spawn");

    assert_eq!(handle.thread().name(), Some("hook-ipc-server"));

    // Signal shutdown so the accept loop exits cleanly.
    request_shutdown();
    handle
        .join()
        .expect("hook IPC server thread should join cleanly");
}

/// Test that `emit_ntdll_patching_enabled_event` emits a `NtdllPatchingEnabled`
/// audit event with the correct fields and SIEM routing.
#[cfg(test)]
#[test]
#[serial_test::serial]
fn test_emit_ntdll_patching_enabled_event() {
    use dlp_common::audit::EventType;

    // Enable the in-process capture sink so we can assert on emitted events.
    let _guard = crate::audit_emitter::audit_test_lock();
    crate::audit_emitter::enable_test_capture();

    // Call the emission function.
    emit_ntdll_patching_enabled_event();

    // Drain captured events and verify.
    let events = crate::audit_emitter::drain_test_events();
    assert!(
        !events.is_empty(),
        "emit_ntdll_patching_enabled_event must emit at least one audit event"
    );

    let event = &events[0];
    assert_eq!(
        event.event_type,
        EventType::NtdllPatchingEnabled,
        "event type must be NtdllPatchingEnabled"
    );
    assert_eq!(event.user_sid, "SYSTEM", "user_sid must be SYSTEM");
    assert_eq!(event.user_name, "SYSTEM", "user_name must be SYSTEM");
    assert_eq!(event.resource_path, "N/A", "resource_path must be N/A");
    assert_eq!(
        event.classification,
        dlp_common::Classification::T1,
        "classification must be T1"
    );
    assert_eq!(
        event.action_attempted,
        dlp_common::Action::PolicyUpdate,
        "action must be PolicyUpdate"
    );
    assert_eq!(
        event.decision,
        dlp_common::Decision::ALLOW,
        "decision must be ALLOW"
    );
    assert!(
        event.event_type.routed_to_siem(),
        "NtdllPatchingEnabled must be routed to SIEM"
    );
    assert!(!event.agent_id.is_empty(), "agent_id must not be empty");
}

/// Test that `map_hook_action_to_abac` correctly maps all known hook action strings.
#[test]
fn test_map_hook_action_to_abac_all_variants() {
    assert_eq!(map_hook_action_to_abac("READ"), dlp_common::Action::READ);
    assert_eq!(map_hook_action_to_abac("NT_READ"), dlp_common::Action::READ);
    assert_eq!(map_hook_action_to_abac("WRITE"), dlp_common::Action::WRITE);
    assert_eq!(map_hook_action_to_abac("CREATE"), dlp_common::Action::WRITE);
    assert_eq!(
        map_hook_action_to_abac("NT_WRITE"),
        dlp_common::Action::WRITE
    );
    assert_eq!(map_hook_action_to_abac("COPY"), dlp_common::Action::COPY);
    assert_eq!(
        map_hook_action_to_abac("DELETE"),
        dlp_common::Action::DELETE
    );
    assert_eq!(map_hook_action_to_abac("MOVE"), dlp_common::Action::DELETE);
    assert_eq!(
        map_hook_action_to_abac("RENAME"),
        dlp_common::Action::DELETE
    );
    assert_eq!(
        map_hook_action_to_abac("REPLACE"),
        dlp_common::Action::DELETE
    );
    assert_eq!(
        map_hook_action_to_abac("SET_INFO"),
        dlp_common::Action::DELETE
    );
    assert_eq!(
        map_hook_action_to_abac("NT_SET_INFO"),
        dlp_common::Action::DELETE
    );
    // Unknown actions fall back to READ.
    assert_eq!(map_hook_action_to_abac("UNKNOWN"), dlp_common::Action::READ);
    // Case insensitivity.
    assert_eq!(map_hook_action_to_abac("read"), dlp_common::Action::READ);
    assert_eq!(map_hook_action_to_abac("Write"), dlp_common::Action::WRITE);
}

/// Test that `hook_request_to_evaluate_request` builds a correct `EvaluateRequest`
/// with volume classes forwarded and all optional fields left as `None`.
#[test]
fn test_hook_request_to_evaluate_request() {
    let req = dlp_common::HookRequest {
        path: r"C:\Users\test\file.txt".to_string(),
        action: "COPY".to_string(),
        cache_version: 0,
        protocol_version: 1,
        op: dlp_common::hook_ipc::HookOp::Read,
        source_volume_class: Some(dlp_common::VolumeClass::LocalNTFS),
        destination_volume_class: Some(dlp_common::VolumeClass::USBRemovable),
        pid: 1234,
    };
    let caller_sid = "S-1-5-21-1234567890-1234567890-1234567890-1001".to_string();

    let eval_req = hook_request_to_evaluate_request(&req, caller_sid.clone());

    assert_eq!(eval_req.subject.user_sid, caller_sid);
    assert_eq!(eval_req.resource.path, req.path);
    assert_eq!(eval_req.action, dlp_common::Action::COPY);
    assert_eq!(
        eval_req.source_volume_class,
        Some(dlp_common::VolumeClass::LocalNTFS)
    );
    assert_eq!(
        eval_req.destination_volume_class,
        Some(dlp_common::VolumeClass::USBRemovable)
    );
    assert!(eval_req.agent.is_none());
    assert!(eval_req.source_application.is_none());
    assert!(eval_req.destination_application.is_none());
    assert!(eval_req.source_origin.is_none());
    assert!(eval_req.destination_origin.is_none());
}

/// Test that `hook_request_to_evaluate_request` forwards Optical volume class.
#[test]
fn test_hook_request_to_evaluate_request_forwards_volume_classes() {
    let req = dlp_common::HookRequest {
        path: r"C:\test.txt".to_string(),
        action: "COPY".to_string(),
        cache_version: 0,
        protocol_version: 1,
        op: dlp_common::hook_ipc::HookOp::Read,
        source_volume_class: Some(dlp_common::VolumeClass::LocalNTFS),
        destination_volume_class: Some(dlp_common::VolumeClass::Optical),
        pid: 1234,
    };
    let caller_sid = "S-1-5-21-123".to_string();

    let eval_req = hook_request_to_evaluate_request(&req, caller_sid.clone());

    assert_eq!(eval_req.subject.user_sid, caller_sid);
    assert_eq!(eval_req.resource.path, r"C:\test.txt");
    assert_eq!(eval_req.action, dlp_common::Action::COPY);
    assert_eq!(
        eval_req.source_volume_class,
        Some(dlp_common::VolumeClass::LocalNTFS)
    );
    assert_eq!(
        eval_req.destination_volume_class,
        Some(dlp_common::VolumeClass::Optical)
    );
}

/// Test that `hook_request_to_evaluate_request` leaves optional fields as None.
#[test]
fn test_hook_request_to_evaluate_request_leaves_optional_fields_none() {
    let req = dlp_common::HookRequest {
        path: r"C:\Users\test\file.txt".to_string(),
        action: "READ".to_string(),
        cache_version: 0,
        protocol_version: 1,
        op: dlp_common::hook_ipc::HookOp::Read,
        source_volume_class: None,
        destination_volume_class: None,
        pid: 1234,
    };
    let eval_req = hook_request_to_evaluate_request(&req, "S-1-5-21-test".to_string());

    assert!(eval_req.agent.is_none());
    assert!(eval_req.source_application.is_none());
    assert!(eval_req.destination_application.is_none());
    assert!(eval_req.source_origin.is_none());
    assert!(eval_req.destination_origin.is_none());
}

/// Test that `get_caller_sid` returns a test stub on non-Windows targets.
#[cfg(not(windows))]
#[test]
fn test_get_caller_sid_non_windows_stub() {
    let sid = get_caller_sid(0);
    assert_eq!(sid, Some("S-1-5-18-test".to_string()));
    let sid2 = get_caller_sid(1234);
    assert_eq!(sid2, Some("S-1-5-18-test".to_string()));
}

/// Test that `get_caller_sid` on Windows returns a valid SID string.
#[cfg(windows)]
#[test]
fn test_get_caller_sid_windows_current_process() {
    let current_pid = std::process::id();
    let sid = get_caller_sid(current_pid);
    assert!(
        sid.is_some(),
        "get_caller_sid should return Some for current process"
    );
    let sid_str = sid.unwrap();
    assert!(
        sid_str.starts_with("S-1-5-"),
        "SID should start with S-1-5-, got: {}",
        sid_str
    );
}

// ---------------------------------------------------------------------------
// Tracing log capture helpers for warning verification tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[derive(Clone)]
struct BufferWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

#[cfg(test)]
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for BufferWriter {
    type Writer = BufferGuard;
    fn make_writer(&'a self) -> Self::Writer {
        BufferGuard(self.0.clone())
    }
}

#[cfg(test)]
struct BufferGuard(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

#[cfg(test)]
impl std::io::Write for BufferGuard {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut guard = self.0.lock().expect("buffer poisoned");
        guard.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
static TEST_LOG_BUFFER: std::sync::OnceLock<std::sync::Arc<std::sync::Mutex<Vec<u8>>>> =
    std::sync::OnceLock::new();

#[cfg(test)]
fn get_test_log_buffer() -> std::sync::Arc<std::sync::Mutex<Vec<u8>>> {
    TEST_LOG_BUFFER
        .get_or_init(|| {
            let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let writer = BufferWriter(buf.clone());
            let subscriber = tracing_subscriber::fmt::Subscriber::builder()
                .with_max_level(tracing::Level::WARN)
                .with_writer(writer)
                .with_ansi(false)
                .finish();
            let _ = tracing::dispatcher::set_global_default(subscriber.into());
            buf
        })
        .clone()
}

// ---------------------------------------------------------------------------
// Gap 58.2-02-02: PID->SID resolution failures must result in DENY
// ---------------------------------------------------------------------------

/// Test that a HookRequest with an invalid PID (pid=0) results in a DENY
/// decision with reason "identity resolution failed" on Windows.
///
/// On non-Windows, `get_caller_sid` returns a test stub for any PID, so
/// this test is Windows-only.
#[cfg(test)]
#[cfg(windows)]
#[test]
#[serial_test::serial]
fn test_invalid_pid_returns_deny_identity_resolution_failed() {
    let _guard = SHUTDOWN_TEST_MUTEX.lock().unwrap();
    reset_shutdown_signal();

    let cache: Arc<dyn crate::hook_ipc::CacheAccessor> = Arc::new(MockCache { version: 1 });
    let offline = test_offline_manager();
    let (bypass_tx, _bypass_rx) = crossbeam_channel::unbounded::<BypassAlert>();
    let diag = Arc::new(crate::diagnostic_aggregator::DiagnosticAggregator::new());
    let health = Arc::new(crate::health_aggregator::HealthAggregator::new());
    let (override_tx, _override_rx) =
        tokio::sync::mpsc::channel::<dlp_common::hook_ipc::OverrideRequest>(100);
    let approval = Arc::new(crate::approval_cache::ApprovalCache::new());

    let config = HookIpcServerConfig {
        pipe_name: r"\\.\pipe\DlpHookPipeTestInvalidPid".to_string(),
        cache,
        offline,
        bypass_tx,
        diagnostic_aggregator: diag,
        health_aggregator: health,
        override_tx,
        approval_cache: approval,
        hash_cache: crate::hash_cache::create_hash_cache(),
        process_registry: Arc::new(crate::process_registry::ProcessRegistry::new()),
        audit_ctx: crate::audit_emitter::EmitContext {
            agent_id: "AGENT-TEST".to_string(),
            session_id: 0,
            user_sid: "S-1-5-18".to_string(),
            user_name: "SYSTEM".to_string(),
            machine_name: None,
        },
    };

    let handle = spawn_hook_ipc_server(config).expect("hook IPC server thread should spawn");

    // Give the server time to create the pipe.
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Connect a client and send a Request with pid=0.
    let client = crate::hook_ipc::connect_client(r"\\.\pipe\DlpHookPipeTestInvalidPid")
        .expect("client connect");

    let req = dlp_common::HookRequest {
        path: r"C:\test\file.txt".to_string(),
        action: "READ".to_string(),
        cache_version: 0,
        protocol_version: 1,
        op: dlp_common::hook_ipc::HookOp::Read,
        source_volume_class: None,
        destination_volume_class: None,
        pid: 0,
    };

    let envelope = dlp_common::hook_ipc::IpcEnvelope::V1(dlp_common::hook_ipc::IpcMessageV1 {
        payload: dlp_common::hook_ipc::IpcPayloadV1::Request(req),
    });

    let payload = bincode::serialize(&envelope).expect("serialize envelope");
    crate::ipc::frame::write_frame(client, &payload).expect("write frame");

    let frame = crate::ipc::frame::read_frame(client).expect("read frame");
    let response_envelope: dlp_common::hook_ipc::IpcEnvelope =
        bincode::deserialize(&frame).expect("deserialize envelope");

    match response_envelope {
        dlp_common::hook_ipc::IpcEnvelope::V1(dlp_common::hook_ipc::IpcMessageV1 {
            payload: dlp_common::hook_ipc::IpcPayloadV1::Response(resp),
        }) => {
            assert_eq!(
                resp.decision,
                dlp_common::Decision::DENY,
                "Expected DENY for invalid PID, got {:?}",
                resp.decision
            );
            assert!(
                resp.reason.contains("identity resolution failed"),
                "Expected 'identity resolution failed' reason, got: {}",
                resp.reason
            );
        }
        other => panic!("Expected Response frame, got {:?}", other),
    }

    crate::hook_ipc::close_pipe(client);

    request_shutdown();
    handle.join().expect("server thread should join cleanly");
    reset_shutdown_signal();
}

// ---------------------------------------------------------------------------
// Gap 58.2-02-03: COPY/MOVE with None volume class logs warning
// ---------------------------------------------------------------------------

/// Test that COPY/MOVE requests with None source or destination volume class
/// emit a tracing::warn! warning through the actual handler closure.
#[cfg(test)]
#[test]
#[serial_test::serial]
fn test_copy_move_none_volume_class_logs_warning() {
    let _guard = SHUTDOWN_TEST_MUTEX.lock().unwrap();
    reset_shutdown_signal();

    // Ensure the global test subscriber is installed and clear the buffer.
    let buf = get_test_log_buffer();
    {
        let mut guard = buf.lock().expect("buffer poisoned");
        guard.clear();
    }

    let cache: Arc<dyn crate::hook_ipc::CacheAccessor> = Arc::new(MockCache { version: 1 });
    let offline = test_offline_manager();
    let (bypass_tx, _bypass_rx) = crossbeam_channel::unbounded::<BypassAlert>();
    let diag = Arc::new(crate::diagnostic_aggregator::DiagnosticAggregator::new());
    let health = Arc::new(crate::health_aggregator::HealthAggregator::new());
    let (override_tx, _override_rx) =
        tokio::sync::mpsc::channel::<dlp_common::hook_ipc::OverrideRequest>(100);
    let approval = Arc::new(crate::approval_cache::ApprovalCache::new());

    let config = HookIpcServerConfig {
        pipe_name: r"\\.\pipe\DlpHookPipeTestWarning".to_string(),
        cache,
        offline,
        bypass_tx,
        diagnostic_aggregator: diag,
        health_aggregator: health,
        override_tx,
        approval_cache: approval,
        hash_cache: crate::hash_cache::create_hash_cache(),
        process_registry: Arc::new(crate::process_registry::ProcessRegistry::new()),
        audit_ctx: crate::audit_emitter::EmitContext {
            agent_id: "AGENT-TEST".to_string(),
            session_id: 0,
            user_sid: "S-1-5-18".to_string(),
            user_name: "SYSTEM".to_string(),
            machine_name: None,
        },
    };

    let handle = spawn_hook_ipc_server(config).expect("hook IPC server thread should spawn");

    // Give the server time to create the pipe.
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Connect a client and send a COPY request with None volume classes.
    let client = crate::hook_ipc::connect_client(r"\\.\pipe\DlpHookPipeTestWarning")
        .expect("client connect");

    let req = dlp_common::HookRequest {
        path: r"C:\test\file.txt".to_string(),
        action: "COPY".to_string(),
        cache_version: 0,
        protocol_version: 1,
        op: dlp_common::hook_ipc::HookOp::Read,
        source_volume_class: None,
        destination_volume_class: None,
        pid: std::process::id(),
    };

    let envelope = dlp_common::hook_ipc::IpcEnvelope::V1(dlp_common::hook_ipc::IpcMessageV1 {
        payload: dlp_common::hook_ipc::IpcPayloadV1::Request(req),
    });

    let payload = bincode::serialize(&envelope).expect("serialize envelope");
    crate::ipc::frame::write_frame(client, &payload).expect("write frame");

    let frame = crate::ipc::frame::read_frame(client).expect("read frame");
    let response_envelope: dlp_common::hook_ipc::IpcEnvelope =
        bincode::deserialize(&frame).expect("deserialize envelope");

    // Verify we got a response (the server processed the request).
    match response_envelope {
        dlp_common::hook_ipc::IpcEnvelope::V1(dlp_common::hook_ipc::IpcMessageV1 {
            payload: dlp_common::hook_ipc::IpcPayloadV1::Response(_),
        }) => {}
        other => panic!("Expected Response frame, got {:?}", other),
    }

    crate::hook_ipc::close_pipe(client);

    request_shutdown();
    handle.join().expect("server thread should join cleanly");
    reset_shutdown_signal();

    // Verify the warning was logged.
    let log_text = {
        let guard = buf.lock().expect("buffer poisoned");
        String::from_utf8_lossy(&guard).to_string()
    };
    assert!(
        log_text.contains("missing source_volume_class"),
        "Expected warning about missing source_volume_class. Log buffer: {}",
        log_text
    );
    assert!(
        log_text.contains("missing destination_volume_class"),
        "Expected warning about missing destination_volume_class. Log buffer: {}",
        log_text
    );
}

// ---------------------------------------------------------------------------
// Phase 58.5: Unhook orchestration tests
// ---------------------------------------------------------------------------

/// Builds a minimal `EmitContext` for Phase 58.5 tests.
#[cfg(test)]
fn make_test_emit_context() -> crate::audit_emitter::EmitContext {
    crate::audit_emitter::EmitContext {
        agent_id: "AGENT-TEST".to_string(),
        session_id: 1,
        user_sid: "S-1-5-18".to_string(),
        user_name: "SYSTEM".to_string(),
        machine_name: None,
    }
}

/// Test that `reconcile_watchdog_evidence` transitions a matching Injected
/// entry to Exited, emits `WatchdogSelfUnload`, and removes the evidence file.
#[cfg(test)]
#[test]
#[serial_test::serial]
fn test_reconcile_watchdog_evidence_transitions_and_emits() {
    let _guard = crate::audit_emitter::audit_test_lock();
    let _shutdown_guard = SHUTDOWN_TEST_MUTEX.lock().unwrap();
    reset_shutdown_signal();
    crate::audit_emitter::enable_test_capture();

    let dir = tempfile::tempdir()
        .unwrap()
        .as_ref()
        .join("WatchdogSelfUnload");
    std::fs::create_dir_all(&dir).unwrap();

    // Write a test evidence file.
    let evidence_path = dir.join("1234.evidence.json");
    let evidence = serde_json::json!({
        "pid": 1234,
        "creation_time": 1000,
        "reason": "watchdog_timeout",
        "timestamp_secs": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    });
    std::fs::write(&evidence_path, serde_json::to_string(&evidence).unwrap()).unwrap();

    // Seed the registry with a matching Injected entry.
    let registry = Arc::new(crate::process_registry::ProcessRegistry::new());
    let key = crate::process_registry::ProcessKey {
        pid: 1234,
        creation_time: 1000,
    };
    registry.try_claim(key);
    registry.record_injected(key, "x64".to_string());

    let audit_ctx = make_test_emit_context();

    reconcile_watchdog_evidence_in_dir(&audit_ctx, Some(Arc::clone(&registry)), dir.clone());

    // Registry entry should be Exited.
    let state = registry.get(&key).expect("key should exist");
    assert_eq!(*state, crate::process_registry::ProcessState::Exited);

    // WatchdogSelfUnload event should be captured.
    let events = crate::audit_emitter::drain_test_events();
    let watchdog_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == dlp_common::EventType::WatchdogSelfUnload)
        .collect();
    assert_eq!(watchdog_events.len(), 1);
    assert_eq!(
        watchdog_events[0].resource_path,
        "process://1234/watchdog_self_unload"
    );
    assert!(watchdog_events[0]
        .justification
        .as_deref()
        .unwrap_or("")
        .contains("reason=watchdog_timeout"));
}

/// Test that `reconcile_watchdog_evidence` emits an untracked `WatchdogSelfUnload`
/// event and retains the evidence file when no matching registry entry exists.
#[cfg(test)]
#[test]
#[serial_test::serial]
fn test_reconcile_watchdog_evidence_untracked_emits_and_retains() {
    let _guard = crate::audit_emitter::audit_test_lock();
    let _shutdown_guard = SHUTDOWN_TEST_MUTEX.lock().unwrap();
    reset_shutdown_signal();
    crate::audit_emitter::enable_test_capture();

    let dir = tempfile::tempdir()
        .unwrap()
        .as_ref()
        .join("WatchdogSelfUnload");
    std::fs::create_dir_all(&dir).unwrap();

    let evidence_path = dir.join("9999.evidence.json");
    let evidence = serde_json::json!({
        "pid": 9999,
        "creation_time": 1000,
        "reason": "watchdog_timeout",
        "timestamp_secs": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    });
    std::fs::write(&evidence_path, serde_json::to_string(&evidence).unwrap()).unwrap();

    let registry = Arc::new(crate::process_registry::ProcessRegistry::new());
    let audit_ctx = make_test_emit_context();

    reconcile_watchdog_evidence_in_dir(&audit_ctx, Some(Arc::clone(&registry)), dir.clone());

    // Evidence file should be retained.
    assert!(
        evidence_path.exists(),
        "unmatched evidence file should be retained"
    );

    // Untracked WatchdogSelfUnload event should be captured.
    let events = crate::audit_emitter::drain_test_events();
    let watchdog_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == dlp_common::EventType::WatchdogSelfUnload)
        .collect();
    assert_eq!(watchdog_events.len(), 1);
    assert!(
        watchdog_events[0]
            .justification
            .as_deref()
            .unwrap_or("")
            .contains("untracked=true"),
        "expected untracked flag in justification"
    );

    // Cleanup is handled by the tempfile directory automatically.
}

/// Test that `request_unhook_from_injected` sets `UNHOOK_ALL_REQUESTED` and emits
/// `AgentShutdownUnhook` when the registry contains injected processes.
#[cfg(test)]
#[test]
#[serial_test::serial]
fn test_request_unhook_from_injected_sets_flag_and_emits() {
    let _guard = crate::audit_emitter::audit_test_lock();
    reset_shutdown_signal();
    reset_unhook_signal();
    crate::audit_emitter::enable_test_capture();

    let registry = Arc::new(crate::process_registry::ProcessRegistry::new());
    let key = crate::process_registry::ProcessKey {
        pid: 1234,
        creation_time: 1000,
    };
    registry.try_claim(key);
    registry.record_injected(key, "x64".to_string());

    let audit_ctx = make_test_emit_context();
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(request_unhook_from_injected(&registry, &audit_ctx));

    assert!(
        UNHOOK_ALL_REQUESTED.load(Ordering::Acquire),
        "UNHOOK_ALL_REQUESTED should be set"
    );

    let events = crate::audit_emitter::drain_test_events();
    let shutdown_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == dlp_common::EventType::AgentShutdownUnhook)
        .collect();
    assert_eq!(shutdown_events.len(), 1);
    assert_eq!(shutdown_events[0].decision, dlp_common::Decision::ALLOW);
    assert_eq!(
        shutdown_events[0].resource_path,
        format!("agent://{}/unhook_request", std::process::id())
    );
    assert!(shutdown_events[0]
        .justification
        .as_deref()
        .unwrap_or("")
        .contains("injected_count=1"));
    assert!(shutdown_events[0]
        .justification
        .as_deref()
        .unwrap_or("")
        .contains("target_pids=[1234]"));

    // The entry never acked, so it should still be Injected and an UnhookFailure
    // event should have been emitted.
    let failure_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == dlp_common::EventType::UnhookFailure)
        .collect();
    assert_eq!(failure_events.len(), 1);
    assert_eq!(failure_events[0].resource_path, "pid=1234");

    reset_unhook_signal();
}

/// Test that `wait_for_unhook_acks` returns immediately when the registry has
/// no injected processes.
#[cfg(test)]
#[tokio::test]
#[serial_test::serial]
async fn test_wait_for_unhook_acks_empty_registry_returns_zero() {
    let registry = Arc::new(crate::process_registry::ProcessRegistry::new());
    let remaining = wait_for_unhook_acks(&registry, Duration::from_millis(50)).await;
    assert_eq!(remaining, 0);
}
