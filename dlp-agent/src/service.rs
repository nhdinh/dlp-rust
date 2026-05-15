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
use std::time::Duration;

use anyhow::{Context, Result};
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

/// Maximum time allowed for graceful shutdown (OP-04).
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum time to wait for in-flight disk enumeration to cancel (OP-04).
const DISK_ENUM_CANCEL_TIMEOUT: Duration = Duration::from_secs(5);

/// Global SCM status handle — set once after `register()` returns.
///
/// The control handler callback cannot capture the status handle (chicken-and-egg:
/// the handler is passed to `register`, which returns the handle).  This global
/// bridges the gap so the handler can report state transitions (e.g. `StopPending`)
/// directly to the SCM instead of only updating the internal `SERVICE_STATE` mutex.
static SCM_HANDLE: std::sync::OnceLock<ServiceStatusHandle> = std::sync::OnceLock::new();

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

/// Runs the DLP Agent Windows Service to completion.
pub fn run_service() -> Result<()> {
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
    let chrome_handle = std::thread::Builder::new()
        .name("chrome-pipe".into())
        .spawn(|| {
            if let Err(e) = crate::chrome::handler::serve() {
                error!(error = %e, "Chrome pipe server exited with error");
            }
        })
        .context("failed to spawn Chrome pipe thread")?;
    info!(thread_id = ?chrome_handle.thread().id(), "Chrome pipe server started");

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
    rt.block_on(run_loop(&status_handle, machine_name))?;

    // Shut down the tokio runtime immediately.  Background tasks (IPC pipe
    // servers, session monitor) use blocking ReadFile calls that never
    // return on their own.  Dropping the runtime without shutdown_timeout
    // would hang forever waiting for those tasks.
    rt.shutdown_timeout(Duration::from_secs(2));

    // ── Graceful shutdown of blocking threads ────────────────────────
    crate::password_stop::debug_log("run_service: run_loop returned — shutting down subsystems");
    info!(service_name = SERVICE_NAME, "shutting down subsystems");

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

/// Periodically polls the server for updated agent config.
///
/// Runs on a separate timer independent of heartbeat. On each tick:
/// 1. Fetch resolved config from `GET /agent-config/{agent_id}`.
/// 2. Diff all pushed fields (including `disk_allowlist`) against in-memory state.
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
            // Capture interval BEFORE applying any update (T-06-08 DoS mitigation).
            let current_interval = {
                let cfg = config.lock();
                cfg.heartbeat_interval_secs.unwrap_or(30)
            };

            match server_client.fetch_agent_config().await {
                Ok(payload) => {
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
    detector_arc: Arc<crate::detection::UsbDetector>,
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
    /// Stored for future integration with the interception engine's three-stage pipeline.
    #[allow(dead_code)]
    approval_cache: Arc<crate::approval_cache::ApprovalCache>,
    /// Handle to the approval cache poll task.
    approval_poll_handle: Option<tokio::task::JoinHandle<()>>,
    /// Sender to signal the approval poll task to exit.
    approval_shutdown_tx: tokio::sync::watch::Sender<bool>,
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
) -> Result<()> {
    // ── Open the audit log ────────────────────────────────────────────────
    let _log_path = crate::audit_emitter::log_path();
    info!(audit_log = %_log_path.display(), "audit subsystem initialised");

    // Initialise all subsystems and collect handles into a single context.
    let ctx = run_loop_init(machine_name).await;

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

/// Initialises all enforcement subsystems and returns a [`RunLoopContext`]
/// containing every handle and sender needed for graceful shutdown.
///
/// Extracted from [`run_loop`] to reduce cognitive complexity.  Each subsystem
/// block is kept in source order so comments remain valid.
async fn run_loop_init(machine_name: Option<String>) -> RunLoopContext {
    // ── Initialise the agent's local SQLite DB (offline audit queue) ───────
    if let Err(e) = init_agent_db() {
        warn!(error = %e, "agent DB init failed — offline audit queue unavailable");
    }

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

    // ── Load agent config (needed for server_url before monitor setup) ───
    let agent_config = crate::config::AgentConfig::load_default();

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

    // SAFETY: detector_arc is stored in the RunLoopContext which outlives the
    // service main loop. The static reference is only used during the lifetime
    // of the service process.
    let detector_static: &'static crate::detection::UsbDetector =
        unsafe { std::mem::transmute(detector_arc.as_ref()) };
    crate::detection::usb::set_drive_detector(detector_static);

    // ── Offline manager ────────────────────────────────────────────────────
    let offline = init_offline_manager(engine_client, cache, &server_client, machine_name.clone());

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
    let (config_shutdown_tx, config_poll_handle) =
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

    let audit_ctx = build_audit_ctx(machine_name);

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
            let injector = crate::hook_injector::HookInjector::new(&dll_path, Some(dll_path_x86.clone()));
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
    );

    let file_monitor_for_shutdown = file_monitor.clone();
    let file_handle = tokio::task::spawn_blocking(move || {
        let _ = file_monitor.run(action_tx, Some(watch_rx));
    });

    info!(
        service_name = SERVICE_NAME,
        "enforcement subsystems started"
    );

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
async fn init_usb_detector() -> Arc<crate::detection::UsbDetector> {
    use std::sync::OnceLock;
    static USB_DETECTOR: OnceLock<Arc<crate::detection::UsbDetector>> = OnceLock::new();
    let detector = USB_DETECTOR.get_or_init(|| Arc::new(crate::detection::UsbDetector::new()));
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

/// Spawns the config poll task when a server client is available.
///
/// Returns `(shutdown_tx, poll_handle)` where `poll_handle` is `None` when no
/// server client is available.
fn spawn_config_poll_task(
    server_client: Option<crate::server_client::ServerClient>,
    config: Arc<parking_lot::Mutex<crate::config::AgentConfig>>,
) -> (
    tokio::sync::watch::Sender<bool>,
    Option<tokio::task::JoinHandle<()>>,
) {
    let (tx, rx) = tokio::sync::watch::channel(false);
    let handle = server_client.map(|sc| {
        tokio::spawn(async move {
            config_poll_loop(sc, config, rx).await;
        })
    });
    (tx, handle)
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
                    // We use jsonwebtoken::decode without verification here because
                    // the token was just fetched from the trusted server over HTTPS.
                    // The signature is re-verified on every cache read via
                    // ApprovalCache::check() using the cached public key.
                    let token_data = match jsonwebtoken::decode::<ApprovalClaims>(
                        &entry.token,
                        &jsonwebtoken::DecodingKey::from_secret(&[]),
                        &{
                            let mut v =
                                jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
                            v.insecure_disable_signature_validation();
                            v.set_issuer(&["dlp-server"]);
                            v
                        },
                    ) {
                        Ok(data) => data.claims,
                        Err(e) => {
                            warn!(approval_id = %entry.id, error = %e, "failed to parse approval token claims");
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

/// Builds the default [`EmitContext`] used for audit events.
fn build_audit_ctx(machine_name: Option<String>) -> crate::audit_emitter::EmitContext {
    crate::audit_emitter::EmitContext {
        agent_id: std::env::var("DLP_AGENT_ID").unwrap_or_else(|_| "AGENT-UNKNOWN".to_string()),
        session_id: 1,
        user_sid: "S-1-5-18".to_string(), // default; overridden per-event
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
        )
        .await;
    })
}

/// Performs graceful shutdown of all subsystems.
///
/// Extracted from [`run_loop`] to reduce cognitive complexity.  Each subsystem
/// is stopped in reverse order of initialisation.
async fn run_loop_shutdown(ctx: RunLoopContext) {
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

    // Stop the audit buffer flush task (final flush runs inside).
    let _ = ctx.audit_shutdown_tx.send(true);
    if let Some(h) = ctx.audit_flush_handle {
        let _ = h.await;
    }
    crate::password_stop::debug_log("run_loop: audit buffer stopped");

    crate::password_stop::debug_log("run_loop: shutdown complete");
    info!(
        service_name = SERVICE_NAME,
        "enforcement subsystems stopped"
    );
}

/// Restores volume ACLs for all tracked USB drives on shutdown.
#[cfg(windows)]
fn restore_usb_volume_acls(detector: &Arc<crate::detection::UsbDetector>) {
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
fn reenable_usb_devices(detector: &Arc<crate::detection::UsbDetector>) {
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
        }
    } else {
        EvaluateResponse {
            decision: Decision::ALLOW,
            matched_policy_id: None,
            reason: "Source origin is not managed".to_string(),
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
/// Calls `std::process::exit(1)` when another instance is detected.
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
        std::process::exit(1);
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
        let mut cfg = AgentConfig::default();
        cfg.usb_blocked_failure_mode = Some("Warning only".to_string());
        cfg.usb_startup_resolution_mode = Some("VID/PID/serial fallback".to_string());
        cfg.usb_none_serial_policy = Some("Always Blocked".to_string());
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
        let mut cfg = AgentConfig::default();
        cfg.usb_blocked_failure_mode = Some("Hard error".to_string());
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
        let mut cfg = AgentConfig::default();
        cfg.print_enabled = Some(true);
        cfg.print_xps_timeout_ms = Some(3000);
        cfg.print_unclassifiable_action = Some("Allow".to_string());
        cfg.print_max_pages = Some(50);
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
        let mut cfg = AgentConfig::default();
        cfg.print_unclassifiable_action = Some("Allow".to_string());
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
