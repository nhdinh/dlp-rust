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

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
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

/// Global SCM status handle — set once after `register()` returns.
///
/// The control handler callback cannot capture the status handle (chicken-and-egg:
/// the handler is passed to `register`, which returns the handle).  This global
/// bridges the gap so the handler can report state transitions (e.g. `StopPending`)
/// directly to the SCM instead of only updating the internal `SERVICE_STATE` mutex.
static SCM_HANDLE: std::sync::OnceLock<ServiceStatusHandle> = std::sync::OnceLock::new();

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
    let _instance_mutex = acquire_instance_mutex()
        .context("failed to acquire single-instance mutex")?;
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
type DiskMergeData = Option<(std::collections::HashSet<String>, Vec<dlp_common::DiskIdentity>)>;

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

        // Re-arm the timer using the PREVIOUS interval, not the new one.
        // The new interval takes effect after the *next* tick completes.
        interval = tokio::time::interval(Duration::from_secs(next_interval));
        interval.tick().await; // consume immediate first tick
    }
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
    // Construct from pushed LDAP config embedded in agent_config (set by config poll loop).
    // Stored in Arc<Option<AdClient>> so all interception threads share the same client.
    let ad_client: Arc<Option<dlp_common::AdClient>> =
        if let Some(ref ldap_config) = agent_config.ldap_config {
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
        } else {
            tracing::debug!("No LDAP config in agent config — AD features disabled");
            Arc::new(None)
        };

    // ── dlp-server client (best-effort -- server may not be running) ─────
    let server_client = match crate::server_client::ServerClient::from_env_with_config(
        agent_config.server_url.as_deref(),
    ) {
        Ok(sc) => {
            // Register with dlp-server. Errors are logged, not fatal.
            if let Err(e) = sc.register().await {
                warn!(error = %e, "dlp-server registration failed (best-effort)");
            }
            Some(sc)
        }
        Err(e) => {
            warn!(error = %e, "dlp-server client init failed -- server relay disabled");
            None
        }
    };

    // ── Store server client for on-demand auth hash fetching ─────────────
    if let Some(ref sc) = server_client {
        crate::password_stop::set_server_client(sc.clone());
        crate::password_stop::sync_auth_hash_from_server(sc).await;
    }

    // ── Audit buffer for server relay ────────────────────────────────────
    let (audit_shutdown_tx, audit_shutdown_rx) = tokio::sync::watch::channel(false);
    let _audit_flush_handle = if let Some(ref sc) = server_client {
        let buffer = Arc::new(crate::server_client::AuditBuffer::new(sc.clone()));
        crate::audit_emitter::set_audit_buffer(Arc::clone(&buffer));
        Some(crate::server_client::AuditBuffer::spawn_flush_task(
            buffer,
            audit_shutdown_rx,
        ))
    } else {
        drop(audit_shutdown_rx);
        None
    };

    // ── Start USB mass-storage detection (inside run_loop for tokio Handle access) ──
    // USB registration is done here (not in run_service) so that usb_wndproc can
    // schedule async device-registry refreshes via a stored tokio::runtime::Handle.
    // The Handle is captured now (we are inside rt.block_on) and stored in a static
    // so the USB message-loop thread can reach it without capturing environment.
    // (Approach A from 24-03-PLAN.md)
    use std::sync::OnceLock;
    static USB_DETECTOR: OnceLock<Arc<crate::detection::UsbDetector>> = OnceLock::new();
    // Store an Arc in the OnceLock so UsbEnforcer (Phase 26) can hold a shared
    // reference without cloning a non-Clone type.
    let detector_arc = USB_DETECTOR.get_or_init(|| Arc::new(crate::detection::UsbDetector::new()));
    // Obtain a plain reference for the existing scan_existing_drives() and
    // register_usb_notifications() call sites (both accept &UsbDetector).
    let detector = detector_arc.as_ref();
    detector.scan_existing_drives();

    // ── Managed origins cache (D-02) ──────────────────────────────
    let origins_cache = Arc::new(crate::chrome::cache::ManagedOriginsCache::new());
    // Set the global cache so the chrome pipe handler can read from it.
    crate::chrome::handler::set_origins_cache(Arc::clone(&origins_cache));
    let (origins_shutdown_tx, origins_shutdown_rx) = tokio::sync::watch::channel(false);
    let _origins_poll_handle = if let Some(ref sc) = server_client {
        Some(crate::chrome::cache::ManagedOriginsCache::spawn_poll_task(
            Arc::clone(&origins_cache),
            sc.clone(),
            origins_shutdown_rx,
        ))
    } else {
        drop(origins_shutdown_rx);
        None
    };

    // ── Device registry cache (D-07, D-08) ──────────────────────────────────
    // Polls GET /admin/device-registry every 30 s. Phase 26 enforcement reads
    // from this cache at I/O time without a server call.
    let registry_cache = Arc::new(crate::device_registry::DeviceRegistryCache::new());
    let (registry_shutdown_tx, registry_shutdown_rx) = tokio::sync::watch::channel(false);
    let _registry_poll_handle = if let Some(ref sc) = server_client {
        // Store the cache and client in statics so usb_wndproc can trigger an
        // immediate refresh on DBT_DEVICEARRIVAL (D-09).
        crate::detection::usb::set_registry_cache(Arc::clone(&registry_cache));
        crate::detection::usb::set_registry_client(sc.clone());
        // Store the current tokio Handle so the USB message-loop thread (a plain
        // std::thread that does NOT inherit the tokio context) can spawn async tasks.
        crate::detection::usb::set_registry_runtime_handle(tokio::runtime::Handle::current());
        Some(
            crate::device_registry::DeviceRegistryCache::spawn_poll_task(
                Arc::clone(&registry_cache),
                sc.clone(),
                registry_shutdown_rx,
            ),
        )
    } else {
        drop(registry_shutdown_rx);
        None
    };

    // ── DeviceController (Phase 31) ───────────────────────────────────────
    // Active PnP enforcement: disables devices (Blocked tier) and modifies
    // volume DACLs (ReadOnly tier). Set in the static before USB notifications
    // are registered so usb_wndproc has access on first arrival.
    let device_controller = Arc::new(crate::device_controller::DeviceController::new());
    crate::detection::usb::set_device_controller(Arc::clone(&device_controller));

    // ── UsbEnforcer (D-12) ────────────────────────────────────────────────
    // Constructed after registry_cache so both backing caches are ready.
    // Always constructed (registry_cache exists even without a server_client).
    let usb_enforcer_opt: Option<Arc<crate::usb_enforcer::UsbEnforcer>> =
        Some(Arc::new(crate::usb_enforcer::UsbEnforcer::new(
            Arc::clone(detector_arc),
            Arc::clone(&registry_cache),
        )));

    // Set the global DRIVE_DETECTOR reference before spawning the watcher so
    // dispatch callbacks can reach the UsbDetector on first arrival.
    // The device watcher itself is spawned below (after audit_ctx is constructed).
    crate::detection::usb::set_drive_detector(detector);

    // ── Clone server client for config poll BEFORE it moves into offline_manager ──
    // server_client is an Option<ServerClient>. ServerClient is Clone.
    let server_client_for_config = server_client.clone();

    let mut offline_manager =
        crate::offline::OfflineManager::new(engine_client, cache, machine_name.clone());
    if let Some(sc) = server_client {
        offline_manager = offline_manager.with_server_client(sc);
    }
    let offline = Arc::new(offline_manager);

    // ── Wrap agent_config in Arc<Mutex<>> for shared access ──────────────
    // The config poll loop needs a shared mutable reference to apply server-pushed
    // updates. InterceptionEngine gets a clone of the config at construction time
    // (paths are fixed; live path hot-reload is out of scope for this phase).
    let config_arc = Arc::new(parking_lot::Mutex::new(agent_config.clone()));

    // ── Phase 35: Arc<RwLock<AgentConfig>> for disk allowlist persistence ──
    // The disk enumeration task (D-04) needs a write-capable shared reference
    // to AgentConfig so it can update `disk_allowlist` after merge and call
    // `save(config_path)`. RwLock is used (not Mutex) because future Phase
    // 36/37 readers may need concurrent read access to the allowlist.
    //
    // CRITICAL: must be constructed BEFORE `InterceptionEngine::with_config`
    // moves `agent_config` (Pitfall 2). The window is between this point and
    // the `with_config(agent_config)` call below.
    let disk_config_arc = Arc::new(parking_lot::RwLock::new(agent_config.clone()));
    let config_path = std::path::PathBuf::from(crate::config::AgentConfig::effective_config_path());

    // ── Start the Policy Engine heartbeat ─────────────────────────────────
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let offline_hb = offline.clone();
    let _heartbeat_handle = tokio::spawn(async move {
        offline_hb.heartbeat_loop(shutdown_rx).await;
    });

    // ── Start the Pipe 1 heartbeat ────────────────────────────────────────
    let (pipe1_shutdown_tx, mut pipe1_shutdown_rx) = tokio::sync::watch::channel(false);
    let _pipe1_hb_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    crate::ipc::pipe1::send_ping_to_all();
                }
                _ = pipe1_shutdown_rx.changed() => {
                    debug!("Pipe 1 heartbeat shutting down");
                    return;
                }
            }
        }
    });

    // ── Start the config poll loop ─────────────────────────────────────────
    let (config_shutdown_tx, config_shutdown_rx) = tokio::sync::watch::channel(false);
    let _config_poll_handle = if let Some(sc) = server_client_for_config {
        let config_for_poll = Arc::clone(&config_arc);
        Some(tokio::spawn(async move {
            config_poll_loop(sc, config_for_poll, config_shutdown_rx).await;
        }))
    } else {
        drop(config_shutdown_rx);
        None
    };

    // ── Start the file system monitor pipeline ─────────────────────────
    // Capture the recheck interval before agent_config is consumed by with_config below.
    // Per CRYPT-02, the cadence must come exclusively from admin config — no hard-coded value.
    let recheck_interval = agent_config.resolved_recheck_interval();
    let file_monitor = crate::interception::InterceptionEngine::with_config(agent_config)
        .expect("file monitor initialisation always succeeds");
    let file_monitor_for_shutdown = file_monitor.clone();

    let (action_tx, action_rx) = mpsc::channel::<crate::interception::FileAction>(1024);

    // Channel for dynamically adding USB drive roots to the file watcher after
    // startup. The sender is stored in a global so usb_wndproc can push new
    // drive roots from the USB notification thread without holding a reference
    // to the InterceptionEngine.
    let (watch_tx, watch_rx) = std::sync::mpsc::channel::<std::path::PathBuf>();
    crate::detection::usb::set_watch_path_sender(watch_tx);

    // Per-session identity map — resolves actual interactive users for
    // file events instead of attributing everything to SYSTEM.
    let session_map = Arc::new(crate::session_identity::SessionIdentityMap::new());
    crate::session_identity::init_global(session_map.clone());

    // Populate with any sessions that are already active.
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

    let audit_ctx = crate::audit_emitter::EmitContext {
        agent_id: std::env::var("DLP_AGENT_ID").unwrap_or_else(|_| "AGENT-UNKNOWN".to_string()),
        session_id: 1,
        user_sid: "S-1-5-18".to_string(), // default; overridden per-event
        user_name: "SYSTEM".to_string(),
        machine_name: machine_name.clone(),
    };

    // Initialise the clipboard listener's audit emit context.
    crate::clipboard::listener::init_emit_context(audit_ctx.clone());

    // ── Disk Enumeration (Phase 33) ───────────────────────────────────────
    // Initialize the DiskEnumerator and spawn the background enumeration task.
    // This runs after USB setup so both detectors are available for Phase 36.
    let disk_enumerator = Arc::new(crate::detection::DiskEnumerator::new());
    crate::detection::disk::set_disk_enumerator(Arc::clone(&disk_enumerator));
    crate::detection::disk::spawn_disk_enumeration_task(
        tokio::runtime::Handle::current(),
        audit_ctx.clone(),
        Arc::clone(&disk_config_arc),
        config_path.clone(),
    );
    info!("disk enumeration task spawned");

    // ── Device watcher (Phase 36 D-12) ───────────────────────────────────
    // Spawned after audit_ctx and disk enumeration are ready so the watcher
    // can emit DiskDiscovery events from the disk arrival handler.
    // Replaces the old `register_usb_notifications` Win32 window.
    let device_watcher_cleanup =
        match crate::detection::spawn_device_watcher_task(audit_ctx.clone()) {
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
        };

    // ── DiskEnforcer (Phase 36) ───────────────────────────────────────────
    // Constructed after disk enumeration so the global OnceLock is populated.
    // Fails closed (blocks all fixed-disk writes) until the enumeration task
    // sets `is_ready()` (D-06).
    let disk_enforcer_opt: Option<Arc<crate::disk_enforcer::DiskEnforcer>> =
        Some(Arc::new(crate::disk_enforcer::DiskEnforcer::new()));
    info!("disk enforcer constructed");

    // ── BitLocker Encryption Verification (Phase 34) ──────────────────────
    // Initialize the EncryptionChecker and spawn the background verification
    // task. The task waits internally for `DiskEnumerator::is_ready` (D-04)
    // before scanning, then re-checks every `recheck_interval` (D-10, D-11).
    // Per CRYPT-02, the cadence comes exclusively from admin config — there
    // is no hard-coded value. Per D-16, an Alert is emitted only on the
    // initial total-failure outcome; subsequent periodic-poll failures yield
    // `Unknown` silently.
    let encryption_checker = Arc::new(crate::detection::encryption::EncryptionChecker::new());
    crate::detection::encryption::set_encryption_checker(Arc::clone(&encryption_checker));
    crate::detection::encryption::spawn_encryption_check_task(
        tokio::runtime::Handle::current(),
        audit_ctx.clone(),
        recheck_interval,
    );
    info!(
        recheck_interval_secs = recheck_interval.as_secs(),
        "encryption verification task spawned"
    );

    let offline_ev = offline.clone();
    let ctx_ev = audit_ctx.clone();
    let session_map_ev = session_map.clone();
    let ad_client_ev = ad_client.clone();
    let event_loop_handle = tokio::spawn(async move {
        crate::interception::run_event_loop(
            action_rx,
            offline_ev,
            ctx_ev,
            session_map_ev,
            ad_client_ev,
            usb_enforcer_opt,
            disk_enforcer_opt,
        )
        .await;
    });

    // Spawn the file monitor — run() is blocking and must run on a dedicated thread
    // because the notify watcher blocks on its internal channel.  Wrap it in
    // spawn_blocking so it doesn't monopolise a Tokio thread.
    let file_monitor_clone = file_monitor.clone();
    let file_handle = tokio::task::spawn_blocking(move || {
        // file_monitor.run() is synchronous; it blocks until stop() is called.
        let _ = file_monitor_clone.run(action_tx, Some(watch_rx));
    });

    info!(
        service_name = SERVICE_NAME,
        "enforcement subsystems started"
    );

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

    // ── Graceful shutdown ──────────────────────────────────────────────────
    crate::password_stop::debug_log("run_loop: starting graceful shutdown");
    info!(
        service_name = SERVICE_NAME,
        "shutting down enforcement subsystems"
    );

    // Stop the file monitor first so no new events arrive.
    crate::password_stop::debug_log("run_loop: stopping file monitor");
    file_monitor_for_shutdown.stop();
    let _ = file_handle.await;
    crate::password_stop::debug_log("run_loop: file monitor stopped");

    // Signal the event loop to drain and exit.
    drop(event_loop_handle);
    crate::password_stop::debug_log("run_loop: event loop dropped");

    // Stop the heartbeat loop.
    let _ = shutdown_tx.send(true);
    let _ = _heartbeat_handle.await;
    crate::password_stop::debug_log("run_loop: heartbeat stopped");

    // Stop the Pipe 1 heartbeat.
    let _ = pipe1_shutdown_tx.send(true);
    let _ = _pipe1_hb_handle.await;
    crate::password_stop::debug_log("run_loop: Pipe 1 heartbeat stopped");

    // Stop the config poll loop.
    let _ = config_shutdown_tx.send(true);
    if let Some(h) = _config_poll_handle {
        let _ = h.await;
    }
    crate::password_stop::debug_log("run_loop: config poll stopped");

    // Stop the device registry poll task.
    let _ = registry_shutdown_tx.send(true);
    if let Some(h) = _registry_poll_handle {
        let _ = h.await;
    }
    crate::password_stop::debug_log("run_loop: device registry poll stopped");

    // Stop the managed origins poll task.
    let _ = origins_shutdown_tx.send(true);
    if let Some(h) = _origins_poll_handle {
        let _ = h.await;
    }
    crate::password_stop::debug_log("run_loop: managed origins poll stopped");

    // Unregister device watcher (Phase 36 D-12 replacement for register_usb_notifications).
    if let Some((hwnd, thread)) = device_watcher_cleanup {
        crate::password_stop::debug_log("run_loop: unregistering device watcher");
        crate::detection::unregister_device_watcher(hwnd, thread);
        crate::password_stop::debug_log("run_loop: device watcher unregistered");
    }

    // Kill all UI processes spawned by the session monitor.  Must happen before
    // the process exits so users are not left with orphaned dlp-user-ui windows.
    crate::password_stop::debug_log("run_loop: killing UI processes");
    crate::ui_spawner::kill_all();
    crate::password_stop::debug_log("run_loop: UI processes killed");

    // Stop the audit buffer flush task (final flush runs inside).
    let _ = audit_shutdown_tx.send(true);
    if let Some(h) = _audit_flush_handle {
        let _ = h.await;
    }
    crate::password_stop::debug_log("run_loop: audit buffer stopped");

    crate::password_stop::debug_log("run_loop: shutdown complete");
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
    use windows::Win32::Foundation::{GetLastError, WIN32_ERROR};
    use windows::Win32::System::Threading::CreateMutexW;
    use windows::core::PCWSTR;

    // Null-terminated UTF-16 name in the Global kernel namespace.
    let name: Vec<u16> = "Global\\DlpAgentSingleInstance\0"
        .encode_utf16()
        .collect();

    // SAFETY: `name` is a valid null-terminated UTF-16 string; the handle is
    // immediately checked and stored for the service lifetime.
    let handle = unsafe {
        CreateMutexW(
            None,  // default security — inheritable by child processes
            true,  // bInitialOwner: this instance claims ownership immediately
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
    info!(service_name = SERVICE_NAME, "single-instance check skipped (non-Windows)");
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
        let (old_ids, new_list) = disk_merge_data
            .expect("disk_merge_data must be Some when disk_allowlist changed");
        assert!(old_ids.is_empty(), "old_ids must be empty on first-time apply");
        assert_eq!(new_list.len(), 2);

        // Apply the merge into a real DiskEnumerator.
        let enumerator = DiskEnumerator::new();
        merge_disk_allowlist_into_map(&enumerator, &old_ids, &new_list);

        // Both disks must be in instance_id_map.
        let map = enumerator.instance_id_map.read();
        assert!(map.contains_key("DISK\\INSTANCE\\A"), "disk A must be in map");
        assert!(map.contains_key("DISK\\INSTANCE\\B"), "disk B must be in map");
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
            reloaded.disk_allowlist[0].instance_id,
            "DISK\\PERSIST\\001",
            "persisted instance_id must survive TOML roundtrip"
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
