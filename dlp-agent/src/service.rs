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

    // Acquire single-instance mutex.
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

/// Periodically polls the server for updated agent config.
///
/// Runs on a separate timer independent of heartbeat. On each tick:
/// 1. Fetch resolved config from `GET /agent-config/{agent_id}`.
/// 2. Compare the three pushed fields against in-memory state.
/// 3. If changed: update in-memory, write to TOML, log field names only.
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
    // Helper closure: fetch, diff, and persist config. Returns the previous
    // interval (before the update), which is used to re-arm the timer.
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
                    let mut changed_fields: Vec<&str> = Vec::new();
                    {
                        let mut cfg = config.lock();

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
                            cfg.ldap_config = payload.ldap_config;
                        }
                        if cfg.excluded_paths != payload.excluded_paths {
                            changed_fields.push("excluded_paths");
                            cfg.excluded_paths = payload.excluded_paths;
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
                            if let Err(e) = cfg.save(config_path) {
                                tracing::error!(
                                    error = %e,
                                    "failed to write updated config to TOML"
                                );
                            }
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

    // ── UsbEnforcer (D-12) ────────────────────────────────────────────────
    // Constructed after registry_cache so both backing caches are ready.
    // Always constructed (registry_cache exists even without a server_client).
    let usb_enforcer_opt: Option<Arc<crate::usb_enforcer::UsbEnforcer>> =
        Some(Arc::new(crate::usb_enforcer::UsbEnforcer::new(
            Arc::clone(detector_arc),
            Arc::clone(&registry_cache),
        )));

    // Register USB notifications NOW (after statics are set) so usb_wndproc
    // has valid REGISTRY_CACHE / REGISTRY_CLIENT / REGISTRY_RUNTIME_HANDLE on first arrival.
    let usb_cleanup = match crate::detection::usb::register_usb_notifications(detector) {
        Ok((hwnd, thread)) => {
            info!(
                thread_id = ?thread.thread().id(),
                "USB notifications registered"
            );
            Some((hwnd, thread))
        }
        Err(e) => {
            warn!(
                error = %e,
                "USB detection unavailable — continuing without USB monitoring"
            );
            None
        }
    };

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

            // Ctrl+C from console session.
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

    // Unregister USB device notifications (owned by run_loop since Approach A move).
    if let Some((hwnd, thread)) = usb_cleanup {
        crate::password_stop::debug_log("run_loop: unregistering USB notifications");
        crate::detection::usb::unregister_usb_notifications(hwnd, thread);
        crate::password_stop::debug_log("run_loop: USB unregistered");
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

/// Acquires the global single-instance mutex — anonymous mutex prevents
/// a second agent instance from starting on the same machine.
fn acquire_instance_mutex() {
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
/// output.  In console mode, both the file and stderr outputs are active.
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
    //   2. Stderr layer — only useful in console/debug mode; silently
    //      discarded when running as a Windows Service (no attached console).
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
// Console / CLI mode
// ──────────────────────────────────────────────────────────────────────────────

/// Runs the DLP Agent as a regular console application for testing and
/// development.
///
/// Sets up the full interception pipeline (file monitor + Policy Engine + audit log)
/// without requiring Windows Service registration.  Press Ctrl+C to stop.
///
/// The UI spawner, IPC servers, health monitor, and file monitor pipeline
/// all run identically to the service mode.  The only differences are:
///   - No SCM integration (no password-protected stop, no service status)
///   - No UI is spawned (console sessions don't have an interactive desktop)
///   - File monitor runs with the console user's identity context
pub fn run_console() -> Result<()> {
    let log_level = crate::config::AgentConfig::load_default().resolved_log_level();
    init_logging(log_level);
    info!(
        service_name = SERVICE_NAME,
        "DLP Agent running in console mode (full pipeline)"
    );

    // Harden the agent process DACL — same hardening as service mode.
    crate::protection::harden_agent_process();

    // Register as Chrome Content Analysis agent in HKLM (best-effort).
    if let Err(e) = crate::chrome::registry::register_agent() {
        warn!(error = %e, "Chrome HKLM registration failed — continuing");
    }

    // ── Health monitor first (sets ROUTER state before Pipe 3 clients connect) ──
    let _health_handle = crate::health_monitor::start();
    info!(thread_id = ?_health_handle.thread().id(), "health monitor started");

    // ── IPC pipe servers (blocking threads) ───────────────────────────────────
    // Skip pipe creation when DLP_SKIP_IPC=1. Integration tests that spawn
    // the agent binary may have an older agent instance holding the pipe
    // server handles (named pipes are unique per name). Skipping IPC in tests
    // avoids the 5-second start_all() timeout from failing CreateNamedPipeW calls.
    if std::env::var("DLP_SKIP_IPC").is_ok_and(|v| v == "1") {
        info!("IPC pipe servers skipped (DLP_SKIP_IPC=1)");
    } else {
        crate::ipc::start_all()?;
        info!("IPC pipe servers started");
    }

    // ── Start Chrome Content Analysis pipe server ────────────────
    let chrome_handle = std::thread::Builder::new()
        .name("chrome-pipe".into())
        .spawn(|| {
            if let Err(e) = crate::chrome::handler::serve() {
                error!(error = %e, "Chrome pipe server exited with error");
            }
        })
        .context("failed to spawn Chrome pipe thread")?;
    info!(thread_id = ?chrome_handle.thread().id(), "Chrome pipe server started");

    // ── File system monitor + event loop on a Tokio runtime ─────────────────
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async_run_console())?;

    info!(service_name = SERVICE_NAME, "DLP Agent stopped by Ctrl+C");
    Ok(())
}

/// The async body of [`run_console`] — sets up and runs the interception pipeline.
async fn async_run_console() -> Result<()> {
    // ── Machine hostname (used in evaluation requests) ──────────────────────
    let machine_name = hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .ok();

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

    // ── Load agent config (needed for server_url before monitor setup) ───
    let agent_config = crate::config::AgentConfig::load_default();

    // ── AD client (best-effort — AD features disabled if config absent or init fails) ───
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
                    tracing::info!("AD client initialised from pushed config (console mode)");
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

    // ── dlp-server client (best-effort) ──────────────────────────────────
    let server_client = match crate::server_client::ServerClient::from_env_with_config(
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
    };

    // ── Store server client for on-demand auth hash fetching ─────────────
    if let Some(ref sc) = server_client {
        crate::password_stop::set_server_client(sc.clone());
        crate::password_stop::sync_auth_hash_from_server(sc).await;
    }

    // ── Clone server client for config poll BEFORE it moves into offline_manager ──
    // ServerClient is Clone; we need two independent owners: offline_manager and
    // the config poll loop.
    let server_client_for_config = server_client.clone();

    // ── Managed origins cache (console mode) ─────────────────────
    let origins_cache = Arc::new(crate::chrome::cache::ManagedOriginsCache::new());
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

    let mut offline_manager =
        crate::offline::OfflineManager::new(engine_client, cache, machine_name.clone());
    if let Some(sc) = server_client {
        offline_manager = offline_manager.with_server_client(sc);
    }
    let offline = Arc::new(offline_manager);

    // ── Wrap agent_config in Arc<Mutex<>> for shared access ──────────────
    // The config poll loop needs a shared mutable reference to apply
    // server-pushed updates. InterceptionEngine gets a clone of the config
    // at construction time (paths are fixed at startup).
    let config_arc = Arc::new(parking_lot::Mutex::new(agent_config.clone()));

    // ── Heartbeat ───────────────────────────────────────────────────────────
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

    // ── Start file system monitor pipeline ─────────────────────────────
    let file_monitor = crate::interception::InterceptionEngine::with_config(agent_config)
        .expect("file monitor must be constructable");
    let (action_tx, action_rx) = mpsc::channel::<crate::interception::FileAction>(1024);

    // Resolve the actual console user via process token (not a stub).
    let (console_sid, console_name) = crate::session_identity::resolve_console_user();

    let audit_ctx = crate::audit_emitter::EmitContext {
        agent_id: std::env::var("DLP_AGENT_ID").unwrap_or_else(|_| "AGENT-CONSOLE".to_string()),
        session_id: 1,
        user_sid: console_sid.clone(),
        user_name: console_name.clone(),
        machine_name: hostname::get()
            .map(|h| h.to_string_lossy().into_owned())
            .ok(),
    };
    crate::clipboard::listener::init_emit_context(audit_ctx.clone());

    // Console mode identity map — pre-populated with the current user.
    let session_map = Arc::new(crate::session_identity::SessionIdentityMap::new());
    crate::session_identity::init_global(session_map.clone());
    // Insert the console user directly (no WTSQueryUserToken needed).
    {
        use crate::session_identity::UserIdentity;
        session_map.sessions.write().insert(
            1,
            UserIdentity {
                sid: console_sid,
                name: console_name.clone(),
            },
        );
        session_map
            .username_to_session
            .write()
            .insert(console_name.to_lowercase(), 1);
    }

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
            // Console mode has no USB detector static — USB enforcement disabled.
            None,
        )
        .await;
    });

    // File monitor runs on a blocking thread so it doesn't starve the Tokio executor.
    let file_monitor_clone = file_monitor.clone();
    let file_handle = tokio::task::spawn_blocking(move || {
        if let Err(e) = file_monitor_clone.run(action_tx, None) {
            // Always log this error — it means the file monitor failed to start or crashed.
            // This is important enough to print to stderr directly as a fallback
            // in case tracing is misconfigured.
            eprintln!("[ERROR] file monitor failed: {e}");
            tracing::error!(error = %e, "file monitor failed");
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

    file_monitor.stop();
    let _ = file_handle.await;
    drop(event_loop_handle);
    let _ = shutdown_tx.send(true);
    let _ = _heartbeat_handle.await;

    // Stop the Pipe 1 heartbeat.
    let _ = pipe1_shutdown_tx.send(true);
    let _ = _pipe1_hb_handle.await;

    // Stop the config poll loop.
    let _ = config_shutdown_tx.send(true);
    if let Some(h) = _config_poll_handle {
        let _ = h.await;
    }

    // Stop the audit buffer flush task (final flush runs inside).
    let _ = audit_shutdown_tx.send(true);
    if let Some(h) = _audit_flush_handle {
        let _ = h.await;
    }

    // Stop the managed origins poll task.
    let _ = origins_shutdown_tx.send(true);
    if let Some(h) = _origins_poll_handle {
        let _ = h.await;
    }

    // Kill all UI processes so users are not left with orphaned dlp-user-ui windows.
    crate::ui_spawner::kill_all();

    info!(
        service_name = SERVICE_NAME,
        "enforcement subsystems stopped"
    );
    Ok(())
}
