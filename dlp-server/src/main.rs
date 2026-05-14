//! `dlp-server` entry point.
//!
//! Initialises tracing, opens the SQLite database, provisions the
//! initial admin user if needed, builds the HTTP router, and serves
//! with graceful shutdown on CTRL+C.
//!
//! ## Usage
//!
//! ```text
//! dlp-server.exe [OPTIONS]
//!
//! OPTIONS:
//!   --bind <host:port>           Listen address (default: 127.0.0.1:9090)
//!   --db <path>                  SQLite database path (default: ./dlp-server.db)
//!   --log-level <level>          Log level: trace, debug, info, warn, error
//!                                (default: info)
//!   --init-admin <password>      Create the dlp-admin user non-interactively
//!                                (for installer / scripted setup)
//!   --help                       Show this help message
//! ```

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

use dlp_common::ad_client::{AdClient, LdapConfig};
use dlp_server::admin_api;
use dlp_server::admin_auth;
use dlp_server::agent_registry;
use dlp_server::alert_router::AlertRouter;
use dlp_server::crypto::SecretCrypto;
use dlp_server::db;
use dlp_server::db::repositories::LdapConfigRepository;
use dlp_server::policy_store::PolicyStore;
use dlp_server::secrets_migration;
use dlp_server::siem_connector::SiemConnector;
use dlp_server::db::repositories::SyslogQueueRepository;
use dlp_server::label_service::LabelService;
use dlp_server::observability;
use dlp_server::AppState;
use secrecy::ExposeSecret;

/// Loads the LDAP configuration from the SQLite database via `LdapConfigRepository`.
///
/// Returns `None` if the config cannot be read (DB not yet initialized or row missing).
fn load_ldap_config(pool: &db::Pool) -> Option<LdapConfig> {
    let row = LdapConfigRepository::get(pool).ok()?;
    Some(LdapConfig {
        ldap_url: row.ldap_url,
        base_dn: row.base_dn,
        require_tls: row.require_tls,
        cache_ttl_secs: row.cache_ttl_secs,
        vpn_subnets: row.vpn_subnets,
    })
}

/// Default bind address.
const DEFAULT_BIND: &str = "127.0.0.1:9090";
/// Default SQLite database path.
const DEFAULT_DB: &str = "./dlp-server.db";
/// Default log level.
const DEFAULT_LOG_LEVEL: &str = "info";

/// Parsed command-line configuration.
struct Config {
    bind_addr: String,
    db_path: String,
    log_level: String,
    /// Non-interactive admin password (from `--init-admin`).
    /// When set, the admin user is created without prompting.
    init_admin_password: Option<String>,
    /// Development mode — allows insecure JWT secret fallback.
    dev_mode: bool,
}

/// Parses CLI flags into a [`Config`].
///
/// Falls back to compiled defaults when a flag is not provided.
fn parse_config() -> Config {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help(args.first().map(|s| s.as_str()).unwrap_or("dlp-server"));
        std::process::exit(0);
    }

    Config {
        bind_addr: get_flag(&args, "--bind").unwrap_or_else(|| DEFAULT_BIND.to_string()),
        db_path: get_flag(&args, "--db").unwrap_or_else(|| DEFAULT_DB.to_string()),
        log_level: get_flag(&args, "--log-level").unwrap_or_else(|| DEFAULT_LOG_LEVEL.to_string()),
        init_admin_password: get_flag(&args, "--init-admin"),
        dev_mode: args.iter().any(|a| a == "--dev"),
    }
}

/// Extracts the value following `flag` in the argument list.
fn get_flag(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn print_help(name: &str) {
    eprintln!(
        r#"dlp-server -- DLP central management server

USAGE:
    {name} [OPTIONS]

OPTIONS:
    --bind <host:port>           Listen address (default: {DEFAULT_BIND})
    --db <path>                  SQLite database path (default: {DEFAULT_DB})
    --log-level <level>          Log level: trace, debug, info, warn, error
                                 (default: {DEFAULT_LOG_LEVEL})
    --init-admin <password>      Create dlp-admin user non-interactively
                                 (for installer / scripted setup)
    --dev                        Development mode — allow insecure JWT
                                 secret fallback (do NOT use in production)
    --help                       Show this help message

FIRST RUN:
    On first start, if no admin user exists in the database, the server
    will prompt interactively for the dlp-admin password. For scripted
    or installer-based setup, use --init-admin to skip the prompt.

EXAMPLES:
    {name}
    {name} --bind 0.0.0.0:9090 --db /data/dlp.db
    {name} --init-admin "my-secure-password"
    {name} --log-level debug
"#
    );
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = parse_config();

    // Initialise structured logging.
    let filter = EnvFilter::new(&config.log_level);
    tracing_subscriber::fmt().with_env_filter(filter).init();

    // Validate bind address.
    let addr: SocketAddr = config
        .bind_addr
        .parse()
        .with_context(|| format!("invalid bind address: '{}'", config.bind_addr))?;

    // Open (or create) the SQLite database pool. WAL + `secure_delete`
    // are enabled by `new_pool` (the latter is the Phase 47 Task 47-06
    // requirement that frees pages get zero-overwritten so any pre-
    // migration cleartext bytes on disk become unrecoverable post-
    // VACUUM).
    let pool = Arc::new(db::new_pool(&config.db_path)?);
    info!(path = %config.db_path, "database pool opened");

    // Phase 47 Task 47-06 bootstrap sequence:
    //
    //   (a) Bring up the active KEK. On a fresh DB this generates a
    //       v1 KEK with DPAPI-wrapped seed; on an existing DB this
    //       reads the highest active version. Failure here is
    //       fatal-by-design (CONTEXT D-Q4: DPAPI recovery deferred to
    //       Phase 52).
    //   (b) Run the one-shot atomic cleartext-to-encrypted migration.
    //       This is idempotent: on an already-migrated DB it is a
    //       no-op (the cleartext columns are absent so the
    //       `PRAGMA table_info` probe short-circuits). On a pre-
    //       Phase-47 DB it encrypts every populated cleartext row and
    //       drops the cleartext columns in the same transaction.
    //   (c) Migrate the JWT_SECRET env-var into `secrets_jwt` if and
    //       only if the encrypted row does not already exist.
    let crypto = Arc::new(SecretCrypto::load_active_or_bootstrap(&pool).map_err(|e| {
        eprintln!("Error: failed to bootstrap SecretCrypto: {e:?}");
        anyhow::anyhow!("SecretCrypto bootstrap failed: {e:?}")
    })?);
    let migration_report = secrets_migration::migrate_secrets_to_encrypted(
        &pool,
        &crypto,
        std::env::var("JWT_SECRET").ok().as_deref(),
    )?;
    info!(
        rows_encrypted = migration_report.rows_encrypted,
        jwt_migrated = migration_report.jwt_migrated_from_env,
        dropped = ?migration_report.cleartext_columns_dropped,
        "secrets migration complete"
    );

    // Resolve and store the JWT secret. Reads from the encrypted DB
    // row, falling back to env-var-bootstrap (already handled by the
    // migration above) or the dev secret (`--dev`).
    let jwt_secret =
        admin_auth::resolve_jwt_secret(&pool, &crypto, config.dev_mode).map_err(|msg| {
            eprintln!("Error: {msg}");
            anyhow::anyhow!("{msg}")
        })?;
    admin_auth::set_jwt_secret(jwt_secret.expose_secret().to_string());

    // Provision the admin user on first run.
    ensure_admin_user(&pool, config.init_admin_password.as_deref())?;

    // Initialise the SIEM relay connector. Configuration is loaded on
    // every relay call from the `siem_config` table (hot-reload). The
    // `crypto` handle decrypts the on-disk `splunk_token` /
    // `elk_api_key` envelopes on each load.
    let siem = SiemConnector::new(Arc::clone(&pool), Arc::clone(&crypto));

    // Initialise the alert router. Configuration is loaded on every
    // send_alert call from the `alert_router_config` table (hot-
    // reload). The `crypto` handle decrypts the on-disk
    // `smtp_password` / `webhook_secret` envelopes on each load.
    let alert = AlertRouter::new(Arc::clone(&pool), Arc::clone(&crypto));

    // Initialise the syslog forwarder (Phase 62).
    // Reads config from `syslog_config` on each forward call (hot-reload).
    let syslog = dlp_server::syslog_connector::SyslogConnector::new(
        Arc::clone(&pool),
        Arc::clone(&crypto),
    );

    // Attempt to construct the AD client from DB config.
    // Fail-open: server starts even if AD is unreachable.
    let ad_client = match load_ldap_config(&pool) {
        Some(config) => {
            tracing::info!(ldap_url = %config.ldap_url, base_dn = %config.base_dn, "initializing AD client");
            match AdClient::new(config).await {
                Ok(client) => Some(client),
                Err(e) => {
                    tracing::warn!(error = %e, "AD client initialization failed — AD features disabled");
                    None
                }
            }
        }
        None => None,
    };

    // Load all policies into the in-memory cache.
    // Fails the server startup if the DB is corrupt or unreachable.
    let policy_store = Arc::new(PolicyStore::new(Arc::clone(&pool)).map_err(|e| {
        eprintln!("Error: failed to load policies: {e}");
        anyhow::anyhow!("policy store initialization failed: {e}")
    })?);
    info!(
        count = policy_store.list_policies().len(),
        "policy store loaded"
    );

    // Initialise the label resolution service.
    let label_service = Arc::new(LabelService::new(Arc::clone(&pool)));
    info!("label service initialized");

    // Initialise the approval token service (Phase 61).
    // This loads or generates the Ed25519 keypair using Phase 47 encrypted storage.
    let approval_token_service = {
        let conn = pool.get().map_err(|e| {
            anyhow::anyhow!("failed to acquire connection for approval token service: {e}")
        })?;
        Arc::new(dlp_server::approval_token::ApprovalTokenService::new(
            &crypto,
            &conn,
        )?)
    };
    info!("approval token service initialized");

    // Build shared application state.
    let state = Arc::new(AppState {
        pool: Arc::clone(&pool),
        crypto: Arc::clone(&crypto),
        policy_store,
        siem,
        alert,
        ad: ad_client,
        label_service,
        approval_token_service,
        syslog: syslog.clone(),
    });

    // Start the background heartbeat sweeper (marks agents offline
    // after 90 seconds of silence).
    agent_registry::spawn_offline_sweeper(Arc::clone(&state));

    // Background task: reload the policy cache every 5 minutes.
    // Refresh failures are logged but do not crash the server — stale cache is used
    // until the next interval.
    let refresh_store = Arc::clone(&state.policy_store);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(
            dlp_server::policy_store::POLICY_REFRESH_INTERVAL_SECS,
        ));
        loop {
            interval.tick().await;
            refresh_store.refresh();
        }
    });

    // Spawn background syslog queue drain loop (Phase 62, SYSLOG-02).
    // Periodically reads from the encrypted queue and forwards via
    // SyslogConnector with peek-confirm-delete semantics.
    let drain_syslog = syslog.clone();
    let drain_pool = Arc::clone(&pool);
    let drain_crypto = Arc::clone(&crypto);
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);

    let drain_handle = tokio::spawn(async move {
        let interval_secs = std::env::var("SYSLOG_DRAIN_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30u64);
        let mut interval = tokio::time::interval(
            std::time::Duration::from_secs(interval_secs),
        );
        interval.set_missed_tick_behavior(
            tokio::time::MissedTickBehavior::Skip,
        );

        let mut consecutive_failures: u32 = 0;

        loop {
            tokio::select! {
                _ = interval.tick() => {},
                _ = shutdown_rx.recv() => {
                    tracing::info!("syslog drain loop shutting down gracefully");
                    break;
                }
            }

            // Check queue depth for observability.
            let depth = match tokio::task::spawn_blocking({
                let pool = Arc::clone(&drain_pool);
                move || SyslogQueueRepository::count(&pool)
            }).await {
                Ok(Ok(c)) => c as u64,
                _ => 0,
            };
            observability::record_syslog_queue_depth(depth);

            if depth == 0 {
                consecutive_failures = 0;
                continue;
            }

            // Check how many events are ready for retry.
            let ready_count = match tokio::task::spawn_blocking({
                let pool = Arc::clone(&drain_pool);
                move || SyslogQueueRepository::count_ready(&pool)
            }).await {
                Ok(Ok(c)) => c,
                _ => 0,
            };

            if ready_count == 0 {
                // Events exist but none are ready yet (backoff in effect).
                continue;
            }

            // Peek a batch (does NOT remove rows).
            let batch = match tokio::task::spawn_blocking({
                let pool = Arc::clone(&drain_pool);
                let crypto = Arc::clone(&drain_crypto);
                move || SyslogQueueRepository::peek_oldest(&pool, &crypto, 100)
            }).await {
                Ok(Ok(b)) => b,
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "syslog drain: failed to peek batch");
                    consecutive_failures += 1;
                    continue;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "syslog drain: join error peeking batch");
                    consecutive_failures += 1;
                    continue;
                }
            };

            if batch.is_empty() {
                consecutive_failures = 0;
                continue;
            }

            // Deserialize and forward.
            let events: Vec<dlp_common::AuditEvent> = match batch.iter()
                .map(|qe| serde_json::from_str::<dlp_common::AuditEvent>(&qe.event_json))
                .collect::<Result<Vec<_>, _>>() {
                Ok(e) => e,
                Err(e) => {
                    tracing::error!(error = %e, "syslog drain: failed to deserialize queued events");
                    // Corrupt events: mark as failed with a far-future retry.
                    for qe in &batch {
                        let _ = tokio::task::spawn_blocking({
                            let pool = Arc::clone(&drain_pool);
                            let id = qe.id;
                            move || -> Result<(), dlp_server::AppError> {
                                let mut conn = pool.get()?;
                                let uow = db::UnitOfWork::new(&mut conn)?;
                                SyslogQueueRepository::mark_failed(
                                    &uow, id, "deserialization error", "2099-01-01T00:00:00Z",
                                )?;
                                uow.commit()?;
                                Ok(())
                            }
                        }).await;
                    }
                    continue;
                }
            };

            let start = std::time::Instant::now();
            match drain_syslog.forward(&events).await {
                Ok(()) => {
                    // Confirm-delete: remove successfully forwarded events.
                    let ids: Vec<i64> = batch.iter().map(|qe| qe.id).collect();
                    if let Err(e) = tokio::task::spawn_blocking({
                        let pool = Arc::clone(&drain_pool);
                        move || {
                            let mut conn = pool.get()?;
                            let uow = db::UnitOfWork::new(&mut conn)?;
                            SyslogQueueRepository::delete(&uow, &ids)?;
                            uow.commit()?;
                            Ok::<_, dlp_server::AppError>(())
                        }
                    }).await {
                        tracing::warn!(error = %e, "syslog drain: failed to delete forwarded events");
                        // Events were forwarded but not deleted -- they'll be re-forwarded
                        // on next drain (at-least-once semantics). This is acceptable.
                    }
                    let latency_ms = start.elapsed().as_millis() as u64;
                    observability::record_syslog_send_latency(latency_ms);
                    tracing::info!(
                        count = events.len(),
                        latency_ms,
                        "syslog drain: forwarded queued events"
                    );
                    consecutive_failures = 0;
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        count = events.len(),
                        "syslog drain: forward failed"
                    );
                    observability::record_syslog_tls_error();
                    // Mark each event as failed with exponential backoff scheduling.
                    let next_attempt = compute_next_attempt(consecutive_failures);
                    for qe in &batch {
                        let _ = tokio::task::spawn_blocking({
                            let pool = Arc::clone(&drain_pool);
                            let id = qe.id;
                            let error = e.to_string();
                            let next = next_attempt.clone();
                            move || -> Result<(), dlp_server::AppError> {
                                let mut conn = pool.get()?;
                                let uow = db::UnitOfWork::new(&mut conn)?;
                                SyslogQueueRepository::mark_failed(&uow, id, &error, &next)?;
                                uow.commit()?;
                                Ok(())
                            }
                        }).await;
                        observability::record_syslog_retry(1);
                    }
                    consecutive_failures += 1;
                }
            }

            // Exponential backoff on failure.
            if consecutive_failures > 0 {
                let base = 1u64;
                let max = 60u64;
                let exp = std::cmp::min(consecutive_failures, 6);
                let delay = std::cmp::min(base * 2u64.pow(exp), max);
                // Deterministic jitter based on time (no rand dependency needed).
                let jitter = (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() % (delay as u128 * 500_000_000 + 1)) as u64;
                let backoff = std::time::Duration::from_secs(delay + jitter);
                tracing::info!(backoff_secs = backoff.as_secs(), "syslog drain: backing off");
                tokio::time::sleep(backoff).await;
            }
        }
    });

    // Build the HTTP router.
    let app = admin_api::admin_router(Arc::clone(&state));

    // Bind and serve.
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "dlp-server listening");

    // `into_make_service_with_connect_info` is required so that
    // `AgentIdOrIpKeyExtractor` can read the peer's socket address for IP-based
    // rate limiting on non-agent routes.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    // On shutdown signal, notify drain loop and wait for it to finish.
    let _ = shutdown_tx.send(());
    drain_handle.await.ok();

    info!("dlp-server shut down");
    Ok(())
}

/// Compute the next retry attempt timestamp based on consecutive failures.
///
/// Uses exponential backoff capped at 60 seconds with deterministic jitter.
fn compute_next_attempt(consecutive_failures: u32) -> String {
    let base = 1u64;
    let max = 60u64;
    let exp = std::cmp::min(consecutive_failures, 6);
    let delay = std::cmp::min(base * 2u64.pow(exp), max);
    let jitter = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() % (delay as u128 * 500_000_000 + 1)) as u64;
    let backoff = std::time::Duration::from_secs(delay + jitter);
    (chrono::Utc::now() + chrono::Duration::from_std(backoff).unwrap_or_default())
        .to_rfc3339()
}

/// Ensures at least one admin user exists in the database.
///
/// - If `init_password` is provided (`--init-admin`), creates the `dlp-admin`
///   user non-interactively (for installer / scripted setup).
/// - Otherwise, prompts interactively for the password on the terminal.
/// - If an admin user already exists, this is a no-op.
fn ensure_admin_user(pool: &db::Pool, init_password: Option<&str>) -> anyhow::Result<()> {
    if admin_auth::has_admin_users(pool)? {
        return Ok(());
    }

    info!("no admin user found — initial setup required");

    let password = match init_password {
        Some(pw) => pw.to_string(),
        None => prompt_admin_password()?,
    };

    admin_auth::create_admin_user(pool, "dlp-admin", &password)?;
    println!("Admin user 'dlp-admin' created successfully.");
    Ok(())
}

/// Interactively prompts for the initial admin password (with confirmation).
fn prompt_admin_password() -> anyhow::Result<String> {
    use std::io::Write;

    println!("\n--- First-run setup: create dlp-admin account ---\n");

    print!("New dlp-admin password: ");
    std::io::stdout().flush()?;
    let pw1 =
        rpassword::read_password().map_err(|e| anyhow::anyhow!("failed to read password: {e}"))?;
    if pw1.is_empty() {
        anyhow::bail!("password cannot be empty");
    }

    print!("Confirm dlp-admin password: ");
    std::io::stdout().flush()?;
    let pw2 =
        rpassword::read_password().map_err(|e| anyhow::anyhow!("failed to read password: {e}"))?;

    if pw1 != pw2 {
        anyhow::bail!("passwords do not match — aborting");
    }

    Ok(pw1)
}

/// Waits for a CTRL+C signal to initiate graceful shutdown.
async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C handler");
    info!("shutdown signal received");
}
