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

use dlp_server::admin_api;
use dlp_server::admin_auth;
use dlp_server::agent_registry;
use dlp_server::alert_router::AlertRouter;
use dlp_server::db::Database;
use dlp_server::siem_connector::SiemConnector;
use dlp_server::AppState;

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

    // Resolve and store the JWT secret (must happen before serving requests).
    let jwt_secret = admin_auth::resolve_jwt_secret(config.dev_mode).map_err(|msg| {
        eprintln!("Error: {msg}");
        anyhow::anyhow!("{msg}")
    })?;
    admin_auth::set_jwt_secret(jwt_secret);

    // Validate bind address.
    let addr: SocketAddr = config
        .bind_addr
        .parse()
        .with_context(|| format!("invalid bind address: '{}'", config.bind_addr))?;

    // Open (or create) the SQLite database.
    let db = Arc::new(Database::open(&config.db_path)?);
    info!(path = %config.db_path, "database opened");

    // Provision the admin user on first run.
    ensure_admin_user(&db, config.init_admin_password.as_deref())?;

    // Initialise the SIEM relay connector. Configuration is loaded on
    // every relay call from the `siem_config` table (hot-reload).
    let siem = SiemConnector::new(Arc::clone(&db));

    // Initialise the alert router. Configuration is loaded on every
    // send_alert call from the `alert_router_config` table (hot-reload).
    let alert = AlertRouter::new(Arc::clone(&db));

    // Build shared application state.
    let state = Arc::new(AppState { db, siem, alert });

    // Start the background heartbeat sweeper (marks agents offline
    // after 90 seconds of silence).
    agent_registry::spawn_offline_sweeper(Arc::clone(&state));

    // Build the HTTP router.
    let app = admin_api::admin_router(Arc::clone(&state));

    // Bind and serve.
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "dlp-server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("dlp-server shut down");
    Ok(())
}

/// Ensures at least one admin user exists in the database.
///
/// - If `init_password` is provided (`--init-admin`), creates the `dlp-admin`
///   user non-interactively (for installer / scripted setup).
/// - Otherwise, prompts interactively for the password on the terminal.
/// - If an admin user already exists, this is a no-op.
fn ensure_admin_user(db: &Database, init_password: Option<&str>) -> anyhow::Result<()> {
    if admin_auth::has_admin_users(db)? {
        return Ok(());
    }

    info!("no admin user found — initial setup required");

    let password = match init_password {
        Some(pw) => pw.to_string(),
        None => prompt_admin_password()?,
    };

    admin_auth::create_admin_user(db, "dlp-admin", &password)?;
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
