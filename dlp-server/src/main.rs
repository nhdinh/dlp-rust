//! `dlp-server` entry point.
//!
//! Initialises tracing, opens the SQLite database, builds the HTTP
//! router, and serves with graceful shutdown on CTRL+C.
//!
//! ## Usage
//!
//! ```text
//! dlp-server.exe [OPTIONS]
//!
//! OPTIONS:
//!   --bind <host:port>    Listen address (default: 127.0.0.1:9090)
//!   --db <path>           SQLite database path (default: ./dlp-server.db)
//!   --log-level <level>   Log level: trace, debug, info, warn, error
//!                         (default: info, overridden by RUST_LOG env var)
//!   --help                Show this help message
//! ```
//!
//! Environment variables override defaults but CLI flags take priority:
//!
//! | Env var       | CLI flag        | Default              |
//! |---------------|-----------------|----------------------|
//! | `BIND_ADDR`   | `--bind`        | `127.0.0.1:9090`     |
//! | `DB_PATH`     | `--db`          | `./dlp-server.db`    |
//! | `RUST_LOG`    | `--log-level`   | `info`               |

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

use dlp_server::admin_api;
use dlp_server::agent_registry;
use dlp_server::db::Database;

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
}

/// Parses CLI flags and environment variables into a [`Config`].
///
/// Priority: CLI flag > env var > compiled default.
fn parse_config() -> Config {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help(
            args.first()
                .map(|s| s.as_str())
                .unwrap_or("dlp-server"),
        );
        std::process::exit(0);
    }

    Config {
        bind_addr: get_flag(&args, "--bind")
            .or_else(|| std::env::var("BIND_ADDR").ok())
            .unwrap_or_else(|| DEFAULT_BIND.to_string()),
        db_path: get_flag(&args, "--db")
            .or_else(|| std::env::var("DB_PATH").ok())
            .unwrap_or_else(|| DEFAULT_DB.to_string()),
        log_level: get_flag(&args, "--log-level")
            .unwrap_or_else(|| DEFAULT_LOG_LEVEL.to_string()),
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
    --bind <host:port>    Listen address (default: {DEFAULT_BIND})
    --db <path>           SQLite database path (default: {DEFAULT_DB})
    --log-level <level>   Log level: trace, debug, info, warn, error
                          (default: {DEFAULT_LOG_LEVEL})
    --help                Show this help message

ENVIRONMENT VARIABLES (CLI flags take priority):
    BIND_ADDR             Listen address
    DB_PATH               SQLite database path
    RUST_LOG              Tracing filter (overrides --log-level)

EXAMPLES:
    {name}
    {name} --bind 0.0.0.0:9090 --db /data/dlp.db
    {name} --log-level debug
"#
    );
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = parse_config();

    // Initialise structured logging.
    // RUST_LOG env var takes priority over --log-level flag.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.log_level));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    // Validate bind address.
    let addr: SocketAddr = config.bind_addr.parse().with_context(
        || format!("invalid bind address: '{}'", config.bind_addr),
    )?;

    // Open (or create) the SQLite database.
    let db = Arc::new(Database::open(&config.db_path)?);
    info!(path = %config.db_path, "database opened");

    // Start the background heartbeat sweeper (marks agents offline
    // after 90 seconds of silence).
    agent_registry::spawn_offline_sweeper(Arc::clone(&db));

    // Build the HTTP router.
    let app = admin_api::admin_router(Arc::clone(&db));

    // Bind and serve.
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "dlp-server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("dlp-server shut down");
    Ok(())
}

/// Waits for a CTRL+C signal to initiate graceful shutdown.
async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C handler");
    info!("shutdown signal received");
}
