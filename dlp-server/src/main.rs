//! `dlp-server` entry point.
//!
//! Initializes tracing, opens the SQLite database, loads the ABAC
//! policy engine (with hot-reload), builds the HTTP router, registers
//! the bind address in the Windows registry, and serves with graceful
//! shutdown on CTRL+C.
//!
//! ## Configuration (environment variables)
//!
//! | Variable      | Default                  | Description              |
//! |---------------|--------------------------|--------------------------|
//! | `BIND_ADDR`   | `127.0.0.1:9090`         | Listen address           |
//! | `DB_PATH`     | `./dlp-server.db`        | SQLite database file     |
//! | `POLICY_FILE` | `./policies.json`        | Path to policy JSON file |
//! | `RUST_LOG`    | `info`                   | Log level filter         |

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use dlp_server::admin_api;
use dlp_server::agent_registry;
use dlp_server::bind_registry;
use dlp_server::db::Database;
use dlp_server::engine::AbacEngine;
use dlp_server::policy_api;
use dlp_server::policy_store::PolicyStore;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize structured logging (respects RUST_LOG env var).
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Read configuration from environment.
    let bind_addr: SocketAddr = std::env::var("BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:9090".to_string())
        .parse()
        .context("invalid BIND_ADDR")?;

    let db_path = std::env::var("DB_PATH")
        .unwrap_or_else(|_| "./dlp-server.db".to_string());

    let policy_path = PathBuf::from(
        std::env::var("POLICY_FILE")
            .unwrap_or_else(|_| "./policies.json".into()),
    );

    // Open (or create) the SQLite database.
    let db = Arc::new(Database::open(&db_path)?);
    tracing::info!(path = %db_path, "database opened");

    // Initialize the ABAC engine and policy store.
    let engine = Arc::new(AbacEngine::new());
    let store = Arc::new(
        PolicyStore::open(policy_path, engine)
            .context("failed to open policy store")?,
    );

    // Start the filesystem watcher so policy file changes are
    // hot-reloaded without restarting the server.
    store.start_hot_reload();

    // Start the background heartbeat sweeper.
    agent_registry::spawn_offline_sweeper(Arc::clone(&db));

    // Build the combined HTTP router: admin API (SQLite-backed) +
    // policy engine API (JSON file-backed). The admin API's old
    // SQLite-based policy CRUD routes are replaced by the policy
    // engine's JSON-based routes.
    let admin_routes = admin_api::admin_router(Arc::clone(&db));
    let policy_routes = policy_api::router(Arc::clone(&store));

    let app = admin_routes
        .merge(policy_routes)
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive());

    // Bind and serve.
    let listener = TcpListener::bind(bind_addr)
        .await
        .context("failed to bind")?;

    // Register the bind address in the Windows registry so
    // dlp-admin-cli can auto-detect the server on the same machine.
    bind_registry::register(&bind_addr);

    tracing::info!(addr = %bind_addr, "dlp-server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;

    // Clear the registry entry so stale addresses are never left
    // behind.
    bind_registry::unregister();

    tracing::info!("dlp-server shut down");
    Ok(())
}

/// Waits for a CTRL+C signal to initiate graceful shutdown.
async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C handler");
    tracing::info!("shutdown signal received");
}
