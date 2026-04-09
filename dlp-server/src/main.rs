//! `dlp-server` entry point.
//!
//! Initializes tracing, opens the SQLite database, builds the HTTP
//! router, and serves with graceful shutdown on CTRL+C.

use std::sync::Arc;

use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use dlp_server::admin_api;
use dlp_server::agent_registry;
use dlp_server::db::Database;

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
    let bind_addr = std::env::var("BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:9090".to_string());
    let db_path = std::env::var("DB_PATH")
        .unwrap_or_else(|_| "./dlp-server.db".to_string());

    // Open (or create) the SQLite database.
    let db = Arc::new(Database::open(&db_path)?);
    tracing::info!(path = %db_path, "database opened");

    // Start the background heartbeat sweeper.
    agent_registry::spawn_offline_sweeper(Arc::clone(&db));

    // Build the HTTP router.
    let app = admin_api::admin_router(Arc::clone(&db));

    // Bind and serve.
    let listener = TcpListener::bind(&bind_addr).await?;
    tracing::info!(addr = %bind_addr, "dlp-server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

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
