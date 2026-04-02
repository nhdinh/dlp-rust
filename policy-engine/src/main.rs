//! Standalone Policy Engine binary.
//!
//! Starts the ABAC policy evaluation server with all endpoints:
//! - `POST /evaluate` — policy evaluation
//! - `GET/POST/PUT/DELETE /policies` — policy CRUD
//! - `GET /health`, `GET /ready` — probes
//!
//! ## Configuration (environment variables)
//!
//! | Variable      | Default                  | Description              |
//! |---------------|--------------------------|--------------------------|
//! | `BIND_ADDR`   | `127.0.0.1:8443`         | Listen address           |
//! | `POLICY_FILE` | `./policies.json`        | Path to policy JSON file |
//! | `RUST_LOG`    | `info`                   | Log level filter         |
//!
//! ## Usage
//!
//! ```cmd
//! cargo run -p policy-engine
//! # or with custom config:
//! BIND_ADDR=0.0.0.0:9000 POLICY_FILE=/etc/dlp/policies.json cargo run -p policy-engine
//! ```

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use tracing::info;

use policy_engine::engine::AbacEngine;
use policy_engine::http_server;
use policy_engine::policy_store::PolicyStore;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let addr: SocketAddr = std::env::var("BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8443".into())
        .parse()
        .context("invalid BIND_ADDR")?;

    let policy_path =
        PathBuf::from(std::env::var("POLICY_FILE").unwrap_or_else(|_| "./policies.json".into()));

    let engine = Arc::new(AbacEngine::new());
    let store =
        Arc::new(PolicyStore::open(policy_path, engine).context("failed to open policy store")?);

    // Start the filesystem watcher so policy file changes are hot-reloaded
    // without restarting the server (F-SVC-04).
    store.start_hot_reload();

    let app = http_server::build_full_router(store);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .context("failed to bind")?;

    info!(%addr, "policy engine listening");
    axum::serve(listener, app).await.context("server error")?;

    Ok(())
}
