//! Full-stack integration test: agent TOML write-back verification.
//!
//! Spawns an in-process dlp-server router, seeds global agent config via the
//! admin API, spawns the real dlp-agent binary in console mode, and asserts
//! the agent writes the exact config back to its TOML file within 5 seconds.
//!
//! This test automates the deferred Phase 6 UAT item for agent TOML write-back.
//!
//! ## Test environment
//!
//! - Server: in-process axum router on ephemeral port (avoids binary locking)
//! - Agent: spawned via `cargo run --bin dlp-agent -- --console`
//! - Config: temp directory (no admin rights required)
//! - Poll interval: `heartbeat_interval_secs = 1` for fast test completion

use std::path::Path;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use dlp_agent::config::AgentConfig;
use dlp_e2e::helpers::server::{build_test_app, mint_jwt, TEST_JWT_SECRET};
use serde_json::json;
use tokio::net::TcpListener;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Spawns the dlp-agent binary in console mode pointing at the given config
/// path and server URL.
///
/// Uses `CARGO_TARGET_DIR=target-test` to avoid locking the debug binary.
/// Stdout and stderr are redirected to null to keep test output clean.
///
/// # Arguments
///
/// * `config_path` - Path to the agent's TOML config file.
/// * `server_url` - Full base URL of the dlp-server (e.g. `http://127.0.0.1:12345`).
///
/// # Panics
///
/// Panics if the agent binary cannot be spawned.
fn spawn_agent(config_path: &Path, server_url: &str) -> std::process::Child {
    Command::new("cargo")
        .args(["run", "--bin", "dlp-agent", "--", "--console"])
        .env("DLP_CONFIG_PATH", config_path)
        .env("DLP_SERVER_URL", server_url)
        .env("CARGO_TARGET_DIR", "target-test")
        .env("DLP_JWT_SECRET", TEST_JWT_SECRET)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn dlp-agent binary")
}

/// Polls the temp config TOML file until it exists and parses successfully,
/// or until the timeout expires.
///
/// # Arguments
///
/// * `config_path` - Path to the agent's TOML config file.
/// * `timeout` - Maximum duration to wait.
///
/// # Returns
///
/// `Some(AgentConfig)` if the file was successfully loaded before timeout,
/// `None` otherwise.
fn poll_config_file(config_path: &Path, timeout: Duration) -> Option<AgentConfig> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if config_path.exists() {
            let config = AgentConfig::load(config_path);
            // Only return if the config has been populated (not just defaults).
            // We check heartbeat_interval_secs because it's always set by the server.
            if config.heartbeat_interval_secs.is_some() {
                return Some(config);
            }
        }
        sleep(Duration::from_millis(500));
    }
    None
}

/// Seeds the global agent config via the admin API.
///
/// Sends a `PUT /admin/agent-config` request with the given payload and
/// asserts a 200 OK response.
///
/// # Arguments
///
/// * `port` - The port the in-process server is listening on.
/// * `payload` - JSON payload for the agent config update.
///
/// # Panics
///
/// Panics if the request fails or the server returns a non-2xx status.
fn seed_global_agent_config(port: u16, payload: serde_json::Value) {
    let client = reqwest::blocking::Client::new();
    let token = mint_jwt();
    let resp = client
        .put(format!("http://127.0.0.1:{port}/admin/agent-config"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&payload)
        .send()
        .expect("send admin config request");

    assert!(
        resp.status().is_success(),
        "seed config failed: {} — {}",
        resp.status(),
        resp.text().unwrap_or_default()
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Full round-trip test: seed config via admin API, wait for agent to poll
/// and write back to TOML, assert exact values.
///
/// 1. Creates a temp directory for the agent config and server DB.
/// 2. Spawns an in-process axum server on an ephemeral port.
/// 3. Seeds global agent config with specific values (including fast poll).
/// 4. Spawns the dlp-agent binary in console mode.
/// 5. Polls the temp config TOML file for up to 5 seconds.
/// 6. Asserts all seeded values are present in the written TOML.
/// 7. Kills the agent process and cleans up temp files.
#[test]
#[cfg(windows)]
fn test_agent_toml_writeback_roundtrip() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("agent-config.toml");

    // Build the in-process server router and bind to an ephemeral port.
    let rt = tokio::runtime::Runtime::new().expect("create tokio runtime");
    let (router, _pool) = build_test_app();

    let listener = rt
        .block_on(async { TcpListener::bind("127.0.0.1:0").await })
        .expect("bind tcp listener");
    let port = listener.local_addr().expect("get local addr").port();

    // Spawn the server in a background task.
    let server_handle = rt.spawn(async move {
        axum::serve(listener, router).await.expect("serve axum");
    });

    // Seed global agent config with fast-poll interval.
    let payload = json!({
        "monitored_paths": [r"C:\Data\"],
        "excluded_paths": [r"C:\Temp\"],
        "heartbeat_interval_secs": 10,
        "offline_cache_enabled": true
    });
    seed_global_agent_config(port, payload);

    // Spawn the agent binary pointing at our temp config and server.
    let server_url = format!("http://127.0.0.1:{port}");
    let mut agent = spawn_agent(&config_path, &server_url);

    // Poll for the TOML file to be written and populated.
    let config = poll_config_file(&config_path, Duration::from_secs(15))
        .expect("agent should write config TOML within timeout");

    // Assert exact seeded values.
    assert_eq!(
        config.monitored_paths,
        vec![r"C:\Data\"],
        "monitored_paths mismatch"
    );
    assert_eq!(
        config.excluded_paths,
        vec![r"C:\Temp\"],
        "excluded_paths mismatch"
    );
    assert_eq!(
        config.heartbeat_interval_secs,
        Some(10),
        "heartbeat_interval_secs mismatch"
    );
    assert_eq!(
        config.offline_cache_enabled,
        Some(true),
        "offline_cache_enabled mismatch"
    );

    // Cleanup: kill agent, abort server task, drop temp dir.
    let _ = agent.kill();
    let _ = agent.wait();
    server_handle.abort();
    drop(temp_dir);
}

/// Empty-paths variant: seed monitored_paths = [], excluded_paths = [],
/// assert the agent TOML loads with empty vectors.
///
/// This verifies the agent correctly handles the "default to all drives"
/// configuration path.
#[test]
#[cfg(windows)]
fn test_agent_toml_writeback_empty_paths() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("agent-config.toml");

    let rt = tokio::runtime::Runtime::new().expect("create tokio runtime");
    let (router, _pool) = build_test_app();

    let listener = rt
        .block_on(async { TcpListener::bind("127.0.0.1:0").await })
        .expect("bind tcp listener");
    let port = listener.local_addr().expect("get local addr").port();

    let server_handle = rt.spawn(async move {
        axum::serve(listener, router).await.expect("serve axum");
    });

    let payload = json!({
        "monitored_paths": [],
        "excluded_paths": [],
        "heartbeat_interval_secs": 10,
        "offline_cache_enabled": false
    });
    seed_global_agent_config(port, payload);

    let server_url = format!("http://127.0.0.1:{port}");
    let mut agent = spawn_agent(&config_path, &server_url);

    let config = poll_config_file(&config_path, Duration::from_secs(15))
        .expect("agent should write config TOML within timeout");

    assert!(
        config.monitored_paths.is_empty(),
        "monitored_paths should be empty"
    );
    assert!(
        config.excluded_paths.is_empty(),
        "excluded_paths should be empty"
    );
    assert_eq!(
        config.heartbeat_interval_secs,
        Some(10),
        "heartbeat_interval_secs mismatch"
    );
    assert_eq!(
        config.offline_cache_enabled,
        Some(false),
        "offline_cache_enabled mismatch"
    );

    // Cleanup.
    let _ = agent.kill();
    let _ = agent.wait();
    server_handle.abort();
    drop(temp_dir);
}
