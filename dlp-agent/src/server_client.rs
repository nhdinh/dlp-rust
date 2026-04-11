//! Client for dlp-server -- sends audit events and heartbeats.
//!
//! This module provides a best-effort relay to the central dlp-server.
//! All operations are non-blocking: errors are logged via `tracing` but
//! never propagate to the caller. The local JSONL audit log remains the
//! primary audit path; server relay is supplementary.
//!
//! ## Buffered Audit Relay
//!
//! [`AuditBuffer`] collects events and flushes them to the server every
//! 1 second or 100 events (whichever comes first). This amortises HTTP
//! overhead while keeping latency bounded.
//!
//! ## Environment Variables
//!
//! - `DLP_SERVER_URL` -- base URL of dlp-server (default: `http://127.0.0.1:9090`)
//! - `DLP_AGENT_ID` -- unique agent identifier (default: machine hostname)

use std::sync::Arc;
use std::time::Duration;

use dlp_common::AuditEvent;
use parking_lot::Mutex;
use thiserror::Error;
use tracing::{debug, info, warn};

/// Default base URL when `DLP_SERVER_URL` is not set.
const DEFAULT_SERVER_URL: &str = "http://127.0.0.1:9090";

/// Maximum number of events to buffer before flushing.
const FLUSH_THRESHOLD: usize = 100;

/// Maximum time between flushes.
const FLUSH_INTERVAL: Duration = Duration::from_secs(1);

/// HTTP request timeout for individual server calls.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur when communicating with dlp-server.
///
/// These are informational only -- callers log them but never propagate
/// them upward. The agent must continue operating even if the server is
/// unreachable.
#[derive(Debug, Error)]
pub enum ServerClientError {
    /// The HTTP request failed (network error, timeout, etc.).
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization failed.
    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),

    /// The server returned a non-success status code.
    #[error("server returned {status}: {body}")]
    ServerError {
        /// HTTP status code returned by the server.
        status: u16,
        /// Response body (truncated for logging).
        body: String,
    },

    /// Environment configuration error.
    #[error("configuration error: {0}")]
    Config(String),
}

// ---------------------------------------------------------------------------
// ServerClient
// ---------------------------------------------------------------------------

/// HTTP client for communicating with dlp-server.
///
/// Handles agent registration, heartbeats, and audit event relay.
/// All methods are best-effort: errors are returned for the caller to
/// log but should never block agent operation.
#[derive(Debug, Clone)]
pub struct ServerClient {
    /// The underlying HTTP client (connection-pooled).
    client: reqwest::Client,
    /// Base URL of the dlp-server (e.g., `http://127.0.0.1:9090`).
    base_url: String,
    /// Unique identifier for this agent instance.
    agent_id: String,
    /// Machine hostname, included in registration payloads.
    hostname: String,
}

impl ServerClient {
    /// Normalises a server URL by prepending `http://` if the scheme is absent.
    ///
    /// Handles bare hostnames that users write in `agent-config.toml`:
    /// `127.0.0.1:9090` → `http://127.0.0.1:9090`.
    ///
    /// `Manage-DlpAgentService.ps1` writes `server_url = '127.0.0.1:9090'`
    /// without a scheme because it looks cleaner in TOML.  The agent must
    /// accept both forms gracefully rather than silently failing.
    fn normalize_url(url: &str) -> String {
        if url.starts_with("http://") || url.starts_with("https://") {
            url.to_string()
        } else {
            format!("http://{url}")
        }
    }

    /// Creates a new `ServerClient` from an optional config URL,
    /// environment variables, or the compiled default.
    ///
    /// Resolution order for the server URL:
    /// 1. `config_url` parameter (from `agent-config.toml`).
    /// 2. `DLP_SERVER_URL` environment variable.
    /// 3. Compiled default: `http://127.0.0.1:9090`.
    ///
    /// # Arguments
    ///
    /// * `config_url` -- optional URL from the agent config file.
    ///
    /// # Errors
    ///
    /// Returns `ServerClientError::Config` if the hostname cannot be resolved
    /// and no `DLP_AGENT_ID` is set.
    pub fn from_env_with_config(config_url: Option<&str>) -> Result<Self, ServerClientError> {
        let base_url = Self::normalize_url(
            &config_url
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .or_else(|| std::env::var("DLP_SERVER_URL").ok())
                .unwrap_or_else(|| DEFAULT_SERVER_URL.to_string()),
        );

        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "unknown-host".to_string());

        let agent_id = std::env::var("DLP_AGENT_ID").unwrap_or_else(|_| hostname.clone());

        // Build a client with a reasonable timeout so we never block
        // the agent for too long on a slow/dead server.
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(ServerClientError::Http)?;

        info!(
            base_url = %base_url,
            agent_id = %agent_id,
            "ServerClient configured"
        );

        Ok(Self {
            client,
            base_url,
            agent_id,
            hostname,
        })
    }

    /// Creates a new `ServerClient` from environment variables only.
    ///
    /// Equivalent to `from_env_with_config(None)`.
    pub fn from_env() -> Result<Self, ServerClientError> {
        Self::from_env_with_config(None)
    }

    /// Returns the agent ID used by this client.
    #[must_use]
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// Registers this agent with the dlp-server.
    ///
    /// Should be called once during agent startup. If the server is
    /// unreachable the error is returned for the caller to log.
    ///
    /// # Errors
    ///
    /// Returns `ServerClientError::Http` on network failures.
    /// Returns `ServerClientError::ServerError` on non-2xx responses.
    pub async fn register(&self) -> Result<(), ServerClientError> {
        let url = format!("{}/agents/register", self.base_url);

        let os_version = os_version_string();
        let agent_version = env!("CARGO_PKG_VERSION").to_string();

        // The IP field is best-effort; the server can also read the
        // source IP from the TCP connection.
        let payload = serde_json::json!({
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "ip": "0.0.0.0",
            "os_version": os_version,
            "agent_version": agent_version,
        });

        let resp = self.client.post(&url).json(&payload).send().await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp
                .text()
                .await
                .unwrap_or_else(|_| "<no body>".to_string());
            return Err(ServerClientError::ServerError { status, body });
        }

        info!(agent_id = %self.agent_id, "registered with dlp-server");
        Ok(())
    }

    /// Sends a heartbeat to the dlp-server.
    ///
    /// Called periodically (every 30 s) from the heartbeat loop.
    ///
    /// # Errors
    ///
    /// Returns `ServerClientError::Http` on network failures.
    /// Returns `ServerClientError::ServerError` on non-2xx responses.
    pub async fn send_heartbeat(&self) -> Result<(), ServerClientError> {
        let url = format!("{}/agents/{}/heartbeat", self.base_url, self.agent_id);

        let payload = serde_json::json!({
            "status": "healthy",
        });

        let resp = self.client.post(&url).json(&payload).send().await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp
                .text()
                .await
                .unwrap_or_else(|_| "<no body>".to_string());
            return Err(ServerClientError::ServerError { status, body });
        }

        debug!(agent_id = %self.agent_id, "heartbeat sent");
        Ok(())
    }

    /// Fetches the agent auth hash from the dlp-server.
    ///
    /// Calls `GET /agent-credentials/auth-hash` and returns the bcrypt
    /// hash string. Returns an error if the server is unreachable or no
    /// hash has been stored.
    ///
    /// # Errors
    ///
    /// Returns `ServerClientError::Http` on network failures.
    /// Returns `ServerClientError::ServerError` on non-2xx responses (including 404).
    pub async fn fetch_auth_hash(&self) -> Result<String, ServerClientError> {
        let url = format!("{}/agent-credentials/auth-hash", self.base_url);

        let resp = self.client.get(&url).send().await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp
                .text()
                .await
                .unwrap_or_else(|_| "<no body>".to_string());
            return Err(ServerClientError::ServerError { status, body });
        }

        #[derive(serde::Deserialize)]
        struct HashResponse {
            hash: String,
        }
        let body: HashResponse = resp.json().await?;
        debug!("fetched auth hash from server");
        Ok(body.hash)
    }

    /// Sends a batch of audit events to the dlp-server.
    ///
    /// # Arguments
    ///
    /// * `events` -- slice of audit events to send
    ///
    /// # Errors
    ///
    /// Returns `ServerClientError::Http` on network failures.
    /// Returns `ServerClientError::ServerError` on non-2xx responses.
    pub async fn send_audit_events(&self, events: &[AuditEvent]) -> Result<(), ServerClientError> {
        if events.is_empty() {
            return Ok(());
        }

        let url = format!("{}/audit/events", self.base_url);

        let resp = self.client.post(&url).json(events).send().await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp
                .text()
                .await
                .unwrap_or_else(|_| "<no body>".to_string());
            return Err(ServerClientError::ServerError { status, body });
        }

        debug!(count = events.len(), "audit events relayed to server");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// AuditBuffer -- batches events for periodic flush
// ---------------------------------------------------------------------------

/// Buffers audit events and flushes them to the server periodically.
///
/// Events are collected into an internal `Vec` and flushed when either
/// [`FLUSH_THRESHOLD`] events have accumulated or [`FLUSH_INTERVAL`]
/// has elapsed since the last flush.
///
/// The buffer is designed to be shared via `Arc<AuditBuffer>` across
/// the agent. The background flush task is started by [`AuditBuffer::spawn_flush_task`].
pub struct AuditBuffer {
    /// Buffered events awaiting flush.
    buffer: Mutex<Vec<AuditEvent>>,
    /// The server client used for flushing.
    client: ServerClient,
}

impl AuditBuffer {
    /// Creates a new buffer backed by the given server client.
    ///
    /// # Arguments
    ///
    /// * `client` -- the `ServerClient` to use for flushing
    #[must_use]
    pub fn new(client: ServerClient) -> Self {
        Self {
            buffer: Mutex::new(Vec::with_capacity(FLUSH_THRESHOLD)),
            client,
        }
    }

    /// Enqueues an audit event for relay to the server.
    ///
    /// This call is non-blocking. If the buffer reaches
    /// [`FLUSH_THRESHOLD`], the events are not flushed inline -- the
    /// background task handles periodic draining.
    pub fn enqueue(&self, event: AuditEvent) {
        let mut buf = self.buffer.lock();
        buf.push(event);
    }

    /// Drains the buffer and sends all pending events to the server.
    ///
    /// Called periodically by the background flush task. Errors are
    /// logged but never propagated.
    async fn flush(&self) {
        // Take all buffered events under the lock, then release the
        // lock before doing async I/O.
        let events: Vec<AuditEvent> = {
            let mut buf = self.buffer.lock();
            if buf.is_empty() {
                return;
            }
            std::mem::take(&mut *buf)
        };

        let count = events.len();
        if let Err(e) = self.client.send_audit_events(&events).await {
            // Log the error but do not re-enqueue -- the local JSONL
            // file is the authoritative audit trail. Server relay is
            // best-effort.
            warn!(
                count,
                error = %e,
                "failed to relay audit events to server -- events dropped"
            );
        } else {
            debug!(count, "audit buffer flushed to server");
        }
    }

    /// Spawns a background tokio task that flushes the buffer at
    /// [`FLUSH_INTERVAL`] intervals.
    ///
    /// The task runs until the provided `shutdown` receiver signals.
    ///
    /// # Arguments
    ///
    /// * `self_arc` -- `Arc<AuditBuffer>` to share with the task
    /// * `shutdown` -- watch channel that signals shutdown
    pub fn spawn_flush_task(
        self_arc: Arc<Self>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(FLUSH_INTERVAL);

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        self_arc.flush().await;
                    }
                    _ = shutdown.changed() => {
                        // Final flush before exiting.
                        self_arc.flush().await;
                        debug!("audit buffer flush task shutting down");
                        return;
                    }
                }
            }
        })
    }
}

// In `Debug` for `AuditBuffer` we avoid locking the mutex (which
// could deadlock if called from a panic handler).
impl std::fmt::Debug for AuditBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditBuffer")
            .field("client", &self.client)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns a human-readable OS version string.
///
/// On Windows this returns the OS caption from `ver`; on other
/// platforms (tests) it returns a placeholder.
fn os_version_string() -> String {
    #[cfg(windows)]
    {
        // Best-effort: fall back to a generic string if the API fails.
        std::env::var("OS").unwrap_or_else(|_| "Windows".to_string())
    }
    #[cfg(not(windows))]
    {
        "non-windows (test)".to_string()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use dlp_common::{Action, Classification, Decision, EventType};

    fn make_event() -> AuditEvent {
        AuditEvent::new(
            EventType::Access,
            "S-1-5-21-123".to_string(),
            "jsmith".to_string(),
            r"C:\Data\report.xlsx".to_string(),
            Classification::T2,
            Action::WRITE,
            Decision::ALLOW,
            "AGENT-TEST".to_string(),
            1,
        )
    }

    // NOTE: `from_env` reads process-wide env vars, which cannot be safely
    // mutated across parallel test threads. We test the defaults path only
    // (which does not require setting env vars) and test the custom-URL
    // path via direct construction.

    #[test]
    fn test_from_env_defaults() {
        // This test only verifies that `from_env` succeeds when the env
        // vars are absent. It does NOT clear them (unsafe in parallel tests).
        // If DLP_SERVER_URL happens to be set in the test environment, the
        // assertion still passes because we only check non-emptiness.
        let client = ServerClient::from_env().expect("from_env should succeed");
        assert!(!client.base_url.is_empty());
        assert!(!client.agent_id.is_empty());
    }

    #[test]
    fn test_default_server_url_constant() {
        assert_eq!(DEFAULT_SERVER_URL, "http://127.0.0.1:9090");
    }

    #[test]
    fn test_normalize_url() {
        // Bare hostname (common in agent-config.toml) gets http:// prepended.
        assert_eq!(
            ServerClient::normalize_url("127.0.0.1:9090"),
            "http://127.0.0.1:9090"
        );
        assert_eq!(
            ServerClient::normalize_url("localhost:8080"),
            "http://localhost:8080"
        );
        assert_eq!(
            ServerClient::normalize_url("dlp-server.corp.internal:9090"),
            "http://dlp-server.corp.internal:9090"
        );
        // Already has scheme — unchanged.
        assert_eq!(
            ServerClient::normalize_url("http://127.0.0.1:9090"),
            "http://127.0.0.1:9090"
        );
        assert_eq!(
            ServerClient::normalize_url("https://dlp-server.corp:9443"),
            "https://dlp-server.corp:9443"
        );
    }

    #[test]
    fn test_audit_buffer_enqueue() {
        let client = ServerClient::from_env().expect("from_env should succeed");
        let buffer = AuditBuffer::new(client);

        buffer.enqueue(make_event());
        buffer.enqueue(make_event());

        let buf = buffer.buffer.lock();
        assert_eq!(buf.len(), 2);
    }

    #[test]
    fn test_audit_buffer_debug() {
        let client = ServerClient::from_env().expect("from_env should succeed");
        let buffer = AuditBuffer::new(client);
        // Should not panic.
        let debug_str = format!("{buffer:?}");
        assert!(debug_str.contains("AuditBuffer"));
    }

    #[tokio::test]
    async fn test_flush_empty_buffer_is_noop() {
        let client = ServerClient::from_env().expect("from_env should succeed");
        let buffer = AuditBuffer::new(client);
        // Should not panic or send any HTTP request.
        buffer.flush().await;
    }

    #[tokio::test]
    async fn test_send_audit_events_empty_slice() {
        let client = ServerClient::from_env().expect("from_env should succeed");
        // Empty slice should return Ok immediately without HTTP call.
        let result = client.send_audit_events(&[]).await;
        assert!(result.is_ok());
    }

    /// Helper to construct a `ServerClient` pointing at a black-hole address
    /// (TEST-NET-1, RFC 5737) so HTTP calls fail fast without touching env vars.
    fn unreachable_client() -> ServerClient {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .expect("reqwest client");
        ServerClient {
            client,
            base_url: "http://192.0.2.1:1".to_string(),
            agent_id: "AGENT-TEST".to_string(),
            hostname: "test-host".to_string(),
        }
    }

    #[tokio::test]
    async fn test_register_unreachable_server() {
        let client = unreachable_client();
        let result = client.register().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_heartbeat_unreachable_server() {
        let client = unreachable_client();
        let result = client.send_heartbeat().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_fetch_auth_hash_unreachable_server() {
        let client = unreachable_client();
        let result = client.fetch_auth_hash().await;
        assert!(result.is_err());
    }
}
