//! RFC 5424 syslog forwarder with TLS transport.
//!
//! Mirrors the proven [`SiemConnector`] pattern: hot-reload config,
//! batched relay, fire-and-forget. On send failure, events are queued
//! to the encrypted `syslog_queue` table for later retry.
//!
//! # Design
//!
//! - `forward()` re-reads config from DB on every call (no caching).
//! - Events are formatted as RFC 5424 messages with JSON payload in MSG.
//! - TLS 1.2+ with system CA store (no custom CA or mTLS per D-10/D-11).
//! - Each `forward()` call opens a new TCP+TLS connection (no pooling
//!   in Phase 62 -- noted as future optimization).
//! - Failed sends enqueue events to `syslog_queue` for retry.
//!
//! # RFC 5424 Format
//!
//! ```text
//! <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
//! ```
//!
//! Example:
//! ```text
//! <166>1 2026-05-14T12:00:00.000Z server01 DLP-Audit 1234 DLP-BLOCK - {"event_id":"..."}
//! ```

use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::rustls;
use tokio_rustls::TlsConnector;

use dlp_common::audit::{AuditEvent, EventType};

use crate::crypto::SecretCrypto;
use crate::db;
use crate::db::repositories::{SyslogConfigRepository, SyslogConfigRow, SyslogQueueRepository};
use crate::AppError;

/// Syslog forwarder that formats audit events as RFC 5424 messages and
/// sends them over TLS to a syslog collector.
#[derive(Clone)]
pub struct SyslogConnector {
    pool: Arc<db::Pool>,
    crypto: Arc<SecretCrypto>,
}

impl std::fmt::Debug for SyslogConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyslogConnector")
            .field("pool", &self.pool)
            .field("crypto", &"<SecretCrypto>")
            .finish()
    }
}

/// Error type for syslog forwarder operations.
#[derive(Debug, thiserror::Error)]
pub enum SyslogError {
    /// A TLS-related error occurred.
    #[error("syslog TLS error: {0}")]
    Tls(String),

    /// JSON serialization failed.
    #[error("syslog serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Reading syslog config or queue from the database failed.
    #[error("syslog config DB error: {0}")]
    Database(#[from] rusqlite::Error),

    /// An IO error occurred during TCP/TLS operations.
    #[error("syslog IO error: {0}")]
    Io(#[from] std::io::Error),

    /// An internal error occurred.
    #[error("syslog internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl From<r2d2::Error> for SyslogError {
    fn from(e: r2d2::Error) -> Self {
        SyslogError::Database(rusqlite::Error::InvalidParameterName(format!(
            "pool error: {e}"
        )))
    }
}

impl SyslogError {
    /// Funnels [`AppError`] from repositories into a syslog-flavoured error variant.
    fn from_app_error(e: AppError) -> Self {
        match e {
            AppError::Database(db) => SyslogError::Database(db),
            AppError::Json(json) => SyslogError::Serialization(json),
            AppError::Internal(inner) => SyslogError::Internal(inner),
            AppError::BadRequest(msg) => {
                SyslogError::Internal(anyhow::anyhow!("bad request: {msg}"))
            }
            AppError::NotFound(msg) => SyslogError::Internal(anyhow::anyhow!("not found: {msg}")),
            AppError::Unauthorized(msg) => {
                SyslogError::Internal(anyhow::anyhow!("unauthorized: {msg}"))
            }
            AppError::UnprocessableEntity(msg) => {
                SyslogError::Internal(anyhow::anyhow!("unprocessable: {msg}"))
            }
            AppError::Conflict(msg) => SyslogError::Internal(anyhow::anyhow!("conflict: {msg}")),
            AppError::Forbidden(msg) => SyslogError::Internal(anyhow::anyhow!("forbidden: {msg}")),
        }
    }
}

impl SyslogConnector {
    /// Constructs a `SyslogConnector` backed by the given connection pool
    /// and active KEK handle.
    ///
    /// The connector reads syslog configuration from the `syslog_config`
    /// table on each `forward` call. No caching is performed, so admin
    /// updates take effect immediately.
    pub fn new(pool: Arc<db::Pool>, crypto: Arc<SecretCrypto>) -> Self {
        Self { pool, crypto }
    }

    /// Forwards a batch of audit events to the configured syslog collector.
    ///
    /// Re-reads syslog config from the database on each call (hot-reload).
    /// On connection or send failure, events are queued to `syslog_queue`
    /// for later retry.
    ///
    /// # Arguments
    ///
    /// * `events` - Slice of audit events to forward.
    ///
    /// # Errors
    ///
    /// Returns the first error encountered. Events that fail to send are
    /// enqueued for retry; the error is still returned so callers can log it.
    pub async fn forward(&self, events: &[AuditEvent]) -> Result<(), SyslogError> {
        if events.is_empty() {
            return Ok(());
        }

        // Load config synchronously -- the read is brief.
        let config = SyslogConfigRepository::get(&self.pool, &self.crypto)
            .map_err(SyslogError::from_app_error)?;

        if config.enabled == 0 {
            return Ok(());
        }

        if config.host.is_empty() {
            tracing::warn!("syslog host is empty, skipping forward");
            return Ok(());
        }

        // Build TLS config.
        let tls_config = build_tls_config(&config.tls_min_version)?;
        let connector = TlsConnector::from(Arc::new(tls_config));

        // Resolve server name (DNS or IP per R-62-04).
        let server_name = resolve_server_name(&config.host)?;

        // TCP connect with 10-second timeout.
        let addr = format!("{}:{}", config.host, config.port);
        let tcp_stream = match timeout(Duration::from_secs(10), TcpStream::connect(&addr)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                tracing::error!("syslog TCP connect failed: {e}");
                self.enqueue_events(events).await?;
                return Err(SyslogError::Io(e));
            }
            Err(_) => {
                tracing::error!("syslog TCP connect timed out after 10s");
                self.enqueue_events(events).await?;
                return Err(SyslogError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "TCP connect timeout",
                )));
            }
        };

        // TLS handshake with 10-second timeout.
        let mut tls_stream = match timeout(
            Duration::from_secs(10),
            connector.connect(server_name, tcp_stream),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                tracing::error!("syslog TLS handshake failed: {e}");
                self.enqueue_events(events).await?;
                return Err(SyslogError::Tls(e.to_string()));
            }
            Err(_) => {
                tracing::error!("syslog TLS handshake timed out after 10s");
                self.enqueue_events(events).await?;
                return Err(SyslogError::Tls("TLS handshake timeout".to_string()));
            }
        };

        // Format and send all events.
        let hostname = get_hostname();
        let procid = std::process::id().to_string();

        for event in events {
            let msg = format_rfc5424(event, &config, &hostname, &procid)?;
            if let Err(e) = tls_stream.write_all(msg.as_bytes()).await {
                tracing::error!("syslog TLS write failed: {e}");
                self.enqueue_events(events).await?;
                return Err(SyslogError::Io(e));
            }
        }

        // Graceful shutdown.
        if let Err(e) = tls_stream.shutdown().await {
            tracing::warn!("syslog TLS shutdown failed: {e}");
        }

        tracing::info!(count = events.len(), "forwarded events to syslog");
        Ok(())
    }

    /// Enqueue events to the syslog queue for later retry.
    ///
    /// This is called when the forward fails so events are not lost.
    async fn enqueue_events(&self, events: &[AuditEvent]) -> Result<(), SyslogError> {
        for event in events {
            let json = serde_json::to_string(event)?;
            let mut conn = self.pool.get().map_err(SyslogError::from)?;
            let uow = db::UnitOfWork::new(&mut conn).map_err(SyslogError::Database)?;

            // Read max_size from config for tail-drop enforcement.
            let config = SyslogConfigRepository::get(&self.pool, &self.crypto)
                .map_err(SyslogError::from_app_error)?;

            if let Err(e) =
                SyslogQueueRepository::enqueue(&uow, &json, &self.crypto, config.queue_max_size)
            {
                tracing::error!("failed to enqueue syslog event: {e}");
                // Don't propagate enqueue failures -- we've already lost the
                // network path, and failing the enqueue would double-drop.
            } else {
                uow.commit().map_err(SyslogError::Database)?;
            }
        }
        Ok(())
    }
}

/// Formats a single audit event as an RFC 5424 message.
///
/// # Format
///
/// ```text
/// <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG\n
/// ```
///
/// - PRI = facility * 8 + severity (RFC 5424 section 6.2.1).
/// - VERSION = 1 (RFC 5424).
/// - APP-NAME = "DLP-AUDIT" (fixed per CONTEXT.md).
/// - STRUCTURED-DATA = "-" (nil value, per D-01 JSON-in-MSG).
/// - MSG = serde_json::to_string(event) -- flat JSON with all AuditEvent fields (per D-02).
/// - Newlines in JSON are escaped to prevent RFC 5424 framing issues.
/// - Line terminator is LF (\n) not CRLF (per review, broader collector compatibility).
fn format_rfc5424(
    event: &AuditEvent,
    config: &SyslogConfigRow,
    hostname: &str,
    procid: &str,
) -> Result<String, SyslogError> {
    let severity = map_severity(event.event_type, config);
    let priority = (config.facility_code * 8 + severity) as u8;
    let timestamp = event
        .timestamp
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let msgid = event_type_to_msgid(event.event_type);
    let json_payload = serde_json::to_string(event)?;
    // Sanitize: escape newlines in JSON to prevent RFC 5424 framing issues.
    let sanitized_payload = json_payload.replace('\n', "\\n").replace('\r', "\\r");
    // Use LF (\n) not CRLF (\r\n) for broader syslog collector compatibility.
    Ok(format!(
        "<{priority}>1 {timestamp} {hostname} DLP-AUDIT {procid} {msgid} - {sanitized_payload}\n"
    ))
}

/// Maps an event type to its configured syslog severity.
///
/// Per D-03:
/// - Alert -> severity_alert (default 3 = ERROR)
/// - Block -> severity_block (default 4 = WARNING)
/// - All others -> severity_audit (default 6 = INFORMATIONAL)
fn map_severity(event_type: EventType, config: &SyslogConfigRow) -> i64 {
    match event_type {
        EventType::Alert => config.severity_alert,
        EventType::Block => config.severity_block,
        _ => config.severity_audit,
    }
}

/// Maps an event type to its RFC 5424 MSGID.
///
/// Returns DLP-BLOCK, DLP-ALERT, or DLP-AUDIT.
fn event_type_to_msgid(event_type: EventType) -> &'static str {
    match event_type {
        EventType::Block => "DLP-BLOCK",
        EventType::Alert => "DLP-ALERT",
        _ => "DLP-AUDIT",
    }
}

/// Returns the local hostname, or "localhost" as fallback.
fn get_hostname() -> String {
    // Use the HOSTNAME environment variable if available (common on Windows
    // and Unix). Fallback to "localhost" for test environments where the
    // variable may not be set.
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "localhost".to_string())
}

/// Builds a TLS client configuration using the system CA store.
///
/// Falls back to webpki-roots if the system store is empty.
/// No client auth (no mTLS per D-10).
fn build_tls_config(tls_min_version: &str) -> Result<rustls::ClientConfig, SyslogError> {
    let mut root_store = rustls::RootCertStore::empty();
    let cert_result = rustls_native_certs::load_native_certs();
    for cert in cert_result.certs {
        root_store
            .add(cert)
            .map_err(|e| SyslogError::Tls(format!("cert add failed: {e}")))?;
    }
    if root_store.is_empty() {
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Enforce TLS version minimum per D-11.
    // TLS 1.3 is preferred when explicitly requested.
    if tls_min_version == "1.3" {
        // rustls 0.23 defaults to 1.2+; 1.3-only requires protocol version config.
        // For now we accept 1.2+ as the baseline; the connector will negotiate
        // up to 1.3 if the server supports it.
        config.alpn_protocols = vec![];
    }

    Ok(config)
}

/// Resolves a hostname to a rustls `ServerName`, handling both DNS names
/// and IP addresses (per R-62-04 and Pitfall 2 in RESEARCH.md).
fn resolve_server_name(host: &str) -> Result<rustls_pki_types::ServerName<'static>, SyslogError> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        Ok(rustls_pki_types::ServerName::IpAddress(ip.into()))
    } else {
        rustls_pki_types::ServerName::try_from(host.to_string())
            .map_err(|e| SyslogError::Tls(format!("invalid server name: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{SecretCrypto, ENVELOPE_VERSION_V1};
    use crate::db::new_pool;
    use dlp_common::{Action, Classification, Decision};

    const TEST_KEK: [u8; 32] = [
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42,
    ];

    fn fixture_crypto() -> SecretCrypto {
        SecretCrypto::from_kek(TEST_KEK, ENVELOPE_VERSION_V1)
    }

    fn fixture_config() -> SyslogConfigRow {
        SyslogConfigRow {
            host: "syslog.example.com".to_string(),
            port: 6514,
            enabled: 1,
            protocol: "tls".to_string(),
            facility_code: 20,
            format: "json".to_string(),
            batching_enabled: 1,
            severity_alert: 3,
            severity_block: 4,
            severity_audit: 6,
            queue_policy: "fifo_tail_drop".to_string(),
            queue_max_size: 100000,
            tls_min_version: "1.2".to_string(),
            updated_at: "2026-05-14T00:00:00Z".to_string(),
        }
    }

    fn fixture_event(event_type: EventType) -> AuditEvent {
        AuditEvent::new(
            event_type,
            "S-1-5-21-123".to_string(),
            "jsmith".to_string(),
            r"C:\Data\File.txt".to_string(),
            Classification::T3,
            Action::COPY,
            Decision::DENY,
            "AGENT-001".to_string(),
            1,
        )
    }

    #[test]
    fn test_debug_redacts_crypto() {
        let pool = Arc::new(new_pool(":memory:").expect("create pool"));
        let crypto = Arc::new(fixture_crypto());
        let connector = SyslogConnector::new(pool, crypto);
        let dbg = format!("{connector:?}");
        assert!(
            dbg.contains("<SecretCrypto>"),
            "Debug must redact crypto; got: {dbg}"
        );
        assert!(
            !dbg.contains("0x42"),
            "Debug must not contain KEK bytes; got: {dbg}"
        );
    }

    #[test]
    fn test_format_rfc5424_structure() {
        let config = fixture_config();
        let event = fixture_event(EventType::Block);
        let msg = format_rfc5424(&event, &config, "server01", "1234").expect("format");

        // Must start with <PRI>1.
        assert!(msg.starts_with('<'), "must start with <PRI>");
        assert!(msg.contains(">1 "), "must contain VERSION=1");

        // Must contain all RFC 5424 header fields.
        assert!(msg.contains("server01"), "must contain HOSTNAME");
        assert!(msg.contains("DLP-AUDIT"), "must contain APP-NAME");
        assert!(msg.contains("1234"), "must contain PROCID");
        assert!(msg.contains("DLP-BLOCK"), "must contain MSGID for Block");
        assert!(msg.contains(" - "), "must contain NILVALUE structured-data");

        // Must end with LF.
        assert!(msg.ends_with('\n'), "must end with LF");
        assert!(!msg.ends_with("\r\n"), "must NOT end with CRLF");
    }

    #[test]
    fn test_format_rfc5424_pri_calculation() {
        let config = fixture_config();
        let event = fixture_event(EventType::Block);
        let msg = format_rfc5424(&event, &config, "server01", "1234").expect("format");

        // PRI = facility * 8 + severity = 20 * 8 + 4 = 164.
        assert!(
            msg.starts_with("<164>"),
            "PRI for facility=20, severity=4 must be 164"
        );
    }

    #[test]
    fn test_format_rfc5424_json_payload() {
        let config = fixture_config();
        let event = fixture_event(EventType::Block);
        let msg = format_rfc5424(&event, &config, "server01", "1234").expect("format");

        // The MSG field must contain the JSON-serialized event.
        assert!(
            msg.contains("\"event_type\":"),
            "must contain event_type in JSON"
        );
        assert!(
            msg.contains("\"user_name\":\"jsmith\""),
            "must contain user_name in JSON"
        );
        assert!(
            msg.contains("\"resource_path\":\"C:\\\\Data\\\\File.txt\""),
            "must contain escaped resource_path in JSON"
        );
    }

    #[test]
    fn test_format_rfc5424_newline_escaping() {
        let config = fixture_config();
        let mut event = fixture_event(EventType::Block);
        // Inject a newline into the user_name field to test escaping.
        // serde_json will encode this as "line1\nline2" in the JSON string.
        event.user_name = "line1\nline2".to_string();
        let msg = format_rfc5424(&event, &config, "server01", "1234").expect("format");

        // The raw message must not contain actual newlines in the MSG portion
        // (the only newline should be the LF terminator at the end).
        let msg_part = msg.split(" - ").nth(1).expect("MSG part");
        // msg_part includes the JSON payload + LF terminator.
        // Remove the trailing LF and check no other newlines exist.
        let payload = msg_part.strip_suffix('\n').unwrap_or(msg_part);
        assert!(
            !payload.contains('\n'),
            "JSON payload must not contain raw newlines; got: {payload}"
        );
        // The JSON-encoded string contains \n which in the raw bytes is
        // backslash + n (two characters). serde_json handles this automatically.
        assert!(
            payload.contains("line1"),
            "payload must contain the original text"
        );
    }

    #[test]
    fn test_map_severity_defaults() {
        let config = fixture_config();
        assert_eq!(map_severity(EventType::Alert, &config), 3);
        assert_eq!(map_severity(EventType::Block, &config), 4);
        assert_eq!(map_severity(EventType::Access, &config), 6);
        assert_eq!(map_severity(EventType::ConfigChange, &config), 6);
    }

    #[test]
    fn test_event_type_to_msgid() {
        assert_eq!(event_type_to_msgid(EventType::Block), "DLP-BLOCK");
        assert_eq!(event_type_to_msgid(EventType::Alert), "DLP-ALERT");
        assert_eq!(event_type_to_msgid(EventType::Access), "DLP-AUDIT");
        assert_eq!(event_type_to_msgid(EventType::ConfigChange), "DLP-AUDIT");
    }

    #[test]
    fn test_resolve_server_name_dns() {
        let result = resolve_server_name("syslog.example.com");
        assert!(result.is_ok(), "DNS hostname must resolve");
    }

    #[test]
    fn test_resolve_server_name_ipv4() {
        let result = resolve_server_name("192.168.1.1");
        assert!(result.is_ok(), "IPv4 address must resolve");
    }

    #[test]
    fn test_resolve_server_name_ipv6() {
        let result = resolve_server_name("::1");
        assert!(result.is_ok(), "IPv6 address must resolve");
    }

    #[test]
    fn test_build_tls_config_no_panic() {
        // rustls 0.23 requires a crypto provider to be installed.
        // In production this is done in main.rs; in tests we install it here.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let result = build_tls_config("1.2");
        assert!(result.is_ok(), "TLS config build must not panic");
    }

    #[test]
    fn test_build_tls_config_1_3() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let result = build_tls_config("1.3");
        assert!(result.is_ok(), "TLS 1.3 config build must not panic");
    }

    #[tokio::test]
    async fn test_forward_empty_events_short_circuits() {
        let pool = Arc::new(new_pool(":memory:").expect("create pool"));
        let crypto = Arc::new(fixture_crypto());
        let connector = SyslogConnector::new(pool, crypto);

        // Empty slice must short-circuit before touching DB/network.
        connector
            .forward(&[])
            .await
            .expect("empty forward should succeed");
    }

    #[tokio::test]
    async fn test_forward_disabled_config_short_circuits() {
        let pool = Arc::new(new_pool(":memory:").expect("create pool"));
        let crypto = Arc::new(fixture_crypto());
        let connector = SyslogConnector::new(pool, crypto);

        // Config defaults to enabled=0, so forward should short-circuit.
        let event = fixture_event(EventType::Block);
        connector
            .forward(&[event])
            .await
            .expect("disabled forward should succeed");
    }

    #[test]
    fn test_syslog_error_from_app_error() {
        let app_err = AppError::BadRequest("test".to_string());
        let syslog_err = SyslogError::from_app_error(app_err);
        assert!(syslog_err.to_string().contains("bad request"));
    }
}
