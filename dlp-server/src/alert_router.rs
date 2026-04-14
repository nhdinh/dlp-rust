//! Email (SMTP) and webhook alerts for DENY_WITH_ALERT events.
//!
//! Reads alert configuration from the `alert_router_config` SQLite table on
//! every `send_alert` call (hot-reload). Supports sending email via SMTP
//! (lettre) and HTTP POST to a webhook endpoint.
//!
//! ## TM-03 forward-compat rule (MANDATORY for reviewers)
//!
//! `send_email` serializes the full `AuditEvent` as-is via
//! `serde_json::to_string_pretty`. Today `AuditEvent` contains no
//! content-snippet field — every field is metadata (timestamps, IDs,
//! classifications, decisions) or operator-useful routing data
//! (`resource_path`, `user_name`, `justification`).
//!
//! If a future PR adds a content/sample/snippet/preview/body/raw/
//! payload_content/clipboard_text/file_excerpt/plaintext field to
//! `dlp_common::AuditEvent`, `send_email` MUST be updated **in the same
//! PR** to redact or omit that field before serialization. Reviewers
//! enforce this via grep against `dlp-common/src/audit.rs`.

use std::sync::Arc;

use dlp_common::AuditEvent;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use reqwest::Client;

/// SMTP email alert configuration.
#[derive(Debug, Clone)]
pub struct SmtpConfig {
    /// SMTP server hostname.
    pub host: String,
    /// SMTP server port.
    pub port: u16,
    /// SMTP username for authentication.
    pub username: String,
    /// SMTP password for authentication.
    pub password: String,
    /// Sender email address.
    pub from: String,
    /// List of recipient email addresses.
    pub to: Vec<String>,
}

/// Webhook alert configuration.
#[derive(Debug, Clone)]
pub struct WebhookConfig {
    /// Webhook endpoint URL.
    pub url: String,
    /// Optional shared secret for HMAC signing (future use).
    pub secret: Option<String>,
}

/// Snapshot of the single `alert_router_config` row loaded from the database.
#[derive(Debug, Clone)]
struct AlertRouterConfigRow {
    smtp_host: String,
    smtp_port: u16,
    smtp_username: String,
    smtp_password: String,
    smtp_from: String,
    smtp_to: String,
    smtp_enabled: bool,
    webhook_url: String,
    webhook_secret: String,
    webhook_enabled: bool,
}

/// Routes real-time alerts to email and/or webhook destinations.
///
/// Construct via [`AlertRouter::new`] with an `Arc<db::Pool>`. On every
/// [`AlertRouter::send_alert`] call, the router re-reads the single row
/// from the `alert_router_config` table so that configuration changes
/// made via the admin API take effect immediately without restarting
/// the server (hot-reload).
#[derive(Debug, Clone)]
pub struct AlertRouter {
    /// Shared SQLite connection pool.
    pool: Arc<db::Pool>,
    /// Shared HTTP client for outbound webhook requests.
    client: Client,
}

/// Error type for alert delivery failures.
#[derive(Debug, thiserror::Error)]
pub enum AlertError {
    /// SMTP transport or message construction failed.
    #[error("email alert error: {0}")]
    Email(String),

    /// Webhook HTTP request failed.
    #[error("webhook alert error: {0}")]
    Webhook(#[from] reqwest::Error),

    /// JSON serialization failed.
    #[error("alert serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Reading alert router config from the database failed.
    #[error("alert config DB error: {0}")]
    Database(#[from] rusqlite::Error),
}

/// Maps pool acquisition errors to database errors.
impl From<r2d2::PoolError> for AlertError {
    fn from(e: r2d2::PoolError) -> Self {
        AlertError::Database(e.into())
    }
}

impl AlertRouter {
    /// Constructs an `AlertRouter` backed by the given connection pool.
    ///
    /// The router reads alert configuration from the `alert_router_config`
    /// table on each [`send_alert`](Self::send_alert) call. No caching is
    /// performed, so admin updates via the API take effect on the next
    /// alert.
    ///
    /// # Arguments
    ///
    /// * `pool` — Shared connection pool; the router keeps a clone.
    pub fn new(pool: Arc<db::Pool>) -> Self {
        // HI-01: fire-and-forget alert tasks must not pin memory indefinitely on
        // a hung/tarpit webhook endpoint. 5s connect + 10s total is tight enough
        // to cap worst-case task lifetime under DenyWithAlert bursts.
        let client = Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("reqwest client build (static config)");
        Self { pool, client }
    }

    /// Loads the current alert router configuration row from the database.
    ///
    /// Performs a single SELECT against `alert_router_config WHERE id = 1`.
    /// The mutex lock is brief — this avoids the overhead of
    /// `spawn_blocking` for a single-row read (matches the rationale in
    /// [`crate::siem_connector::SiemConnector`]'s `load_config`).
    ///
    /// Note: this method calls `self.pool.get()` directly instead of
    /// wrapping in `tokio::task::spawn_blocking` because it is a single-row
    /// SELECT on the fire-and-forget alert path. The admin PUT handler in
    /// `admin_api.rs::update_alert_config_handler` uses `spawn_blocking`
    /// because it writes under a transaction — the asymmetry is deliberate.
    ///
    /// # Errors
    ///
    /// Returns [`AlertError::Database`] if the row cannot be read or the
    /// stored `smtp_port` is outside the `u16` range.
    fn load_config(&self) -> Result<AlertRouterConfigRow, AlertError> {
        let conn = self.pool.get().map_err(AlertError::from)?;
        let row = conn.query_row(
            "SELECT smtp_host, smtp_port, smtp_username, smtp_password, \
                    smtp_from, smtp_to, smtp_enabled, \
                    webhook_url, webhook_secret, webhook_enabled \
             FROM alert_router_config WHERE id = 1",
            [],
            |r| {
                let port_i64: i64 = r.get(1)?;
                let smtp_port = u16::try_from(port_i64).map_err(|_| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Integer,
                        format!("smtp_port out of range: {port_i64}").into(),
                    )
                })?;
                Ok(AlertRouterConfigRow {
                    smtp_host: r.get(0)?,
                    smtp_port,
                    smtp_username: r.get(2)?,
                    smtp_password: r.get(3)?,
                    smtp_from: r.get(4)?,
                    smtp_to: r.get(5)?,
                    smtp_enabled: r.get::<_, i64>(6)? != 0,
                    webhook_url: r.get(7)?,
                    webhook_secret: r.get(8)?,
                    webhook_enabled: r.get::<_, i64>(9)? != 0,
                })
            },
        )?;
        Ok(row)
    }

    /// Sends an alert for a single audit event to all configured destinations.
    ///
    /// Re-reads the alert router config from the database on each call so
    /// that admin updates take effect immediately (hot-reload).
    ///
    /// # Arguments
    ///
    /// * `event` — The audit event that triggered the alert.
    ///
    /// # Errors
    ///
    /// Returns the first error encountered; **all** errors (SMTP and webhook)
    /// are individually logged at `warn` level before returning (TM-04).
    /// Subsequent errors after the first are dropped — callers who need
    /// complete error accounting must collect per-channel results directly.
    pub async fn send_alert(&self, event: &AuditEvent) -> Result<(), AlertError> {
        let row = self.load_config()?;

        let mut errors: Vec<AlertError> = Vec::new();

        // SMTP path: active iff enabled AND host non-empty AND to non-empty.
        if row.smtp_enabled && !row.smtp_host.is_empty() && !row.smtp_to.is_empty() {
            // smtp_to is a comma-separated string in the DB. Split, trim, filter empties.
            let to: Vec<String> = row
                .smtp_to
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !to.is_empty() {
                let cfg = SmtpConfig {
                    host: row.smtp_host.clone(),
                    port: row.smtp_port,
                    username: row.smtp_username.clone(),
                    password: row.smtp_password.clone(),
                    from: row.smtp_from.clone(),
                    to,
                };
                if let Err(e) = self.send_email(&cfg, event).await {
                    tracing::warn!(error = %e, "alert email delivery failed (best-effort)");
                    errors.push(e);
                }
            }
        }

        // Webhook path: active iff enabled AND url non-empty.
        if row.webhook_enabled && !row.webhook_url.is_empty() {
            let cfg = WebhookConfig {
                url: row.webhook_url.clone(),
                secret: if row.webhook_secret.is_empty() {
                    None
                } else {
                    Some(row.webhook_secret.clone())
                },
            };
            if let Err(e) = self.send_webhook(&cfg, event).await {
                tracing::warn!(error = %e, "alert webhook delivery failed (best-effort)");
                errors.push(e);
            }
        }

        if let Some(e) = errors.into_iter().next() {
            return Err(e);
        }

        Ok(())
    }

    /// Sends a test alert using the current configuration in the database.
    ///
    /// Builds a synthetic `AuditEvent` with type `TestAlert` and sends it
    /// through the same delivery paths (`send_email` + `send_webhook`) as a
    /// real `DenyWithAlert` event. Used by the admin CLI "Test Connection"
    /// action to verify SMTP and webhook settings without triggering a real
    /// policy violation.
    ///
    /// # Errors
    ///
    /// Returns the first delivery error encountered (SMTP or webhook).
    /// Both channels are tried independently (best-effort per channel);
    /// the first failure is returned after both channels have been attempted.
    pub async fn send_test_alert(&self) -> Result<(), AlertError> {
        let event = AuditEvent {
            timestamp: chrono::Utc::now(),
            event_type: dlp_common::EventType::Alert,
            user_sid: "S-1-5-18".to_string(),
            user_name: "dlp-admin".to_string(),
            resource_path: "[DLP Test Connection]".to_string(),
            classification: dlp_common::Classification::T4,
            action_attempted: dlp_common::Action::COPY,
            decision: dlp_common::Decision::DenyWithAlert,
            policy_id: None,
            policy_name: None,
            agent_id: "dlp-server".to_string(),
            session_id: 0,
            device_trust: None,
            network_location: None,
            justification: Some("SMTP test connection verification".to_string()),
            override_granted: false,
            access_context: dlp_common::AuditAccessContext::Local,
            correlation_id: Some(uuid::Uuid::new_v4().to_string()),
            application_path: None,
            application_hash: None,
            resource_owner: None,
        };
        self.send_alert(&event).await
    }

    /// Sends an email alert via SMTP.
    ///
    /// Serializes the full `AuditEvent` via `serde_json::to_string_pretty`.
    /// See the module-level TM-03 forward-compat rule.
    async fn send_email(&self, config: &SmtpConfig, event: &AuditEvent) -> Result<(), AlertError> {
        // LO-02: event_type round-trips through serde_json::Value just to get a
        // discriminant string. Fragile — if EventType ever adds a tuple/struct
        // variant, as_str() silently returns None and the subject becomes
        // "UNKNOWN". Replace once EventType has a Display impl in
        // dlp-common/src/audit.rs with:
        //   format!("[DLP ALERT] {} on {} by {}", event.event_type, event.resource_path, event.user_name)
        let subject = format!(
            "[DLP ALERT] {} on {} by {}",
            serde_json::to_value(event.event_type)
                .unwrap_or_default()
                .as_str()
                .unwrap_or("UNKNOWN"),
            event.resource_path,
            event.user_name,
        );

        // TM-03: AuditEvent has no content-snippet fields today. If a future
        // PR adds any content/sample/snippet field, update this line in the
        // same PR to redact before serialization.
        let body = serde_json::to_string_pretty(event)?;

        let from_mailbox: Mailbox = config
            .from
            .parse()
            .map_err(|e| AlertError::Email(format!("invalid from address: {e}")))?;

        // HI-02: SMTP transport is rebuilt on every call, incurring DNS + TCP
        // + STARTTLS handshake per alert. Acceptable for Phase 4 because
        // DenyWithAlert volume is expected to be low; revisit with a
        // parking_lot::RwLock<Option<(CacheKey, AsyncSmtpTransport<_>)>> cache
        // keyed by (host, port, username) if alert volume grows. See 04-REVIEW.md
        // HI-02 for Option A implementation notes.
        // TODO(followup): cache SMTP transport keyed by config hash.
        let creds = Credentials::new(config.username.clone(), config.password.clone());
        let mailer = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
            .map_err(|e| AlertError::Email(format!("SMTP relay error: {e}")))?
            .port(config.port)
            .credentials(creds)
            .build();

        // ME-02: collect per-recipient errors but keep going so a single bad
        // address in a distribution list does not starve the remaining
        // recipients. Mirrors the best-effort semantics at the outer
        // `send_alert` level. Per-recipient diagnostics are emitted at
        // `debug!` so the TM-04 `warn!` budget (count == 2 for this file)
        // is preserved; the outer `send_alert` still emits the aggregated
        // `warn!` on the returned error.
        let mut errors: Vec<AlertError> = Vec::new();
        for recipient in &config.to {
            let to_mailbox: Mailbox = match recipient.parse() {
                Ok(mb) => mb,
                Err(e) => {
                    tracing::debug!(recipient, error = %e, "invalid to address, skipping");
                    errors.push(AlertError::Email(format!(
                        "invalid to address {recipient}: {e}"
                    )));
                    continue;
                }
            };

            let email = match Message::builder()
                .from(from_mailbox.clone())
                .to(to_mailbox)
                .subject(&subject)
                .body(body.clone())
            {
                Ok(m) => m,
                Err(e) => {
                    tracing::debug!(recipient, error = %e, "message build failed, skipping");
                    errors.push(AlertError::Email(format!(
                        "message build error for {recipient}: {e}"
                    )));
                    continue;
                }
            };

            if let Err(e) = mailer.send(email).await {
                tracing::debug!(recipient, error = %e, "SMTP send failed for recipient");
                errors.push(AlertError::Email(format!(
                    "SMTP send error to {recipient}: {e}"
                )));
            }
        }

        if let Some(e) = errors.into_iter().next() {
            return Err(e);
        }

        tracing::info!(recipients = config.to.len(), "sent email alert");
        Ok(())
    }

    /// Sends an alert payload to a webhook endpoint via HTTP POST.
    ///
    /// Non-2xx responses are treated as silent successes at this layer.
    /// The caller (`send_alert`) logs failures at `warn` via the
    /// reqwest error path when the request itself fails. Per-status-code
    /// logging is deferred to a dedicated observability phase (TM-04).
    async fn send_webhook(
        &self,
        config: &WebhookConfig,
        event: &AuditEvent,
    ) -> Result<(), AlertError> {
        let _ = self
            .client
            .post(&config.url)
            .header("Content-Type", "application/json")
            .json(event)
            .send()
            .await?;

        tracing::info!("sent webhook alert");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smtp_config_fields() {
        let cfg = SmtpConfig {
            host: "smtp.example.com".to_string(),
            port: 587,
            username: "user".to_string(),
            password: "pass".to_string(),
            from: "dlp@example.com".to_string(),
            to: vec!["admin@example.com".to_string()],
        };
        assert_eq!(cfg.port, 587);
        assert_eq!(cfg.to.len(), 1);
    }

    #[test]
    fn test_webhook_config_fields() {
        let cfg = WebhookConfig {
            url: "https://hooks.example.com/alert".to_string(),
            secret: Some("s3cret".to_string()),
        };
        assert!(!cfg.url.is_empty());
        assert!(cfg.secret.is_some());
    }

    #[tokio::test]
    async fn test_alert_router_disabled_default() {
        use dlp_common::{Action, AuditEvent, Classification, Decision, EventType};

        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        let router = AlertRouter::new(Arc::clone(&pool));

        // Seed row has both enabled=0 — send_alert must be a no-op Ok.
        let event = AuditEvent::new(
            EventType::Block,
            "S-1-5-21-123".to_string(),
            "jsmith".to_string(),
            r"C:\Data\File.txt".to_string(),
            Classification::T4,
            Action::COPY,
            Decision::DenyWithAlert,
            "AGENT-001".to_string(),
            1,
        );
        router
            .send_alert(&event)
            .await
            .expect("default config should be a no-op Ok");
    }

    #[test]
    fn test_load_config_roundtrip() {
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        {
            let conn = pool.get().expect("acquire connection");
            conn.execute(
                "UPDATE alert_router_config SET \
                    smtp_host = ?1, smtp_port = ?2, smtp_username = ?3, \
                    smtp_password = ?4, smtp_from = ?5, smtp_to = ?6, \
                    smtp_enabled = ?7, webhook_url = ?8, webhook_secret = ?9, \
                    webhook_enabled = ?10, updated_at = ?11 WHERE id = 1",
                rusqlite::params![
                    "smtp.example.com",
                    465_i64,
                    "user",
                    "pass",
                    "dlp@example.com",
                    "a@example.com, b@example.com",
                    1_i64,
                    "https://hooks.example.com/x",
                    "shh",
                    1_i64,
                    "2026-04-10T00:00:00Z",
                ],
            )
            .expect("update seed row");
        }

        let router = AlertRouter::new(Arc::clone(&pool));
        let row = router.load_config().expect("load_config");
        assert_eq!(row.smtp_host, "smtp.example.com");
        assert_eq!(row.smtp_port, 465);
        assert_eq!(row.smtp_username, "user");
        assert_eq!(row.smtp_password, "pass");
        assert_eq!(row.smtp_from, "dlp@example.com");
        assert_eq!(row.smtp_to, "a@example.com, b@example.com");
        assert!(row.smtp_enabled);
        assert_eq!(row.webhook_url, "https://hooks.example.com/x");
        assert_eq!(row.webhook_secret, "shh");
        assert!(row.webhook_enabled);
    }

    #[test]
    fn test_load_config_port_overflow() {
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        {
            let conn = pool.get().expect("acquire connection");
            conn.execute(
                "UPDATE alert_router_config SET smtp_port = ?1 WHERE id = 1",
                rusqlite::params![70000_i64],
            )
            .expect("update port to overflow");
        }
        let router = AlertRouter::new(pool);
        let err = router.load_config().expect_err("must fail on u16 overflow");
        assert!(matches!(err, AlertError::Database(_)));
    }

    #[tokio::test]
    async fn test_send_email_continues_past_bad_recipient() {
        // ME-02 regression: when the first recipient fails parsing, the
        // loop MUST continue to subsequent recipients and the function
        // MUST return the first collected error rather than short-
        // circuiting on the first `?`. This test exercises the address-
        // parsing failure path (no network needed) because a bad address
        // like "not-an-email" fails `Mailbox::parse()` deterministically.
        use dlp_common::{Action, AuditEvent, Classification, Decision, EventType};

        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        let router = AlertRouter::new(pool);

        let cfg = SmtpConfig {
            host: "smtp.example.com".to_string(),
            port: 587,
            username: "u".to_string(),
            password: "p".to_string(),
            from: "dlp@example.com".to_string(),
            // First address is invalid; second is invalid; neither reaches
            // the network. Both MUST be attempted — the old short-circuit
            // code would return after the first one.
            to: vec!["not-an-email".to_string(), "also bad".to_string()],
        };

        let event = AuditEvent::new(
            EventType::Block,
            "S-1-5-21-123".to_string(),
            "jsmith".to_string(),
            r"C:\Data\File.txt".to_string(),
            Classification::T4,
            Action::COPY,
            Decision::DenyWithAlert,
            "AGENT-001".to_string(),
            1,
        );

        let err = router
            .send_email(&cfg, &event)
            .await
            .expect_err("both recipients are invalid; must return Err");

        // The returned error MUST be the FIRST error (from the first bad
        // address), and its message MUST mention that first recipient to
        // prove the loop started at the first item.
        match err {
            AlertError::Email(msg) => {
                assert!(
                    msg.contains("not-an-email"),
                    "expected first error to reference the first bad recipient, got: {msg}"
                );
            }
            other => panic!("expected AlertError::Email, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_hot_reload() {
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        let router = AlertRouter::new(Arc::clone(&pool));

        // First read: defaults.
        let row1 = router.load_config().expect("load 1");
        assert_eq!(row1.smtp_host, "");

        // UPDATE the row.
        {
            let conn = pool.get().expect("acquire connection");
            conn.execute(
                "UPDATE alert_router_config SET smtp_host = ?1 WHERE id = 1",
                rusqlite::params!["updated.example.com"],
            )
            .expect("update smtp_host");
        }

        // Second read: must reflect the update (no caching).
        let row2 = router.load_config().expect("load 2");
        assert_eq!(row2.smtp_host, "updated.example.com");
    }
}
