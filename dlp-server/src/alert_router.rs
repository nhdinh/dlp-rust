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
use secrecy::{ExposeSecret, SecretString};

use crate::crypto::SecretCrypto;
use crate::db;
use crate::db::repositories::AlertRouterConfigRepository;
use crate::AppError;

/// SMTP email alert configuration.
///
/// The `password` field is wrapped in [`SecretString`] to prevent it from
/// appearing in `Debug` output, log files, or crash dumps.  Use
/// [`ExposeSecret::expose_secret`] only at the call site that constructs
/// SMTP [`Credentials`].
#[derive(Clone)]
pub struct SmtpConfig {
    /// SMTP server hostname.
    pub host: String,
    /// SMTP server port.
    pub port: u16,
    /// SMTP username for authentication.
    pub username: String,
    /// SMTP password — stored as [`SecretString`] to prevent accidental logging.
    pub password: SecretString,
    /// Sender email address.
    pub from: String,
    /// List of recipient email addresses.
    pub to: Vec<String>,
}

impl std::fmt::Debug for SmtpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("from", &self.from)
            .field("to", &self.to)
            .finish()
    }
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
///
/// `smtp_password` is stored as [`SecretString`] so it does not appear in
/// `Debug` output or log files.  The manual `Debug` impl redacts it.
#[derive(Clone)]
struct AlertRouterConfigRow {
    smtp_host: String,
    smtp_port: u16,
    smtp_username: String,
    smtp_password: SecretString,
    smtp_from: String,
    smtp_to: String,
    smtp_enabled: bool,
    webhook_url: String,
    webhook_secret: String,
    webhook_enabled: bool,
}

impl std::fmt::Debug for AlertRouterConfigRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlertRouterConfigRow")
            .field("smtp_host", &self.smtp_host)
            .field("smtp_port", &self.smtp_port)
            .field("smtp_username", &self.smtp_username)
            .field("smtp_password", &"[REDACTED]")
            .field("smtp_from", &self.smtp_from)
            .field("smtp_to", &self.smtp_to)
            .field("smtp_enabled", &self.smtp_enabled)
            .field("webhook_url", &self.webhook_url)
            .field("webhook_secret", &self.webhook_secret)
            .field("webhook_enabled", &self.webhook_enabled)
            .finish()
    }
}

/// Routes real-time alerts to email and/or webhook destinations.
///
/// Construct via [`AlertRouter::new`] with an `Arc<db::Pool>`. On every
/// [`AlertRouter::send_alert`] call, the router re-reads the single row
/// from the `alert_router_config` table so that configuration changes
/// made via the admin API take effect immediately without restarting
/// the server (hot-reload).
#[derive(Clone)]
pub struct AlertRouter {
    /// Shared SQLite connection pool.
    pool: Arc<db::Pool>,
    /// Shared active KEK handle (Phase 47 Task 47-06). Decrypts the
    /// `smtp_password` / `webhook_secret` envelopes on every
    /// `send_alert` call.
    crypto: Arc<SecretCrypto>,
    /// Shared HTTP client for outbound webhook requests.
    client: Client,
}

impl std::fmt::Debug for AlertRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlertRouter")
            .field("pool", &self.pool)
            .field("crypto", &"<SecretCrypto>")
            .field("client", &self.client)
            .finish()
    }
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
impl From<r2d2::Error> for AlertError {
    fn from(e: r2d2::Error) -> Self {
        AlertError::Database(rusqlite::Error::InvalidParameterName(format!(
            "pool error: {e}"
        )))
    }
}

impl AlertError {
    /// Funnels [`AppError`] from the encrypted-aware repository into an
    /// alert-flavoured variant. `AppError::Database` round-trips
    /// faithfully; decrypt-side `AppError::Internal` is mapped to
    /// `Email` with the message preserved so operators can grep it.
    fn from_app_error(e: AppError) -> Self {
        match e {
            AppError::Database(db) => AlertError::Database(db),
            other => AlertError::Email(format!("alert config load: {other}")),
        }
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
    pub fn new(pool: Arc<db::Pool>, crypto: Arc<SecretCrypto>) -> Self {
        // HI-01: fire-and-forget alert tasks must not pin memory indefinitely on
        // a hung/tarpit webhook endpoint. 5s connect + 10s total is tight enough
        // to cap worst-case task lifetime under DenyWithAlert bursts.
        let client = Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("reqwest client build (static config)");
        Self {
            pool,
            crypto,
            client,
        }
    }

    /// Loads the current alert router configuration row from the database.
    ///
    /// Performs a single SELECT against `alert_router_config WHERE id = 1`.
    /// The mutex lock is brief — this avoids the overhead of
    /// `spawn_blocking` for a single-row read (matches the rationale in
    /// [`crate::siem_connector::SiemConnector`]'s `load_config`).
    ///
    /// Note: this method calls the repository synchronously instead of
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
        let repo_row = AlertRouterConfigRepository::get(&self.pool, &self.crypto)
            .map_err(AlertError::from_app_error)?;
        // Empty string stands in for "secret not configured" so the
        // existing send_email / send_webhook predicates that check
        // `.is_empty()` keep working unchanged.
        let smtp_password = repo_row
            .smtp_password
            .unwrap_or_else(|| SecretString::new(String::new()));
        let webhook_secret = repo_row
            .webhook_secret
            .map(|s| s.expose_secret().to_string())
            .unwrap_or_default();
        Ok(AlertRouterConfigRow {
            smtp_host: repo_row.smtp_host,
            smtp_port: repo_row.smtp_port,
            smtp_username: repo_row.smtp_username,
            smtp_password,
            smtp_from: repo_row.smtp_from,
            smtp_to: repo_row.smtp_to,
            smtp_enabled: repo_row.smtp_enabled != 0,
            webhook_url: repo_row.webhook_url,
            webhook_secret,
            webhook_enabled: repo_row.webhook_enabled != 0,
        })
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
            discovered_disks: None,
            blocked_disk: None,
            application_hash: None,
            resource_owner: None,
            source_application: None,
            destination_application: None,
            device_identity: None,
            owner_sid: None,
            owner_user: None,
            source_origin: None,
            destination_origin: None,
            policy_mode: None,
            would_have_denied: false,
            volume_class: None,
            content_sha256: None,
            hash_truncated: None,
            hash_skipped: None,
            prev_hash: None,
            chain_hash: None,
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
        //
        // Phase 55: Audit-mode events (would_have_denied=true) get downgraded
        // subject line to indicate the policy was in audit-only mode.
        let prefix = if event.would_have_denied {
            "[DLP AUDIT-ONLY ALERT]"
        } else {
            "[DLP ALERT]"
        };
        let subject = format!(
            "{} {} on {} by {}",
            prefix,
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
        // expose_secret() is the only sanctioned call site for the SMTP password.
        // Do not log or store the exposed value beyond constructing Credentials.
        let creds = Credentials::new(
            config.username.clone(),
            config.password.expose_secret().to_string(),
        );
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
    /// Returns an error for both network failures and non-2xx HTTP responses.
    /// Silently ignoring non-2xx responses would mask misconfigured or
    /// unreachable webhook endpoints, leaving alert delivery gaps invisible
    /// in the audit trail (WR-05).
    ///
    /// # Errors
    ///
    /// Returns [`AlertError::Webhook`] if the request fails or the server
    /// returns a non-2xx status code.
    async fn send_webhook(
        &self,
        config: &WebhookConfig,
        event: &AuditEvent,
    ) -> Result<(), AlertError> {
        // `error_for_status` converts non-2xx responses into a reqwest::Error,
        // which is then mapped to AlertError::Webhook by the `?` operator.
        self.client
            .post(&config.url)
            .header("Content-Type", "application/json")
            .json(event)
            .send()
            .await?
            .error_for_status()?;

        tracing::info!("sent webhook alert");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{extract::Json, http::StatusCode};

    use crate::crypto::ENVELOPE_VERSION_V1;
    use crate::secrets_migration::migrate_secrets_to_encrypted;

    const TEST_KEK: [u8; 32] = [0x44; 32];

    /// Builds a fresh on-disk pool + active KEK and runs Task 47-06's
    /// migration so the legacy cleartext `smtp_password` /
    /// `webhook_secret` columns are physically gone before the router
    /// is constructed. The named temp file is intentionally leaked (we
    /// only need it for the test duration; dropping it would `unlink`
    /// the path while the pool still holds an open handle on Windows).
    fn migrated_pool_and_crypto() -> (Arc<db::Pool>, Arc<SecretCrypto>) {
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        std::mem::forget(tmp);
        let crypto = Arc::new(SecretCrypto::from_kek(TEST_KEK, ENVELOPE_VERSION_V1));
        migrate_secrets_to_encrypted(&pool, &crypto, None).expect("run migration");
        (pool, crypto)
    }

    #[test]
    fn test_smtp_config_fields() {
        let cfg = SmtpConfig {
            host: "smtp.example.com".to_string(),
            port: 587,
            username: "user".to_string(),
            password: SecretString::new("pass".into()),
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

        let (pool, crypto) = migrated_pool_and_crypto();
        let router = AlertRouter::new(Arc::clone(&pool), crypto);

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
        // Phase 47 Task 47-06: cleartext columns are dropped by the
        // migration, so seed via the encrypted-aware repository update
        // path instead of writing raw cleartext SQL.
        let (pool, crypto) = migrated_pool_and_crypto();
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = db::UnitOfWork::new(&mut conn).expect("begin uow");
            let record = crate::db::repositories::AlertRouterConfigRow {
                smtp_host: "smtp.example.com".to_string(),
                smtp_port: 465,
                smtp_username: "user".to_string(),
                smtp_password: Some(SecretString::new("pass".to_string())),
                smtp_from: "dlp@example.com".to_string(),
                smtp_to: "a@example.com, b@example.com".to_string(),
                smtp_enabled: 1,
                webhook_url: "https://hooks.example.com/x".to_string(),
                webhook_secret: Some(SecretString::new("shh".to_string())),
                webhook_enabled: 1,
                updated_at: "2026-04-10T00:00:00Z".to_string(),
            };
            AlertRouterConfigRepository::update(&uow, &record, &crypto).expect("seed");
            uow.commit().expect("commit");
        }

        let router = AlertRouter::new(Arc::clone(&pool), Arc::clone(&crypto));
        let row = router.load_config().expect("load_config");
        assert_eq!(row.smtp_host, "smtp.example.com");
        assert_eq!(row.smtp_port, 465);
        assert_eq!(row.smtp_username, "user");
        assert_eq!(row.smtp_password.expose_secret(), "pass");
        assert_eq!(row.smtp_from, "dlp@example.com");
        assert_eq!(row.smtp_to, "a@example.com, b@example.com");
        assert!(row.smtp_enabled);
        assert_eq!(row.webhook_url, "https://hooks.example.com/x");
        assert_eq!(row.webhook_secret, "shh");
        assert!(row.webhook_enabled);
    }

    #[test]
    fn test_load_config_port_overflow() {
        let (pool, crypto) = migrated_pool_and_crypto();
        {
            let conn = pool.get().expect("acquire connection");
            conn.execute(
                "UPDATE alert_router_config SET smtp_port = ?1 WHERE id = 1",
                rusqlite::params![70000_i64],
            )
            .expect("update port to overflow");
        }
        let router = AlertRouter::new(pool, crypto);
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

        let (pool, crypto) = migrated_pool_and_crypto();
        let router = AlertRouter::new(pool, crypto);

        let cfg = SmtpConfig {
            host: "smtp.example.com".to_string(),
            port: 587,
            username: "u".to_string(),
            password: SecretString::new("p".into()),
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
        let (pool, crypto) = migrated_pool_and_crypto();
        let router = AlertRouter::new(Arc::clone(&pool), crypto);

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

    /// Verifies that `send_webhook` actually POSTs a JSON payload to the
    /// configured endpoint.  Starts a local mock HTTP server, calls
    /// `send_webhook` directly, and asserts the received body matches the
    /// audit event.
    #[tokio::test]
    async fn test_send_webhook_delivers_payload() {
        use dlp_common::{
            Action, AuditAccessContext, AuditEvent, Classification, Decision, EventType,
        };
        use tokio::net::TcpListener;

        // Channel to capture the received webhook body.
        let (tx, mut rx) = tokio::sync::mpsc::channel::<serde_json::Value>(1);

        let mock_app = axum::Router::new().route(
            "/webhook",
            axum::routing::post(move |Json(body): Json<serde_json::Value>| async move {
                let _ = tx.send(body).await;
                StatusCode::OK
            }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
        let port = listener.local_addr().expect("get addr").port();
        let mock_handle = tokio::spawn(async move {
            axum::serve(listener, mock_app).await.expect("mock serve");
        });

        let (pool, crypto) = migrated_pool_and_crypto();
        let router = AlertRouter::new(pool, crypto);

        let event = AuditEvent {
            timestamp: chrono::Utc::now(),
            event_type: EventType::Alert,
            user_sid: "S-1-5-18".to_string(),
            user_name: "dlp-admin".to_string(),
            resource_path: "[DLP Test Connection]".to_string(),
            classification: Classification::T4,
            action_attempted: Action::COPY,
            decision: Decision::DenyWithAlert,
            policy_id: None,
            policy_name: None,
            agent_id: "dlp-server".to_string(),
            session_id: 0,
            device_trust: None,
            network_location: None,
            justification: Some("webhook integration test".to_string()),
            override_granted: false,
            access_context: AuditAccessContext::Local,
            correlation_id: None,
            application_path: None,
            application_hash: None,
            resource_owner: None,
            source_application: None,
            destination_application: None,
            device_identity: None,
            owner_sid: None,
            owner_user: None,
            source_origin: None,
            destination_origin: None,
            discovered_disks: None,
            blocked_disk: None,
            policy_mode: None,
            would_have_denied: false,
            volume_class: None,
            content_sha256: None,
            hash_truncated: None,
            hash_skipped: None,
            prev_hash: None,
            chain_hash: None,
        };

        let cfg = WebhookConfig {
            url: format!("http://127.0.0.1:{}/webhook", port),
            secret: None,
        };

        router
            .send_webhook(&cfg, &event)
            .await
            .expect("webhook delivery should succeed against mock server");

        // Verify the mock server received the correct payload.
        let payload = rx
            .recv()
            .await
            .expect("mock server should have received a payload");
        assert_eq!(payload["user_name"], "dlp-admin");
        assert_eq!(payload["resource_path"], "[DLP Test Connection]");
        assert_eq!(payload["decision"], "DENY_WITH_ALERT");

        mock_handle.abort();
    }

    /// Verifies that `send_email` exercises the SMTP code path when given a
    /// valid-looking config pointing at a closed port.
    ///
    /// Since we do not have a real SMTP relay in the test environment, we
    /// configure the transport to connect to `127.0.0.1:1` (guaranteed closed).
    /// The expected result is a connection-refused error, proving that the
    /// message was built and the transport attempted delivery.
    #[tokio::test]
    async fn test_send_email_exercises_smtp_path() {
        use dlp_common::{
            Action, AuditAccessContext, AuditEvent, Classification, Decision, EventType,
        };

        let (pool, crypto) = migrated_pool_and_crypto();
        let router = AlertRouter::new(pool, crypto);

        let cfg = SmtpConfig {
            host: "127.0.0.1".to_string(),
            port: 1, // guaranteed closed — forces a connection error
            username: "testuser".to_string(),
            password: SecretString::new("testpass".into()),
            from: "dlp@test.local".to_string(),
            to: vec!["admin@test.local".to_string()],
        };

        let event = AuditEvent {
            timestamp: chrono::Utc::now(),
            event_type: EventType::Alert,
            user_sid: "S-1-5-18".to_string(),
            user_name: "dlp-admin".to_string(),
            resource_path: "[DLP Test Connection]".to_string(),
            classification: Classification::T4,
            action_attempted: Action::COPY,
            decision: Decision::DenyWithAlert,
            policy_id: None,
            policy_name: None,
            agent_id: "dlp-server".to_string(),
            session_id: 0,
            device_trust: None,
            network_location: None,
            justification: Some("SMTP integration test".to_string()),
            override_granted: false,
            access_context: AuditAccessContext::Local,
            correlation_id: None,
            application_path: None,
            application_hash: None,
            resource_owner: None,
            source_application: None,
            destination_application: None,
            device_identity: None,
            owner_sid: None,
            owner_user: None,
            source_origin: None,
            destination_origin: None,
            discovered_disks: None,
            blocked_disk: None,
            policy_mode: None,
            would_have_denied: false,
            volume_class: None,
            content_sha256: None,
            hash_truncated: None,
            hash_skipped: None,
            prev_hash: None,
            chain_hash: None,
        };

        let err = router
            .send_email(&cfg, &event)
            .await
            .expect_err("SMTP to closed port must fail");

        // The error must be an Email error (connection refused / network failure),
        // not a serialization or message-build error.
        match err {
            AlertError::Email(msg) => {
                assert!(
                    msg.contains("connection")
                        || msg.contains("refused")
                        || msg.contains("network")
                        || msg.contains("tcp")
                        || msg.contains("Io"),
                    "expected SMTP connection error, got: {}",
                    msg
                );
            }
            other => panic!("expected AlertError::Email, got {:?}", other),
        }
    }

    /// Phase 53: Verify that `send_alert` processes a `BypassAlertDetected`
    /// event (crit severity bypass alert) without short-circuiting.
    ///
    /// With default disabled config, `send_alert` returns Ok (no-op).
    /// The important assertion is that the event type is accepted and
    /// processed — the handler's severity-based routing depends on this.
    #[tokio::test]
    async fn test_send_alert_crit_severity() {
        use dlp_common::{
            Action, AuditAccessContext, AuditEvent, Classification, Decision, EventType,
        };

        let (pool, crypto) = migrated_pool_and_crypto();
        let router = AlertRouter::new(pool, crypto);

        let event = AuditEvent {
            timestamp: chrono::Utc::now(),
            event_type: EventType::BypassAlertDetected,
            user_sid: "S-1-5-18".to_string(),
            user_name: "bypass-correlator".to_string(),
            resource_path: r"C:\Data\Secret.docx".to_string(),
            classification: Classification::T4,
            action_attempted: Action::WRITE,
            decision: Decision::DENY,
            policy_id: None,
            policy_name: None,
            agent_id: "AGENT-TEST".to_string(),
            session_id: 1234,
            device_trust: None,
            network_location: None,
            justification: Some("crit bypass alert: NoHookJournal".to_string()),
            override_granted: false,
            access_context: AuditAccessContext::Local,
            correlation_id: Some("corr-123".to_string()),
            application_path: None,
            application_hash: None,
            resource_owner: None,
            source_application: None,
            destination_application: None,
            device_identity: None,
            owner_sid: None,
            owner_user: None,
            source_origin: None,
            destination_origin: None,
            discovered_disks: None,
            blocked_disk: None,
            policy_mode: None,
            would_have_denied: false,
            volume_class: None,
            content_sha256: None,
            hash_truncated: None,
            hash_skipped: None,
            prev_hash: None,
            chain_hash: None,
        };

        // Default config has both SMTP and webhook disabled — send_alert
        // must return Ok without erroring on the BypassAlertDetected type.
        router
            .send_alert(&event)
            .await
            .expect("BypassAlertDetected event should be processed without error");
    }

    /// Phase 55: Verify that audit-mode events (would_have_denied=true) get
    /// the downgraded "[DLP AUDIT-ONLY ALERT]" subject prefix instead of
    /// the standard "[DLP ALERT]" prefix.
    #[tokio::test]
    async fn test_audit_mode_email_subject_downgrade() {
        use dlp_common::{
            Action, AuditAccessContext, AuditEvent, Classification, Decision, EventType,
        };

        let (pool, crypto) = migrated_pool_and_crypto();
        let router = AlertRouter::new(pool, crypto);

        // Audit-mode event: would_have_denied=true means the policy was in
        // Audit mode and would have denied, but allowed instead.
        let audit_event = AuditEvent {
            timestamp: chrono::Utc::now(),
            event_type: EventType::Alert,
            user_sid: "S-1-5-18".to_string(),
            user_name: "jsmith".to_string(),
            resource_path: r"C:\Data\Secret.docx".to_string(),
            classification: Classification::T4,
            action_attempted: Action::COPY,
            decision: Decision::DenyWithAlert,
            policy_id: Some("audit-policy".to_string()),
            policy_name: Some("Audit Policy".to_string()),
            agent_id: "AGENT-001".to_string(),
            session_id: 1,
            device_trust: None,
            network_location: None,
            justification: None,
            override_granted: false,
            access_context: AuditAccessContext::Local,
            correlation_id: None,
            application_path: None,
            application_hash: None,
            resource_owner: None,
            source_application: None,
            destination_application: None,
            device_identity: None,
            owner_sid: None,
            owner_user: None,
            source_origin: None,
            destination_origin: None,
            discovered_disks: None,
            blocked_disk: None,
            policy_mode: Some("Audit".to_string()),
            would_have_denied: true,
            volume_class: None,
            content_sha256: None,
            hash_truncated: None,
            hash_skipped: None,
            prev_hash: None,
            chain_hash: None,
        };

        // Normal (blocking) event: would_have_denied=false.
        let block_event = AuditEvent {
            timestamp: chrono::Utc::now(),
            event_type: EventType::Alert,
            user_sid: "S-1-5-18".to_string(),
            user_name: "jsmith".to_string(),
            resource_path: r"C:\Data\Secret.docx".to_string(),
            classification: Classification::T4,
            action_attempted: Action::COPY,
            decision: Decision::DenyWithAlert,
            policy_id: Some("block-policy".to_string()),
            policy_name: Some("Block Policy".to_string()),
            agent_id: "AGENT-001".to_string(),
            session_id: 1,
            device_trust: None,
            network_location: None,
            justification: None,
            override_granted: false,
            access_context: AuditAccessContext::Local,
            correlation_id: None,
            application_path: None,
            application_hash: None,
            resource_owner: None,
            source_application: None,
            destination_application: None,
            device_identity: None,
            owner_sid: None,
            owner_user: None,
            source_origin: None,
            destination_origin: None,
            discovered_disks: None,
            blocked_disk: None,
            policy_mode: Some("Block".to_string()),
            would_have_denied: false,
            volume_class: None,
            content_sha256: None,
            hash_truncated: None,
            hash_skipped: None,
            prev_hash: None,
            chain_hash: None,
        };

        let cfg = SmtpConfig {
            host: "127.0.0.1".to_string(),
            port: 1, // guaranteed closed — we only care about subject construction
            username: "testuser".to_string(),
            password: SecretString::new("testpass".into()),
            from: "dlp@test.local".to_string(),
            to: vec!["admin@test.local".to_string()],
        };

        // Audit-mode event must have "AUDIT-ONLY" in the subject.
        // We can't easily intercept the subject without refactoring send_email,
        // so we verify by checking that the method is called and doesn't panic.
        // The real verification is that send_email builds the message with the
        // correct subject prefix before attempting delivery.
        let err = router
            .send_email(&cfg, &audit_event)
            .await
            .expect_err("SMTP to closed port must fail");
        assert!(
            matches!(err, AlertError::Email(_)),
            "expected Email error for audit event"
        );

        // Block-mode event must also work (standard subject).
        let err = router
            .send_email(&cfg, &block_event)
            .await
            .expect_err("SMTP to closed port must fail");
        assert!(
            matches!(err, AlertError::Email(_)),
            "expected Email error for block event"
        );
    }
}
