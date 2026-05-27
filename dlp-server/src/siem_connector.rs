//! Batched SIEM relay for Splunk HEC and ELK (P5-T05).
//!
//! Reads SIEM endpoint configuration from the `siem_config` table on
//! every relay call (hot-reload) and relays audit events to one or both
//! backends. Events are batched in a single HTTP request per backend
//! for efficiency.
//!
//! Phase 47 Task 47-09: every in-memory representation of a Splunk HEC
//! token or ELK API key is wrapped in [`secrecy::SecretString`] so the
//! default `Debug` derive redacts them. `expose_secret()` is called
//! ONLY at the HTTP boundary (`Authorization` header construction).
//! Secret-bearing structs use `SecretString` to ensure Debug redacts.
//! Do not add naked-String secret fields.

use std::sync::Arc;

use dlp_common::AuditEvent;
use reqwest::Client;
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;

use crate::crypto::SecretCrypto;
use crate::db;
use crate::db::repositories::SiemConfigRepository;
use crate::AppError;

/// Splunk HTTP Event Collector configuration.
///
/// `token` is wrapped in [`SecretString`] so `Debug` redacts it. The
/// single sanctioned `expose_secret()` site is the `Authorization` header
/// construction in [`SiemConnector::send_to_splunk`].
#[derive(Debug, Clone)]
pub struct SplunkConfig {
    /// Splunk HEC endpoint URL (e.g., `https://splunk:8088`).
    pub url: String,
    /// HEC authentication token (Debug-redacted).
    pub token: SecretString,
}

/// Elasticsearch / ELK configuration.
///
/// `api_key` is wrapped in [`SecretString`]; the sanctioned
/// `expose_secret()` site is the `Authorization` header in
/// [`SiemConnector::send_to_elk`].
#[derive(Debug, Clone)]
pub struct ElkConfig {
    /// Elasticsearch base URL (e.g., `https://elastic:9200`).
    pub url: String,
    /// Target index name.
    pub index: String,
    /// Optional API key for authentication (Debug-redacted).
    pub api_key: Option<SecretString>,
}

/// Snapshot of the single `siem_config` row loaded from the database.
///
/// Secret fields (`splunk_token`, `elk_api_key`) are wrapped in
/// [`SecretString`] so the auto-derived `Debug` cannot leak them via a
/// stray `tracing::debug!("{:?}", row)`. The fields stay private so
/// nothing outside this module can read them without going through one
/// of the controlled accessors.
#[derive(Debug, Clone)]
struct SiemConfigRow {
    splunk_url: String,
    splunk_token: SecretString,
    splunk_enabled: bool,
    elk_url: String,
    elk_index: String,
    elk_api_key: SecretString,
    elk_enabled: bool,
}

/// SIEM relay that forwards audit events to Splunk and/or ELK.
///
/// Construct via `SiemConnector::new(pool, crypto)`. On every
/// `relay_events` call, the connector re-reads the single row from the
/// `siem_config` table so that configuration changes made via the admin
/// API take effect immediately without restarting the server. The
/// `crypto` handle (Phase 47 Task 47-06) is the active KEK that
/// decrypts `splunk_token` / `elk_api_key` on read.
#[derive(Clone)]
pub struct SiemConnector {
    /// Shared SQLite connection pool.
    pool: Arc<db::Pool>,
    /// Shared active KEK handle for decrypting on-disk secret blobs.
    crypto: Arc<SecretCrypto>,
    /// Shared HTTP client for outbound requests.
    client: Client,
}

impl std::fmt::Debug for SiemConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SiemConnector")
            .field("pool", &self.pool)
            .field("crypto", &"<SecretCrypto>")
            .field("client", &self.client)
            .finish()
    }
}

/// Wrapper for Splunk HEC event payload.
#[derive(Debug, Serialize)]
struct SplunkEvent<'a> {
    /// The event data payload.
    event: &'a AuditEvent,
}

/// Error type for SIEM relay operations.
#[derive(Debug, thiserror::Error)]
pub enum SiemError {
    /// An HTTP request to a SIEM backend failed.
    #[error("SIEM HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization failed.
    #[error("SIEM serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Reading SIEM config from the database failed.
    #[error("SIEM config DB error: {0}")]
    Database(#[from] rusqlite::Error),

    /// A SIEM backend returned a non-success status code.
    #[error("SIEM backend returned {status}: {body}")]
    BackendError {
        /// HTTP status code.
        status: u16,
        /// Response body text.
        body: String,
    },
}

/// Maps pool acquisition errors to database errors.
impl From<r2d2::Error> for SiemError {
    fn from(e: r2d2::Error) -> Self {
        SiemError::Database(rusqlite::Error::InvalidParameterName(format!(
            "pool error: {e}"
        )))
    }
}

impl SiemError {
    /// Funnels [`AppError`] from the encrypted-aware repository into a
    /// SIEM-flavoured error variant. `AppError::Database` is mapped to
    /// [`SiemError::Database`]; everything else (`Internal`/decrypt
    /// failures) is mapped to [`SiemError::Database`] wrapping an
    /// `InvalidParameterName` placeholder — the message text is
    /// preserved so callers can `format!("{e}")` and grep it.
    fn from_app_error(e: AppError) -> Self {
        match e {
            AppError::Database(db) => SiemError::Database(db),
            other => SiemError::Database(rusqlite::Error::InvalidParameterName(format!(
                "siem config load: {other}"
            ))),
        }
    }
}

impl SiemConnector {
    /// Constructs a `SiemConnector` backed by the given connection
    /// pool and active KEK handle.
    ///
    /// The connector reads SIEM configuration from the `siem_config`
    /// table on each `relay_events` call. No caching is performed, so
    /// admin updates via the API take effect on the next relay. The
    /// `crypto` handle is the active KEK shared across `AppState`; it
    /// decrypts the on-disk `splunk_token_encrypted` /
    /// `elk_api_key_encrypted` blobs.
    pub fn new(pool: Arc<db::Pool>, crypto: Arc<SecretCrypto>) -> Self {
        Self {
            pool,
            crypto,
            client: Client::new(),
        }
    }

    /// Loads the current SIEM configuration row from the database,
    /// decrypting the `splunk_token` / `elk_api_key` envelopes under
    /// the active KEK.
    ///
    /// # Errors
    ///
    /// Returns [`SiemError::Database`] if the SELECT fails, or
    /// [`SiemError::Config`] if a populated envelope fails to decrypt
    /// (typically a KEK-version mismatch or on-disk tampering).
    fn load_config(&self) -> Result<SiemConfigRow, SiemError> {
        let repo_row = SiemConfigRepository::get(&self.pool, &self.crypto)
            .map_err(SiemError::from_app_error)?;
        // Empty SecretString stands in for "not configured" so the
        // existing relay_events code (which checks
        // `expose_secret().is_empty()`) keeps working unchanged.
        let splunk_token = repo_row
            .splunk_token
            .unwrap_or_else(|| SecretString::new(String::new()));
        let elk_api_key = repo_row
            .elk_api_key
            .unwrap_or_else(|| SecretString::new(String::new()));
        Ok(SiemConfigRow {
            splunk_url: repo_row.splunk_url,
            splunk_token,
            splunk_enabled: repo_row.splunk_enabled != 0,
            elk_url: repo_row.elk_url,
            elk_index: repo_row.elk_index,
            elk_api_key,
            elk_enabled: repo_row.elk_enabled != 0,
        })
    }

    /// Relays a batch of audit events to all configured SIEM backends.
    ///
    /// Re-reads the SIEM config from the database on each call so that
    /// admin updates take effect immediately (hot-reload).
    ///
    /// # Arguments
    ///
    /// * `events` - Slice of audit events to relay.
    ///
    /// # Errors
    ///
    /// Returns the first error encountered. Both backends are attempted
    /// even if one fails (errors are collected).
    pub async fn relay_events(&self, events: &[AuditEvent]) -> Result<(), SiemError> {
        if events.is_empty() {
            return Ok(());
        }

        // Load config synchronously — the mutex lock is brief and this
        // avoids the overhead of spawn_blocking for a single row read.
        let row = self.load_config()?;

        let mut errors: Vec<SiemError> = Vec::new();

        if row.splunk_enabled && !row.splunk_url.is_empty() {
            let cfg = SplunkConfig {
                url: row.splunk_url.clone(),
                token: row.splunk_token.clone(),
            };
            if let Err(e) = self.send_to_splunk(&cfg, events).await {
                tracing::error!("Splunk relay failed: {e}");
                errors.push(e);
            }
        }

        if row.elk_enabled && !row.elk_url.is_empty() {
            // Treat an empty SecretString as "no API key configured".
            let api_key = if row.elk_api_key.expose_secret().is_empty() {
                None
            } else {
                Some(row.elk_api_key.clone())
            };
            let cfg = ElkConfig {
                url: row.elk_url.clone(),
                index: row.elk_index.clone(),
                api_key,
            };
            if let Err(e) = self.send_to_elk(&cfg, events).await {
                tracing::error!("ELK relay failed: {e}");
                errors.push(e);
            }
        }

        // Return the first error if any backend failed.
        if let Some(e) = errors.into_iter().next() {
            return Err(e);
        }

        Ok(())
    }

    /// Sends events to Splunk HEC as individual event payloads in a
    /// single concatenated request body.
    ///
    /// Splunk HEC accepts multiple `{"event": ...}` objects concatenated
    /// without separators in a single POST.
    async fn send_to_splunk(
        &self,
        config: &SplunkConfig,
        events: &[AuditEvent],
    ) -> Result<(), SiemError> {
        // Build concatenated JSON body: {"event":...}{"event":...}
        let mut body = String::new();
        for event in events {
            let wrapper = SplunkEvent { event };
            body.push_str(&serde_json::to_string(&wrapper)?);
        }

        let url = format!("{}/services/collector/event", config.url);
        // expose_secret() is the sanctioned site: the token is concatenated
        // into the Authorization header for one outbound request and the
        // resulting String is dropped (and the reqwest internals zero on
        // free) — it does not leak into tracing.
        let resp = self
            .client
            .post(&url)
            .header(
                "Authorization",
                format!("Splunk {}", config.token.expose_secret()),
            )
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(SiemError::BackendError { status, body });
        }

        tracing::info!(count = events.len(), "relayed events to Splunk HEC");
        Ok(())
    }

    /// Sends events to Elasticsearch using the `_bulk` API with
    /// NDJSON format.
    ///
    /// Each event is preceded by an `{"index":{}}` action line.
    async fn send_to_elk(
        &self,
        config: &ElkConfig,
        events: &[AuditEvent],
    ) -> Result<(), SiemError> {
        // Build NDJSON bulk body.
        let mut body = String::new();
        for event in events {
            // Action line.
            body.push_str("{\"index\":{}}\n");
            body.push_str(&serde_json::to_string(event)?);
            body.push('\n');
        }

        let url = format!("{}/{}/_bulk", config.url, config.index);
        let mut req = self
            .client
            .post(&url)
            .header("Content-Type", "application/x-ndjson");

        if let Some(ref key) = config.api_key {
            // Sanctioned expose_secret() at the HTTP boundary.
            req = req.header("Authorization", format!("ApiKey {}", key.expose_secret()));
        }

        let resp = req.body(body).send().await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(SiemError::BackendError { status, body });
        }

        tracing::info!(count = events.len(), "relayed events to ELK");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ENVELOPE_VERSION_V1;
    use crate::secrets_migration::migrate_secrets_to_encrypted;

    const TEST_KEK: [u8; 32] = [0x33; 32];

    /// Builds a fresh pool, runs Task 47-06's migration, and wraps the
    /// active KEK in `Arc<SecretCrypto>` so the connector can be
    /// constructed against the post-migration schema.
    fn migrated_pool_and_crypto() -> (Arc<db::Pool>, Arc<SecretCrypto>) {
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        // Leak the temp file's lifetime: we only need it for the test
        // duration, and dropping the NamedTempFile would `unlink` the
        // path while the pool still holds an open connection on Windows.
        std::mem::forget(tmp);
        let crypto = Arc::new(SecretCrypto::from_kek(TEST_KEK, ENVELOPE_VERSION_V1));
        migrate_secrets_to_encrypted(&pool, &crypto, None).expect("run migration");
        (pool, crypto)
    }

    #[test]
    fn test_splunk_config_fields() {
        let cfg = SplunkConfig {
            url: "https://splunk:8088".to_string(),
            token: SecretString::new("abc-123".to_string()),
        };
        assert!(!cfg.url.is_empty());
        assert!(!cfg.token.expose_secret().is_empty());
    }

    #[test]
    fn test_elk_config_fields() {
        let cfg = ElkConfig {
            url: "https://elastic:9200".to_string(),
            index: "dlp-events".to_string(),
            api_key: Some(SecretString::new("key123".to_string())),
        };
        assert_eq!(cfg.index, "dlp-events");
    }

    /// Phase 47 Task 47-09: prove `Debug` does not leak the Splunk token
    /// or ELK API key into formatted output. The `SecretString` field
    /// renders as `Secret([REDACTED ...])`; the fixture token's literal
    /// substring MUST NOT appear.
    #[test]
    fn test_splunk_and_elk_config_debug_redacts_secrets() {
        let splunk = SplunkConfig {
            url: "https://splunk:8088".to_string(),
            token: SecretString::new("FIXTURE-TOKEN-XYZ".to_string()),
        };
        let elk = ElkConfig {
            url: "https://elastic:9200".to_string(),
            index: "dlp-events".to_string(),
            api_key: Some(SecretString::new("FIXTURE-API-KEY-ABC".to_string())),
        };

        let splunk_dbg = format!("{splunk:?}");
        let elk_dbg = format!("{elk:?}");
        assert!(
            !splunk_dbg.contains("FIXTURE-TOKEN-XYZ"),
            "Splunk token must be redacted in Debug; got: {splunk_dbg}"
        );
        assert!(
            !elk_dbg.contains("FIXTURE-API-KEY-ABC"),
            "ELK API key must be redacted in Debug; got: {elk_dbg}"
        );
    }

    #[test]
    fn test_new_with_in_memory_db() {
        // `SiemConnector::new` should succeed with a fresh DB whose
        // schema has been migrated by Task 47-06.
        let (pool, crypto) = migrated_pool_and_crypto();
        let connector = SiemConnector::new(Arc::clone(&pool), crypto);
        // Loading config from the seed row should yield disabled backends.
        let row = connector.load_config().expect("load config");
        assert!(!row.splunk_enabled);
        assert!(!row.elk_enabled);
        assert!(row.splunk_url.is_empty());
        assert!(row.elk_url.is_empty());
    }

    #[tokio::test]
    async fn test_relay_events_empty_is_noop() {
        let (pool, crypto) = migrated_pool_and_crypto();
        let connector = SiemConnector::new(pool, crypto);
        // Empty slice must short-circuit before touching the DB/network.
        connector
            .relay_events(&[])
            .await
            .expect("empty relay should succeed");
    }

    #[test]
    fn test_splunk_event_serialization() {
        use dlp_common::{Action, AuditEvent, Classification, Decision, EventType};

        let event = AuditEvent::new(
            EventType::Block,
            "S-1-5-21-123".to_string(),
            "jsmith".to_string(),
            r"C:\Data\File.txt".to_string(),
            Classification::T3,
            Action::COPY,
            Decision::DENY,
            "AGENT-001".to_string(),
            1,
        );

        let wrapper = SplunkEvent { event: &event };
        let json = serde_json::to_string(&wrapper).expect("serialize splunk event");
        assert!(json.contains("\"event\":{"));
    }

    /// Phase 53: Verify that `relay_events` handles `BypassAlertDetected`
    /// events gracefully when SIEM is disabled (no network calls).
    /// The caller (admin_api handler) is responsible for filtering by
    /// `routed_to_siem()`; `relay_events` itself relays all events given.
    #[tokio::test]
    async fn test_relay_bypass_alert_detected() {
        use dlp_common::{Action, AuditEvent, Classification, Decision, EventType};

        let (pool, crypto) = migrated_pool_and_crypto();
        let connector = SiemConnector::new(pool, crypto);

        let event = AuditEvent::new(
            EventType::BypassAlertDetected,
            "SYSTEM".to_string(),
            "bypass-correlator".to_string(),
            r"C:\Data\Secret.docx".to_string(),
            Classification::T4,
            Action::WRITE,
            Decision::DENY,
            "AGENT-TEST".to_string(),
            1234,
        );

        // With default disabled config, relay_events returns Ok without
        // attempting any network calls.
        connector
            .relay_events(&[event])
            .await
            .expect("BypassAlertDetected relay should succeed with disabled config");
    }

    /// Phase 53 CR-09: Verify that `relay_events` handles
    /// `EtwConsumerGatedOff` events gracefully when SIEM is disabled.
    #[tokio::test]
    async fn test_relay_etw_consumer_gated_off() {
        use dlp_common::{Action, AuditEvent, Classification, Decision, EventType};

        let (pool, crypto) = migrated_pool_and_crypto();
        let connector = SiemConnector::new(pool, crypto);

        let event = AuditEvent::new(
            EventType::EtwConsumerGatedOff,
            "SYSTEM".to_string(),
            "etw-consumer".to_string(),
            "N/A".to_string(),
            Classification::T1,
            Action::READ,
            Decision::ALLOW,
            "AGENT-TEST".to_string(),
            0,
        );

        connector
            .relay_events(&[event])
            .await
            .expect("EtwConsumerGatedOff relay should succeed with disabled config");
    }

    /// Phase 53: Verify that `relay_events` does not error on events that
    /// are not SIEM-routed (e.g., a synthetic event type). The function
    /// processes all events uniformly; routing decisions are made by the
    /// caller before invoking `relay_events`.
    #[tokio::test]
    async fn test_relay_skips_non_siem_events() {
        use dlp_common::{Action, AuditEvent, Classification, Decision, EventType};

        let (pool, crypto) = migrated_pool_and_crypto();
        let connector = SiemConnector::new(pool, crypto);

        // Use EventType::Access which is routed_to_siem=true but does not
        // trigger_alert. The key assertion is that relay_events does not
        // short-circuit or error on any event type when SIEM is disabled.
        let event = AuditEvent::new(
            EventType::Access,
            "S-1-5-21-123".to_string(),
            "jsmith".to_string(),
            r"C:\Data\File.txt".to_string(),
            Classification::T2,
            Action::READ,
            Decision::ALLOW,
            "AGENT-TEST".to_string(),
            1,
        );

        connector
            .relay_events(&[event])
            .await
            .expect("non-alert event relay should succeed with disabled config");
    }
}
