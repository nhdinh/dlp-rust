//! Batched SIEM relay for Splunk HEC and ELK (P5-T05).
//!
//! Reads SIEM endpoint configuration from the `siem_config` table on
//! every relay call (hot-reload) and relays audit events to one or both
//! backends. Events are batched in a single HTTP request per backend
//! for efficiency.

use std::sync::Arc;

use dlp_common::AuditEvent;
use reqwest::Client;
use serde::Serialize;

/// Splunk HTTP Event Collector configuration.
#[derive(Debug, Clone)]
pub struct SplunkConfig {
    /// Splunk HEC endpoint URL (e.g., `https://splunk:8088`).
    pub url: String,
    /// HEC authentication token.
    pub token: String,
}

/// Elasticsearch / ELK configuration.
#[derive(Debug, Clone)]
pub struct ElkConfig {
    /// Elasticsearch base URL (e.g., `https://elastic:9200`).
    pub url: String,
    /// Target index name.
    pub index: String,
    /// Optional API key for authentication.
    pub api_key: Option<String>,
}

/// Snapshot of the single `siem_config` row loaded from the database.
#[derive(Debug, Clone)]
struct SiemConfigRow {
    splunk_url: String,
    splunk_token: String,
    splunk_enabled: bool,
    elk_url: String,
    elk_index: String,
    elk_api_key: String,
    elk_enabled: bool,
}

/// SIEM relay that forwards audit events to Splunk and/or ELK.
///
/// Construct via `SiemConnector::new(pool)`. On every `relay_events` call,
/// the connector re-reads the single row from the `siem_config` table so
/// that configuration changes made via the admin API take effect
/// immediately without restarting the server.
#[derive(Debug, Clone)]
pub struct SiemConnector {
    /// Shared SQLite connection pool.
    pool: Arc<db::Pool>,
    /// Shared HTTP client for outbound requests.
    client: Client,
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
impl From<r2d2::PoolError> for SiemError {
    fn from(e: r2d2::PoolError) -> Self {
        SiemError::Database(e.into())
    }
}

impl SiemConnector {
    /// Constructs a `SiemConnector` backed by the given connection pool.
    ///
    /// The connector reads SIEM configuration from the `siem_config`
    /// table on each `relay_events` call. No caching is performed, so
    /// admin updates via the API take effect on the next relay.
    pub fn new(pool: Arc<db::Pool>) -> Self {
        Self {
            pool,
            client: Client::new(),
        }
    }

    /// Loads the current SIEM configuration row from the database.
    ///
    /// # Errors
    ///
    /// Returns [`SiemError::Database`] if the row cannot be read.
    fn load_config(&self) -> Result<SiemConfigRow, SiemError> {
        let conn = self.pool.get().map_err(SiemError::from)?;
        let row = conn.query_row(
            "SELECT splunk_url, splunk_token, splunk_enabled, \
                    elk_url, elk_index, elk_api_key, elk_enabled \
             FROM siem_config WHERE id = 1",
            [],
            |r| {
                Ok(SiemConfigRow {
                    splunk_url: r.get(0)?,
                    splunk_token: r.get(1)?,
                    splunk_enabled: r.get::<_, i64>(2)? != 0,
                    elk_url: r.get(3)?,
                    elk_index: r.get(4)?,
                    elk_api_key: r.get(5)?,
                    elk_enabled: r.get::<_, i64>(6)? != 0,
                })
            },
        )?;
        Ok(row)
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
            let api_key = if row.elk_api_key.is_empty() {
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
        let resp = self
            .client
            .post(&url)
            .header("Authorization", format!("Splunk {}", config.token))
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
            req = req.header("Authorization", format!("ApiKey {key}"));
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

    #[test]
    fn test_splunk_config_fields() {
        let cfg = SplunkConfig {
            url: "https://splunk:8088".to_string(),
            token: "abc-123".to_string(),
        };
        assert!(!cfg.url.is_empty());
        assert!(!cfg.token.is_empty());
    }

    #[test]
    fn test_elk_config_fields() {
        let cfg = ElkConfig {
            url: "https://elastic:9200".to_string(),
            index: "dlp-events".to_string(),
            api_key: Some("key123".to_string()),
        };
        assert_eq!(cfg.index, "dlp-events");
    }

    #[test]
    fn test_new_with_in_memory_db() {
        // `SiemConnector::new` should succeed with a fresh in-memory DB
        // and the seed row inserted by `init_tables`.
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        let connector = SiemConnector::new(Arc::clone(&pool));
        // Loading config from the seed row should yield disabled backends.
        let row = connector.load_config().expect("load config");
        assert!(!row.splunk_enabled);
        assert!(!row.elk_enabled);
        assert!(row.splunk_url.is_empty());
        assert!(row.elk_url.is_empty());
    }

    #[tokio::test]
    async fn test_relay_events_empty_is_noop() {
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        let connector = SiemConnector::new(pool);
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
}
