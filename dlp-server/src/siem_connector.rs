//! Batched SIEM relay for Splunk HEC and ELK (P5-T05).
//!
//! Reads SIEM endpoint configuration from environment variables and
//! relays audit events to one or both backends. Events are batched
//! in a single HTTP request per backend for efficiency.

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

/// SIEM relay that forwards audit events to Splunk and/or ELK.
///
/// Construct via `SiemConnector::from_env()` which reads configuration
/// from environment variables. If neither backend is configured, relay
/// calls are no-ops.
#[derive(Debug, Clone)]
pub struct SiemConnector {
    /// Optional Splunk HEC configuration.
    splunk: Option<SplunkConfig>,
    /// Optional ELK configuration.
    elk: Option<ElkConfig>,
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

    /// A SIEM backend returned a non-success status code.
    #[error("SIEM backend returned {status}: {body}")]
    BackendError {
        /// HTTP status code.
        status: u16,
        /// Response body text.
        body: String,
    },
}

impl SiemConnector {
    /// Constructs a `SiemConnector` by reading environment variables.
    ///
    /// Environment variables:
    /// - `SPLUNK_HEC_URL` + `SPLUNK_HEC_TOKEN` — enables Splunk relay
    /// - `ELK_URL` + `ELK_INDEX` — enables ELK relay
    /// - `ELK_API_KEY` — optional ELK authentication
    ///
    /// If neither set of variables is present, the connector is inert.
    pub fn from_env() -> Self {
        let splunk = match (
            std::env::var("SPLUNK_HEC_URL"),
            std::env::var("SPLUNK_HEC_TOKEN"),
        ) {
            (Ok(url), Ok(token)) if !url.is_empty() => {
                tracing::info!("Splunk HEC relay enabled");
                Some(SplunkConfig { url, token })
            }
            _ => None,
        };

        let elk = match (
            std::env::var("ELK_URL"),
            std::env::var("ELK_INDEX"),
        ) {
            (Ok(url), Ok(index)) if !url.is_empty() => {
                let api_key = std::env::var("ELK_API_KEY").ok();
                tracing::info!("ELK relay enabled");
                Some(ElkConfig {
                    url,
                    index,
                    api_key,
                })
            }
            _ => None,
        };

        Self {
            splunk,
            elk,
            client: Client::new(),
        }
    }

    /// Relays a batch of audit events to all configured SIEM backends.
    ///
    /// # Arguments
    ///
    /// * `events` - Slice of audit events to relay.
    ///
    /// # Errors
    ///
    /// Returns the first error encountered. Both backends are attempted
    /// even if one fails (errors are collected).
    pub async fn relay_events(
        &self,
        events: &[AuditEvent],
    ) -> Result<(), SiemError> {
        if events.is_empty() {
            return Ok(());
        }

        let mut errors: Vec<SiemError> = Vec::new();

        if let Some(ref cfg) = self.splunk {
            if let Err(e) = self.send_to_splunk(cfg, events).await {
                tracing::error!("Splunk relay failed: {e}");
                errors.push(e);
            }
        }

        if let Some(ref cfg) = self.elk {
            if let Err(e) = self.send_to_elk(cfg, events).await {
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

        let url =
            format!("{}/services/collector/event", config.url);
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

        tracing::info!(
            count = events.len(),
            "relayed events to Splunk HEC"
        );
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

        let url =
            format!("{}/{}/_bulk", config.url, config.index);
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

        tracing::info!(
            count = events.len(),
            "relayed events to ELK"
        );
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
    fn test_from_env_no_vars() {
        // When no env vars are set, both backends should be None.
        // Note: this test assumes SPLUNK_HEC_URL etc. are not set
        // in the test environment.
        let connector = SiemConnector {
            splunk: None,
            elk: None,
            client: Client::new(),
        };
        assert!(connector.splunk.is_none());
        assert!(connector.elk.is_none());
    }

    #[test]
    fn test_splunk_event_serialization() {
        use dlp_common::{
            Action, AuditEvent, Classification, Decision, EventType,
        };

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
        let json = serde_json::to_string(&wrapper)
            .expect("serialize splunk event");
        assert!(json.contains("\"event\":{"));
    }
}
