//! HTTPS client to the Policy Engine (T-16).
//!
//! Evaluates file-access requests against the Policy Engine's REST API using
//! a `reqwest` HTTPS client.  Retries with exponential backoff on transient
//! failures; fails closed (DENY) when the engine is unreachable.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use dlp_common::{EvaluateRequest, EvaluateResponse};
use reqwest::Client;
use tracing::{debug, error, warn};

/// Default base URL for the dlp-server evaluate endpoint.
pub const DEFAULT_ENGINE_URL: &str = "http://127.0.0.1:9090";

/// Maximum number of retry attempts before giving up.
const MAX_RETRIES: u32 = 3;

/// Initial backoff delay between retries.
const INITIAL_BACKOFF: Duration = Duration::from_millis(200);

/// Maximum backoff delay cap.
const MAX_BACKOFF: Duration = Duration::from_secs(4);

/// Errors returned by the Policy Engine client.
#[derive(Debug, thiserror::Error)]
pub enum EngineClientError {
    #[error("Policy Engine is unreachable after {attempts} attempts")]
    Unreachable { attempts: u32 },

    #[error("HTTP error {status} from Policy Engine: {body}")]
    HttpError { status: u16, body: String },

    #[error("TLS verification failed: {0}")]
    TlsError(String),

    #[error("request timeout after {duration:?}")]
    Timeout { duration: Duration },

    #[error("serialisation error: {0}")]
    Serialisation(#[from] serde_json::Error),
}

/// The Policy Engine HTTPS client.
///
/// Wraps a `reqwest::Client` and provides `evaluate` with built-in retry
/// and exponential backoff.  Thread-safe via `Arc`.
#[derive(Clone)]
pub struct EngineClient {
    inner: Arc<Inner>,
}

struct Inner {
    client: Client,
    base_url: String,
    retries: u32,
}

impl EngineClient {
    /// Constructs a new client pointing at `base_url`.
    ///
    /// TLS verification is enabled by default.  Set `tls_verify = false`
    /// only for local development with self-signed certificates.
    pub fn new(base_url: impl Into<String>, _tls_verify: bool) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("failed to build reqwest HTTPS client")?;

        Ok(Self {
            inner: Arc::new(Inner {
                client,
                base_url: base_url.into(),
                retries: MAX_RETRIES,
            }),
        })
    }

    /// Constructs a client with the default URL and TLS verification enabled.
    pub fn default_client() -> Result<Self> {
        Self::new(DEFAULT_ENGINE_URL, true)
    }

    /// Evaluates a request against the Policy Engine.
    ///
    /// On transient failures (network, TLS, 5xx), retries with exponential
    /// backoff up to [`MAX_RETRIES`] attempts.  On permanent failures (4xx),
    /// returns immediately without retry.
    ///
    /// When all retries are exhausted, returns `EngineClientError::Unreachable`
    /// — the caller should fall back to the offline cache.
    pub async fn evaluate(
        &self,
        request: &EvaluateRequest,
    ) -> Result<EvaluateResponse, EngineClientError> {
        let url = format!("{}/evaluate", self.inner.base_url);
        let body = serde_json::to_string(request)?;

        let mut backoff = INITIAL_BACKOFF;
        let mut attempts = 0u32;

        loop {
            attempts += 1;

            match self._send(&url, &body).await {
                Ok(resp) => {
                    debug!(url, attempts, "Policy Engine responded successfully");
                    return Ok(resp);
                }
                Err(e) => {
                    let retryable = Self::is_retryable(&e);

                    if !retryable || attempts >= self.inner.retries {
                        error!(error = %e, attempts, retryable, "Policy Engine evaluation failed");
                        return Err(e);
                    }

                    warn!(error = %e, attempts, ?backoff, "Policy Engine unreachable — retrying");
                    tokio::time::sleep(backoff).await;
                    backoff = backoff.saturating_mul(2).min(MAX_BACKOFF);
                }
            }
        }
    }

    /// Sends a single POST request to the Policy Engine.
    async fn _send(&self, url: &str, body: &str) -> Result<EvaluateResponse, EngineClientError> {
        let response = self
            .inner
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .body(body.to_owned())
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    EngineClientError::Timeout {
                        duration: Duration::from_secs(10),
                    }
                } else if e.is_connect() {
                    EngineClientError::Unreachable { attempts: 1 }
                } else {
                    EngineClientError::TlsError(e.to_string())
                }
            })?;

        let status = response.status().as_u16();

        if response.status().is_server_error() {
            let body = response.text().await.unwrap_or_default();
            return Err(EngineClientError::HttpError { status, body });
        }

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(EngineClientError::HttpError { status, body });
        }

        let body = response
            .text()
            .await
            .map_err(|e| EngineClientError::TlsError(e.to_string()))?;

        let resp: EvaluateResponse = serde_json::from_str(&body)?;
        Ok(resp)
    }

    /// Returns `true` if the error should trigger a retry.
    pub fn is_retryable(e: &EngineClientError) -> bool {
        match e {
            EngineClientError::Unreachable { .. }
            | EngineClientError::TlsError(_)
            | EngineClientError::Timeout { .. } => true,
            EngineClientError::HttpError { status, .. } => *status >= 500,
            EngineClientError::Serialisation(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_retryable_5xx() {
        let err = EngineClientError::HttpError {
            status: 503,
            body: "".to_string(),
        };
        assert!(EngineClient::is_retryable(&err));
    }

    #[test]
    fn test_is_retryable_4xx() {
        let err = EngineClientError::HttpError {
            status: 400,
            body: "bad request".to_string(),
        };
        assert!(!EngineClient::is_retryable(&err));
    }

    #[test]
    fn test_is_retryable_timeout() {
        let err = EngineClientError::Timeout {
            duration: Duration::from_secs(10),
        };
        assert!(EngineClient::is_retryable(&err));
    }

    #[test]
    fn test_engine_client_new() {
        let client = EngineClient::new("http://127.0.0.1:9090", true);
        assert!(client.is_ok());
    }

    #[test]
    fn test_engine_client_default() {
        let client = EngineClient::default_client();
        assert!(client.is_ok());
    }
}
