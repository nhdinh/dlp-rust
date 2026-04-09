//! HTTP client for the DLP Server REST API.
//!
//! Handles TLS certificate configuration and provides typed request helpers.

use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::Client;

/// The DLP Server HTTP client, built from environment variables.
#[derive(Clone)]
pub struct EngineClient {
    inner: Client,
    base_url: String,
}

/// Helper: load a mTLS client identity from cert + key PEM files.
fn load_identity(cert_path: &str, key_path: &str) -> Result<reqwest::Identity> {
    let cert_data =
        std::fs::read(cert_path).with_context(|| format!("failed to read certificate: {cert_path}"))?;
    let key_data =
        std::fs::read(key_path).with_context(|| format!("failed to read key: {key_path}"))?;
    let pem = format!(
        "{}\n{}",
        String::from_utf8_lossy(&cert_data),
        String::from_utf8_lossy(&key_data)
    );
    reqwest::Identity::from_pem(pem.as_bytes())
        .context("failed to parse client certificate/key PEM")
}

impl EngineClient {
    /// Resolves the DLP Server URL using auto-detection, then builds
    /// the HTTP client.
    ///
    /// Resolution order: env var -> registry BIND_ADDR -> local port
    /// probe -> compiled default.
    pub fn from_env() -> Result<Self> {
        let base_url = crate::engine::resolve_engine_url();

        let cert_path = std::env::var("DLP_ENGINE_CERT_PATH").ok();
        let key_path = std::env::var("DLP_ENGINE_KEY_PATH").ok();

        let tls_verify = std::env::var("DLP_ENGINE_TLS_VERIFY")
            .map(|v| v == "false")
            .unwrap_or(false);

        let mut builder = Client::builder().timeout(Duration::from_secs(10));

        // Apply mTLS identity if cert/key files are provided.
        if let (Some(cert), Some(key)) = (&cert_path, &key_path) {
            let identity = load_identity(cert, key)?;
            builder = builder.identity(identity);
        }

        // Disable TLS verification in development when explicitly requested.
        if tls_verify {
            tracing::warn!("TLS verification disabled (DLP_ENGINE_TLS_VERIFY=false)");
            builder = builder.danger_accept_invalid_certs(true);
        }

        let client = builder.build().context("failed to build HTTP client")?;

        Ok(Self {
            inner: client,
            base_url,
        })
    }

    /// The configured base URL.
    #[allow(dead_code)]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Sends a GET request and deserialises the JSON response.
    pub async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = format!("{}/{}", self.base_url.trim_end_matches('/'), path.trim_start_matches('/'));
        tracing::debug!(url);
        let resp = self
            .inner
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {url} failed"))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("GET {url} returned {status}: {body}");
        }
        let body = resp
            .json::<T>()
            .await
            .context("response body is not valid JSON")?;
        Ok(body)
    }

    /// Sends a POST request with a JSON body and deserialises the response.
    pub async fn post<T: serde::de::DeserializeOwned, B: serde::Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let url = format!("{}/{}", self.base_url.trim_end_matches('/'), path.trim_start_matches('/'));
        tracing::debug!(url);
        let resp = self
            .inner
            .post(&url)
            .json(body)
            .send()
            .await
            .with_context(|| format!("POST {url} failed"))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("POST {url} returned {status}: {body}");
        }
        let body = resp
            .json::<T>()
            .await
            .context("response body is not valid JSON")?;
        Ok(body)
    }

    /// Sends a PUT request with a JSON body and deserialises the response.
    pub async fn put<T: serde::de::DeserializeOwned, B: serde::Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let url = format!("{}/{}", self.base_url.trim_end_matches('/'), path.trim_start_matches('/'));
        tracing::debug!(url);
        let resp = self
            .inner
            .put(&url)
            .json(body)
            .send()
            .await
            .with_context(|| format!("PUT {url} failed"))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("PUT {url} returned {status}: {body}");
        }
        let body = resp
            .json::<T>()
            .await
            .context("response body is not valid JSON")?;
        Ok(body)
    }

    /// Sends a DELETE request.  Returns `Ok(())` on 204 No Content.
    pub async fn delete(&self, path: &str) -> Result<()> {
        let url = format!("{}/{}", self.base_url.trim_end_matches('/'), path.trim_start_matches('/'));
        tracing::debug!(url);
        let resp = self
            .inner
            .delete(&url)
            .send()
            .await
            .with_context(|| format!("DELETE {url} failed"))?;
        let status = resp.status();
        if !status.is_success() && status.as_u16() != 204 {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("DELETE {url} returned {status}: {body}");
        }
        Ok(())
    }
}

/// Wrapper around `tokio::main`-style blocking runs so submodules don't each
/// need `#[tokio::main]`.
pub fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(f)
}
