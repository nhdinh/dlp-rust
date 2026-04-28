//! HTTP client for the DLP Server REST API.
//!
//! Handles TLS certificate configuration and provides typed request helpers.

use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::Client;

/// The DLP Server HTTP client, built from environment variables.
///
/// Supports optional JWT authentication via [`set_token`](EngineClient::set_token).
/// When a token is set, all requests include an `Authorization: Bearer <token>` header.
#[derive(Clone)]
pub struct EngineClient {
    inner: Client,
    base_url: String,
    /// Optional JWT bearer token for authenticated endpoints.
    token: Option<String>,
}

/// Helper: load a mTLS client identity from cert + key PEM files.
fn load_identity(cert_path: &str, key_path: &str) -> Result<reqwest::Identity> {
    let cert_data = std::fs::read(cert_path)
        .with_context(|| format!("failed to read certificate: {cert_path}"))?;
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
            token: None,
        })
    }

    /// The configured base URL.
    #[allow(dead_code)]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Checks that the dlp-server is reachable by calling `GET /health`.
    ///
    /// Returns `Ok(())` if the server responds with a success status code.
    /// Returns a descriptive error guiding the user to use `--connect` if
    /// the server is unreachable.
    pub async fn check_health(&self) -> Result<()> {
        let url = self.build_url("health");
        let result = self.inner.get(&url).send().await;
        match result {
            Ok(resp) if resp.status().is_success() => Ok(()),
            Ok(resp) => {
                anyhow::bail!(
                    "dlp-server at {} returned {} on health check.\n\
                     If the server is at a different address, use: \
                     --connect <host:port>",
                    self.base_url,
                    resp.status()
                );
            }
            Err(_) => {
                anyhow::bail!(
                    "Cannot reach dlp-server at {}.\n\
                     Ensure the server is running, or specify the correct \
                     address with: --connect <host:port>",
                    self.base_url
                );
            }
        }
    }

    /// Constructs a minimal `EngineClient` for unit tests.
    ///
    /// Points to a non-routable address so no actual network traffic is
    /// produced; only the validation paths (which return before any HTTP
    /// call) are exercised in tests.
    #[cfg(test)]
    pub fn for_test() -> Self {
        Self::for_test_with_url("http://127.0.0.1:0".to_string())
    }

    /// Constructs an `EngineClient` pointing at a specific base URL for
    /// integration tests.
    ///
    /// Unlike [`for_test`], this allows the caller to specify a real mock
    /// server address (e.g. `http://127.0.0.1:12345`).
    pub fn for_test_with_url(base_url: String) -> Self {
        let inner = Client::builder()
            .build()
            .expect("test client build must succeed");
        Self {
            inner,
            base_url,
            token: None,
        }
    }

    /// Sets a JWT bearer token for authenticated requests.
    ///
    /// Once set, all subsequent HTTP calls include an
    /// `Authorization: Bearer <token>` header.
    #[allow(dead_code)]
    pub fn set_token(&mut self, token: String) {
        self.token = Some(token);
    }

    /// Logs in to the DLP Server with the given admin credentials and stores the JWT.
    ///
    /// Calls `POST /auth/login` and stores the returned token for subsequent
    /// authenticated requests.
    ///
    /// # Arguments
    ///
    /// * `username` - Admin username.
    /// * `password` - Admin plaintext password.
    ///
    /// # Errors
    ///
    /// Returns an error if the login request fails or credentials are invalid.
    pub async fn login(&mut self, username: &str, password: &str) -> Result<()> {
        let url = format!("{}/{}", self.base_url.trim_end_matches('/'), "auth/login");
        let payload = serde_json::json!({
            "username": username,
            "password": password,
        });
        let resp = self
            .inner
            .post(&url)
            .json(&payload)
            .send()
            .await
            .with_context(|| format!("POST {url} failed"))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("login failed ({status}): {body}");
        }
        #[derive(serde::Deserialize)]
        struct TokenResp {
            token: String,
        }
        let body: TokenResp = resp
            .json()
            .await
            .context("failed to parse login response")?;
        self.token = Some(body.token);
        Ok(())
    }

    /// Builds a request builder with the base URL and optional auth header.
    fn build_url(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }

    /// Attaches the Bearer token to a request if one is set.
    fn apply_auth(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(ref token) = self.token {
            builder.bearer_auth(token)
        } else {
            builder
        }
    }

    /// Sends a GET request and deserialises the JSON response.
    pub async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = self.build_url(path);
        tracing::debug!(url);
        let resp = self
            .apply_auth(self.inner.get(&url))
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
        let url = self.build_url(path);
        tracing::debug!(url);
        let resp = self
            .apply_auth(self.inner.post(&url).json(body))
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
        let url = self.build_url(path);
        tracing::debug!(url);
        let resp = self
            .apply_auth(self.inner.put(&url).json(body))
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
        let url = self.build_url(path);
        tracing::debug!(url);
        let resp = self
            .apply_auth(self.inner.delete(&url))
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
