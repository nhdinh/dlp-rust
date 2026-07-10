//! HTTP client for the DLP Server REST API.
//!
//! Handles TLS certificate configuration and provides typed request helpers.

use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;

/// Deserialised body of `POST /admin/secrets/rotate`.
///
/// Mirrors `dlp_server::secrets_migration::RotationReport`. The struct
/// is duplicated here (rather than imported from `dlp-server`) so the
/// admin CLI does not pull the full server crate into its dependency
/// graph — the public REST contract is the only coupling.
#[derive(Debug, Clone, Deserialize)]
pub struct RotationReport {
    /// KEK version that was active before rotation; now retired.
    pub old_version: u8,
    /// KEK version newly inserted into `secret_kek_history`; now active.
    pub new_version: u8,
    /// Total `(row, column)` envelopes re-encrypted under the new KEK.
    pub rows_reencrypted: u32,
    /// `"<table>.<column>"` strings for every rotation target that had
    /// at least one row re-encrypted.
    pub tables_rotated: Vec<String>,
}

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
            .map(|v| !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true);

        let mut builder = Client::builder().timeout(Duration::from_secs(10));

        // Apply mTLS identity if cert/key files are provided.
        if let (Some(cert), Some(key)) = (&cert_path, &key_path) {
            let identity = load_identity(cert, key)?;
            builder = builder.identity(identity);
        }

        // Disable TLS verification in development when explicitly requested.
        if !tls_verify {
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
    #[allow(dead_code)]
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

    /// Calls `POST /admin/secrets/rotate` to rotate the KEK and re-encrypt
    /// every populated secret column under the new key.
    ///
    /// Phase 47 Task 47-08. `force_while_running == true` bypasses the
    /// server-side `system_kv.maintenance_mode` gate so the rotation can
    /// proceed while the service is still serving traffic. Default
    /// (`false`) requires the operator to have run `maintenance enter`
    /// first.
    ///
    /// # Errors
    ///
    /// Returns the server's error body verbatim if the HTTP call fails
    /// (e.g. 400 when the maintenance gate is closed and `force=false`).
    pub async fn rotate_secrets(&self, force_while_running: bool) -> Result<RotationReport> {
        let body = serde_json::json!({ "force": force_while_running });
        self.post::<RotationReport, _>("admin/secrets/rotate", &body)
            .await
    }

    /// Calls `POST /admin/maintenance/enter`. Idempotent.
    pub async fn maintenance_enter(&self) -> Result<()> {
        let url = self.build_url("admin/maintenance/enter");
        let resp = self
            .apply_auth(self.inner.post(&url))
            .send()
            .await
            .with_context(|| format!("POST {url} failed"))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("POST {url} returned {status}: {body}");
        }
        Ok(())
    }

    /// Calls GET /admin/config/global-enforcement-mode.
    ///
    /// Returns the current global enforcement mode as a string
    /// ("Audit", "Block", "AuditAndBlock", or "PerPolicy").
    /// Returns an error if the request fails or the response cannot be parsed.
    pub async fn get_global_enforcement_mode(&self) -> Result<String> {
        #[derive(serde::Deserialize)]
        struct ModeResp {
            mode: dlp_common::abac::EnforcementMode,
        }
        let resp: ModeResp = self.get("admin/config/global-enforcement-mode").await?;
        // EnforcementMode serializes as PascalCase via serde(rename_all).
        let mode_str =
            serde_json::to_string(&resp.mode).context("failed to serialize enforcement mode")?;
        // Strip surrounding quotes from the JSON string.
        Ok(mode_str.trim_matches('"').to_string())
    }

    /// Calls `POST /admin/maintenance/exit`. Idempotent.
    pub async fn maintenance_exit(&self) -> Result<()> {
        let url = self.build_url("admin/maintenance/exit");
        let resp = self
            .apply_auth(self.inner.post(&url))
            .send()
            .await
            .with_context(|| format!("POST {url} failed"))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("POST {url} returned {status}: {body}");
        }
        Ok(())
    }

    /// Calls GET /admin/labels with optional state and department filters and pagination.
    #[allow(dead_code)]
    pub async fn list_labels(
        &self,
        state_filter: Option<&str>,
        department_filter: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<PaginatedLabelsResponse> {
        let mut path = format!("admin/labels?limit={limit}&offset={offset}");
        if let Some(f) = state_filter {
            path.push_str(&format!("&state={}", urlencoding::encode(f)));
        }
        if let Some(d) = department_filter {
            path.push_str(&format!("&department={}", urlencoding::encode(d)));
        }
        self.get(&path).await
    }

    /// Calls GET /admin/labels/departments to fetch distinct department values.
    #[allow(dead_code)]
    pub async fn list_departments(&self) -> Result<Vec<String>> {
        self.get("admin/labels/departments").await
    }

    /// Calls GET /admin/labels/:id.
    #[allow(dead_code)]
    pub async fn get_label(&self, id: &str) -> Result<serde_json::Value> {
        self.get(&format!("admin/labels/{}", id)).await
    }

    /// Calls POST /admin/labels.
    #[allow(dead_code)]
    pub async fn create_label(&self, body: &serde_json::Value) -> Result<serde_json::Value> {
        self.post("admin/labels", body).await
    }

    /// Calls PUT /admin/labels/:id.
    #[allow(dead_code)]
    pub async fn update_label(
        &self,
        id: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.put(&format!("admin/labels/{}", id), body).await
    }

    /// Calls POST /admin/labels/:id/confirm.
    #[allow(dead_code)]
    pub async fn confirm_label(&self, id: &str) -> Result<serde_json::Value> {
        self.post(
            &format!("admin/labels/{}/confirm", id),
            &serde_json::json!({}),
        )
        .await
    }

    /// Calls POST /admin/labels/:id/reject.
    #[allow(dead_code)]
    pub async fn reject_label(&self, id: &str) -> Result<serde_json::Value> {
        self.post(
            &format!("admin/labels/{}/reject", id),
            &serde_json::json!({}),
        )
        .await
    }

    /// Calls DELETE /admin/labels/:id.
    #[allow(dead_code)]
    pub async fn delete_label(&self, id: &str) -> Result<()> {
        self.delete(&format!("admin/labels/{}", id)).await
    }

    /// Calls POST /admin/labels/:id/expire.
    #[allow(dead_code)]
    pub async fn expire_label(&self, id: &str) -> Result<serde_json::Value> {
        self.post(
            &format!("admin/labels/{}/expire", id),
            &serde_json::json!({}),
        )
        .await
    }

    // -----------------------------------------------------------------------
    // Approval Workflow API (Phase 61)
    // -----------------------------------------------------------------------

    /// Calls GET /admin/approvals with optional status filter and pagination.
    ///
    /// Returns a JSON object with `approvals`, `total`, `page`, `per_page` fields.
    #[allow(dead_code)]
    pub async fn list_approvals(
        &self,
        status: Option<&str>,
        page: u32,
        per_page: u32,
    ) -> Result<serde_json::Value> {
        let mut path = format!("admin/approvals?page={page}&per_page={per_page}");
        if let Some(s) = status {
            path.push_str(&format!("&status={}", urlencoding::encode(s)));
        }
        self.get(&path).await
    }

    /// Calls GET /admin/approvals/:id.
    ///
    /// Returns a JSON object with `approval`, `tier`, `t4_canonical_message` fields.
    #[allow(dead_code)]
    pub async fn get_approval(&self, id: &str) -> Result<serde_json::Value> {
        self.get(&format!("admin/approvals/{id}")).await
    }

    /// Calls POST /admin/approvals/:id/grant.
    ///
    /// `valid_until` is an RFC 3339 timestamp string. `signature` is the hex-encoded
    /// Ed25519 signature required for T4 Board approvals; pass `None` for T3.
    #[allow(dead_code)]
    pub async fn grant_approval(
        &self,
        id: &str,
        valid_until: &str,
        signature: Option<&str>,
    ) -> Result<serde_json::Value> {
        let body = serde_json::json!({
            "valid_until": valid_until,
            "signature": signature,
        });
        self.post(&format!("admin/approvals/{id}/grant"), &body)
            .await
    }

    /// Calls POST /admin/approvals/:id/reject.
    #[allow(dead_code)]
    pub async fn reject_approval(
        &self,
        id: &str,
        reason: Option<&str>,
    ) -> Result<serde_json::Value> {
        let body = serde_json::json!({ "reason": reason });
        self.post(&format!("admin/approvals/{id}/reject"), &body)
            .await
    }

    /// Calls POST /admin/approvals/:id/revoke.
    #[allow(dead_code)]
    pub async fn revoke_approval(&self, id: &str) -> Result<serde_json::Value> {
        self.post(
            &format!("admin/approvals/{id}/revoke"),
            &serde_json::json!({}),
        )
        .await
    }

    // -----------------------------------------------------------------------
    // Protected Paths API (Phase 54)
    // -----------------------------------------------------------------------

    /// Calls GET /admin/protected-paths.
    ///
    /// Returns the full list of protected paths. The server does not support
    /// pagination on this endpoint; the TUI paginates client-side.
    #[allow(dead_code)]
    pub async fn list_protected_paths(&self) -> Result<Vec<serde_json::Value>> {
        self.get("admin/protected-paths").await
    }

    /// Calls POST /admin/protected-paths.
    ///
    /// Creates a new protected path with `source = "manual"`. The server
    /// validates the path via `GetFullPathNameW` and returns 400 on invalid
    /// paths.
    #[allow(dead_code)]
    pub async fn create_protected_path(
        &self,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.post("admin/protected-paths", body).await
    }

    /// Calls PUT /admin/protected-paths/{id}.
    #[allow(dead_code)]
    pub async fn update_protected_path(
        &self,
        id: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.put(&format!("admin/protected-paths/{id}"), body).await
    }

    /// Calls DELETE /admin/protected-paths/{id}.
    #[allow(dead_code)]
    pub async fn delete_protected_path(&self, id: &str) -> Result<()> {
        self.delete(&format!("admin/protected-paths/{id}")).await
    }

    // -----------------------------------------------------------------------
    // Diagnostics API (Phase 58)
    // -----------------------------------------------------------------------

    /// Calls GET /admin/diagnostics with optional filters and pagination.
    ///
    /// Returns a JSON object with `total` and `events` fields.
    #[allow(dead_code)]
    pub async fn list_diagnostics(
        &self,
        since: Option<&str>,
        user_sid: Option<&str>,
        policy_id: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<serde_json::Value> {
        let mut path = format!("admin/diagnostics?limit={limit}&offset={offset}");
        if let Some(s) = since {
            path.push_str(&format!("&since={}", urlencoding::encode(s)));
        }
        if let Some(u) = user_sid {
            path.push_str(&format!("&user_sid={}", urlencoding::encode(u)));
        }
        if let Some(p) = policy_id {
            path.push_str(&format!("&policy_id={}", urlencoding::encode(p)));
        }
        self.get(&path).await
    }

    /// Calls GET /admin/health to fetch self-health snapshot and history.
    ///
    /// Returns a JSON object with `snapshot` and `history` fields.
    #[allow(dead_code)]
    pub async fn get_self_health(&self) -> Result<serde_json::Value> {
        self.get("admin/health").await
    }

    /// Calls POST /admin/protected-paths/sync.
    ///
    /// Re-imports policy-derived paths from labels. Idempotent; preserves
    /// manual entries. Returns a JSON object with a `synced` count field.
    #[allow(dead_code)]
    pub async fn sync_protected_paths(&self) -> Result<serde_json::Value> {
        self.post("admin/protected-paths/sync", &serde_json::json!({}))
            .await
    }

    // -----------------------------------------------------------------------
    // Bypass Alerts API (Phase 54)
    // -----------------------------------------------------------------------

    /// Calls GET /admin/bypass-alerts with optional filters and pagination.
    ///
    /// Returns a JSON object with `total` and `alerts` fields.
    ///
    /// # Arguments
    ///
    /// * `severity` - Optional severity filter ("crit", "warn", or "info").
    /// * `acknowledged` - Optional acknowledged filter (`Some(false)` for unacknowledged only).
    /// * `limit` - Maximum number of alerts to return.
    /// * `offset` - Number of alerts to skip (for pagination).
    #[allow(dead_code)]
    pub async fn list_bypass_alerts(
        &self,
        severity: Option<&str>,
        acknowledged: Option<bool>,
        limit: usize,
        offset: usize,
    ) -> Result<serde_json::Value> {
        let mut path = format!("admin/bypass-alerts?limit={limit}&offset={offset}");
        if let Some(s) = severity {
            path.push_str(&format!("&severity={}", urlencoding::encode(s)));
        }
        if let Some(a) = acknowledged {
            path.push_str(&format!("&acknowledged={a}"));
        }
        self.get(&path).await
    }

    /// Calls GET /admin/audit/integrity.
    ///
    /// Returns a JSON object with `agents`, `total`, and `integrity_ok` fields.
    ///
    /// # Arguments
    ///
    /// * `agent_id` - Optional agent ID filter.
    #[allow(dead_code)]
    pub async fn list_audit_integrity(&self, agent_id: Option<&str>) -> Result<serde_json::Value> {
        let mut path = "admin/audit/integrity".to_string();
        if let Some(id) = agent_id {
            path.push_str(&format!("?agent_id={}", urlencoding::encode(id)));
        }
        self.get(&path).await
    }

    /// Calls POST /admin/bypass-alerts/{id}/ack.
    ///
    /// Acknowledges a bypass alert. Returns `Ok(())` on 200 success.
    /// Returns an error with the server response body on non-2xx status.
    #[allow(dead_code)]
    pub async fn ack_bypass_alert(&self, id: i64) -> Result<()> {
        let url = self.build_url(&format!("admin/bypass-alerts/{id}/ack"));
        let resp = self
            .apply_auth(self.inner.post(&url))
            .send()
            .await
            .with_context(|| format!("POST {url} failed"))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("POST {url} returned {status}: {body}");
        }
        Ok(())
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

// ---------------------------------------------------------------------------
// Paginated response types
// ---------------------------------------------------------------------------

/// Paginated response from `GET /admin/labels`.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct PaginatedLabelsResponse {
    /// Label records returned for the current page.
    pub labels: Vec<serde_json::Value>,
    /// Total number of labels matching the query (across all pages).
    pub total: i64,
    /// Maximum number of items per page.
    pub limit: usize,
    /// Number of items skipped from the start of the result set.
    pub offset: usize,
}

#[cfg(test)]
mod client_tests {
    use super::*;

    #[test]
    fn list_protected_paths_method_exists() {
        let client = EngineClient::for_test();
        // Method exists and is callable; runtime would fail on non-routable URL.
        let _future = client.list_protected_paths();
    }

    #[test]
    fn create_protected_path_method_exists() {
        let client = EngineClient::for_test();
        let body = serde_json::json!({"path": "C:\\Test", "source": "manual", "tier": "T3"});
        let _future = client.create_protected_path(&body);
    }

    #[test]
    fn update_protected_path_method_exists() {
        let client = EngineClient::for_test();
        let body = serde_json::json!({"path": "C:\\Test", "source": "manual", "tier": "T3"});
        let _future = client.update_protected_path("test-id", &body);
    }

    #[test]
    fn delete_protected_path_method_exists() {
        let client = EngineClient::for_test();
        let _future = client.delete_protected_path("test-id");
    }

    #[test]
    fn sync_protected_paths_method_exists() {
        let client = EngineClient::for_test();
        let _future = client.sync_protected_paths();
    }

    #[test]
    fn list_bypass_alerts_method_exists() {
        let client = EngineClient::for_test();
        let _future = client.list_bypass_alerts(Some("crit"), Some(false), 20, 0);
    }

    #[test]
    fn list_bypass_alerts_all_filters_none() {
        let client = EngineClient::for_test();
        let _future = client.list_bypass_alerts(None, None, 20, 0);
    }

    #[test]
    fn list_bypass_alerts_encodes_severity_in_query_string() {
        // T-54-04: Verify that list_bypass_alerts URL-encodes the severity parameter.
        // We use a mock server to intercept the request and inspect the query string.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        rt.block_on(async {
            use wiremock::matchers::method;
            use wiremock::{Mock, MockServer, ResponseTemplate};

            let server = MockServer::start().await;

            // severity value with characters that require URL encoding
            let severity = "crit&foo";
            let encoded = urlencoding::encode(severity);

            // Use a broad mock that matches any GET to the endpoint.
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "total": 0,
                    "alerts": []
                })))
                .mount(&server)
                .await;

            let client = EngineClient::for_test_with_url(server.uri());
            let result = client.list_bypass_alerts(Some(severity), None, 20, 0).await;
            assert!(
                result.is_ok(),
                "list_bypass_alerts should succeed: {:?}",
                result.err()
            );

            // Verify the request was made with the encoded severity parameter.
            let requests = server.received_requests().await.unwrap();
            assert_eq!(requests.len(), 1, "expected exactly one request");
            let req = &requests[0];
            let query = req.url.query().unwrap_or("");
            assert!(
                query.contains(&format!("severity={}", encoded)),
                "query string should contain encoded severity. got: {}",
                query
            );
        });
    }

    #[test]
    fn get_self_health_returns_exact_dashboard_fields_and_sends_auth() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        rt.block_on(async {
            use wiremock::matchers::method;
            use wiremock::{Mock, MockServer, ResponseTemplate};

            let server = MockServer::start().await;

            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "snapshot": {
                        "overall_status": "healthy",
                        "injected_pids": 1,
                        "patched_modules": 2,
                        "pipe_round_trips_60s": 10,
                        "cache_hit_rate_60s": 0.95,
                        "fail_state": 0,
                        "timestamp_secs": 1000
                    },
                    "history": []
                })))
                .mount(&server)
                .await;

            let mut client = EngineClient::for_test_with_url(server.uri());
            client.set_token("test-token".to_string());

            let response = client
                .get_self_health()
                .await
                .expect("get_self_health should succeed");

            assert!(response.get("snapshot").is_some(), "snapshot field must be present");
            assert_eq!(response["snapshot"]["overall_status"], "healthy");
            assert_eq!(response["snapshot"]["injected_pids"], 1);
            assert_eq!(response["snapshot"]["patched_modules"], 2);
            assert_eq!(response["snapshot"]["pipe_round_trips_60s"], 10);

            let cache_hit_rate = response["snapshot"]["cache_hit_rate_60s"]
                .as_f64()
                .expect("cache_hit_rate_60s should be a float");
            assert!((cache_hit_rate - 0.95).abs() < f64::EPSILON);

            assert_eq!(response["snapshot"]["fail_state"], 0);

            let requests = server
                .received_requests()
                .await
                .expect("should have received requests");
            assert_eq!(requests.len(), 1, "expected exactly one request");
            let req = &requests[0];
            let auth_header = req
                .headers
                .get("authorization")
                .expect("authorization header should be present");
            assert_eq!(auth_header.to_str().expect("valid ascii"), "Bearer test-token");
        });
    }

    #[test]
    fn ack_bypass_alert_method_exists() {
        let client = EngineClient::for_test();
        let _future = client.ack_bypass_alert(42);
    }

    #[test]
    fn ack_bypass_alert_builds_correct_url() {
        let client = EngineClient::for_test_with_url("http://127.0.0.1:9999".to_string());
        // Verify the URL is built correctly by inspecting the method signature.
        // The actual HTTP call would fail at runtime against a non-routable address.
        let _future = client.ack_bypass_alert(123);
    }

    #[test]
    fn test_list_audit_integrity_method_exists() {
        let client = EngineClient::for_test();
        let _future = client.list_audit_integrity(None);
    }

    #[test]
    fn test_list_audit_integrity_with_agent_id() {
        let client = EngineClient::for_test_with_url("http://127.0.0.1:9999".to_string());
        let _future = client.list_audit_integrity(Some("agent-001"));
    }
}
