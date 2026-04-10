//! Admin REST API that aggregates all management endpoints (P5-T09).
//!
//! Builds the complete axum `Router` with all sub-routes. Public
//! endpoints (health, ready, auth) are unauthenticated. All other
//! routes require a valid JWT Bearer token.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::admin_auth;
use crate::agent_registry;
use crate::audit_store;
use crate::exception_store;
use crate::AppError;
use crate::AppState;

// ---------------------------------------------------------------------------
// Agent credential types
// ---------------------------------------------------------------------------

/// Payload for setting the agent auth hash.
#[derive(Debug, Clone, Deserialize)]
pub struct SetAuthHashRequest {
    /// The bcrypt hash string (must start with `$2`).
    pub hash: String,
}

/// Response after setting or retrieving the agent auth hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthHashResponse {
    /// The bcrypt hash.
    pub hash: String,
    /// ISO 8601 timestamp of last update.
    pub updated_at: String,
}

// ---------------------------------------------------------------------------
// Policy request / response types
// ---------------------------------------------------------------------------

/// Payload for creating or updating a policy.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyPayload {
    /// Unique policy ID (provided by the caller on create).
    pub id: String,
    /// Human-readable policy name.
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
    /// Evaluation priority (lower = evaluated first).
    pub priority: u32,
    /// JSON-encoded conditions array.
    pub conditions: serde_json::Value,
    /// The enforcement action (ALLOW, DENY, etc.).
    pub action: String,
    /// Whether the policy is enabled.
    pub enabled: bool,
}

/// Policy record returned by the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResponse {
    /// Unique policy ID.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
    /// Evaluation priority.
    pub priority: u32,
    /// JSON conditions.
    pub conditions: serde_json::Value,
    /// Enforcement action.
    pub action: String,
    /// Whether the policy is active.
    pub enabled: bool,
    /// Monotonic version number.
    pub version: i64,
    /// ISO 8601 timestamp of last update.
    pub updated_at: String,
}

// ---------------------------------------------------------------------------
// SIEM config request / response types
// ---------------------------------------------------------------------------

/// Read/write payload for SIEM connector configuration.
///
/// Represents the single row of the `siem_config` table. Both the
/// `GET /admin/siem-config` response body and the `PUT
/// /admin/siem-config` request body use this shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemConfigPayload {
    /// Splunk HEC base URL (e.g., `https://splunk:8088`).
    pub splunk_url: String,
    /// Splunk HEC authentication token.
    pub splunk_token: String,
    /// Whether the Splunk backend is active.
    pub splunk_enabled: bool,
    /// Elasticsearch base URL (e.g., `https://elastic:9200`).
    pub elk_url: String,
    /// Target Elasticsearch index name.
    pub elk_index: String,
    /// Optional ELK API key for authentication.
    pub elk_api_key: String,
    /// Whether the ELK backend is active.
    pub elk_enabled: bool,
}

// ---------------------------------------------------------------------------
// Alert router config request / response types
// ---------------------------------------------------------------------------

/// Read/write payload for alert router configuration.
///
/// Represents the editable columns of the single row in the
/// `alert_router_config` table (excluding `id` and `updated_at`). Both the
/// `GET /admin/alert-config` response body and the `PUT /admin/alert-config`
/// request body use this shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AlertRouterConfigPayload {
    /// SMTP server hostname (empty string disables SMTP).
    pub smtp_host: String,
    /// SMTP server port.
    pub smtp_port: u16,
    /// SMTP username for authentication.
    pub smtp_username: String,
    /// SMTP password for authentication (plaintext — see TM-01).
    pub smtp_password: String,
    /// Sender email address.
    pub smtp_from: String,
    /// Recipient email addresses (comma-separated).
    pub smtp_to: String,
    /// Whether SMTP delivery is active.
    pub smtp_enabled: bool,
    /// Webhook endpoint URL (empty string disables webhook; must be https).
    pub webhook_url: String,
    /// Optional shared secret for HMAC signing (not used today — see deferred).
    pub webhook_secret: String,
    /// Whether webhook delivery is active.
    pub webhook_enabled: bool,
}

/// Health/readiness probe response.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    /// Current server status.
    pub status: String,
    /// ISO 8601 timestamp.
    pub timestamp: String,
}

// ---------------------------------------------------------------------------
// TM-02: Webhook URL validation (SSRF hardening)
// ---------------------------------------------------------------------------

/// Validates a webhook URL for SSRF hardening (TM-02).
///
/// Textual validation only — no DNS lookup. RFC1918 private ranges
/// (10/8, 172.16/12, 192.168/16) are ALLOWED because on-prem webhooks
/// to internal Slack/Teams/PagerDuty are a legitimate DLP use case.
///
/// # Rules
///
/// 1. Must parse as a URL.
/// 2. Scheme must be `https`.
/// 3. IPv4 host: reject loopback (127.0.0.0/8) and link-local (169.254.0.0/16).
/// 4. IPv6 host: reject loopback (`::1`) and link-local (`fe80::/10`).
/// 5. Domain hosts and public/RFC1918 IPs are accepted.
///
/// # Errors
///
/// Returns a human-readable reason string on rejection.
///
/// # Examples
///
/// ```ignore
/// assert!(validate_webhook_url("https://hooks.example.com").is_ok());
/// assert!(validate_webhook_url("http://example.com").is_err());
/// assert!(validate_webhook_url("https://127.0.0.1").is_err());
/// ```
pub(crate) fn validate_webhook_url(url: &str) -> Result<(), String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;

    if parsed.scheme() != "https" {
        return Err("scheme must be https".to_string());
    }

    match parsed.host() {
        Some(url::Host::Ipv4(ip)) => {
            if ip.is_loopback() {
                return Err("loopback addresses not allowed".to_string());
            }
            if ip.is_link_local() {
                // `is_link_local` covers 169.254.0.0/16 on stable Rust.
                return Err("link-local addresses not allowed".to_string());
            }
            // RFC1918 (10/8, 172.16/12, 192.168/16) intentionally ALLOWED.
            Ok(())
        }
        Some(url::Host::Ipv6(ip)) => {
            if ip.is_loopback() {
                return Err("loopback addresses not allowed".to_string());
            }
            // G3: Ipv6Addr::is_unicast_link_local is unstable on rustc 1.94,
            // so do the fe80::/10 check manually: first 10 bits == 1111111010,
            // i.e. first segment in 0xfe80..=0xfebf.
            let first_segment = ip.segments()[0];
            if (first_segment & 0xffc0) == 0xfe80 {
                return Err("link-local addresses not allowed".to_string());
            }
            Ok(())
        }
        Some(url::Host::Domain(_)) => {
            // Textual hostname — accept. No DNS lookup (TM-02 ratified).
            Ok(())
        }
        None => Err("URL has no host".to_string()),
    }
}

// ---------------------------------------------------------------------------
// Router construction
// ---------------------------------------------------------------------------

/// Builds the complete admin API router with all routes.
///
/// # Arguments
///
/// * `db` - Shared database handle.
///
/// # Routes
///
/// **Unauthenticated:**
/// - `GET /health` — health probe
/// - `GET /ready` — readiness probe
/// - `POST /auth/login` — admin login
/// - `POST /agents/register` — agent self-registration
/// - `POST /agents/:id/heartbeat` — agent heartbeat
/// - `POST /audit/events` — event ingestion (agent-to-server)
/// - `GET /agent-credentials/auth-hash` — fetch agent auth hash
///
/// **Authenticated (JWT required):**
/// - `GET /agents` — list agents
/// - `GET /agents/:id` — get agent
/// - `GET /audit/events` — query audit events
/// - `GET /audit/events/count` — event count
/// - `GET /policies` — list policies
/// - `GET /policies/:id` — get policy
/// - `PUT /policies/:id` — update policy
/// - `POST /policies` — create policy
/// - `DELETE /policies/:id` — delete policy
/// - `GET /exceptions` — list exceptions
/// - `GET /exceptions/:id` — get exception
/// - `POST /exceptions` — create exception
/// - `PUT /agent-credentials/auth-hash` — set agent auth hash
/// - `PUT /auth/password` — change admin password
/// - `GET /admin/siem-config` — get SIEM connector configuration
/// - `PUT /admin/siem-config` — update SIEM connector configuration
/// - `GET /admin/alert-config` — get alert router configuration
/// - `PUT /admin/alert-config` — update alert router configuration
pub fn admin_router(state: Arc<AppState>) -> Router {
    // Routes that do NOT require authentication.
    let public_routes = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/auth/login", post(admin_auth::login))
        .route("/agents/register", post(agent_registry::register_agent))
        .route("/agents/{id}/heartbeat", post(agent_registry::heartbeat))
        .route("/audit/events", post(audit_store::ingest_events))
        .route("/agent-credentials/auth-hash", get(get_agent_auth_hash));

    // Routes that require a valid JWT.
    let protected_routes = Router::new()
        .route("/agents", get(agent_registry::list_agents))
        .route("/agents/{id}", get(agent_registry::get_agent))
        .route("/audit/events", get(audit_store::query_events))
        .route("/audit/events/count", get(audit_store::get_event_count))
        .route("/policies", get(list_policies))
        .route("/policies", post(create_policy))
        .route("/policies/{id}", get(get_policy))
        .route("/policies/{id}", put(update_policy))
        .route("/policies/{id}", delete(delete_policy))
        .route("/exceptions", get(exception_store::list_exceptions))
        .route("/exceptions/{id}", get(exception_store::get_exception))
        .route("/exceptions", post(exception_store::create_exception))
        .route("/agent-credentials/auth-hash", put(set_agent_auth_hash))
        .route("/auth/password", put(admin_auth::change_password))
        .route("/admin/siem-config", get(get_siem_config_handler))
        .route("/admin/siem-config", put(update_siem_config_handler))
        .route("/admin/alert-config", get(get_alert_config_handler))
        .route("/admin/alert-config", put(update_alert_config_handler))
        .layer(middleware::from_fn(admin_auth::require_auth));

    public_routes.merge(protected_routes).with_state(state)
}

// ---------------------------------------------------------------------------
// Health probes
// ---------------------------------------------------------------------------

/// `GET /health` — liveness probe.
async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        timestamp: Utc::now().to_rfc3339(),
    })
}

/// `GET /ready` — readiness probe.
async fn ready(State(state): State<Arc<AppState>>) -> Result<Json<HealthResponse>, AppError> {
    // Verify the database is accessible.
    let db = Arc::clone(&state.db);
    tokio::task::spawn_blocking(move || {
        let conn = db.conn().lock();
        conn.execute_batch("SELECT 1")
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    Ok(Json(HealthResponse {
        status: "ready".to_string(),
        timestamp: Utc::now().to_rfc3339(),
    }))
}

// ---------------------------------------------------------------------------
// Policy CRUD handlers
// ---------------------------------------------------------------------------

/// `GET /policies` — list all policies.
async fn list_policies(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<PolicyResponse>>, AppError> {
    let db = Arc::clone(&state.db);
    let policies = tokio::task::spawn_blocking(move || {
        let conn = db.conn().lock();
        let mut stmt = conn.prepare(
            "SELECT id, name, description, priority, conditions, \
                    action, enabled, version, updated_at \
             FROM policies ORDER BY priority ASC",
        )?;

        let rows = stmt
            .query_map([], |row| {
                let conditions_str: String = row.get(4)?;
                let conditions: serde_json::Value =
                    serde_json::from_str(&conditions_str).unwrap_or(serde_json::Value::Null);
                Ok(PolicyResponse {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    priority: row.get(3)?,
                    conditions,
                    action: row.get(5)?,
                    enabled: row.get::<_, bool>(6)?,
                    version: row.get(7)?,
                    updated_at: row.get(8)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok::<_, rusqlite::Error>(rows)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    Ok(Json(policies))
}

/// `GET /policies/{id}` — get a single policy.
async fn get_policy(
    State(state): State<Arc<AppState>>,
    Path(policy_id): Path<String>,
) -> Result<Json<PolicyResponse>, AppError> {
    let id = policy_id.clone();
    let db = Arc::clone(&state.db);

    let result = tokio::task::spawn_blocking(move || {
        let conn = db.conn().lock();
        conn.query_row(
            "SELECT id, name, description, priority, conditions, \
                    action, enabled, version, updated_at \
             FROM policies WHERE id = ?1",
            rusqlite::params![id],
            |row| {
                let conditions_str: String = row.get(4)?;
                let conditions: serde_json::Value =
                    serde_json::from_str(&conditions_str).unwrap_or(serde_json::Value::Null);
                Ok(PolicyResponse {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    priority: row.get(3)?,
                    conditions,
                    action: row.get(5)?,
                    enabled: row.get::<_, bool>(6)?,
                    version: row.get(7)?,
                    updated_at: row.get(8)?,
                })
            },
        )
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))?;

    match result {
        Ok(p) => Ok(Json(p)),
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            Err(AppError::NotFound(format!("policy {policy_id} not found")))
        }
        Err(e) => Err(AppError::Database(e)),
    }
}

/// `POST /policies` — create a new policy.
async fn create_policy(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<PolicyPayload>,
) -> Result<(StatusCode, Json<PolicyResponse>), AppError> {
    if payload.id.is_empty() || payload.name.is_empty() {
        return Err(AppError::BadRequest("id and name are required".to_string()));
    }

    let now = Utc::now().to_rfc3339();
    let conditions_json = serde_json::to_string(&payload.conditions)?;

    let resp = PolicyResponse {
        id: payload.id.clone(),
        name: payload.name.clone(),
        description: payload.description.clone(),
        priority: payload.priority,
        conditions: payload.conditions.clone(),
        action: payload.action.clone(),
        enabled: payload.enabled,
        version: 1,
        updated_at: now.clone(),
    };

    let r = resp.clone();
    let db = Arc::clone(&state.db);
    tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let conn = db.conn().lock();
        conn.execute(
            "INSERT INTO policies \
                (id, name, description, priority, conditions, \
                 action, enabled, version, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8)",
            rusqlite::params![
                r.id,
                r.name,
                r.description,
                r.priority,
                conditions_json,
                r.action,
                r.enabled,
                r.updated_at,
            ],
        )?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!(policy_id = %resp.id, "policy created");
    Ok((StatusCode::CREATED, Json(resp)))
}

/// `PUT /policies/{id}` — update an existing policy.
async fn update_policy(
    State(state): State<Arc<AppState>>,
    Path(policy_id): Path<String>,
    Json(payload): Json<PolicyPayload>,
) -> Result<Json<PolicyResponse>, AppError> {
    let now = Utc::now().to_rfc3339();
    let conditions_json = serde_json::to_string(&payload.conditions)?;
    let id = policy_id.clone();
    let db = Arc::clone(&state.db);

    let resp = tokio::task::spawn_blocking(move || -> Result<PolicyResponse, AppError> {
        let conn = db.conn().lock();

        // Increment the version number atomically.
        let rows = conn.execute(
            "UPDATE policies SET \
                    name = ?1, description = ?2, priority = ?3, \
                    conditions = ?4, action = ?5, enabled = ?6, \
                    version = version + 1, updated_at = ?7 \
                 WHERE id = ?8",
            rusqlite::params![
                payload.name,
                payload.description,
                payload.priority,
                conditions_json,
                payload.action,
                payload.enabled,
                now,
                id,
            ],
        )?;

        if rows == 0 {
            return Err(AppError::NotFound(format!("policy {id} not found")));
        }

        // Read back the updated row for the version.
        let version: i64 = conn.query_row(
            "SELECT version FROM policies WHERE id = ?1",
            rusqlite::params![id],
            |row| row.get(0),
        )?;

        Ok(PolicyResponse {
            id,
            name: payload.name,
            description: payload.description,
            priority: payload.priority,
            conditions: payload.conditions,
            action: payload.action,
            enabled: payload.enabled,
            version,
            updated_at: now,
        })
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!(policy_id = %resp.id, "policy updated");
    Ok(Json(resp))
}

/// `DELETE /policies/{id}` — delete a policy.
async fn delete_policy(
    State(state): State<Arc<AppState>>,
    Path(policy_id): Path<String>,
) -> Result<StatusCode, AppError> {
    let id = policy_id.clone();
    let db = Arc::clone(&state.db);

    let rows = tokio::task::spawn_blocking(move || {
        let conn = db.conn().lock();
        conn.execute("DELETE FROM policies WHERE id = ?1", rusqlite::params![id])
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    if rows == 0 {
        return Err(AppError::NotFound(format!("policy {policy_id} not found")));
    }

    tracing::info!(policy_id = %policy_id, "policy deleted");
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Agent credential handlers
// ---------------------------------------------------------------------------

/// `PUT /agent-credentials/auth-hash` — set the agent auth hash (JWT required).
///
/// Validates that the hash looks like a bcrypt string, then upserts into the
/// `agent_credentials` table.
async fn set_agent_auth_hash(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SetAuthHashRequest>,
) -> Result<Json<AuthHashResponse>, AppError> {
    if !payload.hash.starts_with("$2") {
        return Err(AppError::BadRequest(
            "hash must be a bcrypt string (starts with $2)".to_string(),
        ));
    }

    let now = Utc::now().to_rfc3339();
    let hash = payload.hash.clone();
    let ts = now.clone();
    let db = Arc::clone(&state.db);

    tokio::task::spawn_blocking(move || {
        let conn = db.conn().lock();
        conn.execute(
            "INSERT INTO agent_credentials (key, value, updated_at) \
             VALUES ('DLPAuthHash', ?1, ?2) \
             ON CONFLICT(key) DO UPDATE SET value = ?1, updated_at = ?2",
            rusqlite::params![hash, ts],
        )
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!("agent auth hash updated");
    Ok(Json(AuthHashResponse {
        hash: payload.hash,
        updated_at: now,
    }))
}

/// `GET /agent-credentials/auth-hash` — fetch the agent auth hash (public).
///
/// Returns 404 if no hash has been stored yet. Agents call this endpoint
/// on startup and periodically to sync the password hash.
async fn get_agent_auth_hash(
    State(state): State<Arc<AppState>>,
) -> Result<Json<AuthHashResponse>, AppError> {
    let db = Arc::clone(&state.db);
    let result = tokio::task::spawn_blocking(move || {
        let conn = db.conn().lock();
        conn.query_row(
            "SELECT value, updated_at FROM agent_credentials WHERE key = 'DLPAuthHash'",
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))?;

    match result {
        Ok((hash, updated_at)) => Ok(Json(AuthHashResponse { hash, updated_at })),
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            Err(AppError::NotFound("agent auth hash not set".to_string()))
        }
        Err(e) => Err(AppError::Database(e)),
    }
}

// ---------------------------------------------------------------------------
// SIEM config handlers
// ---------------------------------------------------------------------------

/// `GET /admin/siem-config` — returns the current SIEM connector config.
///
/// Reads the single row from `siem_config` and returns it as a JSON
/// [`SiemConfigPayload`]. The row is guaranteed to exist because it is
/// seeded during `Database::open`.
async fn get_siem_config_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<SiemConfigPayload>, AppError> {
    let db = Arc::clone(&state.db);
    let payload = tokio::task::spawn_blocking(move || {
        let conn = db.conn().lock();
        conn.query_row(
            "SELECT splunk_url, splunk_token, splunk_enabled, \
                    elk_url, elk_index, elk_api_key, elk_enabled \
             FROM siem_config WHERE id = 1",
            [],
            |row| {
                Ok(SiemConfigPayload {
                    splunk_url: row.get(0)?,
                    splunk_token: row.get(1)?,
                    splunk_enabled: row.get::<_, i64>(2)? != 0,
                    elk_url: row.get(3)?,
                    elk_index: row.get(4)?,
                    elk_api_key: row.get(5)?,
                    elk_enabled: row.get::<_, i64>(6)? != 0,
                })
            },
        )
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    Ok(Json(payload))
}

/// `PUT /admin/siem-config` — updates the SIEM connector config.
///
/// Overwrites the single row in `siem_config` with the provided values
/// and stamps `updated_at` with the current time. Returns the payload
/// that was written so clients can refresh their local copy.
async fn update_siem_config_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SiemConfigPayload>,
) -> Result<Json<SiemConfigPayload>, AppError> {
    let now = Utc::now().to_rfc3339();
    let p = payload.clone();
    let db = Arc::clone(&state.db);

    tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let conn = db.conn().lock();
        conn.execute(
            "UPDATE siem_config SET \
                splunk_url = ?1, splunk_token = ?2, splunk_enabled = ?3, \
                elk_url = ?4, elk_index = ?5, elk_api_key = ?6, \
                elk_enabled = ?7, updated_at = ?8 \
             WHERE id = 1",
            rusqlite::params![
                p.splunk_url,
                p.splunk_token,
                p.splunk_enabled as i64,
                p.elk_url,
                p.elk_index,
                p.elk_api_key,
                p.elk_enabled as i64,
                now,
            ],
        )?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!("SIEM config updated");
    Ok(Json(payload))
}

// ---------------------------------------------------------------------------
// Alert router config handlers
// ---------------------------------------------------------------------------

/// `GET /admin/alert-config` — returns the current alert router config.
///
/// Reads the single row from `alert_router_config` and returns it as a JSON
/// [`AlertRouterConfigPayload`]. The row is guaranteed to exist because it
/// is seeded during `Database::open`.
async fn get_alert_config_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<AlertRouterConfigPayload>, AppError> {
    let db = Arc::clone(&state.db);
    let payload =
        tokio::task::spawn_blocking(move || -> Result<AlertRouterConfigPayload, AppError> {
            let conn = db.conn().lock();
            let payload = conn.query_row(
                "SELECT smtp_host, smtp_port, smtp_username, smtp_password, \
                        smtp_from, smtp_to, smtp_enabled, \
                        webhook_url, webhook_secret, webhook_enabled \
                 FROM alert_router_config WHERE id = 1",
                [],
                |row| {
                    let port_i64: i64 = row.get(1)?;
                    let smtp_port = u16::try_from(port_i64).map_err(|_| {
                        rusqlite::Error::FromSqlConversionFailure(
                            1,
                            rusqlite::types::Type::Integer,
                            format!("smtp_port out of range: {port_i64}").into(),
                        )
                    })?;
                    Ok(AlertRouterConfigPayload {
                        smtp_host: row.get(0)?,
                        smtp_port,
                        smtp_username: row.get(2)?,
                        smtp_password: row.get(3)?,
                        smtp_from: row.get(4)?,
                        smtp_to: row.get(5)?,
                        smtp_enabled: row.get::<_, i64>(6)? != 0,
                        webhook_url: row.get(7)?,
                        webhook_secret: row.get(8)?,
                        webhook_enabled: row.get::<_, i64>(9)? != 0,
                    })
                },
            )?;
            Ok(payload)
        })
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    Ok(Json(payload))
}

/// `PUT /admin/alert-config` — updates the alert router config.
///
/// Validates `webhook_url` (TM-02 SSRF hardening) before writing. Overwrites
/// the single row in `alert_router_config` with the provided values and
/// stamps `updated_at` with the current time. Returns the payload that was
/// written so clients can refresh their local copy.
///
/// # Errors
///
/// Returns `AppError::BadRequest` if `webhook_url` fails validation.
async fn update_alert_config_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AlertRouterConfigPayload>,
) -> Result<Json<AlertRouterConfigPayload>, AppError> {
    // TM-02: validate webhook_url BEFORE any DB write. Empty string is
    // allowed (means webhook delivery is disabled).
    if !payload.webhook_url.is_empty() {
        validate_webhook_url(&payload.webhook_url)
            .map_err(|reason| AppError::BadRequest(format!("webhook_url rejected: {reason}")))?;
    }

    let now = Utc::now().to_rfc3339();
    let p = payload.clone();
    let db = Arc::clone(&state.db);

    tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let conn = db.conn().lock();
        conn.execute(
            "UPDATE alert_router_config SET \
                smtp_host = ?1, smtp_port = ?2, smtp_username = ?3, \
                smtp_password = ?4, smtp_from = ?5, smtp_to = ?6, \
                smtp_enabled = ?7, webhook_url = ?8, webhook_secret = ?9, \
                webhook_enabled = ?10, updated_at = ?11 \
             WHERE id = 1",
            rusqlite::params![
                p.smtp_host,
                p.smtp_port as i64,
                p.smtp_username,
                p.smtp_password,
                p.smtp_from,
                p.smtp_to,
                p.smtp_enabled as i64,
                p.webhook_url,
                p.webhook_secret,
                p.webhook_enabled as i64,
                now,
            ],
        )?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!("alert router config updated");
    Ok(Json(payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_response_serde() {
        let resp = HealthResponse {
            status: "ok".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        assert!(json.contains("\"status\":\"ok\""));
    }

    #[test]
    fn test_policy_payload_serde() {
        let json = r#"{
            "id": "pol-001",
            "name": "Block T4 Copy",
            "description": "Prevent copying T4 files",
            "priority": 1,
            "conditions": [{"attribute":"classification","op":"eq","value":"T4"}],
            "action": "DENY",
            "enabled": true
        }"#;
        let p: PolicyPayload = serde_json::from_str(json).expect("deserialize");
        assert_eq!(p.id, "pol-001");
        assert_eq!(p.priority, 1);
        assert!(p.enabled);
    }

    #[test]
    fn test_set_auth_hash_request_serde() {
        let json = r#"{"hash":"$2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012"}"#;
        let req: SetAuthHashRequest = serde_json::from_str(json).expect("deserialize");
        assert!(req.hash.starts_with("$2"));
    }

    #[test]
    fn test_auth_hash_response_serde() {
        let resp = AuthHashResponse {
            hash: "$2b$12$test".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        let rt: AuthHashResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rt.hash, "$2b$12$test");
    }

    #[test]
    fn test_siem_config_payload_roundtrip() {
        let p = SiemConfigPayload {
            splunk_url: "https://splunk:8088".to_string(),
            splunk_token: "tok-abc".to_string(),
            splunk_enabled: true,
            elk_url: "https://elastic:9200".to_string(),
            elk_index: "dlp-events".to_string(),
            elk_api_key: "k1".to_string(),
            elk_enabled: false,
        };
        let json = serde_json::to_string(&p).expect("serialize");
        let rt: SiemConfigPayload = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rt.splunk_url, "https://splunk:8088");
        assert!(rt.splunk_enabled);
        assert!(!rt.elk_enabled);
        assert_eq!(rt.elk_index, "dlp-events");
    }

    #[test]
    fn test_policy_response_serde() {
        let resp = PolicyResponse {
            id: "pol-001".to_string(),
            name: "Test".to_string(),
            description: None,
            priority: 10,
            conditions: serde_json::json!([]),
            action: "ALLOW".to_string(),
            enabled: true,
            version: 1,
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        let rt: PolicyResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rt.id, "pol-001");
        assert_eq!(rt.version, 1);
    }

    #[test]
    fn test_alert_router_config_payload_roundtrip() {
        let p = AlertRouterConfigPayload {
            smtp_host: "smtp.example.com".to_string(),
            smtp_port: 587,
            smtp_username: "user".to_string(),
            smtp_password: "pass".to_string(),
            smtp_from: "dlp@example.com".to_string(),
            smtp_to: "a@example.com, b@example.com".to_string(),
            smtp_enabled: true,
            webhook_url: "https://hooks.example.com/x".to_string(),
            webhook_secret: "shh".to_string(),
            webhook_enabled: false,
        };
        let json = serde_json::to_string(&p).expect("serialize");
        let rt: AlertRouterConfigPayload = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rt, p);
    }

    #[test]
    fn test_validate_webhook_url() {
        // TM-02 — 26-case table-driven test. Each row is (input, expected_ok).
        // The Err branch uses `.is_err()` rather than matching the exact string
        // so minor wording tweaks to the reason do not break the test; the
        // per-category tests below assert the specific rejection reasons.
        let cases: &[(&str, bool)] = &[
            ("", false),                                     //  1 empty
            ("http://example.com", false),                   //  2 http
            ("ftp://example.com", false),                    //  3 ftp
            ("file:///etc/passwd", false),                   //  4 file
            ("not a url", false),                            //  5 parse fail
            ("https://127.0.0.1", false),                    //  6 loopback
            ("https://127.0.0.1:8443", false),               //  7 loopback + port
            ("https://127.1.2.3", false),                    //  8 127/8 range
            ("https://[::1]", false),                        //  9 v6 loopback
            ("https://[::1]:8080", false),                   // 10 v6 loopback + port
            ("https://169.254.169.254", false),              // 11 cloud metadata
            ("https://169.254.1.1", false),                  // 12 link-local /16
            ("https://[fe80::1]", false),                    // 13 v6 link-local
            ("https://[fe80::dead:beef]", false),            // 14 v6 link-local
            ("https://[febf::1]", false),                    // 15 v6 link-local upper edge
            ("https://[fec0::1]", true),                     // 16 site-local (OK, not link-local)
            ("https://10.0.0.1", true),                      // 17 RFC1918
            ("https://10.255.255.255", true),                // 18 RFC1918 edge
            ("https://172.16.5.5", true),                    // 19 RFC1918
            ("https://172.31.255.255", true),                // 20 RFC1918 edge
            ("https://192.168.1.1", true),                   // 21 RFC1918
            ("https://8.8.8.8", true),                       // 22 public v4
            ("https://example.com", true),                   // 23 public hostname
            ("https://internal.corp.example.com", true),     // 24 internal hostname
            ("https://example.com:8443/path?query=1", true), // 25 path + query
            ("https://[2001:db8::1]", true),                 // 26 public v6
        ];
        for (i, (input, expected_ok)) in cases.iter().enumerate() {
            let result = validate_webhook_url(input);
            assert_eq!(
                result.is_ok(),
                *expected_ok,
                "case {} ({input:?}): expected ok={}, got {:?}",
                i + 1,
                expected_ok,
                result,
            );
        }

        // Spot-check the rejection reasons for the four failure categories.
        assert!(validate_webhook_url("http://example.com")
            .unwrap_err()
            .contains("https"));
        assert!(validate_webhook_url("https://127.0.0.1")
            .unwrap_err()
            .contains("loopback"));
        assert!(validate_webhook_url("https://169.254.169.254")
            .unwrap_err()
            .contains("link-local"));
        assert!(validate_webhook_url("https://[fe80::1]")
            .unwrap_err()
            .contains("link-local"));
    }

    #[test]
    fn test_put_alert_config_rejects_http() {
        // Direct unit test of validate_webhook_url — the handler path is
        // exercised end-to-end in the integration tests below.
        let err = validate_webhook_url("http://example.com").unwrap_err();
        assert!(err.contains("https"));
    }

    #[test]
    fn test_put_alert_config_rejects_loopback() {
        let err = validate_webhook_url("https://127.0.0.1/hook").unwrap_err();
        assert!(err.contains("loopback"));
    }

    #[test]
    fn test_put_alert_config_accepts_rfc1918() {
        // RFC1918 MUST be accepted — on-prem webhooks are a legitimate use case.
        validate_webhook_url("https://10.0.0.1/hook").expect("RFC1918 must be accepted");
        validate_webhook_url("https://172.16.5.5/hook").expect("RFC1918 must be accepted");
        validate_webhook_url("https://192.168.1.1/hook").expect("RFC1918 must be accepted");
    }

    /// Shared test secret. All integration tests in this module and in
    /// admin_auth::tests must agree on this value because
    /// `admin_auth::set_jwt_secret` is backed by a `OnceLock` that silently
    /// ignores duplicate set calls — whichever test runs first wins. We use
    /// the same literal that `admin_auth::DEV_JWT_SECRET` does (checked into
    /// `admin_auth.rs`) so all cross-module tests converge on one secret.
    const TEST_JWT_SECRET: &str = "dlp-server-dev-secret-change-me";

    #[tokio::test]
    async fn test_get_alert_config_requires_auth() {
        // Integration test at the handler level: a real router build that
        // exercises the JWT middleware. We bind the full admin_router and send
        // an unauthenticated GET to /admin/alert-config — expect 401.
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt; // for `oneshot`

        // JWT secret must be set for the middleware to initialise. OnceLock
        // silently ignores duplicate set calls, so this is safe across tests.
        crate::admin_auth::set_jwt_secret(TEST_JWT_SECRET.to_string());
        let db = Arc::new(crate::db::Database::open(":memory:").expect("open db"));
        let siem = crate::siem_connector::SiemConnector::new(Arc::clone(&db));
        let alert = crate::alert_router::AlertRouter::new(Arc::clone(&db));
        let state = Arc::new(AppState { db, siem, alert });
        let app = admin_router(state);

        let req = Request::builder()
            .method("GET")
            .uri("/admin/alert-config")
            .body(Body::empty())
            .expect("build request");

        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_put_alert_config_roundtrip() {
        // Full PUT -> GET round-trip via the router with a valid JWT.
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use jsonwebtoken::{encode, EncodingKey, Header};
        use tower::ServiceExt;

        // Use the shared constant so all cross-module tests agree on the
        // secret stored in the process-wide OnceLock.
        crate::admin_auth::set_jwt_secret(TEST_JWT_SECRET.to_string());
        let db = Arc::new(crate::db::Database::open(":memory:").expect("open db"));
        let siem = crate::siem_connector::SiemConnector::new(Arc::clone(&db));
        let alert = crate::alert_router::AlertRouter::new(Arc::clone(&db));
        let state = Arc::new(AppState { db, siem, alert });
        let app = admin_router(state);

        // Mint a valid JWT inline. Claims struct is pub on admin_auth.
        let claims = crate::admin_auth::Claims {
            sub: "test-admin".to_string(),
            exp: (Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
            iss: "dlp-server".to_string(),
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(TEST_JWT_SECRET.as_bytes()),
        )
        .expect("encode JWT");

        let payload = AlertRouterConfigPayload {
            smtp_host: "smtp.internal.corp".to_string(),
            smtp_port: 587,
            smtp_username: "dlp-alerts".to_string(),
            smtp_password: "t0p-secret".to_string(),
            smtp_from: "dlp@internal.corp".to_string(),
            smtp_to: "secops@internal.corp".to_string(),
            smtp_enabled: true,
            webhook_url: "https://hooks.internal.corp/dlp".to_string(),
            webhook_secret: "shh".to_string(),
            webhook_enabled: true,
        };
        let body = serde_json::to_string(&payload).expect("serialize");

        let put_req = Request::builder()
            .method("PUT")
            .uri("/admin/alert-config")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .expect("build PUT request");

        let put_resp = app.clone().oneshot(put_req).await.expect("PUT oneshot");
        assert_eq!(put_resp.status(), StatusCode::OK);

        let get_req = Request::builder()
            .method("GET")
            .uri("/admin/alert-config")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build GET request");

        let get_resp = app.oneshot(get_req).await.expect("GET oneshot");
        assert_eq!(get_resp.status(), StatusCode::OK);
        let bytes = to_bytes(get_resp.into_body(), 64 * 1024)
            .await
            .expect("read body");
        let rt: AlertRouterConfigPayload = serde_json::from_slice(&bytes).expect("parse body");
        assert_eq!(rt, payload);
    }
}
