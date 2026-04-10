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

/// Health/readiness probe response.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    /// Current server status.
    pub status: String,
    /// ISO 8601 timestamp.
    pub timestamp: String,
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
    #[ignore = "Wave 0 stub — implemented in Wave 3"]
    fn test_alert_router_config_payload_roundtrip() {
        todo!("Wave 3");
    }

    #[test]
    #[ignore = "Wave 0 stub — implemented in Wave 3"]
    fn test_validate_webhook_url() {
        todo!("Wave 3 — 26-case table");
    }

    #[test]
    #[ignore = "Wave 0 stub — implemented in Wave 3"]
    fn test_put_alert_config_rejects_http() {
        todo!("Wave 3");
    }

    #[test]
    #[ignore = "Wave 0 stub — implemented in Wave 3"]
    fn test_put_alert_config_rejects_loopback() {
        todo!("Wave 3");
    }

    #[test]
    #[ignore = "Wave 0 stub — implemented in Wave 3"]
    fn test_put_alert_config_accepts_rfc1918() {
        todo!("Wave 3");
    }

    #[test]
    #[ignore = "Wave 0 stub — implemented in Wave 3"]
    fn test_get_alert_config_requires_auth() {
        todo!("Wave 3");
    }

    #[test]
    #[ignore = "Wave 0 stub — implemented in Wave 3"]
    fn test_put_alert_config_roundtrip() {
        todo!("Wave 3");
    }
}
