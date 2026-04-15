//! Admin REST API that aggregates all management endpoints (P5-T09).
//!
//! Builds the complete axum `Router` with all sub-routes. Public
//! endpoints (health, ready, auth) are unauthenticated. All other
//! routes require a valid JWT Bearer token.
//
// TODO(followup): apply the same ME-01 mask-on-GET pattern to siem-config
// (Phase 3.1 has the same exposure).

use std::sync::Arc;

use axum::extract::{FromRequest, Path, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use dlp_common::abac::{EvaluateRequest, EvaluateResponse};
use crate::admin_auth::{self, AdminUsername};
use crate::agent_registry;
use crate::audit_store;
use crate::db;
use crate::db::repositories;
use crate::db::repositories::{
    AgentConfigRepository, AlertRouterConfigRepository, CredentialsRepository,
    LdapConfigRepository, PolicyRepository, SiemConfigRepository,
};
use crate::exception_store;
use crate::rate_limiter::{self, default_config, policy_config};
use crate::AppError;
use crate::AppState;
use tracing::info;

// ---------------------------------------------------------------------------
// Evaluation endpoint
// ---------------------------------------------------------------------------

/// Evaluates an ABAC access request against the loaded policy set.
///
/// `POST /evaluate` — intentionally unauthenticated.
/// Agent identity is established by `AgentInfo` in the request body.
async fn evaluate_handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<EvaluateRequest>,
) -> Result<Json<EvaluateResponse>, AppError> {
    let agent_id = request
        .agent
        .as_ref()
        .map(|a| {
            format!(
                "{}\\{}",
                a.machine_name.as_deref().unwrap_or("unknown"),
                a.current_user.as_deref().unwrap_or("unknown"),
            )
        })
        .unwrap_or_else(|| "unknown".to_string());

    info!(
        agent_id = %agent_id,
        resource_classification = ?request.resource.classification,
        "policy evaluation request"
    );

    // NOTE: evaluate() is synchronous — no .await here.
    let response = state.policy_store.evaluate(&request);
    Ok(Json(response))
}

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
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// ME-01: Sentinel placeholder returned by `GET /admin/alert-config` in place
/// of the plaintext `smtp_password` and `webhook_secret` columns. The TUI
/// save path treats this sentinel as "user kept the existing secret" and the
/// PUT handler substitutes the stored value when it sees the mask echoed
/// back, so the DB column is never overwritten with the literal string.
/// Admins who need to rotate a secret type the new value over the mask in
/// the TUI.
pub(crate) const ALERT_SECRET_MASK: &str = "***MASKED***";

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

// ---------------------------------------------------------------------------
// LDAP config request / response types
// ---------------------------------------------------------------------------

/// Read/write payload for LDAP / Active Directory connection configuration.
///
/// Represents the editable columns of the single row in the `ldap_config`
/// table (excluding `id` and `updated_at`). Both the `GET /admin/ldap-config`
/// response body and the `PUT /admin/ldap-config` request body use this shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LdapConfigPayload {
    /// LDAP URL, e.g. `ldaps://dc.corp.internal:636`.
    pub ldap_url: String,
    /// Search base DN, e.g. `DC=corp,DC=internal`.
    pub base_dn: String,
    /// Whether LDAPS/TLS is required (plaintext connections rejected when true).
    pub require_tls: bool,
    /// Group membership cache TTL in seconds (min 60, max 3600, default 300).
    pub cache_ttl_secs: u64,
    /// Comma-separated VPN subnet CIDRs for location detection.
    pub vpn_subnets: String,
}

/// Read/write payload for agent configuration distribution.
///
/// Used by `GET/PUT /admin/agent-config` (global default) and
/// `GET/PUT/DELETE /admin/agent-config/{agent_id}` (per-agent override).
/// Also returned by the public `GET /agent-config/{id}` endpoint that
/// agents poll for their resolved config.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentConfigPayload {
    /// Directory paths the agent should monitor (empty = all drives).
    pub monitored_paths: Vec<String>,
    /// Heartbeat interval in seconds (minimum 10).
    pub heartbeat_interval_secs: u64,
    /// Whether offline caching is active.
    pub offline_cache_enabled: bool,
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
            // TM-02 hardening (BL-01 fix): IPv4-mapped IPv6 addresses
            // (`::ffff:a.b.c.d`) route to the v4 stack on dual-stack hosts,
            // so `[::ffff:127.0.0.1]` and `[::ffff:169.254.169.254]` would
            // otherwise bypass the v4 loopback/link-local guards and let an
            // attacker reach cloud metadata via the mapped form. Re-run the
            // v4 blocklist against the unwrapped address. `to_ipv4_mapped`
            // is stable since Rust 1.63.
            if let Some(v4) = ip.to_ipv4_mapped() {
                if v4.is_loopback() {
                    return Err("loopback addresses not allowed (IPv4-mapped)".to_string());
                }
                if v4.is_link_local() {
                    return Err("link-local addresses not allowed (IPv4-mapped)".to_string());
                }
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
/// - `POST /agents/{id}/heartbeat` — agent heartbeat
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
/// - `GET /admin/agent-config` — get global agent config default
/// - `PUT /admin/agent-config` — update global agent config default
/// - `GET /admin/agent-config/:agent_id` — get per-agent config override
/// - `PUT /admin/agent-config/:agent_id` — upsert per-agent config override
/// - `DELETE /admin/agent-config/:agent_id` — remove per-agent config override
///
/// **Unauthenticated (additional):**
/// - `GET /agent-config/:id` — resolved agent config (per-agent override or global fallback)
pub fn admin_router(state: Arc<AppState>) -> Router {
    // Routes that do NOT require authentication.
    // Each route that needs rate limiting gets its own GovernorLayer applied
    // via `.route_layer()`. The key extractor (AgentIdOrIpKeyExtractor) keys
    // by agent_id for /agents/* paths and by peer IP for all others.
    let public_routes = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/evaluate", post(evaluate_handler))
        .route("/auth/login", post(admin_auth::login).route_layer(rate_limiter::strict_config()))
        .route("/agents/register", post(agent_registry::register_agent))
        .route(
            "/agents/{id}/heartbeat",
            post(agent_registry::heartbeat).route_layer(rate_limiter::moderate_config()),
        )
        .route(
            "/audit/events",
            post(audit_store::ingest_events).route_layer(rate_limiter::per_agent_config()),
        )
        .route("/agent-credentials/auth-hash", get(get_agent_auth_hash))
        .route("/agent-config/{id}", get(get_agent_config_for_agent));

    // Routes that require a valid JWT.
    // Policy routes get a tighter limit (60/min) via `.route_layer()`.
    // Remaining protected routes fall back to the default 100/min limit.
    let protected_routes = Router::new()
        .route("/agents", get(agent_registry::list_agents))
        .route("/agents/{id}", get(agent_registry::get_agent))
        .route("/audit/events", get(audit_store::query_events))
        .route("/audit/events/count", get(audit_store::get_event_count))
        .route("/policies", get(list_policies).post(create_policy).route_layer(policy_config()))
        .route(
            "/policies/{id}",
            get(get_policy)
                .put(update_policy)
                .delete(delete_policy)
                .route_layer(policy_config()),
        )
        // Policy CRUD under /admin/policies (Phase 9 requirement).
        .route("/admin/policies", post(create_policy).route_layer(policy_config()))
        .route(
            "/admin/policies/{id}",
            put(update_policy)
                .delete(delete_policy)
                .route_layer(policy_config()),
        )
        .route("/exceptions", get(exception_store::list_exceptions))
        .route("/exceptions/{id}", get(exception_store::get_exception))
        .route("/exceptions", post(exception_store::create_exception))
        .route("/agent-credentials/auth-hash", put(set_agent_auth_hash))
        .route("/auth/password", put(admin_auth::change_password))
        .route("/admin/siem-config", get(get_siem_config_handler))
        .route("/admin/siem-config", put(update_siem_config_handler))
        .route("/admin/alert-config", get(get_alert_config_handler))
        .route("/admin/alert-config", put(update_alert_config_handler))
        .route("/admin/alert-config/test", post(test_alert_config_handler))
        .route("/admin/ldap-config", get(get_ldap_config_handler))
        .route("/admin/ldap-config", put(update_ldap_config_handler))
        .route(
            "/admin/agent-config",
            get(get_global_agent_config_handler).put(update_global_agent_config_handler),
        )
        .route(
            "/admin/agent-config/{agent_id}",
            get(get_agent_config_override_handler)
                .put(update_agent_config_override_handler)
                .delete(delete_agent_config_override_handler),
        )
        .route_layer(default_config())
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
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);
    tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let conn = pool.get().map_err(AppError::from)?;
        conn.execute_batch("SELECT 1").map_err(AppError::from)
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
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);
    let rows = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let db_rows = PolicyRepository::list(&pool).map_err(AppError::Database)?;
        let policies: Vec<PolicyResponse> = db_rows
            .into_iter()
            .map(|r| {
                let conditions: serde_json::Value =
                    serde_json::from_str(&r.conditions).unwrap_or(serde_json::Value::Null);
                PolicyResponse {
                    id: r.id,
                    name: r.name,
                    description: r.description,
                    priority: u32::try_from(r.priority)
                        .unwrap_or(r.priority as u32),
                    conditions,
                    action: r.action,
                    enabled: r.enabled != 0,
                    version: r.version,
                    updated_at: r.updated_at,
                }
            })
            .collect();
        Ok(policies)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    Ok(Json(rows))
}

/// `GET /policies/:id` — get a single policy.
async fn get_policy(
    State(state): State<Arc<AppState>>,
    Path(policy_id): Path<String>,
) -> Result<Json<PolicyResponse>, AppError> {
    let id = policy_id.clone();
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);

    let p = tokio::task::spawn_blocking(move || -> Result<PolicyResponse, AppError> {
        let r = PolicyRepository::get_by_id(&pool, &id).map_err(AppError::Database)?;
        let conditions: serde_json::Value =
            serde_json::from_str(&r.conditions).unwrap_or(serde_json::Value::Null);
        Ok(PolicyResponse {
            id: r.id,
            name: r.name,
            description: r.description,
            priority: u32::try_from(r.priority).unwrap_or(r.priority as u32),
            conditions,
            action: r.action,
            enabled: r.enabled != 0,
            version: r.version,
            updated_at: r.updated_at,
        })
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    Ok(Json(p))
}

/// `POST /policies` — create a new policy.
async fn create_policy(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<(StatusCode, Json<PolicyResponse>), AppError> {
    let username = AdminUsername::extract_from_headers(req.headers())?;
    let payload: Json<PolicyPayload> = Json::from_request(req, &state)
        .await
        .map_err(AppError::from)?;
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

    // Persist the new policy via repository + UnitOfWork.
    let r = resp.clone();
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);
    tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        let record = repositories::PolicyRow {
            id: r.id.clone(),
            name: r.name.clone(),
            description: r.description.clone(),
            priority: i64::from(r.priority),
            conditions: conditions_json.clone(),
            action: r.action.clone(),
            enabled: if r.enabled { 1 } else { 0 },
            version: r.version,
            updated_at: r.updated_at.clone(),
        };
        PolicyRepository::insert(&uow, &record).map_err(AppError::Database)?;
        uow.commit().map_err(AppError::Database)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    // Invalidate the policy cache so the next evaluation sees the new policy.
    state.policy_store.invalidate();

    // Emit admin audit event after DB commit.
    let audit_event = dlp_common::AuditEvent::new(
        dlp_common::EventType::AdminAction,
        String::new(),
        username,
        format!("policy:{}", resp.id),
        dlp_common::Classification::T3,
        dlp_common::Action::PolicyCreate,
        dlp_common::Decision::ALLOW,
        "server".to_string(),
        0,
    );
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);
    tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        audit_store::store_events_sync(&uow, &[audit_event])?;
        uow.commit().map_err(AppError::Database)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!(policy_id = %resp.id, "policy created");
    Ok((StatusCode::CREATED, Json(resp)))
}

/// `PUT /policies/:id` — update an existing policy.
async fn update_policy(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<Json<PolicyResponse>, AppError> {
    let username = AdminUsername::extract_from_headers(req.headers())?;

    // Extract path param from URI. Supports both /policies/:id and /admin/policies/:id.
    let path = req.uri().path();
    let policy_id = if let Some(rest) = path.strip_prefix("/policies/") {
        rest.to_string()
    } else if let Some(rest) = path.strip_prefix("/admin/policies/") {
        rest.to_string()
    } else {
        return Err(AppError::BadRequest("invalid policy path".to_string()));
    };
    if policy_id.is_empty() {
        return Err(AppError::BadRequest(
            "missing policy id in path".to_string(),
        ));
    }

    // Let Json consume the request body.
    let payload: Json<PolicyPayload> = Json::from_request(req, &state)
        .await
        .map_err(AppError::from)?;

    // Clone all fields needed inside spawn_blocking since Json derefs to &T (not owned).
    let now = Utc::now().to_rfc3339();
    let conditions_json = serde_json::to_string(&payload.conditions)?;
    let id = policy_id.clone();
    let payload_name = payload.name.clone();
    let payload_desc = payload.description.clone();
    let payload_priority = i64::from(payload.priority);
    let payload_action = payload.action.clone();
    let payload_enabled = if payload.enabled { 1 } else { 0 };
    let payload_conditions = payload.conditions.clone();
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);

    let resp = tokio::task::spawn_blocking(move || -> Result<PolicyResponse, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;

        let row = repositories::PolicyUpdateRow {
            name: &payload_name,
            description: payload_desc.as_deref(),
            priority: payload_priority,
            conditions: &conditions_json,
            action: &payload_action,
            enabled: payload_enabled,
            updated_at: &now,
            id: &id,
        };
        let rows = PolicyRepository::update(&uow, &row)
            .map_err(AppError::Database)?;

        if rows == 0 {
            return Err(AppError::NotFound(format!("policy {id} not found")));
        }

        let version = PolicyRepository::get_version(&uow, &id)
            .map_err(AppError::Database)?;

        uow.commit().map_err(AppError::Database)?;

        Ok(PolicyResponse {
            id,
            name: payload_name,
            description: payload_desc,
            priority: u32::try_from(payload_priority).unwrap_or(payload_priority as u32),
            conditions: payload_conditions,
            action: payload_action,
            enabled: payload_enabled != 0,
            version,
            updated_at: now,
        })
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    // Invalidate the policy cache so the next evaluation sees the updated policy.
    state.policy_store.invalidate();

    // Emit admin audit event after DB commit.
    let audit_event = dlp_common::AuditEvent::new(
        dlp_common::EventType::AdminAction,
        String::new(),
        username,
        format!("policy:{}", resp.id),
        dlp_common::Classification::T3,
        dlp_common::Action::PolicyUpdate,
        dlp_common::Decision::ALLOW,
        "server".to_string(),
        0,
    );
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);
    tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        audit_store::store_events_sync(&uow, &[audit_event])?;
        uow.commit().map_err(AppError::Database)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!(policy_id = %resp.id, "policy updated");
    Ok(Json(resp))
}

/// `DELETE /policies/:id` — delete a policy.
async fn delete_policy(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<StatusCode, AppError> {
    let username = AdminUsername::extract_from_headers(req.headers())?;
    let policy_id = Path::<String>::from_request(req, &state)
        .await
        .map_err(AppError::from)?
        .0;
    let id = policy_id.clone();
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);

    let rows = tokio::task::spawn_blocking(move || -> Result<usize, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        let rows = PolicyRepository::delete(&uow, &id).map_err(AppError::Database)?;
        uow.commit().map_err(AppError::Database)?;
        Ok(rows)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    // Invalidate the policy cache so the next evaluation sees the deleted policy.
    state.policy_store.invalidate();

    if rows == 0 {
        return Err(AppError::NotFound(format!("policy {policy_id} not found")));
    }

    // Emit admin audit event after DB commit.
    let audit_event = dlp_common::AuditEvent::new(
        dlp_common::EventType::AdminAction,
        String::new(),
        username,
        format!("policy:{}", policy_id),
        dlp_common::Classification::T3,
        dlp_common::Action::PolicyDelete,
        dlp_common::Decision::ALLOW,
        "server".to_string(),
        0,
    );
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);
    tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        audit_store::store_events_sync(&uow, &[audit_event])?;
        uow.commit().map_err(AppError::Database)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

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
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);

    tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        CredentialsRepository::upsert(&uow, "DLPAuthHash", &hash, &ts)
            .map_err(AppError::Database)?;
        uow.commit().map_err(AppError::Database)?;
        Ok(())
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
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);
    let (hash, updated_at) = tokio::task::spawn_blocking(move || -> Result<(String, String), AppError> {
        let row = CredentialsRepository::get(&pool, "DLPAuthHash")
            .map_err(AppError::Database)?;
        Ok((row.value, row.updated_at))
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    Ok(Json(AuthHashResponse { hash, updated_at }))
}

// ---------------------------------------------------------------------------
// SIEM config handlers
// ---------------------------------------------------------------------------

/// `GET /admin/siem-config` — returns the current SIEM connector config.
///
/// Reads the single row from `siem_config` and returns it as a JSON
/// [`SiemConfigPayload`]. The row is guaranteed to exist because it is
/// seeded during pool initialization.
async fn get_siem_config_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<SiemConfigPayload>, AppError> {
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);
    let row = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        SiemConfigRepository::get(&pool).map_err(AppError::Database)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    Ok(Json(SiemConfigPayload {
        splunk_url: row.splunk_url,
        splunk_token: row.splunk_token,
        splunk_enabled: row.splunk_enabled != 0,
        elk_url: row.elk_url,
        elk_index: row.elk_index,
        elk_api_key: row.elk_api_key,
        elk_enabled: row.elk_enabled != 0,
    }))
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
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);

    tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        let record = repositories::SiemConfigRow {
            splunk_url: p.splunk_url.clone(),
            splunk_token: p.splunk_token.clone(),
            splunk_enabled: if p.splunk_enabled { 1 } else { 0 },
            elk_url: p.elk_url.clone(),
            elk_index: p.elk_index.clone(),
            elk_api_key: p.elk_api_key.clone(),
            elk_enabled: if p.elk_enabled { 1 } else { 0 },
            updated_at: now,
        };
        SiemConfigRepository::update(&uow, &record).map_err(AppError::Database)?;
        uow.commit().map_err(AppError::Database)?;
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
/// is seeded during pool initialization.
///
/// ME-01: `smtp_password` and `webhook_secret` are replaced with
/// [`ALERT_SECRET_MASK`] in the response. Empty stored values are returned
/// as empty strings so the TUI can distinguish "never set" from "set but
/// hidden". The PUT handler substitutes the stored value when it sees the
/// mask echoed back, preserving secret-preserving round-trips.
async fn get_alert_config_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<AlertRouterConfigPayload>, AppError> {
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);
    let row =
        tokio::task::spawn_blocking(move || -> Result<_, AppError> {
            AlertRouterConfigRepository::get(&pool).map_err(AppError::Database)
        })
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    // ME-01: Never return plaintext credentials on GET. Empty stays empty
    // so the TUI can render "not configured".
    let smtp_password_out = if row.smtp_password.is_empty() {
        String::new()
    } else {
        ALERT_SECRET_MASK.to_string()
    };
    let webhook_secret_out = if row.webhook_secret.is_empty() {
        String::new()
    } else {
        ALERT_SECRET_MASK.to_string()
    };

    Ok(Json(AlertRouterConfigPayload {
        smtp_host: row.smtp_host,
        smtp_port: row.smtp_port,
        smtp_username: row.smtp_username,
        smtp_password: smtp_password_out,
        smtp_from: row.smtp_from,
        smtp_to: row.smtp_to,
        smtp_enabled: row.smtp_enabled != 0,
        webhook_url: row.webhook_url,
        webhook_secret: webhook_secret_out,
        webhook_enabled: row.webhook_enabled != 0,
    }))
}

/// `PUT /admin/alert-config` — updates the alert router config.
///
/// Validates `webhook_url` (TM-02 SSRF hardening) before writing. Overwrites
/// the single row in `alert_router_config` with the provided values and
/// stamps `updated_at` with the current time. Returns the payload that was
/// written so clients can refresh their local copy.
///
/// ME-01: both the SELECT (secret mask resolution) and UPDATE share a single
/// `UnitOfWork`, preventing any TOCTOU window between reading and writing.
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
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);

    tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;

        // ME-01: Read secrets within the same transaction to prevent TOCTOU.
        let (stored_smtp_password, stored_webhook_secret) =
            AlertRouterConfigRepository::get_secrets(&uow)
                .map_err(AppError::Database)?;

        let smtp_password_to_write = if p.smtp_password == ALERT_SECRET_MASK {
            stored_smtp_password
        } else {
            p.smtp_password.clone()
        };
        let webhook_secret_to_write = if p.webhook_secret == ALERT_SECRET_MASK {
            stored_webhook_secret
        } else {
            p.webhook_secret.clone()
        };

        let record = repositories::AlertRouterConfigRow {
            smtp_host: p.smtp_host.clone(),
            smtp_port: p.smtp_port,
            smtp_username: p.smtp_username.clone(),
            smtp_password: smtp_password_to_write,
            smtp_from: p.smtp_from.clone(),
            smtp_to: p.smtp_to.clone(),
            smtp_enabled: if p.smtp_enabled { 1 } else { 0 },
            webhook_url: p.webhook_url.clone(),
            webhook_secret: webhook_secret_to_write,
            webhook_enabled: if p.webhook_enabled { 1 } else { 0 },
            updated_at: now,
        };
        AlertRouterConfigRepository::update(&uow, &record)
            .map_err(AppError::Database)?;
        uow.commit().map_err(AppError::Database)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!("alert router config updated");
    // Re-mask the response so the secret never reappears on the wire.
    let mut masked_response = payload;
    if !masked_response.smtp_password.is_empty() {
        masked_response.smtp_password = ALERT_SECRET_MASK.to_string();
    }
    if !masked_response.webhook_secret.is_empty() {
        masked_response.webhook_secret = ALERT_SECRET_MASK.to_string();
    }
    Ok(Json(masked_response))
}

// ---------------------------------------------------------------------------
// Agent config handlers
// ---------------------------------------------------------------------------



/// `GET /agent-config/:id` — returns the resolved config for a specific agent.
///
/// Tries per-agent override first; falls back to global default if no override
/// exists. This endpoint is intentionally unauthenticated — agents call it
/// using their `agent_id` as identity, not admin JWT.
async fn get_agent_config_for_agent(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
) -> Result<Json<AgentConfigPayload>, AppError> {
    let id = agent_id.clone();
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);
    let payload = tokio::task::spawn_blocking(move || -> Result<AgentConfigPayload, AppError> {
        // Try per-agent override first via repository.
        match AgentConfigRepository::get_override(&pool, &id) {
            Ok(row) => Ok(AgentConfigPayload {
                monitored_paths: serde_json::from_str(&row.monitored_paths)
                    .unwrap_or_default(),
                heartbeat_interval_secs: u64::try_from(row.heartbeat_interval_secs)
                    .unwrap_or(30),
                offline_cache_enabled: row.offline_cache_enabled != 0,
            }),
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                // Fall back to global default.
                let row = AgentConfigRepository::get_global(&pool)
                    .map_err(AppError::Database)?;
                Ok(AgentConfigPayload {
                    monitored_paths: serde_json::from_str(&row.monitored_paths)
                        .unwrap_or_default(),
                    heartbeat_interval_secs: u64::try_from(row.heartbeat_interval_secs)
                        .unwrap_or(30),
                    offline_cache_enabled: row.offline_cache_enabled != 0,
                })
            }
            Err(e) => Err(AppError::Database(e)),
        }
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    Ok(Json(payload))
}

// ---------------------------------------------------------------------------
// LDAP config handlers
// ---------------------------------------------------------------------------

/// `GET /admin/ldap-config` — returns the current LDAP connection configuration.
///
/// Reads the single row from `ldap_config` and returns it as a JSON
/// [`LdapConfigPayload`]. The row is guaranteed to exist because it is
/// seeded during pool initialization.
async fn get_ldap_config_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<LdapConfigPayload>, AppError> {
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);
    let row = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        LdapConfigRepository::get(&pool).map_err(AppError::Database)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    Ok(Json(LdapConfigPayload {
        ldap_url: row.ldap_url,
        base_dn: row.base_dn,
        require_tls: row.require_tls,
        cache_ttl_secs: row.cache_ttl_secs,
        vpn_subnets: row.vpn_subnets,
    }))
}

/// `PUT /admin/ldap-config` — updates LDAP connection configuration.
///
/// Overwrites the single row in `ldap_config` with the provided values
/// and stamps `updated_at` with the current time. Returns the payload
/// that was written so clients can refresh their local copy.
///
/// Validates that `cache_ttl_secs` is in the range [60, 3600].
async fn update_ldap_config_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LdapConfigPayload>,
) -> Result<Json<LdapConfigPayload>, AppError> {
    if payload.cache_ttl_secs < 60 {
        return Err(AppError::BadRequest(
            "cache_ttl_secs must be at least 60".to_string(),
        ));
    }
    if payload.cache_ttl_secs > 3600 {
        return Err(AppError::BadRequest(
            "cache_ttl_secs must be at most 3600".to_string(),
        ));
    }

    let now = Utc::now().to_rfc3339();
    let p = payload.clone();
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);

    tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        let record = repositories::LdapConfigRow {
            ldap_url: p.ldap_url.clone(),
            base_dn: p.base_dn.clone(),
            require_tls: p.require_tls,
            cache_ttl_secs: p.cache_ttl_secs,
            vpn_subnets: p.vpn_subnets.clone(),
            updated_at: now,
        };
        LdapConfigRepository::update(&uow, &record).map_err(AppError::Database)?;
        uow.commit().map_err(AppError::Database)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!("LDAP config updated");
    Ok(Json(payload))
}

/// `GET /admin/agent-config` — returns the current global agent config default.
///
/// Reads the single row from `global_agent_config` (guaranteed by seed) and
/// returns it as a JSON [`AgentConfigPayload`].
async fn get_global_agent_config_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<AgentConfigPayload>, AppError> {
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);
    let row = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        AgentConfigRepository::get_global(&pool).map_err(AppError::Database)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    Ok(Json(AgentConfigPayload {
        monitored_paths: serde_json::from_str(&row.monitored_paths).unwrap_or_default(),
        heartbeat_interval_secs: u64::try_from(row.heartbeat_interval_secs).unwrap_or(30),
        offline_cache_enabled: row.offline_cache_enabled != 0,
    }))
}

/// `PUT /admin/agent-config` — updates the global agent config default.
///
/// Validates that `heartbeat_interval_secs >= 10` before writing. Overwrites
/// the single row in `global_agent_config` and stamps `updated_at`. Returns
/// the payload that was written.
///
/// # Errors
///
/// Returns `AppError::BadRequest` if `heartbeat_interval_secs < 10`.
async fn update_global_agent_config_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AgentConfigPayload>,
) -> Result<Json<AgentConfigPayload>, AppError> {
    if payload.heartbeat_interval_secs < 10 {
        return Err(AppError::BadRequest(
            "heartbeat_interval_secs must be >= 10".to_string(),
        ));
    }

    let now = Utc::now().to_rfc3339();
    let p = payload.clone();
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);

    tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        let paths_json = serde_json::to_string(&p.monitored_paths)
            .map_err(AppError::from)?;
        let record = repositories::GlobalAgentConfigRow {
            monitored_paths: paths_json,
            heartbeat_interval_secs: i64::try_from(p.heartbeat_interval_secs)
                .unwrap_or(30),
            offline_cache_enabled: if p.offline_cache_enabled { 1 } else { 0 },
            updated_at: now,
        };
        AgentConfigRepository::update_global(&uow, &record)
            .map_err(AppError::Database)?;
        uow.commit().map_err(AppError::Database)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!("global agent config updated");
    Ok(Json(payload))
}

/// `GET /admin/agent-config/:agent_id` — returns the per-agent config override.
///
/// Returns 404 if no override exists for the given `agent_id`.
async fn get_agent_config_override_handler(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
) -> Result<Json<AgentConfigPayload>, AppError> {
    let id = agent_id.clone();
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);
    let row = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        AgentConfigRepository::get_override(&pool, &id).map_err(AppError::Database)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    Ok(Json(AgentConfigPayload {
        monitored_paths: serde_json::from_str(&row.monitored_paths).unwrap_or_default(),
        heartbeat_interval_secs: u64::try_from(row.heartbeat_interval_secs).unwrap_or(30),
        offline_cache_enabled: row.offline_cache_enabled != 0,
    }))
}

/// `PUT /admin/agent-config/:agent_id` — upserts a per-agent config override.
///
/// Validates `heartbeat_interval_secs >= 10`. Uses `INSERT OR REPLACE` so the
/// call is idempotent — a second PUT for the same `agent_id` updates the row.
///
/// # Errors
///
/// Returns `AppError::BadRequest` if `heartbeat_interval_secs < 10`.
async fn update_agent_config_override_handler(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
    Json(payload): Json<AgentConfigPayload>,
) -> Result<Json<AgentConfigPayload>, AppError> {
    if payload.heartbeat_interval_secs < 10 {
        return Err(AppError::BadRequest(
            "heartbeat_interval_secs must be >= 10".to_string(),
        ));
    }

    let now = Utc::now().to_rfc3339();
    let p = payload.clone();
    let id = agent_id.clone();
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);

    tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        let paths_json = serde_json::to_string(&p.monitored_paths)
            .map_err(AppError::from)?;
        AgentConfigRepository::upsert_override(
            &uow,
            &id,
            &paths_json,
            i64::try_from(p.heartbeat_interval_secs).unwrap_or(30),
            if p.offline_cache_enabled { 1 } else { 0 },
            &now,
        )
        .map_err(AppError::Database)?;
        uow.commit().map_err(AppError::Database)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!(agent_id = %agent_id, "per-agent config override updated");
    Ok(Json(payload))
}

/// `DELETE /admin/agent-config/:agent_id` — removes a per-agent config override.
///
/// After deletion the agent falls back to the global default on the next poll.
/// Returns 204 No Content on success, 404 if no override row existed.
async fn delete_agent_config_override_handler(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
) -> Result<StatusCode, AppError> {
    let id = agent_id.clone();
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);

    let rows = tokio::task::spawn_blocking(move || -> Result<usize, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        let rows = AgentConfigRepository::delete_override(&uow, &id)
            .map_err(AppError::Database)?;
        uow.commit().map_err(AppError::Database)?;
        Ok(rows)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    if rows == 0 {
        return Err(AppError::NotFound(format!(
            "no config override for agent {agent_id}"
        )));
    }

    tracing::info!(agent_id = %agent_id, "per-agent config override deleted");
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /admin/alert-config/test` — sends a test alert using the current
/// configuration from the database.
///
/// Invokes `AlertRouter::send_test_alert()` which builds a synthetic audit
/// event and delivers it via the configured SMTP and/or webhook channels.
/// Used by the dlp-admin-cli "Test Connection" action so operators can
/// verify their alert settings before relying on them.
///
/// # Errors
///
/// Returns `AppError::Internal` with the delivery error message if SMTP
/// or webhook delivery fails.
async fn test_alert_config_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    state
        .alert
        .send_test_alert()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("{e}")))?;

    Ok(Json(serde_json::json!({ "status": "ok" })))
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
        // TM-02 — 28-case table-driven test. Each row is (input, expected_ok).
        // The Err branch uses `.is_err()` rather than matching the exact string
        // so minor wording tweaks to the reason do not break the test; the
        // per-category tests below assert the specific rejection reasons.
        // Cases 27-28 were added after code review BL-01 exposed an IPv4-mapped
        // IPv6 bypass that let `[::ffff:127.0.0.1]` and `[::ffff:169.254.169.254]`
        // pass the v6 guards.
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
            ("https://[::ffff:127.0.0.1]", false),           // 27 IPv4-mapped loopback (BL-01)
            ("https://[::ffff:169.254.169.254]", false), // 28 IPv4-mapped cloud metadata (BL-01)
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

    /// Common test setup: initialise JWT secret, open a fresh in-memory
    /// database, build the full `admin_router`, and return the router
    /// ready for `oneshot` requests.
    fn spawn_admin_app() -> axum::Router {
        crate::admin_auth::set_jwt_secret(TEST_JWT_SECRET.to_string());
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        let siem = crate::siem_connector::SiemConnector::new(Arc::clone(&pool));
        let alert = crate::alert_router::AlertRouter::new(Arc::clone(&pool));
        let policy_store = Arc::new(
            crate::policy_store::PolicyStore::new(Arc::clone(&pool))
                .expect("policy store"),
        );
        let state = Arc::new(AppState {
            pool,
            policy_store,
            siem,
            alert,
            ad: None,
        });
        admin_router(state)
    }

    /// Mints a valid admin JWT for the test secret.
    fn mint_admin_jwt() -> String {
        use jsonwebtoken::{encode, EncodingKey, Header};
        let claims = crate::admin_auth::Claims {
            sub: "test-admin".to_string(),
            exp: (Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
            iss: "dlp-server".to_string(),
        };
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(TEST_JWT_SECRET.as_bytes()),
        )
        .expect("encode JWT")
    }

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
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        let siem = crate::siem_connector::SiemConnector::new(Arc::clone(&pool));
        let alert = crate::alert_router::AlertRouter::new(Arc::clone(&pool));
        let policy_store = Arc::new(
            crate::policy_store::PolicyStore::new(Arc::clone(&pool))
                .expect("policy store"),
        );
        let state = Arc::new(AppState {
            pool,
            policy_store,
            siem,
            alert,
            ad: None,
        });
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
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        let siem = crate::siem_connector::SiemConnector::new(Arc::clone(&pool));
        let alert = crate::alert_router::AlertRouter::new(Arc::clone(&pool));
        let policy_store = Arc::new(
            crate::policy_store::PolicyStore::new(Arc::clone(&pool))
                .expect("policy store"),
        );
        let state = Arc::new(AppState {
            pool,
            policy_store,
            siem,
            alert,
            ad: None,
        });
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

        // ME-01: GET must return masked sentinels in place of plaintext
        // secrets, but every other field must round-trip identically.
        let mut expected = payload.clone();
        expected.smtp_password = ALERT_SECRET_MASK.to_string();
        expected.webhook_secret = ALERT_SECRET_MASK.to_string();
        assert_eq!(rt, expected);
        assert_eq!(rt.smtp_password, ALERT_SECRET_MASK);
        assert_eq!(rt.webhook_secret, ALERT_SECRET_MASK);
    }

    #[tokio::test]
    async fn test_put_alert_config_preserves_masked_secret() {
        // ME-01 regression test: when the TUI echoes the masked sentinel
        // back on save (user kept the existing secret), the server MUST
        // preserve the stored plaintext value and NOT overwrite the DB
        // column with the literal mask string.
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use jsonwebtoken::{encode, EncodingKey, Header};
        use tower::ServiceExt;

        crate::admin_auth::set_jwt_secret(TEST_JWT_SECRET.to_string());
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        let siem = crate::siem_connector::SiemConnector::new(Arc::clone(&pool));
        let alert = crate::alert_router::AlertRouter::new(Arc::clone(&pool));
        let policy_store = Arc::new(
            crate::policy_store::PolicyStore::new(Arc::clone(&pool))
                .expect("policy store"),
        );
        let state = Arc::new(AppState {
            pool: Arc::clone(&pool),
            policy_store,
            siem,
            alert,
            ad: None,
        });
        let app = admin_router(state);

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

        // Step 1: Seed initial config with real plaintext secrets.
        let initial = AlertRouterConfigPayload {
            smtp_host: "smtp.internal.corp".to_string(),
            smtp_port: 587,
            smtp_username: "dlp-alerts".to_string(),
            smtp_password: "s3cret".to_string(),
            smtp_from: "dlp@internal.corp".to_string(),
            smtp_to: "secops@internal.corp".to_string(),
            smtp_enabled: true,
            webhook_url: "https://hooks.internal.corp/dlp".to_string(),
            webhook_secret: "hmac-key".to_string(),
            webhook_enabled: true,
        };
        let put1 = Request::builder()
            .method("PUT")
            .uri("/admin/alert-config")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&initial).expect("ser")))
            .expect("build PUT 1");
        let put1_resp = app.clone().oneshot(put1).await.expect("PUT 1 oneshot");
        assert_eq!(put1_resp.status(), StatusCode::OK);

        // Step 2: GET — response must show masked sentinels.
        let get1 = Request::builder()
            .method("GET")
            .uri("/admin/alert-config")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build GET 1");
        let get1_resp = app.clone().oneshot(get1).await.expect("GET 1 oneshot");
        assert_eq!(get1_resp.status(), StatusCode::OK);
        let get1_bytes = to_bytes(get1_resp.into_body(), 64 * 1024)
            .await
            .expect("read body 1");
        let masked: AlertRouterConfigPayload =
            serde_json::from_slice(&get1_bytes).expect("parse body 1");
        assert_eq!(masked.smtp_password, ALERT_SECRET_MASK);
        assert_eq!(masked.webhook_secret, ALERT_SECRET_MASK);

        // Step 3: PUT the masked payload unchanged (TUI save-without-edit).
        let put2 = Request::builder()
            .method("PUT")
            .uri("/admin/alert-config")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&masked).expect("ser 2")))
            .expect("build PUT 2");
        let put2_resp = app.clone().oneshot(put2).await.expect("PUT 2 oneshot");
        assert_eq!(put2_resp.status(), StatusCode::OK);

        // Step 4: Read the DB directly — stored secrets MUST be the original
        // plaintext values, not the literal mask string.
        let conn = pool.get().expect("acquire connection for direct read");
        let (stored_smtp_password, stored_webhook_secret): (String, String) = conn
            .query_row(
                "SELECT smtp_password, webhook_secret FROM alert_router_config WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("direct DB read");
        assert_eq!(stored_smtp_password, "s3cret");
        assert_eq!(stored_webhook_secret, "hmac-key");
        assert_ne!(stored_smtp_password, ALERT_SECRET_MASK);
        assert_ne!(stored_webhook_secret, ALERT_SECRET_MASK);
    }

    // ── Temporary diagnostic: verify DB insert→select round-trip ────────────

    #[tokio::test]
    async fn test_db_insert_select_roundtrip_via_spawn_blocking() {
        // This test verifies that spawn_blocking DB writes are visible to
        // subsequent spawn_blocking reads on the same Arc<pool>.
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        let pool2 = Arc::clone(&pool);

        tokio::task::spawn_blocking(move || -> Result<_, AppError> {
            let conn = pool.get().map_err(AppError::from)?;
            conn.execute(
                "INSERT INTO policies (id, name, description, priority, conditions,                  action, enabled, version, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8)",
                rusqlite::params![
                    "diag-001",
                    "Diag Test",
                    None::<String>,
                    1i64,
                    "[]",
                    "ALLOW",
                    true,
                    "2026-01-01T00:00:00Z"
                ],
            )?;
            Ok(())
        })
        .await
        .expect("join")
        .expect("execute");

        let count: i64 = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
            let conn = pool2.get().map_err(AppError::from)?;
            let n = conn.query_row(
                "SELECT COUNT(*) FROM policies WHERE id = ?1",
                rusqlite::params!["diag-001"],
                |row| row.get::<_, i64>(0),
            )?;
            Ok(n)
        })
        .await
        .expect("join")
        .expect("query");

        assert_eq!(
            count, 1,
            "INSERT must be visible to subsequent SELECT via same Arc<pool>"
        );
    }


    // Verify POST via router → direct DB read round-trip.
    #[tokio::test]
    async fn test_router_post_then_direct_db_read() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        crate::admin_auth::set_jwt_secret(TEST_JWT_SECRET.to_string());
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        let pool_read = Arc::clone(&pool);
        let siem = crate::siem_connector::SiemConnector::new(Arc::clone(&pool));
        let alert = crate::alert_router::AlertRouter::new(Arc::clone(&pool));
        let policy_store = Arc::new(
            crate::policy_store::PolicyStore::new(Arc::clone(&pool))
                .expect("policy store"),
        );
        let state = Arc::new(AppState {
            pool,
            policy_store,
            siem,
            alert,
            ad: None,
        });
        let app = admin_router(state);
        let token = mint_admin_jwt();

        let payload = PolicyPayload {
            id: "diag-router-001".to_string(),
            name: "Diag Router Test".to_string(),
            description: None,
            priority: 1,
            conditions: serde_json::json!([]),
            action: "ALLOW".to_string(),
            enabled: true,
        };
        let req = Request::builder()
            .method("POST")
            .uri("/policies")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&payload).unwrap()))
            .expect("build");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Now directly read from the pool (not via router).
        let conn = pool_read.get().expect("acquire connection for read");
        let (count,): (i64,) = conn
            .query_row(
                "SELECT COUNT(*) FROM policies WHERE id = ?1",
                rusqlite::params!["diag-router-001"],
                |row| Ok((row.get::<_, i64>(0)?,)),
            )
            .expect("direct DB read");

        assert_eq!(
            count, 1,
            "POST via router must persist to DB visible via direct read"
        );
    }

    // Verify POST via router then GET-by-ID via router.
    #[tokio::test]
    async fn test_router_post_then_router_get_by_id() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();

        let payload = PolicyPayload {
            id: "diag-getbyid-001".to_string(),
            name: "Diag GetById".to_string(),
            description: None,
            priority: 1,
            conditions: serde_json::json!([]),
            action: "ALLOW".to_string(),
            enabled: true,
        };
        let post_req = Request::builder()
            .method("POST")
            .uri("/policies")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&payload).unwrap()))
            .expect("build POST");
        let post_resp = app.clone().oneshot(post_req).await.expect("oneshot POST");
        eprintln!("POST status: {}", post_resp.status());
        assert_eq!(post_resp.status(), StatusCode::CREATED);

        let get_req = Request::builder()
            .method("GET")
            .uri("/policies/diag-getbyid-001")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build GET");
        let get_resp = app.oneshot(get_req).await.expect("oneshot GET");
        let status = get_resp.status();
        let bytes = to_bytes(get_resp.into_body(), 64 * 1024)
            .await
            .expect("read body");
        eprintln!(
            "GET status: {}, body: {}",
            status,
            String::from_utf8_lossy(&bytes)
        );
        assert_eq!(
            status,
            StatusCode::OK,
            "GET by ID must find the created policy"
        );
    }

    // ── Task 04.1-02 / Task 1: Policy CRUD round-trip tests ──────────────────

    #[tokio::test]
    async fn test_create_policy_persists_and_get_returns_it() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();

        let payload = PolicyPayload {
            id: "pol-create-01".to_string(),
            name: "Restricted Write Block".to_string(),
            description: Some("Blocks T4 writes to removable media".to_string()),
            priority: 100,
            conditions: serde_json::json!([{"attr":"classification","op":"eq","value":"T4"}]),
            action: "DENY".to_string(),
            enabled: true,
        };
        let body = serde_json::to_string(&payload).expect("serialize");

        let create_req = Request::builder()
            .method("POST")
            .uri("/policies")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .expect("build POST");
        let create_resp = app.clone().oneshot(create_req).await.expect("oneshot POST");
        assert_eq!(create_resp.status(), StatusCode::CREATED);

        let bytes = to_bytes(create_resp.into_body(), 64 * 1024)
            .await
            .expect("read body");
        let created: PolicyResponse = serde_json::from_slice(&bytes).expect("parse created policy");
        assert_eq!(created.id, "pol-create-01");
        assert_eq!(created.name, "Restricted Write Block");
        assert_eq!(created.action, "DENY");
        assert_eq!(created.version, 1);
        assert!(created.enabled);

        let get_req = Request::builder()
            .method("GET")
            .uri("/policies/pol-create-01")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build GET");
        let get_resp = app.oneshot(get_req).await.expect("oneshot GET");
        assert_eq!(get_resp.status(), StatusCode::OK);
        let bytes = to_bytes(get_resp.into_body(), 64 * 1024)
            .await
            .expect("read body");
        let fetched: PolicyResponse = serde_json::from_slice(&bytes).expect("parse fetched policy");
        assert_eq!(fetched.id, "pol-create-01");
        assert_eq!(fetched.name, "Restricted Write Block");
    }

    #[tokio::test]
    async fn test_create_policy_rejects_empty_id_or_name() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();

        // Empty id → 400.
        let bad_id = PolicyPayload {
            id: "".to_string(),
            name: "Some name".to_string(),
            description: None,
            priority: 1,
            conditions: serde_json::json!([]),
            action: "ALLOW".to_string(),
            enabled: true,
        };
        let req = Request::builder()
            .method("POST")
            .uri("/policies")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&bad_id).unwrap()))
            .expect("build");
        let resp = app.clone().oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Empty name → 400.
        let bad_name = PolicyPayload {
            id: "pol-bad".to_string(),
            name: "".to_string(),
            description: None,
            priority: 1,
            conditions: serde_json::json!([]),
            action: "ALLOW".to_string(),
            enabled: true,
        };
        let req = Request::builder()
            .method("POST")
            .uri("/policies")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&bad_name).unwrap()))
            .expect("build");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_update_policy_increments_version() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();

        // Seed
        let initial = PolicyPayload {
            id: "pol-update-01".to_string(),
            name: "Initial".to_string(),
            description: None,
            priority: 50,
            conditions: serde_json::json!([]),
            action: "ALLOW".to_string(),
            enabled: true,
        };
        let post_req = Request::builder()
            .method("POST")
            .uri("/policies")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&initial).unwrap()))
            .expect("build");
        let resp = app.clone().oneshot(post_req).await.expect("oneshot POST");
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Update
        let updated = PolicyPayload {
            id: "pol-update-01".to_string(),
            name: "Updated Name".to_string(),
            description: Some("new desc".to_string()),
            priority: 25,
            conditions: serde_json::json!([{"attr":"tier","op":"eq","value":"T3"}]),
            action: "DENY".to_string(),
            enabled: false,
        };
        let put_req = Request::builder()
            .method("PUT")
            .uri("/policies/pol-update-01")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&updated).unwrap()))
            .expect("build");
        let put_resp = app.oneshot(put_req).await.expect("oneshot PUT");
        assert_eq!(put_resp.status(), StatusCode::OK);

        let bytes = to_bytes(put_resp.into_body(), 64 * 1024)
            .await
            .expect("read body");
        let rt: PolicyResponse = serde_json::from_slice(&bytes).expect("parse updated");
        assert_eq!(rt.name, "Updated Name");
        assert_eq!(rt.action, "DENY");
        assert_eq!(rt.priority, 25);
        assert!(!rt.enabled);
        assert_eq!(
            rt.version, 2,
            "version must be incremented by update_policy"
        );
    }

    #[tokio::test]
    async fn test_update_unknown_policy_returns_404() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();

        let payload = PolicyPayload {
            id: "pol-does-not-exist".to_string(),
            name: "x".to_string(),
            description: None,
            priority: 1,
            conditions: serde_json::json!([]),
            action: "ALLOW".to_string(),
            enabled: true,
        };
        let req = Request::builder()
            .method("PUT")
            .uri("/policies/pol-does-not-exist")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&payload).unwrap()))
            .expect("build");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_delete_policy_removes_row_and_subsequent_delete_is_404() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();

        // Seed
        let seed = PolicyPayload {
            id: "pol-delete-01".to_string(),
            name: "To Be Deleted".to_string(),
            description: None,
            priority: 1,
            conditions: serde_json::json!([]),
            action: "ALLOW".to_string(),
            enabled: true,
        };
        let post_req = Request::builder()
            .method("POST")
            .uri("/policies")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&seed).unwrap()))
            .expect("build");
        let resp = app.clone().oneshot(post_req).await.expect("oneshot POST");
        assert_eq!(resp.status(), StatusCode::CREATED);

        // First delete → 204
        let del_req = Request::builder()
            .method("DELETE")
            .uri("/policies/pol-delete-01")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build");
        let del_resp = app.clone().oneshot(del_req).await.expect("oneshot DELETE");
        assert_eq!(del_resp.status(), StatusCode::NO_CONTENT);

        // Second delete → 404
        let del_req2 = Request::builder()
            .method("DELETE")
            .uri("/policies/pol-delete-01")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build");
        let del_resp2 = app.oneshot(del_req2).await.expect("oneshot DELETE 2");
        assert_eq!(del_resp2.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_list_policies_returns_seeded_rows() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();

        for i in 0..3 {
            let payload = PolicyPayload {
                id: format!("pol-list-{i:02}"),
                name: format!("Policy {i}"),
                description: None,
                priority: i as u32,
                conditions: serde_json::json!([]),
                action: "ALLOW".to_string(),
                enabled: true,
            };
            let req = Request::builder()
                .method("POST")
                .uri("/policies")
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .expect("build");
            let resp = app.clone().oneshot(req).await.expect("oneshot POST");
            assert_eq!(resp.status(), StatusCode::CREATED);
        }

        let list_req = Request::builder()
            .method("GET")
            .uri("/policies")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build");
        let list_resp = app.oneshot(list_req).await.expect("oneshot GET");
        assert_eq!(list_resp.status(), StatusCode::OK);
        let bytes = to_bytes(list_resp.into_body(), 64 * 1024)
            .await
            .expect("read body");
        let policies: Vec<PolicyResponse> = serde_json::from_slice(&bytes).expect("parse list");
        assert!(
            policies.len() >= 3,
            "expected at least 3 seeded policies, got {}",
            policies.len()
        );
        let ids: std::collections::HashSet<_> = policies.iter().map(|p| p.id.clone()).collect();
        assert!(ids.contains("pol-list-00"));
        assert!(ids.contains("pol-list-01"));
        assert!(ids.contains("pol-list-02"));
    }

    // ── Task 04.1-02 / Task 2: Audit event ingest and query round-trip tests ─

    /// Build one audit event with the given agent id for seeding tests.
    fn sample_audit_event(agent_id: &str, resource_path: &str) -> dlp_common::AuditEvent {
        dlp_common::AuditEvent::new(
            dlp_common::EventType::Block,
            "S-1-5-21-TEST".to_string(),
            "testuser".to_string(),
            resource_path.to_string(),
            dlp_common::Classification::T4,
            dlp_common::Action::WRITE,
            dlp_common::Decision::DENY,
            agent_id.to_string(),
            1,
        )
        .with_policy("pol-audit-test".to_string(), "Test block".to_string())
    }

    #[tokio::test]
    async fn test_ingest_audit_events_round_trip_and_count() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();

        // POST /audit/events is UNAUTHENTICATED — no Bearer header needed.
        let batch = vec![
            sample_audit_event("AGENT-001", r"C:\Restricted\a.xlsx"),
            sample_audit_event("AGENT-001", r"C:\Restricted\b.xlsx"),
        ];
        let body = serde_json::to_string(&batch).expect("serialize");
        let ingest_req = Request::builder()
            .method("POST")
            .uri("/audit/events")
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .expect("build ingest");
        let ingest_resp = app
            .clone()
            .oneshot(ingest_req)
            .await
            .expect("oneshot ingest");
        assert_eq!(ingest_resp.status(), StatusCode::CREATED);

        // GET /audit/events/count requires a JWT.
        let count_req = Request::builder()
            .method("GET")
            .uri("/audit/events/count")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build count");
        let count_resp = app.clone().oneshot(count_req).await.expect("oneshot count");
        assert_eq!(count_resp.status(), StatusCode::OK);
        let bytes = to_bytes(count_resp.into_body(), 64 * 1024)
            .await
            .expect("read body");
        let count: crate::audit_store::EventCount =
            serde_json::from_slice(&bytes).expect("parse count");
        assert!(
            count.count >= 2,
            "expected at least 2 audit events, got {}",
            count.count
        );

        // GET /audit/events returns the seeded rows.
        let query_req = Request::builder()
            .method("GET")
            .uri("/audit/events")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build query");
        let query_resp = app.oneshot(query_req).await.expect("oneshot query");
        assert_eq!(query_resp.status(), StatusCode::OK);
        let bytes = to_bytes(query_resp.into_body(), 1024 * 1024)
            .await
            .expect("read body");
        let events: Vec<dlp_common::AuditEvent> =
            serde_json::from_slice(&bytes).expect("parse events");
        assert!(
            events.len() >= 2,
            "expected at least 2 events returned, got {}",
            events.len()
        );
        let agent_ids: std::collections::HashSet<_> =
            events.iter().map(|e| e.agent_id.clone()).collect();
        assert!(agent_ids.contains("AGENT-001"));
    }

    #[tokio::test]
    async fn test_ingest_empty_batch_returns_400() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let empty: Vec<dlp_common::AuditEvent> = Vec::new();
        let body = serde_json::to_string(&empty).unwrap();
        let req = Request::builder()
            .method("POST")
            .uri("/audit/events")
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .expect("build");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_ingest_malformed_json_returns_400() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let req = Request::builder()
            .method("POST")
            .uri("/audit/events")
            .header("Content-Type", "application/json")
            .body(Body::from("{ this is not valid JSON ]"))
            .expect("build");
        let resp = app.oneshot(req).await.expect("oneshot");
        // axum 0.7's `Json` extractor maps a JSON parse failure to 422.
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_query_events_filters_by_agent_id() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();

        // Seed with two different agent ids.
        let batch = vec![
            sample_audit_event("AGENT-ALPHA", r"C:\x\one.xlsx"),
            sample_audit_event("AGENT-BETA", r"C:\x\two.xlsx"),
        ];
        let body = serde_json::to_string(&batch).unwrap();
        let ingest = Request::builder()
            .method("POST")
            .uri("/audit/events")
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .expect("build ingest");
        let resp = app.clone().oneshot(ingest).await.expect("oneshot ingest");
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Filter by agent_id = AGENT-ALPHA.
        let q = Request::builder()
            .method("GET")
            .uri("/audit/events?agent_id=AGENT-ALPHA")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build query");
        let qr = app.oneshot(q).await.expect("oneshot query");
        assert_eq!(qr.status(), StatusCode::OK);
        let bytes = to_bytes(qr.into_body(), 1024 * 1024)
            .await
            .expect("read body");
        let events: Vec<dlp_common::AuditEvent> =
            serde_json::from_slice(&bytes).expect("parse events");
        assert!(
            events.iter().all(|e| e.agent_id == "AGENT-ALPHA"),
            "filter returned foreign agent_id"
        );
        assert!(events.iter().any(|e| e.agent_id == "AGENT-ALPHA"));
    }

    #[tokio::test]
    async fn test_audit_event_deny_with_alert_roundtrip() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();

        // POST /audit/events is UNAUTHENTICATED — no Bearer header needed.
        let event = dlp_common::AuditEvent::new(
            dlp_common::EventType::Alert,
            "S-1-5-21-TEST-ALERT".to_string(),
            "alertuser".to_string(),
            r"C:\Restricted\sensitive.docx".to_string(),
            dlp_common::Classification::T4,
            dlp_common::Action::WRITE,
            dlp_common::Decision::DenyWithAlert,
            "AGENT-ALERT-001".to_string(),
            1,
        )
        .with_policy(
            "pol-alert-test".to_string(),
            "DenyWithAlert policy".to_string(),
        );

        let batch = vec![event];
        let body = serde_json::to_string(&batch).expect("serialize");
        let ingest_req = Request::builder()
            .method("POST")
            .uri("/audit/events")
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .expect("build ingest");
        let ingest_resp = app
            .clone()
            .oneshot(ingest_req)
            .await
            .expect("oneshot ingest");
        assert_eq!(ingest_resp.status(), StatusCode::CREATED);

        // GET /audit/events requires a JWT. Retrieve and find our event.
        let query_req = Request::builder()
            .method("GET")
            .uri("/audit/events")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build query");
        let query_resp = app.oneshot(query_req).await.expect("oneshot query");
        assert_eq!(query_resp.status(), StatusCode::OK);
        let bytes = to_bytes(query_resp.into_body(), 1024 * 1024)
            .await
            .expect("read body");
        let events: Vec<dlp_common::AuditEvent> =
            serde_json::from_slice(&bytes).expect("parse events");
        let found = events
            .iter()
            .find(|e| e.agent_id == "AGENT-ALERT-001")
            .expect("DenyWithAlert event must be present after ingest");
        assert_eq!(
            found.decision,
            dlp_common::Decision::DenyWithAlert,
            "retrieved event must have decision == DenyWithAlert"
        );
    }

    // ── Task 04.1-02 / Task 3: JWT auth-gate tests for protected policy routes

    #[tokio::test]
    async fn test_policies_get_without_token_returns_401() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let req = Request::builder()
            .method("GET")
            .uri("/policies")
            .body(Body::empty())
            .expect("build");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_policies_post_with_invalid_token_returns_401() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let payload = PolicyPayload {
            id: "pol-auth-01".to_string(),
            name: "x".to_string(),
            description: None,
            priority: 1,
            conditions: serde_json::json!([]),
            action: "ALLOW".to_string(),
            enabled: true,
        };
        let req = Request::builder()
            .method("POST")
            .uri("/policies")
            .header("Authorization", "Bearer not-a-real-token")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&payload).unwrap()))
            .expect("build");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_policies_get_with_valid_token_returns_200() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();
        let req = Request::builder()
            .method("GET")
            .uri("/policies")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_audit_query_without_token_returns_401() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let req = Request::builder()
            .method("GET")
            .uri("/audit/events")
            .body(Body::empty())
            .expect("build");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ── Task 06-01 / Task 1: AgentConfigPayload serde test ───────────────────

    #[test]
    fn test_agent_config_payload_serde() {
        let payload = AgentConfigPayload {
            monitored_paths: vec![r"C:\Data\".to_string()],
            heartbeat_interval_secs: 60,
            offline_cache_enabled: false,
        };
        let json = serde_json::to_string(&payload).expect("serialize");
        let rt: AgentConfigPayload = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rt, payload);
    }

    // ── Task 06-01 / Task 2: Agent config handler integration tests ───────────

    /// Register a test agent directly in the DB so agent_config_overrides FK is satisfied.
    fn seed_agent(pool: &crate::db::Pool, agent_id: &str) {
        let conn = pool.get().expect("acquire connection");
        conn.execute(
            "INSERT OR IGNORE INTO agents \
             (agent_id, hostname, ip, os_version, agent_version, last_heartbeat, status, registered_at) \
             VALUES (?1, 'test-host', '127.0.0.1', 'Windows 10', '0.1.0', '2026-01-01T00:00:00Z', 'online', '2026-01-01T00:00:00Z')",
            rusqlite::params![agent_id],
        )
        .expect("seed agent");
    }

    #[tokio::test]
    async fn test_get_agent_config_falls_back_to_global() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        crate::admin_auth::set_jwt_secret(TEST_JWT_SECRET.to_string());
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        seed_agent(&pool, "agent-fallback-01");
        let siem = crate::siem_connector::SiemConnector::new(Arc::clone(&pool));
        let alert = crate::alert_router::AlertRouter::new(Arc::clone(&pool));
        let policy_store = Arc::new(
            crate::policy_store::PolicyStore::new(Arc::clone(&pool))
                .expect("policy store"),
        );
        let state = Arc::new(AppState {
            pool,
            policy_store,
            siem,
            alert,
            ad: None,
        });
        let app = admin_router(state);

        // No override set — should return global defaults.
        let req = Request::builder()
            .method("GET")
            .uri("/agent-config/agent-fallback-01")
            .body(Body::empty())
            .expect("build");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("read body");
        let payload: AgentConfigPayload = serde_json::from_slice(&bytes).expect("parse");
        assert_eq!(payload.monitored_paths, Vec::<String>::new());
        assert_eq!(payload.heartbeat_interval_secs, 30);
        assert!(payload.offline_cache_enabled);
    }

    #[tokio::test]
    async fn test_put_global_agent_config() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();

        let new_config = AgentConfigPayload {
            monitored_paths: vec![r"C:\Data\".to_string()],
            heartbeat_interval_secs: 60,
            offline_cache_enabled: true,
        };

        // PUT the new global config.
        let put_req = Request::builder()
            .method("PUT")
            .uri("/admin/agent-config")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&new_config).expect("ser")))
            .expect("build PUT");
        let put_resp = app.clone().oneshot(put_req).await.expect("oneshot PUT");
        assert_eq!(put_resp.status(), StatusCode::OK);

        // GET must return the updated values.
        let get_req = Request::builder()
            .method("GET")
            .uri("/admin/agent-config")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build GET");
        let get_resp = app.oneshot(get_req).await.expect("oneshot GET");
        assert_eq!(get_resp.status(), StatusCode::OK);
        let bytes = to_bytes(get_resp.into_body(), 64 * 1024)
            .await
            .expect("read body");
        let fetched: AgentConfigPayload = serde_json::from_slice(&bytes).expect("parse");
        assert_eq!(fetched.monitored_paths, vec![r"C:\Data\".to_string()]);
        assert_eq!(fetched.heartbeat_interval_secs, 60);
    }

    #[tokio::test]
    async fn test_put_global_config_rejects_low_interval() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();

        let bad_config = AgentConfigPayload {
            monitored_paths: vec![],
            heartbeat_interval_secs: 5,
            offline_cache_enabled: true,
        };
        let req = Request::builder()
            .method("PUT")
            .uri("/admin/agent-config")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&bad_config).expect("ser")))
            .expect("build");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_put_agent_config_override() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        crate::admin_auth::set_jwt_secret(TEST_JWT_SECRET.to_string());
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        seed_agent(&pool, "agent-override-01");
        let siem = crate::siem_connector::SiemConnector::new(Arc::clone(&pool));
        let alert = crate::alert_router::AlertRouter::new(Arc::clone(&pool));
        let policy_store = Arc::new(
            crate::policy_store::PolicyStore::new(Arc::clone(&pool))
                .expect("policy store"),
        );
        let state = Arc::new(AppState {
            pool,
            policy_store,
            siem,
            alert,
            ad: None,
        });
        let app = admin_router(state);
        let token = mint_admin_jwt();

        let override_config = AgentConfigPayload {
            monitored_paths: vec![r"D:\Secret\".to_string()],
            heartbeat_interval_secs: 15,
            offline_cache_enabled: false,
        };

        // PUT per-agent override.
        let put_req = Request::builder()
            .method("PUT")
            .uri("/admin/agent-config/agent-override-01")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_string(&override_config).expect("ser"),
            ))
            .expect("build PUT");
        let put_resp = app.clone().oneshot(put_req).await.expect("oneshot PUT");
        assert_eq!(put_resp.status(), StatusCode::OK);

        // Public GET /agent-config/{id} must return the override, not global.
        let get_req = Request::builder()
            .method("GET")
            .uri("/agent-config/agent-override-01")
            .body(Body::empty())
            .expect("build GET");
        let get_resp = app.oneshot(get_req).await.expect("oneshot GET");
        assert_eq!(get_resp.status(), StatusCode::OK);
        let bytes = to_bytes(get_resp.into_body(), 64 * 1024)
            .await
            .expect("read body");
        let fetched: AgentConfigPayload = serde_json::from_slice(&bytes).expect("parse");
        assert_eq!(fetched.monitored_paths, vec![r"D:\Secret\".to_string()]);
        assert_eq!(fetched.heartbeat_interval_secs, 15);
        assert!(!fetched.offline_cache_enabled);
    }

    #[tokio::test]
    async fn test_delete_agent_config_override() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        crate::admin_auth::set_jwt_secret(TEST_JWT_SECRET.to_string());
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        seed_agent(&pool, "agent-del-01");
        let siem = crate::siem_connector::SiemConnector::new(Arc::clone(&pool));
        let alert = crate::alert_router::AlertRouter::new(Arc::clone(&pool));
        let policy_store = Arc::new(
            crate::policy_store::PolicyStore::new(Arc::clone(&pool))
                .expect("policy store"),
        );
        let state = Arc::new(AppState {
            pool,
            policy_store,
            siem,
            alert,
            ad: None,
        });
        let app = admin_router(state);
        let token = mint_admin_jwt();

        // Seed an override first.
        let override_config = AgentConfigPayload {
            monitored_paths: vec![r"E:\Logs\".to_string()],
            heartbeat_interval_secs: 20,
            offline_cache_enabled: false,
        };
        let put_req = Request::builder()
            .method("PUT")
            .uri("/admin/agent-config/agent-del-01")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_string(&override_config).expect("ser"),
            ))
            .expect("build PUT");
        let put_resp = app.clone().oneshot(put_req).await.expect("oneshot PUT");
        assert_eq!(put_resp.status(), StatusCode::OK);

        // DELETE the override.
        let del_req = Request::builder()
            .method("DELETE")
            .uri("/admin/agent-config/agent-del-01")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build DELETE");
        let del_resp = app.clone().oneshot(del_req).await.expect("oneshot DELETE");
        assert_eq!(del_resp.status(), StatusCode::NO_CONTENT);

        // Public GET must now fall back to global default (heartbeat 30, empty paths).
        let get_req = Request::builder()
            .method("GET")
            .uri("/agent-config/agent-del-01")
            .body(Body::empty())
            .expect("build GET");
        let get_resp = app.oneshot(get_req).await.expect("oneshot GET");
        assert_eq!(get_resp.status(), StatusCode::OK);
        let bytes = to_bytes(get_resp.into_body(), 64 * 1024)
            .await
            .expect("read body");
        let fetched: AgentConfigPayload = serde_json::from_slice(&bytes).expect("parse");
        assert_eq!(fetched.heartbeat_interval_secs, 30);
        assert_eq!(fetched.monitored_paths, Vec::<String>::new());
    }

    #[tokio::test]
    async fn test_get_agent_config_requires_no_auth() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        // Public endpoint: no Authorization header required.
        let app = spawn_admin_app();
        let req = Request::builder()
            .method("GET")
            .uri("/agent-config/any-agent-id")
            .body(Body::empty())
            .expect("build");
        let resp = app.oneshot(req).await.expect("oneshot");
        // 200 OK (falls back to global default — agent_id not required to exist).
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_put_admin_agent_config_requires_jwt() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let config = AgentConfigPayload {
            monitored_paths: vec![],
            heartbeat_interval_secs: 30,
            offline_cache_enabled: true,
        };
        let req = Request::builder()
            .method("PUT")
            .uri("/admin/agent-config")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&config).expect("ser")))
            .expect("build");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ── Phase 12 TC tests: server-side enforcement ──────────────────────────────

    /// Seeds an AuditEvent into the server's audit store via POST /audit/events.
    ///
    /// Used by TC-02 and TC-03 to seed Block/DenyWithAlert events and then
    /// query them back via GET /audit/events.
    async fn seed_tc_audit_event(
        app: &axum::Router,
        tc_id: &str,
        classification: dlp_common::Classification,
        action: dlp_common::Action,
        decision: dlp_common::Decision,
        event_type: dlp_common::EventType,
        resource_path: &str,
    ) -> Result<(), String> {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let event = dlp_common::AuditEvent::new(
            event_type,
            format!("S-1-5-21-TC-{tc_id}"),
            format!("tc-{tc_id}-user"),
            resource_path.to_string(),
            classification,
            action,
            decision,
            format!("AGENT-TC-{tc_id}"),
            1,
        )
        .with_policy(format!("pol-tc-{tc_id}"), format!("TC-{tc_id} policy"));

        let body = serde_json::to_string(&vec![event]).map_err(|e| e.to_string())?;
        let req = Request::builder()
            .method("POST")
            .uri("/audit/events")
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .expect("build seed");
        let resp = app.clone().oneshot(req).await.map_err(|e| e.to_string())?;
        if resp.status() != StatusCode::CREATED {
            return Err(format!("seed failed with status {:?}", resp.status()));
        }
        Ok(())
    }

    /// TC-01: Access Internal file with permission
    /// Expected: allowed | preventive | allow
    ///
    /// Validates that `classify_text` returns T2 for internal-only content.
    /// T2 is not sensitive and maps to Decision::ALLOW in the ABAC engine.
    /// No audit block event is required for T2 access.
    #[tokio::test]
    async fn test_tc_01_internal_file_access_allowed() {
        let text = "For internal only distribution — Q4 planning document";
        let cls = dlp_common::classify_text(text);
        assert_eq!(cls, dlp_common::Classification::T2);
        assert!(!cls.is_sensitive());
        // T2 → ALLOW; server's ABAC engine returns Decision::ALLOW.
    }

    /// TC-02: Access Confidential without permission
    /// Expected: denied | preventive | block, log
    ///
    /// Validates that `classify_text` returns T3 for CONFIDENTIAL keyword.
    /// T3 access triggers Decision::DENY from the ABAC engine.
    /// The audit store must contain an EventType::Block audit event.
    #[tokio::test]
    async fn test_tc_02_confidential_file_access_denied_logged() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let text = "CONFIDENTIAL: M&A deal analysis";
        let cls = dlp_common::classify_text(text);
        assert_eq!(cls, dlp_common::Classification::T3);
        assert!(cls.is_sensitive());

        let app = spawn_admin_app();
        let token = mint_admin_jwt();

        seed_tc_audit_event(
            &app,
            "02",
            dlp_common::Classification::T3,
            dlp_common::Action::READ,
            dlp_common::Decision::DENY,
            dlp_common::EventType::Block,
            r"C:\Confidential\ma_analysis.xlsx",
        )
        .await
        .expect("seed failed");

        let query_req = Request::builder()
            .method("GET")
            .uri("/audit/events")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build query");
        let query_resp = app.oneshot(query_req).await.expect("oneshot query");
        assert_eq!(query_resp.status(), StatusCode::OK);
        let bytes = to_bytes(query_resp.into_body(), 1024 * 1024)
            .await
            .expect("read body");
        let events: Vec<dlp_common::AuditEvent> =
            serde_json::from_slice(&bytes).expect("parse events");
        let tc_event = events
            .iter()
            .find(|e| e.agent_id == "AGENT-TC-02")
            .expect("TC-02 event must be present in audit store");
        assert_eq!(tc_event.decision, dlp_common::Decision::DENY);
        assert_eq!(tc_event.classification, dlp_common::Classification::T3);
        assert_eq!(tc_event.event_type, dlp_common::EventType::Block);
    }

    /// TC-03: Access Restricted by non-privileged user
    /// Expected: denied | preventive | block, alert
    ///
    /// Validates that T4 classification (SSN pattern) triggers
    /// Decision::DenyWithAlert. The audit store must contain an
    /// EventType::Alert audit event (not just Block).
    #[tokio::test]
    async fn test_tc_03_restricted_file_access_denied_alert() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let text = "Employee SSN: 123-45-6789 for payroll processing";
        let cls = dlp_common::classify_text(text);
        assert_eq!(cls, dlp_common::Classification::T4);

        let app = spawn_admin_app();
        let token = mint_admin_jwt();

        seed_tc_audit_event(
            &app,
            "03",
            dlp_common::Classification::T4,
            dlp_common::Action::READ,
            dlp_common::Decision::DenyWithAlert,
            dlp_common::EventType::Alert,
            r"C:\Restricted\secret.xlsx",
        )
        .await
        .expect("seed failed");

        let query_req = Request::builder()
            .method("GET")
            .uri("/audit/events")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build query");
        let query_resp = app.oneshot(query_req).await.expect("oneshot query");
        assert_eq!(query_resp.status(), StatusCode::OK);
        let bytes = to_bytes(query_resp.into_body(), 1024 * 1024)
            .await
            .expect("read body");
        let events: Vec<dlp_common::AuditEvent> =
            serde_json::from_slice(&bytes).expect("parse events");
        let alert_event = events
            .iter()
            .find(|e| e.agent_id == "AGENT-TC-03")
            .expect("TC-03 event must be present in audit store");
        assert_eq!(alert_event.decision, dlp_common::Decision::DenyWithAlert);
        assert_eq!(alert_event.classification, dlp_common::Classification::T4);
        assert!(
            matches!(
                alert_event.event_type,
                dlp_common::EventType::Alert | dlp_common::EventType::Block
            ),
            "T4 block must emit Alert or Block event type"
        );
    }

    /// TC-51: Print Confidential file
    /// Expected: restricted | preventive | require_auth
    ///
    /// Validates classification contract for print interception.
    /// T3 file print → Decision::RequireAuth (not immediate DENY).
    /// Print spooler interception not yet implemented — stub with todo!().
    #[tokio::test]
    #[ignore = "print spooler interception not yet implemented"]
    async fn test_tc_51_print_confidential_require_auth() {
        let text = "CONFIDENTIAL budget report for FY2025";
        let cls = dlp_common::classify_text(text);
        assert_eq!(cls, dlp_common::Classification::T3);
        assert!(cls.is_sensitive());
        // Expected: print action on T3 file → Decision::RequireAuth.
        // Acceptance: print spooler intercept returns require_auth;
        // user must re-authenticate before job reaches print queue.
        todo!("TC-51: print action on T3 file — Decision::RequireAuth — not yet implemented")
    }

    /// TC-52: Print Restricted file
    /// Expected: blocked | preventive | block
    ///
    /// Validates that T4 classification blocks print action.
    /// Print spooler interception not yet implemented — stub with todo!().
    #[tokio::test]
    #[ignore = "print spooler interception not yet implemented"]
    async fn test_tc_52_print_restricted_blocked() {
        let text = "SSN: 123-45-6789 for direct deposit setup";
        let cls = dlp_common::classify_text(text);
        assert_eq!(cls, dlp_common::Classification::T4);
        // Expected: print action on T4 file → Decision::DENY.
        // Acceptance: print spooler intercept returns DENY;
        // job cancelled before reaching print queue.
        todo!("TC-52: print action on T4 file — Decision::DENY — not yet implemented")
    }

    /// TC-80: Access Confidential file — logged, not blocked
    /// Expected: logged | detective | log
    ///
    /// Validates that GET /audit/events returns an EventType::Access event
    /// (not Block) for a Confidential file that was accessed but not blocked.
    /// Detective control: no preventive action, audit-only logging.
    #[tokio::test]
    async fn test_tc_80_confidential_access_logged() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();

        let access_event = dlp_common::AuditEvent::new(
            dlp_common::EventType::Access,
            "S-1-5-21-TC-80".to_string(),
            "tc-80-user".to_string(),
            r"C:\Confidential\report.xlsx".to_string(),
            dlp_common::Classification::T3,
            dlp_common::Action::READ,
            dlp_common::Decision::ALLOW,
            "AGENT-TC-80".to_string(),
            1,
        )
        .with_policy(
            "pol-tc-80".to_string(),
            "TC-80 detective policy".to_string(),
        );

        let body = serde_json::to_string(&vec![access_event]).expect("serialize");
        let ingest_req = Request::builder()
            .method("POST")
            .uri("/audit/events")
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .expect("build ingest");
        let ingest_resp = app
            .clone()
            .oneshot(ingest_req)
            .await
            .expect("oneshot ingest");
        assert_eq!(ingest_resp.status(), StatusCode::CREATED);

        let query_req = Request::builder()
            .method("GET")
            .uri("/audit/events")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build query");
        let query_resp = app.oneshot(query_req).await.expect("oneshot query");
        assert_eq!(query_resp.status(), StatusCode::OK);
        let bytes = to_bytes(query_resp.into_body(), 1024 * 1024)
            .await
            .expect("read body");
        let events: Vec<dlp_common::AuditEvent> =
            serde_json::from_slice(&bytes).expect("parse events");

        let access = events
            .iter()
            .find(|e| e.agent_id == "AGENT-TC-80")
            .expect("TC-80 Access event must be in audit store");

        // Detective control: event_type must be Access (not Block).
        assert_eq!(access.event_type, dlp_common::EventType::Access);
        assert_eq!(access.classification, dlp_common::Classification::T3);
        assert_eq!(access.decision, dlp_common::Decision::ALLOW);
        // No block occurred — key difference from TC-02.
    }
}
