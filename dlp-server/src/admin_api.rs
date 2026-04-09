//! Admin REST API that aggregates all management endpoints (P5-T09).
//!
//! Builds the complete axum `Router` with all sub-routes. Public
//! endpoints (health, ready, auth) are unauthenticated. All other
//! routes require a valid JWT Bearer token.
//!
//! **Note:** Policy CRUD and evaluation endpoints are served by
//! [`crate::policy_api`] (backed by `PolicyStore` JSON file +
//! hot-reload). This module handles agents, audit, exceptions, and
//! admin auth only.

use std::sync::Arc;

use axum::extract::State;
use axum::middleware;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::Serialize;

use crate::admin_auth;
use crate::agent_registry;
use crate::audit_store;
use crate::db::Database;
use crate::exception_store;
use crate::AppError;

// -----------------------------------------------------------------------
// Response types
// -----------------------------------------------------------------------

/// Health/readiness probe response.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    /// Current server status.
    pub status: String,
    /// ISO 8601 timestamp.
    pub timestamp: String,
}

// -----------------------------------------------------------------------
// Router construction
// -----------------------------------------------------------------------

/// Builds the admin API router for agents, audit, exceptions, and auth.
///
/// Policy CRUD and `/evaluate` are handled by the separate
/// `policy_api` router, which is merged in `main.rs`.
///
/// # Arguments
///
/// * `db` - Shared database handle.
///
/// # Routes
///
/// **Unauthenticated:**
/// - `GET /health` -- health probe
/// - `GET /ready` -- readiness probe
/// - `POST /auth/login` -- admin login
/// - `POST /auth/admin` -- create admin user
/// - `POST /agents/register` -- agent self-registration
/// - `POST /agents/:id/heartbeat` -- agent heartbeat
/// - `POST /audit/events` -- event ingestion (agent-to-server)
///
/// **Authenticated (JWT required):**
/// - `GET /agents` -- list agents
/// - `GET /agents/:id` -- get agent
/// - `GET /audit/events` -- query audit events
/// - `GET /audit/events/count` -- event count
/// - `GET /exceptions` -- list exceptions
/// - `GET /exceptions/:id` -- get exception
/// - `POST /exceptions` -- create exception
pub fn admin_router(db: Arc<Database>) -> Router {
    // Routes that do NOT require authentication.
    let public_routes = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/auth/login", post(admin_auth::login))
        .route("/auth/admin", post(admin_auth::create_admin))
        .route(
            "/agents/register",
            post(agent_registry::register_agent),
        )
        .route(
            "/agents/{id}/heartbeat",
            post(agent_registry::heartbeat),
        )
        .route(
            "/audit/events",
            post(audit_store::ingest_events),
        );

    // Routes that require a valid JWT.
    let protected_routes = Router::new()
        .route("/agents", get(agent_registry::list_agents))
        .route(
            "/agents/{id}",
            get(agent_registry::get_agent),
        )
        .route(
            "/audit/events",
            get(audit_store::query_events),
        )
        .route(
            "/audit/events/count",
            get(audit_store::get_event_count),
        )
        .route(
            "/exceptions",
            get(exception_store::list_exceptions),
        )
        .route(
            "/exceptions/{id}",
            get(exception_store::get_exception),
        )
        .route(
            "/exceptions",
            post(exception_store::create_exception),
        )
        .layer(middleware::from_fn(admin_auth::require_auth));

    public_routes.merge(protected_routes).with_state(db)
}

// -----------------------------------------------------------------------
// Health probes
// -----------------------------------------------------------------------

/// `GET /health` -- liveness probe.
async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        timestamp: Utc::now().to_rfc3339(),
    })
}

/// `GET /ready` -- readiness probe.
async fn ready(
    State(db): State<Arc<Database>>,
) -> Result<Json<HealthResponse>, AppError> {
    // Verify the database is accessible.
    tokio::task::spawn_blocking(move || {
        let conn = db.conn().lock();
        conn.execute_batch("SELECT 1")
    })
    .await
    .map_err(|e| {
        AppError::Internal(anyhow::anyhow!("join error: {e}"))
    })??;

    Ok(Json(HealthResponse {
        status: "ready".to_string(),
        timestamp: Utc::now().to_rfc3339(),
    }))
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
        let json =
            serde_json::to_string(&resp).expect("serialize");
        assert!(json.contains("\"status\":\"ok\""));
    }
}
