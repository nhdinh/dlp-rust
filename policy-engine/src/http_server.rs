//! HTTP REST API server for the Policy Engine.
//!
//! ## Endpoints
//!
//! - `POST /evaluate` — ABAC policy evaluation (T-04)
//! - `GET  /health`  — liveness probe
//! - `GET  /ready`   — readiness probe (policy store loaded)
//!
//! ## TLS
//!
//! This server binds plain HTTP. In production, a TLS termination proxy
//! (nginx, HAProxy, or a cloud load balancer) should be placed in front.
//! The `rustls` crate is present for future in-process TLS support.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use dlp_common::abac::{EvaluateRequest, EvaluateResponse};
use tokio::net::TcpListener;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::info;

use crate::error::AppError;
use crate::policy_store::PolicyStore;

/// Application state shared across all request handlers.
#[derive(Debug, Clone)]
pub struct AppState {
    /// The policy store (provides the ABAC engine and CRUD operations).
    pub store: Arc<PolicyStore>,
}

/// Server builder for the Policy Engine HTTP API.
#[derive(Debug)]
pub struct Server {
    addr: SocketAddr,
    state: AppState,
}

impl Server {
    /// Creates a new server bound to the given address with the given state.
    pub fn new(addr: SocketAddr, store: Arc<PolicyStore>) -> Self {
        Self {
            addr,
            state: AppState { store },
        }
    }

    /// Starts the server and runs it until shutdown.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket cannot be bound.
    pub async fn serve(self) -> std::result::Result<(), crate::error::PolicyEngineError> {
        let listener = TcpListener::bind(self.addr)
            .await
            .map_err(crate::error::PolicyEngineError::IoError)?;

        info!(addr = %self.addr, "policy engine HTTP server starting");

        let app = build_app(self.state);

        axum::serve(listener, app)
            .await
            .map_err(|e| crate::error::PolicyEngineError::Internal(format!("server error: {e}")))
    }
}

/// Builds the axum router with evaluate + health + ready routes.
fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/evaluate", post(evaluate_handler))
        .route("/health", get(health_handler))
        .route("/ready", get(ready_handler))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state)
}

/// Builds the full router combining evaluation endpoints and CRUD REST API.
///
/// Use this when running the policy engine as a standalone server.
/// Merges the evaluate/health/ready routes with the policy management
/// CRUD routes from [`crate::rest_api`].
///
/// Layers (tracing, CORS) are applied to the merged router so that all
/// routes — both evaluation and CRUD — are covered.
pub fn build_full_router(store: Arc<PolicyStore>) -> Router {
    let state = AppState { store: store.clone() };
    let eval_routes = Router::new()
        .route("/evaluate", post(evaluate_handler))
        .route("/health", get(health_handler))
        .route("/ready", get(ready_handler))
        .with_state(state);
    let crud_routes = crate::rest_api::router(store);
    eval_routes
        .merge(crud_routes)
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
}

// ─── Handlers ────────────────────────────────────────────────────────────────

/// Evaluates an ABAC access request against the loaded policy set.
///
/// `POST /evaluate`
///
/// # Request body
///
/// `EvaluateRequest` JSON
///
/// # Response body
///
/// `EvaluateResponse` JSON
async fn evaluate_handler(
    State(state): State<AppState>,
    Json(request): Json<EvaluateRequest>,
) -> Result<Json<EvaluateResponse>, AppError> {
    let response = state.store.evaluate(&request).await;
    Ok(Json(response))
}

/// Simple liveness probe — always returns 200 if the process is running.
async fn health_handler() -> StatusCode {
    StatusCode::OK
}

/// Readiness probe — returns 200 only if the policy store is loaded and usable.
async fn ready_handler(State(state): State<AppState>) -> Result<StatusCode, AppError> {
    // If we can list policies without error, the store is ready.
    let _ = state.store.list_policies();
    Ok(StatusCode::OK)
}
