//! REST CRUD API for policy management.
//!
//! ## Endpoints
//!
//! | Method | Path                     | Description                  |
//! |--------|--------------------------|------------------------------|
//! | GET    | `/policies`              | List all policies            |
//! | POST   | `/policies`              | Create a new policy          |
//! | GET    | `/policies/:id`          | Get a single policy           |
//! | PUT    | `/policies/:id`          | Update an existing policy     |
//! | DELETE | `/policies/:id`          | Delete a policy               |
//! | GET    | `/policies/:id/versions` | Get version history (stub)    |
//!
//! OpenAPI 3.0 specification is generated via `utoipa` when the feature flag
//! `openapi` is enabled.

use std::sync::Arc;

#[allow(unused_imports)]
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use dlp_common::abac::Policy;
use tracing::info;

use crate::error::{AppError, PolicyEngineError};
use crate::policy_store::PolicyStore;

/// Application state for the REST API.
#[derive(Debug, Clone)]
pub struct RestState {
    pub store: Arc<PolicyStore>,
}

/// Builds the CRUD router.
pub fn router(store: Arc<PolicyStore>) -> Router {
    let state = RestState { store };
    Router::new()
        .route("/policies", get(list_policies).post(create_policy))
        .route(
            "/policies/:id",
            get(get_policy).put(update_policy).delete(delete_policy),
        )
        .route("/policies/{id}/versions", get(get_policy_versions))
        .with_state(state)
}

// ─── Handlers ────────────────────────────────────────────────────────────────

/// Lists all currently loaded policies.
async fn list_policies(State(state): State<RestState>) -> Result<Json<Vec<Policy>>, AppError> {
    Ok(Json(state.store.list_policies()))
}

/// Creates a new policy.
///
/// The policy ID must be unique. The version is assigned by the store.
async fn create_policy(
    State(state): State<RestState>,
    Json(policy): Json<Policy>,
) -> Result<(StatusCode, Json<Policy>), AppError> {
    let policy_id = policy.id.clone();
    state
        .store
        .add_policy(policy)
        .map_err(AppError::PolicyEngine)?;
    info!(policy_id = %policy_id, "policy created via REST API");
    // Return 201 Created with the stored policy (has version assigned).
    let stored = state
        .store
        .list_policies()
        .into_iter()
        .find(|p| p.id == policy_id)
        .expect("policy must be present after add_policy");
    Ok((StatusCode::CREATED, Json(stored)))
}

/// Retrieves a single policy by ID.
async fn get_policy(
    State(state): State<RestState>,
    Path(id): Path<String>,
) -> Result<Json<Policy>, AppError> {
    state
        .store
        .list_policies()
        .into_iter()
        .find(|p| p.id == id)
        .map(Json)
        .ok_or_else(|| AppError::PolicyEngine(PolicyEngineError::PolicyNotFound(id)))
}

/// Updates an existing policy.
///
/// The policy's version is incremented on update.
async fn update_policy(
    State(state): State<RestState>,
    Path(id): Path<String>,
    Json(policy): Json<Policy>,
) -> Result<Json<Policy>, AppError> {
    state
        .store
        .update_policy(&id, policy)
        .map_err(AppError::PolicyEngine)?;
    info!(policy_id = %id, "policy updated via REST API");
    let updated = state
        .store
        .list_policies()
        .into_iter()
        .find(|p| p.id == id)
        .expect("policy must be present after update_policy");
    Ok(Json(updated))
}

/// Deletes a policy by ID.
async fn delete_policy(
    State(state): State<RestState>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    state
        .store
        .delete_policy(&id)
        .map_err(AppError::PolicyEngine)?;
    info!(policy_id = %id, "policy deleted via REST API");
    Ok(StatusCode::NO_CONTENT)
}

/// Returns the version history for a policy.
///
/// Currently returns the single current version. Full history tracking
/// (T-06) is implemented by persisting previous versions on update.
async fn get_policy_versions(
    State(state): State<RestState>,
    Path(id): Path<String>,
) -> Result<Json<Vec<u64>>, AppError> {
    let policy = state
        .store
        .list_policies()
        .into_iter()
        .find(|p| p.id == id)
        .ok_or_else(|| AppError::PolicyEngine(PolicyEngineError::PolicyNotFound(id.clone())))?;
    // Return the current version only until full history tracking is implemented.
    Ok(Json(vec![policy.version]))
}
