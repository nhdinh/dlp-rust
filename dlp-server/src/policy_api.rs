//! Policy evaluation and CRUD REST API.
//!
//! ## Endpoints
//!
//! | Method | Path                     | Description                  |
//! |--------|--------------------------|------------------------------|
//! | POST   | `/evaluate`              | ABAC policy evaluation       |
//! | GET    | `/health`                | Liveness probe               |
//! | GET    | `/ready`                 | Readiness probe              |
//! | GET    | `/policies`              | List all policies            |
//! | POST   | `/policies`              | Create a new policy          |
//! | GET    | `/policies/{id}`          | Get a single policy          |
//! | PUT    | `/policies/{id}`          | Update an existing policy    |
//! | DELETE | `/policies/{id}`          | Delete a policy              |
//! | GET    | `/policies/{id}/versions` | Get version history (stub)   |

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{get, post};
use axum::Router;
use dlp_common::abac::{EvaluateRequest, EvaluateResponse, Policy};
use tracing::info;

use crate::policy_engine_error::PolicyEngineError;
use crate::policy_store::PolicyStore;
use crate::AppError;

/// Builds the full policy evaluation + CRUD router.
///
/// Layers (tracing, CORS) are applied by the caller so that all routes
/// share the same middleware stack.
pub fn router(store: Arc<PolicyStore>) -> Router<()> {
    Router::new()
        .route("/evaluate", post(evaluate_handler))
        .route(
            "/policies",
            get(list_policies).post(create_policy),
        )
        .route(
            "/policies/{id}",
            get(get_policy)
                .put(update_policy)
                .delete(delete_policy),
        )
        .route(
            "/policies/{id}/versions",
            get(get_policy_versions),
        )
        .with_state(store)
}

// ---- Evaluate handler ---------------------------------------------------

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
    State(store): State<Arc<PolicyStore>>,
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
        "policy evaluation request from agent"
    );

    let response = store.evaluate(&request).await;
    Ok(Json(response))
}

// ---- CRUD handlers ------------------------------------------------------

/// `GET /policies` -- list all currently loaded policies.
async fn list_policies(
    State(store): State<Arc<PolicyStore>>,
) -> Result<Json<Vec<Policy>>, AppError> {
    Ok(Json(store.list_policies()))
}

/// `POST /policies` -- create a new policy.
///
/// The policy ID must be unique. The version is assigned by the store.
async fn create_policy(
    State(store): State<Arc<PolicyStore>>,
    Json(policy): Json<Policy>,
) -> Result<(StatusCode, Json<Policy>), AppError> {
    let policy_id = policy.id.clone();
    store
        .add_policy(policy)
        .map_err(AppError::from)?;
    info!(policy_id = %policy_id, "policy created via REST API");
    let stored = store
        .list_policies()
        .into_iter()
        .find(|p| p.id == policy_id)
        .ok_or_else(|| {
            AppError::Internal(anyhow::anyhow!(
                "policy disappeared after add_policy"
            ))
        })?;
    Ok((StatusCode::CREATED, Json(stored)))
}

/// `GET /policies/{id}` -- retrieve a single policy by ID.
async fn get_policy(
    State(store): State<Arc<PolicyStore>>,
    Path(id): Path<String>,
) -> Result<Json<Policy>, AppError> {
    store
        .list_policies()
        .into_iter()
        .find(|p| p.id == id)
        .map(Json)
        .ok_or_else(|| {
            AppError::from(PolicyEngineError::PolicyNotFound(id))
        })
}

/// `PUT /policies/{id}` -- update an existing policy.
///
/// The policy's version is incremented on update.
async fn update_policy(
    State(store): State<Arc<PolicyStore>>,
    Path(id): Path<String>,
    Json(policy): Json<Policy>,
) -> Result<Json<Policy>, AppError> {
    store
        .update_policy(&id, policy)
        .map_err(AppError::from)?;
    info!(policy_id = %id, "policy updated via REST API");
    let updated = store
        .list_policies()
        .into_iter()
        .find(|p| p.id == id)
        .ok_or_else(|| {
            AppError::Internal(anyhow::anyhow!(
                "policy disappeared after update_policy"
            ))
        })?;
    Ok(Json(updated))
}

/// `DELETE /policies/{id}` -- delete a policy by ID.
async fn delete_policy(
    State(store): State<Arc<PolicyStore>>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    store
        .delete_policy(&id)
        .map_err(AppError::from)?;
    info!(policy_id = %id, "policy deleted via REST API");
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /policies/{id}/versions` -- get version history for a policy.
///
/// Currently returns the single current version. Full history tracking
/// is a future enhancement.
async fn get_policy_versions(
    State(store): State<Arc<PolicyStore>>,
    Path(id): Path<String>,
) -> Result<Json<Vec<u64>>, AppError> {
    let policy = store
        .list_policies()
        .into_iter()
        .find(|p| p.id == id)
        .ok_or_else(|| {
            AppError::from(PolicyEngineError::PolicyNotFound(
                id.clone(),
            ))
        })?;
    Ok(Json(vec![policy.version]))
}
