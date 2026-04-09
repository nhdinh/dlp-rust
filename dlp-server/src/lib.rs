//! `dlp-server` -- Central management and policy engine server for the
//! Enterprise DLP System.
//!
//! Provides agent registration, audit event ingestion, ABAC policy
//! evaluation, policy CRUD, SIEM relay, alerting, and admin APIs over
//! HTTP (axum).

pub mod ad_client;
pub mod admin_api;
pub mod admin_auth;
pub mod agent_registry;
pub mod alert_router;
pub mod audit_store;
pub mod bind_registry;
pub mod config_push;
pub mod db;
pub mod engine;
pub mod exception_store;
pub mod policy_api;
pub mod policy_engine_error;
pub mod policy_store;
pub mod siem_connector;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Unified application error type returned by all HTTP handlers.
///
/// Converts internal errors into appropriate HTTP status codes and JSON
/// bodies. This ensures consistent error responses across the entire
/// API surface.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// A database operation failed.
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    /// A JSON serialization or deserialization error.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// A generic internal server error (wraps anyhow for convenience).
    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),

    /// The requested resource was not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// The request is invalid or missing required fields.
    #[error("bad request: {0}")]
    BadRequest(String),

    /// Authentication failed or token is invalid/expired.
    #[error("unauthorized: {0}")]
    Unauthorized(String),
}

/// Converts `AppError` into an axum HTTP response with a JSON body.
///
/// Maps each variant to the appropriate HTTP status code:
/// - `Database` / `Internal` / `Json` -> 500
/// - `NotFound` -> 404
/// - `BadRequest` -> 400
/// - `Unauthorized` -> 401
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::Database(e) => {
                tracing::error!("database error: {e}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    self.to_string(),
                )
            }
            AppError::Json(e) => {
                tracing::error!("json error: {e}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    self.to_string(),
                )
            }
            AppError::Internal(e) => {
                tracing::error!("internal error: {e}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    self.to_string(),
                )
            }
            AppError::NotFound(_) => {
                (StatusCode::NOT_FOUND, self.to_string())
            }
            AppError::BadRequest(_) => {
                (StatusCode::BAD_REQUEST, self.to_string())
            }
            AppError::Unauthorized(_) => {
                (StatusCode::UNAUTHORIZED, self.to_string())
            }
        };

        let body = serde_json::json!({ "error": message });
        (status, axum::Json(body)).into_response()
    }
}
