//! `dlp-server` — Central management HTTP server for the Enterprise DLP System.
//!
//! Provides agent registration, audit event ingestion, policy management,
//! SIEM relay, alerting, and admin APIs over HTTP (axum).

pub mod admin_api;
pub mod admin_auth;
pub mod agent_registry;
pub mod alert_router;
pub mod audit_store;
pub mod db;
pub mod exception_store;
pub mod policy_sync;
pub mod siem_connector;

use std::sync::Arc;

use axum::extract::rejection::{JsonRejection, PathRejection};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use dlp_common::AdClient;

/// Shared application state passed to all HTTP handlers via axum's `State` extractor.
///
/// Wraps the database connection pool, SIEM connector, alert router, and AD
/// client so handlers can access them through a single `Arc<AppState>`.
#[derive(Clone)]
pub struct AppState {
    /// Shared SQLite connection pool (Arc so AppState is Clone).
    pub pool: Arc<db::Pool>,
    /// SIEM relay connector (Splunk HEC / ELK).
    pub siem: siem_connector::SiemConnector,
    /// Alert router for DenyWithAlert email/webhook notifications.
    pub alert: alert_router::AlertRouter,
    /// Active Directory LDAP client for group resolution and admin SID lookup.
    /// None when AD is unreachable (fail-open at startup).
    pub ad: Option<AdClient>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("pool", &self.pool)
            .field("siem", &self.siem)
            .field("alert", &self.alert)
            .field(
                "ad",
                &if self.ad.is_some() {
                    "AdClient(...)"
                } else {
                    "None"
                },
            )
            .finish()
    }
}

/// Unified application error type returned by all HTTP handlers.
///
/// Converts internal errors into appropriate HTTP status codes and JSON bodies.
/// This ensures consistent error responses across the entire API surface.
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

/// Converts axum extract rejections into `AppError::BadRequest`.
impl From<JsonRejection> for AppError {
    fn from(e: JsonRejection) -> Self {
        AppError::BadRequest(e.to_string())
    }
}

/// Converts axum path extraction rejections into `AppError::BadRequest`.
impl From<PathRejection> for AppError {
    fn from(e: PathRejection) -> Self {
        AppError::BadRequest(e.to_string())
    }
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
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
            AppError::Json(e) => {
                tracing::error!("json error: {e}");
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
            AppError::Internal(e) => {
                tracing::error!("internal error: {e}");
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
            AppError::NotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            AppError::BadRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::Unauthorized(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
        };

        let body = serde_json::json!({ "error": message });
        (status, axum::Json(body)).into_response()
    }
}

/// Maps pool acquisition errors to internal server errors.
impl From<r2d2::Error> for AppError {
    fn from(e: r2d2::Error) -> Self {
        AppError::Internal(anyhow::anyhow!("pool error: {e}"))
    }
}
