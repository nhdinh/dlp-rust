//! Shared error types for the Policy Engine.
//!
//! Uses `thiserror` for all crate-level error types. `anyhow` is used only at
//! the `main.rs` entry point boundary for context-wrapping.

use http::StatusCode;
use thiserror::Error;

/// Errors that can occur during ABAC policy evaluation.
#[derive(Debug, Error)]
pub enum PolicyEngineError {
    /// No matching policy was found for the request.
    #[error("no matching policy found")]
    NoMatchingPolicy,

    /// The policy store is unavailable or unreadable.
    #[error("policy store error: {0}")]
    PolicyStoreError(String),

    /// A policy failed validation during load or reload.
    #[error("policy validation error: {0}")]
    PolicyValidationError(String),

    /// The requested policy does not exist.
    #[error("policy not found: {0}")]
    PolicyNotFound(String),

    /// Active Directory lookup failed.
    #[error("AD lookup failed: {0}")]
    AdError(String),

    /// The AD cache is unavailable.
    #[error("AD cache error: {0}")]
    AdCacheError(String),

    /// A file system operation failed.
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// A JSON serialization or deserialization error.
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// The policy store watcher encountered an error.
    #[error("watcher error: {0}")]
    WatcherError(String),

    /// Internal error used for invariants that should never be violated.
    #[error("internal error: {0}")]
    Internal(String),
}

impl PolicyEngineError {
    /// Returns `true` if this error represents a client-facing HTTP 4xx condition.
    #[must_use]
    pub fn is_client_error(&self) -> bool {
        matches!(
            self,
            Self::PolicyNotFound(_) | Self::PolicyValidationError(_) | Self::JsonError(_)
        )
    }
}

/// Axum-level application error that maps `PolicyEngineError` to HTTP status codes.
///
/// This type implements `IntoResponse`, allowing it to be returned directly from
/// axum request handlers.
#[derive(Debug)]
pub struct AppError {
    /// The underlying error.
    pub inner: PolicyEngineError,
    /// The HTTP status code to return to the client.
    pub status: StatusCode,
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}

impl std::error::Error for AppError {}

impl From<PolicyEngineError> for AppError {
    fn from(err: PolicyEngineError) -> Self {
        let status = if err.is_client_error() {
            StatusCode::BAD_REQUEST
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        Self { inner: err, status }
    }
}

impl AppError {
    /// Constructs an `AppError` with an explicit status code.
    pub fn with_status(err: PolicyEngineError, status: StatusCode) -> Self {
        Self { inner: err, status }
    }
}

// Required for axum's IntoResponse blanket impl.
impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let body = serde_json::json!({
            "error": self.inner.to_string(),
        });
        (self.status, axum::Json(body)).into_response()
    }
}

/// Result type alias using `PolicyEngineError`.
pub type Result<T> = std::result::Result<T, PolicyEngineError>;
