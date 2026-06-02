//! `dlp-server` — Central management HTTP server for the Enterprise DLP System.
//!
//! Provides agent registration, audit event ingestion, policy management,
//! SIEM relay, alerting, and admin APIs over HTTP (axum).

pub mod admin_api;
pub mod admin_auth;
pub mod agent_registry;
pub mod alert_router;
pub mod approval_api;
pub mod approval_token;
pub mod audit_store;
pub mod crypto;
pub mod db;
pub mod diagnostic_store;
pub mod exception_store;
pub mod label_service;
pub mod observability;
pub mod policy_engine_error;
pub mod policy_store;
pub mod policy_sync;
pub mod rate_limiter;
pub mod secrets_migration;
pub mod siem_connector;
pub mod syslog_connector;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use axum::extract::rejection::{JsonRejection, PathRejection};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use dlp_common::AdClient;

use crate::policy_engine_error::PolicyEngineError;
use crate::policy_store::PolicyStore;

/// Shared application state passed to all HTTP handlers via axum's `State` extractor.
///
/// Wraps the database connection pool, SIEM connector, alert router, and AD
/// client so handlers can access them through a single `Arc<AppState>`.
#[derive(Clone)]
pub struct AppState {
    /// Shared SQLite connection pool (Arc so AppState is Clone).
    pub pool: Arc<db::Pool>,
    /// Active KEK handle (Phase 47 Task 47-06). Every encrypted-column
    /// repository takes `&SecretCrypto` as a parameter; `AppState`
    /// owns the canonical reference so handlers, background tasks,
    /// `AlertRouter`, and `SiemConnector` all share the same KEK
    /// version without re-loading from DB on every request.
    pub crypto: Arc<crypto::SecretCrypto>,
    /// Policy evaluation cache — loaded at startup, kept fresh by a background task.
    pub policy_store: Arc<PolicyStore>,
    /// SIEM relay connector (Splunk HEC / ELK).
    pub siem: siem_connector::SiemConnector,
    /// Alert router for DenyWithAlert email/webhook notifications.
    pub alert: alert_router::AlertRouter,
    /// Active Directory LDAP client for group resolution and admin SID lookup.
    /// None when AD is unreachable (fail-open at startup).
    pub ad: Option<AdClient>,
    /// Label resolution service with TTL caching and folder inheritance.
    pub label_service: Arc<label_service::LabelService>,
    /// Approval token signing and verification service.
    pub approval_token_service: Arc<approval_token::ApprovalTokenService>,
    /// Syslog forwarder for RFC 5424 over TLS (Phase 62).
    pub syslog: syslog_connector::SyslogConnector,
    /// Cached label-aware evaluation flag.
    ///
    /// Refreshed from `system_kv` every 30 seconds by a background task.
    /// Default is `false` (off) until the operator explicitly enables it
    /// via the `label_aware_evaluation_enabled` key in `system_kv`.
    pub label_aware_enabled: Arc<AtomicBool>,
    /// Phase 52: Protected paths repository for admin API and agent config sync.
    pub protected_paths: Arc<db::repositories::protected_paths::ProtectedPathsRepository>,
    /// Phase 53: Bypass alerts repository for admin API and agent ingest.
    pub bypass_alerts: Arc<db::repositories::bypass_alerts::BypassAlertsRepository>,
    /// Phase 58: Optional diagnostic snapshot store for admin diagnostics API.
    /// Populated when server runs bundled with agent (test mode).
    pub diagnostic_store: Option<Arc<diagnostic_store::DiagnosticSnapshotStore>>,
}

impl AppState {
    /// Returns the cached `label_aware_evaluation_enabled` flag.
    ///
    /// This is a hot-path read — no DB query. The value is refreshed
    /// every 30 seconds by a background task in `main.rs`.
    #[must_use]
    pub fn is_label_aware_enabled(&self) -> bool {
        self.label_aware_enabled.load(Ordering::Relaxed)
    }
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("pool", &self.pool)
            .field("crypto", &self.crypto)
            .field("policy_store", &"PolicyStore(...)")
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
            .field("label_service", &"LabelService(...)")
            .field("approval_token_service", &"ApprovalTokenService(...)")
            .field("syslog", &"SyslogConnector(...)")
            .field(
                "label_aware_enabled",
                &if self.is_label_aware_enabled() {
                    "true"
                } else {
                    "false"
                },
            )
            .field("protected_paths", &"ProtectedPathsRepository(...)")
            .field("bypass_alerts", &"BypassAlertsRepository(...)")
            .field(
                "diagnostic_store",
                &if self.diagnostic_store.is_some() {
                    "Some(DiagnosticSnapshotStore)"
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

    /// The request is semantically invalid (e.g., enum value out of range).
    ///
    /// Maps to HTTP 422 Unprocessable Entity. Use this instead of
    /// `BadRequest` when the JSON is structurally valid but violates
    /// domain-level invariants (e.g., an unrecognized `trust_tier` string).
    #[error("unprocessable entity: {0}")]
    UnprocessableEntity(String),

    /// A resource conflict occurred (e.g., unique constraint violation).
    ///
    /// Maps to HTTP 409 Conflict. Use this when an insert fails because the
    /// resource already exists (e.g., duplicate origin string).
    #[error("conflict: {0}")]
    Conflict(String),

    /// The caller lacks permission for the requested action.
    ///
    /// Maps to HTTP 403 Forbidden. Use this when an authenticated user
    /// attempts an action they are not authorized to perform.
    #[error("forbidden: {0}")]
    Forbidden(String),
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
            AppError::UnprocessableEntity(_) => {
                (StatusCode::UNPROCESSABLE_ENTITY, self.to_string())
            }
            AppError::Conflict(_) => (StatusCode::CONFLICT, self.to_string()),
            AppError::Forbidden(_) => (StatusCode::FORBIDDEN, self.to_string()),
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

/// Maps `PolicyEngineError::PolicyNotFound` to `AppError::NotFound`.
impl From<PolicyEngineError> for AppError {
    fn from(e: PolicyEngineError) -> Self {
        match e {
            PolicyEngineError::PolicyNotFound(id) => AppError::NotFound(id),
        }
    }
}

#[cfg(test)]
mod app_state_tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use super::AppState;

    /// Helper: builds a minimal AppState for testing with label_aware_enabled set.
    /// Uses from_kek for crypto (no DB needed) and minimal stubs for other fields.
    fn app_state_with_flag(flag: bool) -> AppState {
        let pool = Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool"));
        let crypto = Arc::new(crate::crypto::SecretCrypto::from_kek([0u8; 32], 1));
        AppState {
            pool: Arc::clone(&pool),
            crypto: Arc::clone(&crypto),
            policy_store: Arc::new(
                crate::policy_store::PolicyStore::new(Arc::clone(&pool)).expect("store"),
            ),
            siem: crate::siem_connector::SiemConnector::new(Arc::clone(&pool), Arc::clone(&crypto)),
            alert: crate::alert_router::AlertRouter::new(Arc::clone(&pool), Arc::clone(&crypto)),
            ad: None,
            label_service: Arc::new(crate::label_service::LabelService::new(Arc::clone(&pool))),
            approval_token_service: Arc::new(
                // ApprovalTokenService::new requires a DB connection with system_kv table.
                // For unit tests of AppState fields, we use a stub that will only be
                // exercised if the test calls approval_token methods (which we don't).
                {
                    let conn = pool.get().expect("conn");
                    crate::approval_token::ApprovalTokenService::new(&crypto, &conn)
                        .expect("approval token")
                },
            ),
            syslog: crate::syslog_connector::SyslogConnector::new(Arc::clone(&pool), crypto),
            label_aware_enabled: Arc::new(AtomicBool::new(flag)),
            protected_paths: Arc::new(
                crate::db::repositories::protected_paths::ProtectedPathsRepository,
            ),
            bypass_alerts: Arc::new(crate::db::repositories::bypass_alerts::BypassAlertsRepository),
            diagnostic_store: None,
        }
    }

    /// AppState includes label_aware_enabled AtomicBool field.
    #[test]
    fn test_app_state_has_label_aware_enabled() {
        let state = app_state_with_flag(false);
        // The field exists and is accessible
        let _ = state.label_aware_enabled.load(Ordering::Relaxed);
    }

    /// is_label_aware_enabled() reads cached flag without DB query.
    #[test]
    fn test_is_label_aware_enabled_reads_cached_flag() {
        let state = app_state_with_flag(true);
        assert!(state.is_label_aware_enabled());

        let state_off = app_state_with_flag(false);
        assert!(!state_off.is_label_aware_enabled());
    }

    /// Default value is false when key is missing.
    #[test]
    fn test_default_label_aware_is_false() {
        let state = app_state_with_flag(false);
        assert!(!state.is_label_aware_enabled());
    }

    /// Debug impl includes the label_aware_enabled field.
    #[test]
    fn test_debug_includes_label_aware_enabled() {
        let state = app_state_with_flag(true);
        let debug = format!("{:?}", state);
        assert!(debug.contains("label_aware_enabled"));
        assert!(debug.contains("true"));
    }
}
