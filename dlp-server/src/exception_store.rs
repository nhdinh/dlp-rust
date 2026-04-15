//! Exception/override approval records (P5-T08).
//!
//! Exceptions grant temporary overrides to DLP policies for specific
//! users. Each exception has a fixed duration and is tracked with
//! approver identity and justification.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::AppError;
use crate::AppState;

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// Payload for creating a new policy exception.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateExceptionRequest {
    /// The ID of the policy to override.
    pub policy_id: String,
    /// The SID of the user who receives the exception.
    pub user_sid: String,
    /// The admin who approved this exception.
    pub approver: String,
    /// Business justification for the exception.
    pub justification: String,
    /// Duration in seconds for which the exception is valid.
    pub duration_seconds: i64,
}

/// An exception record returned by the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Exception {
    /// Unique exception identifier.
    pub id: String,
    /// The policy being overridden.
    pub policy_id: String,
    /// The user receiving the exception.
    pub user_sid: String,
    /// The admin who approved it.
    pub approver: String,
    /// Business justification.
    pub justification: String,
    /// Duration in seconds.
    pub duration_seconds: i64,
    /// ISO 8601 timestamp when granted.
    pub granted_at: String,
    /// ISO 8601 timestamp when the exception expires.
    pub expires_at: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /exceptions` — create a new policy exception.
///
/// Generates a unique ID and computes the expiry from the current
/// time plus the requested duration.
///
/// # Errors
///
/// Returns `AppError::BadRequest` if required fields are empty.
/// Returns `AppError::Database` on SQLite failures.
pub async fn create_exception(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateExceptionRequest>,
) -> Result<Json<Exception>, AppError> {
    if payload.policy_id.is_empty() || payload.user_sid.is_empty() {
        return Err(AppError::BadRequest(
            "policy_id and user_sid are required".to_string(),
        ));
    }

    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let granted_at = now.to_rfc3339();
    let expires_at = (now + chrono::Duration::seconds(payload.duration_seconds)).to_rfc3339();

    let exception = Exception {
        id: id.clone(),
        policy_id: payload.policy_id,
        user_sid: payload.user_sid,
        approver: payload.approver,
        justification: payload.justification,
        duration_seconds: payload.duration_seconds,
        granted_at,
        expires_at,
    };

    let exc = exception.clone();
    let pool = Arc::clone(&state.pool);
    tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let conn = pool.get().map_err(AppError::from)?;
        conn.execute(
            "INSERT INTO exceptions \
                (id, policy_id, user_sid, approver, justification, \
                 duration_seconds, granted_at, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                exc.id,
                exc.policy_id,
                exc.user_sid,
                exc.approver,
                exc.justification,
                exc.duration_seconds,
                exc.granted_at,
                exc.expires_at,
            ],
        )?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!(exception_id = %exception.id, "exception created");
    Ok(Json(exception))
}

/// `GET /exceptions` — list all exceptions.
///
/// # Errors
///
/// Returns `AppError::Database` on SQLite failures.
pub async fn list_exceptions(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<Exception>>, AppError> {
    let pool = Arc::clone(&state.pool);
    let exceptions = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let conn = pool.get().map_err(AppError::from)?;
        let mut stmt = conn.prepare(
            "SELECT id, policy_id, user_sid, approver, \
                    justification, duration_seconds, \
                    granted_at, expires_at \
             FROM exceptions ORDER BY granted_at DESC",
        )?;

        let rows = stmt
            .query_map([], |row| {
                Ok(Exception {
                    id: row.get(0)?,
                    policy_id: row.get(1)?,
                    user_sid: row.get(2)?,
                    approver: row.get(3)?,
                    justification: row.get(4)?,
                    duration_seconds: row.get(5)?,
                    granted_at: row.get(6)?,
                    expires_at: row.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok::<_, AppError>(rows)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    Ok(Json(exceptions))
}

/// `GET /exceptions/{id}` — get a single exception by ID.
///
/// # Errors
///
/// Returns `AppError::NotFound` if the exception does not exist.
pub async fn get_exception(
    State(state): State<Arc<AppState>>,
    Path(exception_id): Path<String>,
) -> Result<Json<Exception>, AppError> {
    let id = exception_id.clone();
    let pool = Arc::clone(&state.pool);

    let result = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let conn = pool.get().map_err(|e: r2d2::Error| AppError::from(e))?;
        let exc = conn.query_row(
            "SELECT id, policy_id, user_sid, approver, \
                    justification, duration_seconds, \
                    granted_at, expires_at \
             FROM exceptions WHERE id = ?1",
            rusqlite::params![id],
            |row| {
                Ok(Exception {
                    id: row.get(0)?,
                    policy_id: row.get(1)?,
                    user_sid: row.get(2)?,
                    approver: row.get(3)?,
                    justification: row.get(4)?,
                    duration_seconds: row.get(5)?,
                    granted_at: row.get(6)?,
                    expires_at: row.get(7)?,
                })
            },
        )
        .map_err(AppError::from)?;
        Ok(exc)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))?;

    match result {
        Ok(exc) => Ok(Json(exc)),
        Err(AppError::NotFound(_)) => Err(AppError::NotFound(format!(
            "exception {exception_id} not found"
        ))),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_exception_request_serde() {
        let json = r#"{
            "policy_id": "pol-001",
            "user_sid": "S-1-5-21-123",
            "approver": "admin",
            "justification": "Emergency access needed",
            "duration_seconds": 3600
        }"#;
        let req: CreateExceptionRequest = serde_json::from_str(json).expect("deserialize");
        assert_eq!(req.policy_id, "pol-001");
        assert_eq!(req.duration_seconds, 3600);
    }

    #[test]
    fn test_exception_serde_round_trip() {
        let exc = Exception {
            id: "exc-001".to_string(),
            policy_id: "pol-001".to_string(),
            user_sid: "S-1-5-21-123".to_string(),
            approver: "admin".to_string(),
            justification: "Testing".to_string(),
            duration_seconds: 7200,
            granted_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: "2026-01-01T02:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&exc).expect("serialize");
        let rt: Exception = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(exc.id, rt.id);
        assert_eq!(exc.duration_seconds, rt.duration_seconds);
    }
}
