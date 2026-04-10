//! Append-only audit event ingestion and query API (P5-T04).
//!
//! Events flow in from dlp-agents via `POST /audit/events` and are stored
//! permanently in SQLite. No update or delete operations are exposed —
//! the audit log is immutable by design.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use dlp_common::AuditEvent;
use serde::{Deserialize, Serialize};

use crate::AppError;
use crate::AppState;

// ---------------------------------------------------------------------------
// Query / response types
// ---------------------------------------------------------------------------

/// Query parameters for `GET /audit/events`.
#[derive(Debug, Clone, Deserialize)]
pub struct EventQuery {
    /// Filter by agent identifier.
    pub agent_id: Option<String>,
    /// Filter by user display name.
    pub user_name: Option<String>,
    /// Filter by classification tier (e.g., "T3").
    pub classification: Option<String>,
    /// Filter by event type (e.g., "BLOCK").
    pub event_type: Option<String>,
    /// ISO 8601 lower bound (inclusive).
    pub from: Option<String>,
    /// ISO 8601 upper bound (inclusive).
    pub to: Option<String>,
    /// Maximum number of rows to return (default 100).
    pub limit: Option<u32>,
    /// Number of rows to skip (for pagination).
    pub offset: Option<u32>,
}

/// Response for `GET /audit/events/count`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventCount {
    /// Total number of audit events stored.
    pub count: i64,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /audit/events` — ingest a batch of audit events (append-only).
///
/// Accepts a JSON array of `AuditEvent` objects. Each event is inserted
/// into the `audit_events` table. Duplicate `correlation_id` values are
/// silently ignored (idempotent ingestion).
///
/// # Errors
///
/// Returns `AppError::BadRequest` if the batch is empty.
/// Returns `AppError::Database` on SQLite failures.
pub async fn ingest_events(
    State(state): State<Arc<AppState>>,
    Json(events): Json<Vec<AuditEvent>>,
) -> Result<StatusCode, AppError> {
    if events.is_empty() {
        return Err(AppError::BadRequest(
            "event batch must not be empty".to_string(),
        ));
    }

    let count = events.len();

    // Clone events before moving into spawn_blocking so we can relay to SIEM after.
    let relay_events = events.clone();

    let db = Arc::clone(&state.db);
    tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let conn = db.conn().lock();

        // Use a transaction for batch atomicity.
        let tx = conn.unchecked_transaction()?;

        for event in &events {
            // Serialize enum fields to their JSON string representations.
            let event_type = serde_json::to_value(event.event_type)?
                .as_str()
                .unwrap_or_default()
                .to_string();
            let classification = serde_json::to_value(event.classification)?
                .as_str()
                .unwrap_or_default()
                .to_string();
            let action = serde_json::to_value(event.action_attempted)?
                .as_str()
                .unwrap_or_default()
                .to_string();
            let decision = serde_json::to_value(event.decision)?
                .as_str()
                .unwrap_or_default()
                .to_string();
            let access_ctx = serde_json::to_value(event.access_context)?
                .as_str()
                .unwrap_or_default()
                .to_string();

            tx.execute(
                "INSERT OR IGNORE INTO audit_events \
                    (timestamp, event_type, user_sid, user_name, \
                     resource_path, classification, action_attempted, \
                     decision, policy_id, policy_name, agent_id, \
                     session_id, access_context, correlation_id) \
                 VALUES \
                    (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, \
                     ?11, ?12, ?13, ?14)",
                rusqlite::params![
                    event.timestamp.to_rfc3339(),
                    event_type,
                    event.user_sid,
                    event.user_name,
                    event.resource_path,
                    classification,
                    action,
                    decision,
                    event.policy_id,
                    event.policy_name,
                    event.agent_id,
                    event.session_id,
                    access_ctx,
                    event.correlation_id,
                ],
            )?;
        }

        tx.commit()?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    // G7: Compute alert-eligible events BEFORE the SIEM spawn so
    // relay_events can still be moved into the SIEM closure while
    // alert_events is moved into the alert closure. Filtered to
    // Decision::DenyWithAlert — do NOT alert on Deny or AllowWithLog.
    let alert_events: Vec<AuditEvent> = relay_events
        .iter()
        .filter(|e| matches!(e.decision, dlp_common::Decision::DenyWithAlert))
        .cloned()
        .collect();

    // Best-effort SIEM relay — fire-and-forget in a background task
    // so the HTTP response is not delayed by external SIEM latency.
    let siem = state.siem.clone();
    tokio::spawn(async move {
        if let Err(e) = siem.relay_events(&relay_events).await {
            tracing::warn!(error = %e, "SIEM relay failed (best-effort)");
        }
    });

    // Best-effort alert routing — fire-and-forget, only when there are
    // DenyWithAlert events. Per-channel (SMTP/webhook) warn! logging
    // happens inside AlertRouter::send_alert (TM-04); this wrapper
    // catches the outer error path only. The spawned task is never
    // awaited — ingest latency must be unaffected by alert I/O.
    if !alert_events.is_empty() {
        let alert = state.alert.clone();
        tokio::spawn(async move {
            for event in alert_events {
                if let Err(e) = alert.send_alert(&event).await {
                    tracing::warn!(error = %e, "alert delivery failed (best-effort)");
                }
            }
        });
    }

    tracing::info!(count, "ingested audit events");
    Ok(StatusCode::CREATED)
}

/// `GET /audit/events` — query audit events with optional filters.
///
/// Supports filtering by agent_id, user_name, classification,
/// event_type, and time range. Results are ordered by timestamp
/// descending.
///
/// # Errors
///
/// Returns `AppError::Database` on SQLite failures.
pub async fn query_events(
    State(state): State<Arc<AppState>>,
    Query(q): Query<EventQuery>,
) -> Result<Json<Vec<serde_json::Value>>, AppError> {
    let db = Arc::clone(&state.db);
    let rows = tokio::task::spawn_blocking(move || {
        let conn = db.conn().lock();

        // Build a dynamic WHERE clause from the provided filters.
        let mut conditions: Vec<String> = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(ref v) = q.agent_id {
            conditions.push(format!("agent_id = ?{}", params.len() + 1));
            params.push(Box::new(v.clone()));
        }
        if let Some(ref v) = q.user_name {
            conditions.push(format!("user_name = ?{}", params.len() + 1));
            params.push(Box::new(v.clone()));
        }
        if let Some(ref v) = q.classification {
            conditions.push(format!("classification = ?{}", params.len() + 1));
            params.push(Box::new(v.clone()));
        }
        if let Some(ref v) = q.event_type {
            conditions.push(format!("event_type = ?{}", params.len() + 1));
            params.push(Box::new(v.clone()));
        }
        if let Some(ref v) = q.from {
            conditions.push(format!("timestamp >= ?{}", params.len() + 1));
            params.push(Box::new(v.clone()));
        }
        if let Some(ref v) = q.to {
            conditions.push(format!("timestamp <= ?{}", params.len() + 1));
            params.push(Box::new(v.clone()));
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        let limit = q.limit.unwrap_or(100);
        let offset = q.offset.unwrap_or(0);

        let sql = format!(
            "SELECT id, timestamp, event_type, user_sid, user_name, \
                    resource_path, classification, action_attempted, \
                    decision, policy_id, policy_name, agent_id, \
                    session_id, access_context, correlation_id \
             FROM audit_events {where_clause} \
             ORDER BY timestamp DESC \
             LIMIT ?{} OFFSET ?{}",
            params.len() + 1,
            params.len() + 2,
        );

        params.push(Box::new(limit));
        params.push(Box::new(offset));

        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|p| p.as_ref()).collect();

        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt
            .query_map(param_refs.as_slice(), |row| {
                Ok(serde_json::json!({
                    "id": row.get::<_, i64>(0)?,
                    "timestamp": row.get::<_, String>(1)?,
                    "event_type": row.get::<_, String>(2)?,
                    "user_sid": row.get::<_, String>(3)?,
                    "user_name": row.get::<_, String>(4)?,
                    "resource_path": row.get::<_, String>(5)?,
                    "classification": row.get::<_, String>(6)?,
                    "action_attempted": row.get::<_, String>(7)?,
                    "decision": row.get::<_, String>(8)?,
                    "policy_id": row.get::<_, Option<String>>(9)?,
                    "policy_name": row.get::<_, Option<String>>(10)?,
                    "agent_id": row.get::<_, String>(11)?,
                    "session_id": row.get::<_, i64>(12)?,
                    "access_context": row.get::<_, String>(13)?,
                    "correlation_id": row.get::<_, Option<String>>(14)?,
                }))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok::<_, rusqlite::Error>(rows)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    Ok(Json(rows))
}

/// `GET /audit/events/count` — return total audit event count.
///
/// # Errors
///
/// Returns `AppError::Database` on SQLite failures.
pub async fn get_event_count(
    State(state): State<Arc<AppState>>,
) -> Result<Json<EventCount>, AppError> {
    let db = Arc::clone(&state.db);
    let count = tokio::task::spawn_blocking(move || {
        let conn = db.conn().lock();
        conn.query_row("SELECT COUNT(*) FROM audit_events", [], |row| {
            row.get::<_, i64>(0)
        })
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    Ok(Json(EventCount { count }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_query_defaults() {
        let json = "{}";
        let q: EventQuery = serde_json::from_str(json).expect("deserialize");
        assert!(q.agent_id.is_none());
        assert!(q.limit.is_none());
        assert!(q.offset.is_none());
    }

    #[test]
    fn test_event_count_serde() {
        let ec = EventCount { count: 42 };
        let json = serde_json::to_string(&ec).expect("serialize");
        let rt: EventCount = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rt.count, 42);
    }
}
