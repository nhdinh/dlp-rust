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

use crate::db::repositories::audit_events::{AuditEventFilter, AuditEventRepository};
use crate::db::repositories::AuditEventRow;
use crate::db::UnitOfWork;
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
// Sync helper (for use inside spawn_blocking)
// ---------------------------------------------------------------------------

/// Synchronously stores audit events directly to the DB via a UnitOfWork.
///
/// Used by admin audit handlers that run inside `spawn_blocking` — we cannot
/// call the async `ingest_events` from within a blocking thread without
/// deadlocking the async runtime. JSON serialization of enum fields stays here.
pub fn store_events_sync(
    uow: &UnitOfWork<'_>,
    events: &[AuditEvent],
) -> Result<(), AppError> {
    let rows: Vec<AuditEventRow> = events
        .iter()
        .map(|event| {
            Ok(AuditEventRow {
                timestamp: event.timestamp.to_rfc3339(),
                event_type: serde_json::to_string(&event.event_type)?,
                user_sid: event.user_sid.clone(),
                user_name: event.user_name.clone(),
                resource_path: event.resource_path.clone(),
                classification: serde_json::to_string(&event.classification)?,
                action_attempted: serde_json::to_string(&event.action_attempted)?,
                decision: serde_json::to_string(&event.decision)?,
                policy_id: event.policy_id.clone(),
                policy_name: event.policy_name.clone(),
                agent_id: event.agent_id.clone(),
                session_id: event.session_id as i64,
                access_context: serde_json::to_string(&event.access_context)?,
                correlation_id: event.correlation_id.clone(),
            })
        })
        .collect::<Result<Vec<_>, serde_json::Error>>()?;
    AuditEventRepository::insert_batch(uow, &rows).map_err(AppError::from)?;
    Ok(())
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
    // LO-03 (deferred): this clones the full batch into relay_events, then
    // filter+clone again into alert_events below (lines 147-151). Each
    // DenyWithAlert event is cloned twice (2N allocations for N events).
    // Fix with Arc<AuditEvent> wrapping: Arc-clone at line 77 instead of
    // full clone, then Arc-clone the filter subset. Requires updating
    // SiemConnector::relay_events and AlertRouter::send_alert signatures.
    let relay_events = events.clone();

    let pool = Arc::clone(&state.pool);
    let events_for_repo = events.clone();
    tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = UnitOfWork::new(&mut conn).map_err(AppError::from)?;

        // Pre-serialize enum fields into AuditEventRow structs.
        let rows: Vec<AuditEventRow> = events_for_repo
            .iter()
            .map(|event| {
                Ok(AuditEventRow {
                    timestamp: event.timestamp.to_rfc3339(),
                    event_type: serde_json::to_value(event.event_type)?
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    user_sid: event.user_sid.clone(),
                    user_name: event.user_name.clone(),
                    resource_path: event.resource_path.clone(),
                    classification: serde_json::to_value(event.classification)?
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    action_attempted: serde_json::to_value(event.action_attempted)?
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    decision: serde_json::to_value(event.decision)?
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    policy_id: event.policy_id.clone(),
                    policy_name: event.policy_name.clone(),
                    agent_id: event.agent_id.clone(),
                    session_id: event.session_id as i64,
                    access_context: serde_json::to_value(event.access_context)?
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    correlation_id: event.correlation_id.clone(),
                })
            })
            .collect::<Result<Vec<_>, serde_json::Error>>()
            .map_err(AppError::from)?;

        AuditEventRepository::insert_batch(&uow, &rows).map_err(AppError::from)?;
        uow.commit().map_err(AppError::from)?;
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
    let pool = Arc::clone(&state.pool);
    let filter = AuditEventFilter {
        agent_id: q.agent_id,
        user_name: q.user_name,
        classification: q.classification,
        event_type: q.event_type,
        from: q.from,
        to: q.to,
        limit: q.limit,
        offset: q.offset,
    };
    let rows = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let rows = AuditEventRepository::query(&pool, &filter)
            .map_err(AppError::from)?;
        Ok(rows)
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
    let pool = Arc::clone(&state.pool);
    let count = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let n = AuditEventRepository::count(&pool).map_err(AppError::from)?;
        Ok(n)
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

    #[test]
    fn test_store_events_sync_admin_action() {
        use crate::db;
        let pool = db::new_pool(":memory:").expect("build pool");
        let event = dlp_common::AuditEvent::new(
            dlp_common::EventType::AdminAction,
            "".to_string(),
            "admin".to_string(),
            "policy:test-policy".to_string(),
            dlp_common::Classification::T3,
            dlp_common::Action::PolicyCreate,
            dlp_common::Decision::ALLOW,
            "server".to_string(),
            0,
        );
        let mut conn = pool.get().expect("acquire connection");
        let uow = db::UnitOfWork::new(&mut *conn).expect("begin transaction");
        store_events_sync(&uow, &[event]).expect("store event");
        uow.commit().expect("commit");

        let (event_type, action, resource_path): (String, String, String) = conn
            .query_row(
                "SELECT event_type, action_attempted, resource_path FROM audit_events",
                [],
                |row: &rusqlite::Row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("query audit_events");
        assert_eq!(event_type, "\"ADMIN_ACTION\"");
        assert_eq!(action, "\"PolicyCreate\"");
        assert_eq!(resource_path, "policy:test-policy");
    }
}
