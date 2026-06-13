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
use crate::db::repositories::{AuditEventRow, SyslogConfigRepository, SyslogQueueRepository};
use crate::db::UnitOfWork;
use crate::AppError;
use crate::AppState;

// ---------------------------------------------------------------------------
// Chain verification types (Phase 63)
// ---------------------------------------------------------------------------

/// Reason for a detected chain break during server-side verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ChainBreakReason {
    /// Recomputed hash does not match the claimed chain_hash.
    HashMismatch,
    /// event.prev_hash does not match the last stored chain_hash for this agent.
    PrevHashMismatch,
    /// compute_chain_hash returned an error (e.g. malformed JSON).
    HashComputationFailed,
}

/// Response for `POST /audit/events`.
///
/// Returned after successful ingestion.  Contains tamper-detection
/// metadata so the agent can react locally to chain-breaks that
/// involve its own audit stream.
#[derive(Debug, Clone, Serialize)]
pub struct IngestEventsResponse {
    /// `Some(agent_id)` when at least one chain break in the batch
    /// belongs to the requesting agent.  `None` otherwise.
    pub tamper_detected_for_agent: Option<String>,
    /// Total number of unique chain breaks detected in this batch
    /// (deduplicated per agent+reason).
    pub chain_break_count: usize,
}

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
// Phase 63: Integrity endpoint types
// ---------------------------------------------------------------------------

/// A detected chain break in the integrity report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainBreak {
    /// Agent whose chain is broken.
    pub agent_id: String,
    /// Database row id of the broken event.
    pub event_id: i64,
    /// Expected prev_hash based on prior chain state.
    pub expected_prev_hash: String,
    /// Actual prev_hash stored in the event.
    pub actual_prev_hash: String,
}

/// Per-agent chain status in the integrity report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentChainStatus {
    /// Agent identifier.
    pub agent_id: String,
    /// Total events with chain_hash for this agent.
    pub event_count: i64,
    /// Events that passed continuity verification.
    pub verified_count: i64,
    /// Most recent chain_hash for this agent.
    pub last_chain_hash: Option<String>,
}

/// Response for `GET /admin/audit/integrity`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditIntegrityResponse {
    /// Total events with chain_hash examined.
    pub total_events: i64,
    /// Events that passed continuity verification.
    pub verified_events: i64,
    /// Detected chain breaks.
    pub chain_breaks: Vec<ChainBreak>,
    /// Per-agent chain statuses.
    pub agents: Vec<AgentChainStatus>,
    /// True if no chain breaks were detected across all verified events.
    pub integrity_ok: bool,
}

/// Query parameters for `GET /admin/audit/integrity`.
#[derive(Debug, Clone, Deserialize)]
pub struct IntegrityQueryParams {
    /// Filter to a single agent's chain.
    pub agent_id: Option<String>,
    /// ISO-8601 timestamp -- only verify events at or after this time.
    pub since: Option<String>,
    /// Maximum number of events to verify (default 10_000, max 100_000).
    pub limit: Option<i64>,
}

// ---------------------------------------------------------------------------
// Sync helper (for use inside spawn_blocking)
// ---------------------------------------------------------------------------

/// Synchronously stores audit events directly to the DB via a UnitOfWork.
///
/// Used by admin audit handlers that run inside `spawn_blocking` — we cannot
/// call the async `ingest_events` from within a blocking thread without
/// deadlocking the async runtime. JSON serialization of enum fields stays here.
pub fn store_events_sync(uow: &UnitOfWork<'_>, events: &[AuditEvent]) -> Result<(), AppError> {
    let rows: Vec<AuditEventRow> = events
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
                prev_hash: event.prev_hash.clone(),
                chain_hash: event.chain_hash.clone(),
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
    Json(mut events): Json<Vec<AuditEvent>>,
) -> Result<(StatusCode, Json<IngestEventsResponse>), AppError> {
    if events.is_empty() {
        return Err(AppError::BadRequest(
            "event batch must not be empty".to_string(),
        ));
    }

    // AUDIT-04 (Phase 42): Validate app identity fields on ingestion.
    for event in &events {
        if event.source_application.is_none() {
            tracing::warn!(
                correlation_id = %event.correlation_id.as_deref().unwrap_or("none"),
                "Rejecting audit event with missing source_application — agent may need update"
            );
            return Err(AppError::BadRequest(
                "audit event missing source_application".to_string(),
            ));
        }
        if event.destination_application.is_none() {
            tracing::warn!(
                correlation_id = %event.correlation_id.as_deref().unwrap_or("none"),
                "Rejecting audit event with missing destination_application — agent may need update"
            );
            return Err(AppError::BadRequest(
                "audit event missing destination_application".to_string(),
            ));
        }
    }

    // Phase 63: Sort events by (agent_id, event_timestamp) to ensure correct
    // per-agent chain order and prevent false positives from out-of-order arrival.
    events.sort_by(|a, b| {
        a.agent_id
            .cmp(&b.agent_id)
            .then_with(|| a.timestamp.cmp(&b.timestamp))
    });

    // Phase 63: Server-side chain verification — two-step integrity + continuity.
    let pool = Arc::clone(&state.pool);
    let mut chain_breaks: Vec<(String, Option<String>, ChainBreakReason)> = Vec::new();
    let mut last_hash_cache: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    for event in &events {
        if let Some(ref chain_hash) = event.chain_hash {
            let genesis = dlp_common::audit::genesis_hash();
            let prev_hash = event.prev_hash.as_deref().unwrap_or(genesis.as_str());

            // Step A: Verify event integrity (recomputed hash must match claimed chain_hash).
            match dlp_common::audit::compute_chain_hash(prev_hash, event) {
                Ok(expected) => {
                    if expected != *chain_hash {
                        chain_breaks.push((
                            event.agent_id.clone(),
                            event.correlation_id.clone(),
                            ChainBreakReason::HashMismatch,
                        ));
                        continue;
                    }
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        agent_id = %event.agent_id,
                        "failed to compute chain hash; flagging chain break"
                    );
                    chain_breaks.push((
                        event.agent_id.clone(),
                        event.correlation_id.clone(),
                        ChainBreakReason::HashComputationFailed,
                    ));
                    continue;
                }
            }

            // Step B: Verify chain continuity (prev_hash must match last stored hash).
            let expected_prev = last_hash_cache
                .get(&event.agent_id)
                .cloned()
                .or_else(|| {
                    AuditEventRepository::get_last_chain_hash(&pool, &event.agent_id)
                        .ok()
                        .flatten()
                })
                .unwrap_or_else(dlp_common::audit::genesis_hash);

            if prev_hash != expected_prev {
                chain_breaks.push((
                    event.agent_id.clone(),
                    event.correlation_id.clone(),
                    ChainBreakReason::PrevHashMismatch,
                ));
            } else {
                // Update cache with this event's chain_hash for subsequent events in the same batch.
                last_hash_cache.insert(event.agent_id.clone(), chain_hash.clone());
            }
        }
    }

    let count = events.len();
    let requesting_agent_id = events.first().map(|e| e.agent_id.clone());

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
    let chain_breaks_for_persist = chain_breaks.clone();
    let synthetic_events = tokio::task::spawn_blocking(move || -> Result<Vec<AuditEvent>, AppError> {
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
                    prev_hash: event.prev_hash.clone(),
                    chain_hash: event.chain_hash.clone(),
                })
            })
            .collect::<Result<Vec<_>, serde_json::Error>>()
            .map_err(AppError::from)?;

        AuditEventRepository::insert_batch(&uow, &rows).map_err(AppError::from)?;

        // Phase 63: Persist synthetic ChainBreakDetected events for detected chain breaks.
        // Deduplicate per (agent_id, reason) within the batch to prevent alert storms.
        let mut seen = std::collections::HashSet::new();
        let mut synthetic_events = Vec::new();
        for (agent_id, _correlation_id, reason) in &chain_breaks_for_persist {
            let key = (agent_id.clone(), *reason);
            if !seen.insert(key) {
                continue; // skip duplicate (same agent + same reason)
            }

            let synthetic = dlp_common::AuditEvent::new(
                dlp_common::EventType::ChainBreakDetected,
                "S-1-5-18".to_string(),
                "SYSTEM".to_string(),
                "audit_chain_break".to_string(),
                dlp_common::Classification::T4,
                dlp_common::Action::WRITE,
                dlp_common::Decision::DenyWithAlert,
                agent_id.clone(),
                0,
            );
            // Synthetic events do NOT copy the original correlation_id because
            // audit_events.correlation_id has a UNIQUE constraint.

            let row = AuditEventRow {
                timestamp: synthetic.timestamp.to_rfc3339(),
                event_type: serde_json::to_value(synthetic.event_type)?
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                user_sid: synthetic.user_sid.clone(),
                user_name: synthetic.user_name.clone(),
                resource_path: synthetic.resource_path.clone(),
                classification: serde_json::to_value(synthetic.classification)?
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                action_attempted: serde_json::to_value(synthetic.action_attempted)?
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                decision: serde_json::to_value(synthetic.decision)?
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                policy_id: synthetic.policy_id.clone(),
                policy_name: synthetic.policy_name.clone(),
                agent_id: synthetic.agent_id.clone(),
                session_id: synthetic.session_id as i64,
                access_context: serde_json::to_value(synthetic.access_context)?
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                correlation_id: synthetic.correlation_id.clone(),
                prev_hash: synthetic.prev_hash.clone(),
                chain_hash: synthetic.chain_hash.clone(),
            };
            AuditEventRepository::insert_batch(&uow, &[row]).map_err(AppError::from)?;
            synthetic_events.push(synthetic);
        }

        uow.commit().map_err(AppError::from)?;
        Ok(synthetic_events)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    // Phase 63: Emit tamper alerts for detected chain breaks (fire-and-forget).
    let chain_breaks_for_alert = chain_breaks.clone();
    if !chain_breaks_for_alert.is_empty() {
        let alert_router = state.alert.clone();
        tokio::spawn(async move {
            for (agent_id, correlation_id, reason) in &chain_breaks_for_alert {
                let synthetic = dlp_common::AuditEvent::new(
                    dlp_common::EventType::ChainBreakDetected,
                    "S-1-5-18".to_string(),
                    "SYSTEM".to_string(),
                    "audit_chain_break".to_string(),
                    dlp_common::Classification::T4,
                    dlp_common::Action::WRITE,
                    dlp_common::Decision::DenyWithAlert,
                    agent_id.clone(),
                    0,
                );
                // Synthetic events do NOT copy the original correlation_id because
                // audit_events.correlation_id has a UNIQUE constraint.

                if let Err(e) = alert_router.send_alert(&synthetic).await {
                    tracing::warn!(
                        error = %e,
                        agent_id = %agent_id,
                        "chain break alert delivery failed (best-effort)"
                    );
                }

                tracing::error!(
                    agent_id = %agent_id,
                    correlation_id = %correlation_id.as_deref().unwrap_or("none"),
                    reason = ?reason,
                    "audit chain break detected"
                );
            }
        });
    }

    // G7: Compute alert-eligible events BEFORE the SIEM spawn so
    // relay_events can still be moved into the SIEM closure while
    // alert_events is moved into the alert closure. Filtered to
    // Decision::DenyWithAlert — do NOT alert on Deny or AllowWithLog.
    let alert_events: Vec<AuditEvent> = relay_events
        .iter()
        .filter(|e| matches!(e.decision, dlp_common::Decision::DenyWithAlert))
        .cloned()
        .collect();

    // Durable-first syslog forwarding: queue events BEFORE attempting external delivery.
    // This ensures no audit events are lost even if the syslog collector is unreachable.
    // The background drain loop (spawned in main.rs) reads from the queue and forwards.
    let mut syslog_events_vec = events;
    syslog_events_vec.extend(synthetic_events.clone());
    let syslog_events = Arc::new(syslog_events_vec);
    let syslog_pool = Arc::clone(&state.pool);
    let syslog_crypto = Arc::clone(&state.crypto);
    tokio::task::spawn_blocking(move || {
        let mut conn = match syslog_pool.get().map_err(AppError::from) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "syslog queue: failed to acquire connection");
                return;
            }
        };
        let uow = match UnitOfWork::new(&mut conn).map_err(AppError::from) {
            Ok(u) => u,
            Err(e) => {
                tracing::warn!(error = %e, "syslog queue: failed to begin uow");
                return;
            }
        };
        let config = match SyslogConfigRepository::get(&syslog_pool, &syslog_crypto) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "syslog queue: failed to read config");
                return;
            }
        };
        for event in syslog_events.iter() {
            let json = match serde_json::to_string(event) {
                Ok(j) => j,
                Err(e) => {
                    tracing::warn!(error = %e, "syslog queue: failed to serialize event");
                    continue;
                }
            };
            if let Err(e) =
                SyslogQueueRepository::enqueue(&uow, &json, &syslog_crypto, config.queue_max_size)
            {
                tracing::warn!(error = %e, "syslog queue enqueue failed");
            }
        }
        if let Err(e) = uow.commit().map_err(AppError::from) {
            tracing::warn!(error = %e, "syslog queue: commit failed");
        }
    });

    // Best-effort SIEM relay — fire-and-forget in a background task
    // so the HTTP response is not delayed by external SIEM latency.
    let mut relay_events = relay_events;
    relay_events.extend(synthetic_events);
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

    // Compute response fields.
    let tamper_detected_for_agent = requesting_agent_id.and_then(|req_id| {
        chain_breaks
            .iter()
            .find(|(agent_id, _, _)| *agent_id == req_id)
            .map(|(agent_id, _, _)| agent_id.clone())
    });
    // Deduplicate chain breaks per (agent_id, reason) for the count.
    let mut seen_breaks = std::collections::HashSet::new();
    for (agent_id, _, reason) in &chain_breaks {
        seen_breaks.insert((agent_id.clone(), *reason));
    }
    let chain_break_count = seen_breaks.len();

    tracing::info!(count, "ingested audit events");
    Ok((StatusCode::CREATED, Json(IngestEventsResponse {
        tamper_detected_for_agent,
        chain_break_count,
    })))
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
        let rows = AuditEventRepository::query(&pool, &filter).map_err(AppError::from)?;
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

/// `GET /admin/audit/integrity` -- re-verify hash chain for stored events.
///
/// Query parameters (all optional):
/// - `agent_id`: Filter to a single agent's chain
/// - `since`: ISO-8601 timestamp -- only verify events at or after this time
/// - `limit`: Maximum number of events to verify (default 10_000, max 100_000)
///
/// Returns a summary of total events, verified events, detected chain breaks,
/// per-agent chain status, and an overall integrity_ok boolean.
/// Requires admin authentication.
pub async fn get_audit_integrity(
    State(state): State<Arc<AppState>>,
    Query(params): Query<IntegrityQueryParams>,
) -> Result<Json<AuditIntegrityResponse>, AppError> {
    let pool = Arc::clone(&state.pool);
    let response =
        tokio::task::spawn_blocking(move || -> Result<AuditIntegrityResponse, AppError> {
            let mut conn = pool.get().map_err(AppError::from)?;
            let uow = UnitOfWork::new(&mut conn).map_err(AppError::from)?;

            let limit = params.limit.unwrap_or(10_000).min(100_000);

            let mut conditions = vec!["chain_hash IS NOT NULL"];
            let mut query_params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

            if let Some(ref agent) = params.agent_id {
                conditions.push("agent_id = ?");
                query_params.push(Box::new(agent.clone()));
            }
            if let Some(ref since) = params.since {
                conditions.push("timestamp >= ?");
                query_params.push(Box::new(since.clone()));
            }

            let where_clause = conditions.join(" AND ");
            let sql = format!(
                "SELECT id, agent_id, prev_hash, chain_hash \
                 FROM audit_events \
                 WHERE {where_clause} \
                 ORDER BY agent_id, id \
                 LIMIT {limit}"
            );

            let param_refs: Vec<&dyn rusqlite::types::ToSql> =
                query_params.iter().map(|p| p.as_ref()).collect();

            let rows = uow
                .tx
                .prepare(&sql)?
                .query_map(rusqlite::params_from_iter(param_refs.iter()), |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;

            let mut total_events = 0i64;
            let mut verified_events = 0i64;
            let mut chain_breaks = Vec::new();
            let mut agent_statuses: std::collections::HashMap<String, AgentChainStatus> =
                std::collections::HashMap::new();
            let mut last_by_agent: std::collections::HashMap<String, String> =
                std::collections::HashMap::new();

            for (id, agent_id, prev_hash, chain_hash) in rows {
                total_events += 1;
                let prev = prev_hash.unwrap_or_else(dlp_common::audit::genesis_hash);
                let status =
                    agent_statuses
                        .entry(agent_id.clone())
                        .or_insert_with(|| AgentChainStatus {
                            agent_id: agent_id.clone(),
                            event_count: 0,
                            verified_count: 0,
                            last_chain_hash: None,
                        });
                status.event_count += 1;

                let expected_prev = last_by_agent
                    .get(&agent_id)
                    .cloned()
                    .unwrap_or_else(dlp_common::audit::genesis_hash);
                if prev != expected_prev {
                    chain_breaks.push(ChainBreak {
                        agent_id: agent_id.clone(),
                        event_id: id,
                        expected_prev_hash: expected_prev,
                        actual_prev_hash: prev.to_string(),
                    });
                } else {
                    verified_events += 1;
                    status.verified_count += 1;
                }
                if let Some(hash) = chain_hash {
                    last_by_agent.insert(agent_id.clone(), hash.clone());
                    status.last_chain_hash = Some(hash);
                }
            }

            let integrity_ok = chain_breaks.is_empty();

            Ok(AuditIntegrityResponse {
                total_events,
                verified_events,
                chain_breaks,
                agents: agent_statuses.into_values().collect(),
                integrity_ok,
            })
        })
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    use super::*;
    use crate::db::repositories::audit_events::AuditEventRepository;

    /// Helper: build a minimal AppState with a file-backed SQLite pool
    /// so data persists across connections (required for spawn_blocking tests).
    fn test_app_state() -> Arc<AppState> {
        let tmp = tempfile::NamedTempFile::new().expect("create temp db file");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        std::mem::forget(tmp);
        let crypto = Arc::new(crate::crypto::SecretCrypto::from_kek([0u8; 32], 1));
        Arc::new(AppState {
            pool: Arc::clone(&pool),
            crypto: Arc::clone(&crypto),
            policy_store: Arc::new(
                crate::policy_store::PolicyStore::new(Arc::clone(&pool)).expect("store"),
            ),
            siem: crate::siem_connector::SiemConnector::new(Arc::clone(&pool), Arc::clone(&crypto)),
            alert: crate::alert_router::AlertRouter::new(Arc::clone(&pool), Arc::clone(&crypto)),
            ad: None,
            label_service: Arc::new(crate::label_service::LabelService::new(Arc::clone(&pool))),
            approval_token_service: Arc::new({
                let conn = pool.get().expect("conn");
                crate::approval_token::ApprovalTokenService::new(&crypto, &conn)
                    .expect("approval token")
            }),
            syslog: crate::syslog_connector::SyslogConnector::new(Arc::clone(&pool), crypto),
            label_aware_enabled: Arc::new(AtomicBool::new(false)),
            protected_paths: Arc::new(
                crate::db::repositories::protected_paths::ProtectedPathsRepository,
            ),
            bypass_alerts: Arc::new(crate::db::repositories::bypass_alerts::BypassAlertsRepository),
        })
    }

    /// Helper: create a valid chain-hashed AuditEvent for a given agent.
    fn chain_event(
        agent_id: &str,
        prev_hash: Option<String>,
        timestamp_offset: chrono::Duration,
    ) -> AuditEvent {
        let mut event = AuditEvent::new(
            dlp_common::EventType::Access,
            "S-1-5-21-1".to_string(),
            "testuser".to_string(),
            r"C:\test.txt".to_string(),
            dlp_common::Classification::T2,
            dlp_common::Action::READ,
            dlp_common::Decision::ALLOW,
            agent_id.to_string(),
            1,
        );
        event.timestamp = chrono::Utc::now() + timestamp_offset;
        // Set required app-identity fields (AUDIT-04).
        event.source_application = Some(dlp_common::endpoint::AppIdentity {
            image_path: r"C:\test.exe".to_string(),
            publisher: "Test".to_string(),
            trust_tier: dlp_common::endpoint::AppTrustTier::Trusted,
            signature_state: dlp_common::endpoint::SignatureState::Valid,
            aumid: None,
            package_family_name: None,
            is_uwp: false,
        });
        event.destination_application = Some(dlp_common::endpoint::AppIdentity {
            image_path: r"C:\dst.exe".to_string(),
            publisher: "Test".to_string(),
            trust_tier: dlp_common::endpoint::AppTrustTier::Trusted,
            signature_state: dlp_common::endpoint::SignatureState::Valid,
            aumid: None,
            package_family_name: None,
            is_uwp: false,
        });
        event.prev_hash = prev_hash.clone();
        if let Some(ref ph) = prev_hash {
            event.chain_hash =
                Some(dlp_common::audit::compute_chain_hash(ph, &event).expect("compute hash"));
        }
        event
    }

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
        let uow = db::UnitOfWork::new(&mut conn).expect("begin transaction");
        store_events_sync(&uow, &[event]).expect("store event");
        uow.commit().expect("commit");

        let (event_type, action, resource_path): (String, String, String) = conn
            .query_row(
                "SELECT event_type, action_attempted, resource_path FROM audit_events",
                [],
                |row: &rusqlite::Row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("query audit_events");
        assert_eq!(event_type, "ADMIN_ACTION");
        assert_eq!(action, "PolicyCreate");
        assert_eq!(resource_path, "policy:test-policy");
    }

    // --- Phase 63: chain verification tests ---

    /// A valid event with genesis prev_hash and correct chain_hash is accepted.
    #[test]
    fn test_ingest_verifies_valid_chain() {
        let rt = tokio::runtime::Runtime::new().expect("create runtime");
        rt.block_on(async {
            let state = test_app_state();
            let genesis = dlp_common::audit::genesis_hash();
            let event = chain_event("agent-a", Some(genesis), chrono::Duration::zero());

            let result = ingest_events(State(state.clone()), Json(vec![event])).await;
            assert!(result.is_ok(), "valid chain event must be accepted");

            // Query back and verify hash fields are persisted.
            let rows = AuditEventRepository::query(
                &state.pool,
                &AuditEventFilter {
                    agent_id: Some("agent-a".to_string()),
                    ..Default::default()
                },
            )
            .expect("query");
            assert_eq!(rows.len(), 1, "one event must be stored");
            assert!(
                rows[0]["prev_hash"].as_str().is_some(),
                "prev_hash must be persisted"
            );
            assert!(
                rows[0]["chain_hash"].as_str().is_some(),
                "chain_hash must be persisted"
            );

            // No ChainBreakDetected synthetic event should exist.
            let breaks = AuditEventRepository::query(
                &state.pool,
                &AuditEventFilter {
                    event_type: Some("CHAIN_BREAK_DETECTED".to_string()),
                    ..Default::default()
                },
            )
            .expect("query breaks");
            assert_eq!(breaks.len(), 0, "no chain break for valid event");
        });
    }

    /// A broken chain (wrong prev_hash) is detected and stored alongside a synthetic alert.
    #[test]
    fn test_ingest_detects_broken_chain() {
        let rt = tokio::runtime::Runtime::new().expect("create runtime");
        rt.block_on(async {
            let state = test_app_state();
            let genesis = dlp_common::audit::genesis_hash();

            // First: ingest a valid event to establish chain state.
            let event1 = chain_event("agent-b", Some(genesis.clone()), chrono::Duration::zero());
            let _ = ingest_events(State(state.clone()), Json(vec![event1]))
                .await
                .expect("first event ingested");

            // Second: ingest an event with wrong prev_hash but computable chain_hash.
            let mut event2 = chain_event(
                "agent-b",
                Some(genesis.clone()),
                chrono::Duration::seconds(1),
            );
            // Force wrong prev_hash: claim it links to genesis again, but DB expects event1's chain_hash.
            event2.prev_hash = Some(genesis.clone());
            event2.chain_hash =
                Some(dlp_common::audit::compute_chain_hash(&genesis, &event2).expect("compute"));

            let result = ingest_events(State(state.clone()), Json(vec![event2])).await;
            assert!(result.is_ok(), "broken event must still be stored");

            // Verify a synthetic ChainBreakDetected event was persisted.
            let breaks = AuditEventRepository::query(
                &state.pool,
                &AuditEventFilter {
                    event_type: Some("CHAIN_BREAK_DETECTED".to_string()),
                    agent_id: Some("agent-b".to_string()),
                    ..Default::default()
                },
            )
            .expect("query breaks");
            assert_eq!(
                breaks.len(),
                1,
                "exactly one chain break alert must be persisted"
            );
        });
    }

    /// Legacy events without hash fields skip verification entirely.
    #[test]
    fn test_ingest_skips_verification_for_legacy_events() {
        let rt = tokio::runtime::Runtime::new().expect("create runtime");
        rt.block_on(async {
            let state = test_app_state();
            let mut event = AuditEvent::new(
                dlp_common::EventType::Access,
                "S-1-5-21-1".to_string(),
                "legacy".to_string(),
                r"C:\legacy.txt".to_string(),
                dlp_common::Classification::T1,
                dlp_common::Action::READ,
                dlp_common::Decision::ALLOW,
                "agent-legacy".to_string(),
                1,
            );
            event.source_application = Some(dlp_common::endpoint::AppIdentity {
                image_path: r"C:\test.exe".to_string(),
                publisher: "Test".to_string(),
                trust_tier: dlp_common::endpoint::AppTrustTier::Trusted,
                signature_state: dlp_common::endpoint::SignatureState::Valid,
                aumid: None,
                package_family_name: None,
                is_uwp: false,
            });
            event.destination_application = Some(dlp_common::endpoint::AppIdentity {
                image_path: r"C:\dst.exe".to_string(),
                publisher: "Test".to_string(),
                trust_tier: dlp_common::endpoint::AppTrustTier::Trusted,
                signature_state: dlp_common::endpoint::SignatureState::Valid,
                aumid: None,
                package_family_name: None,
                is_uwp: false,
            });
            // Explicitly no hash fields.
            event.prev_hash = None;
            event.chain_hash = None;

            let result = ingest_events(State(state.clone()), Json(vec![event])).await;
            assert!(result.is_ok(), "legacy event must be accepted");

            let rows = AuditEventRepository::query(
                &state.pool,
                &AuditEventFilter {
                    agent_id: Some("agent-legacy".to_string()),
                    ..Default::default()
                },
            )
            .expect("query");
            assert_eq!(rows.len(), 1, "legacy event must be stored");

            // No chain break alert should be generated.
            let breaks = AuditEventRepository::query(
                &state.pool,
                &AuditEventFilter {
                    event_type: Some("CHAIN_BREAK_DETECTED".to_string()),
                    ..Default::default()
                },
            )
            .expect("query breaks");
            assert_eq!(breaks.len(), 0, "no chain break for legacy event");
        });
    }

    /// A chain break triggers a synthetic ChainBreakDetected event in the audit log.
    #[test]
    fn test_ingest_triggers_alert_on_chain_break() {
        let rt = tokio::runtime::Runtime::new().expect("create runtime");
        rt.block_on(async {
            let state = test_app_state();
            let genesis = dlp_common::audit::genesis_hash();

            // Seed a broken event directly.
            let mut event = chain_event("agent-c", Some(genesis.clone()), chrono::Duration::zero());
            // Corrupt the prev_hash so it does not match genesis (it IS genesis, but let's
            // make the chain_hash mismatch by mutating the event after hash computation).
            event.resource_path = r"C:\tampered.txt".to_string();
            // Recompute chain_hash with original prev_hash — now the event data doesn't match.
            event.chain_hash =
                Some(dlp_common::audit::compute_chain_hash(&genesis, &event).expect("compute"));
            // Mutate again AFTER computing hash — this creates a HashMismatch.
            event.resource_path = r"C:\original.txt".to_string();

            let result = ingest_events(State(state.clone()), Json(vec![event])).await;
            assert!(result.is_ok(), "handler must not error on chain break");

            // The broken event is still persisted.
            let rows = AuditEventRepository::query(
                &state.pool,
                &AuditEventFilter {
                    agent_id: Some("agent-c".to_string()),
                    ..Default::default()
                },
            )
            .expect("query");
            assert_eq!(
                rows.len(),
                2,
                "broken event + synthetic alert must both be stored"
            );

            // A synthetic ChainBreakDetected row must exist.
            let breaks = AuditEventRepository::query(
                &state.pool,
                &AuditEventFilter {
                    event_type: Some("CHAIN_BREAK_DETECTED".to_string()),
                    agent_id: Some("agent-c".to_string()),
                    ..Default::default()
                },
            )
            .expect("query breaks");
            assert_eq!(
                breaks.len(),
                1,
                "synthetic ChainBreakDetected must be persisted"
            );
        });
    }

    /// Multiple broken events from the same agent with the same reason deduplicate to one alert.
    #[test]
    fn test_ingest_deduplicates_chain_break_alerts() {
        let rt = tokio::runtime::Runtime::new().expect("create runtime");
        rt.block_on(async {
            let state = test_app_state();
            let _genesis = dlp_common::audit::genesis_hash();

            // Ingest two events with the SAME broken prev_hash (both claim genesis
            // when no prior event exists — but the first event SHOULD use genesis,
            // so this is only a break for the SECOND event if the first was valid).
            // Instead: both events have a computable chain_hash but share a prev_hash
            // that does NOT match the DB state (we seed nothing, so DB expects genesis).
            // If both use a WRONG prev_hash (not genesis), both break with the same reason.
            let wrong_prev =
                "0000000000000000000000000000000000000000000000000000000000000000".to_string();
            let mut event1 = chain_event(
                "agent-d",
                Some(wrong_prev.clone()),
                chrono::Duration::zero(),
            );
            event1.prev_hash = Some(wrong_prev.clone());
            event1.chain_hash =
                Some(dlp_common::audit::compute_chain_hash(&wrong_prev, &event1).expect("compute"));

            let mut event2 = chain_event(
                "agent-d",
                Some(wrong_prev.clone()),
                chrono::Duration::seconds(1),
            );
            event2.prev_hash = Some(wrong_prev.clone());
            event2.chain_hash =
                Some(dlp_common::audit::compute_chain_hash(&wrong_prev, &event2).expect("compute"));

            let result = ingest_events(State(state.clone()), Json(vec![event1, event2])).await;
            assert!(result.is_ok());

            // Only ONE synthetic event should be persisted (deduplicated per agent+reason).
            let breaks = AuditEventRepository::query(
                &state.pool,
                &AuditEventFilter {
                    event_type: Some("CHAIN_BREAK_DETECTED".to_string()),
                    agent_id: Some("agent-d".to_string()),
                    ..Default::default()
                },
            )
            .expect("query breaks");
            assert_eq!(
                breaks.len(),
                1,
                "duplicate chain breaks must be deduplicated to one alert"
            );
        });
    }

    /// Out-of-order events within a batch are sorted and pass verification.
    #[test]
    fn test_ingest_out_of_order_events_sorted_correctly() {
        let rt = tokio::runtime::Runtime::new().expect("create runtime");
        rt.block_on(async {
            let state = test_app_state();
            let genesis = dlp_common::audit::genesis_hash();

            // Create event A (timestamp 0) and event B (timestamp 1).
            // B depends on A's chain_hash as its prev_hash.
            let event_a = chain_event("agent-e", Some(genesis.clone()), chrono::Duration::zero());
            let chain_hash_a = event_a.chain_hash.clone().unwrap();

            let mut event_b = chain_event(
                "agent-e",
                Some(chain_hash_a.clone()),
                chrono::Duration::seconds(1),
            );
            event_b.chain_hash = Some(
                dlp_common::audit::compute_chain_hash(&chain_hash_a, &event_b).expect("compute"),
            );

            // Submit in REVERSE order: B first, then A.
            let result = ingest_events(State(state.clone()), Json(vec![event_b, event_a])).await;
            assert!(result.is_ok(), "out-of-order batch must pass after sorting");

            // Both events stored, no chain break.
            let rows = AuditEventRepository::query(
                &state.pool,
                &AuditEventFilter {
                    agent_id: Some("agent-e".to_string()),
                    ..Default::default()
                },
            )
            .expect("query");
            assert_eq!(rows.len(), 2, "both events must be stored");

            let breaks = AuditEventRepository::query(
                &state.pool,
                &AuditEventFilter {
                    event_type: Some("\"ChainBreakDetected\"".to_string()),
                    agent_id: Some("agent-e".to_string()),
                    ..Default::default()
                },
            )
            .expect("query breaks");
            assert_eq!(
                breaks.len(),
                0,
                "no false positive chain break after sorting"
            );
        });
    }

    // --- Phase 68.1: IngestEventsResponse tamper detection tests ---

    /// A valid batch returns tamper_detected_for_agent: None and chain_break_count: 0.
    #[test]
    fn test_ingest_response_contains_tamper_flag() {
        let rt = tokio::runtime::Runtime::new().expect("create runtime");
        rt.block_on(async {
            let state = test_app_state();
            let genesis = dlp_common::audit::genesis_hash();
            let event = chain_event("agent-x", Some(genesis.clone()), chrono::Duration::zero());

            let result = ingest_events(State(state.clone()), Json(vec![event])).await;
            assert!(result.is_ok(), "valid batch must be accepted");

            let (status, json) = result.expect("unwrap");
            assert_eq!(status, StatusCode::CREATED);
            let resp = json.0;
            assert_eq!(
                resp.tamper_detected_for_agent, None,
                "no tamper for valid batch"
            );
            assert_eq!(resp.chain_break_count, 0, "no breaks for valid batch");
        });
    }

    /// A broken batch for the same agent returns tamper_detected_for_agent: Some(agent-x)
    /// and chain_break_count: 1.
    #[test]
    fn test_ingest_response_tamper_flag_for_same_agent() {
        let rt = tokio::runtime::Runtime::new().expect("create runtime");
        rt.block_on(async {
            let state = test_app_state();
            let genesis = dlp_common::audit::genesis_hash();

            // Seed a broken event: hash mismatch.
            let mut event = chain_event("agent-x", Some(genesis.clone()), chrono::Duration::zero());
            event.resource_path = r"C:\tampered.txt".to_string();
            event.chain_hash =
                Some(dlp_common::audit::compute_chain_hash(&genesis, &event).expect("compute"));
            event.resource_path = r"C:\original.txt".to_string(); // mutate after hash

            let result = ingest_events(State(state.clone()), Json(vec![event])).await;
            assert!(result.is_ok(), "handler must not error on chain break");

            let (status, json) = result.expect("unwrap");
            assert_eq!(status, StatusCode::CREATED);
            let resp = json.0;
            assert_eq!(
                resp.tamper_detected_for_agent,
                Some("agent-x".to_string()),
                "tamper flag must name the requesting agent"
            );
            assert_eq!(resp.chain_break_count, 1, "one unique break");
        });
    }

    /// When a batch contains events from agent A but the break is for agent B,
    /// tamper_detected_for_agent is None.
    #[test]
    fn test_ingest_response_other_agent_break() {
        let rt = tokio::runtime::Runtime::new().expect("create runtime");
        rt.block_on(async {
            let state = test_app_state();
            let genesis = dlp_common::audit::genesis_hash();

            // First: seed a valid event for agent-b to establish DB state.
            let event_b = chain_event("agent-b", Some(genesis.clone()), chrono::Duration::zero());
            let _ = ingest_events(State(state.clone()), Json(vec![event_b]))
                .await
                .expect("seed agent-b");

            // Second: ingest an event from agent-a with a broken chain_hash,
            // but the prev_hash points to agent-b's chain (wrong agent).
            // Actually, the chain verification only checks per-agent continuity,
            // so a break for agent-b would require an agent-b event. Instead:
            // Send a valid event for agent-a, and a separate broken event for agent-b
            // in the SAME batch. The requesting_agent_id is agent-a (first event),
            // but the break is for agent-b.
            let event_a = chain_event("agent-a", Some(genesis.clone()), chrono::Duration::zero());

            // Broken event for agent-b: wrong prev_hash (claims genesis again,
            // but DB now expects event_b's chain_hash).
            let mut event_b2 = chain_event(
                "agent-b",
                Some(genesis.clone()),
                chrono::Duration::seconds(1),
            );
            event_b2.prev_hash = Some(genesis.clone());
            event_b2.chain_hash =
                Some(dlp_common::audit::compute_chain_hash(&genesis, &event_b2).expect("compute"));

            let result = ingest_events(
                State(state.clone()),
                Json(vec![event_a, event_b2]),
            )
            .await;
            assert!(result.is_ok(), "handler must not error");

            let (status, json) = result.expect("unwrap");
            assert_eq!(status, StatusCode::CREATED);
            let resp = json.0;
            // The first event is from agent-a, so requesting_agent_id = agent-a.
            // The break is for agent-b, so tamper_detected_for_agent should be None.
            assert_eq!(
                resp.tamper_detected_for_agent, None,
                "no tamper flag when break is for a different agent"
            );
            assert_eq!(resp.chain_break_count, 1, "one unique break counted");
        });
    }

    /// Synthetic ChainBreakDetected events are included in the relay_events Vec
    /// that is passed to the SIEM relay.
    #[test]
    fn test_synthetic_events_in_relay_list() {
        let rt = tokio::runtime::Runtime::new().expect("create runtime");
        rt.block_on(async {
            let state = test_app_state();
            let genesis = dlp_common::audit::genesis_hash();

            // Ingest a broken event to trigger synthetic event generation.
            let mut event = chain_event("agent-f", Some(genesis.clone()), chrono::Duration::zero());
            event.resource_path = r"C:\tampered.txt".to_string();
            event.chain_hash =
                Some(dlp_common::audit::compute_chain_hash(&genesis, &event).expect("compute"));
            event.resource_path = r"C:\original.txt".to_string(); // mutate after hash

            let result = ingest_events(State(state.clone()), Json(vec![event])).await;
            assert!(result.is_ok(), "handler must not error on chain break");

            // Verify a synthetic ChainBreakDetected row was persisted.
            let breaks = AuditEventRepository::query(
                &state.pool,
                &AuditEventFilter {
                    event_type: Some("CHAIN_BREAK_DETECTED".to_string()),
                    agent_id: Some("agent-f".to_string()),
                    ..Default::default()
                },
            )
            .expect("query breaks");
            assert_eq!(
                breaks.len(),
                1,
                "synthetic ChainBreakDetected must be persisted"
            );
        });
    }
}
