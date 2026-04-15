//! Repository for the `audit_events` table.
//!
//! Encapsulates all SQL for audit event insertion and querying.
//! Callers are responsible for JSON-serializing enum fields (event_type,
//! classification, action_attempted, decision, access_context) before
//! passing them to write methods.

use std::collections::HashMap;

use rusqlite::params;

use crate::db::{Pool, UnitOfWork};

/// Filter parameters for audit event queries.
#[derive(Debug, Clone, Default)]
pub struct AuditEventFilter {
    pub agent_id: Option<String>,
    pub user_name: Option<String>,
    pub classification: Option<String>,
    pub event_type: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

/// Plain data row for a single audit event write.
///
/// All enum fields must be pre-serialized to strings by the caller.
#[derive(Debug, Clone)]
pub struct AuditEventRow {
    /// ISO-8601 timestamp when the event occurred.
    pub timestamp: String,
    /// Serialized event type (e.g., `"FileRead"`).
    pub event_type: String,
    /// Windows SID of the user who triggered the event.
    pub user_sid: String,
    /// Display name of the user.
    pub user_name: String,
    /// Full filesystem path of the accessed resource.
    pub resource_path: String,
    /// Serialized data classification tier (e.g., `"Confidential"`).
    pub classification: String,
    /// Serialized attempted action (e.g., `"Write"`).
    pub action_attempted: String,
    /// Serialized policy decision (e.g., `"Allow"`, `"Deny"`).
    pub decision: String,
    /// Optional policy UUID that produced the decision.
    pub policy_id: Option<String>,
    /// Optional human-readable policy name.
    pub policy_name: Option<String>,
    /// Agent UUID that reported the event.
    pub agent_id: String,
    /// Session identifier linking related events.
    pub session_id: i64,
    /// Serialized access context (e.g., `"local"`, `"vpn"`).
    pub access_context: String,
    /// Optional UUID for cross-system correlation. Must be globally unique.
    pub correlation_id: Option<String>,
}

/// Stateless repository for the `audit_events` table.
pub struct AuditEventRepository;

impl AuditEventRepository {
    /// Returns the total count of audit events stored.
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if pool acquisition or query execution fails.
    pub fn count(pool: &Pool) -> rusqlite::Result<i64> {
        let conn = pool.get().map_err(|e| {
            rusqlite::Error::ToSqlConversionFailure(Box::new(e))
        })?;
        conn.query_row("SELECT COUNT(*) FROM audit_events", [], |r| r.get(0))
    }

    /// Inserts a batch of audit events using `INSERT OR IGNORE` to skip duplicates.
    ///
    /// All enum fields in each row must be pre-serialized to strings by the caller.
    ///
    /// # Arguments
    ///
    /// * `uow` - Active unit of work to execute the writes within.
    /// * `rows` - Slice of pre-serialized audit event rows to insert.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` on the first statement failure.
    pub fn insert_batch(uow: &UnitOfWork<'_>, rows: &[AuditEventRow]) -> rusqlite::Result<()> {
        for row in rows {
            uow.tx.execute(
                "INSERT OR IGNORE INTO audit_events (
                    timestamp, event_type, user_sid, user_name, resource_path,
                    classification, action_attempted, decision, policy_id, policy_name,
                    agent_id, session_id, access_context, correlation_id
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                params![
                    row.timestamp,
                    row.event_type,
                    row.user_sid,
                    row.user_name,
                    row.resource_path,
                    row.classification,
                    row.action_attempted,
                    row.decision,
                    row.policy_id,
                    row.policy_name,
                    row.agent_id,
                    row.session_id,
                    row.access_context,
                    row.correlation_id,
                ],
            )?;
        }
        Ok(())
    }

    /// Queries audit events with optional filters, returning a vector of
    /// JSON objects ordered by timestamp descending.
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    /// * `filter` - Filter parameters (all fields optional).
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if pool acquisition or query execution fails.
    pub fn query(
        pool: &Pool,
        filter: &AuditEventFilter,
    ) -> rusqlite::Result<Vec<serde_json::Value>> {
        let conn = pool.get().map_err(|e| {
            rusqlite::Error::ToSqlConversionFailure(Box::new(e))
        })?;

        let mut conditions: Vec<String> = Vec::new();
        let mut params_map: HashMap<usize, String> = HashMap::new();

        if let Some(ref v) = filter.agent_id {
            let n = conditions.len() + 1;
            conditions.push(format!("agent_id = ?{n}"));
            params_map.insert(n, v.clone());
        }
        if let Some(ref v) = filter.user_name {
            let n = conditions.len() + 1;
            conditions.push(format!("user_name = ?{n}"));
            params_map.insert(n, v.clone());
        }
        if let Some(ref v) = filter.classification {
            let n = conditions.len() + 1;
            conditions.push(format!("classification = ?{n}"));
            params_map.insert(n, v.clone());
        }
        if let Some(ref v) = filter.event_type {
            let n = conditions.len() + 1;
            conditions.push(format!("event_type = ?{n}"));
            params_map.insert(n, v.clone());
        }
        if let Some(ref v) = filter.from {
            let n = conditions.len() + 1;
            conditions.push(format!("timestamp >= ?{n}"));
            params_map.insert(n, v.clone());
        }
        if let Some(ref v) = filter.to {
            let n = conditions.len() + 1;
            conditions.push(format!("timestamp <= ?{n}"));
            params_map.insert(n, v.clone());
        }

        let base_count = conditions.len();
        let limit = filter.limit.unwrap_or(100) as i64;
        let offset = filter.offset.unwrap_or(0) as i64;

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        let sql = format!(
            "SELECT id, timestamp, event_type, user_sid, user_name, \
                    resource_path, classification, action_attempted, \
                    decision, policy_id, policy_name, agent_id, \
                    session_id, access_context, correlation_id \
             FROM audit_events {where_clause} \
             ORDER BY timestamp DESC \
             LIMIT ?{} OFFSET ?{}",
            base_count + 1,
            base_count + 2,
        );

        let mut stmt = conn.prepare(&sql)?;
        let mut param_vec: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        for i in 1..=base_count {
            param_vec.push(Box::new(params_map[&i].clone()));
        }
        param_vec.push(Box::new(limit));
        param_vec.push(Box::new(offset));

        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            param_vec.iter().map(|p| p.as_ref()).collect();

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
        Ok(rows)
    }
}
