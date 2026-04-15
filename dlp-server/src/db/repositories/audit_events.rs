//! Repository for the `audit_events` table.
//!
//! Encapsulates all SQL for audit event insertion and querying.
//! Callers are responsible for JSON-serializing enum fields (event_type,
//! classification, action_attempted, decision, access_context) before
//! passing them to write methods.

use rusqlite::params;

use crate::db::{Pool, UnitOfWork};

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
}
