//! Repository for the `exceptions` table.
//!
//! Encapsulates all SQL for policy exception CRUD operations.

use rusqlite::params;

use crate::db::{Pool, UnitOfWork};

/// Plain data row returned by exception reads.
#[derive(Debug, Clone)]
pub struct ExceptionRow {
    /// UUID string identifying this exception grant.
    pub id: String,
    /// UUID of the policy this exception applies to.
    pub policy_id: String,
    /// Windows SID of the user granted the exception.
    pub user_sid: String,
    /// Username of the approver who granted the exception.
    pub approver: String,
    /// Business justification for the exception.
    pub justification: String,
    /// Duration in seconds for which the exception is valid.
    pub duration_seconds: i64,
    /// ISO-8601 timestamp when the exception was granted.
    pub granted_at: String,
    /// ISO-8601 timestamp when the exception expires.
    pub expires_at: String,
}

/// Stateless repository for the `exceptions` table.
pub struct ExceptionRepository;

impl ExceptionRepository {
    /// Returns all active exceptions ordered by `granted_at` descending.
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if pool acquisition or query execution fails.
    pub fn list(pool: &Pool) -> rusqlite::Result<Vec<ExceptionRow>> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        let mut stmt = conn.prepare(
            "SELECT id, policy_id, user_sid, approver, justification, \
             duration_seconds, granted_at, expires_at \
             FROM exceptions ORDER BY granted_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(ExceptionRow {
                id: row.get(0)?,
                policy_id: row.get(1)?,
                user_sid: row.get(2)?,
                approver: row.get(3)?,
                justification: row.get(4)?,
                duration_seconds: row.get(5)?,
                granted_at: row.get(6)?,
                expires_at: row.get(7)?,
            })
        })?;
        rows.collect()
    }

    /// Inserts a new policy exception.
    ///
    /// # Arguments
    ///
    /// * `uow` - Active unit of work to execute the write within.
    /// * `record` - Exception data to insert.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the statement fails (e.g., duplicate `id`).
    pub fn insert(uow: &UnitOfWork<'_>, record: &ExceptionRow) -> rusqlite::Result<()> {
        uow.tx.execute(
            "INSERT INTO exceptions (
                id, policy_id, user_sid, approver, justification,
                duration_seconds, granted_at, expires_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                record.id,
                record.policy_id,
                record.user_sid,
                record.approver,
                record.justification,
                record.duration_seconds,
                record.granted_at,
                record.expires_at,
            ],
        )?;
        Ok(())
    }

    /// Returns a single exception by its UUID.
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    /// * `id` - Exception UUID to look up.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error::QueryReturnedNoRows` if the exception is not found.
    pub fn get_by_id(pool: &Pool, id: &str) -> rusqlite::Result<ExceptionRow> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        conn.query_row(
            "SELECT id, policy_id, user_sid, approver, justification, \
             duration_seconds, granted_at, expires_at \
             FROM exceptions WHERE id = ?1",
            params![id],
            |row| {
                Ok(ExceptionRow {
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
    }
}
