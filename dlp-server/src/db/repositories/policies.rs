//! Repository for the `policies` table.
//!
//! Encapsulates all SQL for policy CRUD operations.

use rusqlite::params;

use crate::db::{Pool, UnitOfWork};

/// Plain data row returned by policy reads.
#[derive(Debug, Clone)]
pub struct PolicyRow {
    /// UUID string identifying the policy.
    pub id: String,
    /// Human-readable policy name.
    pub name: String,
    /// Optional description of what the policy enforces.
    pub description: Option<String>,
    /// Evaluation priority — lower numbers evaluated first.
    pub priority: i64,
    /// JSON-serialized policy conditions.
    pub conditions: String,
    /// Policy action: `"Allow"`, `"Deny"`, `"DenyWithAlert"`, etc.
    pub action: String,
    /// Whether the policy is active (1) or disabled (0).
    pub enabled: i64,
    /// Boolean composition mode for the conditions list.
    pub mode: String,
    /// Version counter incremented on each update.
    pub version: i64,
    /// ISO-8601 timestamp of last update.
    pub updated_at: String,
}

/// Row type for policy update operations.
///
/// Fields map 1-to-1 to the positional parameters of the `UPDATE policies`
/// statement. The `version` column is incremented server-side, not supplied
/// by callers.
#[derive(Debug, Clone)]
pub struct PolicyUpdateRow<'a> {
    /// New policy name.
    pub name: &'a str,
    /// New optional description.
    pub description: Option<&'a str>,
    /// New evaluation priority.
    pub priority: i64,
    /// New JSON-serialized conditions string.
    pub conditions: &'a str,
    /// New enforcement action.
    pub action: &'a str,
    /// New enabled flag (1 = true, 0 = false).
    pub enabled: i64,
    /// New boolean composition mode.
    pub mode: &'a str,
    /// New ISO-8601 timestamp.
    pub updated_at: &'a str,
    /// Unique policy identifier of the row to update.
    pub id: &'a str,
}

/// Stateless repository for the `policies` table.
pub struct PolicyRepository;

impl PolicyRepository {
    /// Returns all policies ordered by priority ascending.
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if pool acquisition or query execution fails.
    pub fn list(pool: &Pool) -> rusqlite::Result<Vec<PolicyRow>> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        let mut stmt = conn.prepare(
            "SELECT id, name, description, priority, conditions, action, \
             enabled, mode, version, updated_at \
             FROM policies ORDER BY priority ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(PolicyRow {
                id: row.get(0)?,
                name: row.get(1)?,
                description: row.get(2)?,
                priority: row.get(3)?,
                conditions: row.get(4)?,
                action: row.get(5)?,
                enabled: row.get(6)?,
                mode: row.get(7)?,
                version: row.get(8)?,
                updated_at: row.get(9)?,
            })
        })?;
        rows.collect()
    }

    /// Inserts a new policy record.
    ///
    /// # Arguments
    ///
    /// * `uow` - Active unit of work to execute the write within.
    /// * `record` - Policy data to insert.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the statement fails (e.g., duplicate `id`).
    pub fn insert(uow: &UnitOfWork<'_>, record: &PolicyRow) -> rusqlite::Result<()> {
        uow.tx.execute(
            "INSERT INTO policies (id, name, description, priority, conditions, \
             action, enabled, mode, version, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                record.id,
                record.name,
                record.description,
                record.priority,
                record.conditions,
                record.action,
                record.enabled,
                record.mode,
                record.version,
                record.updated_at,
            ],
        )?;
        Ok(())
    }

    /// Returns the single policy row with the given `id`.
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    /// * `id` - Unique policy identifier.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error::QueryReturnedNoRows` if the policy does not exist.
    pub fn get_by_id(pool: &Pool, id: &str) -> rusqlite::Result<PolicyRow> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        conn.query_row(
            "SELECT id, name, description, priority, conditions, action, \
             enabled, mode, version, updated_at \
             FROM policies WHERE id = ?1",
            params![id],
            |row| {
                Ok(PolicyRow {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    priority: row.get(3)?,
                    conditions: row.get(4)?,
                    action: row.get(5)?,
                    enabled: row.get(6)?,
                    mode: row.get(7)?,
                    version: row.get(8)?,
                    updated_at: row.get(9)?,
                })
            },
        )
    }

    /// Updates an existing policy row.
    ///
    /// The `version` column is incremented by 1 inside the SQL.
    ///
    /// # Arguments
    ///
    /// * `uow` - Active unit of work to execute the write within.
    /// * `row` - Policy update data; `id` identifies the row to update.
    ///
    /// # Returns
    ///
    /// Returns the number of rows affected (0 if the policy did not exist).
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the statement fails.
    pub fn update(uow: &UnitOfWork<'_>, row: &PolicyUpdateRow<'_>) -> rusqlite::Result<usize> {
        uow.tx.execute(
            "UPDATE policies SET \
                    name = ?1, description = ?2, priority = ?3, \
                    conditions = ?4, action = ?5, enabled = ?6, \
                    mode = ?7, version = version + 1, updated_at = ?8 \
             WHERE id = ?9",
            params![
                row.name,
                row.description,
                row.priority,
                row.conditions,
                row.action,
                row.enabled,
                row.mode,
                row.updated_at,
                row.id,
            ],
        )
    }

    /// Returns the current `version` number for the given policy `id`.
    ///
    /// Queries the transaction's uncommitted state, so it reflects updates
    /// applied within the same `UnitOfWork` before this call.
    ///
    /// # Arguments
    ///
    /// * `uow` - Active unit of work (provides the transaction to read from).
    /// * `id` - Unique policy identifier.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the query fails or the policy does not exist.
    pub fn get_version(uow: &UnitOfWork<'_>, id: &str) -> rusqlite::Result<i64> {
        uow.tx.query_row(
            "SELECT version FROM policies WHERE id = ?1",
            params![id],
            |row| row.get(0),
        )
    }

    /// Deletes the policy row with the given `id`.
    ///
    /// # Arguments
    ///
    /// * `uow` - Active unit of work to execute the write within.
    /// * `id` - Unique policy identifier to delete.
    ///
    /// # Returns
    ///
    /// Returns the number of rows deleted (0 if the policy did not exist).
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the statement fails.
    pub fn delete(uow: &UnitOfWork<'_>, id: &str) -> rusqlite::Result<usize> {
        uow.tx
            .execute("DELETE FROM policies WHERE id = ?1", params![id])
    }
}
