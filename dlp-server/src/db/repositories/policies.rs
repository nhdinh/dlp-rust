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
    /// Version counter incremented on each update.
    pub version: i64,
    /// ISO-8601 timestamp of last update.
    pub updated_at: String,
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
        let conn = pool.get().map_err(|e| {
            rusqlite::Error::ToSqlConversionFailure(Box::new(e))
        })?;
        let mut stmt = conn.prepare(
            "SELECT id, name, description, priority, conditions, action, \
             enabled, version, updated_at \
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
                version: row.get(7)?,
                updated_at: row.get(8)?,
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
             action, enabled, version, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                record.id,
                record.name,
                record.description,
                record.priority,
                record.conditions,
                record.action,
                record.enabled,
                record.version,
                record.updated_at,
            ],
        )?;
        Ok(())
    }
}
