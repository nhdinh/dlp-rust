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
    /// Evaluation priority -- lower numbers evaluated first.
    pub priority: i64,
    /// JSON-serialized policy conditions.
    pub conditions: String,
    /// Policy action: `"Allow"`, `"Deny"`, `"DenyWithAlert"`, etc.
    pub action: String,
    /// Whether the policy is active (1) or disabled (0).
    pub enabled: i64,
    /// Boolean composition mode for the conditions list.
    pub mode: String,
    /// Enforcement mode: "Audit", "Block", or "AuditAndBlock".
    pub enforcement_mode: String,
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
    /// New enforcement mode.
    pub enforcement_mode: &'a str,
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
             enabled, mode, enforcement_mode, version, updated_at \
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
                enforcement_mode: row.get(8)?,
                version: row.get(9)?,
                updated_at: row.get(10)?,
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
             action, enabled, mode, enforcement_mode, version, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                record.id,
                record.name,
                record.description,
                record.priority,
                record.conditions,
                record.action,
                record.enabled,
                record.mode,
                record.enforcement_mode,
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
             enabled, mode, enforcement_mode, version, updated_at \
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
                    enforcement_mode: row.get(8)?,
                    version: row.get(9)?,
                    updated_at: row.get(10)?,
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
                    mode = ?7, enforcement_mode = ?8, version = version + 1, updated_at = ?9 \
             WHERE id = ?10",
            params![
                row.name,
                row.description,
                row.priority,
                row.conditions,
                row.action,
                row.enabled,
                row.mode,
                row.enforcement_mode,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{new_pool, UnitOfWork};

    #[test]
    fn test_policy_row_enforcement_mode() {
        let row = PolicyRow {
            id: "p1".to_string(),
            name: "Test Policy".to_string(),
            description: None,
            priority: 1,
            conditions: "[]".to_string(),
            action: "DENY".to_string(),
            enabled: 1,
            mode: "ALL".to_string(),
            enforcement_mode: "Block".to_string(),
            version: 1,
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        };
        assert_eq!(row.enforcement_mode, "Block");
    }

    #[test]
    fn test_policy_repository_crud_with_enforcement_mode() {
        let tmp = tempfile::NamedTempFile::new().expect("create temp db file");
        let pool = new_pool(tmp.path().to_str().expect("temp path utf8")).expect("create pool");

        // Insert a policy with enforcement_mode = Audit.
        let mut conn = pool.get().expect("acquire connection");
        let uow = UnitOfWork::new(&mut conn).expect("create uow");
        let row = PolicyRow {
            id: "p-audit".to_string(),
            name: "Audit Policy".to_string(),
            description: Some("Test".to_string()),
            priority: 10,
            conditions: "[]".to_string(),
            action: "DENY".to_string(),
            enabled: 1,
            mode: "ALL".to_string(),
            enforcement_mode: "Audit".to_string(),
            version: 1,
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        };
        PolicyRepository::insert(&uow, &row).expect("insert policy");
        uow.commit().expect("commit");

        // Read back via list.
        let policies = PolicyRepository::list(&pool).expect("list policies");
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].enforcement_mode, "Audit");

        // Read back via get_by_id.
        let fetched = PolicyRepository::get_by_id(&pool, "p-audit").expect("get by id");
        assert_eq!(fetched.enforcement_mode, "Audit");

        // Update enforcement_mode to AuditAndBlock.
        let mut conn2 = pool.get().expect("acquire connection");
        let uow2 = UnitOfWork::new(&mut conn2).expect("create uow");
        let update = PolicyUpdateRow {
            name: "Audit Policy",
            description: Some("Test"),
            priority: 10,
            conditions: "[]",
            action: "DENY",
            enabled: 1,
            mode: "ALL",
            enforcement_mode: "AuditAndBlock",
            updated_at: "2026-01-02T00:00:00Z",
            id: "p-audit",
        };
        let affected = PolicyRepository::update(&uow2, &update).expect("update");
        assert_eq!(affected, 1);
        uow2.commit().expect("commit");

        // Verify update.
        let updated = PolicyRepository::get_by_id(&pool, "p-audit").expect("get updated");
        assert_eq!(updated.enforcement_mode, "AuditAndBlock");
        assert_eq!(updated.version, 2, "version must be incremented");
    }

    #[test]
    fn test_policy_repository_default_enforcement_mode() {
        // Simulate a pre-Phase-55 database where policies exist without
        // the enforcement_mode column. After migration, existing rows
        // must default to 'Block'.
        let tmp = tempfile::NamedTempFile::new().expect("create temp db file");
        let path = tmp.path().to_str().expect("temp path utf8");

        // Step 1: create a pre-Phase-55 policies table without enforcement_mode.
        {
            let conn = rusqlite::Connection::open(path).expect("open temp db");
            conn.execute_batch(
                "CREATE TABLE policies (
                    id          TEXT PRIMARY KEY,
                    name        TEXT NOT NULL,
                    description TEXT,
                    priority    INTEGER NOT NULL,
                    conditions  TEXT NOT NULL,
                    action      TEXT NOT NULL,
                    enabled     INTEGER NOT NULL DEFAULT 1,
                    mode        TEXT NOT NULL DEFAULT 'ALL',
                    version     INTEGER NOT NULL DEFAULT 1,
                    updated_at  TEXT NOT NULL
                );
                INSERT INTO policies
                    (id, name, priority, conditions, action, enabled, mode, version, updated_at)
                VALUES
                    ('legacy-policy', 'Legacy', 1, '[]', 'Allow', 1, 'ALL', 1, '2026-01-01T00:00:00Z');",
            )
            .expect("create pre-Phase-55 schema");
        }

        // Step 2: open via new_pool -- triggers run_migrations.
        let pool = new_pool(path).expect("open pool with migrations");
        let conn = pool.get().expect("acquire connection");

        // Step 3: confirm enforcement_mode column exists.
        let columns: Vec<String> = conn
            .prepare("PRAGMA table_info(policies)")
            .expect("prepare pragma")
            .query_map([], |row| row.get::<_, String>(1))
            .expect("query pragma")
            .filter_map(Result::ok)
            .collect();
        assert!(
            columns.contains(&"enforcement_mode".to_string()),
            "enforcement_mode column must exist after migration; saw {columns:?}"
        );

        // Step 4: pre-existing row picks up SQL DEFAULT 'Block'.
        let mode: String = conn
            .query_row(
                "SELECT enforcement_mode FROM policies WHERE id = 'legacy-policy'",
                [],
                |r| r.get(0),
            )
            .expect("read enforcement_mode from pre-existing row");
        assert_eq!(
            mode, "Block",
            "pre-existing rows must default to 'Block' enforcement_mode"
        );

        // Step 5: idempotency -- re-running migrations must not error.
        crate::db::run_migrations(&conn).expect("second run must not error");
    }

    #[test]
    fn test_global_enforcement_mode_system_kv_seed() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let value: String = conn
            .query_row(
                "SELECT value FROM system_kv WHERE key = 'global_enforcement_mode'",
                [],
                |r| r.get(0),
            )
            .expect("global_enforcement_mode system_kv row must exist");
        assert_eq!(
            value, "PerPolicy",
            "default global_enforcement_mode must be PerPolicy"
        );
    }

    #[test]
    fn test_enforcement_mode_check_constraint() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        // Valid enforcement_mode values must succeed.
        for mode in ["Audit", "Block", "AuditAndBlock"] {
            let id = format!("p-{mode}");
            conn.execute(
                "INSERT INTO policies (id, name, priority, conditions, action, enabled, mode, enforcement_mode, version, updated_at) \
                 VALUES (?1, 'Test', 1, '[]', 'Allow', 1, 'ALL', ?2, 1, '2026-01-01T00:00:00Z')",
                rusqlite::params![id, mode],
            )
            .unwrap_or_else(|e| panic!("INSERT with enforcement_mode='{mode}' must succeed; got: {e}"));
        }

        // Invalid enforcement_mode must fail CHECK constraint.
        let result = conn.execute(
            "INSERT INTO policies (id, name, priority, conditions, action, enabled, mode, enforcement_mode, version, updated_at) \
             VALUES ('p-bad', 'Test', 1, '[]', 'Allow', 1, 'ALL', 'InvalidMode', 1, '2026-01-01T00:00:00Z')",
            [],
        );
        assert!(
            result.is_err(),
            "invalid enforcement_mode must fail CHECK constraint"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("CHECK constraint failed"),
            "error must mention CHECK constraint; got: {err_msg}"
        );
    }
}
