//! Repository for the `allowlist_entries` and `allowlist_audit_log` tables.
//!
//! Encapsulates all SQL for allowlist CRUD and audit logging. The allowlist
//! is used for universal injection protection: entries match DLL paths,
//! certificate subjects, or certificate thumbprints to determine whether a
//! process is trusted enough to inject code into the DLP agent.

use rusqlite::params;

use crate::db::{Pool, UnitOfWork};

/// Plain data row returned by allowlist entry reads.
#[derive(Debug, Clone)]
pub struct AllowlistEntryRow {
    /// Server-generated UUID string (primary key).
    pub id: String,
    /// Match type: "exact_path", "path_glob", "path_prefix", "cert_subject", or "cert_thumbprint".
    pub match_type: String,
    /// The match value (path pattern, cert subject, or thumbprint hex string).
    pub value: String,
    /// Human-readable description of the entry.
    pub description: String,
    /// Category: "self", "avedr", "system_critical", or "operator_defined".
    pub category: String,
    /// Priority for deterministic ordering (lower = higher priority).
    pub priority: i64,
    /// Enabled flag stored as INTEGER (0 = disabled, 1 = enabled).
    pub enabled: i64,
    /// Version counter for optimistic concurrency (bumped on every update).
    pub version: i64,
    /// ISO-8601 timestamp of when this entry was created.
    pub created_at: String,
    /// ISO-8601 timestamp of when this entry was last updated.
    pub updated_at: String,
}

/// Plain data row returned by allowlist audit log reads.
#[derive(Debug, Clone)]
pub struct AllowlistAuditRow {
    /// Server-generated UUID string (primary key).
    pub id: String,
    /// Foreign key referencing the allowlist entry that was mutated.
    pub entry_id: String,
    /// Action performed: "create", "update", "delete", "enable", or "disable".
    pub action: String,
    /// Username or SID of the actor who performed the action.
    pub actor: String,
    /// JSON snapshot of the entry state before the action (None for create).
    pub old_value: Option<String>,
    /// JSON snapshot of the entry state after the action (None for delete).
    pub new_value: Option<String>,
    /// ISO-8601 timestamp of when the audit record was created.
    pub timestamp: String,
}

/// Stateless repository for the `allowlist_entries` table.
///
/// All methods are associated functions (no `&self`) — the repository holds
/// no state. Connection pooling is handled by the caller via `Pool` for reads
/// and `UnitOfWork` for writes.
pub struct AllowlistRepository;

impl AllowlistRepository {
    /// Returns all allowlist entries ordered by `priority` ascending, then `created_at` ascending.
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if pool acquisition or query execution fails.
    pub fn list_all(pool: &Pool) -> rusqlite::Result<Vec<AllowlistEntryRow>> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

        let mut stmt = conn.prepare(
            "SELECT id, match_type, value, description, category, priority, enabled, version, created_at, updated_at \
             FROM allowlist_entries \
             ORDER BY priority ASC, created_at ASC",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(AllowlistEntryRow {
                id: row.get(0)?,
                match_type: row.get(1)?,
                value: row.get(2)?,
                description: row.get(3)?,
                category: row.get(4)?,
                priority: row.get(5)?,
                enabled: row.get(6)?,
                version: row.get(7)?,
                created_at: row.get(8)?,
                updated_at: row.get(9)?,
            })
        })?;
        rows.collect()
    }

    /// Returns allowlist entries filtered by category.
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    /// * `category` - Category filter value.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if pool acquisition or query execution fails.
    pub fn list_by_category(
        pool: &Pool,
        category: &str,
    ) -> rusqlite::Result<Vec<AllowlistEntryRow>> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

        let mut stmt = conn.prepare(
            "SELECT id, match_type, value, description, category, priority, enabled, version, created_at, updated_at \
             FROM allowlist_entries \
             WHERE category = ?1 \
             ORDER BY priority ASC, created_at ASC",
        )?;

        let rows = stmt.query_map(params![category], |row| {
            Ok(AllowlistEntryRow {
                id: row.get(0)?,
                match_type: row.get(1)?,
                value: row.get(2)?,
                description: row.get(3)?,
                category: row.get(4)?,
                priority: row.get(5)?,
                enabled: row.get(6)?,
                version: row.get(7)?,
                created_at: row.get(8)?,
                updated_at: row.get(9)?,
            })
        })?;
        rows.collect()
    }

    /// Returns the allowlist entry with the given `id`.
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    /// * `id` - UUID string of the entry to retrieve.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error::QueryReturnedNoRows` if no matching row exists.
    pub fn get_by_id(pool: &Pool, id: &str) -> rusqlite::Result<AllowlistEntryRow> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        conn.query_row(
            "SELECT id, match_type, value, description, category, priority, enabled, version, created_at, updated_at \
             FROM allowlist_entries WHERE id = ?1",
            params![id],
            |row| {
                Ok(AllowlistEntryRow {
                    id: row.get(0)?,
                    match_type: row.get(1)?,
                    value: row.get(2)?,
                    description: row.get(3)?,
                    category: row.get(4)?,
                    priority: row.get(5)?,
                    enabled: row.get(6)?,
                    version: row.get(7)?,
                    created_at: row.get(8)?,
                    updated_at: row.get(9)?,
                })
            },
        )
    }

    /// Inserts a new allowlist entry.
    ///
    /// # Arguments
    ///
    /// * `uow` - Active unit of work to execute the write within.
    /// * `row` - Allowlist entry data to insert.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the statement fails (e.g., invalid `match_type`
    /// rejected by the DB CHECK constraint).
    pub fn insert(uow: &UnitOfWork<'_>, row: &AllowlistEntryRow) -> rusqlite::Result<()> {
        uow.tx.execute(
            "INSERT INTO allowlist_entries \
                 (id, match_type, value, description, category, priority, enabled, version, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                row.id,
                row.match_type,
                row.value,
                row.description,
                row.category,
                row.priority,
                row.enabled,
                row.version,
                row.created_at,
                row.updated_at,
            ],
        )?;
        Ok(())
    }

    /// Updates an existing allowlist entry, bumping the version counter.
    ///
    /// # Arguments
    ///
    /// * `uow` - Active unit of work to execute the write within.
    /// * `row` - Allowlist entry data to update. The `id` field is used as the
    ///   primary key, and `version` is incremented by 1 in the UPDATE.
    ///
    /// # Returns
    ///
    /// Returns the number of rows updated (0 if the `id` did not exist — not an error).
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the UPDATE statement fails.
    pub fn update(uow: &UnitOfWork<'_>, row: &AllowlistEntryRow) -> rusqlite::Result<usize> {
        uow.tx.execute(
            "UPDATE allowlist_entries SET \
                 match_type  = ?2, \
                 value       = ?3, \
                 description = ?4, \
                 category    = ?5, \
                 priority    = ?6, \
                 enabled     = ?7, \
                 version     = version + 1, \
                 updated_at  = ?8 \
             WHERE id = ?1",
            params![
                row.id,
                row.match_type,
                row.value,
                row.description,
                row.category,
                row.priority,
                row.enabled,
                row.updated_at,
            ],
        )
    }

    /// Deletes the allowlist entry with the given `id`.
    ///
    /// # Arguments
    ///
    /// * `uow` - Active unit of work to execute the write within.
    /// * `id` - UUID string of the entry to delete.
    ///
    /// # Returns
    ///
    /// Returns the number of rows deleted (0 if the `id` did not exist — not an error).
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the DELETE statement itself fails.
    pub fn delete_by_id(uow: &UnitOfWork<'_>, id: &str) -> rusqlite::Result<usize> {
        uow.tx
            .execute("DELETE FROM allowlist_entries WHERE id = ?1", params![id])
    }

    /// Toggles the enabled state of an allowlist entry.
    ///
    /// # Arguments
    ///
    /// * `uow` - Active unit of work to execute the write within.
    /// * `id` - UUID string of the entry to toggle.
    /// * `enabled` - New enabled state (0 = disabled, 1 = enabled).
    /// * `updated_at` - ISO-8601 timestamp for the update.
    ///
    /// # Returns
    ///
    /// Returns the number of rows updated (0 if the `id` did not exist — not an error).
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the UPDATE statement fails.
    pub fn set_enabled(
        uow: &UnitOfWork<'_>,
        id: &str,
        enabled: i64,
        updated_at: &str,
    ) -> rusqlite::Result<usize> {
        uow.tx.execute(
            "UPDATE allowlist_entries SET enabled = ?2, version = version + 1, updated_at = ?3 WHERE id = ?1",
            params![id, enabled, updated_at],
        )
    }

    /// Returns the current maximum version across all allowlist entries.
    ///
    /// Returns 0 if the table is empty (safe default for agent change detection).
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if pool acquisition or query execution fails.
    pub fn current_version(pool: &Pool) -> rusqlite::Result<i64> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        let version: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM allowlist_entries",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);
        Ok(version)
    }
}

/// Stateless repository for the `allowlist_audit_log` table.
///
/// All methods are associated functions (no `&self`).
pub struct AllowlistAuditRepository;

impl AllowlistAuditRepository {
    /// Inserts a new audit log record.
    ///
    /// # Arguments
    ///
    /// * `uow` - Active unit of work to execute the write within.
    /// * `row` - Audit log data to insert.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the statement fails.
    pub fn insert(uow: &UnitOfWork<'_>, row: &AllowlistAuditRow) -> rusqlite::Result<()> {
        uow.tx.execute(
            "INSERT INTO allowlist_audit_log \
                 (id, entry_id, action, actor, old_value, new_value, timestamp) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                row.id,
                row.entry_id,
                row.action,
                row.actor,
                row.old_value,
                row.new_value,
                row.timestamp,
            ],
        )?;
        Ok(())
    }

    /// Returns all audit log records for a given entry, ordered by timestamp descending.
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    /// * `entry_id` - UUID string of the allowlist entry to query.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if pool acquisition or query execution fails.
    pub fn list_by_entry_id(
        pool: &Pool,
        entry_id: &str,
    ) -> rusqlite::Result<Vec<AllowlistAuditRow>> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

        let mut stmt = conn.prepare(
            "SELECT id, entry_id, action, actor, old_value, new_value, timestamp \
             FROM allowlist_audit_log \
             WHERE entry_id = ?1 \
             ORDER BY timestamp DESC",
        )?;

        let rows = stmt.query_map(params![entry_id], |row| {
            Ok(AllowlistAuditRow {
                id: row.get(0)?,
                entry_id: row.get(1)?,
                action: row.get(2)?,
                actor: row.get(3)?,
                old_value: row.get(4)?,
                new_value: row.get(5)?,
                timestamp: row.get(6)?,
            })
        })?;
        rows.collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{new_pool, unit_of_work::UnitOfWork};

    /// Helper: build an in-memory pool with the full schema initialized.
    fn make_pool() -> Pool {
        new_pool(":memory:").expect("create in-memory pool")
    }

    /// Helper: construct a test allowlist entry row.
    fn make_row(
        id: &str,
        match_type: &str,
        value: &str,
        category: &str,
        priority: i64,
    ) -> AllowlistEntryRow {
        AllowlistEntryRow {
            id: id.to_string(),
            match_type: match_type.to_string(),
            value: value.to_string(),
            description: "Test entry".to_string(),
            category: category.to_string(),
            priority,
            enabled: 1,
            version: 1,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn test_list_all_empty() {
        let pool = make_pool();
        let rows = AllowlistRepository::list_all(&pool).expect("list_all on empty DB");
        assert!(
            rows.is_empty(),
            "expected empty vec from fresh DB; got {rows:?}"
        );
    }

    #[test]
    fn test_insert_and_list() {
        let pool = make_pool();

        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin transaction");
            let row = make_row(
                "uuid-1",
                "exact_path",
                "C:\\Windows\\System32\\foo.dll",
                "self",
                10,
            );
            AllowlistRepository::insert(&uow, &row).expect("insert new row");
            uow.commit().expect("commit");
        }

        let rows = AllowlistRepository::list_all(&pool).expect("list_all");
        assert_eq!(rows.len(), 1, "expected 1 row after insert");
        let r = &rows[0];
        assert_eq!(r.id, "uuid-1");
        assert_eq!(r.match_type, "exact_path");
        assert_eq!(r.value, "C:\\Windows\\System32\\foo.dll");
        assert_eq!(r.category, "self");
        assert_eq!(r.priority, 10);
        assert_eq!(r.enabled, 1);
        assert_eq!(r.version, 1);
    }

    #[test]
    fn test_get_by_id_found() {
        let pool = make_pool();

        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin transaction");
            let row = make_row(
                "uuid-1",
                "exact_path",
                "C:\\Windows\\System32\\foo.dll",
                "self",
                10,
            );
            AllowlistRepository::insert(&uow, &row).expect("insert");
            uow.commit().expect("commit");
        }

        let r = AllowlistRepository::get_by_id(&pool, "uuid-1").expect("get_by_id");
        assert_eq!(r.id, "uuid-1");
        assert_eq!(r.match_type, "exact_path");
    }

    #[test]
    fn test_get_by_id_not_found() {
        let pool = make_pool();
        let result = AllowlistRepository::get_by_id(&pool, "missing");
        assert!(result.is_err(), "expected error for missing id");
    }

    #[test]
    fn test_update_bumps_version() {
        let pool = make_pool();

        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin transaction");
            let row = make_row(
                "uuid-1",
                "exact_path",
                "C:\\Windows\\System32\\foo.dll",
                "self",
                10,
            );
            AllowlistRepository::insert(&uow, &row).expect("insert");
            uow.commit().expect("commit");
        }

        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin transaction");
            let updated = AllowlistEntryRow {
                value: "C:\\Windows\\System32\\bar.dll".to_string(),
                updated_at: "2026-06-01T00:00:00Z".to_string(),
                ..make_row(
                    "uuid-1",
                    "exact_path",
                    "C:\\Windows\\System32\\foo.dll",
                    "self",
                    10,
                )
            };
            let affected = AllowlistRepository::update(&uow, &updated).expect("update");
            assert_eq!(affected, 1, "expected 1 row updated");
            uow.commit().expect("commit");
        }

        let r = AllowlistRepository::get_by_id(&pool, "uuid-1").expect("get after update");
        assert_eq!(r.value, "C:\\Windows\\System32\\bar.dll");
        assert_eq!(r.version, 2, "version must be bumped");
        assert_eq!(r.updated_at, "2026-06-01T00:00:00Z");
    }

    #[test]
    fn test_delete_by_id_removes_row() {
        let pool = make_pool();

        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin transaction");
            let row = make_row(
                "uuid-1",
                "exact_path",
                "C:\\Windows\\System32\\foo.dll",
                "self",
                10,
            );
            AllowlistRepository::insert(&uow, &row).expect("insert");
            uow.commit().expect("commit");
        }

        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin transaction");
            let affected = AllowlistRepository::delete_by_id(&uow, "uuid-1").expect("delete_by_id");
            assert_eq!(affected, 1, "expected 1 row deleted");
            uow.commit().expect("commit");
        }

        let rows = AllowlistRepository::list_all(&pool).expect("list_all after delete");
        assert!(rows.is_empty(), "expected empty vec after delete");
    }

    #[test]
    fn test_delete_by_id_nonexistent_returns_zero() {
        let pool = make_pool();
        let mut conn = pool.get().expect("get connection");
        let uow = UnitOfWork::new(&mut conn).expect("begin transaction");
        let affected = AllowlistRepository::delete_by_id(&uow, "does-not-exist")
            .expect("delete_by_id on missing UUID must not error");
        uow.commit().expect("commit");
        assert_eq!(
            affected, 0,
            "expected 0 rows affected for non-existent UUID"
        );
    }

    #[test]
    fn test_list_by_category() {
        let pool = make_pool();

        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin transaction");
            let self_row = make_row("uuid-1", "exact_path", "C:\\foo.dll", "self", 10);
            let av_row = make_row("uuid-2", "cert_thumbprint", "ABCD", "avedr", 20);
            AllowlistRepository::insert(&uow, &self_row).expect("insert self");
            AllowlistRepository::insert(&uow, &av_row).expect("insert avedr");
            uow.commit().expect("commit");
        }

        let self_rows =
            AllowlistRepository::list_by_category(&pool, "self").expect("list_by_category");
        assert_eq!(self_rows.len(), 1);
        assert_eq!(self_rows[0].id, "uuid-1");

        let av_rows =
            AllowlistRepository::list_by_category(&pool, "avedr").expect("list_by_category avedr");
        assert_eq!(av_rows.len(), 1);
        assert_eq!(av_rows[0].id, "uuid-2");
    }

    #[test]
    fn test_set_enabled() {
        let pool = make_pool();

        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin transaction");
            let row = make_row("uuid-1", "exact_path", "C:\\foo.dll", "self", 10);
            AllowlistRepository::insert(&uow, &row).expect("insert");
            uow.commit().expect("commit");
        }

        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin transaction");
            let affected =
                AllowlistRepository::set_enabled(&uow, "uuid-1", 0, "2026-06-01T00:00:00Z")
                    .expect("set_enabled");
            assert_eq!(affected, 1);
            uow.commit().expect("commit");
        }

        let r = AllowlistRepository::get_by_id(&pool, "uuid-1").expect("get after disable");
        assert_eq!(r.enabled, 0);
        assert_eq!(r.version, 2, "version must be bumped on enable toggle");
    }

    #[test]
    fn test_check_constraint_rejects_invalid_match_type() {
        let pool = make_pool();
        let mut conn = pool.get().expect("get connection");
        let uow = UnitOfWork::new(&mut conn).expect("begin transaction");
        let bad_row = AllowlistEntryRow {
            match_type: "invalid_type".to_string(),
            ..make_row("uuid-bad", "invalid_type", "val", "self", 10)
        };
        let result = AllowlistRepository::insert(&uow, &bad_row);
        assert!(result.is_err(), "invalid match_type must be rejected");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("CHECK constraint failed"),
            "error must mention CHECK constraint; got: {err_msg}"
        );
    }

    #[test]
    fn test_check_constraint_rejects_invalid_category() {
        let pool = make_pool();
        let mut conn = pool.get().expect("get connection");
        let uow = UnitOfWork::new(&mut conn).expect("begin transaction");
        let bad_row = AllowlistEntryRow {
            category: "invalid_cat".to_string(),
            ..make_row("uuid-bad", "exact_path", "val", "invalid_cat", 10)
        };
        let result = AllowlistRepository::insert(&uow, &bad_row);
        assert!(result.is_err(), "invalid category must be rejected");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("CHECK constraint failed"),
            "error must mention CHECK constraint; got: {err_msg}"
        );
    }

    #[test]
    fn test_audit_insert_and_list_by_entry() {
        let pool = make_pool();

        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin transaction");
            // Insert the parent allowlist entry first so the FK constraint is satisfied.
            let row = make_row("uuid-1", "exact_path", "C:\\foo.dll", "self", 10);
            AllowlistRepository::insert(&uow, &row).expect("insert entry");
            let audit = AllowlistAuditRow {
                id: "audit-1".to_string(),
                entry_id: "uuid-1".to_string(),
                action: "create".to_string(),
                actor: "admin".to_string(),
                old_value: None,
                new_value: Some(r#"{"id":"uuid-1","value":"foo.dll"}"#.to_string()),
                timestamp: "2026-01-01T00:00:00Z".to_string(),
            };
            AllowlistAuditRepository::insert(&uow, &audit).expect("insert audit");
            uow.commit().expect("commit");
        }

        let audits =
            AllowlistAuditRepository::list_by_entry_id(&pool, "uuid-1").expect("list_by_entry_id");
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0].action, "create");
        assert_eq!(audits[0].actor, "admin");
        assert_eq!(
            audits[0].new_value,
            Some(r#"{"id":"uuid-1","value":"foo.dll"}"#.to_string())
        );
    }

    #[test]
    fn test_audit_list_by_entry_id_empty() {
        let pool = make_pool();
        let audits = AllowlistAuditRepository::list_by_entry_id(&pool, "missing")
            .expect("list_by_entry_id on empty DB");
        assert!(audits.is_empty(), "expected empty vec for missing entry_id");
    }
}
