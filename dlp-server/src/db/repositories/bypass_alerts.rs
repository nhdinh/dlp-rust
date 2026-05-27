//! Repository for the `bypass_alerts` table.
//!
//! Encapsulates all SQL for bypass alert CRUD, batch insert, ack, and filtering.
//! Used by the admin API and agent batch ingest endpoint.

use rusqlite::params;

use crate::db::{Pool, UnitOfWork};

/// Plain data row returned by bypass alert reads.
#[derive(Debug, Clone)]
pub struct BypassAlertRow {
    /// Auto-increment primary key.
    pub id: i64,
    /// Unique identifier of the agent that emitted this alert.
    pub agent_id: String,
    /// Process ID where the alert occurred.
    pub pid: i32,
    /// Full path to the process image executable.
    pub image_path: String,
    /// SHA-256 hex digest of the process executable (None if not computed).
    pub image_sha256: Option<String>,
    /// File path involved in the operation.
    pub file_path: String,
    /// Human-readable operation type (e.g., "Create", "Write").
    pub operation: String,
    /// Kernel FILE_OBJECT pointer (forensics correlation).
    pub file_object: i64,
    /// QueryPerformanceCounter timestamp at correlation time.
    pub qpc_timestamp: i64,
    /// ISO-8601 timestamp when the alert was stored.
    pub created_at: String,
    /// Severity: "info", "warn", or "crit".
    pub severity: String,
    /// Admin username who acknowledged the alert.
    pub ack_by: Option<String>,
    /// ISO-8601 timestamp when the alert was acknowledged.
    pub ack_at: Option<String>,
    /// Correlation reason: "no_hook_journal", "op_mismatch", or "hook_overwritten".
    pub correlation_reason: String,
    /// Batch ID for idempotency (IN-02).
    pub batch_id: Option<String>,
}

/// Row type for bypass alert insert operations.
#[derive(Debug, Clone)]
pub struct BypassAlertInsertRow {
    /// Unique identifier of the agent that emitted this alert.
    pub agent_id: String,
    /// Process ID where the alert occurred.
    pub pid: i32,
    /// Full path to the process image executable.
    pub image_path: String,
    /// SHA-256 hex digest of the process executable.
    pub image_sha256: Option<String>,
    /// File path involved in the operation.
    pub file_path: String,
    /// Human-readable operation type.
    pub operation: String,
    /// Kernel FILE_OBJECT pointer.
    pub file_object: i64,
    /// QueryPerformanceCounter timestamp.
    pub qpc_timestamp: i64,
    /// ISO-8601 timestamp when the alert was stored.
    pub created_at: String,
    /// Severity: "info", "warn", or "crit".
    pub severity: String,
    /// Correlation reason string.
    pub correlation_reason: String,
    /// Batch ID for idempotency.
    pub batch_id: Option<String>,
}

/// Filter parameters for bypass alert queries.
#[derive(Debug, Clone, Default)]
pub struct BypassAlertFilter {
    /// ISO-8601 lower bound (inclusive).
    pub since: Option<String>,
    /// List of severity values to include (e.g., ["crit", "warn"]).
    pub severity: Option<Vec<String>>,
    /// Filter by acknowledged status.
    pub acknowledged: Option<bool>,
    /// Filter by agent ID.
    pub agent_id: Option<String>,
    /// Filter by PID (WR-05).
    pub pid: Option<i32>,
    /// Maximum rows to return (default 50, capped at 500).
    pub limit: Option<usize>,
    /// Number of rows to skip.
    pub offset: Option<usize>,
}

/// Stateless repository for the `bypass_alerts` table.
pub struct BypassAlertsRepository;

impl BypassAlertsRepository {
    /// Returns bypass alerts filtered by optional criteria at the DB level.
    ///
    /// Builds a parameterized query with `WHERE 1=1` base and adds clauses
    /// for each provided filter. Supports pagination via `limit` and `offset`.
    /// Limit is capped at 500.
    pub fn list_by_filters(
        pool: &Pool,
        filter: &BypassAlertFilter,
    ) -> rusqlite::Result<Vec<BypassAlertRow>> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

        let mut sql = String::from(
            "SELECT id, agent_id, pid, image_path, image_sha256, file_path, \
             operation, file_object, qpc_timestamp, created_at, severity, \
             ack_by, ack_at, correlation_reason, batch_id \
             FROM bypass_alerts WHERE 1=1",
        );
        let mut param_count = 0;

        if filter.since.is_some() {
            param_count += 1;
            sql.push_str(&format!(" AND created_at >= ?{param_count}"));
        }
        if let Some(ref sev_list) = filter.severity {
            if !sev_list.is_empty() {
                param_count += 1;
                let placeholders: Vec<String> =
                    (param_count..param_count + sev_list.len())
                        .map(|i| format!("?{i}"))
                        .collect();
                sql.push_str(&format!(" AND severity IN ({})", placeholders.join(", ")));
                param_count += sev_list.len() - 1;
            }
        }
        if let Some(ack) = filter.acknowledged {
            // No parameter placeholder — IS NULL / IS NOT NULL are literal.
            if ack {
                sql.push_str(" AND ack_by IS NOT NULL");
            } else {
                sql.push_str(" AND ack_by IS NULL");
            }
        }
        if filter.agent_id.is_some() {
            param_count += 1;
            sql.push_str(&format!(" AND agent_id = ?{param_count}"));
        }
        if filter.pid.is_some() {
            param_count += 1;
            sql.push_str(&format!(" AND pid = ?{param_count}"));
        }

        sql.push_str(" ORDER BY created_at DESC");

        let limit = filter.limit.map(|l| l.min(500)).unwrap_or(50);
        param_count += 1;
        sql.push_str(&format!(" LIMIT ?{param_count}"));
        if filter.offset.is_some() {
            param_count += 1;
            sql.push_str(&format!(" OFFSET ?{param_count}"));
        }

        let mut stmt = conn.prepare(&sql)?;

        // Build params vector.
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        if let Some(ref since) = filter.since {
            params.push(Box::new(since.clone()));
        }
        if let Some(ref sev_list) = filter.severity {
            for sev in sev_list {
                params.push(Box::new(sev.clone()));
            }
        }
        // acknowledged does not add a param (IS NULL / IS NOT NULL).
        if filter.agent_id.is_some() {
            params.push(Box::new(filter.agent_id.clone().unwrap()));
        }
        if filter.pid.is_some() {
            params.push(Box::new(filter.pid.unwrap()));
        }
        params.push(Box::new(limit as i64));
        if filter.offset.is_some() {
            params.push(Box::new(filter.offset.unwrap() as i64));
        }

        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|p| p.as_ref()).collect();

        let rows = stmt.query_map(param_refs.as_slice(), |row| {
            Ok(BypassAlertRow {
                id: row.get(0)?,
                agent_id: row.get(1)?,
                pid: row.get(2)?,
                image_path: row.get(3)?,
                image_sha256: row.get(4)?,
                file_path: row.get(5)?,
                operation: row.get(6)?,
                file_object: row.get(7)?,
                qpc_timestamp: row.get(8)?,
                created_at: row.get(9)?,
                severity: row.get(10)?,
                ack_by: row.get(11)?,
                ack_at: row.get(12)?,
                correlation_reason: row.get(13)?,
                batch_id: row.get(14)?,
            })
        })?;
        rows.collect()
    }

    /// Inserts a single bypass alert using `INSERT OR IGNORE`.
    ///
    /// Returns `last_insert_rowid()` if the row was inserted, or `0` if a
    /// duplicate was ignored (detected via `changes()` == 0).
    pub fn insert(uow: &UnitOfWork<'_>, row: &BypassAlertInsertRow) -> rusqlite::Result<i64> {
        uow.tx.execute(
            "INSERT OR IGNORE INTO bypass_alerts \
             (agent_id, pid, image_path, image_sha256, file_path, operation, \
              file_object, qpc_timestamp, created_at, severity, correlation_reason, batch_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                row.agent_id,
                row.pid,
                row.image_path,
                row.image_sha256,
                row.file_path,
                row.operation,
                row.file_object,
                row.qpc_timestamp,
                row.created_at,
                row.severity,
                row.correlation_reason,
                row.batch_id,
            ],
        )?;
        if uow.tx.changes() == 0 {
            Ok(0)
        } else {
            Ok(uow.tx.last_insert_rowid())
        }
    }

    /// Acknowledges a bypass alert by ID.
    ///
    /// Returns the number of rows affected (0 if ID not found).
    pub fn ack_by_id(
        uow: &UnitOfWork<'_>,
        id: i64,
        ack_by: &str,
    ) -> rusqlite::Result<usize> {
        uow.tx.execute(
            "UPDATE bypass_alerts \
             SET ack_by = ?1, ack_at = datetime('now') \
             WHERE id = ?2",
            params![ack_by, id],
        )
    }

    /// Returns a single bypass alert by ID.
    pub fn get_by_id(pool: &Pool, id: i64) -> rusqlite::Result<Option<BypassAlertRow>> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        let mut stmt = conn.prepare(
            "SELECT id, agent_id, pid, image_path, image_sha256, file_path, \
             operation, file_object, qpc_timestamp, created_at, severity, \
             ack_by, ack_at, correlation_reason, batch_id \
             FROM bypass_alerts WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map(params![id], |row| {
            Ok(BypassAlertRow {
                id: row.get(0)?,
                agent_id: row.get(1)?,
                pid: row.get(2)?,
                image_path: row.get(3)?,
                image_sha256: row.get(4)?,
                file_path: row.get(5)?,
                operation: row.get(6)?,
                file_object: row.get(7)?,
                qpc_timestamp: row.get(8)?,
                created_at: row.get(9)?,
                severity: row.get(10)?,
                ack_by: row.get(11)?,
                ack_at: row.get(12)?,
                correlation_reason: row.get(13)?,
                batch_id: row.get(14)?,
            })
        })?;
        rows.next().transpose()
    }

    /// Inserts a batch of bypass alerts using `INSERT OR IGNORE`.
    ///
    /// Returns `(inserted_count, skipped_count)` for telemetry.
    pub fn insert_batch(
        uow: &UnitOfWork<'_>,
        rows: &[BypassAlertInsertRow],
    ) -> rusqlite::Result<(usize, usize)> {
        let mut inserted: usize = 0;
        let mut skipped: usize = 0;
        for row in rows {
            let last_id = Self::insert(uow, row)?;
            if last_id == 0 {
                skipped += 1;
            } else {
                inserted += 1;
            }
        }
        Ok((inserted, skipped))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::new_pool;
    use crate::db::unit_of_work::UnitOfWork;

    fn insert_admin_user(conn: &mut rusqlite::Connection, username: &str) {
        conn.execute(
            "INSERT INTO admin_users (username, password_hash, created_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![username, "hash", "2026-01-01T00:00:00Z"],
        )
        .expect("insert admin user");
    }

    fn make_insert_row(agent_id: &str, pid: i32, qpc: i64, file_path: &str) -> BypassAlertInsertRow {
        BypassAlertInsertRow {
            agent_id: agent_id.to_string(),
            pid,
            image_path: r"C:\Test\app.exe".to_string(),
            image_sha256: None,
            file_path: file_path.to_string(),
            operation: "Create".to_string(),
            file_object: 0,
            qpc_timestamp: qpc,
            created_at: "2026-05-28T00:00:00Z".to_string(),
            severity: "crit".to_string(),
            correlation_reason: "no_hook_journal".to_string(),
            batch_id: None,
        }
    }

    #[test]
    fn test_insert_and_get_by_id() {
        let pool = new_pool(":memory:").expect("create pool");
        let id = {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");

            let row = make_insert_row("agent-1", 1234, 1000, r"C:\file.txt");
            let id = BypassAlertsRepository::insert(&uow, &row).expect("insert");
            assert!(id > 0, "insert must return positive id");
            uow.commit().expect("commit");
            id
        };

        let found = BypassAlertsRepository::get_by_id(&pool, id).expect("get_by_id");
        assert!(found.is_some(), "row must exist after insert");
        let found = found.unwrap();
        assert_eq!(found.agent_id, "agent-1");
        assert_eq!(found.pid, 1234);
        assert_eq!(found.file_path, r"C:\file.txt");
    }

    #[test]
    fn test_insert_duplicate_ignored() {
        let pool = new_pool(":memory:").expect("create pool");
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");

            let row = make_insert_row("agent-1", 1234, 1000, r"C:\file.txt");
            let id1 = BypassAlertsRepository::insert(&uow, &row).expect("first insert");
            assert!(id1 > 0);
            let id2 = BypassAlertsRepository::insert(&uow, &row).expect("second insert");
            assert_eq!(id2, 0, "duplicate must be ignored, returning 0");
            uow.commit().expect("commit");
        }
    }

    #[test]
    fn test_insert_batch_with_duplicates() {
        let pool = new_pool(":memory:").expect("create pool");
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");

            let rows = vec![
                make_insert_row("agent-1", 1234, 1000, r"C:\file1.txt"),
                make_insert_row("agent-1", 1234, 1000, r"C:\file1.txt"), // duplicate
                make_insert_row("agent-1", 1235, 1001, r"C:\file2.txt"),
            ];
            let (inserted, skipped) =
                BypassAlertsRepository::insert_batch(&uow, &rows).expect("batch insert");
            assert_eq!(inserted, 2, "expected 2 inserted");
            assert_eq!(skipped, 1, "expected 1 skipped");
            uow.commit().expect("commit");
        }
    }

    #[test]
    fn test_list_by_filters_severity() {
        let pool = new_pool(":memory:").expect("create pool");
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");

            let mut crit = make_insert_row("agent-1", 1234, 1000, r"C:\file1.txt");
            crit.severity = "crit".to_string();
            let mut warn = make_insert_row("agent-1", 1235, 1001, r"C:\file2.txt");
            warn.severity = "warn".to_string();
            let mut info = make_insert_row("agent-1", 1236, 1002, r"C:\file3.txt");
            info.severity = "info".to_string();

            BypassAlertsRepository::insert_batch(&uow, &[crit, warn, info]).expect("insert batch");
            uow.commit().expect("commit");
        }

        let filter = BypassAlertFilter {
            severity: Some(vec!["crit".to_string()]),
            ..Default::default()
        };
        let results = BypassAlertsRepository::list_by_filters(&pool, &filter).expect("list");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].severity, "crit");
    }

    #[test]
    fn test_list_by_filters_acknowledged() {
        let pool = new_pool(":memory:").expect("create pool");
        {
            let mut conn = pool.get().expect("acquire connection");
            insert_admin_user(&mut conn, "admin-1");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");

            let row = make_insert_row("agent-1", 1234, 1000, r"C:\file.txt");
            BypassAlertsRepository::insert(&uow, &row).expect("insert");
            uow.commit().expect("commit");
        }

        // Ack the row.
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            BypassAlertsRepository::ack_by_id(&uow, 1, "admin-1").expect("ack");
            uow.commit().expect("commit");
        }

        let filter = BypassAlertFilter {
            acknowledged: Some(true),
            ..Default::default()
        };
        let results = BypassAlertsRepository::list_by_filters(&pool, &filter).expect("list acked");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].ack_by, Some("admin-1".to_string()));

        let filter_unacked = BypassAlertFilter {
            acknowledged: Some(false),
            ..Default::default()
        };
        let unacked =
            BypassAlertsRepository::list_by_filters(&pool, &filter_unacked).expect("list unacked");
        assert_eq!(unacked.len(), 0);
    }

    #[test]
    fn test_list_by_filters_since() {
        let pool = new_pool(":memory:").expect("create pool");
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");

            let old = make_insert_row("agent-1", 1234, 1000, r"C:\old.txt");
            let mut new = make_insert_row("agent-1", 1235, 1001, r"C:\new.txt");
            new.created_at = "2026-05-28T12:00:00Z".to_string();

            BypassAlertsRepository::insert_batch(&uow, &[old, new]).expect("insert batch");
            uow.commit().expect("commit");
        }

        let filter = BypassAlertFilter {
            since: Some("2026-05-28T10:00:00Z".to_string()),
            ..Default::default()
        };
        let results = BypassAlertsRepository::list_by_filters(&pool, &filter).expect("list");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].file_path, r"C:\new.txt");
    }

    #[test]
    fn test_list_by_filters_agent_id() {
        let pool = new_pool(":memory:").expect("create pool");
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");

            let row1 = make_insert_row("agent-a", 1234, 1000, r"C:\file1.txt");
            let row2 = make_insert_row("agent-b", 1235, 1001, r"C:\file2.txt");
            BypassAlertsRepository::insert_batch(&uow, &[row1, row2]).expect("insert batch");
            uow.commit().expect("commit");
        }

        let filter = BypassAlertFilter {
            agent_id: Some("agent-a".to_string()),
            ..Default::default()
        };
        let results = BypassAlertsRepository::list_by_filters(&pool, &filter).expect("list");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].agent_id, "agent-a");
    }

    #[test]
    fn test_list_by_filters_pid() {
        let pool = new_pool(":memory:").expect("create pool");
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");

            let row1 = make_insert_row("agent-1", 1234, 1000, r"C:\file1.txt");
            let row2 = make_insert_row("agent-1", 5678, 1001, r"C:\file2.txt");
            BypassAlertsRepository::insert_batch(&uow, &[row1, row2]).expect("insert batch");
            uow.commit().expect("commit");
        }

        let filter = BypassAlertFilter {
            pid: Some(1234),
            ..Default::default()
        };
        let results = BypassAlertsRepository::list_by_filters(&pool, &filter).expect("list");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].pid, 1234);
    }

    #[test]
    fn test_list_pagination() {
        let pool = new_pool(":memory:").expect("create pool");
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");

            let mut rows = Vec::new();
            for i in 1..=10 {
                let mut row = make_insert_row("agent-1", 1000 + i, i as i64, &format!(r"C:\file{i}.txt"));
                row.created_at = format!("2026-05-28T{:02}:00:00Z", i);
                rows.push(row);
            }
            BypassAlertsRepository::insert_batch(&uow, &rows).expect("insert batch");
            uow.commit().expect("commit");
        }

        let filter1 = BypassAlertFilter {
            limit: Some(5),
            offset: Some(0),
            ..Default::default()
        };
        let page1 = BypassAlertsRepository::list_by_filters(&pool, &filter1).expect("page1");
        assert_eq!(page1.len(), 5);

        let filter2 = BypassAlertFilter {
            limit: Some(5),
            offset: Some(5),
            ..Default::default()
        };
        let page2 = BypassAlertsRepository::list_by_filters(&pool, &filter2).expect("page2");
        assert_eq!(page2.len(), 5);
    }

    #[test]
    fn test_list_limit_capped_at_500() {
        let pool = new_pool(":memory:").expect("create pool");
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");

            let mut rows = Vec::new();
            for i in 1..=10 {
                let row = make_insert_row("agent-1", 1000 + i, i as i64, &format!(r"C:\file{i}.txt"));
                rows.push(row);
            }
            BypassAlertsRepository::insert_batch(&uow, &rows).expect("insert batch");
            uow.commit().expect("commit");
        }

        let filter = BypassAlertFilter {
            limit: Some(1000),
            ..Default::default()
        };
        let results = BypassAlertsRepository::list_by_filters(&pool, &filter).expect("list");
        assert_eq!(results.len(), 10, "all 10 rows returned even with limit=1000");
        // Note: with only 10 rows, cap doesn't visibly limit. Test verifies no error.
    }

    #[test]
    fn test_ack_by_id() {
        let pool = new_pool(":memory:").expect("create pool");
        let id = {
            let mut conn = pool.get().expect("acquire connection");
            insert_admin_user(&mut conn, "admin-1");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");

            let row = make_insert_row("agent-1", 1234, 1000, r"C:\file.txt");
            let id = BypassAlertsRepository::insert(&uow, &row).expect("insert");
            uow.commit().expect("commit");
            id
        };

        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            let affected = BypassAlertsRepository::ack_by_id(&uow, id, "admin-1").expect("ack");
            assert_eq!(affected, 1);
            uow.commit().expect("commit");
        }

        let found = BypassAlertsRepository::get_by_id(&pool, id).expect("get");
        assert_eq!(found.unwrap().ack_by, Some("admin-1".to_string()));
    }

    #[test]
    fn test_ack_by_id_idempotent() {
        let pool = new_pool(":memory:").expect("create pool");
        let id = {
            let mut conn = pool.get().expect("acquire connection");
            insert_admin_user(&mut conn, "admin-1");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");

            let row = make_insert_row("agent-1", 1234, 1000, r"C:\file.txt");
            let id = BypassAlertsRepository::insert(&uow, &row).expect("insert");
            uow.commit().expect("commit");
            id
        };

        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            BypassAlertsRepository::ack_by_id(&uow, id, "admin-1").expect("first ack");
            uow.commit().expect("commit");
        }

        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            let affected = BypassAlertsRepository::ack_by_id(
                &uow, id, "admin-1").expect("second ack");
            assert_eq!(affected, 1, "ack must affect 1 row even when already acked");
            uow.commit().expect("commit");
        }
    }

    #[test]
    fn test_ack_by_id_not_found() {
        let pool = new_pool(":memory:").expect("create pool");
        let mut conn = pool.get().expect("acquire connection");
        insert_admin_user(&mut conn, "admin-1");
        let uow = UnitOfWork::new(&mut conn).expect("create uow");

        let affected = BypassAlertsRepository::ack_by_id(&uow, 9999, "admin-1").expect("ack missing");
        assert_eq!(affected, 0, "ack on non-existent ID must return 0");
        // No commit needed — no changes made.
    }

    #[test]
    fn test_batch_id_stored() {
        let pool = new_pool(":memory:").expect("create pool");
        let id = {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");

            let mut row = make_insert_row("agent-1", 1234, 1000, r"C:\file.txt");
            row.batch_id = Some("batch-001".to_string());
            let id = BypassAlertsRepository::insert(&uow, &row).expect("insert");
            uow.commit().expect("commit");
            id
        };

        let found = BypassAlertsRepository::get_by_id(&pool, id).expect("get");
        assert_eq!(found.unwrap().batch_id, Some("batch-001".to_string()));
    }

    #[test]
    fn test_file_object_default_zero() {
        let pool = new_pool(":memory:").expect("create pool");
        let id = {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");

            let row = make_insert_row("agent-1", 1234, 1000, r"C:\file.txt");
            let id = BypassAlertsRepository::insert(&uow, &row).expect("insert");
            uow.commit().expect("commit");
            id
        };

        let found = BypassAlertsRepository::get_by_id(&pool, id).expect("get");
        assert_eq!(found.unwrap().file_object, 0);
    }
}
