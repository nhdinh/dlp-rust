//! Repository for the `approvals` table.
//!
//! Encapsulates all SQL for approval CRUD, filtering, and lifecycle
//! management. The `approvals` table stores approval requests and grants
//! for T3 Data Owner and T4 Board digital-signature workflows.
//!
//! ## Soft reference to labels
//!
//! `data_object_id` is intentionally NOT a foreign key to `labels(id)`.
//! During pilot phase, data objects may be referenced before they exist
//! in the labels table (e.g. path-based approvals). The API layer resolves
//! paths to label IDs where possible.

use rusqlite::params;

use crate::db::{Pool, UnitOfWork};

/// Plain data row returned by approval reads.
#[derive(Debug, Clone)]
pub struct ApprovalRow {
    /// UUID string identifying the approval.
    pub id: String,
    /// AD SID of the user requesting the override.
    pub requester_sid: String,
    /// AD SID of the Data Owner who granted the approval.
    pub approver_sid: Option<String>,
    /// FK to labels.id (soft reference — not enforced at DB level).
    pub data_object_id: String,
    /// Action being approved (e.g. "WRITE", "COPY").
    pub allowed_action: String,
    /// Where the data can go (None = any).
    pub destination_scope: Option<String>,
    /// ISO-8601 timestamp when the approval becomes valid.
    pub valid_from: Option<String>,
    /// ISO-8601 timestamp when the approval expires.
    pub valid_until: Option<String>,
    /// Hex-encoded Ed25519 signature for T4 Board approval.
    pub signature: Option<String>,
    /// Current lifecycle state.
    pub status: String,
    /// User-provided justification text.
    pub justification: String,
    /// ISO-8601 timestamp of creation.
    pub created_at: String,
    /// ISO-8601 timestamp of last update.
    pub updated_at: String,
}

/// Row type for approval insert operations.
#[derive(Debug, Clone)]
pub struct ApprovalUpsertRow<'a> {
    /// UUID string identifying the approval.
    pub id: &'a str,
    /// AD SID of the requesting user.
    pub requester_sid: &'a str,
    /// FK to labels.id (soft reference).
    pub data_object_id: &'a str,
    /// Action being approved.
    pub allowed_action: &'a str,
    /// Destination scope restriction.
    pub destination_scope: Option<&'a str>,
    /// User-provided justification.
    pub justification: &'a str,
    /// ISO-8601 timestamp of creation.
    pub created_at: &'a str,
    /// ISO-8601 timestamp of last update.
    pub updated_at: &'a str,
}

/// Stateless repository for the `approvals` table.
pub struct ApprovalRepository;

impl ApprovalRepository {
    /// Returns all approvals ordered by `created_at DESC`.
    ///
    /// Supports optional pagination via `limit` and `offset`.
    pub fn list(
        pool: &Pool,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> rusqlite::Result<Vec<ApprovalRow>> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

        let mut sql = String::from(
            "SELECT id, requester_sid, approver_sid, data_object_id, allowed_action, \
             destination_scope, valid_from, valid_until, signature, status, \
             justification, created_at, updated_at \
             FROM approvals ORDER BY created_at DESC",
        );
        if let Some(lim) = limit {
            sql.push_str(&format!(" LIMIT {lim}"));
            if let Some(off) = offset {
                sql.push_str(&format!(" OFFSET {off}"));
            }
        }

        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| {
            Ok(ApprovalRow {
                id: row.get(0)?,
                requester_sid: row.get(1)?,
                approver_sid: row.get(2)?,
                data_object_id: row.get(3)?,
                allowed_action: row.get(4)?,
                destination_scope: row.get(5)?,
                valid_from: row.get(6)?,
                valid_until: row.get(7)?,
                signature: row.get(8)?,
                status: row.get(9)?,
                justification: row.get(10)?,
                created_at: row.get(11)?,
                updated_at: row.get(12)?,
            })
        })?;
        rows.collect()
    }

    /// Returns approvals filtered by status, ordered by `created_at DESC`.
    ///
    /// Supports optional pagination via `limit` and `offset`.
    pub fn list_by_status(
        pool: &Pool,
        status: &str,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> rusqlite::Result<Vec<ApprovalRow>> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

        let mut sql = String::from(
            "SELECT id, requester_sid, approver_sid, data_object_id, allowed_action, \
             destination_scope, valid_from, valid_until, signature, status, \
             justification, created_at, updated_at \
             FROM approvals WHERE status = ?1 ORDER BY created_at DESC",
        );
        if let Some(lim) = limit {
            sql.push_str(&format!(" LIMIT {lim}"));
            if let Some(off) = offset {
                sql.push_str(&format!(" OFFSET {off}"));
            }
        }

        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params![status], |row| {
            Ok(ApprovalRow {
                id: row.get(0)?,
                requester_sid: row.get(1)?,
                approver_sid: row.get(2)?,
                data_object_id: row.get(3)?,
                allowed_action: row.get(4)?,
                destination_scope: row.get(5)?,
                valid_from: row.get(6)?,
                valid_until: row.get(7)?,
                signature: row.get(8)?,
                status: row.get(9)?,
                justification: row.get(10)?,
                created_at: row.get(11)?,
                updated_at: row.get(12)?,
            })
        })?;
        rows.collect()
    }

    /// Returns approvals filtered by requester SID, ordered by `created_at DESC`.
    ///
    /// Supports optional pagination via `limit` and `offset`.
    pub fn list_by_requester(
        pool: &Pool,
        requester_sid: &str,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> rusqlite::Result<Vec<ApprovalRow>> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

        let mut sql = String::from(
            "SELECT id, requester_sid, approver_sid, data_object_id, allowed_action, \
             destination_scope, valid_from, valid_until, signature, status, \
             justification, created_at, updated_at \
             FROM approvals WHERE requester_sid = ?1 ORDER BY created_at DESC",
        );
        if let Some(lim) = limit {
            sql.push_str(&format!(" LIMIT {lim}"));
            if let Some(off) = offset {
                sql.push_str(&format!(" OFFSET {off}"));
            }
        }

        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params![requester_sid], |row| {
            Ok(ApprovalRow {
                id: row.get(0)?,
                requester_sid: row.get(1)?,
                approver_sid: row.get(2)?,
                data_object_id: row.get(3)?,
                allowed_action: row.get(4)?,
                destination_scope: row.get(5)?,
                valid_from: row.get(6)?,
                valid_until: row.get(7)?,
                signature: row.get(8)?,
                status: row.get(9)?,
                justification: row.get(10)?,
                created_at: row.get(11)?,
                updated_at: row.get(12)?,
            })
        })?;
        rows.collect()
    }

    /// Returns the single approval row with the given `id`.
    pub fn get_by_id(pool: &Pool, id: &str) -> rusqlite::Result<ApprovalRow> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        conn.query_row(
            "SELECT id, requester_sid, approver_sid, data_object_id, allowed_action, \
             destination_scope, valid_from, valid_until, signature, status, \
             justification, created_at, updated_at \
             FROM approvals WHERE id = ?1",
            params![id],
            |row| {
                Ok(ApprovalRow {
                    id: row.get(0)?,
                    requester_sid: row.get(1)?,
                    approver_sid: row.get(2)?,
                    data_object_id: row.get(3)?,
                    allowed_action: row.get(4)?,
                    destination_scope: row.get(5)?,
                    valid_from: row.get(6)?,
                    valid_until: row.get(7)?,
                    signature: row.get(8)?,
                    status: row.get(9)?,
                    justification: row.get(10)?,
                    created_at: row.get(11)?,
                    updated_at: row.get(12)?,
                })
            },
        )
    }

    /// Inserts a new pending approval record.
    pub fn insert(uow: &UnitOfWork, record: &ApprovalUpsertRow) -> rusqlite::Result<()> {
        uow.tx.execute(
            "INSERT INTO approvals \
             (id, requester_sid, data_object_id, allowed_action, destination_scope, \
              status, justification, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6, ?7, ?8)",
            params![
                record.id,
                record.requester_sid,
                record.data_object_id,
                record.allowed_action,
                record.destination_scope,
                record.justification,
                record.created_at,
                record.updated_at,
            ],
        )?;
        Ok(())
    }

    /// Updates the status and related fields of an approval with a TOCTOU guard.
    ///
    /// Uses a parameterized `WHERE status = ?` clause with `expected_current_status`
    /// to prevent race conditions (e.g. double-grant). Returns the number of rows
    /// affected — callers should check for `1` to confirm the transition succeeded.
    ///
    /// # Arguments
    ///
    /// * `uow` — unit of work (transaction)
    /// * `id` — approval UUID
    /// * `expected_current_status` — the status the approval must currently have
    ///   (e.g. "pending" for grant/reject, "approved" for revoke)
    /// * `new_status` — the new status to set
    /// * `approver_sid` — SID of the approver (set on grant)
    /// * `valid_from` — ISO-8601 timestamp when approval becomes valid
    /// * `valid_until` — ISO-8601 timestamp when approval expires
    /// * `signature` — hex-encoded Ed25519 signature (T4 only)
    /// * `updated_at` — ISO-8601 timestamp of this update
    #[allow(clippy::too_many_arguments)]
    pub fn update_state(
        uow: &UnitOfWork,
        id: &str,
        expected_current_status: &str,
        new_status: &str,
        approver_sid: Option<&str>,
        valid_from: Option<&str>,
        valid_until: Option<&str>,
        signature: Option<&str>,
        updated_at: &str,
    ) -> rusqlite::Result<usize> {
        uow.tx.execute(
            "UPDATE approvals SET \
                    status = ?1, \
                    approver_sid = ?2, \
                    valid_from = ?3, \
                    valid_until = ?4, \
                    signature = ?5, \
                    updated_at = ?6 \
             WHERE id = ?7 AND status = ?8",
            params![
                new_status,
                approver_sid,
                valid_from,
                valid_until,
                signature,
                updated_at,
                id,
                expected_current_status,
            ],
        )
    }

    /// Deletes the approval row with the given `id`.
    pub fn delete(uow: &UnitOfWork, id: &str) -> rusqlite::Result<usize> {
        uow.tx
            .execute("DELETE FROM approvals WHERE id = ?1", params![id])
    }

    /// Deletes pending approvals older than the given timestamp.
    ///
    /// Used for periodic cleanup of orphaned pending approvals (e.g. 7-day
    /// auto-reject).
    pub fn cleanup_orphaned(uow: &UnitOfWork, before: &str) -> rusqlite::Result<usize> {
        uow.tx.execute(
            "DELETE FROM approvals WHERE status = 'pending' AND created_at < ?1",
            params![before],
        )
    }

    /// Returns the count of approvals with the given status.
    pub fn count_by_status(pool: &Pool, status: &str) -> rusqlite::Result<i64> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        conn.query_row(
            "SELECT COUNT(*) FROM approvals WHERE status = ?1",
            params![status],
            |r| r.get(0),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::new_pool;
    use crate::db::unit_of_work::UnitOfWork;

    fn make_pending_row<'a>(
        id: &'a str,
        requester_sid: &'a str,
        data_object_id: &'a str,
    ) -> ApprovalUpsertRow<'a> {
        ApprovalUpsertRow {
            id,
            requester_sid,
            data_object_id,
            allowed_action: "WRITE",
            destination_scope: Some("C:\\Data"),
            justification: "Business need",
            created_at: "2026-05-14T00:00:00Z",
            updated_at: "2026-05-14T00:00:00Z",
        }
    }

    #[test]
    fn test_approvals_table_exists() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='approvals'",
                [],
                |r| r.get(0),
            )
            .expect("query sqlite_master");
        assert_eq!(count, 1, "approvals table must exist after init");
    }

    #[test]
    fn test_insert_and_list() {
        let pool = new_pool(":memory:").expect("create pool");

        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            ApprovalRepository::insert(
                &uow,
                &make_pending_row("app-001", "S-1-5-21-1", "label-001"),
            )
            .expect("insert");
            uow.commit().expect("commit");
        }

        let all = ApprovalRepository::list(&pool, None, None).expect("list");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, "app-001");
        assert_eq!(all[0].status, "pending");
        assert_eq!(all[0].requester_sid, "S-1-5-21-1");
    }

    #[test]
    fn test_list_ordered_by_created_at_desc() {
        let pool = new_pool(":memory:").expect("create pool");

        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            ApprovalRepository::insert(
                &uow,
                &ApprovalUpsertRow {
                    id: "app-001",
                    requester_sid: "S-1-5-21-1",
                    data_object_id: "label-001",
                    allowed_action: "WRITE",
                    destination_scope: None,
                    justification: "First",
                    created_at: "2026-05-14T00:00:00Z",
                    updated_at: "2026-05-14T00:00:00Z",
                },
            )
            .expect("insert first");
            ApprovalRepository::insert(
                &uow,
                &ApprovalUpsertRow {
                    id: "app-002",
                    requester_sid: "S-1-5-21-2",
                    data_object_id: "label-002",
                    allowed_action: "COPY",
                    destination_scope: None,
                    justification: "Second",
                    created_at: "2026-05-14T01:00:00Z",
                    updated_at: "2026-05-14T01:00:00Z",
                },
            )
            .expect("insert second");
            uow.commit().expect("commit");
        }

        let all = ApprovalRepository::list(&pool, None, None).expect("list");
        assert_eq!(all.len(), 2);
        // DESC order: app-002 (later) first
        assert_eq!(all[0].id, "app-002");
        assert_eq!(all[1].id, "app-001");
    }

    #[test]
    fn test_list_by_status() {
        let pool = new_pool(":memory:").expect("create pool");

        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            ApprovalRepository::insert(
                &uow,
                &make_pending_row("app-001", "S-1-5-21-1", "label-001"),
            )
            .expect("insert");
            uow.commit().expect("commit");
        }

        let pending =
            ApprovalRepository::list_by_status(&pool, "pending", None, None).expect("list pending");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, "app-001");

        let approved = ApprovalRepository::list_by_status(&pool, "approved", None, None)
            .expect("list approved");
        assert_eq!(approved.len(), 0);
    }

    #[test]
    fn test_list_by_requester() {
        let pool = new_pool(":memory:").expect("create pool");

        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            ApprovalRepository::insert(
                &uow,
                &make_pending_row("app-001", "S-1-5-21-1", "label-001"),
            )
            .expect("insert");
            ApprovalRepository::insert(
                &uow,
                &make_pending_row("app-002", "S-1-5-21-2", "label-002"),
            )
            .expect("insert second");
            uow.commit().expect("commit");
        }

        let by_sid = ApprovalRepository::list_by_requester(&pool, "S-1-5-21-1", None, None)
            .expect("list by requester");
        assert_eq!(by_sid.len(), 1);
        assert_eq!(by_sid[0].id, "app-001");
    }

    #[test]
    fn test_get_by_id() {
        let pool = new_pool(":memory:").expect("create pool");

        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            ApprovalRepository::insert(
                &uow,
                &make_pending_row("app-001", "S-1-5-21-1", "label-001"),
            )
            .expect("insert");
            uow.commit().expect("commit");
        }

        let row = ApprovalRepository::get_by_id(&pool, "app-001").expect("get by id");
        assert_eq!(row.requester_sid, "S-1-5-21-1");
        assert_eq!(row.data_object_id, "label-001");
    }

    #[test]
    fn test_update_state_toctou_guard() {
        let pool = new_pool(":memory:").expect("create pool");

        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            ApprovalRepository::insert(
                &uow,
                &make_pending_row("app-001", "S-1-5-21-1", "label-001"),
            )
            .expect("insert");
            uow.commit().expect("commit");
        }

        // Grant: pending -> approved
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            let affected = ApprovalRepository::update_state(
                &uow,
                "app-001",
                "pending",          // expected current status
                "approved",         // new status
                Some("S-1-5-21-2"), // approver SID
                Some("2026-05-14T00:00:00Z"),
                Some("2026-05-15T00:00:00Z"),
                None, // no signature (T3)
                "2026-05-14T01:00:00Z",
            )
            .expect("update state");
            assert_eq!(affected, 1, "exactly one row should be updated");
            uow.commit().expect("commit");
        }

        // Verify the update
        let row = ApprovalRepository::get_by_id(&pool, "app-001").expect("get by id");
        assert_eq!(row.status, "approved");
        assert_eq!(row.approver_sid, Some("S-1-5-21-2".to_string()));
        assert_eq!(row.valid_from, Some("2026-05-14T00:00:00Z".to_string()));
        assert_eq!(row.valid_until, Some("2026-05-15T00:00:00Z".to_string()));

        // Second grant attempt on already-approved should return 0 (TOCTOU guard)
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            let affected = ApprovalRepository::update_state(
                &uow,
                "app-001",
                "pending", // expected current status (wrong now)
                "approved",
                Some("S-1-5-21-3"),
                None,
                None,
                None,
                "2026-05-14T02:00:00Z",
            )
            .expect("update state");
            assert_eq!(affected, 0, "second grant on same approval must return 0");
            uow.commit().expect("commit");
        }
    }

    #[test]
    fn test_delete() {
        let pool = new_pool(":memory:").expect("create pool");

        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            ApprovalRepository::insert(
                &uow,
                &make_pending_row("app-001", "S-1-5-21-1", "label-001"),
            )
            .expect("insert");
            uow.commit().expect("commit");
        }

        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            let affected = ApprovalRepository::delete(&uow, "app-001").expect("delete");
            assert_eq!(affected, 1);
            uow.commit().expect("commit");
        }

        let all = ApprovalRepository::list(&pool, None, None).expect("list after delete");
        assert_eq!(all.len(), 0);
    }

    #[test]
    fn test_cleanup_orphaned() {
        let pool = new_pool(":memory:").expect("create pool");

        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            ApprovalRepository::insert(
                &uow,
                &ApprovalUpsertRow {
                    id: "app-old",
                    requester_sid: "S-1-5-21-1",
                    data_object_id: "label-001",
                    allowed_action: "WRITE",
                    destination_scope: None,
                    justification: "Old request",
                    created_at: "2026-05-01T00:00:00Z",
                    updated_at: "2026-05-01T00:00:00Z",
                },
            )
            .expect("insert old");
            ApprovalRepository::insert(
                &uow,
                &ApprovalUpsertRow {
                    id: "app-new",
                    requester_sid: "S-1-5-21-1",
                    data_object_id: "label-002",
                    allowed_action: "COPY",
                    destination_scope: None,
                    justification: "New request",
                    created_at: "2026-05-14T00:00:00Z",
                    updated_at: "2026-05-14T00:00:00Z",
                },
            )
            .expect("insert new");
            uow.commit().expect("commit");
        }

        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            let affected = ApprovalRepository::cleanup_orphaned(&uow, "2026-05-07T00:00:00Z")
                .expect("cleanup");
            assert_eq!(affected, 1, "only old pending approval should be deleted");
            uow.commit().expect("commit");
        }

        let all = ApprovalRepository::list(&pool, None, None).expect("list after cleanup");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, "app-new");
    }

    #[test]
    fn test_count_by_status() {
        let pool = new_pool(":memory:").expect("create pool");

        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            ApprovalRepository::insert(
                &uow,
                &make_pending_row("app-001", "S-1-5-21-1", "label-001"),
            )
            .expect("insert");
            ApprovalRepository::insert(
                &uow,
                &make_pending_row("app-002", "S-1-5-21-2", "label-002"),
            )
            .expect("insert second");
            uow.commit().expect("commit");
        }

        let count = ApprovalRepository::count_by_status(&pool, "pending").expect("count");
        assert_eq!(count, 2);

        let count_approved =
            ApprovalRepository::count_by_status(&pool, "approved").expect("count approved");
        assert_eq!(count_approved, 0);
    }

    #[test]
    fn test_pagination() {
        let pool = new_pool(":memory:").expect("create pool");

        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            for i in 0..5 {
                ApprovalRepository::insert(
                    &uow,
                    &ApprovalUpsertRow {
                        id: &format!("app-{i:03}"),
                        requester_sid: "S-1-5-21-1",
                        data_object_id: &format!("label-{i:03}"),
                        allowed_action: "WRITE",
                        destination_scope: None,
                        justification: "Test",
                        created_at: &format!("2026-05-14T{:02}:00:00Z", i),
                        updated_at: &format!("2026-05-14T{:02}:00:00Z", i),
                    },
                )
                .expect("insert");
            }
            uow.commit().expect("commit");
        }

        let page1 = ApprovalRepository::list(&pool, Some(2), Some(0)).expect("page 1");
        assert_eq!(page1.len(), 2);
        assert_eq!(page1[0].id, "app-004"); // latest first (DESC)
        assert_eq!(page1[1].id, "app-003");

        let page2 = ApprovalRepository::list(&pool, Some(2), Some(2)).expect("page 2");
        assert_eq!(page2.len(), 2);
        assert_eq!(page2[0].id, "app-002");
        assert_eq!(page2[1].id, "app-001");

        let page3 = ApprovalRepository::list(&pool, Some(2), Some(4)).expect("page 3");
        assert_eq!(page3.len(), 1);
        assert_eq!(page3[0].id, "app-000");
    }

    #[test]
    fn test_check_constraint_rejects_invalid_status() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let result = conn.execute(
            "INSERT INTO approvals \
             (id, requester_sid, data_object_id, allowed_action, status, \
              justification, created_at, updated_at) \
             VALUES ('id1', 'sid1', 'obj1', 'WRITE', 'bad_status', '', \
                     '2026-01-01', '2026-01-01')",
            [],
        );
        assert!(result.is_err(), "invalid status must fail CHECK constraint");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("CHECK constraint failed"),
            "error must mention CHECK constraint; got: {err_msg}"
        );
    }

    #[test]
    fn test_revoke_toctou_guard() {
        let pool = new_pool(":memory:").expect("create pool");

        // Insert and grant
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            ApprovalRepository::insert(
                &uow,
                &make_pending_row("app-001", "S-1-5-21-1", "label-001"),
            )
            .expect("insert");
            ApprovalRepository::update_state(
                &uow,
                "app-001",
                "pending",
                "approved",
                Some("S-1-5-21-2"),
                Some("2026-05-14T00:00:00Z"),
                Some("2026-05-15T00:00:00Z"),
                None,
                "2026-05-14T01:00:00Z",
            )
            .expect("grant");
            uow.commit().expect("commit");
        }

        // Revoke: approved -> revoked (must pass "approved" as expected_current_status)
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            let affected = ApprovalRepository::update_state(
                &uow,
                "app-001",
                "approved", // expected current status
                "revoked",  // new status
                None,
                None,
                None,
                None,
                "2026-05-14T02:00:00Z",
            )
            .expect("revoke");
            assert_eq!(affected, 1, "revoke must succeed");
            uow.commit().expect("commit");
        }

        let row = ApprovalRepository::get_by_id(&pool, "app-001").expect("get by id");
        assert_eq!(row.status, "revoked");
    }
}
