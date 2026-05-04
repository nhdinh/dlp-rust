//! Repository for the `disk_registry` table (Phase 37, ADMIN-01..03).
//!
//! Encapsulates all SQL for disk registry CRUD. Unlike `device_registry`,
//! the insert is a PURE INSERT without any conflict-update clause -- security
//! allowlists must fail loudly on duplicates (D-05). The handler in
//! `admin_api.rs` maps the rusqlite UNIQUE error to HTTP 409 Conflict.

use rusqlite::params;

use crate::db::{Pool, UnitOfWork};

/// Plain data row returned by disk registry reads.
#[derive(Debug, Clone)]
pub struct DiskRegistryRow {
    /// Server-generated UUID string (primary key).
    pub id: String,
    /// Identifier of the agent this disk allowlist entry is scoped to (D-01).
    pub agent_id: String,
    /// Device instance ID (canonical disk identity from `dlp_common::DiskIdentity`).
    pub instance_id: String,
    /// Physical bus type as the lowercase serde name of `dlp_common::BusType`.
    pub bus_type: String,
    /// One of `"fully_encrypted"`, `"partially_encrypted"`, `"unencrypted"`, `"unknown"` (D-11).
    pub encryption_status: String,
    /// Drive model string (may be empty when unknown).
    pub model: String,
    /// RFC-3339 UTC timestamp of when this entry was created.
    pub registered_at: String,
}

/// Stateless repository for the `disk_registry` table.
///
/// All methods are associated functions (no `&self`) — the repository holds
/// no state. Connection pooling is handled by the caller via `Pool` for reads
/// and `UnitOfWork` for writes.
pub struct DiskRegistryRepository;

impl DiskRegistryRepository {
    /// Returns all disk registry entries, optionally filtered by `agent_id`,
    /// ordered by `registered_at` ascending.
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    /// * `agent_id_filter` - When `Some(id)`, returns only entries whose `agent_id == id`.
    ///   When `None`, returns all fleet entries.
    ///
    /// # Returns
    ///
    /// A `Vec` of rows ordered by `registered_at ASC`.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if pool acquisition or query execution fails.
    pub fn list_all(
        pool: &Pool,
        agent_id_filter: Option<&str>,
    ) -> rusqlite::Result<Vec<DiskRegistryRow>> {
        // Pool::get() returns an r2d2 error type; bridge it into rusqlite::Error
        // because this function's return type is rusqlite::Result.
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

        match agent_id_filter {
            None => {
                let mut stmt = conn.prepare(
                    "SELECT id, agent_id, instance_id, bus_type, encryption_status, model, \
                     registered_at \
                     FROM disk_registry ORDER BY registered_at ASC",
                )?;
                let rows = stmt.query_map([], |row| {
                    Ok(DiskRegistryRow {
                        id: row.get(0)?,
                        agent_id: row.get(1)?,
                        instance_id: row.get(2)?,
                        bus_type: row.get(3)?,
                        encryption_status: row.get(4)?,
                        model: row.get(5)?,
                        registered_at: row.get(6)?,
                    })
                })?;
                rows.collect()
            }
            Some(id) => {
                let mut stmt = conn.prepare(
                    "SELECT id, agent_id, instance_id, bus_type, encryption_status, model, \
                     registered_at \
                     FROM disk_registry WHERE agent_id = ?1 ORDER BY registered_at ASC",
                )?;
                let rows = stmt.query_map(params![id], |row| {
                    Ok(DiskRegistryRow {
                        id: row.get(0)?,
                        agent_id: row.get(1)?,
                        instance_id: row.get(2)?,
                        bus_type: row.get(3)?,
                        encryption_status: row.get(4)?,
                        model: row.get(5)?,
                        registered_at: row.get(6)?,
                    })
                })?;
                rows.collect()
            }
        }
    }

    /// Returns all disk registry entries for the given `agent_id`, ordered by
    /// `registered_at` ascending.
    ///
    /// Convenience wrapper around `list_all(pool, Some(agent_id))`.
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    /// * `agent_id` - Filter to return only entries scoped to this agent.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if pool acquisition or query execution fails.
    pub fn list_by_agent(pool: &Pool, agent_id: &str) -> rusqlite::Result<Vec<DiskRegistryRow>> {
        Self::list_all(pool, Some(agent_id))
    }

    /// Inserts a new disk registry entry.
    ///
    /// This is a PURE INSERT with no conflict-update clause. If a row with the
    /// same `(agent_id, instance_id)` already exists, rusqlite returns
    /// `Err(SqliteFailure(...))` with the UNIQUE constraint error string.
    /// The calling handler must map this to HTTP 409 Conflict (D-05).
    ///
    /// # Arguments
    ///
    /// * `uow` - Active unit of work to execute the write within.
    /// * `row` - Disk registry data to insert.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the INSERT fails, including:
    /// - UNIQUE constraint violation: `(agent_id, instance_id)` already exists.
    /// - CHECK constraint violation: `encryption_status` is not one of the four
    ///   allowed values (`fully_encrypted`, `partially_encrypted`, `unencrypted`, `unknown`).
    pub fn insert(uow: &UnitOfWork<'_>, row: &DiskRegistryRow) -> rusqlite::Result<()> {
        uow.tx.execute(
            "INSERT INTO disk_registry \
                 (id, agent_id, instance_id, bus_type, encryption_status, model, registered_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                row.id,
                row.agent_id,
                row.instance_id,
                row.bus_type,
                row.encryption_status,
                row.model,
                row.registered_at,
            ],
        )?;
        Ok(())
    }

    /// Deletes the disk registry entry with the given `id`.
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
            .execute("DELETE FROM disk_registry WHERE id = ?1", params![id])
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

    /// Helper: construct a test row with given ids, status, and timestamp.
    ///
    /// Defaults: `bus_type = "usb"`, `model = "Test Model"`.
    fn make_row(
        id: &str,
        agent_id: &str,
        instance_id: &str,
        status: &str,
        registered_at: &str,
    ) -> DiskRegistryRow {
        DiskRegistryRow {
            id: id.to_string(),
            agent_id: agent_id.to_string(),
            instance_id: instance_id.to_string(),
            bus_type: "usb".to_string(),
            encryption_status: status.to_string(),
            model: "Test Model".to_string(),
            registered_at: registered_at.to_string(),
        }
    }

    #[test]
    fn test_list_all_empty() {
        let pool = make_pool();
        let rows = DiskRegistryRepository::list_all(&pool, None)
            .expect("list_all on empty DB");
        assert!(rows.is_empty(), "expected empty vec from fresh DB; got {rows:?}");
    }

    #[test]
    fn test_insert_and_list_all() {
        let pool = make_pool();
        let row = make_row("uuid-1", "agent-A", "disk-1", "unencrypted", "2026-01-01T00:00:00Z");

        // Explicit scope so the write connection is dropped before list_all acquires.
        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut *conn).expect("begin transaction");
            DiskRegistryRepository::insert(&uow, &row).expect("insert");
            uow.commit().expect("commit");
        } // conn dropped here — returns to pool

        let rows = DiskRegistryRepository::list_all(&pool, None).expect("list_all");
        assert_eq!(rows.len(), 1, "expected 1 row after insert");
        let r = &rows[0];
        assert_eq!(r.id, "uuid-1");
        assert_eq!(r.agent_id, "agent-A");
        assert_eq!(r.instance_id, "disk-1");
        assert_eq!(r.bus_type, "usb");
        assert_eq!(r.encryption_status, "unencrypted");
        assert_eq!(r.model, "Test Model");
        assert_eq!(r.registered_at, "2026-01-01T00:00:00Z");
    }

    #[test]
    fn test_list_all_orders_by_registered_at_asc() {
        let pool = make_pool();

        // Insert rows out of chronological order — list_all must return them sorted.
        let rows_to_insert = [
            make_row("uuid-1", "agent-A", "disk-1", "unencrypted", "2026-01-01T00:00:00Z"),
            make_row("uuid-2", "agent-A", "disk-2", "unencrypted", "2026-02-01T00:00:00Z"),
            make_row("uuid-3", "agent-A", "disk-3", "unencrypted", "2025-12-01T00:00:00Z"),
        ];

        for row in &rows_to_insert {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut *conn).expect("begin transaction");
            DiskRegistryRepository::insert(&uow, row).expect("insert");
            uow.commit().expect("commit");
        }

        let result = DiskRegistryRepository::list_all(&pool, None).expect("list_all");
        assert_eq!(result.len(), 3);
        // Chronological order: 2025-12, 2026-01, 2026-02.
        assert_eq!(result[0].registered_at, "2025-12-01T00:00:00Z");
        assert_eq!(result[1].registered_at, "2026-01-01T00:00:00Z");
        assert_eq!(result[2].registered_at, "2026-02-01T00:00:00Z");
    }

    #[test]
    fn test_list_all_filtered_by_agent_id() {
        let pool = make_pool();

        let rows_to_insert = [
            make_row("uuid-1", "agent-A", "disk-1", "unencrypted", "2026-01-01T00:00:00Z"),
            make_row("uuid-2", "agent-A", "disk-2", "unencrypted", "2026-01-02T00:00:00Z"),
            make_row("uuid-3", "agent-B", "disk-3", "unencrypted", "2026-01-03T00:00:00Z"),
        ];

        for row in &rows_to_insert {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut *conn).expect("begin transaction");
            DiskRegistryRepository::insert(&uow, row).expect("insert");
            uow.commit().expect("commit");
        }

        let agent_a_rows = DiskRegistryRepository::list_all(&pool, Some("agent-A"))
            .expect("list_all agent-A");
        assert_eq!(agent_a_rows.len(), 2, "agent-A must have 2 entries");
        assert!(agent_a_rows.iter().all(|r| r.agent_id == "agent-A"));

        let agent_b_rows = DiskRegistryRepository::list_all(&pool, Some("agent-B"))
            .expect("list_all agent-B");
        assert_eq!(agent_b_rows.len(), 1, "agent-B must have 1 entry");
        assert_eq!(agent_b_rows[0].agent_id, "agent-B");

        let agent_c_rows = DiskRegistryRepository::list_all(&pool, Some("agent-C"))
            .expect("list_all agent-C");
        assert_eq!(agent_c_rows.len(), 0, "agent-C must have 0 entries");
    }

    #[test]
    fn test_insert_unique_conflict_returns_err() {
        let pool = make_pool();
        let row = make_row("uuid-1", "agent-A", "disk-1", "unencrypted", "2026-01-01T00:00:00Z");

        // First insert must succeed.
        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut *conn).expect("begin transaction");
            DiskRegistryRepository::insert(&uow, &row).expect("first insert");
            uow.commit().expect("commit");
        }

        // Second insert with the same (agent_id, instance_id) must fail.
        // A new UnitOfWork is required — the first transaction must be committed
        // before the UNIQUE constraint is visible to the second transaction.
        let duplicate = make_row(
            "uuid-2",
            "agent-A",
            "disk-1",
            "fully_encrypted",
            "2026-01-02T00:00:00Z",
        );
        let result = {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut *conn).expect("begin transaction");
            DiskRegistryRepository::insert(&uow, &duplicate)
        };
        assert!(result.is_err(), "duplicate (agent_id, instance_id) must return Err");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("UNIQUE constraint failed"),
            "error must mention UNIQUE constraint; got: {err_msg}"
        );
    }

    #[test]
    fn test_insert_does_not_silently_update_on_conflict() {
        // Regression test for D-05 anti-upsert invariant.
        // The pure INSERT must NOT update the existing row on conflict.
        let pool = make_pool();
        let original = make_row(
            "uuid-1",
            "agent-A",
            "disk-1",
            "unencrypted",
            "2026-01-01T00:00:00Z",
        );

        // Insert the original row.
        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut *conn).expect("begin transaction");
            DiskRegistryRepository::insert(&uow, &original).expect("first insert");
            uow.commit().expect("commit");
        }

        // Attempt to insert again with a different encryption_status — must fail.
        let upgraded = make_row(
            "uuid-2",
            "agent-A",
            "disk-1",
            "fully_encrypted",
            "2026-01-02T00:00:00Z",
        );
        let result = {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut *conn).expect("begin transaction");
            DiskRegistryRepository::insert(&uow, &upgraded)
        };
        assert!(result.is_err(), "second insert must return Err (D-05)");

        // Verify the original row is unchanged (encryption_status must still be "unencrypted").
        let rows = DiskRegistryRepository::list_all(&pool, None).expect("list_all");
        assert_eq!(rows.len(), 1, "only the original row must exist");
        assert_eq!(
            rows[0].encryption_status, "unencrypted",
            "original encryption_status must be preserved (D-05 anti-upsert)"
        );
    }

    #[test]
    fn test_delete_by_id_removes_row() {
        let pool = make_pool();
        let row = make_row("uuid-1", "agent-A", "disk-1", "unencrypted", "2026-01-01T00:00:00Z");

        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut *conn).expect("begin transaction");
            DiskRegistryRepository::insert(&uow, &row).expect("insert");
            uow.commit().expect("commit");
        }

        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut *conn).expect("begin transaction");
            let affected = DiskRegistryRepository::delete_by_id(&uow, "uuid-1")
                .expect("delete_by_id");
            uow.commit().expect("commit");
            assert_eq!(affected, 1, "expected 1 row deleted");
        }

        let rows = DiskRegistryRepository::list_all(&pool, None)
            .expect("list_all after delete");
        assert!(rows.is_empty(), "expected empty vec after delete");
    }

    #[test]
    fn test_delete_by_id_nonexistent_returns_zero() {
        let pool = make_pool();
        let mut conn = pool.get().expect("get connection");
        let uow = UnitOfWork::new(&mut *conn).expect("begin transaction");
        let affected = DiskRegistryRepository::delete_by_id(&uow, "does-not-exist")
            .expect("delete_by_id on missing UUID must not error");
        uow.commit().expect("commit");
        assert_eq!(
            affected, 0,
            "expected 0 rows affected for non-existent UUID"
        );
    }

    #[test]
    fn test_check_constraint_via_repository() {
        // Confirm that the CHECK constraint fires when insert is called via
        // the repository (not just raw SQL), closing the proxy gap.
        let pool = make_pool();
        let bad_row = make_row(
            "uuid-1",
            "agent-A",
            "disk-1",
            "bad_value",
            "2026-01-01T00:00:00Z",
        );
        let result = {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut *conn).expect("begin transaction");
            DiskRegistryRepository::insert(&uow, &bad_row)
        };
        assert!(result.is_err(), "invalid encryption_status must return Err");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("CHECK constraint failed"),
            "error must mention CHECK constraint; got: {err_msg}"
        );
    }

    #[test]
    fn test_list_by_agent_is_alias_for_list_all_some() {
        // Confirm that list_by_agent and list_all(pool, Some(...)) return
        // the same rows in the same order.
        let pool = make_pool();
        let rows_to_insert = [
            make_row("uuid-1", "agent-A", "disk-1", "unencrypted", "2026-01-01T00:00:00Z"),
            make_row("uuid-2", "agent-A", "disk-2", "fully_encrypted", "2026-01-02T00:00:00Z"),
            make_row("uuid-3", "agent-B", "disk-3", "unencrypted", "2026-01-03T00:00:00Z"),
        ];

        for row in &rows_to_insert {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut *conn).expect("begin transaction");
            DiskRegistryRepository::insert(&uow, row).expect("insert");
            uow.commit().expect("commit");
        }

        let via_list_all = DiskRegistryRepository::list_all(&pool, Some("agent-A"))
            .expect("list_all(Some)");
        let via_list_by_agent = DiskRegistryRepository::list_by_agent(&pool, "agent-A")
            .expect("list_by_agent");

        assert_eq!(
            via_list_all.len(),
            via_list_by_agent.len(),
            "list_by_agent and list_all(Some) must return the same number of rows"
        );
        for (a, b) in via_list_all.iter().zip(via_list_by_agent.iter()) {
            assert_eq!(a.id, b.id, "row IDs must match between the two call paths");
            assert_eq!(
                a.registered_at, b.registered_at,
                "row timestamps must match between the two call paths"
            );
        }
    }
}
