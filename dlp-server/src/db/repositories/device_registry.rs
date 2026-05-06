//! Repository for the `device_registry` table.
//!
//! Encapsulates all SQL for device registry CRUD operations. The upsert method
//! uses SQLite's `ON CONFLICT DO UPDATE` (available since SQLite 3.24) to update
//! `trust_tier` and `description` when a device with the same `(vid, pid, serial)`
//! already exists, preserving the original UUID primary key.

use rusqlite::params;

use crate::db::{Pool, UnitOfWork};

/// Plain data row returned by device registry reads.
#[derive(Debug, Clone)]
pub struct DeviceRegistryRow {
    /// Server-generated UUID string (primary key).
    pub id: String,
    /// USB Vendor ID hex string, e.g. "0951".
    pub vid: String,
    /// USB Product ID hex string, e.g. "1666".
    pub pid: String,
    /// Device serial number, or "(none)" for devices without one.
    pub serial: String,
    /// Windows Security Identifier of the owning user. NULL means machine-wide entry.
    pub owner_sid: Option<String>,
    /// Human-readable username for display. NULL means machine-wide entry.
    pub owner_user: Option<String>,
    /// Human-readable device description from USB descriptor. Empty string if unknown.
    pub description: String,
    /// Trust tier: "blocked", "read_only", or "full_access".
    pub trust_tier: String,
    /// ISO-8601 timestamp of when this entry was created.
    pub created_at: String,
}

/// Stateless repository for the `device_registry` table.
///
/// All methods are associated functions (no `&self`) — the repository holds
/// no state. Connection pooling is handled by the caller via `Pool` for reads
/// and `UnitOfWork` for writes.
pub struct DeviceRegistryRepository;

impl DeviceRegistryRepository {
    /// Returns all device registry entries ordered by `created_at` ascending.
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if pool acquisition or query execution fails.
    pub fn list_all(pool: &Pool) -> rusqlite::Result<Vec<DeviceRegistryRow>> {
        Self::list_all_filtered(pool, None)
    }

    /// Returns device registry entries with an optional owner_sid filter.
    ///
    /// When `owner_sid_filter` is `Some(sid)`: returns entries where
    /// `owner_sid = sid` OR `owner_sid IS NULL` (per-user + machine-wide).
    /// When `None`: returns all entries (same as `list_all`).
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    /// * `owner_sid_filter` - Optional Windows SID to filter by.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if pool acquisition or query execution fails.
    pub fn list_all_filtered(
        pool: &Pool,
        owner_sid_filter: Option<&str>,
    ) -> rusqlite::Result<Vec<DeviceRegistryRow>> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

        let mut stmt = conn.prepare(
            "SELECT id, vid, pid, serial, owner_sid, owner_user, description, trust_tier, created_at \
             FROM device_registry \
             WHERE (?1 IS NULL OR owner_sid = ?1 OR owner_sid IS NULL) \
             ORDER BY created_at ASC",
        )?;

        let rows = stmt.query_map(params![owner_sid_filter], |row| {
            Ok(DeviceRegistryRow {
                id: row.get(0)?,
                vid: row.get(1)?,
                pid: row.get(2)?,
                serial: row.get(3)?,
                owner_sid: row.get(4)?,
                owner_user: row.get(5)?,
                description: row.get(6)?,
                trust_tier: row.get(7)?,
                created_at: row.get(8)?,
            })
        })?;
        rows.collect()
    }

    /// Inserts a new device registry entry, or updates `trust_tier` and
    /// `description` if a row with the same `(vid, pid, serial)` already exists.
    ///
    /// The original UUID primary key is preserved on conflict — this is why
    /// `ON CONFLICT DO UPDATE` is used instead of `INSERT OR REPLACE`, which
    /// would delete-and-reinsert the row (changing the `id`).
    ///
    /// # Arguments
    ///
    /// * `uow` - Active unit of work to execute the write within.
    /// * `row` - Device registry data to insert or update.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the statement fails (e.g., invalid `trust_tier`
    /// rejected by the DB CHECK constraint).
    pub fn upsert(uow: &UnitOfWork<'_>, row: &DeviceRegistryRow) -> rusqlite::Result<()> {
        uow.tx.execute(
            "INSERT INTO device_registry \
                 (id, vid, pid, serial, owner_sid, owner_user, description, trust_tier, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) \
             ON CONFLICT(vid, pid, serial, COALESCE(owner_sid, '')) DO UPDATE SET \
                 trust_tier  = excluded.trust_tier, \
                 description = excluded.description, \
                 owner_user  = excluded.owner_user",
            params![
                row.id,
                row.vid,
                row.pid,
                row.serial,
                row.owner_sid,
                row.owner_user,
                row.description,
                row.trust_tier,
                row.created_at,
            ],
        )?;
        Ok(())
    }

    /// Returns the device registry entry matching the given `(vid, pid, serial)` key.
    ///
    /// Used after an upsert to retrieve the persisted row — which may carry the
    /// original UUID when the upsert resolved a conflict rather than inserting.
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    /// * `vid` - USB Vendor ID hex string.
    /// * `pid` - USB Product ID hex string.
    /// * `serial` - Device serial number.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error::QueryReturnedNoRows` if no matching row exists.
    /// Returns the device registry entry matching the given `(vid, pid, serial, owner_sid)` key.
    ///
    /// Used after an upsert to retrieve the persisted row — which may carry the
    /// original UUID when the upsert resolved a conflict rather than inserting.
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    /// * `vid` - USB Vendor ID hex string.
    /// * `pid` - USB Product ID hex string.
    /// * `serial` - Device serial number.
    /// * `owner_sid` - Optional Windows SID for per-user entries; `None` for machine-wide.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error::QueryReturnedNoRows` if no matching row exists.
    pub fn get_by_device_key_and_owner(
        pool: &Pool,
        vid: &str,
        pid: &str,
        serial: &str,
        owner_sid: Option<&str>,
    ) -> rusqlite::Result<DeviceRegistryRow> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        conn.query_row(
            "SELECT id, vid, pid, serial, owner_sid, owner_user, description, trust_tier, created_at \
             FROM device_registry WHERE vid = ?1 AND pid = ?2 AND serial = ?3 AND owner_sid IS ?4",
            params![vid, pid, serial, owner_sid],
            |row| {
                Ok(DeviceRegistryRow {
                    id: row.get(0)?,
                    vid: row.get(1)?,
                    pid: row.get(2)?,
                    serial: row.get(3)?,
                    owner_sid: row.get(4)?,
                    owner_user: row.get(5)?,
                    description: row.get(6)?,
                    trust_tier: row.get(7)?,
                    created_at: row.get(8)?,
                })
            },
        )
    }

    /// Returns all device registry entries matching the given `(vid, pid, serial)`
    /// regardless of owner_sid. This is used by the agent for tier-based merge
    /// (D-04/D-05): it fetches both the per-user entry (if any) and the machine-wide
    /// entry (if any), then applies the most restrictive tier.
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    /// * `vid` - USB Vendor ID hex string.
    /// * `pid` - USB Product ID hex string.
    /// * `serial` - Device serial number.
    ///
    /// # Returns
    ///
    /// A `Vec` of matching rows (empty if no entries exist for this device).
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if pool acquisition or query execution fails.
    pub fn get_by_device_key_fallback(
        pool: &Pool,
        vid: &str,
        pid: &str,
        serial: &str,
    ) -> rusqlite::Result<Vec<DeviceRegistryRow>> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        let mut stmt = conn.prepare(
            "SELECT id, vid, pid, serial, owner_sid, owner_user, description, trust_tier, created_at \
             FROM device_registry WHERE vid = ?1 AND pid = ?2 AND serial = ?3",
        )?;
        let rows = stmt.query_map(params![vid, pid, serial], |row| {
            Ok(DeviceRegistryRow {
                id: row.get(0)?,
                vid: row.get(1)?,
                pid: row.get(2)?,
                serial: row.get(3)?,
                owner_sid: row.get(4)?,
                owner_user: row.get(5)?,
                description: row.get(6)?,
                trust_tier: row.get(7)?,
                created_at: row.get(8)?,
            })
        })?;
        rows.collect()
    }

    /// Deletes the device registry entry with the given `id`.
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
            .execute("DELETE FROM device_registry WHERE id = ?1", params![id])
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

    /// Helper: construct a test row with given tier and a unique serial.
    fn make_row(id: &str, vid: &str, pid: &str, serial: &str, tier: &str) -> DeviceRegistryRow {
        DeviceRegistryRow {
            id: id.to_string(),
            vid: vid.to_string(),
            pid: pid.to_string(),
            serial: serial.to_string(),
            owner_sid: None,
            owner_user: None,
            description: "Test device".to_string(),
            trust_tier: tier.to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    /// Helper: construct a test row with owner fields.
    fn make_row_with_owner(
        id: &str,
        vid: &str,
        pid: &str,
        serial: &str,
        tier: &str,
        owner_sid: Option<&str>,
        owner_user: Option<&str>,
    ) -> DeviceRegistryRow {
        DeviceRegistryRow {
            id: id.to_string(),
            vid: vid.to_string(),
            pid: pid.to_string(),
            serial: serial.to_string(),
            owner_sid: owner_sid.map(String::from),
            owner_user: owner_user.map(String::from),
            description: "Test device".to_string(),
            trust_tier: tier.to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn test_list_all_empty() {
        let pool = make_pool();
        let rows = DeviceRegistryRepository::list_all(&pool).expect("list_all on empty DB");
        assert!(
            rows.is_empty(),
            "expected empty vec from fresh DB; got {rows:?}"
        );
    }

    #[test]
    fn test_upsert_insert_and_list() {
        let pool = make_pool();

        // The write connection must be dropped (returning to pool) before list_all
        // acquires a read connection — the in-memory pool has max_size=5 but
        // rusqlite in-memory DBs are per-connection, so we use the same pool
        // and must not hold the write conn open when reading.
        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut *conn).expect("begin transaction");
            let row = make_row("uuid-1", "0951", "1666", "SN001", "blocked");
            DeviceRegistryRepository::upsert(&uow, &row).expect("upsert new row");
            uow.commit().expect("commit");
        } // conn dropped here — returns to pool

        let rows = DeviceRegistryRepository::list_all(&pool).expect("list_all");
        assert_eq!(rows.len(), 1, "expected 1 row after insert");
        let r = &rows[0];
        assert_eq!(r.id, "uuid-1");
        assert_eq!(r.vid, "0951");
        assert_eq!(r.pid, "1666");
        assert_eq!(r.serial, "SN001");
        assert_eq!(r.trust_tier, "blocked");
        assert_eq!(r.description, "Test device");
    }

    #[test]
    fn test_upsert_duplicate_updates_tier_and_description() {
        let pool = make_pool();

        // Insert the initial row.
        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut *conn).expect("begin transaction");
            let row = make_row("uuid-1", "0951", "1666", "SN001", "blocked");
            DeviceRegistryRepository::upsert(&uow, &row).expect("initial upsert");
            uow.commit().expect("commit");
        }

        // Upsert same (vid, pid, serial) with different tier and description.
        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut *conn).expect("begin transaction");
            let updated = DeviceRegistryRow {
                id: "uuid-2".to_string(), // different UUID — must NOT replace original
                vid: "0951".to_string(),
                pid: "1666".to_string(),
                serial: "SN001".to_string(),
                owner_sid: None,
                owner_user: None,
                description: "Updated description".to_string(),
                trust_tier: "full_access".to_string(),
                created_at: "2026-06-01T00:00:00Z".to_string(),
            };
            DeviceRegistryRepository::upsert(&uow, &updated).expect("conflict upsert");
            uow.commit().expect("commit");
        }

        let rows = DeviceRegistryRepository::list_all(&pool).expect("list_all");
        assert_eq!(
            rows.len(),
            1,
            "row count must stay 1 after upsert on conflict"
        );
        let r = &rows[0];
        // Original UUID must be preserved (ON CONFLICT DO UPDATE, not INSERT OR REPLACE).
        assert_eq!(
            r.id, "uuid-1",
            "original UUID must be preserved on conflict"
        );
        assert_eq!(r.trust_tier, "full_access", "trust_tier must be updated");
        assert_eq!(
            r.description, "Updated description",
            "description must be updated"
        );
    }

    #[test]
    fn test_delete_by_id_removes_row() {
        let pool = make_pool();

        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut *conn).expect("begin transaction");
            let row = make_row("uuid-1", "0951", "1666", "SN001", "read_only");
            DeviceRegistryRepository::upsert(&uow, &row).expect("upsert");
            uow.commit().expect("commit");
        }

        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut *conn).expect("begin transaction");
            let affected =
                DeviceRegistryRepository::delete_by_id(&uow, "uuid-1").expect("delete_by_id");
            uow.commit().expect("commit");
            assert_eq!(affected, 1, "expected 1 row deleted");
        }

        let rows = DeviceRegistryRepository::list_all(&pool).expect("list_all after delete");
        assert!(rows.is_empty(), "expected empty vec after delete");
    }

    #[test]
    fn test_delete_by_id_nonexistent_returns_zero() {
        let pool = make_pool();
        let mut conn = pool.get().expect("get connection");
        let uow = UnitOfWork::new(&mut *conn).expect("begin transaction");
        let affected = DeviceRegistryRepository::delete_by_id(&uow, "does-not-exist")
            .expect("delete_by_id on missing UUID must not error");
        uow.commit().expect("commit");
        assert_eq!(
            affected, 0,
            "expected 0 rows affected for non-existent UUID"
        );
    }

    #[test]
    fn test_list_all_filtered_returns_per_user_and_machine_wide() {
        let pool = make_pool();

        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut *conn).expect("begin transaction");
            let machine = make_row("uuid-mw", "0951", "1666", "SN001", "read_only");
            let alice = make_row_with_owner(
                "uuid-a", "0951", "1666", "SN001", "blocked", Some("S-1-5-21-1"), Some("alice"),
            );
            let bob = make_row_with_owner(
                "uuid-b", "0951", "1666", "SN001", "full_access", Some("S-1-5-21-2"), Some("bob"),
            );
            DeviceRegistryRepository::upsert(&uow, &machine).expect("upsert machine-wide");
            DeviceRegistryRepository::upsert(&uow, &alice).expect("upsert alice");
            DeviceRegistryRepository::upsert(&uow, &bob).expect("upsert bob");
            uow.commit().expect("commit");
        }

        // Filter for alice: should get alice's entry + machine-wide entry.
        let rows = DeviceRegistryRepository::list_all_filtered(&pool, Some("S-1-5-21-1"))
            .expect("list_all_filtered");
        assert_eq!(rows.len(), 2, "expected 2 rows: alice + machine-wide");
        let sids: Vec<Option<&str>> = rows.iter().map(|r| r.owner_sid.as_deref()).collect();
        assert!(sids.contains(&Some("S-1-5-21-1")), "alice's entry must be present");
        assert!(sids.contains(&None), "machine-wide entry must be present");

        // No filter: all 3 rows.
        let all = DeviceRegistryRepository::list_all(&pool).expect("list_all");
        assert_eq!(all.len(), 3, "expected 3 rows total");
    }

    #[test]
    fn test_get_by_device_key_and_owner_exact_match() {
        let pool = make_pool();

        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut *conn).expect("begin transaction");
            let machine = make_row("uuid-mw", "0951", "1666", "SN001", "read_only");
            let alice = make_row_with_owner(
                "uuid-a", "0951", "1666", "SN001", "blocked", Some("S-1-5-21-1"), Some("alice"),
            );
            DeviceRegistryRepository::upsert(&uow, &machine).expect("upsert machine-wide");
            DeviceRegistryRepository::upsert(&uow, &alice).expect("upsert alice");
            uow.commit().expect("commit");
        }

        // Query machine-wide (None owner_sid).
        let mw = DeviceRegistryRepository::get_by_device_key_and_owner(
            &pool, "0951", "1666", "SN001", None,
        )
        .expect("get machine-wide");
        assert_eq!(mw.owner_sid, None);
        assert_eq!(mw.trust_tier, "read_only");

        // Query alice's entry.
        let user = DeviceRegistryRepository::get_by_device_key_and_owner(
            &pool, "0951", "1666", "SN001", Some("S-1-5-21-1"),
        )
        .expect("get alice");
        assert_eq!(user.owner_sid, Some("S-1-5-21-1".to_string()));
        assert_eq!(user.trust_tier, "blocked");
    }

    #[test]
    fn test_get_by_device_key_fallback_returns_all_matches() {
        let pool = make_pool();

        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut *conn).expect("begin transaction");
            let machine = make_row("uuid-mw", "0951", "1666", "SN001", "read_only");
            let alice = make_row_with_owner(
                "uuid-a", "0951", "1666", "SN001", "blocked", Some("S-1-5-21-1"), Some("alice"),
            );
            DeviceRegistryRepository::upsert(&uow, &machine).expect("upsert machine-wide");
            DeviceRegistryRepository::upsert(&uow, &alice).expect("upsert alice");
            uow.commit().expect("commit");
        }

        let rows = DeviceRegistryRepository::get_by_device_key_fallback(
            &pool, "0951", "1666", "SN001",
        )
        .expect("fallback");
        assert_eq!(rows.len(), 2, "expected 2 rows: machine-wide + alice");

        // Unknown device returns empty vec.
        let empty = DeviceRegistryRepository::get_by_device_key_fallback(
            &pool, "9999", "9999", "NONE",
        )
        .expect("fallback empty");
        assert!(empty.is_empty(), "unknown device must return empty vec");
    }

    #[test]
    fn test_upsert_per_user_does_not_conflict_with_machine_wide() {
        let pool = make_pool();

        // Insert machine-wide entry.
        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut *conn).expect("begin transaction");
            let machine = make_row("uuid-mw", "0951", "1666", "SN001", "read_only");
            DeviceRegistryRepository::upsert(&uow, &machine).expect("upsert machine-wide");
            uow.commit().expect("commit");
        }

        // Insert per-user entry for same device — must NOT conflict.
        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut *conn).expect("begin transaction");
            let alice = make_row_with_owner(
                "uuid-a", "0951", "1666", "SN001", "blocked", Some("S-1-5-21-1"), Some("alice"),
            );
            DeviceRegistryRepository::upsert(&uow, &alice).expect("upsert alice");
            uow.commit().expect("commit");
        }

        let all = DeviceRegistryRepository::list_all(&pool).expect("list_all");
        assert_eq!(all.len(), 2, "expected 2 rows: machine-wide + per-user");
    }
}
