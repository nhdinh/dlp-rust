//! Repository for the `managed_origins` table.
//!
//! Encapsulates SQL for managed web origin CRUD. Managed origins are URL-pattern
//! strings (e.g. `"https://company.sharepoint.com/*"`) used by the Chrome
//! Enterprise Connector (Phase 29) and surfaced in the admin TUI (Phase 28).

use rusqlite::params;

use crate::db::{Pool, UnitOfWork};

/// Plain data row returned by managed origins reads.
#[derive(Debug, Clone)]
pub struct ManagedOriginRow {
    /// Server-generated UUID string (primary key).
    pub id: String,
    /// URL pattern string, e.g. `"https://company.sharepoint.com/*"`.
    pub origin: String,
}

/// Stateless repository for the `managed_origins` table.
///
/// All methods are associated functions (no `&self`) — the repository holds
/// no state. Connection pooling is handled by the caller via `Pool` for reads
/// and `UnitOfWork` for writes.
pub struct ManagedOriginsRepository;

impl ManagedOriginsRepository {
    /// Returns all managed origin entries ordered by `rowid` ascending.
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if pool acquisition or query execution fails.
    pub fn list_all(pool: &Pool) -> rusqlite::Result<Vec<ManagedOriginRow>> {
        // Pool::get() returns an r2d2 error type; we must bridge it into
        // rusqlite::Error since this function's return type is rusqlite::Result.
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        let mut stmt = conn.prepare("SELECT id, origin FROM managed_origins ORDER BY rowid ASC")?;
        let rows = stmt.query_map([], |row| {
            Ok(ManagedOriginRow {
                id: row.get(0)?,
                origin: row.get(1)?,
            })
        })?;
        rows.collect()
    }

    /// Inserts a new managed origin row.
    ///
    /// Returns `rusqlite::Error` on UNIQUE constraint violation (duplicate
    /// origin string). The caller is responsible for generating a UUID `id`.
    ///
    /// # Arguments
    ///
    /// * `uow` - Active unit of work to execute the write within.
    /// * `row` - Managed origin data to insert.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the INSERT fails, including UNIQUE constraint
    /// violations when the same `origin` string already exists.
    pub fn insert(uow: &UnitOfWork<'_>, row: &ManagedOriginRow) -> rusqlite::Result<()> {
        uow.tx.execute(
            "INSERT INTO managed_origins (id, origin) VALUES (?1, ?2)",
            params![row.id, row.origin],
        )?;
        Ok(())
    }

    /// Deletes the managed origin entry with the given `id`.
    ///
    /// # Arguments
    ///
    /// * `uow` - Active unit of work to execute the write within.
    /// * `id` - UUID string of the entry to delete.
    ///
    /// # Returns
    ///
    /// Returns the number of rows deleted (0 if `id` did not exist — not an error).
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the DELETE statement itself fails.
    pub fn delete_by_id(uow: &UnitOfWork<'_>, id: &str) -> rusqlite::Result<usize> {
        uow.tx
            .execute("DELETE FROM managed_origins WHERE id = ?1", params![id])
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

    /// Helper: construct a test row with given id and origin.
    fn make_row(id: &str, origin: &str) -> ManagedOriginRow {
        ManagedOriginRow {
            id: id.to_string(),
            origin: origin.to_string(),
        }
    }

    #[test]
    fn test_list_all_empty() {
        let pool = make_pool();
        let rows = ManagedOriginsRepository::list_all(&pool).expect("list_all on empty DB");
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
            let uow = UnitOfWork::new(&mut *conn).expect("begin transaction");
            let row = make_row("uuid-1", "https://example.com/*");
            ManagedOriginsRepository::insert(&uow, &row).expect("insert");
            uow.commit().expect("commit");
        }
        let rows = ManagedOriginsRepository::list_all(&pool).expect("list_all");
        assert_eq!(rows.len(), 1, "expected 1 row after insert");
        assert_eq!(rows[0].id, "uuid-1");
        assert_eq!(rows[0].origin, "https://example.com/*");
    }

    #[test]
    fn test_delete_removes_row() {
        let pool = make_pool();
        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut *conn).expect("begin transaction");
            ManagedOriginsRepository::insert(&uow, &make_row("uuid-1", "https://a.com/*"))
                .expect("insert");
            uow.commit().expect("commit");
        }
        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut *conn).expect("begin transaction");
            let affected =
                ManagedOriginsRepository::delete_by_id(&uow, "uuid-1").expect("delete_by_id");
            uow.commit().expect("commit");
            assert_eq!(affected, 1, "expected 1 row deleted");
        }
        let rows = ManagedOriginsRepository::list_all(&pool).expect("list_all after delete");
        assert!(rows.is_empty(), "expected empty vec after delete");
    }

    #[test]
    fn test_duplicate_origin_errors() {
        let pool = make_pool();
        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut *conn).expect("begin transaction");
            ManagedOriginsRepository::insert(&uow, &make_row("uuid-1", "https://dup.com/*"))
                .expect("first insert");
            uow.commit().expect("commit");
        }
        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut *conn).expect("begin transaction");
            let result =
                ManagedOriginsRepository::insert(&uow, &make_row("uuid-2", "https://dup.com/*"));
            assert!(result.is_err(), "duplicate origin must return an error");
        }
    }
}
