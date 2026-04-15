//! RAII transaction wrapper for SQLite write operations.
//!
//! Dropping a `UnitOfWork` without calling [`UnitOfWork::commit`] automatically
//! rolls back the transaction (rusqlite's `Transaction` does this on drop).

/// RAII transaction wrapper. All write-side repository methods accept
/// `&UnitOfWork` and execute SQL against `self.tx`.
///
/// Dropping without calling `.commit()` auto-rolls back -- this is enforced
/// by rusqlite's `Transaction::drop` implementation.
pub struct UnitOfWork<'conn> {
    /// The underlying rusqlite transaction. Repository write methods
    /// access this field directly (crate-visible).
    pub(crate) tx: rusqlite::Transaction<'conn>,
}

impl<'conn> UnitOfWork<'conn> {
    /// Begins a new transaction on the given connection.
    ///
    /// # Arguments
    ///
    /// * `conn` - Mutable reference to a `rusqlite::Connection`. Typically
    ///   obtained via `&mut *pooled_conn` where `pooled_conn` is a
    ///   `PooledConnection<SqliteConnectionManager>`.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the BEGIN TRANSACTION statement fails.
    pub fn new(conn: &'conn mut rusqlite::Connection) -> rusqlite::Result<Self> {
        let tx = conn.transaction()?;
        Ok(Self { tx })
    }

    /// Commits the transaction, consuming the `UnitOfWork`.
    ///
    /// If this method is not called, the transaction is rolled back when
    /// the `UnitOfWork` is dropped.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the COMMIT statement fails.
    pub fn commit(self) -> rusqlite::Result<()> {
        self.tx.commit()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uow_commit() {
        let mut conn = rusqlite::Connection::open_in_memory().expect("open in-memory connection");
        conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY);")
            .expect("create table");

        {
            let uow = UnitOfWork::new(&mut conn).expect("begin transaction");
            uow.tx
                .execute("INSERT INTO t (id) VALUES (1)", [])
                .expect("insert");
            uow.commit().expect("commit");
        }

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))
            .expect("count");
        assert_eq!(count, 1, "committed row must persist");
    }

    #[test]
    fn test_uow_rollback_on_drop() {
        let mut conn = rusqlite::Connection::open_in_memory().expect("open in-memory connection");
        conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY);")
            .expect("create table");

        {
            let uow = UnitOfWork::new(&mut conn).expect("begin transaction");
            uow.tx
                .execute("INSERT INTO t (id) VALUES (1)", [])
                .expect("insert");
            // uow is dropped here without commit -- should rollback
        }

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))
            .expect("count");
        assert_eq!(count, 0, "uncommitted row must be rolled back");
    }
}
