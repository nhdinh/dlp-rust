//! SQLite database initialization and shared connection pool.
//!
//! Uses `parking_lot::Mutex` for synchronous access to a single
//! `rusqlite::Connection`. All axum handlers should wrap DB calls in
//! `tokio::task::spawn_blocking` to avoid blocking the async reactor.

use anyhow::Context;
use parking_lot::Mutex;
use rusqlite::Connection;

/// Thread-safe wrapper around a single SQLite connection.
///
/// The mutex ensures only one thread accesses the connection at a time.
/// For higher concurrency, consider migrating to `r2d2` or `deadpool`
/// with a connection pool.
#[derive(Debug)]
pub struct Database {
    /// Guarded connection — acquire via `self.conn.lock()`.
    conn: Mutex<Connection>,
}

impl Database {
    /// Opens (or creates) a SQLite database at the given path and
    /// initializes all required tables.
    ///
    /// # Arguments
    ///
    /// * `path` - Filesystem path to the SQLite database file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened or table
    /// creation fails.
    pub fn open(path: &str) -> anyhow::Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("failed to open database at {path}"))?;

        // Enable WAL mode for better concurrent read performance.
        conn.execute_batch("PRAGMA journal_mode=WAL;")
            .context("failed to enable WAL journal mode")?;

        let db = Self {
            conn: Mutex::new(conn),
        };
        db.init_tables()?;
        Ok(db)
    }

    /// Returns a reference to the mutex-guarded connection.
    ///
    /// Callers should hold the lock for as short a duration as possible.
    pub fn conn(&self) -> &Mutex<Connection> {
        &self.conn
    }

    /// Creates all application tables if they do not already exist.
    ///
    /// # Errors
    ///
    /// Returns an error if any `CREATE TABLE` statement fails.
    fn init_tables(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS agents (
                agent_id       TEXT PRIMARY KEY,
                hostname       TEXT NOT NULL,
                ip             TEXT NOT NULL,
                os_version     TEXT NOT NULL,
                agent_version  TEXT NOT NULL,
                last_heartbeat TEXT NOT NULL,
                status         TEXT NOT NULL DEFAULT 'online',
                registered_at  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_events (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp        TEXT NOT NULL,
                event_type       TEXT NOT NULL,
                user_sid         TEXT NOT NULL,
                user_name        TEXT NOT NULL,
                resource_path    TEXT NOT NULL,
                classification   TEXT NOT NULL,
                action_attempted TEXT NOT NULL,
                decision         TEXT NOT NULL,
                policy_id        TEXT,
                policy_name      TEXT,
                agent_id         TEXT NOT NULL,
                session_id       INTEGER NOT NULL,
                access_context   TEXT NOT NULL DEFAULT 'local',
                correlation_id   TEXT UNIQUE
            );

            CREATE TABLE IF NOT EXISTS policies (
                id          TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                description TEXT,
                priority    INTEGER NOT NULL,
                conditions  TEXT NOT NULL,
                action      TEXT NOT NULL,
                enabled     INTEGER NOT NULL DEFAULT 1,
                version     INTEGER NOT NULL DEFAULT 1,
                updated_at  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS exceptions (
                id               TEXT PRIMARY KEY,
                policy_id        TEXT NOT NULL,
                user_sid         TEXT NOT NULL,
                approver         TEXT NOT NULL,
                justification    TEXT NOT NULL,
                duration_seconds INTEGER NOT NULL,
                granted_at       TEXT NOT NULL,
                expires_at       TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS admin_users (
                username      TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                created_at    TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS agent_credentials (
                key        TEXT PRIMARY KEY,
                value      TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS siem_config (
                id              INTEGER PRIMARY KEY CHECK (id = 1),
                splunk_url      TEXT NOT NULL DEFAULT '',
                splunk_token    TEXT NOT NULL DEFAULT '',
                splunk_enabled  INTEGER NOT NULL DEFAULT 0,
                elk_url         TEXT NOT NULL DEFAULT '',
                elk_index       TEXT NOT NULL DEFAULT '',
                elk_api_key     TEXT NOT NULL DEFAULT '',
                elk_enabled     INTEGER NOT NULL DEFAULT 0,
                updated_at      TEXT NOT NULL DEFAULT ''
            );
            INSERT OR IGNORE INTO siem_config (id) VALUES (1);
            ",
        )
        .context("failed to initialize database tables")?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_in_memory() {
        // `:memory:` creates a transient in-memory database.
        let db = Database::open(":memory:");
        assert!(db.is_ok(), "should open in-memory database");
    }

    #[test]
    fn test_tables_created() {
        let db = Database::open(":memory:")
            .expect("open in-memory db");
        let conn = db.conn().lock();

        // Query sqlite_master for our expected tables.
        let tables: Vec<String> = conn
            .prepare(
                "SELECT name FROM sqlite_master \
                 WHERE type='table' ORDER BY name",
            )
            .expect("prepare")
            .query_map([], |row| row.get(0))
            .expect("query")
            .filter_map(|r| r.ok())
            .collect();

        assert!(tables.contains(&"agents".to_string()));
        assert!(tables.contains(&"audit_events".to_string()));
        assert!(tables.contains(&"policies".to_string()));
        assert!(tables.contains(&"exceptions".to_string()));
        assert!(tables.contains(&"admin_users".to_string()));
        assert!(tables.contains(&"agent_credentials".to_string()));
        assert!(tables.contains(&"siem_config".to_string()));

        // Verify the seed row was inserted.
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM siem_config", [], |r| r.get(0))
            .expect("count siem_config rows");
        assert_eq!(count, 1, "siem_config should have exactly one seed row");
    }

    #[test]
    fn test_idempotent_init() {
        // Calling open twice on the same path should not fail.
        let db = Database::open(":memory:")
            .expect("first open");
        let result = db.init_tables();
        assert!(result.is_ok(), "re-init should be idempotent");
    }
}
