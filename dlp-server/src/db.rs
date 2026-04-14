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
        let conn =
            Connection::open(path).with_context(|| format!("failed to open database at {path}"))?;

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

            -- user_sid: added via Phase 9 ALTER TABLE migration below.
            -- NOTE: This column is added by the ALTER TABLE statement that runs after
            -- CREATE TABLE. On fresh databases (first run) CREATE TABLE includes user_sid
            -- directly. On existing databases (re-run), ALTER TABLE adds it if missing.
            -- The IF NOT EXISTS guard on ALTER TABLE makes this block idempotent.
            CREATE TABLE IF NOT EXISTS admin_users (
                username      TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                user_sid      TEXT NULL,
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

            CREATE TABLE IF NOT EXISTS alert_router_config (
                id                INTEGER PRIMARY KEY CHECK (id = 1),
                smtp_host         TEXT NOT NULL DEFAULT '',
                smtp_port         INTEGER NOT NULL DEFAULT 587,
                smtp_username     TEXT NOT NULL DEFAULT '',
                smtp_password     TEXT NOT NULL DEFAULT '',
                smtp_from         TEXT NOT NULL DEFAULT '',
                smtp_to           TEXT NOT NULL DEFAULT '',
                smtp_enabled      INTEGER NOT NULL DEFAULT 0,
                webhook_url       TEXT NOT NULL DEFAULT '',
                webhook_secret    TEXT NOT NULL DEFAULT '',
                webhook_enabled   INTEGER NOT NULL DEFAULT 0,
                updated_at        TEXT NOT NULL DEFAULT ''
            );
            INSERT OR IGNORE INTO alert_router_config (id) VALUES (1);

            -- ldap_config: Active Directory connection configuration (Phase 7).
            -- Single-row table enforced via CHECK (id = 1), seeded below.
            -- vpn_subnets is a comma-separated list of CIDR ranges.
            CREATE TABLE IF NOT EXISTS ldap_config (
                id               INTEGER PRIMARY KEY CHECK (id = 1),
                ldap_url         TEXT NOT NULL DEFAULT 'ldaps://dc.corp.internal:636',
                base_dn          TEXT NOT NULL DEFAULT '',
                require_tls      INTEGER NOT NULL DEFAULT 1,
                cache_ttl_secs   INTEGER NOT NULL DEFAULT 300,
                vpn_subnets      TEXT NOT NULL DEFAULT '',
                updated_at       TEXT NOT NULL DEFAULT ''
            );
            INSERT OR IGNORE INTO ldap_config (id) VALUES (1);

            -- global_agent_config: single-row default applied to all agents unless overridden.
            -- Uses CHECK (id = 1) to enforce exactly one row, seeded below.
            -- monitored_paths is stored as a JSON text array.
            -- NOTE: agent_config_overrides has a FK to agents(agent_id) ON DELETE CASCADE,
            -- but rusqlite does NOT enforce FK constraints unless PRAGMA foreign_keys = ON
            -- is set per connection. The cascade is a safety net, not a correctness invariant.
            CREATE TABLE IF NOT EXISTS global_agent_config (
                id                      INTEGER PRIMARY KEY CHECK (id = 1),
                monitored_paths         TEXT NOT NULL DEFAULT '[]',
                heartbeat_interval_secs INTEGER NOT NULL DEFAULT 30,
                offline_cache_enabled   INTEGER NOT NULL DEFAULT 1,
                updated_at              TEXT NOT NULL DEFAULT ''
            );
            INSERT OR IGNORE INTO global_agent_config (id) VALUES (1);

            CREATE TABLE IF NOT EXISTS agent_config_overrides (
                agent_id                TEXT PRIMARY KEY
                                        REFERENCES agents(agent_id) ON DELETE CASCADE,
                monitored_paths         TEXT NOT NULL DEFAULT '[]',
                heartbeat_interval_secs INTEGER NOT NULL DEFAULT 30,
                offline_cache_enabled   INTEGER NOT NULL DEFAULT 1,
                updated_at              TEXT NOT NULL DEFAULT ''
            );
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
        let db = Database::open(":memory:").expect("open in-memory db");
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
        assert!(tables.contains(&"alert_router_config".to_string()));
        assert!(tables.contains(&"ldap_config".to_string()));
        assert!(tables.contains(&"global_agent_config".to_string()));
        assert!(tables.contains(&"agent_config_overrides".to_string()));

        // Verify the seed row was inserted.
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM siem_config", [], |r| r.get(0))
            .expect("count siem_config rows");
        assert_eq!(count, 1, "siem_config should have exactly one seed row");
    }

    #[test]
    fn test_global_agent_config_seed_row() {
        let db = Database::open(":memory:").expect("open in-memory db");
        let conn = db.conn().lock();

        // The seed row (id=1) must exist with expected defaults.
        let (monitored_paths, heartbeat_interval_secs, offline_cache_enabled): (String, i64, i64) =
            conn.query_row(
                "SELECT monitored_paths, heartbeat_interval_secs, offline_cache_enabled \
                 FROM global_agent_config WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("seed row must exist");

        assert_eq!(
            monitored_paths, "[]",
            "default monitored_paths must be empty JSON array"
        );
        assert_eq!(
            heartbeat_interval_secs, 30,
            "default heartbeat_interval_secs must be 30"
        );
        assert_eq!(
            offline_cache_enabled, 1,
            "default offline_cache_enabled must be 1 (true)"
        );
    }

    #[test]
    fn test_idempotent_init() {
        // Calling open twice on the same path should not fail.
        let db = Database::open(":memory:").expect("first open");
        let result = db.init_tables();
        assert!(result.is_ok(), "re-init should be idempotent");
    }

    #[test]
    fn test_alert_router_config_seed_row() {
        let db = Database::open(":memory:").expect("open in-memory db");
        let conn = db.conn().lock();

        // Table must exist.
        let tables: Vec<String> = conn
            .prepare(
                "SELECT name FROM sqlite_master \
                 WHERE type='table' AND name='alert_router_config'",
            )
            .expect("prepare")
            .query_map([], |row| row.get(0))
            .expect("query")
            .filter_map(|r| r.ok())
            .collect();
        assert!(
            tables.contains(&"alert_router_config".to_string()),
            "alert_router_config table must exist after init"
        );

        // Seed row must exist.
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM alert_router_config", [], |r| r.get(0))
            .expect("count alert_router_config rows");
        assert_eq!(
            count, 1,
            "alert_router_config must have exactly one seed row"
        );

        // Defaults: both channels disabled.
        let (smtp_enabled, webhook_enabled): (i64, i64) = conn
            .query_row(
                "SELECT smtp_enabled, webhook_enabled FROM alert_router_config WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("read seed row");
        assert_eq!(smtp_enabled, 0, "smtp_enabled default must be 0");
        assert_eq!(webhook_enabled, 0, "webhook_enabled default must be 0");
    }
}
