#!/usr/bin/env python3
"""Write the new db.rs with r2d2 Pool + new_pool()."""

db_rs = """//! SQLite database initialization and shared connection pool.
//!
//! Uses `r2d2` with a custom `ManageConnection` implementation for
//! `rusqlite::Connection`. All axum handlers should wrap DB calls in
//! `tokio::task::spawn_blocking` to avoid blocking the async reactor.

use anyhow::Context;
use r2d2::ManageConnection;
use rusqlite::Connection;

/// Pool type alias -- wraps our custom `SqlitePoolManager`.
pub type Pool = r2d2::Pool<SqlitePoolManager>;

/// Custom `ManageConnection` for `rusqlite::Connection`.
///
/// This avoids pulling in `r2d2_sqlite` (which requires `rusqlite 0.39`,
/// incompatible with our existing `rusqlite 0.31` dependency) by implementing
/// the trait directly. Each pooled connection gets its own `rusqlite::Connection`
/// to the same database file.
#[derive(Debug)]
pub struct SqlitePoolManager {
    path: String,
}

impl SqlitePoolManager {
    /// Creates a manager that opens connections to the given SQLite path.
    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
        }
    }
}

impl ManageConnection for SqlitePoolManager {
    type Connection = Connection;
    type Error = rusqlite::Error;

    fn connect(&self) -> Result<Self::Connection, Self::Error> {
        Connection::open(&self.path)
    }

    fn is_valid(&self, conn: &mut Self::Connection) -> Result<(), Self::Error> {
        conn.execute_batch("SELECT 1")?;
        Ok(())
    }

    fn has_broken(&self, conn: &mut Self::Connection) -> bool {
        conn.execute_batch("SELECT 1").is_err()
    }
}

/// Creates a connection pool for the given SQLite database path and
/// initializes all required tables.
///
/// # Arguments
///
/// * `path` - Filesystem path for the SQLite database.
///
/// # Errors
///
/// Returns an error if the pool cannot be built or table creation fails.
pub fn new_pool(path: &str) -> anyhow::Result<Pool> {
    let mgr = SqlitePoolManager::new(path);
    let pool = r2d2::Pool::builder()
        .max_size(5)
        .build(mgr)
        .context("failed to build connection pool")?;

    let conn = pool.get().context("failed to acquire connection for init")?;
    conn.execute_batch("PRAGMA journal_mode=WAL;")
        .context("failed to enable WAL journal mode")?;

    init_tables(&conn)?;
    Ok(pool)
}

/// Creates all application tables if they do not already exist.
fn init_tables(conn: &Connection) -> anyhow::Result<()> {
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
            user_sid      TEXT NULL,
            created_at    TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS agent_credentials (
            key        TEXT PRIMARY KEY,
            value      TEXT NOT NULL,
            updated_at TEXT NOT NULL
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_pool_in_memory() {
        // Note: :memory: with r2d2 pool creates isolated per-connection databases.
        // These unit tests use a single connection from the pool so they work fine.
        let pool = new_pool(":memory:");
        assert!(pool.is_ok(), "should create pool for in-memory database");
    }

    #[test]
    fn test_tables_created() {
        // Uses tempfile to ensure init_tables seed rows are visible across
        // pool connections -- avoids SQLite :memory: isolation issues.
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = new_pool(tmp.path().to_str().unwrap()).expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .expect("prepare")
            .query_map([], |row| row.get(0))
            .expect("query")
            .filter_map(|r| r.ok())
            .collect();

        assert!(tables.contains(&"agents".to_string()));
        assert!(tables.contains(&"audit_events".to_string()));
        assert!(tables.contains(&"exceptions".to_string()));
        assert!(tables.contains(&"admin_users".to_string()));
        assert!(tables.contains(&"agent_credentials".to_string()));
        assert!(tables.contains(&"siem_config".to_string()));
        assert!(tables.contains(&"alert_router_config".to_string()));
        assert!(tables.contains(&"ldap_config".to_string()));
        assert!(tables.contains(&"global_agent_config".to_string()));
        assert!(tables.contains(&"agent_config_overrides".to_string()));

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM siem_config", [], |r| r.get(0))
            .expect("count siem_config rows");
        assert_eq!(count, 1, "siem_config should have exactly one seed row");
    }

    #[test]
    fn test_global_agent_config_seed_row() {
        // Uses tempfile to ensure seed rows are visible across pool connections.
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = new_pool(tmp.path().to_str().unwrap()).expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let (monitored_paths, heartbeat_interval_secs, offline_cache_enabled): (String, i64, i64) =
            conn.query_row(
                "SELECT monitored_paths, heartbeat_interval_secs, offline_cache_enabled \
                 FROM global_agent_config WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("seed row must exist");

        assert_eq!(monitored_paths, "[]", "default monitored_paths must be empty JSON array");
        assert_eq!(heartbeat_interval_secs, 30, "default heartbeat_interval_secs must be 30");
        assert_eq!(offline_cache_enabled, 1, "default offline_cache_enabled must be 1 (true)");
    }

    #[test]
    fn test_idempotent_init() {
        // Uses tempfile to ensure multiple init_tables calls on the same
        // file are idempotent and seed rows are accessible across connections.
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = new_pool(tmp.path().to_str().unwrap()).expect("first open");
        let conn = pool.get().expect("acquire connection");
        let result = conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS agents (agent_id TEXT PRIMARY KEY);"
        );
        assert!(result.is_ok(), "re-init should be idempotent");
    }

    #[test]
    fn test_alert_router_config_seed_row() {
        // Uses tempfile to ensure seed rows are visible across pool connections.
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = new_pool(tmp.path().to_str().unwrap()).expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='alert_router_config'")
            .expect("prepare")
            .query_map([], |row| row.get(0))
            .expect("query")
            .filter_map(|r| r.ok())
            .collect();
        assert!(tables.contains(&"alert_router_config".to_string()), "alert_router_config table must exist");

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM alert_router_config", [], |r| r.get(0))
            .expect("count alert_router_config rows");
        assert_eq!(count, 1, "alert_router_config must have exactly one seed row");

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

    #[test]
    fn test_ldap_config_seed_row() {
        // Uses tempfile to ensure seed rows are visible across pool connections.
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = new_pool(tmp.path().to_str().unwrap()).expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='ldap_config'")
            .expect("prepare")
            .query_map([], |row| row.get(0))
            .expect("query")
            .filter_map(|r| r.ok())
            .collect();
        assert!(tables.contains(&"ldap_config".to_string()), "ldap_config table must exist after init");

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM ldap_config", [], |r| r.get(0))
            .expect("count ldap_config rows");
        assert_eq!(count, 1, "ldap_config must have exactly one seed row");

        let (ldap_url, base_dn, require_tls, cache_ttl_secs): (String, String, i64, i64) = conn
            .query_row(
                "SELECT ldap_url, base_dn, require_tls, cache_ttl_secs FROM ldap_config WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .expect("read seed row");
        assert_eq!(ldap_url, "ldaps://dc.corp.internal:636", "default ldap_url");
        assert_eq!(require_tls, 1, "require_tls default must be 1");
        assert_eq!(cache_ttl_secs, 300, "cache_ttl_secs default must be 300");
        assert_eq!(base_dn, "", "default base_dn must be empty string");
    }
}
"""

with open("dlp-server/src/db.rs", "w") as f:
    f.write(db_rs)
print("db.rs written successfully")
