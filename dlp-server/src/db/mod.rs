//! SQLite database initialization and shared connection pool.
//!
//! Uses `r2d2`/`r2d2_sqlite` for multi-connection pooling. All axum
//! handlers should wrap DB calls in `tokio::task::spawn_blocking` to
//! avoid blocking the async reactor.

pub mod repositories;
pub mod unit_of_work;

pub use unit_of_work::UnitOfWork;

use anyhow::Context;
use r2d2::Pool as R2d2Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection as SqliteConn;

/// Pool type alias — wraps `SqliteConnectionManager`.
pub type Pool = R2d2Pool<SqliteConnectionManager>;

/// A checked-out connection from the pool. Automatically returns to
/// the pool when dropped.
pub type Connection = r2d2::PooledConnection<SqliteConnectionManager>;

/// Creates a connection pool for the given SQLite database path and
/// initializes all required tables.
///
/// # Arguments
///
/// * `path` - Filesystem path or `:memory:` URI for the SQLite database.
///
/// # Errors
///
/// Returns an error if the pool cannot be built or table creation fails.
pub fn new_pool(path: &str) -> anyhow::Result<Pool> {
    // Enable foreign-key enforcement on every checked-out connection.
    // SQLite does NOT enforce FK constraints unless `PRAGMA foreign_keys = ON`
    // is set per connection — the setting is not persisted at the file level.
    let mgr = SqliteConnectionManager::file(path)
        .with_init(|conn| conn.execute_batch("PRAGMA foreign_keys = ON;"));
    let pool = R2d2Pool::builder()
        .max_size(5)
        .build(mgr)
        .context("failed to build connection pool")?;

    // Initialize tables using the first connection from the pool.
    // SQLite sets WAL journal mode at the file level on first open,
    // so subsequent connections to the same file inherit that mode.
    let conn = pool
        .get()
        .context("failed to acquire connection for init")?;
    conn.execute_batch("PRAGMA journal_mode=WAL;")
        .context("failed to enable WAL journal mode")?;

    init_tables(&conn)?;
    run_migrations(&conn)?;
    Ok(pool)
}

/// Creates all application tables if they do not already exist.
///
/// # Errors
///
/// Returns an error if any `CREATE TABLE` statement fails.
fn init_tables(conn: &SqliteConn) -> anyhow::Result<()> {
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

            CREATE TABLE IF NOT EXISTS policies (
                id          TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                description TEXT,
                priority    INTEGER NOT NULL,
                conditions  TEXT NOT NULL,
                action      TEXT NOT NULL,
                enabled     INTEGER NOT NULL DEFAULT 1,
                mode        TEXT NOT NULL DEFAULT 'ALL',
                version     INTEGER NOT NULL DEFAULT 1,
                updated_at  TEXT NOT NULL
            );

            -- device_registry: USB device trust assignments managed by dlp-admin.
            -- trust_tier CHECK constraint enforces only valid tier values at the DB layer.
            -- UNIQUE(vid, pid, serial) ensures one row per physical device identity.
            CREATE TABLE IF NOT EXISTS device_registry (
                id          TEXT PRIMARY KEY,
                vid         TEXT NOT NULL,
                pid         TEXT NOT NULL,
                serial      TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                trust_tier  TEXT NOT NULL CHECK(trust_tier IN ('blocked', 'read_only', 'full_access')),
                created_at  TEXT NOT NULL,
                UNIQUE(vid, pid, serial)
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
                excluded_paths          TEXT NOT NULL DEFAULT '[]',
                heartbeat_interval_secs INTEGER NOT NULL DEFAULT 30,
                offline_cache_enabled   INTEGER NOT NULL DEFAULT 1,
                updated_at              TEXT NOT NULL DEFAULT ''
            );
            INSERT OR IGNORE INTO global_agent_config (id) VALUES (1);

            CREATE TABLE IF NOT EXISTS agent_config_overrides (
                agent_id                TEXT PRIMARY KEY
                                        REFERENCES agents(agent_id) ON DELETE CASCADE,
                monitored_paths         TEXT NOT NULL DEFAULT '[]',
                excluded_paths          TEXT NOT NULL DEFAULT '[]',
                heartbeat_interval_secs INTEGER NOT NULL DEFAULT 30,
                offline_cache_enabled   INTEGER NOT NULL DEFAULT 1,
                updated_at              TEXT NOT NULL DEFAULT ''
            );

            -- managed_origins: URL-pattern strings trusted by the Chrome Enterprise
            -- Connector (Phase 29) and managed via the admin TUI (Phase 28).
            -- UNIQUE constraint on `origin` prevents duplicate URL patterns.
            CREATE TABLE IF NOT EXISTS managed_origins (
                id     TEXT PRIMARY KEY,
                origin TEXT NOT NULL UNIQUE
            );

            -- disk_registry: server-side disk allowlist managed by dlp-admin (Phase 37, ADMIN-01).
            -- Entries are scoped per (agent_id, instance_id) pair -- a disk allowed on
            -- machine-A is NOT allowed on machine-B (physical relocation attack prevention, D-01).
            -- UNIQUE(agent_id, instance_id) enforces one allowlist entry per machine-disk pair (D-04).
            -- encryption_status CHECK constraint enforces only canonical serde names (D-11).
            -- Values match EncryptionStatus snake_case serialisation:
            --   Encrypted->encrypted, Suspended->suspended, Unencrypted->unencrypted
            -- Deployments that stored fully_encrypted/partially_encrypted must
            -- drop + recreate disk_registry before upgrading.
            CREATE TABLE IF NOT EXISTS disk_registry (
                id                 TEXT PRIMARY KEY,
                agent_id           TEXT NOT NULL,
                instance_id        TEXT NOT NULL,
                bus_type           TEXT NOT NULL,
                encryption_status  TEXT NOT NULL
                                   CHECK(encryption_status IN
                                         ('encrypted', 'suspended',
                                          'unencrypted', 'unknown')),
                model              TEXT NOT NULL DEFAULT '',
                registered_at      TEXT NOT NULL,
                UNIQUE(agent_id, instance_id)
            );
            ",
    )
    .context("failed to initialize database tables")?;

    Ok(())
}

/// Runs database migrations for existing installations.
///
/// Each migration is idempotent — safe to call on every startup. Duplicate-column
/// errors from `ALTER TABLE` are swallowed; all other errors are propagated.
pub fn run_migrations(conn: &SqliteConn) -> anyhow::Result<()> {
    run_alter(
        conn,
        "ALTER TABLE policies ADD COLUMN mode TEXT NOT NULL DEFAULT 'ALL'",
        "mode",
        "policies",
    )?;
    run_alter(
        conn,
        "ALTER TABLE global_agent_config ADD COLUMN excluded_paths TEXT NOT NULL DEFAULT '[]'",
        "excluded_paths",
        "global_agent_config",
    )?;
    run_alter(
        conn,
        "ALTER TABLE agent_config_overrides ADD COLUMN excluded_paths TEXT NOT NULL DEFAULT '[]'",
        "excluded_paths",
        "agent_config_overrides",
    )?;
    Ok(())
}

/// Executes a single `ALTER TABLE` statement, ignoring duplicate-column errors.
fn run_alter(conn: &SqliteConn, sql: &str, column: &str, table: &str) -> anyhow::Result<()> {
    match conn.execute(sql, []) {
        Ok(_) => Ok(()),
        Err(e)
            if e.to_string()
                .contains(&format!("duplicate column name: {column}")) =>
        {
            Ok(())
        }
        Err(e) => Err(e).context(format!("running migration: add {column} column to {table}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_pool_in_memory() {
        let pool = new_pool(":memory:");
        assert!(pool.is_ok(), "should create pool for in-memory database");
    }

    #[test]
    fn test_tables_created() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

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
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

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
        let pool = new_pool(":memory:").expect("first open");
        let conn = pool.get().expect("acquire connection");
        let result =
            conn.execute_batch("CREATE TABLE IF NOT EXISTS agents (agent_id TEXT PRIMARY KEY);");
        assert!(result.is_ok(), "re-init should be idempotent");
    }

    #[test]
    fn test_alert_router_config_seed_row() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

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

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM alert_router_config", [], |r| r.get(0))
            .expect("count alert_router_config rows");
        assert_eq!(
            count, 1,
            "alert_router_config must have exactly one seed row"
        );

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
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let tables: Vec<String> = conn
            .prepare(
                "SELECT name FROM sqlite_master \
                 WHERE type='table' AND name='ldap_config'",
            )
            .expect("prepare")
            .query_map([], |row| row.get(0))
            .expect("query")
            .filter_map(|r| r.ok())
            .collect();
        assert!(
            tables.contains(&"ldap_config".to_string()),
            "ldap_config table must exist after init"
        );

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM ldap_config", [], |r| r.get(0))
            .expect("count ldap_config rows");
        assert_eq!(count, 1, "ldap_config must have exactly one seed row");

        let (ldap_url, base_dn, require_tls, cache_ttl_secs): (String, String, i64, i64) = conn
            .query_row(
                "SELECT ldap_url, base_dn, require_tls, cache_ttl_secs \
                 FROM ldap_config WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .expect("read seed row");
        assert_eq!(ldap_url, "ldaps://dc.corp.internal:636", "default ldap_url");
        assert_eq!(require_tls, 1, "require_tls default must be 1");
        assert_eq!(cache_ttl_secs, 300, "cache_ttl_secs default must be 300");
        assert_eq!(base_dn, "", "default base_dn must be empty string");
    }

    #[test]
    fn test_device_registry_table_exists() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='device_registry'",
                [],
                |r| r.get(0),
            )
            .expect("query sqlite_master");
        assert_eq!(count, 1, "device_registry table must exist after init");
    }

    #[test]
    fn test_device_registry_columns() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let columns: Vec<String> = conn
            .prepare("PRAGMA table_info(device_registry)")
            .expect("prepare pragma")
            .query_map([], |row| row.get::<_, String>(1))
            .expect("query pragma")
            .filter_map(Result::ok)
            .collect();

        for col in &[
            "id",
            "vid",
            "pid",
            "serial",
            "description",
            "trust_tier",
            "created_at",
        ] {
            assert!(
                columns.contains(&col.to_string()),
                "device_registry must have column '{col}'; found {columns:?}"
            );
        }
    }

    #[test]
    fn test_device_registry_check_constraint() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        // 'bad_tier' is not in ('blocked', 'read_only', 'full_access') — must fail.
        let result = conn.execute(
            "INSERT INTO device_registry (id, vid, pid, serial, description, trust_tier, created_at) \
             VALUES ('id1', 'v', 'p', 's', '', 'bad_tier', '2026-01-01')",
            [],
        );
        assert!(
            result.is_err(),
            "invalid trust_tier must be rejected by CHECK constraint"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("CHECK constraint failed"),
            "error must mention CHECK constraint; got: {err_msg}"
        );
    }

    #[test]
    fn test_device_registry_unique_constraint() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        conn.execute(
            "INSERT INTO device_registry (id, vid, pid, serial, description, trust_tier, created_at) \
             VALUES ('id1', '0951', '1666', 'SN001', '', 'blocked', '2026-01-01')",
            [],
        )
        .expect("first insert must succeed");

        let result = conn.execute(
            "INSERT INTO device_registry (id, vid, pid, serial, description, trust_tier, created_at) \
             VALUES ('id2', '0951', '1666', 'SN001', '', 'read_only', '2026-01-02')",
            [],
        );
        assert!(
            result.is_err(),
            "duplicate (vid, pid, serial) must fail UNIQUE constraint"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("UNIQUE constraint failed"),
            "error must mention UNIQUE constraint; got: {err_msg}"
        );
    }

    #[test]
    fn test_migration_add_mode_column() {
        // Simulates the v0.4.0 → v0.5.0 upgrade path: an existing DB without
        // the `mode` column gets it added by `run_migrations` (called inside
        // `new_pool`), and pre-existing rows pick up the SQL DEFAULT 'ALL'.
        // Idempotency: re-running run_migrations is a no-op.
        let tmp = tempfile::NamedTempFile::new().expect("create temp db file");
        let path = tmp.path().to_str().expect("temp path utf8");

        // Step 1: stand up the v0.4.0 schema directly (no `mode` column) and
        // seed one row.
        {
            let conn = rusqlite::Connection::open(path).expect("open temp db");
            conn.execute_batch(
                "CREATE TABLE policies (
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
                INSERT INTO policies
                    (id, name, priority, conditions, action, enabled, version, updated_at)
                VALUES
                    ('existing-policy', 'existing', 1, '[]', 'Allow', 1, 1, '2026-01-01T00:00:00Z');",
            )
            .expect("create v0.4.0 schema");
        }

        // Step 2: open via new_pool — triggers init_tables (no-op, IF NOT EXISTS)
        // followed by run_migrations (adds the column).
        let pool = new_pool(path).expect("open pool with migrations");
        let conn = pool.get().expect("acquire connection");

        // Step 3: confirm the `mode` column now exists.
        let columns: Vec<String> = conn
            .prepare("PRAGMA table_info(policies)")
            .expect("prepare pragma")
            .query_map([], |row| row.get::<_, String>(1))
            .expect("query pragma")
            .filter_map(Result::ok)
            .collect();
        assert!(
            columns.contains(&"mode".to_string()),
            "mode column must exist after migration; saw {columns:?}"
        );

        // Step 4: pre-existing row picks up SQL DEFAULT 'ALL'.
        let mode: String = conn
            .query_row(
                "SELECT mode FROM policies WHERE id = 'existing-policy'",
                [],
                |r| r.get(0),
            )
            .expect("read mode column from pre-existing row");
        assert_eq!(mode, "ALL", "pre-existing rows must default to 'ALL' mode");

        // Step 5: idempotency — re-running migrations must not error.
        run_migrations(&conn).expect("second run must not error");

        let mode2: String = conn
            .query_row(
                "SELECT mode FROM policies WHERE id = 'existing-policy'",
                [],
                |r| r.get(0),
            )
            .expect("re-read mode column");
        assert_eq!(mode2, "ALL", "mode must persist after re-run");
    }

    #[test]
    fn test_disk_registry_table_exists() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='disk_registry'",
                [],
                |r| r.get(0),
            )
            .expect("query sqlite_master");
        assert_eq!(count, 1, "disk_registry table must exist after init");
    }

    #[test]
    fn test_disk_registry_columns() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let columns: Vec<String> = conn
            .prepare("PRAGMA table_info(disk_registry)")
            .expect("prepare pragma")
            .query_map([], |row| row.get::<_, String>(1))
            .expect("query pragma")
            .filter_map(Result::ok)
            .collect();

        for col in &["id", "agent_id", "instance_id", "bus_type", "encryption_status", "model",
                     "registered_at"] {
            assert!(
                columns.contains(&col.to_string()),
                "disk_registry must have column '{col}'; found {columns:?}"
            );
        }
    }

    #[test]
    fn test_disk_registry_check_constraint() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        // 'bad_value' is not in the allowed set — must fail the CHECK constraint.
        let result = conn.execute(
            "INSERT INTO disk_registry \
             (id, agent_id, instance_id, bus_type, encryption_status, model, registered_at) \
             VALUES ('id1', 'agent-A', 'disk-1', 'usb', 'bad_value', '', '2026-01-01T00:00:00Z')",
            [],
        );
        assert!(
            result.is_err(),
            "invalid encryption_status must be rejected by CHECK constraint"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("CHECK constraint failed"),
            "error must mention CHECK constraint; got: {err_msg}"
        );
    }

    #[test]
    fn test_disk_registry_unique_constraint() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        conn.execute(
            "INSERT INTO disk_registry \
             (id, agent_id, instance_id, bus_type, encryption_status, model, registered_at) \
             VALUES ('id1', 'agent-A', 'disk-1', 'usb', 'unencrypted', '', '2026-01-01T00:00:00Z')",
            [],
        )
        .expect("first insert must succeed");

        let result = conn.execute(
            "INSERT INTO disk_registry \
             (id, agent_id, instance_id, bus_type, encryption_status, model, registered_at) \
             VALUES ('id2', 'agent-A', 'disk-1', 'usb', 'encrypted', '', '2026-01-02T00:00:00Z')",
            [],
        );
        assert!(
            result.is_err(),
            "duplicate (agent_id, instance_id) must fail UNIQUE constraint"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("UNIQUE constraint failed"),
            "error must mention UNIQUE constraint; got: {err_msg}"
        );
    }

    #[test]
    fn test_disk_registry_accepts_all_four_statuses() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        // Each of the four allowed encryption_status values (canonical serde names) must succeed.
        for (i, status) in ["encrypted", "suspended", "unencrypted", "unknown"]
            .iter()
            .enumerate()
        {
            conn.execute(
                "INSERT INTO disk_registry \
                 (id, agent_id, instance_id, bus_type, encryption_status, model, registered_at) \
                 VALUES (?1, 'agent-A', ?2, 'usb', ?3, '', '2026-01-01T00:00:00Z')",
                rusqlite::params![
                    format!("id{i}"),
                    format!("disk-{i}"),
                    status,
                ],
            )
            .unwrap_or_else(|e| {
                panic!("INSERT with encryption_status='{status}' must succeed; got: {e}");
            });
        }

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM disk_registry", [], |r| r.get(0))
            .expect("count rows");
        assert_eq!(count, 4, "all four valid statuses must insert without error");
    }
}
