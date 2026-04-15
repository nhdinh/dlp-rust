---
gsd_state_version: 1.0
wave: 1
depends_on: []
files_modified:
  - dlp-server/Cargo.toml
  - dlp-server/src/db.rs
  - dlp-server/src/lib.rs
  - dlp-server/src/main.rs
  - dlp-server/src/admin_api.rs
  - dlp-server/src/admin_auth.rs
  - dlp-server/src/agent_registry.rs
  - dlp-server/src/alert_router.rs
  - dlp-server/src/audit_store.rs
  - dlp-server/src/exception_store.rs
  - dlp-server/src/siem_connector.rs
autonomous: true
requirements: [R-10]
---

# Phase 10: SQLite Connection Pool — Implementation Plan

## Goal

Replace `parking_lot::Mutex<Connection>` in `dlp-server` with `r2d2`/`r2d2_sqlite` connection pool.
Concurrent API requests no longer serialize on a single mutex. All tests pass.

---

## Wave 1 — Foundation (can run parallel with Wave 2)

### Task 1.1 — Add r2d2 dependencies to `dlp-server/Cargo.toml`

**read_first:**
- `dlp-server/Cargo.toml` (existing dependencies block)

**acceptance_criteria:**
- `Cargo.toml` contains `r2d2 = "0.8"`
- `Cargo.toml` contains `r2d2_sqlite = "0.36"`
- Both entries are in the `[dependencies]` section alongside existing `rusqlite` entry

**action:**
In `dlp-server/Cargo.toml`, add these two entries to the `[dependencies]` section:

```toml
# Database connection pool
r2d2 = "0.8"
r2d2_sqlite = "0.36"
```

---

### Task 1.2 — Refactor `dlp-server/src/db.rs` to expose a pool

**read_first:**
- `dlp-server/src/db.rs` (current `Database` struct with `Mutex<Connection>`)
- `10-RESEARCH.md` §4.2 (type signatures for `new_pool`, `Pool`, `Connection`)
- `10-RESEARCH.md` §3.1 (`:memory:` pool caveat)

**acceptance_criteria:**
- `db.rs` defines `pub type Pool = r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>`
- `db.rs` defines `pub type Connection = r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>`
- `db.rs` exports `pub fn new_pool(path: &str) -> anyhow::Result<Pool>`
- `new_pool` calls `SqliteConnectionManager::file(path)`, builds a pool with `max_size(5)`, sets WAL PRAGMA on the first connection, then calls `init_tables`
- All existing `init_tables` SQL is preserved verbatim
- `db.rs` unit tests (4 tests) use `new_pool(":memory:")` and work with the pool

**action:**
Replace the contents of `dlp-server/src/db.rs` with the following, preserving the existing `init_tables` SQL verbatim:

```rust
//! SQLite database initialization and shared connection pool.
//!
//! Uses `r2d2`/`r2d2_sqlite` for multi-connection pooling. All axum
//! handlers should wrap DB calls in `tokio::task::spawn_blocking` to
//! avoid blocking the async reactor.

use anyhow::Context;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;

/// Pool type alias — wraps `SqliteConnectionManager`.
pub type Pool = Pool<SqliteConnectionManager>;

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
    let mgr = SqliteConnectionManager::file(path);
    let pool = Pool::builder()
        .max_size(5)
        .build(mgr)
        .context("failed to build connection pool")?;

    // Initialize tables using the first connection from the pool.
    // SQLite sets WAL journal mode at the file level on first open,
    // so subsequent connections to the same file inherit that mode.
    let conn = pool.get().context("failed to acquire connection for init")?;
    conn.execute_batch("PRAGMA journal_mode=WAL;")
        .context("failed to enable WAL journal mode")?;

    init_tables(&conn)?;
    Ok(pool)
}

/// Creates all application tables if they do not already exist.
///
/// # Errors
///
/// Returns an error if any `CREATE TABLE` statement fails.
fn init_tables(conn: &Connection) -> anyhow::Result<()> {
    conn.execute_batch(
        "..."  // ← same SQL as original init_tables, preserve verbatim
    )
    .context("failed to initialize database tables")?;

    Ok(())
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

        assert_eq!(monitored_paths, "[]", "default monitored_paths must be empty JSON array");
        assert_eq!(heartbeat_interval_secs, 30, "default heartbeat_interval_secs must be 30");
        assert_eq!(offline_cache_enabled, 1, "default offline_cache_enabled must be 1 (true)");
    }

    #[test]
    fn test_idempotent_init() {
        let pool = new_pool(":memory:").expect("first open");
        let conn = pool.get().expect("acquire connection");
        let result = conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS agents (agent_id TEXT PRIMARY KEY);"
        );
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
}
```

---

## Wave 2 — Structural Changes

### Task 2.1 — Update `AppState` in `dlp-server/src/lib.rs`

**read_first:**
- `dlp-server/src/lib.rs` (current `AppState` struct)

**acceptance_criteria:**
- `AppState` field `db: Arc<db::Database>` is replaced with `pool: db::Pool`
- `AppState` derives `Clone`
- `Debug` impl references `pool` instead of `db`
- `use crate::db::Database` import is removed (no longer needed)
- `use crate::db` (module-level) is still present

**action:**
In `dlp-server/src/lib.rs`:

1. Remove `use crate::db::Database;`
2. In the `AppState` struct, replace `pub db: Arc<db::Database>` with `pub pool: db::Pool`
3. In the `Debug` impl, replace `.field("db", &self.db)` with `.field("pool", &self.pool)`
4. Add `impl From<r2d2::PoolError> for AppError` at the end of the file:

```rust
impl From<r2d2::PoolError> for AppError {
    fn from(e: r2d2::PoolError) -> Self {
        AppError::Internal(anyhow::anyhow!("pool error: {e}"))
    }
}
```

---

### Task 2.2 — Update `main.rs` to use pool

**read_first:**
- `dlp-server/src/main.rs` (current startup sequence)

**acceptance_criteria:**
- `use dlp_server::db::Database` is replaced with `use dlp_server::db`
- `Database::open(&config.db_path)?` is replaced with `db::new_pool(&config.db_path)?`
- `ensure_admin_user(&db, ...)` call site uses `&pool`
- `load_ldap_config(&db)` call site uses `&pool`
- `SiemConnector::new(Arc::clone(&db))` is replaced with `SiemConnector::new(Arc::clone(&pool))`
- `AlertRouter::new(Arc::clone(&db))` is replaced with `AlertRouter::new(Arc::clone(&pool))`
- `AppState { db, ... }` is replaced with `AppState { pool, ... }`
- The log line reads: `info!(path = %config.db_path, "database pool opened");`

**action:**
In `dlp-server/src/main.rs`:

1. Replace `use dlp_server::db::Database;` with `use dlp_server::db;`
2. Replace `let db = Arc::new(Database::open(&config.db_path)?);` with `let pool = Arc::new(db::new_pool(&config.db_path)?);`
3. Replace `info!(path = %config.db_path, "database opened")` with `info!(path = %config.db_path, "database pool opened")`
4. Replace `ensure_admin_user(&db, ...)` with `ensure_admin_user(&pool, ...)`
5. Replace `SiemConnector::new(Arc::clone(&db))` with `SiemConnector::new(Arc::clone(&pool))`
6. Replace `AlertRouter::new(Arc::clone(&db))` with `AlertRouter::new(Arc::clone(&pool))`
7. Replace `load_ldap_config(&db)` with `load_ldap_config(&pool)`
8. Replace `AppState { db, ... }` with `AppState { pool, ... }`
9. Update the `load_ldap_config` function signature from `fn load_ldap_config(db: &Database)` to `fn load_ldap_config(pool: &db::Pool)` and update the body to use `pool.get()` instead of `db.conn().lock()`
10. Update `ensure_admin_user` call sites in `main.rs` (function takes `&db::Pool` now)

---

### Task 2.3 — Update `admin_auth.rs` function signatures and call sites

**read_first:**
- `dlp-server/src/admin_auth.rs` (current `has_admin_users`, `create_admin_user`, all call sites)

**acceptance_criteria:**
- `use crate::db::Database;` import is removed
- `has_admin_users(db: &Database)` is replaced with `has_admin_users(pool: &db::Pool)`
- `create_admin_user(db: &Database, ...)` is replaced with `create_admin_user(pool: &db::Pool, ...)`
- All 29 `conn().lock()` call sites in `admin_auth.rs` are replaced with `pool.get().map_err(AppError::from)?`
- The `&conn` passed to `audit_store::store_events_sync` is `&*conn` (derefed pooled connection)

**action:**
In `dlp-server/src/admin_auth.rs`:

1. Remove `use crate::db::Database;`
2. Update `has_admin_users(db: &Database)` → `has_admin_users(pool: &db::Pool)`. Body: `let conn = pool.get()?;` then `conn.query_row(...)`
3. Update `create_admin_user(db: &Database, ...)` → `create_admin_user(pool: &db::Pool, ...)`. Body: `let conn = pool.get()?;` then `conn.execute(...)`
4. In `login` handler: `db.conn().lock()` → `pool.get().map_err(AppError::from)?`
5. In `change_password` handler: all three `db.conn().lock()` → `pool.get().map_err(AppError::from)?`
6. In the audit event emission in `change_password`: `audit_store::store_events_sync(&conn, &[...])` → `audit_store::store_events_sync(&*conn, &[...])`

---

### Task 2.4 — Update `agent_registry.rs` call sites

**read_first:**
- `dlp-server/src/agent_registry.rs` (all `db.conn().lock()` call sites)

**acceptance_criteria:**
- All 5 `db.conn().lock()` calls in `agent_registry.rs` are replaced with `pool.get().map_err(AppError::from)?`
- `spawn_offline_sweeper(state: Arc<AppState>)` — the sweeper uses `state.pool` instead of `state.db`

**action:**
In `dlp-server/src/agent_registry.rs`:

1. In `register_agent`: `db.conn().lock()` → `pool.get().map_err(AppError::from)?`
2. In `heartbeat`: `db.conn().lock()` → `pool.get().map_err(AppError::from)?`
3. In `list_agents`: `db.conn().lock()` → `pool.get().map_err(AppError::from)?`
4. In `get_agent`: `db.conn().lock()` → `pool.get().map_err(AppError::from)?`
5. In `spawn_offline_sweeper`: `db.conn().lock()` → `pool.get().map_err(AppError::from)?`

---

### Task 2.5 — Update `exception_store.rs` call sites

**read_first:**
- `dlp-server/src/exception_store.rs` (all `db.conn().lock()` call sites)

**acceptance_criteria:**
- All 3 `db.conn().lock()` calls are replaced with `pool.get().map_err(AppError::from)?`

**action:**
In `dlp-server/src/exception_store.rs`:

1. Replace all `db.conn().lock()` with `pool.get().map_err(AppError::from)?`.
2. Replace all `Arc::clone(&state.db)` with `Arc::clone(&state.pool)`.

Note: `exception_store.rs` has no test fixtures using `:memory:` DBs — no tempfile
migration needed in this file.

---

### Task 2.6 — Update `siem_connector.rs` constructor and `load_config`

**read_first:**
- `dlp-server/src/siem_connector.rs` (current `SiemConnector::new` and `load_config`)

**acceptance_criteria:**
- `SiemConnector::new(db: Arc<Database>)` is replaced with `SiemConnector::new(pool: Arc<db::Pool>)`
- `SiemConnector` struct field `db: Arc<Database>` is replaced with `pool: Arc<db::Pool>`
- `self.db.conn().lock()` in `load_config` is replaced with `self.pool.get().map_err(SiemError::from)?`
- `impl From<r2d2::PoolError> for SiemError` is added
- `use crate::db::Database;` import is removed
- Both tests in `siem_connector.rs` use `crate::db::new_pool(":memory:")` and `Arc::clone(&pool)`

**action:**
In `dlp-server/src/siem_connector.rs`:

1. Remove `use crate::db::Database;`
2. Replace `db: Arc<Database>` field with `pool: Arc<db::Pool>` in `SiemConnector` struct
3. Replace `pub fn new(db: Arc<Database>) -> Self` with `pub fn new(pool: Arc<db::Pool>) -> Self`
4. Replace `let conn = self.db.conn().lock();` with `let conn = self.pool.get().map_err(SiemError::from)?;` in `load_config`
5. Add after the `SiemError` enum definition:

```rust
impl From<r2d2::PoolError> for SiemError {
    fn from(e: r2d2::PoolError) -> Self {
        SiemError::Database(e.into())
    }
}
```

6. **Migrate 2 test fixtures to tempfile (BLOCKER — :memory: isolation across pool connections):**

   a. `test_new_with_in_memory_db` — replace:
      ```rust
      let db = Arc::new(Database::open(":memory:").expect("open db"));
      ```
      with:
      ```rust
      let tmp = tempfile::NamedTempFile::new().expect("create temp db");
      let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
      ```

   b. `test_relay_events_empty_is_noop` — replace:
      ```rust
      let db = Arc::new(Database::open(":memory:").expect("open db"));
      let connector = SiemConnector::new(db);
      ```
      with:
      ```rust
      let tmp = tempfile::NamedTempFile::new().expect("create temp db");
      let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
      let connector = SiemConnector::new(pool);
      ```

---

### Task 2.7 — Update `alert_router.rs` constructor and `load_config`

**read_first:**
- `dlp-server/src/alert_router.rs` (current `AlertRouter::new` and `load_config`)

**acceptance_criteria:**
- `AlertRouter::new(db: Arc<Database>)` is replaced with `AlertRouter::new(pool: Arc<db::Pool>)`
- `AlertRouter` struct field `db: Arc<Database>` is replaced with `pool: Arc<db::Pool>`
- `self.db.conn().lock()` in `load_config` is replaced with `self.pool.get().map_err(AlertError::from)?`
- `impl From<r2d2::PoolError> for AlertError` is added
- `use crate::db::Database;` import is removed
- All 3 test setups in `alert_router.rs` use `crate::db::new_pool(":memory:")`

**action:**
In `dlp-server/src/alert_router.rs`:

1. Remove `use crate::db::Database;`
2. Replace `db: Arc<Database>` field with `pool: Arc<db::Pool>` in `AlertRouter` struct
3. Replace `pub fn new(db: Arc<Database>) -> Self` with `pub fn new(pool: Arc<db::Pool>) -> Self`
4. Replace `let conn = self.db.conn().lock();` with `let conn = self.pool.get().map_err(AlertError::from)?;` in `load_config`
5. Add after the `AlertError` enum definition:

```rust
impl From<r2d2::PoolError> for AlertError {
    fn from(e: r2d2::PoolError) -> Self {
        AlertError::Database(e.into())
    }
}
```

6. **Migrate 3 test fixtures to tempfile (BLOCKER — :memory: isolation across pool connections):**

   a. `test_alert_router_disabled_default` — replace:
      ```rust
      let db = Arc::new(Database::open(":memory:").expect("open db"));
      let router = AlertRouter::new(Arc::clone(&db));
      ```
      with tempfile + pool construction.

   b. `test_load_config_roundtrip` — replace:
      ```rust
      let db = Arc::new(Database::open(":memory:").expect("open db"));
      { let conn = db.conn().lock(); ... }
      let router = AlertRouter::new(Arc::clone(&db));
      ```
      with tempfile + pool. The inline `conn = db.conn().lock()` block also migrates
      to `pool.get().expect("acquire connection")`.

   c. `test_load_config_port_overflow` — replace:
      ```rust
      let db = Arc::new(Database::open(":memory:").expect("open db"));
      { let conn = db.conn().lock(); ... }
      let router = AlertRouter::new(db);
      ```
      with tempfile + pool. The inline `conn = db.conn().lock()` block also migrates.

   d. `test_send_email_continues_past_bad_recipient` — replace:
      ```rust
      let db = Arc::new(Database::open(":memory:").expect("open db"));
      let router = AlertRouter::new(db);
      ```
      with tempfile + pool.

   e. `test_hot_reload` — replace:
      ```rust
      let db = Arc::new(Database::open(":memory:").expect("open db"));
      let router = AlertRouter::new(Arc::clone(&db));
      ```
      with tempfile + pool. The inline `conn = db.conn().lock()` UPDATE block also
      migrates to `pool.get().expect("acquire connection")`.

---

### Task 2.8 — Update `audit_store.rs` call sites

**read_first:**
- `dlp-server/src/audit_store.rs` (all `db.conn().lock()` call sites and the `store_events_sync` function)

**acceptance_criteria:**
- All 4 `db.conn().lock()` call sites are replaced with `pool.get().map_err(AppError::from)?`
- `store_events_sync` signature unchanged — takes `&rusqlite::Connection` and is called with `&*conn`

**action:**
In `dlp-server/src/audit_store.rs`:

1. Replace all `Arc::clone(&state.db)` with `Arc::clone(&state.pool)`.
2. In `ingest_events`: `db.conn().lock()` → `pool.get().map_err(AppError::from)?`
3. In `query_events`: `db.conn().lock()` → `pool.get().map_err(AppError::from)?`
4. In `get_event_count`: `db.conn().lock()` → `pool.get().map_err(AppError::from)?`
5. **Migrate 1 test fixture to tempfile (BLOCKER — :memory: isolation across pool connections):**

   `test_store_events_sync_admin_action` — replace:
   ```rust
   use crate::db::Database;
   let db = Database::open(":memory:").expect("open in-memory db");
   let conn = db.conn().lock();
   ```
   with:
   ```rust
   use super::db;
   let pool = db::new_pool(":memory:").expect("build pool");
   let conn = pool.get().expect("acquire connection");
   ```
   (Deref coercion makes `store_events_sync(&conn, &[event])` work unchanged.)

---

### Task 2.9 — Update `admin_api.rs` test helpers and call sites

**read_first:**
- `dlp-server/src/admin_api.rs` (all call sites; read the full file since it's the largest)

**acceptance_criteria:**
- All `state.db` references replaced with `state.pool`
- All `conn().lock()` replaced with `pool.get().map_err(AppError::from)?`
- Test setup functions use `crate::db::new_pool(":memory:")` instead of `crate::db::Database::open(...)`
- `spawn_admin_app()` test helper uses `pool` field
- `use crate::db::Database;` import removed

**action:**
In `dlp-server/src/admin_api.rs`:

1. Remove `use crate::db::Database;`
2. Replace all `Arc::clone(&state.db)` with `Arc::clone(&state.pool)`
3. Replace all `db.conn().lock()` with `pool.get().map_err(AppError::from)?`
4. Update `spawn_admin_app()` test helper:
   - Replace `let db = Arc::new(crate::db::Database::open(":memory:").expect("open db"))` with tempfile + `db::new_pool`
   - Replace `Arc::clone(&db)` with `Arc::clone(&pool)` in `SiemConnector::new` and `AlertRouter::new`
   - Replace `AppState { db, ... }` with `AppState { pool, ... }`
5. Update `seed_agent(&Database)` → `seed_agent(&db::Pool)` helper:
   - Signature: `fn seed_agent(pool: &crate::db::Pool, agent_id: &str)`
   - Body: `db.conn().lock()` → `pool.get().expect("acquire connection")`
6. Update all 19 inline AppState test builds. Each must:
   - Create a tempfile, build a pool from it via `crate::db::new_pool(tmp.path().to_str().unwrap())`
   - Replace all `Database::open(":memory:")` with the tempfile approach
   - Replace all `Arc::clone(&db)` → `Arc::clone(&pool)`
   - Replace all `AppState { db, ... }` → `AppState { pool, ... }`
   - Replace `seed_agent(&db, ...)` → `seed_agent(&pool, ...)`
7. **Migrate 19 inline fixtures to tempfile (BLOCKER — :memory: isolation):**

   All of the following fixtures create an inline `AppState` with `:memory:` DB and must
   be migrated to `tempfile::NamedTempFile` + `db::new_pool`. Affected fixtures:

   - `test_get_alert_config_requires_auth` (line ~1674)
   - `test_put_alert_config_roundtrip` (line ~1706)
   - `test_put_alert_config_preserves_masked_secret` (line ~1791) — **also has an
     inline `db.conn().lock()` at the verification step (line ~1867) that reads the DB
     directly after PUT to verify mask behavior; migrate that to `pool.get().expect(...)`**
   - `test_db_insert_select_roundtrip_via_spawn_blocking` (line ~1887) — **has 2 separate
     `conn().lock()` calls** (INSERT closure at ~1891 and SELECT closure at ~1912);
     the Arc-cloned variable `db` is renamed `pool` (and `db2` → `pool2`) in the migration
   - `test_router_post_then_direct_db_read` (line ~1937) — **has an inline
     `db_read.conn().lock()`** at ~1971; migrate to `pool_read.get().expect(...)`
   - `test_get_agent_config_falls_back_to_global` (line ~2696)
   - `test_put_agent_config_override` (line ~2800)
   - `test_delete_agent_config_override` (line ~2856)

8. **Update `seed_agent` call sites** in `test_get_agent_config_falls_back_to_global`,
   `test_put_agent_config_override`, and `test_delete_agent_config_override` to pass
   `&pool` instead of `&db`.

The `ALERT_SECRET_MASK` doc comments that reference "seeded during `Database::open`" should
be updated to "seeded during table init." as `Database::open` no longer exists.

---

## Wave 3 — Verification

### Task 3.1 — Build and run tests

**read_first:**
- `.planning/REQUIREMENTS.md` (R-10 acceptance criteria)
- `.planning/ROADMAP.md` (Phase 10 UAT)

**acceptance_criteria:**
- `cargo build --all` in the workspace root completes with no warnings
- `cargo test --workspace` passes (all tests green, no compilation errors)
- `cargo clippy -- -D warnings` passes with no warnings
- `grep -r "conn().lock()" dlp-server/src/` returns no matches (no remaining `Database::conn()` calls)
- `grep -r "db\.conn()" dlp-server/src/` returns no matches
- `grep "pub struct Database" dlp-server/src/db.rs` returns no match (Database struct removed)
- `grep "db\.Pool\|db::Pool" dlp-server/src/main.rs` returns a match (pool type used)
- `grep "pub pool:" dlp-server/src/lib.rs` returns a match (`pool` field in AppState)

**action:**
Run the following commands in sequence:

```bash
cd C:\Users\nhdinh\dev\dlp-rust
cargo build --all 2>&1
cargo test --workspace 2>&1
cargo clippy -- -D warnings 2>&1
```

Fix any compilation errors or clippy warnings before declaring the phase complete.

---

## Verification Summary

| Criterion | Check |
|-----------|-------|
| `r2d2` and `r2d2_sqlite` in `Cargo.toml` | grep |
| `new_pool` in `db.rs` | grep |
| `pub type Pool` in `db.rs` | grep |
| No `conn().lock()` remaining | grep |
| No `Database` struct remaining | grep |
| `AppState.pool` field | grep |
| `pool.get()` call sites | grep |
| All tests pass | `cargo test --workspace` |
| Zero warnings | `cargo clippy -- -D warnings` |
