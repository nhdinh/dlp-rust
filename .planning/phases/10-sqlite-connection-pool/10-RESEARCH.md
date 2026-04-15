# Phase 10: SQLite Connection Pool — Research

**Phase:** 10-sqlite-connection-pool
**Status:** Research complete
**Date:** 2026-04-14

---

## 1. What I Know

### 1.1 Existing Infrastructure

**`db.rs` — Current structure:**
- `Database` struct wraps `parking_lot::Mutex<Connection>`
- `Database::open(path)` sets WAL mode and calls `init_tables()`
- `Database::conn()` returns `&Mutex<Connection>` (accessor pattern)
- `init_tables()` runs `CREATE TABLE IF NOT EXISTS` for 10 tables
- All 5 tests use `Database::open(":memory:")`

**`lib.rs` — `AppState`:**
```rust
pub struct AppState {
    pub db: Arc<db::Database>,       // Arc<Database> — pool replaces this
    pub siem: siem_connector::SiemConnector,
    pub alert: alert_router::AlertRouter,
    pub ad: Option<AdClient>,
}
```
`AppState` is `#[derive(Clone)]` — currently cloning `Arc<Database>`.

**`main.rs`:**
- Line 35: `use dlp_server::db::Database`
- Line 168: `let db = Arc::new(Database::open(&config.db_path)?);`
- Line 172: `ensure_admin_user(&db, ...)` — takes `&Database`
- Line 176: `SiemConnector::new(Arc::clone(&db))` — takes `Arc<Database>`
- Line 180: `AlertRouter::new(Arc::clone(&db))` — takes `Arc<Database>`
- Line 199: `AppState { db, siem, alert, ad }`

### 1.2 Call Site Inventory

Grep for `conn().lock()` across `dlp-server/src/`:

| File | Count | Pattern |
|------|-------|---------|
| `admin_api.rs` | 29 | `db.conn().lock()` in `spawn_blocking` |
| `admin_auth.rs` | 6 | `db.conn().lock()` in `spawn_blocking` + startup fns |
| `agent_registry.rs` | 5 | `spawn_blocking` + sweeper loop |
| `alert_router.rs` | 4 | `load_config()` direct, 3 in tests |
| `audit_store.rs` | 4 | `store_events_sync(&conn, ...)` needs `&Connection` |
| `exception_store.rs` | 3 | `spawn_blocking` |
| `siem_connector.rs` | 1 | `load_config()` direct |
| `main.rs` | 1 | `load_ldap_config(&db)` — `&Database` parameter |
| `db.rs` (tests) | 4 | Unit test helper |
| **Total** | **57** | |

### 1.3 `SiemConnector` and `AlertRouter` Hold `Arc<Database>`

Both structs store `db: Arc<Database>` and call `self.db.conn().lock()`:

```rust
// siem_connector.rs line 57
pub struct SiemConnector {
    db: Arc<Database>,   // <- needs to become Arc<Pool>
    client: Client,
}

// alert_router.rs line 80
pub struct AlertRouter {
    db: Arc<Database>,   // <- needs to become Arc<Pool>
    client: Client,
}
```

Their `load_config()` methods are synchronous (no `spawn_blocking`), called directly from async handlers. These must be updated to use `pool.get().map_err(...)`.

### 1.4 `store_events_sync` Needs `&Connection` Directly

```rust
// audit_store.rs line 59
pub fn store_events_sync(conn: &rusqlite::Connection, events: &[AuditEvent])
```

Used in `admin_auth.rs::change_password` (line 321) inside `spawn_blocking`. The function takes `&rusqlite::Connection` — this is the only call site that receives a bare `&Connection`. With the pool, `pool.get()` returns `PooledConnection<SqliteConnectionManager>` which derefs to `&Connection`, so `store_events_sync` works unchanged.

### 1.5 Test Pattern: `Arc::new(Database::open(":memory:"))`

All integration tests use:
```rust
let db = Arc::new(crate::db::Database::open(":memory:").expect("open db"));
let siem = SiemConnector::new(Arc::clone(&db));
let alert = AlertRouter::new(Arc::clone(&db));
let state = Arc::new(AppState { db, siem, alert, ad: None });
```

After migration, `db.rs` must provide `new_pool(path)` that works with `:memory:` URIs so existing tests pass unchanged in most cases.

### 1.6 `load_ldap_config` in `main.rs` Takes `&Database`

```rust
fn load_ldap_config(db: &Database) -> Option<LdapConfig> {
    let conn = db.conn().lock();
    ...
}
```

Called at line 184 in `main`. This function is synchronous and used only at startup. It takes `&Database` — after migration it takes `&Pool`.

---

## 2. What I Need to Clarify

### 2.1 WAL Mode per Connection in Pool

The current `Database::open` sets `PRAGMA journal_mode=WAL` once on the single connection:
```rust
conn.execute_batch("PRAGMA journal_mode=WAL;")
```

With a pool of N connections, **each** borrowed connection must have WAL mode set. `r2d2_sqlite::SqliteConnectionManager::file()` does not automatically apply PRAGMA flags.

**Options:**
1. Use `SqliteConnectionManager::file(path)` and accept that WAL is not set per-connection — SQLite defaults to DELETE mode, which still works but loses WAL concurrency benefits.
2. Wrap `SqliteConnectionManager` with a custom `ConnectionManager` that applies PRAGMA in `connect()`.
3. Use `rusqlite` Connection directly with a pool that calls a custom hook.

`r2d2_sqlite` exposes the `ManageConnection` trait. We can implement a custom manager or use the simpler approach of adding a `connect_hook` via the builder. However, `r2d2_sqlite` doesn't natively support a connection initializer.

**Recommendation:** Keep it simple — `SqliteConnectionManager::file` doesn't apply WAL per connection, but:
- `:memory:` databases are always in-memory; WAL is irrelevant.
- File-based DBs will default to DELETE mode; concurrent reads still work (SQLite allows multiple readers), only writes are serialized.
- The real concurrency win (no mutex contention on read-heavy workloads) comes from multiple connections, not WAL.
- WAL is primarily a durability/crash-recovery feature for this application.

**Decision:** No custom connection initializer at this stage. WAL mode is set only on the first connection opened at startup (existing `Database::open` behavior), which creates the DB file with WAL. Subsequent pool connections inherit the WAL mode set by SQLite at the file level.

### 2.2 `SiemConnector` and `AlertRouter` Constructors

Both `SiemConnector::new` and `AlertRouter::new` currently take `Arc<Database>`. After migration:
- Option A: Change to `Arc<Pool>`, update `load_config()` signatures.
- Option B: Keep `Arc<Database>` wrapper with `Pool` inside — but this adds a layer for no benefit.

**Decision:** Both take `Arc<Pool>`. `load_config()` uses `self.pool.get().map_err(SiemError::from)?` / `.map_err(AlertError::from)?`.

### 2.3 Error Mapping for `r2d2::PoolError`

`r2d2::PoolError` wraps the underlying error (e.g., `rusqlite::Error`). The existing `AppError::Database(rusqlite::Error)` doesn't directly cover `PoolError`. Two approaches:

1. Add `impl From<r2d2::PoolError> for AppError` that maps to `AppError::Internal(...)`.
2. Use `.map_err(|e| AppError::Internal(anyhow::anyhow!("pool error: {e}")))` at call sites.

**Decision:** Option 1 — add a `From` impl in `lib.rs` so pool errors propagate as `AppError::Internal`. `r2d2::PoolError` is display-formatted and contains the underlying cause.

Similarly, `AlertError` has `Database(rusqlite::Error)` — add `impl From<r2d2::PoolError> for AlertError` mapping to `AlertError::Database(e.into())` (`.into()` via `rusqlite::Error::InvalidParameterName` or similar). Actually `r2d2::PoolError` wraps `rusqlite::Error` as its source — use `PoolError::into()`.

`SiemError` has `Database(rusqlite::Error)` — same pattern.

### 2.4 `store_events_sync` Signature

The function takes `conn: &rusqlite::Connection`. With `PooledConnection<SqliteConnectionManager>` from `pool.get()`, we get a smart pointer that implements `Deref<Target = Connection>`. So we can pass `&PooledConnection` directly to `store_events_sync(&conn, ...)` where `conn: &PooledConnection` — Rust's deref coercion should handle this. If not, the call site uses `&*conn` to get `&Connection`. This needs verification.

### 2.5 `AppState::db` Field Name

Renaming `db` to `pool` in `AppState` changes the field name across all call sites in `admin_api.rs`, `admin_auth.rs`, `agent_registry.rs`, `audit_store.rs`, `exception_store.rs`. This is purely mechanical but significant. Alternatively, keep the field named `db` of type `db::Pool` — the name is misleading but avoids 50+ mechanical renames. **Decision:** Rename to `pool` — the name should accurately reflect the type.

---

## 3. Risks and Edge Cases

### 3.1 `:memory:` with Connection Pool

`r2d2_sqlite::SqliteConnectionManager::file(":memory:")` creates an in-memory database. Each connection in the pool gets the same `:memory:` URI — **with SQLite, `:memory:` databases are scoped to a single connection**. Multiple connections to `:memory:` are isolated from each other.

This is a **critical issue** for tests that rely on `:memory:` with multiple connections. If `SiemConnector` holds one pool connection and `AlertRouter` holds another, they see different databases — seed rows won't be visible.

**Verification:** SQLite `:memory:` databases are in-memory and non-shared between connections unless a named shared cache (`:mode=memory`) is used. The `SqliteConnectionManager` creates a new in-memory DB per `connect()` call.

**Workaround for tests:** Use `file(":mode=memory&cache=shared")` URI, or use `tempfile` for a real file-based DB. However, `r2d2_sqlite` may not support arbitrary URI parameters.

**Better approach:** For tests that need shared state across multiple pooled connections, use a file-based temp database:
```rust
let temp_db = tempfile::NamedTempFile::new().unwrap();
let pool = db::new_pool(temp_db.path().to_str().unwrap())?;
```

This is slightly more expensive but correct. Alternatively, configure the pool with `max_size(1)` for tests to ensure single-connection access to `:memory:` — but this still creates separate connections if the pool initializes multiple connections.

**Decision:** Most tests don't need cross-connector shared state (they just create `AlertRouter` and call `load_config()` on the same router). For integration tests that do need shared state, use a temp file.

### 3.2 Pool Exhaustion

With `max_size(5)`, if all connections are checked out and a 6th request tries `pool.get()`, the call **blocks indefinitely** by default. There is no timeout by default in `r2d2`.

For the DLP server's write-heavy (but small N) workload, this is unlikely to be an issue. But if a handler holds a connection while awaiting an async operation (e.g., awaiting a SIEM relay HTTP call), the connection is held and the tokio reactor is blocked from acquiring it.

**Mitigation:** Handlers hold connections for the minimum time — SQLite operations are fast. The existing `spawn_blocking` pattern means connections are held only during the sync DB call, not during async I/O.

### 3.3 Shutdown Ordering

When the server shuts down (graceful shutdown via CTRL+C), the pool will be dropped. r2d2 closes all connections on `Pool::drop`. This is clean — no special shutdown handling needed.

### 3.4 `Arc<AppState>` Cloning

`AppState` is `#[derive(Clone)]`. Cloning `AppState` clones the `Pool` (via `Arc` wrapper). `r2d2::Pool` is `Clone` — it internally holds an `Arc<Inner>`, so cloning is cheap. The pool is shared across all cloned `AppState` instances.

---

## 4. Implementation Plan

### Step 1: Add Dependencies (`Cargo.toml`)

```toml
r2d2 = "0.8"
r2d2_sqlite = "0.36"
```

### Step 2: Refactor `db.rs`

Replace `Database` with `Pool`:

```rust
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite;

pub type Pool = Pool<SqliteConnectionManager>;
pub type Connection = PooledConnection<SqliteConnectionManager>;

/// Creates a connection pool and initializes all tables.
///
/// Returns `Err` if the pool cannot be built or table creation fails.
pub fn new_pool(path: &str) -> anyhow::Result<Pool> {
    let mgr = SqliteConnectionManager::file(path);
    let pool = Pool::builder()
        .max_size(5)
        .build(mgr)
        .context("failed to build connection pool")?;

    // Initialize tables using the first connection from the pool.
    // All connections to the same file share the WAL mode set on first open.
    let conn = pool.get().context("failed to acquire connection for init")?;
    conn.execute_batch("PRAGMA journal_mode=WAL;")
        .context("failed to enable WAL journal mode")?;

    init_tables(&conn)?;
    Ok(pool)
}

fn init_tables(conn: &rusqlite::Connection) -> anyhow::Result<()> {
    conn.execute_batch("...")  // same as current init_tables body
}
```

Keep `Database` as a deprecated type alias or remove entirely — callers use `db::Pool` directly.

### Step 3: Update `AppState` in `lib.rs`

```rust
pub struct AppState {
    pub pool: db::Pool,           // replaces db: Arc<Database>
    pub siem: SiemConnector,
    pub alert: AlertRouter,
    pub ad: Option<AdClient>,
}
```

Update `Debug` impl accordingly.

### Step 4: Add Error Mapping

In `lib.rs`:
```rust
impl From<r2d2::PoolError> for AppError {
    fn from(e: r2d2::PoolError) -> Self {
        AppError::Internal(anyhow::anyhow!("pool error: {e}"))
    }
}
```

### Step 5: Update `SiemConnector` and `AlertRouter`

Both `new()` functions take `Arc<db::Pool>`. `load_config()` does:
```rust
let conn = self.pool.get().map_err(SiemError::from)?;
```

Add `impl From<r2d2::PoolError> for SiemError` and `impl From<r2d2::PoolError> for AlertError`.

### Step 6: Update `main.rs`

```rust
use dlp_server::db;
use dlp_server::siem_connector::SiemConnector;
use dlp_server::alert_router::AlertRouter;

let pool = Arc::new(db::new_pool(&config.db_path)?);
info!(path = %config.db_path, "database pool opened");

ensure_admin_user(&pool, config.init_admin_password.as_deref())?;

let siem = SiemConnector::new(Arc::clone(&pool));
let alert = AlertRouter::new(Arc::clone(&pool));

// load_ldap_config takes &db::Pool now

let state = Arc::new(AppState { pool, siem, alert, ad: ad_client });
```

`ensure_admin_user` signature changes from `fn(&Database)` to `fn(&Pool)`. `load_ldap_config` changes from `fn(&Database)` to `fn(&Pool)`.

### Step 7: Update Call Sites (57 locations)

Pattern:
```rust
// Before:
let db = Arc::clone(&state.db);
tokio::task::spawn_blocking(move || {
    let conn = db.conn().lock();
    conn.execute(...)?;
    Ok(())
})

// After:
let pool = Arc::clone(&state.pool);
tokio::task::spawn_blocking(move || {
    let conn = pool.get().map_err(AppError::from)?;
    conn.execute(...)?;
    Ok(())
})
```

Special cases:
- `store_events_sync(&conn, ...)` in `admin_auth.rs::change_password`: pass `&*conn` after `pool.get()`.
- `spawn_offline_sweeper` in `agent_registry.rs`: same pattern.
- Tests in `db.rs`: Update to use `new_pool(":memory:")` — but note the `:memory:` pool issue (see §3.1). Tests that only call `init_tables` and query within the same connection are fine. Tests that need multiple connections to see the same DB need a temp file.

### Step 8: Update Tests

All test modules that construct `AppState` directly need updating. The `spawn_admin_app()` helper function in `admin_api.rs::tests` changes to:
```rust
let pool = Arc::new(crate::db::new_pool(":memory:").expect("open pool"));
let siem = crate::siem_connector::SiemConnector::new(Arc::clone(&pool));
let alert = crate::alert_router::AlertRouter::new(Arc::clone(&pool));
let state = Arc::new(AppState { pool, siem, alert, ad: None });
```

`db.rs` unit tests use `new_pool(":memory:")` directly.

For tests that verify cross-component DB reads (e.g., `AlertRouter` reads seed row created by table init), the `:memory:` pool creates a single in-memory DB accessible across pool connections using the shared cache. Verify `r2d2_sqlite` supports `mode=memory` or use `cache=shared`.

**Safe test pattern for all integration tests:** Use a tempfile-based DB:
```rust
let tmp = tempfile::NamedTempFile::new().expect("create temp db");
let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
```

This ensures all pool connections see the same database.

---

## 5. File-to-Change Inventory

| File | Changes |
|------|---------|
| `dlp-server/Cargo.toml` | Add `r2d2 = "0.8"`, `r2d2_sqlite = "0.36"` |
| `dlp-server/src/db.rs` | Replace `Database` with `Pool` type, `new_pool()`, `init_tables()` |
| `dlp-server/src/lib.rs` | `AppState.pool` field, `From<r2d2::PoolError>` impls |
| `dlp-server/src/main.rs` | `new_pool()`, `ensure_admin_user(&pool)`, `load_ldap_config(&pool)` |
| `dlp-server/src/admin_api.rs` | 29 `conn().lock()` → `pool.get().map_err(AppError::from)?`; 9 test setups |
| `dlp-server/src/admin_auth.rs` | 6 call sites + `has_admin_users(&pool)`, `create_admin_user(&pool)` |
| `dlp-server/src/agent_registry.rs` | 5 call sites + `spawn_offline_sweeper` |
| `dlp-server/src/alert_router.rs` | `Arc<Pool>` field, 1 direct call, 3 test setups, `From<PoolError>` impl |
| `dlp-server/src/audit_store.rs` | 4 call sites (`store_events_sync` unchanged) |
| `dlp-server/src/exception_store.rs` | 3 call sites |
| `dlp-server/src/siem_connector.rs` | `Arc<Pool>` field, 1 direct call, 2 test setups, `From<PoolError>` impl |
| `dlp-agent/tests/integration.rs` | Check for any direct `Database::open` usage — likely none |

**Estimated LOC change:** ~+60 (db.rs refactor), ~-20 (remove Mutex wrappers), ~+180 (57 call site rewrites + test updates) = net ~+220 lines.

---

## 6. Acceptance Criteria

1. `cargo test --workspace` passes with no compilation errors or test failures.
2. `cargo build --all` compiles with no warnings.
3. `cargo clippy -- -D warnings` passes.
4. Server starts with `new_pool()` and serves requests correctly.
5. Concurrent requests are not serialized on a single mutex — multiple connections are used.
6. All `conn().lock()` usages are replaced; no remaining `Database::conn()` calls.
7. WAL mode is set on the file-based database (even without per-connection PRAGMA, the first connection sets it for the file).

---

## 7. Deferred Decisions

| Decision | Deferred To | Rationale |
|----------|-------------|-----------|
| Configurable pool size | Future phase | Hardcoded 5 is sufficient for v1 |
| Async pool (deadpool) | Future phase | No async DB ops needed; `spawn_blocking` works |
| Connection health checks | Future phase | SQLite connections are self-contained |
| Pool metrics / monitoring | Future phase | No observability surface needed yet |