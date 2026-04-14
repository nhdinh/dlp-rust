# Phase 10: SQLite Connection Pool — Context

**Gathered:** 2026-04-14
**Status:** Ready for planning
**Source:** /gsd-discuss-phase

<domain>
## Phase Boundary

Replace `Mutex<Connection>` in `dlp-server/src/db.rs` with an `r2d2` connection pool.
All 50+ `conn().lock()` call sites across `admin_api.rs`, `admin_auth.rs`,
`agent_registry.rs`, `alert_router.rs`, `audit_store.rs`, `exception_store.rs`,
`siem_connector.rs`, and `main.rs` are updated to use `pool.get()` instead.
`AppState` holds `Arc<r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>>` directly.
Existing tests pass. Concurrent API requests no longer serialize on a single mutex.

**In scope:**
- `dlp-server/src/db.rs` — replace `parking_lot::Mutex<Connection>` with `r2d2::Pool`
- `dlp-server/Cargo.toml` — add `r2d2` and `r2d2_sqlite` dependencies
- All call sites in `dlp-server/src/` — update `conn().lock()` → `pool.get()`
- `AppState` in `dlp-server/src/lib.rs` — pool field replaces `db` field
- `dlp-server/src/main.rs` — pool initialization replaces `Database::open()`
- All unit/integration tests — update to work with pool

**Out of scope:**
- Async pool (deadpool) — the codebase is fundamentally sync via `spawn_blocking`
- Pool size tuning beyond initial 5-connection constant
- Configurable pool size via env var or DB
- Schema migrations (this is purely a refactor, no DB schema changes)
</domain>

<decisions>
## Implementation Decisions

### A — Pool Crate: r2d2

**Decision:** Use `r2d2` + `r2d2_sqlite` (sync pool, sqlite-specific helper).

Rationale: Mature, stable, minimal API. `deadpool` is async-first and adds
unnecessary complexity to a codebase already built around sync + `spawn_blocking`.
The project has no async database operations — `spawn_blocking` bridges sync to async.
`r2d2` is the right fit.

### B — Pool API: Pool in AppState directly

**Decision:** `AppState` holds the pool directly; `Database` wrapper is removed or
reduced to a minimal shim. Call sites use `pool.get()`.

Implementation in `db.rs`:
```rust
pub type Pool = r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>;

pub fn new_pool(path: &str) -> anyhow::Result<Pool> {
    let mgr = r2d2_sqlite::SqliteConnectionManager::file(path);
    let pool = r2d2::Pool::builder()
        .max_size(5)
        .build(mgr)
        .context("failed to build connection pool")?;
    Ok(pool)
}
```

`AppState` field changes:
```rust
// Before:
pub struct AppState {
    pub db: Arc<db::Database>,
    // ...
}

// After:
pub struct AppState {
    pub pool: Pool,  // r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>
    // ...
}
```

Rationale: `db.conn().lock()` → `pool.get()?` is the smallest mechanical diff.
Wrapping the pool in a `Database` struct that just forwards `.conn()` adds a layer
with no benefit. Direct pool exposure is cleaner.

### C — Pool Size: 5

**Decision:** Fixed pool size of 5 connections, hardcoded in `db.rs`.

Rationale: SQLite with WAL allows concurrent reads but serializes writes to one
writer. 5 connections gives real concurrency benefit for the read-heavy admin API
without over-allocating. The number can be raised later if profiling shows it.

### D — Pool Configuration: Hardcoded Constant

**Decision:** Pool size is a `const POOL_SIZE: u32 = 5` in `db.rs`. No env var,
no DB-backed config at this stage.

Rationale: Simplicity. Pool size is an infrastructure tuning detail that rarely
changes. Adding config surface (env var or DB) for this is premature. Hardcoded
is correct for v1.

### E — Call Site Migration: conn().lock() → pool.get()

All 50+ call sites across the server crate follow this pattern:
```rust
// Before:
let conn = db.conn().lock();

// After:
let conn = pool.get().map_err(AppError::Database)?;
```

The `Pooled<Connection>` auto-returns to the pool on drop — no close calls needed.

### F — Error Mapping

`r2d2::PoolError` maps to `AppError::Database` via `From` impl or `.map_err()`.
The existing `AppError::Database(rusqlite::Error)` variant covers rusqlite errors;
`PoolError` wraps `rusqlite::Error` so the same mapping applies.

### G — Tests

All unit tests that use `Database::open(":memory:")` continue to work — the pool
wraps the same `SqliteConnectionManager::file` / `:memory:` URI. Test helper
functions (`seed_agent`, etc.) get `&Pool` instead of `&Database`.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase requirement
- `.planning/ROADMAP.md` — Phase 10 section (R-10, UAT criteria, file list)
- `.planning/REQUIREMENTS.md` — R-10 full text

### Existing DB infrastructure
- `dlp-server/src/db.rs` — current `Mutex<Connection>` implementation, table schemas
- `dlp-server/src/lib.rs` — `AppState` struct (where pool replaces `db` field)
- `dlp-server/src/main.rs` — `Database::open()` call (line 168), `ensure_admin_user`, `load_ldap_config`
- `dlp-server/Cargo.toml` — where to add `r2d2` and `r2d2_sqlite` deps

### All call sites to update
- `dlp-server/src/admin_api.rs` — 27 `conn().lock()` call sites
- `dlp-server/src/admin_auth.rs` — 6 `conn().lock()` call sites
- `dlp-server/src/agent_registry.rs` — 5 `conn().lock()` call sites
- `dlp-server/src/alert_router.rs` — 4 `conn().lock()` call sites + `AlertRouter::new` constructor
- `dlp-server/src/audit_store.rs` — 4 `conn().lock()` call sites
- `dlp-server/src/exception_store.rs` — 3 `conn().lock()` call sites
- `dlp-server/src/siem_connector.rs` — 1 `conn().lock()` call site + `SiemConnector::new` constructor

### Prior phase patterns
- `.planning/phases/06-wire-config-push-for-agent-config-distribution/06-CONTEXT.md` — DB-backed config pattern (established: no env vars for config)
- `.planning/phases/09-admin-operation-audit-logging/09-CONTEXT.md` — Phase 9 audit logging decisions

### Established code patterns
- All DB access already wrapped in `spawn_blocking` (no lock contention across async tasks)
- `AppError::Database(rusqlite::Error)` already exists
- Tests use `Database::open(":memory:")` helper pattern

</canonical_refs>

<codebase_context>
## Existing Code Insights

### Reusable Assets
- `db.rs` module — already encapsulates all DB access; only the `Database` struct internals change
- `AppError::Database` — existing error variant to map pool errors to
- `spawn_blocking` pattern — all handlers offload DB work to a sync thread pool; pool fits the same model

### Established Patterns
- `AppState { db, siem, ... }` — canonical axum state shared across all handlers
- `pool.get().map_err(AppError::Database)?` — uniform error mapping at every call site
- Test helpers (`seed_agent`, etc.) — take `&Database` via Arc; will take `&Pool` after refactor

### Integration Points
- `AppState` in `lib.rs` — `db: Arc<Database>` replaced with `pool: Pool`
- `main.rs` — `Database::open()` replaced with `db::new_pool()`
- All 8 source files in `dlp-server/src/` — `conn().lock()` → `pool.get()`

</codebase_context>

<specifics>
## Specific Implementation Notes

### Cargo.toml additions

```toml
# dlp-server/Cargo.toml
r2d2 = "0.8"
r2d2_sqlite = "0.36"
```

Note: `r2d2_sqlite` wraps `r2d2` with a `SqliteConnectionManager` that knows how
to construct `rusqlite::Connection` objects. It re-exports the connection type.

### db.rs new_pool signature

```rust
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

pub type Pool = Pool<SqliteConnectionManager>;

pub fn new_pool(path: &str) -> anyhow::Result<Pool> {
    let mgr = SqliteConnectionManager::file(path);
    r2d2::Pool::builder()
        .max_size(5)
        .build(mgr)
        .context("failed to build connection pool")
}
```

### WAL mode on pool connections

`SqliteConnectionManager` does not automatically set PRAGMA flags per connection.
Consider setting `PRAGMA journal_mode=WAL` in the manager builder, or via a custom
connection callback. Check if `r2d2_sqlite` supports a hook for this. If not,
a helper that wraps `pool.get()` with a WAL-set guard may be needed, or a custom
`ConnectionManager` that sets PRAGMA on `init` / `connect`.

**Important:** The current `Database::open` sets `PRAGMA journal_mode=WAL` once
on the single connection. With a pool, each borrowed connection should have WAL
already set. Verify `r2d2_sqlite` handles this or add a connection initializer.

### Drop the Database wrapper (or keep minimal)

After migration, `db.rs` can either:
- Keep `Database` as a thin wrapper (`new_pool` + WAL init) with a `pool()` accessor
- Be removed entirely, with `db::new_pool()` called directly in `main.rs`

Decision: Keep a minimal `db` module (or just `db::new_pool`) with the WAL
initialization logic. The module stays; the `Mutex<Connection>` wrapper goes.

</specifics>

<deferred>
## Deferred Ideas

- Async pool (deadpool) — future consideration if async DB operations are added
- Configurable pool size via env var — only if 5 proves insufficient in production
- Pool size tuning via profiling — premature without load testing data

</deferred>

---

*Phase: 10-sqlite-connection-pool*
*Context gathered: 2026-04-14 via /gsd-discuss-phase*
