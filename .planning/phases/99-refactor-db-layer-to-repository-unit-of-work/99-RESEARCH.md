# Phase 99: Refactor DB Layer to Repository + Unit of Work — Research

**Researched:** 2026-04-15
**Domain:** Rust / rusqlite / r2d2 repository pattern refactor
**Confidence:** HIGH — all findings are from direct codebase inspection

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **A** — One repository struct per entity in `db/repositories/`. No naked `conn.execute()` or `conn.query_row()` outside that directory.
- **B** — `UnitOfWork<'conn>` holds a `rusqlite::Transaction<'conn>`. RAII rollback on drop.
- **C** — Every INSERT, UPDATE, DELETE goes through `UnitOfWork`, even single-row writes.
- **D** — Read methods take `&Pool`; write methods take `&UnitOfWork`.
- **E** — Existing handler files (`admin_api.rs`, `admin_auth.rs`, etc.) are retained. Only raw SQL moves.
- **F** — 3-wave migration: Wave 1 = db/ stubs, Wave 2 = small modules (23 sites), Wave 3 = admin_api.rs (26 sites).
- **G** — Repository methods return `rusqlite::Result<T>`.

### Claude's Discretion

- Repository struct field layout (zero-field stateless vs. config-bearing)
- Internal helper function decomposition within repository files

### Deferred Ideas (OUT OF SCOPE)

- Async repositories (deadpool + tokio)
- Repository trait abstraction for mock repos
- Pool size configurability
- Query builder (diesel, sea-query)
</user_constraints>

---

## Summary

Phase 99 is a pure structural refactor with no schema or behavioural changes. All 49 raw
`pool.get()` call sites across 7 handler files are migrated into typed repository structs
under `dlp-server/src/db/repositories/`. The existing `db.rs` becomes `db/mod.rs`.

The primary technical challenge is the `UnitOfWork<'conn>` lifetime: `Transaction<'conn>`
borrows `Connection` for its full lifetime, which means the `PooledConnection` must outlive
the `UnitOfWork`. This is straightforward as long as both are kept in the same
`spawn_blocking` closure scope. The borrow-checker will enforce this correctly.

**Primary recommendation:** Build Wave 1 stubs first to validate the lifetime model compiles
before mass-migrating call sites. `&mut *conn` is the key dereference to get
`&mut rusqlite::Connection` from a `PooledConnection<SqliteConnectionManager>`.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| SQL execution (reads) | DB layer (`db/repositories/`) | — | All SELECT encapsulated here |
| SQL execution (writes) | DB layer (`db/repositories/`) via UoW | — | All INSERT/UPDATE/DELETE here |
| Transaction management | `db/unit_of_work.rs` | — | RAII boundary lives here |
| Pool management | `db/mod.rs` | — | `new_pool()` and `Pool` type alias |
| HTTP routing / response mapping | Handler files (existing) | — | Not touched by this phase |
| Business validation | Handler files (existing) | — | `BadRequest` guards stay in handlers |
| Error conversion (`AppError`) | Handler files (existing) | — | `.map_err(AppError::Database)` at handler boundary |

---

## Question 1: SQL Migration Map

### File: `dlp-server/src/admin_auth.rs` (5 production call sites)

| Line | Handler / Function | Table | Operation | Key Detail |
|------|-------------------|-------|-----------|------------|
| 168 | `login` (spawn_blocking) | `admin_users` | SELECT `password_hash WHERE username = ?1` | Returns `String`; `QueryReturnedNoRows` mapped to Unauthorized |
| 265 | `change_password` (spawn_blocking) | `admin_users` | SELECT `password_hash WHERE username = ?1` | Same pattern as login |
| 300–310 | `change_password` (spawn_blocking) | `admin_users` | UPDATE `SET password_hash = ?1 WHERE username = ?2` | Single-row UPDATE, no transaction today |
| 325–330 | `change_password` (spawn_blocking via `audit_store::store_events_sync`) | `audit_events` | INSERT OR IGNORE (batch) | Delegates to `store_events_sync` — see audit_store section |
| 345 | `has_admin_users` (sync, no spawn_blocking) | `admin_users` | SELECT `COUNT(*)` | Called at startup; uses `anyhow::Result`, not `AppError` |
| 365 | `create_admin_user` (sync, no spawn_blocking) | `admin_users` | INSERT `(username, password_hash, created_at)` | Startup-only; uses `anyhow::Result` |

**Note on `has_admin_users` and `create_admin_user`:** These are sync startup functions, not
axum handlers. They receive `&crate::db::Pool` directly (no `Arc`). They must still be
migrated to use `AdminUserRepository` per Decision A, but they are NOT in the
`spawn_blocking` pattern. The repository method must accept `&Pool` or `&Connection`.

**Repository target:** `db/repositories/admin_users.rs` → `AdminUserRepository`

---

### File: `dlp-server/src/agent_registry.rs` (5 production call sites)

| Line | Handler / Function | Table | Operation | Key Detail |
|------|-------------------|-------|-----------|------------|
| 95 | `register_agent` (spawn_blocking) | `agents` | INSERT ... ON CONFLICT(agent_id) DO UPDATE SET (upsert) | Updates hostname/ip/os_version/agent_version/last_heartbeat/status |
| 158 | `heartbeat` (spawn_blocking) | `agents` | UPDATE `SET last_heartbeat = ?1, status = 'online' WHERE agent_id = ?2` | Returns `rows` count to detect 404 |
| 188 | `list_agents` (spawn_blocking) | `agents` | SELECT all columns ORDER BY hostname | Returns `Vec<AgentInfoResponse>` |
| 232 | `get_agent` (spawn_blocking) | `agents` | SELECT all columns WHERE agent_id = ?1 | Single row; `QueryReturnedNoRows` → NotFound |
| 280 | `spawn_offline_sweeper` (spawn_blocking in tokio::spawn loop) | `agents` | UPDATE `SET status = 'offline' WHERE status = 'online' AND last_heartbeat < ?1` | Background task; not an axum handler |

**Note on `spawn_offline_sweeper`:** Runs in a background `tokio::spawn` loop every 30
seconds. Must still be migrated per Decision A. The write is a single UPDATE, so it needs
a `UnitOfWork` per Decision C.

**Repository target:** `db/repositories/agents.rs` → `AgentRepository`

---

### File: `dlp-server/src/alert_router.rs` (1 production call site + test-only sites)

| Line | Handler / Function | Table | Operation | Key Detail |
|------|-------------------|-------|-----------|------------|
| 155 | `AlertRouter::load_config` (sync, **NOT** spawn_blocking) | `alert_router_config` | SELECT all config columns WHERE id = 1 | Called directly from async context — deliberately sync, noted in doc comment |

**Important:** `load_config` does NOT use `spawn_blocking`. It acquires the connection
synchronously from the async reactor. The doc comment explains this is deliberate for
single-row hot-reload reads. After migration, `AlertRouterConfigRepository::load` will
follow the same pattern (takes `&Pool`, acquires connection internally).

**Repository target:** `db/repositories/alert_router_config.rs` → `AlertRouterConfigRepository`

---

### File: `dlp-server/src/audit_store.rs` (4 production call sites)

| Line | Handler / Function | Table | Operation | Key Detail |
|------|-------------------|-------|-----------|------------|
| 62–93 | `store_events_sync` (sync helper, takes `&rusqlite::Connection`) | `audit_events` | INSERT OR IGNORE (batch, prepared statement loop) | Called from `admin_auth`, `admin_api`; does NOT call `pool.get()` — takes raw `Connection` |
| 133 | `ingest_events` (spawn_blocking) | `audit_events` | INSERT OR IGNORE (batch) via manual `conn.unchecked_transaction()` | Already uses a transaction internally (`tx.commit()`) |
| 249 | `query_events` (spawn_blocking) | `audit_events` | Dynamic SELECT with optional WHERE filters, LIMIT/OFFSET | Returns `Vec<serde_json::Value>` |
| 348 | `get_event_count` (spawn_blocking) | `audit_events` | SELECT COUNT(*) | Returns `i64` |

**Critical observation on `store_events_sync`:** This function takes `&rusqlite::Connection`
directly, not `&Pool`. It is called at lines 327–330 of `admin_auth.rs` and lines 581–585,
692–696, 742–746 of `admin_api.rs`. After migration, the `AuditEventRepository::insert_batch`
method must accept `&UnitOfWork` (Decision C). The callers in `admin_auth` and `admin_api`
will need to acquire a connection, wrap in `UnitOfWork`, call the repo method, and commit.

**Critical observation on `ingest_events`:** Uses `conn.unchecked_transaction()` at line 136
directly on the `PooledConnection`. After migration, this becomes `UnitOfWork::new(&mut *conn)`.

**Repository target:** `db/repositories/audit_events.rs` → `AuditEventRepository`

---

### File: `dlp-server/src/exception_store.rs` (3 production call sites)

| Line | Handler / Function | Table | Operation | Key Detail |
|------|-------------------|-------|-----------|------------|
| 100 | `create_exception` (spawn_blocking) | `exceptions` | INSERT `(id, policy_id, user_sid, approver, justification, duration_seconds, granted_at, expires_at)` | Single-row INSERT |
| 136 | `list_exceptions` (spawn_blocking) | `exceptions` | SELECT all columns ORDER BY granted_at DESC | Returns `Vec<Exception>` |
| 180 | `get_exception` (spawn_blocking) | `exceptions` | SELECT all columns WHERE id = ?1 | Single row; `QueryReturnedNoRows` → NotFound |

**Repository target:** `db/repositories/exceptions.rs` → `ExceptionRepository`

---

### File: `dlp-server/src/siem_connector.rs` (1 production call site)

| Line | Handler / Function | Table | Operation | Key Detail |
|------|-------------------|-------|-----------|------------|
| 120 | `SiemConnector::load_config` (sync, **NOT** spawn_blocking) | `siem_config` | SELECT all config columns WHERE id = 1 | Same pattern as alert_router.rs — deliberately sync hot-reload |

**Repository target:** `db/repositories/siem_config.rs` → `SiemConfigRepository`

---

### File: `dlp-server/src/admin_api.rs` (23 production handler call sites + 3 test-only)

Production call sites only (lines 1865, 1890, 2678 are inside `#[cfg(test)]` blocks):

| Line | Handler / Function | Table | Operation |
|------|-------------------|-------|-----------|
| 417 | `ready` | — | `execute_batch("SELECT 1")` — DB health check only |
| 439 | `list_policies` | `policies` | SELECT all columns ORDER BY priority |
| 482 | `get_policy` | `policies` | SELECT all columns WHERE id = ?1 |
| 545 | `create_policy` | `policies` | INSERT (id, name, description, priority, conditions, action, enabled, version=1, updated_at) |
| 581 | `create_policy` (audit) | `audit_events` | INSERT OR IGNORE via `store_events_sync` |
| 631 | `update_policy` | `policies` | UPDATE SET name/description/priority/conditions/action/enabled/version+1/updated_at WHERE id; then SELECT version |
| 692 | `update_policy` (audit) | `audit_events` | INSERT OR IGNORE via `store_events_sync` |
| 716 | `delete_policy` | `policies` | DELETE WHERE id = ?1; returns rows count |
| 742 | `delete_policy` (audit) | `audit_events` | INSERT OR IGNORE via `store_events_sync` |
| 776 | `set_agent_auth_hash` | `agent_credentials` | INSERT OR REPLACE ON CONFLICT(key) DO UPDATE key='DLPAuthHash' |
| 804 | `get_agent_auth_hash` | `agent_credentials` | SELECT value, updated_at WHERE key = 'DLPAuthHash' |
| 832 | `get_siem_config_handler` | `siem_config` | SELECT all config WHERE id = 1 |
| 872 | `update_siem_config_handler` | `siem_config` | UPDATE SET all config columns WHERE id = 1 |
| 920 | `get_alert_config_handler` | `alert_router_config` | SELECT all config WHERE id = 1 (with ME-01 masking) |
| 1004 | `update_alert_config_handler` | `alert_router_config` | SELECT smtp_password, webhook_secret (mask check) then UPDATE SET all WHERE id = 1 |
| 1104 | `get_agent_config_for_agent` | `agent_config_overrides` then `global_agent_config` | SELECT override; fallback SELECT global |
| 1147 | `get_ldap_config_handler` | `ldap_config` | SELECT all config WHERE id = 1 |
| 1197 | `update_ldap_config_handler` | `ldap_config` | UPDATE SET all config WHERE id = 1 |
| 1230 | `get_global_agent_config_handler` | `global_agent_config` | SELECT monitored_paths/heartbeat/offline WHERE id = 1 |
| 1270 | `update_global_agent_config_handler` | `global_agent_config` | UPDATE SET monitored_paths/heartbeat/offline WHERE id = 1 |
| 1302 | `get_agent_config_override_handler` | `agent_config_overrides` | SELECT WHERE agent_id = ?1; QueryReturnedNoRows → 404 |
| 1343 | `update_agent_config_override_handler` | `agent_config_overrides` | INSERT OR REPLACE |
| 1377 | `delete_agent_config_override_handler` | `agent_config_overrides` | DELETE WHERE agent_id = ?1; returns rows count |

**Special case — `ready` handler (line 417):** Uses `execute_batch("SELECT 1")` as a DB
health check. This is not an entity operation. After migration it could call any cheap
read (e.g., `AgentRepository::ping(pool)` or just keep using `pool.get()` + `execute_batch`
directly in the handler — since it is not entity logic, keeping it in the handler is
acceptable and does not violate Decision A).

**Special case — `update_alert_config_handler` (lines 1007–1023):** This handler does a
SELECT then UPDATE in a single `spawn_blocking` closure. This is atomic because it holds
one connection. After migration, the SELECT-then-UPDATE must be a single `UnitOfWork`
transaction to preserve the TOCTOU-free guarantee noted in the doc comment ("atomic").
`AlertRouterConfigRepository` needs a `update_with_mask_resolution(uow, payload, stored)` or
equivalent that wraps both operations.

**Repository targets for admin_api.rs:**
- `policies` → `PolicyRepository` (`db/repositories/policies.rs`)
- `agent_credentials` → new table not in the existing repository list — needs a dedicated
  file (see Question 3 note below)
- `siem_config` → `SiemConfigRepository` (reused)
- `alert_router_config` → `AlertRouterConfigRepository` (reused)
- `ldap_config` → `LdapConfigRepository` (`db/repositories/ldap_config.rs`)
- `global_agent_config` + `agent_config_overrides` → `AgentConfigRepository` (`db/repositories/agent_config.rs`)
- `audit_events` → `AuditEventRepository` (reused)

---

### File: `dlp-server/src/main.rs` (1 production call site — NOT in scope)

`load_ldap_config` at line 43 reads `ldap_config` to bootstrap the `AdClient` at startup.
This is NOT listed in the 7 in-scope files from CONTEXT.md. However, per Decision A,
raw SQL outside `db/repositories/` is prohibited. This call site will need migration but
is NOT in the 49 counted sites. Include a note in the plan for the implementer to migrate
`load_ldap_config` to use `LdapConfigRepository` during Wave 1 or Wave 3 (it's a startup
function, so it's low-risk to do with Wave 1).

[VERIFIED: codebase grep] `main.rs:43` — `pool.get().ok()?` + raw SQL on `ldap_config`.

---

## Question 2: UnitOfWork Lifetime Pitfalls

### The core model

```rust
// PooledConnection<SqliteConnectionManager> derefs to rusqlite::Connection.
// To call .transaction(), we need &mut rusqlite::Connection.
let mut conn: PooledConnection<SqliteConnectionManager> = pool.get()?;
// &mut *conn dereferences through DerefMut to get &mut Connection:
let uow = UnitOfWork::new(&mut *conn)?;
// conn must stay alive (not dropped) until uow is dropped.
```

`PooledConnection<M>` implements `DerefMut<Target = M::Connection>` (i.e., `rusqlite::Connection`).
`Transaction<'conn>` borrows `&'conn mut Connection`. The borrow lasts until the
`Transaction` is dropped (commit or rollback). `PooledConnection` must not be dropped
before `Transaction`.

[VERIFIED: CONTEXT.md specifics section] The exact pattern is documented at CONTEXT.md line 200–205.

### Pitfall 1: Dropping `conn` before `uow`

```rust
// WRONG — conn dropped at end of block, uow still holds &mut borrow:
let uow = {
    let mut conn = pool.get()?;
    UnitOfWork::new(&mut *conn)?  // borrow of conn escapes its block
};
// CORRECT — both in same scope:
let mut conn = pool.get()?;
let uow = UnitOfWork::new(&mut *conn)?;
repo.insert_foo(&uow, &data)?;
uow.commit()?;
// conn dropped here (returns to pool)
```

The borrow checker will prevent the WRONG pattern from compiling. This is enforced at
compile time, not a runtime concern.

### Pitfall 2: `spawn_blocking` closure capture

The `spawn_blocking` closure captures `conn` and `uow` together. Both must be `Send`.
`PooledConnection<SqliteConnectionManager>` is `Send`. `Transaction<'conn>` is `Send`
**only if** `'conn: 'static` — but the connection is local to the closure, so the lifetime
is not `'static`.

**Consequence:** `UnitOfWork<'conn>` cannot be sent across `spawn_blocking` if `conn` is
declared outside the closure. **The entire sequence (pool.get, UnitOfWork::new, repo call,
commit) must happen inside the same `spawn_blocking` closure.** This is already the pattern
in the existing codebase.

```rust
tokio::task::spawn_blocking(move || -> Result<_, AppError> {
    let mut conn = pool.get().map_err(AppError::Pool)?;
    let uow = UnitOfWork::new(&mut *conn).map_err(AppError::Database)?;
    repo.insert_foo(&uow, &data).map_err(AppError::Database)?;
    uow.commit().map_err(AppError::Database)?;
    Ok(())
})
.await
.map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;
```

### Pitfall 3: `r2d2::Error` → `AppError` conversion

The current codebase uses two error mapping patterns for `pool.get()`:
- `pool.get().map_err(AppError::from)?` (works because `From<r2d2::Error>` is implemented
  on `AppError` via the `Internal` variant at `lib.rs:137–141`)
- `pool.get().map_err(|e: r2d2::Error| AppError::from(e))?` (explicit, identical result)

For the `UnitOfWork` path, the CONTEXT.md specifies:
```rust
let mut conn = pool.get().map_err(AppError::Pool)?;
```
But `AppError` has no `Pool` variant — it has `Internal` wrapping pool errors (lib.rs:137).
The canonical form from the CONTEXT.md specifics section uses `AppError::from`:
```rust
let mut conn = pool.get().map_err(AppError::from)?;
```
[VERIFIED: lib.rs:137–141] `From<r2d2::Error> for AppError` maps to `AppError::Internal`.

### Pitfall 4: `rusqlite::Result<T>` vs `anyhow::Result<T>` in repositories

Repository methods return `rusqlite::Result<T>` (Decision G). But `store_events_sync`
also returns `Result<(), AppError>` today (it serializes enums with `serde_json` and can
produce `AppError::Json`). After migration, `AuditEventRepository::insert_batch` has two
options:
1. Return `rusqlite::Result<()>` — the JSON serialization step must be done by the handler
   before calling the repo (the repo receives pre-serialized strings).
2. Return a custom error type that encompasses both `rusqlite::Error` and `serde_json::Error`.

Decision G mandates option 1 or a wrapper. The cleanest solution consistent with Decision G
is to have the handler pre-serialize enum fields and pass `&str` parameters to the repo.
This matches what `ingest_events` already does (lines 140–159 serialize each field before
the SQL call).

### Pitfall 5: `alert_router.rs` and `siem_connector.rs` are NOT in `spawn_blocking`

Both `AlertRouter::load_config` (line 155) and `SiemConnector::load_config` (line 120) call
`pool.get()` directly from an async context. After migration, the repository method must
also be callable from non-`spawn_blocking` async context. Since the method takes `&Pool`
and does a quick single-row SELECT, this is acceptable — the doc comment in `alert_router.rs`
explicitly notes this asymmetry and its rationale (lines 143–152).

The planner must NOT wrap these in `spawn_blocking` during migration. The existing calling
pattern must be preserved exactly.

---

## Question 3: Existing DB Model Types

The following types are used as return/parameter types in handler files. These become the
return types for repository read methods:

### Types defined in handler files (to stay in handler files per Decision E)

| Type | File | Used As | Tables |
|------|------|---------|--------|
| `AgentInfoResponse` | `agent_registry.rs:47` | SELECT result + HTTP response | `agents` |
| `Exception` | `exception_store.rs:39` | SELECT result + HTTP response | `exceptions` |
| `PolicyResponse` | `admin_api.rs:73` | SELECT result + HTTP response | `policies` |
| `AuthHashResponse` | `admin_api.rs:40` | SELECT result + HTTP response | `agent_credentials` |
| `SiemConfigPayload` | `admin_api.rs:104` | SELECT result + HTTP response | `siem_config` |
| `AlertRouterConfigPayload` | `admin_api.rs:141` | SELECT result + HTTP response | `alert_router_config` |
| `LdapConfigPayload` | `admin_api.rs:174` | SELECT result + HTTP response | `ldap_config` |
| `AgentConfigPayload` | `admin_api.rs:194` | SELECT result + HTTP response | `global_agent_config`, `agent_config_overrides` |

**Critical design question for Wave 1:** Repository read methods return the above types, but
those types are defined in handler files. Two options:

**Option A (recommended):** Repository methods return the existing handler types directly.
`db/repositories/agents.rs` imports `agent_registry::AgentInfoResponse` and uses it.
This is the simplest path — no new structs, no conversion layer. The handler-layer types
already map 1-to-1 to the DB columns.

**Option B:** Define separate DB record types in `db/repositories/` and let handlers convert.
This adds a conversion step with no benefit for this codebase (Decision E and G do not
require it).

**Recommendation:** Use Option A. The CONTEXT.md example signatures at lines 213–220
show `AgentRecord` as the return type, suggesting the planner may introduce entity-specific
record types — but this adds unnecessary type duplication. Confirm with the implementer
whether to reuse handler types or introduce new record types. If introducing new record
types, they must have identical field names and types to the handler response structs to
avoid the conversion overhead.

**The `agent_credentials` table** is not in the CONTEXT.md repository mapping (line 239–248
of CONTEXT.md). It maps to `AgentCredentialsRepository` or can be folded into a
`CredentialsRepository`. The table has only one logical key (`DLPAuthHash`). This is a
planning gap — add `credentials.rs` → `CredentialsRepository` to the repository list.

**`EventQuery` type** (`audit_store.rs:20`) is the filter parameter for `query_events`. The
`AuditEventRepository::query` method will need to accept a similar parameter. Since
`EventQuery` is a handler type (derives `Deserialize` for axum), the repository should
accept individual filter fields or a repository-specific query struct.

---

## Question 4: `init_tables()` and `new_pool()` Migration

### Current state

`db.rs` contains:
- `pub type Pool = R2d2Pool<SqliteConnectionManager>` (line 13)
- `pub type Connection = r2d2::PooledConnection<SqliteConnectionManager>` (line 17)
- `pub fn new_pool(path: &str) -> anyhow::Result<Pool>` (line 29) — builds pool, enables WAL, calls `init_tables`
- `fn init_tables(conn: &SqliteConn) -> anyhow::Result<()>` (line 52) — private, creates all tables + seed rows

### Migration plan

`db.rs` becomes `db/mod.rs`. The `Pool` and `Connection` type aliases, `new_pool()`, and
`init_tables()` all move verbatim into `db/mod.rs`. No functional changes are needed.

`init_tables()` stays private to `db/mod.rs`. It creates all 10 tables and inserts seed
rows for the single-row config tables. There is no reason to split it per repository — the
entire schema must be created atomically on first open.

`lib.rs` already declares `pub mod db;` (line 11). After the rename, change to:
- Remove `pub mod db;` referencing `db.rs`
- Rust will automatically find `db/mod.rs` when `pub mod db;` exists in `lib.rs`

No changes to `lib.rs` code are required beyond the module system picking up the new path.

[VERIFIED: lib.rs:11] `pub mod db;` — this declaration works with both `db.rs` and `db/mod.rs`.

---

## Question 5: Existing Tests That Test DB Operations

### Tests that test DB directly (not via HTTP)

| File | Test Name | What It Tests | Impact |
|------|-----------|---------------|--------|
| `db.rs:204` | `test_new_pool_in_memory` | `new_pool()` succeeds | Keep in `db/mod.rs` — no change |
| `db.rs:209` | `test_tables_created` | All 10 tables exist after init | Keep in `db/mod.rs` — no change |
| `db.rs:243` | `test_global_agent_config_seed_row` | Seed row defaults | Keep in `db/mod.rs` — no change |
| `db.rs:262` | `test_idempotent_init` | `CREATE TABLE IF NOT EXISTS` is idempotent | Keep in `db/mod.rs` — no change |
| `db.rs:272` | `test_alert_router_config_seed_row` | alert_router seed row | Keep in `db/mod.rs` — no change |
| `db.rs:308` | `test_ldap_config_seed_row` | ldap_config seed row | Keep in `db/mod.rs` — no change |
| `audit_store.rs:382` | `test_store_events_sync_admin_action` | `store_events_sync` writes to `audit_events` | Must update: creates pool directly, calls `store_events_sync(&conn, &[event])`. After migration, call `AuditEventRepository::insert_batch(&uow, &[event])` instead |
| `siem_connector.rs:304` | `test_new_with_in_memory_db` | `SiemConnector::load_config` reads seed row | Must update: `load_config` becomes `SiemConfigRepository::get(pool)` |
| `siem_connector.rs:318` | `test_relay_events_empty_is_noop` | empty relay short-circuits | No DB change — keep as-is |
| `alert_router.rs:471` | `test_load_config_roundtrip` | `AlertRouter::load_config` reads updated row | Must update: `load_config` → `AlertRouterConfigRepository::get(pool)` |
| `alert_router.rs:515` | `test_load_config_port_overflow` | port out-of-range → error | Must update |
| `alert_router.rs:589` | `test_hot_reload` | config change visible on re-read | Must update |
| `alert_router.rs:446` | `test_alert_router_disabled_default` | default config is no-op | No direct DB call — no change |

### Tests that test via HTTP (integration tests on full router)

All tests in `admin_api.rs` from line 1621 onward use `spawn_admin_app()` (which calls
`db::new_pool`) and fire HTTP requests via `tower::ServiceExt::oneshot`. These tests do NOT
call DB methods directly — they go through handlers. After migration, these tests continue
to work unchanged if handler behavior is preserved. The only risk is if a handler panics or
returns a different error due to the repository layer.

**Two tests that read the DB directly after HTTP calls:**
- `admin_api.rs:1865` — `pool.get().expect(...)` + raw SQL to verify insert. After migration this
  can remain as a direct pool access (it's in test code, not `#[cfg(not(test))]` restricted).
- `admin_api.rs:1972` — same pattern.

These are test helpers that bypass the repository layer intentionally (test assertions). They
can stay as-is.

---

## Question 6: AppError Variants

[VERIFIED: lib.rs:64–141]

```rust
pub enum AppError {
    Database(#[from] rusqlite::Error),   // line 67 — used for DB failures
    Json(#[from] serde_json::Error),     // line 72
    Internal(#[from] anyhow::Error),     // line 76
    NotFound(String),                    // line 80
    BadRequest(String),                  // line 84
    Unauthorized(String),                // line 88
}

impl From<r2d2::Error> for AppError {    // line 137
    fn from(e: r2d2::Error) -> Self {
        AppError::Internal(anyhow::anyhow!("pool error: {e}"))
    }
}
```

**There is NO `AppError::Pool` variant.** The CONTEXT.md at line 102 shows:
```rust
let mut conn = pool.get().map_err(AppError::Pool)?;
```
This is **incorrect** — `AppError::Pool` does not exist. The correct form is:
```rust
let mut conn = pool.get().map_err(AppError::from)?;
```
which maps `r2d2::Error` → `AppError::Internal`. The planner must use `AppError::from`
(or `|e| AppError::Internal(anyhow::anyhow!("pool error: {e}"))`) not `AppError::Pool`.

**`AppError::Database` is confirmed** — it wraps `rusqlite::Error` via `#[from]`. Repository
methods returning `rusqlite::Result<T>` will map at call sites with
`.map_err(AppError::Database)` or `.map_err(AppError::from)` (both work because
`From<rusqlite::Error> for AppError` is implemented via `#[from]`).

---

## Question 7: spawn_blocking Call Patterns

### Pattern A: Standard handler pattern (most common)

All 43 of the 49 call sites follow this shape:

```rust
let pool = Arc::clone(&state.pool);
// ... capture other values ...
let result = tokio::task::spawn_blocking(move || -> Result<T, AppError> {
    let conn = pool.get().map_err(AppError::from)?;
    // raw SQL here
    Ok(result_value)
})
.await
.map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;
```

After migration, the only change is replacing `pool.get()` + raw SQL with repository calls:

```rust
// READ pattern (Decision D):
let result = tokio::task::spawn_blocking(move || -> Result<T, AppError> {
    let rows = SomeRepository::list_foo(&pool).map_err(AppError::from)?;
    Ok(rows)
})
.await
.map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

// WRITE pattern (Decision C):
let result = tokio::task::spawn_blocking(move || -> Result<(), AppError> {
    let mut conn = pool.get().map_err(AppError::from)?;
    let uow = UnitOfWork::new(&mut *conn).map_err(AppError::from)?;
    SomeRepository::insert_foo(&uow, &data).map_err(AppError::from)?;
    uow.commit().map_err(AppError::from)?;
    Ok(())
})
.await
.map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;
```

### Pattern B: Sync startup functions (NOT in spawn_blocking)

`admin_auth::has_admin_users` (line 344) and `admin_auth::create_admin_user` (line 360)
are called from `main.rs` during server startup. They receive `&crate::db::Pool` directly.
They do NOT use `spawn_blocking`. After migration:

```rust
// has_admin_users stays sync, receives &Pool
pub fn has_admin_users(pool: &crate::db::Pool) -> anyhow::Result<bool> {
    AdminUserRepository::count(pool)
        .map(|n| n > 0)
        .map_err(|e| anyhow::anyhow!("failed to query admin_users: {e}"))
}
```

### Pattern C: Sync hot-reload reads (NOT in spawn_blocking)

`AlertRouter::load_config` and `SiemConnector::load_config` are synchronous methods called
from async contexts. They call `pool.get()` then do a single-row SELECT. After migration:

```rust
fn load_config(&self) -> Result<AlertRouterConfigRow, AlertError> {
    AlertRouterConfigRepository::get(&self.pool)
        .map_err(AlertError::from)
}
```

The repository method `AlertRouterConfigRepository::get(pool: &Pool)` acquires the connection
internally. This is identical to the read pattern in Decision D.

### Pattern D: Background sweeper (spawn_blocking inside tokio::spawn)

`agent_registry::spawn_offline_sweeper` (lines 271–305) uses `tokio::spawn` + `spawn_blocking`
inside a loop. After migration, the UPDATE becomes a UoW write:

```rust
let result = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
    let cutoff = (Utc::now() - chrono::Duration::seconds(90)).to_rfc3339();
    let mut conn = pool.get().map_err(AppError::from)?;
    let uow = UnitOfWork::new(&mut *conn).map_err(AppError::from)?;
    let rows = AgentRepository::mark_stale_offline(&uow, &cutoff).map_err(AppError::from)?;
    uow.commit().map_err(AppError::from)?;
    Ok(rows)
})
.await;
```

### Pattern E: Multi-SQL in one spawn_blocking (special cases)

**`update_policy` (admin_api.rs:630–673):** UPDATE followed by SELECT version in one closure.
After migration, both operations share one `UnitOfWork`. The SELECT can be a read inside the
transaction via `uow.tx.query_row(...)` directly, since transactions support reads.

**`update_alert_config_handler` (admin_api.rs:1003–1046):** SELECT (mask check) + UPDATE in
one closure. Must stay in one UoW to preserve atomicity. The repository method should
encapsulate both operations as `AlertRouterConfigRepository::update_with_secret_preservation(uow, payload)`.

**`ingest_events` (audit_store.rs:131–191):** Currently uses `conn.unchecked_transaction()`
directly. After migration, replace with `UnitOfWork::new(&mut *conn)`. The `unchecked_transaction()`
call bypasses the borrow checker — `UnitOfWork::new` does not, which is strictly safer.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Transaction RAII | Custom Drop impl with raw SQL | `rusqlite::Transaction` (already in `UnitOfWork`) | rusqlite's `Transaction::commit()` is already RAII |
| Connection pooling | Custom pool | `r2d2` + `r2d2_sqlite` (already in Cargo.toml) | Already used |
| Lazy connection | `Option<Connection>` field | `pool.get()` at call site | Pooled connections are already lazy |
| Migration framework | Custom schema versioning | Current `init_tables()` + `IF NOT EXISTS` | No migrations needed in this phase |

---

## Common Pitfalls

### Pitfall 1: `AppError::Pool` does not exist

**What goes wrong:** Implementing CONTEXT.md code snippet verbatim at line 102 fails to compile.
**Why:** `AppError` has `Internal` (wraps `anyhow::Error`) for pool errors, not a `Pool` variant.
**How to avoid:** Use `pool.get().map_err(AppError::from)?` which uses `From<r2d2::Error> for AppError`.
**Warning signs:** Compiler error `no variant named Pool on AppError`.

### Pitfall 2: `UnitOfWork` lifetime escapes `spawn_blocking` closure

**What goes wrong:** Attempting to construct `UnitOfWork` outside the `spawn_blocking` closure
and move it in will fail with lifetime errors because `Transaction<'conn>` is not `'static`.
**Why:** The lifetime is tied to the `Connection`, which lives on the stack inside the closure.
**How to avoid:** Always construct `conn` and `uow` inside the same closure scope.
**Warning signs:** Compiler errors about `'conn` not living long enough or `T: 'static` bounds.

### Pitfall 3: `store_events_sync` takes `&Connection`, not `&Pool`

**What goes wrong:** Trying to call `audit_store::store_events_sync` with the new
`AuditEventRepository` API — the current signature is `fn store_events_sync(conn: &rusqlite::Connection, events: &[AuditEvent])`.
After migration this function is replaced by `AuditEventRepository::insert_batch(uow, events)`.
Callers in `admin_auth.rs` and `admin_api.rs` currently call `store_events_sync(&conn, ...)` inside
their own `spawn_blocking` closures — they will need to pass `&uow` instead and ensure the
audit insert is inside the same UoW as the primary write, or a separate UoW.
**How to avoid:** Decide upfront whether audit inserts share the primary UoW or use a second UoW.

### Pitfall 4: `alert_router` and `siem_connector` must NOT use `spawn_blocking`

**What goes wrong:** Wrapping `load_config` in `spawn_blocking` during migration breaks the
hot-reload semantics — the call would block the blocking thread pool for a single-row read,
and more critically, these are called from fire-and-forget async tasks where the calling
convention is synchronous.
**How to avoid:** Keep `AlertRouterConfigRepository::get` and `SiemConfigRepository::get`
as sync methods callable from async context (they're quick single-row SELECTs).

### Pitfall 5: `agent_credentials` table missing from CONTEXT.md repository map

**What goes wrong:** Wave 1 stubs do not include `CredentialsRepository`, then Wave 3
migration of `admin_api.rs` has no repository to call for `agent_credentials`.
**How to avoid:** Add `db/repositories/credentials.rs` → `CredentialsRepository` to the
Wave 1 stub list.

### Pitfall 6: `parse_agent_config_row` helper function in `admin_api.rs`

**What goes wrong:** `parse_agent_config_row` (admin_api.rs:1075) parses a `rusqlite::Row`
into `AgentConfigPayload`. This helper is tightly coupled to the specific column order of
two different SELECTs. After migration, this logic must move into `AgentConfigRepository`
as a private helper (or be inlined into the two query methods).
**How to avoid:** Copy `parse_agent_config_row` verbatim into `db/repositories/agent_config.rs`
as a private `fn parse_row(row: &rusqlite::Row) -> rusqlite::Result<AgentConfigPayload>`.

---

## Code Examples

### UnitOfWork (from CONTEXT.md, verified against rusqlite API)

```rust
// db/unit_of_work.rs
pub struct UnitOfWork<'conn> {
    pub(crate) tx: rusqlite::Transaction<'conn>,
}

impl<'conn> UnitOfWork<'conn> {
    pub fn new(conn: &'conn mut rusqlite::Connection) -> rusqlite::Result<Self> {
        Ok(Self { tx: conn.transaction()? })
    }

    pub fn commit(self) -> rusqlite::Result<()> {
        self.tx.commit()
    }
    // Drop impl is automatic — Transaction rolls back on drop without commit
}
```

### Repository read pattern

```rust
// db/repositories/agents.rs
impl AgentRepository {
    pub fn list_agents(pool: &crate::db::Pool) -> rusqlite::Result<Vec<AgentInfoResponse>> {
        let conn = pool.get().map_err(|e| {
            rusqlite::Error::ToSqlConversionFailure(Box::new(e))
        })?;
        let mut stmt = conn.prepare(
            "SELECT agent_id, hostname, ip, os_version, agent_version, \
                    last_heartbeat, status, registered_at \
             FROM agents ORDER BY hostname",
        )?;
        let rows = stmt
            .query_map([], |row| Ok(AgentInfoResponse {
                agent_id: row.get(0)?,
                hostname: row.get(1)?,
                // ...
            }))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
}
```

### Repository write pattern

```rust
// db/repositories/agents.rs
impl AgentRepository {
    pub fn upsert_agent(
        uow: &UnitOfWork<'_>,
        agent_id: &str,
        hostname: &str,
        // ... other fields
    ) -> rusqlite::Result<()> {
        uow.tx.execute(
            "INSERT INTO agents (...) VALUES (...)
             ON CONFLICT(agent_id) DO UPDATE SET ...",
            rusqlite::params![agent_id, hostname, ...],
        )?;
        Ok(())
    }
}
```

### Call site after migration (write)

```rust
// In agent_registry::register_agent handler:
let pool = Arc::clone(&state.pool);
let info = tokio::task::spawn_blocking(move || -> Result<AgentInfoResponse, AppError> {
    let mut conn = pool.get().map_err(AppError::from)?;
    let uow = UnitOfWork::new(&mut *conn).map_err(AppError::from)?;
    AgentRepository::upsert_agent(&uow, &agent_id, &hostname, ...).map_err(AppError::from)?;
    uow.commit().map_err(AppError::from)?;
    Ok(AgentInfoResponse { agent_id, hostname, ... })
})
.await
.map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;
```

---

## Runtime State Inventory

This phase is a code-only refactor. No stored data changes, no service config changes,
no OS-registered state, no secrets, no build artifacts are renamed or modified.

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | None — no schema changes, no data migrations | None |
| Live service config | None — no endpoint changes, no config key renames | None |
| OS-registered state | None | None |
| Secrets/env vars | None — JWT_SECRET and other env vars unchanged | None |
| Build artifacts | None — crate name unchanged, no package renames | None |

---

## Environment Availability

Step 2.6: SKIPPED — this phase has no external dependencies beyond the project's own code.
All required tools (cargo, rustc, r2d2, rusqlite) are already in use and confirmed by
successful Phase 10 compilation.

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Rust built-in `#[test]` + `tokio::test` |
| Config file | none — uses `cargo test` |
| Quick run command | `cargo test -p dlp-server -- --test-thread=1` |
| Full suite command | `cargo test --workspace` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| Wave 1 | db/ submodule compiles | build | `cargo build -p dlp-server` | Wave 0 creates files |
| Wave 1 | All tables still created via new_pool | unit | `cargo test -p dlp-server db::` | Existing: `db.rs` tests |
| Wave 2 | agent_registry handlers behavior unchanged | integration | `cargo test -p dlp-server agent_registry::` | Existing |
| Wave 2 | audit_store handlers behavior unchanged | integration | `cargo test -p dlp-server audit_store::` | Existing |
| Wave 2 | exception_store handlers behavior unchanged | unit | `cargo test -p dlp-server exception_store::` | Existing |
| Wave 2 | alert_router config round-trip works | unit | `cargo test -p dlp-server alert_router::` | Existing |
| Wave 2 | siem_connector config loads from DB | unit | `cargo test -p dlp-server siem_connector::` | Existing |
| Wave 2 | admin_auth login + password change work | unit | `cargo test -p dlp-server admin_auth::` | Existing |
| Wave 3 | Policy CRUD via HTTP round-trips | integration | `cargo test -p dlp-server admin_api::` | Existing |
| Wave 3 | Alert config ME-01 masking preserved | integration | `cargo test -p dlp-server admin_api::tests::test_put_alert_config_preserves_masked_secret` | Existing |
| Phase gate | Full suite passes | all | `cargo test --workspace` | Existing |

### Sampling Rate

- **Per task commit:** `cargo test -p dlp-server -- --test-threads=1`
- **Per wave merge:** `cargo clippy -p dlp-server -- -D warnings && cargo test --workspace`
- **Phase gate:** `cargo test --workspace` green before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] `dlp-server/src/db/mod.rs` — placeholder for Pool/Connection types (Wave 1 creates)
- [ ] `dlp-server/src/db/unit_of_work.rs` — UnitOfWork struct (Wave 1 creates)
- [ ] `dlp-server/src/db/repositories/mod.rs` — re-exports (Wave 1 creates)
- [ ] `dlp-server/src/db/repositories/agents.rs` — stub (Wave 1 creates)
- [ ] `dlp-server/src/db/repositories/policies.rs` — stub (Wave 1 creates)
- [ ] `dlp-server/src/db/repositories/audit_events.rs` — stub (Wave 1 creates)
- [ ] `dlp-server/src/db/repositories/exceptions.rs` — stub (Wave 1 creates)
- [ ] `dlp-server/src/db/repositories/admin_users.rs` — stub (Wave 1 creates)
- [ ] `dlp-server/src/db/repositories/ldap_config.rs` — stub (Wave 1 creates)
- [ ] `dlp-server/src/db/repositories/siem_config.rs` — stub (Wave 1 creates)
- [ ] `dlp-server/src/db/repositories/alert_router_config.rs` — stub (Wave 1 creates)
- [ ] `dlp-server/src/db/repositories/agent_config.rs` — stub (Wave 1 creates)
- [ ] `dlp-server/src/db/repositories/credentials.rs` — stub for `agent_credentials` table (Wave 1 creates; missing from CONTEXT.md map)

---

## Security Domain

This is a pure refactor with no new attack surface. ASVS categories not re-evaluated.
Existing security controls are unchanged:

- ME-01 (alert secret masking) — logic stays in `update_alert_config_handler`, not in the repository layer
- TM-02 (webhook URL SSRF validation) — logic stays in `validate_webhook_url` in `admin_api.rs`
- JWT auth — no changes to `admin_auth.rs` auth middleware

The only security-relevant concern: the SELECT+UPDATE pattern in `update_alert_config_handler`
that prevents TOCTOU on secret masking must remain in a single UoW to preserve atomicity.
Document this in the Wave 3 plan explicitly.

---

## Open Questions

1. **Handler response types vs. repository record types**
   - What we know: current types like `AgentInfoResponse` and `Exception` are defined in handler files and map 1-to-1 to DB columns.
   - What's unclear: should repositories return these handler types directly, or should new `db/repositories/` record types be introduced?
   - Recommendation: reuse existing handler types (Option A) to avoid duplication. If the planner introduces new record structs, they must mirror the handler types exactly.

2. **`agent_credentials` repository gap**
   - What we know: the `agent_credentials` table has 2 handler call sites in `admin_api.rs` but is not in the CONTEXT.md repository map.
   - What's unclear: should it be `CredentialsRepository` or `AgentCredentialsRepository`?
   - Recommendation: name it `CredentialsRepository` in `db/repositories/credentials.rs` — it's a generic key-value table.

3. **Audit inserts co-located with primary writes**
   - What we know: `create_policy`, `update_policy`, `delete_policy`, and `change_password` each do a primary write + an audit insert in separate `spawn_blocking` closures today.
   - What's unclear: should the audit insert share the same `UnitOfWork` as the primary write (fully atomic) or use a separate second UoW?
   - Recommendation: keep them as separate UoWs in separate `spawn_blocking` closures (matches current structure, minimizes scope of Wave 3). Atomicity between policy writes and audit inserts is not currently guaranteed and nothing in CONTEXT.md requires it.

4. **`main.rs::load_ldap_config` not in scope but violates Decision A**
   - What we know: `main.rs:43` uses raw SQL on `ldap_config`, which is outside the 7 in-scope files.
   - What's unclear: should this be migrated as part of Wave 1 (when `LdapConfigRepository` is created)?
   - Recommendation: yes, migrate `load_ldap_config` to use `LdapConfigRepository::get(pool)` in Wave 1 since the repository will exist and the function is simple.

---

## Sources

### Primary (HIGH confidence)

- [VERIFIED: codebase] `dlp-server/src/db.rs` — full file read, all tables and `init_tables()` catalogued
- [VERIFIED: codebase] `dlp-server/src/lib.rs` — all `AppError` variants confirmed, `AppError::Pool` does NOT exist
- [VERIFIED: codebase] `dlp-server/src/admin_api.rs` — all 23 production `pool.get()` call sites enumerated by line number
- [VERIFIED: codebase] `dlp-server/src/admin_auth.rs` — 5 call sites enumerated
- [VERIFIED: codebase] `dlp-server/src/agent_registry.rs` — 5 call sites enumerated
- [VERIFIED: codebase] `dlp-server/src/alert_router.rs` — 1 production call site confirmed sync (non-spawn_blocking)
- [VERIFIED: codebase] `dlp-server/src/audit_store.rs` — 4 call sites enumerated, `store_events_sync` signature confirmed
- [VERIFIED: codebase] `dlp-server/src/exception_store.rs` — 3 call sites enumerated
- [VERIFIED: codebase] `dlp-server/src/siem_connector.rs` — 1 production call site confirmed sync
- [VERIFIED: codebase] `dlp-server/src/main.rs` — `load_ldap_config` raw SQL confirmed
- [VERIFIED: codebase] `dlp-server/Cargo.toml` — r2d2 0.8, r2d2_sqlite 0.33, rusqlite 0.39 confirmed
- [VERIFIED: CONTEXT.md] All locked decisions read and reproduced accurately

---

## Metadata

**Confidence breakdown:**
- SQL migration map: HIGH — all 49 call sites located by line number from direct codebase read
- Lifetime analysis: HIGH — based on rusqlite Transaction API and existing CONTEXT.md notes
- DB model types: HIGH — all types verified in source files
- init_tables migration: HIGH — trivial rename, verified by lib.rs module system rules
- Existing tests: HIGH — all test functions enumerated by name and line

**Research date:** 2026-04-15
**Valid until:** Indefinite — this research describes the codebase as-is; only changes invalidated by code modifications
