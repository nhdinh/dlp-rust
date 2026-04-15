# Phase 99: Refactor DB Layer to Repository + Unit of Work — Context

**Gathered:** 2026-04-15
**Status:** Ready for planning
**Source:** /gsd-discuss-phase

<domain>
## Phase Boundary

Refactor the `dlp-server` database layer from scattered `pool.get()` + raw SQL call
sites into a typed Repository + Unit of Work structure. This is a pure structural
refactor — no feature additions, no schema changes, no new endpoints.

**Deliverable:** `dlp-server/src/db/` submodule containing:
- One typed repository struct per entity (all reads + writes via repository methods)
- `UnitOfWork<'conn>` holding a `rusqlite::Transaction` with RAII rollback on drop
- All 49 `pool.get()` call sites across 7 handler files migrated to repository calls
- Existing handler files (`audit_store.rs`, `agent_registry.rs`, etc.) retained as
  the HTTP handler layer; only raw DB logic moves into repositories
- All existing tests pass; no functional behavior changes

**In scope:**
- `dlp-server/src/db/` — new submodule (Pool type, new_pool(), WAL init, all repos, UoW)
- `dlp-server/src/admin_api.rs` — 26 `pool.get()` call sites
- `dlp-server/src/admin_auth.rs` — 5 call sites
- `dlp-server/src/agent_registry.rs` — 5 call sites
- `dlp-server/src/alert_router.rs` — 5 call sites
- `dlp-server/src/audit_store.rs` — 4 call sites
- `dlp-server/src/exception_store.rs` — 3 call sites
- `dlp-server/src/siem_connector.rs` — 1 call site

**Out of scope:**
- Async pool (deadpool) — codebase stays sync via spawn_blocking
- New endpoints or features
- Schema migrations
- Configurable pool size
- New workspace crates

</domain>

<decisions>
## Implementation Decisions

### A — Repository Structure (from Phase 10 Decision I)

One repository struct per entity. All raw SQL is encapsulated inside these structs;
no naked `conn.execute()` or `conn.query_row()` outside `db/repositories/`.

Entities and their repository files:
```
dlp-server/src/db/
    mod.rs                        — Pool type alias, new_pool(), WAL PRAGMA init
    repositories/
        mod.rs                    — re-exports all repos
        agents.rs                 — AgentRepository (CRUD for agents table)
        policies.rs               — PolicyRepository (CRUD for policies table)
        audit_events.rs           — AuditEventRepository (insert + query)
        exceptions.rs             — ExceptionRepository (CRUD for exceptions table)
        admin_users.rs            — AdminUserRepository (auth user management)
        ldap_config.rs            — LdapConfigRepository (single-row config)
        siem_config.rs            — SiemConfigRepository (single-row config)
        alert_router_config.rs    — AlertRouterConfigRepository (single-row config)
        agent_config.rs           — AgentConfigRepository (global + per-agent overrides)
    unit_of_work.rs               — UnitOfWork<'conn> + commit/rollback
```

### B — UnitOfWork (from Phase 10 Decision I)

`UnitOfWork<'conn>` holds a `rusqlite::Transaction<'conn>`. RAII semantics:
dropping without calling `.commit()` auto-rolls back.

```rust
pub struct UnitOfWork<'conn> {
    tx: rusqlite::Transaction<'conn>,
}

impl<'conn> UnitOfWork<'conn> {
    pub fn new(conn: &'conn mut rusqlite::Connection) -> rusqlite::Result<Self> {
        Ok(Self { tx: conn.transaction()? })
    }

    pub fn commit(self) -> rusqlite::Result<()> {
        self.tx.commit()
    }
}
```

Write-side repository methods accept `&UnitOfWork` and use `uow.tx` internally.

### C — All Writes Go Through UoW

**Decision:** Every INSERT, UPDATE, and DELETE must go through `UnitOfWork` — even
single-row writes (e.g., a heartbeat timestamp update). No naked `pool.get()` +
`conn.execute()` on the write path.

Rationale: Consistency. A single rule is easier to audit and enforce than
"UoW for multi-row batches." The overhead for single-row writes is negligible.
This also prevents future callers from accidentally bypassing atomicity guarantees.

Pattern for all write call sites:
```rust
let mut conn = pool.get().map_err(AppError::Pool)?;
let uow = UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
repo.insert_something(&uow, &payload).map_err(AppError::Database)?;
uow.commit().map_err(AppError::Database)?;
```

### D — Read Repositories Take &Pool

**Decision:** Read-only repository methods (SELECTs) take `&Pool` as their first
argument and acquire a connection internally via `pool.get()`.

Rationale: Handlers never need to manage connection lifetimes for reads. Simple,
uniform — one argument to pass. There are no use cases in the current codebase that
require batching multiple reads on a single connection.

Pattern for all read call sites:
```rust
let agents = agent_repo.list_agents(&state.pool).map_err(AppError::Database)?;
```

### E — Fate of Existing Handler Modules

**Decision:** `audit_store.rs`, `agent_registry.rs`, `exception_store.rs`,
`siem_connector.rs`, `admin_auth.rs`, and `admin_api.rs` are retained as handler
modules. Only the raw DB SQL logic is extracted into repositories; HTTP handler code,
request/response types, and business logic stay in the existing files.

Two-layer outcome:
- **DB layer** (`db/repositories/`) — entity types, SQL, typed query results
- **Handler layer** (existing files) — axum extractors, state, routing, response mapping

No files are deleted. No handler routing changes.

### F — Migration Waves (3-Plan Strategy)

**Wave 1 — Build the DB submodule:** Create `dlp-server/src/db/mod.rs`,
`db/repositories/` with all repository stubs, and `db/unit_of_work.rs`. No call site
changes yet. Module compiles but handlers still use pool.get() directly.

**Wave 2 — Migrate small modules:** Update `audit_store.rs`, `agent_registry.rs`,
`exception_store.rs`, `siem_connector.rs`, `admin_auth.rs`, `alert_router.rs` to use
repository methods (49 - 26 = 23 call sites). These files are 250–612 lines each.

**Wave 3 — Migrate admin_api.rs:** The 3235-line file with 26 call sites. Largest
and most complex — done last so the repository API is stable before tackling it.
Separate plan to keep diffs reviewable.

Each wave must compile and pass all tests before the next begins.

### G — Error Mapping

`r2d2::PoolError` already maps to `AppError::Pool` (or similar). `rusqlite::Error`
maps to `AppError::Database`. Repository methods return `rusqlite::Result<T>` or
`anyhow::Result<T>`. Call sites at the handler boundary map to `AppError`.

Repository public methods return `Result<T, rusqlite::Error>` (not anyhow) so the
handler layer stays in control of error conversion.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase architecture decision
- `.planning/phases/10-sqlite-connection-pool/10-CONTEXT.md` — Decision I: Repository +
  Unit of Work architectural intent (original locked decision from Phase 10)

### Current DB infrastructure (post Phase 10)
- `dlp-server/src/db.rs` — current pool implementation, init_tables(), WAL init
- `dlp-server/src/lib.rs` — AppState struct (pool field, error types)
- `dlp-server/Cargo.toml` — existing r2d2 / r2d2_sqlite deps

### All call sites to migrate
- `dlp-server/src/admin_api.rs` — 26 `pool.get()` call sites (Wave 3)
- `dlp-server/src/admin_auth.rs` — 5 call sites (Wave 2)
- `dlp-server/src/agent_registry.rs` — 5 call sites (Wave 2)
- `dlp-server/src/alert_router.rs` — 5 call sites (Wave 2)
- `dlp-server/src/audit_store.rs` — 4 call sites (Wave 2)
- `dlp-server/src/exception_store.rs` — 3 call sites (Wave 2)
- `dlp-server/src/siem_connector.rs` — 1 call site (Wave 2)

### Roadmap
- `.planning/ROADMAP.md` — Phase 99 section

</canonical_refs>

<specifics>
## Specific Implementation Notes

### UnitOfWork lifetime model

`UnitOfWork<'conn>` borrows a `rusqlite::Connection` mutably for its lifetime.
The connection is acquired with `pool.get()` before constructing the UoW:

```rust
// In a spawn_blocking closure:
let mut conn = pool.get().map_err(AppError::Pool)?;
// conn is PooledConnection<SqliteConnectionManager>, which Deref<Target=Connection>
// but to call conn.transaction() we need a &mut Connection:
let uow = UnitOfWork::new(&mut *conn)?;
```

`PooledConnection` derefs to `Connection`, so `&mut *conn` gets the `&mut Connection`
that `transaction()` requires.

### Repository method signatures (canonical patterns)

```rust
// Read repo: takes &Pool
pub fn list_agents(pool: &Pool) -> rusqlite::Result<Vec<AgentRecord>> {
    let conn = pool.get().map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    // ... SELECT ...
}

// Write repo: takes &UnitOfWork
pub fn insert_agent(uow: &UnitOfWork<'_>, record: &AgentRecord) -> rusqlite::Result<()> {
    uow.tx.execute("INSERT INTO agents ...", params![...])?;
    Ok(())
}
```

### Wave 1 output: repository stubs

All repository structs should be created in Wave 1 with at least:
- Struct definition (may be zero-field if stateless)
- One read method
- One write method
This ensures the API design can be validated before bulk migration in Waves 2/3.

### DB table → repository mapping

| Table                     | Repository            |
|---------------------------|-----------------------|
| agents                    | AgentRepository       |
| audit_events              | AuditEventRepository  |
| policies                  | PolicyRepository      |
| exceptions                | ExceptionRepository   |
| admin_users               | AdminUserRepository   |
| ldap_config               | LdapConfigRepository  |
| siem_config               | SiemConfigRepository  |
| alert_router_config       | AlertRouterRepository |
| global_agent_config       | AgentConfigRepository |
| agent_config_overrides    | AgentConfigRepository |

</specifics>

<deferred>
## Deferred Ideas

- Async repositories (deadpool + tokio) — only relevant if the codebase moves to async DB
- Repository trait abstraction for testability with mock repos — consider in Phase 11 (Policy Engine Separation)
- Pool size configurability — deferred from Phase 10, still premature
- Query builder (diesel, sea-query) — raw SQL is fine for this codebase's scale

</deferred>

---

*Phase: 99-refactor-db-layer-to-repository-unit-of-work*
*Context gathered: 2026-04-15 via /gsd-discuss-phase*
