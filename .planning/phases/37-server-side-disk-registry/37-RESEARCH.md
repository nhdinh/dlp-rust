# Phase 37: Server-Side Disk Registry - Research

**Researched:** 2026-05-04
**Domain:** Axum REST API, SQLite repository, audit events, agent config push
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Agent sync mechanism**
- D-01: Disk registry entries scoped to `(agent_id, instance_id)`. A disk allowlisted on machine-A is NOT allowlisted on machine-B (physical relocation attack prevention).
- D-02: POST and DELETE handlers trigger an immediate config push to the target `agent_id` after DB write completes. Existing `config_push` mechanism is reused.
- D-03: Agent receives a config push with updated `disk_allowlist`, reloads `DiskEnumerator.instance_id_map` in memory and writes new TOML to disk. No service restart required.

**Table schema and POST semantics**
- D-04: Primary key is server-generated UUID string. Unique constraint on `(agent_id, instance_id)`.
- D-05: POST `/admin/disk-registry` performs a pure INSERT. Duplicate `(agent_id, instance_id)` returns 409 Conflict. No silent upsert.
- D-06: No FK validation on `agent_id`. Server accepts any string (allows pre-registration). Orphan entries acceptable.

**GET endpoint filtering**
- D-07: `GET /admin/disk-registry` supports optional `?agent_id=` query param. When absent, returns all fleet entries ordered by `registered_at ASC`.

**Audit events (AUDIT-03)**
- D-08: Two new `Action` enum variants in `dlp-common/src/abac.rs`: `DiskRegistryAdd` and `DiskRegistryRemove`, added after `PasswordChange`.
- D-09: Audit event resource field format: `"disk:{instance_id}@{agent_id}"`.
- D-10: Audit events emitted in a separate `tokio::task::spawn_blocking` AFTER the main DB commit (same pattern as `PolicyCreate`/`PolicyDelete`). Audit failure does NOT roll back the registry change.

**encryption_status field**
- D-11: Column renamed from `encrypted` (ADMIN-01) to `encryption_status`. Stores string values: `'fully_encrypted'`, `'partially_encrypted'`, `'unencrypted'`, `'unknown'`. DB-layer CHECK constraint enforces allowed values.
- D-12: REST payload validated server-side with `const VALID_STATUSES: &[&str]` before any DB access. Invalid values return 422 Unprocessable Entity.

### Claude's Discretion

- Column order in `CREATE TABLE`: `id, agent_id, instance_id, bus_type, encryption_status, model, registered_at`
- `registered_at` uses UTC RFC-3339 format (consistent with `created_at` in `device_registry`)
- Config push content: send the full `AgentConfig` (not just `disk_allowlist`)
- `GET /admin/disk-registry` is JWT-protected (recommended)
- `tracing::info!` log content: include `agent_id`, `instance_id`, and action

### Deferred Ideas (OUT OF SCOPE)

- Automatic disk pre-registration from discovery events (requires workflow/UI)
- Batch import of disk registry entries (v0.7.1+)
- Additional GET filters (bus_type, encryption_status, model)
- FK constraint on `agent_id` (could be Phase 38 migration)
- Retroactive audit events for USB device registry
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| ADMIN-01 | Server stores disk registry in SQLite with `agent_id`, `instance_id`, `bus_type`, `encrypted` (renamed to `encryption_status` per D-11), `model`, `registered_at` | `disk_registry` CREATE TABLE in `db/mod.rs::init_tables()`; `DiskRegistryRepository` in new file mirroring `device_registry.rs` |
| ADMIN-02 | Admin can list all registered disks across the fleet via `GET /admin/disk-registry` | `list_disk_registry_handler` in `admin_api.rs`; supports optional `?agent_id=` query param (D-07) |
| ADMIN-03 | Admin can add a disk to the allowlist via `POST /admin/disk-registry` and remove via `DELETE /admin/disk-registry/{id}` | `insert_disk_registry_handler` + `delete_disk_registry_handler`; pure INSERT with 409 on conflict (D-05); immediate config push after DB commit (D-02) |
| AUDIT-03 | Admin override actions (add/remove disk from registry) are emitted as `EventType::AdminAction` audit events | `DiskRegistryAdd`/`DiskRegistryRemove` action variants; resource `"disk:{instance_id}@{agent_id}"`; second `spawn_blocking` after DB commit (D-10) |
</phase_requirements>

---

## Summary

Phase 37 adds a server-side disk registry that allows `dlp-admin` to centrally manage the disk allowlist across the fleet. The server stores disk entries in a new `disk_registry` SQLite table; the admin can list, add, and remove entries via three JWT-protected REST endpoints. After each add or remove, the server triggers a config delivery to the target agent so enforcement changes take effect without a service restart. All add/remove operations emit `EventType::AdminAction` audit events.

The implementation is a close mirror of the existing USB `device_registry` subsystem (`device_registry.rs`, `upsert_device_registry_handler`, `delete_device_registry_handler`), with three critical differences: (1) the insert is a pure INSERT (no `ON CONFLICT DO UPDATE`), returning 409 on duplicate; (2) entries are scoped per `(agent_id, instance_id)` pair; and (3) the handlers trigger a config delivery to the agent after each write.

**Critical finding on config push:** The CONTEXT.md references `config_push.rs` but that file does not exist in the codebase. The existing agent-to-server config delivery mechanism is a **polling loop** in `dlp-agent/src/service.rs::config_poll_loop()`, which calls `GET /agent-config/{agent_id}` periodically. The "immediate config push" in D-02 therefore requires: (a) the server's `GET /agent-config/{id}` endpoint must be extended to include the agent's `disk_allowlist` from the `disk_registry` table, and (b) the agent's `AgentConfigPayload` and `config_poll_loop` must be extended to apply the received `disk_allowlist` to `DiskEnumerator.instance_id_map`. There is no server-initiated push channel; the "immediate" effect comes from having the data available the next time the agent polls (or from the agent re-polling immediately after receiving a signal — which is not currently implemented).

**Primary recommendation:** Follow the `device_registry` template exactly for DB layer and handler structure. Resolve the config push gap by extending `AgentConfigPayload` (server-side) and `AgentConfigPayload` (agent-side) to include `disk_allowlist: Vec<DiskIdentity>`, and extend `config_poll_loop` to update `DiskEnumerator.instance_id_map` when the allowlist changes.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Disk registry CRUD | API / Backend (dlp-server) | — | Persistent state, admin-only write access; agent has no write path to this table |
| REST endpoint auth | API / Backend (dlp-server) | — | JWT middleware already in place; all three endpoints go into `protected_routes` |
| Audit event emission | API / Backend (dlp-server) | — | Post-commit `spawn_blocking` pattern established in `admin_api.rs`; same tier owns all AdminAction events |
| Allowlist delivery to agent | API / Backend (dlp-server) | Agent (dlp-agent) | Server makes data available via `GET /agent-config/{id}`; agent polls and applies |
| In-memory allowlist enforcement | Agent (dlp-agent) | — | `DiskEnumerator.instance_id_map` is the enforcement map; Phase 36 reads it |
| Action enum extension | dlp-common | — | Shared crate; both server and agent depend on it |

---

## Standard Stack

### Core (verified from Cargo.toml in this session)

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| rusqlite | 0.39 | SQLite queries, parameter binding, CHECK constraint enforcement | Project-standard DB layer [VERIFIED: Cargo.toml] |
| r2d2 / r2d2_sqlite | 0.8 / 0.33 | Connection pool | Project-standard pool [VERIFIED: Cargo.toml] |
| axum | 0.8 | HTTP routing, extractors, state sharing | Project-standard web framework [VERIFIED: Cargo.toml] |
| chrono | 0.4 (serde) | `Utc::now().to_rfc3339()` for `registered_at` | All existing timestamps use this [VERIFIED: codebase grep] |
| uuid (workspace) | workspace | `uuid::Uuid::new_v4().to_string()` for `id` | All existing UUIDs use this [VERIFIED: device_registry handler] |
| serde / serde_json (workspace) | workspace | Request/response serialization | Project-wide [VERIFIED: Cargo.toml] |
| dlp-common | path dep | `DiskIdentity`, `Action`, `EventType`, `AuditEvent`, `Classification`, `Decision` | Shared type library [VERIFIED: Cargo.toml] |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| tokio (workspace) | workspace | `spawn_blocking` for all SQLite calls | Mandatory for all DB calls in axum handlers [VERIFIED: all handlers] |
| tracing (workspace) | workspace | `tracing::info!` / `tracing::error!` log lines | Project-standard logging [VERIFIED: CLAUDE.md] |
| parking_lot (workspace) | workspace | `RwLock` on agent side for `DiskEnumerator` | Used by existing `DiskEnumerator` fields [VERIFIED: disk.rs] |

### No New Dependencies

This phase introduces no new dependencies. All needed types, traits, and utilities are available in existing workspace crates.

---

## Architecture Patterns

### System Architecture Diagram

```
Admin Client
    |
    | JWT Bearer
    v
[dlp-server: admin_api.rs]
    |
    |-- POST /admin/disk-registry ────────────────────────────────────────────┐
    |   1. Validate encryption_status allowlist                               |
    |   2. spawn_blocking: UnitOfWork INSERT → disk_registry                 |
    |   3. spawn_blocking: emit AdminAction(DiskRegistryAdd) audit event      |
    |   4. Update GET /agent-config/{id} response (data now in DB)           |
    |   5. Return 201 + DiskRegistryResponse                                  |
    |                                                                          |
    |-- DELETE /admin/disk-registry/{id} ──────────────────────────────────┐  |
    |   1. spawn_blocking: UnitOfWork DELETE → disk_registry               |  |
    |   2. spawn_blocking: emit AdminAction(DiskRegistryRemove) audit event |  |
    |   3. Return 204                                                        |  |
    |                                                                       |  |
    |-- GET /admin/disk-registry?agent_id= ──────────────────────────────┐ |  |
        Authenticated list (all or filtered by agent_id)                 | |  |
                                                                         | |  |
[SQLite: disk_registry table]  <─────────────────────────────────────────┴─┴──┘
    |
    | SELECT disk_allowlist WHERE agent_id = ?
    v
[dlp-server: GET /agent-config/{id}]  ←── [dlp-agent: config_poll_loop, every N secs]
    |                                              |
    | disk_allowlist: Vec<DiskIdentity>            |
    └─────────────────────────────────────────────┘
                                                   |
                               [agent: config_poll_loop applies update]
                                                   |
                               [DiskEnumerator.instance_id_map updated in-place]
                                                   |
                               [AgentConfig::save() writes new TOML]
```

### Recommended Project Structure Changes

```
dlp-common/src/abac.rs
  └── Action enum: add DiskRegistryAdd, DiskRegistryRemove

dlp-server/src/
  ├── db/
  │   ├── mod.rs                              # Add disk_registry CREATE TABLE to init_tables()
  │   └── repositories/
  │       ├── mod.rs                          # pub mod disk_registry; pub use ...
  │       └── disk_registry.rs               # New: DiskRegistryRow, DiskRegistryRepository
  └── admin_api.rs
      ├── DiskRegistryRequest struct (new)
      ├── DiskRegistryResponse struct (new)
      ├── list_disk_registry_handler (new)
      ├── insert_disk_registry_handler (new)
      ├── delete_disk_registry_handler (new)
      ├── get_agent_config_for_agent: extend AgentConfigPayload with disk_allowlist
      └── admin_router: wire 3 new routes into protected_routes

dlp-agent/src/
  ├── server_client.rs
  │   └── AgentConfigPayload: add disk_allowlist field
  └── service.rs
      └── config_poll_loop: apply disk_allowlist from payload to DiskEnumerator
```

### Pattern 1: Pure INSERT with 409 on UNIQUE Conflict

The disk registry uses a pure INSERT (no `ON CONFLICT DO UPDATE`). The existing `upsert` pattern in `device_registry.rs` must NOT be copied verbatim — only `list_all` and `delete_by_id` are reused.

```rust
// Source: adapted from DeviceRegistryRepository (device_registry.rs)
pub fn insert(uow: &UnitOfWork<'_>, row: &DiskRegistryRow) -> rusqlite::Result<()> {
    uow.tx.execute(
        "INSERT INTO disk_registry \
             (id, agent_id, instance_id, bus_type, encryption_status, model, registered_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            row.id,
            row.agent_id,
            row.instance_id,
            row.bus_type,
            row.encryption_status,
            row.model,
            row.registered_at,
        ],
    )?;
    Ok(())
}
```

When the UNIQUE constraint fires, rusqlite returns `Err(rusqlite::Error::SqliteFailure(...))` with extended code `SQLITE_CONSTRAINT_UNIQUE`. The handler must map this to `AppError::Conflict`.

### Pattern 2: UNIQUE Conflict Detection in Handler

```rust
// Source: adapted from create_managed_origin_handler (admin_api.rs)
// Detect UNIQUE constraint violation from rusqlite and map to 409 Conflict.
let result = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
    let mut conn = pool.get().map_err(AppError::from)?;
    let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
    repositories::DiskRegistryRepository::insert(&uow, &row)
        .map_err(|e| {
            // rusqlite surfaces UNIQUE constraint violations as SqliteFailure
            // with error code CONSTRAINT (19) and extended code UNIQUE (2067).
            // Check the string representation as the safest cross-version approach.
            if e.to_string().contains("UNIQUE constraint failed") {
                AppError::Conflict(format!(
                    "disk (agent_id={}, instance_id={}) already registered",
                    row.agent_id, row.instance_id
                ))
            } else {
                AppError::Database(e)
            }
        })?;
    uow.commit().map_err(AppError::Database)?;
    Ok(())
})
.await
.map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;
```

### Pattern 3: Optional Query Param Filtering

For `GET /admin/disk-registry?agent_id=`, the handler uses axum's `Query` extractor:

```rust
// Source: axum 0.8 pattern (ASSUMED — verify Query extractor signature)
#[derive(Deserialize, Default)]
pub struct DiskRegistryFilter {
    pub agent_id: Option<String>,
}

async fn list_disk_registry_handler(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<DiskRegistryFilter>,
) -> Result<Json<Vec<DiskRegistryResponse>>, AppError> {
    // ...
}
```

The repository `list_all` needs a variant that accepts an optional `agent_id` filter:

```rust
// In DiskRegistryRepository
pub fn list_all(pool: &Pool, agent_id_filter: Option<&str>) -> rusqlite::Result<Vec<DiskRegistryRow>> {
    let conn = pool.get().map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    let (sql, params): (&str, Box<dyn rusqlite::ToSql>) = match agent_id_filter {
        Some(id) => (
            "SELECT id, agent_id, instance_id, bus_type, encryption_status, model, registered_at \
             FROM disk_registry WHERE agent_id = ?1 ORDER BY registered_at ASC",
            Box::new(id.to_owned()),
        ),
        None => (
            "SELECT id, agent_id, instance_id, bus_type, encryption_status, model, registered_at \
             FROM disk_registry ORDER BY registered_at ASC",
            Box::new(rusqlite::types::Null),
        ),
    };
    // ...
}
```

Note: The above conditional SQL approach has a type mismatch. Use two separate methods or a conditional SQL string:

```rust
// Cleaner approach: use a single method with dynamic SQL
pub fn list_all(pool: &Pool, agent_id_filter: Option<&str>) -> rusqlite::Result<Vec<DiskRegistryRow>> {
    let conn = pool.get().map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    match agent_id_filter {
        None => {
            let mut stmt = conn.prepare(
                "SELECT id, agent_id, instance_id, bus_type, encryption_status, model, registered_at \
                 FROM disk_registry ORDER BY registered_at ASC"
            )?;
            let rows = stmt.query_map([], |row| { /* ... */ })?;
            rows.collect()
        }
        Some(id) => {
            let mut stmt = conn.prepare(
                "SELECT id, agent_id, instance_id, bus_type, encryption_status, model, registered_at \
                 FROM disk_registry WHERE agent_id = ?1 ORDER BY registered_at ASC"
            )?;
            let rows = stmt.query_map(params![id], |row| { /* ... */ })?;
            rows.collect()
        }
    }
}
```

### Pattern 4: Config Push via get_agent_config_for_agent Endpoint

The CONTEXT.md D-02 refers to "the existing `config_push` mechanism" but `config_push.rs` does not exist. [VERIFIED: `ls dlp-server/src/*.rs` — no config_push.rs found.] The agent-side config delivery is a polling loop (`service.rs::config_poll_loop`) that calls `GET /agent-config/{id}` on a timer.

To achieve the effect of D-02 and D-03, Phase 37 must:

1. **Server side:** Extend `AgentConfigPayload` (in `admin_api.rs`) to include `disk_allowlist: Vec<DiskIdentity>`. The `get_agent_config_for_agent` handler must query `disk_registry` WHERE `agent_id = {id}` and include the entries in the payload.

2. **Agent side:** Extend `AgentConfigPayload` (in `server_client.rs`) to include `disk_allowlist: Vec<DiskIdentity>`. Extend `config_poll_loop` in `service.rs` to detect a changed `disk_allowlist`, call `set_disk_enumerator()` with an updated `DiskEnumerator` (or directly update `DISK_ENUMERATOR.instance_id_map`), and call `AgentConfig::save()`.

The "immediate" effect on the next poll (default 30 seconds) is the only delivery mechanism without a server-initiated push channel. This is architecturally consistent with how all other config changes (`heartbeat_interval_secs`, `monitored_paths`, `ldap_config`) are delivered.

### Anti-Patterns to Avoid

- **Copying `upsert` from `DeviceRegistryRepository`:** Phase 37 requires a pure INSERT. Using `ON CONFLICT DO UPDATE` would silently update an existing entry instead of returning 409. NEVER use `ON CONFLICT DO UPDATE` in `DiskRegistryRepository::insert`.
- **Missing explicit `conn` scope in spawn_blocking:** Every handler with a write + re-read must wrap the write in an explicit `{ ... }` block so the pooled connection is returned before the read re-acquires. See `upsert_device_registry_handler` at line 1657-1668 for the exact pattern.
- **Emitting audit event inside the write transaction:** Audit must be a second `spawn_blocking` call AFTER the first `uow.commit()`. One transaction per `spawn_blocking` call.
- **Putting `GET /admin/disk-registry` in `public_routes`:** Unlike the USB device registry, the disk allowlist is sensitive fleet security data. It goes in `protected_routes` (JWT required). See CONTEXT.md discretion guidance.
- **Overwriting `instance_id_map` wholesale on config push:** The agent should merge — apply only the entries scoped to the agent's own `agent_id`. Entries for other agents must not pollute the local map.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| UUID generation | Custom ID scheme | `uuid::Uuid::new_v4().to_string()` | Already in workspace deps; consistent with all other IDs |
| Timestamp formatting | Custom ISO-8601 | `chrono::Utc::now().to_rfc3339()` | Consistent with `created_at` in `device_registry` |
| Input validation pattern | Custom length check | Copy `upsert_device_registry_handler` length guard + `const VALID_*` pattern | Already reviewed, correct, and tested |
| Conflict error detection | Parsing rusqlite error code numerics | String-based check on `"UNIQUE constraint failed"` | Most robust cross-version approach; used in `create_managed_origin_handler` |
| Config poll scheduling | New polling infrastructure | Extend existing `config_poll_loop` and `AgentConfigPayload` | No new infrastructure needed; just extend the data flowing through existing pipes |

**Key insight:** This phase is a data extension (new table, new endpoints, new fields in existing payload types) — not new infrastructure. Every core pattern is already proven in the codebase.

---

## Common Pitfalls

### Pitfall 1: Missing Pool Connection Scope Guard

**What goes wrong:** `spawn_blocking` calls that write then read (or acquire two connections sequentially) deadlock with a pool `max_size = 5` if the first pooled connection isn't returned before the second is acquired.
**Why it happens:** `r2d2::PooledConnection` holds a checkout until it is dropped. Without an explicit `{ }` block, the write `conn` is still live when the read tries to acquire.
**How to avoid:** Always wrap the write in an explicit scope block: `{ let mut conn = pool.get()?; ... uow.commit()?; } // conn dropped here`. See `upsert_device_registry_handler` lines 1658-1668.
**Warning signs:** Test deadlocks when running with `max_size = 1` in-memory pools.

### Pitfall 2: Copying `upsert` Instead of Writing Pure `insert`

**What goes wrong:** Using `ON CONFLICT DO UPDATE` silently updates an allowlisted disk entry instead of returning 409. This violates D-05 (security allowlists should fail loudly on duplicates) and would let an attacker silently downgrade an encryption_status.
**Why it happens:** `DeviceRegistryRepository::upsert` is the obvious copy template.
**How to avoid:** Write a fresh `INSERT INTO disk_registry ... VALUES (...)` SQL with NO conflict clause. Only `list_all` and `delete_by_id` copy verbatim from `DeviceRegistryRepository`.

### Pitfall 3: Audit Event in Wrong Transaction

**What goes wrong:** If the audit INSERT is in the same `UnitOfWork` as the registry write, a DB error during audit emission would roll back the registry change — violating D-10.
**Why it happens:** Convenience of a single transaction.
**How to avoid:** Two separate `spawn_blocking` calls, each with their own `UnitOfWork`. Audit in the second; registry write in the first.

### Pitfall 4: AgentConfigPayload Missing disk_allowlist on Server Side

**What goes wrong:** The agent polls `GET /agent-config/{id}` but receives no `disk_allowlist` field — config push effectively does nothing for disk enforcement.
**Why it happens:** The `AgentConfigPayload` struct in `admin_api.rs` does not yet have a `disk_allowlist` field, and `get_agent_config_for_agent` does not query `disk_registry`.
**How to avoid:** Add `disk_allowlist: Vec<DiskIdentity>` to both the server-side `AgentConfigPayload` (admin_api.rs line ~260) and the agent-side `AgentConfigPayload` (server_client.rs line ~119). Add a `DiskRegistryRepository::list_by_agent(pool, agent_id)` call inside `get_agent_config_for_agent`.

### Pitfall 5: Agent Overwrites All DiskEnumerator Entries on Config Update

**What goes wrong:** `config_poll_loop` receives the new `disk_allowlist` (scoped to this agent) and replaces the entire `instance_id_map`, losing live-enumerated disks that aren't in the server registry.
**Why it happens:** Simplistic "replace map" implementation.
**How to avoid:** The update should INSERT new entries into `instance_id_map` (i.e., union the server registry with whatever live enumeration found). For delete: remove entries from the map that were in the previous `disk_allowlist` but are absent from the new one.

### Pitfall 6: list_all Ordering Inconsistency

**What goes wrong:** Filtered query (`WHERE agent_id = ?`) returns results in a different order than unfiltered query.
**How to avoid:** Both code paths must use `ORDER BY registered_at ASC` to match D-07 and keep behavior predictable for the Phase 38 TUI.

---

## Code Examples

### disk_registry Table DDL

```sql
-- Source: Canonical from 37-CONTEXT.md specifics section [VERIFIED]
CREATE TABLE IF NOT EXISTS disk_registry (
    id                 TEXT PRIMARY KEY,
    agent_id           TEXT NOT NULL,
    instance_id        TEXT NOT NULL,
    bus_type           TEXT NOT NULL,
    encryption_status  TEXT NOT NULL
                       CHECK(encryption_status IN
                             ('fully_encrypted', 'partially_encrypted',
                              'unencrypted', 'unknown')),
    model              TEXT NOT NULL DEFAULT '',
    registered_at      TEXT NOT NULL,
    UNIQUE(agent_id, instance_id)
);
```

Place this inside `init_tables()` in `db/mod.rs`, appended after the `device_registry` block.

### DiskRegistryRow and DiskRegistryRepository Skeleton

```rust
// Source: Adapted from device_registry.rs [VERIFIED in this session]
use rusqlite::params;
use crate::db::{Pool, UnitOfWork};

pub struct DiskRegistryRow {
    pub id: String,
    pub agent_id: String,
    pub instance_id: String,
    pub bus_type: String,
    pub encryption_status: String,
    pub model: String,
    pub registered_at: String,
}

pub struct DiskRegistryRepository;

impl DiskRegistryRepository {
    pub fn list_all(pool: &Pool, agent_id_filter: Option<&str>) -> rusqlite::Result<Vec<DiskRegistryRow>> { /* ... */ }
    pub fn insert(uow: &UnitOfWork<'_>, row: &DiskRegistryRow) -> rusqlite::Result<()> { /* pure INSERT */ }
    pub fn delete_by_id(uow: &UnitOfWork<'_>, id: &str) -> rusqlite::Result<usize> { /* DELETE WHERE id = ?1 */ }
    pub fn list_by_agent(pool: &Pool, agent_id: &str) -> rusqlite::Result<Vec<DiskRegistryRow>> { /* for config push */ }
}
```

### Audit Event Construction

```rust
// Source: 37-CONTEXT.md specifics section [VERIFIED]
let audit_event = dlp_common::AuditEvent::new(
    dlp_common::EventType::AdminAction,
    String::new(),                               // session_id: N/A for server-side admin ops
    username,                                    // from AdminUsername::extract_from_headers
    format!("disk:{}@{}", instance_id, agent_id), // resource
    dlp_common::Classification::T3,
    dlp_common::Action::DiskRegistryAdd,         // or DiskRegistryRemove for DELETE
    dlp_common::Decision::ALLOW,
    "server".to_string(),                        // machine
    0,                                           // pid
);
```

### Extending AgentConfigPayload (server side)

```rust
// Source: admin_api.rs line ~260, extended for Phase 37 [VERIFIED: existing struct structure]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfigPayload {
    pub monitored_paths: Vec<String>,
    pub excluded_paths: Vec<String>,
    pub heartbeat_interval_secs: u64,
    pub offline_cache_enabled: bool,
    pub ldap_config: Option<LdapConfigPayload>,
    // Phase 37: disk allowlist for this agent (queried from disk_registry table)
    #[serde(default)]
    pub disk_allowlist: Vec<dlp_common::DiskIdentity>,
}
```

Note: the agent-side mirror in `server_client.rs` must also add `#[serde(default)] pub disk_allowlist: Vec<DiskIdentity>` to `AgentConfigPayload` for backward-compatible deserialization.

---

## Runtime State Inventory

> This phase adds a new SQLite table; no rename/refactor of existing stored values.

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | No existing `disk_registry` entries (table is new) | None — `CREATE TABLE IF NOT EXISTS` is idempotent |
| Live service config | No existing config references to disk_registry | None — new feature |
| OS-registered state | None | None |
| Secrets/env vars | No new secrets | None |
| Build artifacts | None | None |

**DB migration note:** The new `disk_registry` table is added in `init_tables()` via `CREATE TABLE IF NOT EXISTS`. This is idempotent — safe on all existing deployments. No `run_migrations` ALTER TABLE entry is needed (the table is new, not a column addition).

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| cargo / rustc | Build | Yes | workspace | — |
| SQLite (bundled) | rusqlite feature "bundled" | Yes | 3.x bundled | — |
| dlp-common path dep | Action enum extension | Yes | workspace | — |

No missing dependencies.

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Rust built-in `#[test]` + `#[tokio::test]` |
| Config file | None (cargo test standard) |
| Quick run command | `cargo test -p dlp-server db::repositories::disk_registry` |
| Full suite command | `cargo test --workspace` |

### Phase Requirements -> Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| ADMIN-01 | disk_registry table created with correct schema | unit | `cargo test -p dlp-server test_disk_registry_table` | Wave 0 |
| ADMIN-01 | CHECK constraint rejects invalid encryption_status | unit | `cargo test -p dlp-server test_disk_registry_check_constraint` | Wave 0 |
| ADMIN-01 | UNIQUE(agent_id, instance_id) constraint enforced | unit | `cargo test -p dlp-server test_disk_registry_unique_constraint` | Wave 0 |
| ADMIN-02 | list_all returns all rows ordered by registered_at ASC | unit | `cargo test -p dlp-server test_disk_registry_list_all` | Wave 0 |
| ADMIN-02 | list_all with agent_id filter returns only matching rows | unit | `cargo test -p dlp-server test_disk_registry_list_filtered` | Wave 0 |
| ADMIN-03 | insert creates row and returns 201 | unit | `cargo test -p dlp-server test_insert_disk_registry_handler` | Wave 0 |
| ADMIN-03 | insert on duplicate (agent_id, instance_id) returns 409 | unit | `cargo test -p dlp-server test_insert_disk_registry_conflict` | Wave 0 |
| ADMIN-03 | delete by UUID removes row and returns 204 | unit | `cargo test -p dlp-server test_delete_disk_registry_handler` | Wave 0 |
| ADMIN-03 | delete on missing UUID returns 404 | unit | `cargo test -p dlp-server test_delete_disk_registry_not_found` | Wave 0 |
| AUDIT-03 | DiskRegistryAdd audit event emitted after insert | unit | `cargo test -p dlp-server test_disk_registry_add_audit_event` | Wave 0 |
| AUDIT-03 | DiskRegistryRemove audit event emitted after delete | unit | `cargo test -p dlp-server test_disk_registry_remove_audit_event` | Wave 0 |
| D-12 | invalid encryption_status returns 422 | unit | `cargo test -p dlp-server test_disk_registry_invalid_status` | Wave 0 |
| D-07 | GET without filter returns all entries | unit | `cargo test -p dlp-server test_list_disk_registry_no_filter` | Wave 0 |
| D-03 | agent config_poll_loop applies disk_allowlist update | unit | `cargo test -p dlp-agent test_config_poll_applies_disk_allowlist` | Wave 0 |

### Sampling Rate

- **Per task commit:** `cargo test -p dlp-server db::repositories::disk_registry`
- **Per wave merge:** `cargo test --workspace`
- **Phase gate:** Full suite green before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] `dlp-server/src/db/repositories/disk_registry.rs` — new file covering ADMIN-01/02/03 repository tests
- [ ] Handler tests embedded in `admin_api.rs` `#[cfg(test)]` module — covers all handler-level tests
- [ ] Agent-side `service.rs` config poll update — covers D-03

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | Yes | JWT middleware (`admin_auth::require_auth`) already in place for all protected_routes |
| V3 Session Management | No | Stateless JWT; no session |
| V4 Access Control | Yes | All three disk registry endpoints in `protected_routes`; admin-only operation |
| V5 Input Validation | Yes | `const VALID_STATUSES` allowlist + length guard before DB access (D-12 pattern) |
| V6 Cryptography | No | No crypto operations in this phase |

### Known Threat Patterns

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Unauthenticated disk allowlist modification | Tampering | All write endpoints in `protected_routes` with JWT middleware |
| Malicious `encryption_status` string injection | Tampering | DB CHECK constraint + server-side allowlist validation (D-12); length guard rejects inputs > 32 chars |
| Duplicate entry confusion (pre-register attack) | Tampering | UNIQUE(agent_id, instance_id) + 409 response makes duplicates visible to admin |
| Disk allowlist enumeration by unauthorized caller | Information Disclosure | `GET /admin/disk-registry` in protected_routes (JWT required), not public_routes |
| Physical relocation attack (disk moved machine-A to machine-B) | Tampering | D-01: entries scoped per (agent_id, instance_id); relocated disk not in new machine's allowlist until re-registered |

---

## Open Questions

1. **True "immediate" config push after add/remove (D-02)**
   - What we know: There is no server-initiated push channel. The agent polls on `heartbeat_interval_secs` (default 30s).
   - What's unclear: D-02 says "immediate" — is 30-second-maximum latency acceptable, or does this phase need to add a server-initiated push mechanism?
   - Recommendation: Accept polling latency for this phase. "Immediate" means "next poll cycle" (at most `heartbeat_interval_secs` delay). If true push is needed, that is a separate infrastructure phase. Note in PLAN.md that enforcement takes effect within one poll interval, not instantaneously.

2. **`list_by_agent` for get_agent_config_for_agent**
   - What we know: `get_agent_config_for_agent` currently only reads `global_agent_config` / `agent_config_overrides`. It does not query `disk_registry`.
   - What's unclear: Should the disk_allowlist be included in the unauthenticated `GET /agent-config/{id}` (currently a public route), or is that a security concern?
   - Recommendation: Include it in the public `GET /agent-config/{id}` endpoint. The USB `device_registry` endpoint is also public (agents need to read it without JWT). Disk allowlist data is less sensitive than the full admin registry (which stays behind JWT). This is consistent with the existing pattern.

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `config_push.rs` does not exist; D-02 "immediate config push" means extending `GET /agent-config/{id}` payload | Architecture Patterns / Pattern 4 | If a different push mechanism exists undiscovered, the config delivery approach must be redesigned |
| A2 | `AgentConfigPayload` in `admin_api.rs` can be extended with `disk_allowlist` without breaking existing agent compatibility via `#[serde(default)]` | Code Examples | If older agents fail on unknown fields, a versioned payload wrapper would be needed |
| A3 | `axum::extract::Query` extractor is available in axum 0.8 for optional query params | Architecture Patterns / Pattern 3 | If extractor signature changed in 0.8, handler definition needs adjustment |

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `ON CONFLICT DO UPDATE` (device_registry) | Pure INSERT with 409 (disk_registry) | Phase 37 | Security allowlists fail loudly; no silent mutation of existing entries |
| Unauthenticated GET for agent-readable data | JWT-protected GET for disk allowlist | Phase 37 | Disk allowlist not exposed to unauthenticated callers via admin endpoint |

---

## Sources

### Primary (HIGH confidence)

- `dlp-server/src/db/repositories/device_registry.rs` — direct template for `DiskRegistryRepository`; `list_all`, `delete_by_id`, `upsert` patterns verified in this session
- `dlp-server/src/db/mod.rs` — `init_tables()` and `run_migrations()` structure; all existing tables and migration patterns verified
- `dlp-server/src/admin_api.rs` — `admin_router()`, `protected_routes` structure, `upsert_device_registry_handler`, `delete_device_registry_handler`, `PolicyCreate` audit event pattern (lines 784-805), `AgentConfigPayload` struct; all verified
- `dlp-agent/src/service.rs` — `config_poll_loop`, `set_disk_enumerator` wiring; all verified
- `dlp-agent/src/detection/disk.rs` — `DiskEnumerator` struct, `instance_id_map`, `set_disk_enumerator`; verified
- `dlp-agent/src/config.rs` — `AgentConfig`, `disk_allowlist` field, `save()` method; verified
- `dlp-agent/src/server_client.rs` — `AgentConfigPayload`, `fetch_agent_config()`, `DeviceRegistryEntry`; verified
- `dlp-server/src/lib.rs` — `AppError` variants (Conflict, NotFound, UnprocessableEntity); verified
- `dlp-common/src/abac.rs` — `Action` enum, `PasswordChange` variant (insertion point for D-08); verified
- `.planning/phases/37-server-side-disk-registry/37-CONTEXT.md` — all decisions D-01 through D-12; source of truth for this phase

### Secondary (MEDIUM confidence)

- `.planning/REQUIREMENTS.md` — ADMIN-01/02/03, AUDIT-03 requirement text; verified
- `.planning/phases/35-disk-allowlist-persistence/35-CONTEXT.md` — `disk_allowlist` field origin, `instance_id_map` as enforcement map; verified

### Tertiary (LOW confidence)

- A3: `axum::extract::Query` signature for optional query param in axum 0.8 — inferred from axum 0.7 pattern; not directly verified via Context7 this session

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all library versions and types verified from Cargo.toml and source
- Architecture: HIGH — all patterns verified against actual source files
- Config push gap: HIGH — verified by absence of config_push.rs and by reading config_poll_loop
- Pitfalls: HIGH — all derived from direct code reading of the template files

**Research date:** 2026-05-04
**Valid until:** 2026-06-04 (stable Rust crates, no fast-moving dependencies)
