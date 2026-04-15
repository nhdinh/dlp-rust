# Plan 02: Migrate Small Modules (23 Call Sites)

**Phase:** 99 -- Refactor DB Layer to Repository + Unit of Work
**Wave:** 2
**Prereq:** Plan 01 passes all tests (db/ submodule compiles, UoW tests green)

## Goal

Migrate all 23 `pool.get()` + raw SQL call sites in the 6 small handler modules to use
the repository structs created in Wave 1. After this wave, the only remaining raw SQL
outside `db/repositories/` is in `admin_api.rs` (26 sites, handled in Wave 3).

Modules migrated (in recommended order):
1. `siem_connector.rs` (1 call site) -- smallest, warm-up
2. `alert_router.rs` (1 call site in production) -- similar hot-reload pattern
3. `audit_store.rs` (4 call sites) -- includes the `store_events_sync` special case
4. `exception_store.rs` (3 call sites) -- straightforward CRUD
5. `agent_registry.rs` (5 call sites) -- includes background sweeper
6. `admin_auth.rs` (5 call sites) -- includes startup sync functions + password handling

Each module must compile and pass tests before moving to the next. The calling patterns
(spawn_blocking vs. direct sync) must be preserved exactly -- do NOT wrap hot-reload reads
in spawn_blocking.

## Threat Model

| Threat | Severity | Mitigation |
|--------|----------|------------|
| SQL injection via string interpolation during migration | medium | All repository methods use `rusqlite::params![]`. Verify no `format!()` appears in any SQL string within `db/repositories/`. |
| Auth hash exposure in error messages | medium | `AdminUserRepository::get_password_hash` returns `rusqlite::Result<String>`. Error variant is `QueryReturnedNoRows` -- does not contain the hash. No `tracing::error!` or `tracing::debug!` call logs the hash value. |
| Transaction isolation on password change | low | `change_password` UPDATE goes through `UnitOfWork`. Single-row UPDATE is already atomic in SQLite, but UoW ensures consistency with the pattern. |
| Hot-reload call sites wrapped in spawn_blocking (performance regression) | medium | `siem_connector::load_config` and `alert_router::load_config` must NOT be wrapped in spawn_blocking after migration. They call `pool.get()` directly. Verify by confirming no `spawn_blocking` wraps the repository read call in those files. |

## Tasks

### Task 2-01: Migrate siem_connector.rs (1 call site)

**File:** `dlp-server/src/siem_connector.rs`
**Action:** EDIT
**Why:** `SiemConnector::load_config` at line 120 has raw SQL reading siem_config.

Replace the raw SQL in `load_config` with `SiemConfigRepository::get(&self.pool)`.

The `SiemConfigRow` struct currently defined privately in `siem_connector.rs` (lines 37-46)
stays in the handler file per Decision E. The `SiemConfigRepository::get()` returns the
repository's own `SiemConfigRow` type from `db/repositories/siem_config.rs`. The handler
maps the repo row to its local `SiemConfigRow`.

Alternatively (simpler): make the handler's `SiemConfigRow` directly constructable from the
repo's row type. The cleanest approach is to have the handler import the repo's row type
and use it directly, removing the duplicate struct. The handler's `SiemConfigRow` can be
deleted and replaced by the repo's version if the fields match exactly.

**Before:**
```rust
fn load_config(&self) -> Result<SiemConfigRow, SiemError> {
    let conn = self.pool.get().map_err(SiemError::from)?;
    let row = conn.query_row(
        "SELECT splunk_url, ...",
        [],
        |r| { ... },
    )?;
    Ok(row)
}
```

**After:**
```rust
use crate::db::repositories::SiemConfigRepository;

fn load_config(&self) -> Result<SiemConfigRow, SiemError> {
    let row = SiemConfigRepository::get(&self.pool)?;
    Ok(SiemConfigRow {
        splunk_url: row.splunk_url,
        splunk_token: row.splunk_token,
        splunk_enabled: row.splunk_enabled,
        elk_url: row.elk_url,
        elk_index: row.elk_index,
        elk_api_key: row.elk_api_key,
        elk_enabled: row.elk_enabled,
    })
}
```

**CRITICAL:** Do NOT wrap in `spawn_blocking`. The existing pattern is deliberately
synchronous (single-row hot-reload read). The `SiemConfigRepository::get()` takes `&Pool`
and acquires a connection internally -- same pattern as before.

The `From<r2d2::Error> for SiemError` impl at line 95 stays because pool errors can
still occur inside the repository's `pool.get()` call, surfacing as
`rusqlite::Error::ToSqlConversionFailure`. However, the `From<rusqlite::Error> for SiemError`
at line 83 already covers this path. Verify tests still pass.

<verify>
cargo test -p dlp-server --lib siem 2>&1 | tail -10
</verify>

---

### Task 2-02: Migrate alert_router.rs (1 call site)

**File:** `dlp-server/src/alert_router.rs`
**Action:** EDIT
**Why:** `AlertRouter::load_config` at line 155 has raw SQL reading alert_router_config.

Same pattern as Task 2-01. Replace raw SQL with `AlertRouterConfigRepository::get(&self.pool)`.

**Before:**
```rust
fn load_config(&self) -> Result<AlertRouterConfigRow, AlertError> {
    let conn = self.pool.get().map_err(AlertError::from)?;
    let row = conn.query_row("SELECT smtp_host, ...", [], |r| { ... })?;
    Ok(row)
}
```

**After:**
```rust
use crate::db::repositories::AlertRouterConfigRepository;

fn load_config(&self) -> Result<AlertRouterConfigRow, AlertError> {
    let row = AlertRouterConfigRepository::get(&self.pool)?;
    Ok(AlertRouterConfigRow {
        smtp_host: row.smtp_host,
        smtp_port: row.smtp_port,
        smtp_username: row.smtp_username,
        smtp_password: row.smtp_password,
        smtp_from: row.smtp_from,
        smtp_to: row.smtp_to,
        smtp_enabled: row.smtp_enabled,
        webhook_url: row.webhook_url,
        webhook_secret: row.webhook_secret,
        webhook_enabled: row.webhook_enabled,
    })
}
```

The `smtp_port` is stored as `i64` in the DB and must be converted to `u16` in the
repository layer (same conversion currently at alert_router.rs lines 164-169). Move this
validation into `AlertRouterConfigRepository::get()`.

**CRITICAL:** Do NOT wrap in `spawn_blocking`. Same rationale as siem_connector.

<verify>
cargo test -p dlp-server --lib alert_router 2>&1 | tail -10
</verify>

---

### Task 2-03: Migrate audit_store.rs (4 call sites)

**File:** `dlp-server/src/audit_store.rs`
**Action:** EDIT
**Why:** 4 call sites: store_events_sync (raw conn), ingest_events (spawn_blocking),
query_events (spawn_blocking), get_event_count (spawn_blocking).

**Migration details per call site:**

**1. `store_events_sync` (lines 59-93):**
This function takes `&rusqlite::Connection` directly. After migration, the function
signature changes to accept `&UnitOfWork<'_>` and delegates to
`AuditEventRepository::insert_batch(uow, rows)`. The JSON serialization of enum fields
(`event_type`, `classification`, `action_attempted`, `decision`, `access_context`) stays
in this function -- the repository receives pre-serialized `&str` values.

The function still exists as a public helper in `audit_store.rs` but becomes a thin
wrapper:

```rust
pub fn store_events_sync(
    uow: &UnitOfWork<'_>,
    events: &[AuditEvent],
) -> Result<(), AppError> {
    // Pre-serialize enum fields (JSON serialization stays in handler layer)
    let rows: Vec<AuditEventInsertRow> = events.iter().map(|event| {
        let event_type = serde_json::to_string(&event.event_type)?;
        let classification = serde_json::to_string(&event.classification)?;
        let action = serde_json::to_string(&event.action_attempted)?;
        let decision = serde_json::to_string(&event.decision)?;
        let access_ctx = serde_json::to_string(&event.access_context)?;
        Ok(AuditEventInsertRow { /* fields */ })
    }).collect::<Result<Vec<_>, serde_json::Error>>()?;
    AuditEventRepository::insert_batch(uow, &rows)
        .map_err(AppError::Database)?;
    Ok(())
}
```

Define `AuditEventInsertRow` in the repository as a struct with all pre-serialized string
fields (timestamp, event_type, user_sid, user_name, resource_path, classification,
action_attempted, decision, policy_id, policy_name, agent_id, session_id, access_context,
correlation_id).

**2. `ingest_events` (lines 110-232):**
Currently uses `conn.unchecked_transaction()`. After migration, use `UnitOfWork::new(&mut *conn)`.
The JSON serialization loop (lines 140-159) stays in the handler and produces the same
pre-serialized row data. Pass it to `AuditEventRepository::insert_batch(uow, &rows)`.
Then `uow.commit()`.

```rust
let pool = Arc::clone(&state.pool);
tokio::task::spawn_blocking(move || -> Result<(), AppError> {
    let mut conn = pool.get().map_err(AppError::from)?;
    let uow = UnitOfWork::new(&mut *conn).map_err(AppError::Database)?;
    // ... serialize enum fields into AuditEventInsertRow vec ...
    AuditEventRepository::insert_batch(&uow, &rows).map_err(AppError::Database)?;
    uow.commit().map_err(AppError::Database)?;
    Ok(())
})
```

**3. `query_events` (lines 243-336):**
The dynamic WHERE clause with optional filters is complex. Move the entire query builder
logic into `AuditEventRepository::query(pool, filters) -> rusqlite::Result<Vec<serde_json::Value>>`.
The `EventQuery` struct stays in `audit_store.rs`. Create a `AuditEventFilter` struct in
the repository that mirrors the filter fields (agent_id, user_name, classification,
event_type, from, to, limit, offset). The handler maps `EventQuery` -> `AuditEventFilter`.

**4. `get_event_count` (lines 343-358):**
Replace with `AuditEventRepository::count(&pool)`.

<verify>
cargo test -p dlp-server --lib audit 2>&1 | tail -10
</verify>

---

### Task 2-04: Migrate exception_store.rs (3 call sites)

**File:** `dlp-server/src/exception_store.rs`
**Action:** EDIT
**Why:** 3 call sites: create_exception (INSERT), list_exceptions (SELECT), get_exception (SELECT).

**1. `create_exception` (lines 71-124):**
Replace `conn.execute("INSERT INTO exceptions ...")` with:
```rust
let mut conn = pool.get().map_err(AppError::from)?;
let uow = UnitOfWork::new(&mut *conn).map_err(AppError::Database)?;
ExceptionRepository::insert(&uow, &exc).map_err(AppError::Database)?;
uow.commit().map_err(AppError::Database)?;
```

The `Exception` struct stays in `exception_store.rs`. The repository's `insert` method
takes a reference to the repo's `ExceptionRow` (or directly to the handler's `Exception`
if re-exported). Cleanest: repository defines `ExceptionInsertRow` with all fields except
`id` auto-generation (id is pre-generated by the handler as UUID).

**2. `list_exceptions` (lines 131-165):**
Replace with `ExceptionRepository::list(&pool)` returning `Vec<ExceptionRow>`.
Map to `Vec<Exception>` in the handler.

**3. `get_exception` (lines 172-213):**
Replace with `ExceptionRepository::get_by_id(&pool, &id)` returning `Option<ExceptionRow>`
or `rusqlite::Result<ExceptionRow>`. `QueryReturnedNoRows` naturally maps to `NotFound`.

<verify>
cargo test -p dlp-server --lib exception 2>&1 | tail -10
</verify>

---

### Task 2-05: Migrate agent_registry.rs (5 call sites)

**File:** `dlp-server/src/agent_registry.rs`
**Action:** EDIT
**Why:** 5 call sites: register_agent (UPSERT), heartbeat (UPDATE), list_agents (SELECT),
get_agent (SELECT), spawn_offline_sweeper (UPDATE in background loop).

**1. `register_agent` (lines 76-141):**
Replace INSERT...ON CONFLICT with:
```rust
let mut conn = pool.get().map_err(AppError::from)?;
let uow = UnitOfWork::new(&mut *conn).map_err(AppError::Database)?;
AgentRepository::upsert(&uow, &record).map_err(AppError::Database)?;
uow.commit().map_err(AppError::Database)?;
```

**2. `heartbeat` (lines 148-176):**
Replace UPDATE with:
```rust
let mut conn = pool.get().map_err(AppError::from)?;
let uow = UnitOfWork::new(&mut *conn).map_err(AppError::Database)?;
let rows = AgentRepository::update_heartbeat(&uow, &id, &now).map_err(AppError::Database)?;
uow.commit().map_err(AppError::Database)?;
Ok(rows)
```
The repository returns the `usize` rows-updated count so the handler can check for 404.

**3. `list_agents` (lines 183-217):**
Replace with `AgentRepository::list(&pool)`.

**4. `get_agent` (lines 224-263):**
Replace with `AgentRepository::get_by_id(&pool, &id)`.

**5. `spawn_offline_sweeper` (lines 270-305):**
The background loop uses `pool.get()` + `conn.execute()`. After migration:
```rust
let mut conn = pool.get().map_err(AppError::from)?;
let uow = UnitOfWork::new(&mut *conn).map_err(AppError::Database)?;
let rows = AgentRepository::mark_stale_offline(&uow, &cutoff).map_err(AppError::Database)?;
uow.commit().map_err(AppError::Database)?;
Ok(rows)
```
The sweeper's error type is `AppError` which it logs and discards -- same pattern after migration.

<verify>
cargo test -p dlp-server --lib agent_registry 2>&1 | tail -10
</verify>

---

### Task 2-06: Migrate admin_auth.rs (5 call sites)

**File:** `dlp-server/src/admin_auth.rs`
**Action:** EDIT
**Why:** 5 call sites: login SELECT, change_password SELECT, change_password UPDATE,
change_password audit INSERT, has_admin_users SELECT, create_admin_user INSERT.

**1. `login` (lines 157-181):**
Replace SELECT with `AdminUserRepository::get_password_hash(&pool, &uname)`.
This is a read -- no UoW needed.

**2. `change_password` SELECT (lines 262-276):**
Same as login: `AdminUserRepository::get_password_hash(&pool2, &uname)`.

**3. `change_password` UPDATE (lines 298-310):**
Replace with UoW write:
```rust
let mut conn = pool.get().map_err(AppError::from)?;
let uow = UnitOfWork::new(&mut *conn).map_err(AppError::Database)?;
AdminUserRepository::update_password_hash(&uow, &uname, &new_hash)
    .map_err(AppError::Database)?;
uow.commit().map_err(AppError::Database)?;
```

**4. `change_password` audit (lines 324-330):**
Currently calls `audit_store::store_events_sync(&conn, &[audit_event])`.
After audit_store migration (Task 2-03), `store_events_sync` takes `&UnitOfWork`.
This call site must acquire its own connection and UoW:
```rust
let mut conn = pool.get().map_err(AppError::from)?;
let uow = UnitOfWork::new(&mut *conn).map_err(AppError::Database)?;
audit_store::store_events_sync(&uow, &[audit_event])?;
uow.commit().map_err(AppError::Database)?;
```

**5. `has_admin_users` (lines 344-350):**
Sync startup function. Replace with `AdminUserRepository::has_any(&pool)`.
Note: This function returns `anyhow::Result<bool>`, not `AppError`. Map:
```rust
pub fn has_admin_users(pool: &crate::db::Pool) -> anyhow::Result<bool> {
    AdminUserRepository::has_any(pool)
        .map_err(|e| anyhow::anyhow!("failed to query admin_users: {e}"))
}
```

**6. `create_admin_user` (lines 360-375):**
Sync startup function. Replace with UoW write. Since this runs at startup (not in an
async context), the pattern is:
```rust
pub fn create_admin_user(pool: &crate::db::Pool, username: &str, password: &str) -> anyhow::Result<()> {
    let hash = bcrypt::hash(password, 12)
        .map_err(|e| anyhow::anyhow!("bcrypt hash failed: {e}"))?;
    let now = Utc::now().to_rfc3339();
    let mut conn = pool.get()?;
    let uow = UnitOfWork::new(&mut *conn)
        .map_err(|e| anyhow::anyhow!("transaction failed: {e}"))?;
    AdminUserRepository::insert(&uow, username, &hash, &now)
        .map_err(|e| anyhow::anyhow!("failed to insert admin user: {e}"))?;
    uow.commit()
        .map_err(|e| anyhow::anyhow!("commit failed: {e}"))?;
    tracing::info!(user = %username, "admin user created");
    Ok(())
}
```

**SECURITY NOTE:** The `AdminUserRepository` methods must never log or include the password
hash in error messages. `get_password_hash` returns the hash as an opaque `String` --
errors from `QueryReturnedNoRows` must be mapped to a generic "user not found" without
including the hash.

<verify>
cargo test -p dlp-server --lib admin_auth 2>&1 | tail -10
</verify>

---

## Verification

After all 6 tasks:

```
cargo test -p dlp-server --lib 2>&1 | tail -20     # all module tests pass
cargo clippy -p dlp-server -- -D warnings           # no clippy warnings
cargo test --workspace 2>&1 | tail -20              # full workspace green
```

Verify no raw SQL remains outside db/repositories/ (except admin_api.rs for Wave 3):
```
grep -rn "conn\.execute\|conn\.query_row\|conn\.prepare\|execute_batch" \
    dlp-server/src/ \
    --include="*.rs" \
    --exclude-dir="db" \
    | grep -v "admin_api.rs" \
    | grep -v "#\[cfg(test)\]" \
    | grep -v "// "
```
Expected output: zero lines (all raw SQL moved to repositories, except admin_api.rs).

## Success Criteria

- All 23 call sites in 6 handler modules replaced with repository method calls
- `siem_connector::load_config` and `alert_router::load_config` still NOT in spawn_blocking
- All writes use `UnitOfWork` pattern (acquire conn, create UoW, repo call, commit)
- All reads use `&Pool` pattern (repository acquires connection internally)
- `store_events_sync` signature changed to accept `&UnitOfWork` (JSON serialization stays in handler)
- `ingest_events` uses `UnitOfWork::new()` instead of `conn.unchecked_transaction()`
- `has_admin_users` and `create_admin_user` (startup functions) use repository methods
- No password hash appears in any log or error message
- `cargo test --workspace` passes with no regressions
- `cargo clippy -p dlp-server -- -D warnings` passes
