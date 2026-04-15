---
wave: 3
depends_on: ["01", "02"]
files_modified:
  - dlp-server/src/admin_api.rs
  - dlp-server/src/db/repositories/policies.rs
  - dlp-server/src/db/repositories/audit_events.rs
  - dlp-server/src/db/repositories/credentials.rs
  - dlp-server/src/db/repositories/siem_config.rs
  - dlp-server/src/db/repositories/alert_router_config.rs
  - dlp-server/src/db/repositories/agent_config.rs
  - dlp-server/src/db/repositories/ldap_config.rs
autonomous: true
requirements: []
---
# Plan 03: Migrate admin_api.rs (26 Call Sites)

**Phase:** 99 -- Refactor DB Layer to Repository + Unit of Work
**Wave:** 3
**Prereq:** Plan 02 passes all tests (all small modules migrated, `cargo test --workspace` green)

## Goal

Migrate all 26 `pool.get()` + raw SQL call sites in `admin_api.rs` (the largest handler
file at ~3200 lines) to use repository methods. This is the final wave -- after completion,
zero raw SQL exists outside `db/repositories/`. The repository API is stable from Waves 1-2,
so this wave is pure mechanical migration of established patterns.

The 26 call sites span 10 distinct handlers across 6 repository targets: PolicyRepository,
AuditEventRepository (via store_events_sync), CredentialsRepository, SiemConfigRepository,
AlertRouterConfigRepository, AgentConfigRepository, and LdapConfigRepository.

Special attention required for:
- `update_alert_config_handler` -- SELECT + UPDATE must use a single UnitOfWork (TOCTOU prevention)
- `ready` health check -- `execute_batch("SELECT 1")` is NOT entity logic; keep in handler per RESEARCH.md
- 3 audit call sites that delegate to `store_events_sync` (already migrated in Wave 2 to accept `&UnitOfWork`)

## Threat Model

| Threat | Severity | Mitigation |
|--------|----------|------------|
| SQL injection in dynamic query construction | low | admin_api.rs has no dynamic WHERE clauses (unlike audit_store's query_events). All 26 sites are fixed SQL with `params![]`. Repository methods continue this pattern. |
| TOCTOU on alert config update (secret mask resolution) | medium | `update_alert_config_handler` does SELECT + UPDATE in one closure. After migration, both operations go through a single `UnitOfWork` -- the transaction holds an exclusive lock, preventing concurrent mask resolution from reading stale secrets. |
| Credential values (DLPAuthHash) in error messages | medium | `CredentialsRepository::get()` returns `rusqlite::Result<CredentialRow>`. On `QueryReturnedNoRows`, the error contains the SQL text but NOT the credential value. The handler maps to `NotFound("auth hash not configured")` -- no credential leaks. |
| SSRF via webhook_url (existing TM-02) | low | URL validation stays in the handler layer (already implemented). Repository only stores the validated value. No change to the security boundary. |

## Tasks

### Task 3-01: Migrate policy CRUD handlers (5 call sites + 3 audit)

**File:** `dlp-server/src/admin_api.rs`
**Action:** EDIT
**Why:** Policy CRUD is the largest handler group (lines 433-750) with 5 direct call sites
plus 3 audit `store_events_sync` calls.

**Call sites to migrate:**

**1. `list_policies` (line 439) -- READ:**
```rust
// Before: conn.prepare("SELECT id, name, ...") + query_map
// After:
let policies = PolicyRepository::list(&pool).map_err(AppError::Database)?;
```
Map `PolicyRow` -> `PolicyResponse` in the handler.

**2. `get_policy` (line 482) -- READ:**
```rust
// After:
let policy = PolicyRepository::get_by_id(&pool, &id).map_err(AppError::Database)?;
```

**3. `create_policy` (line 545) -- WRITE + AUDIT:**
```rust
// After:
let mut conn = pool.get().map_err(AppError::from)?;
let uow = UnitOfWork::new(&mut *conn).map_err(AppError::Database)?;
PolicyRepository::insert(&uow, &record).map_err(AppError::Database)?;
uow.commit().map_err(AppError::Database)?;
```
The audit call at line 581 is a separate `spawn_blocking` block. After Wave 2,
`store_events_sync` accepts `&UnitOfWork`:
```rust
let mut conn = pool.get().map_err(AppError::from)?;
let uow = UnitOfWork::new(&mut *conn).map_err(AppError::Database)?;
audit_store::store_events_sync(&uow, &[audit_event])?;
uow.commit().map_err(AppError::Database)?;
```

**4. `update_policy` (line 631) -- WRITE + AUDIT:**
Same UoW pattern. The UPDATE + SELECT version number must be in the same UoW:
```rust
let mut conn = pool.get().map_err(AppError::from)?;
let uow = UnitOfWork::new(&mut *conn).map_err(AppError::Database)?;
PolicyRepository::update(&uow, &id, &record).map_err(AppError::Database)?;
let new_version = PolicyRepository::get_version(&uow, &id).map_err(AppError::Database)?;
uow.commit().map_err(AppError::Database)?;
```
Note: `get_version` reads from the transaction (`&UnitOfWork`) to see the uncommitted
update. Add `PolicyRepository::get_version(uow: &UnitOfWork, id: &str) -> rusqlite::Result<i64>`
that queries `uow.tx`.

Audit call at line 692 follows same pattern as create_policy audit.

**5. `delete_policy` (line 716) -- WRITE + AUDIT:**
```rust
let mut conn = pool.get().map_err(AppError::from)?;
let uow = UnitOfWork::new(&mut *conn).map_err(AppError::Database)?;
let rows = PolicyRepository::delete(&uow, &id).map_err(AppError::Database)?;
uow.commit().map_err(AppError::Database)?;
```
Returns rows count for 404 check. Audit at line 742 same pattern.

**New repository methods needed (add to PolicyRepository stubs from Wave 1):**
- `list(pool: &Pool) -> rusqlite::Result<Vec<PolicyRow>>`
- `get_by_id(pool: &Pool, id: &str) -> rusqlite::Result<PolicyRow>`
- `insert(uow: &UnitOfWork, record: &PolicyInsertRow) -> rusqlite::Result<()>`
- `update(uow: &UnitOfWork, id: &str, record: &PolicyUpdateRow) -> rusqlite::Result<()>`
- `get_version(uow: &UnitOfWork, id: &str) -> rusqlite::Result<i64>`
- `delete(uow: &UnitOfWork, id: &str) -> rusqlite::Result<usize>`

<verify>
cargo test -p dlp-server --lib admin_api::tests::test_policy 2>&1 | tail -10
</verify>

---

### Task 3-02: Migrate credentials, config, and health check handlers (18 call sites)

**File:** `dlp-server/src/admin_api.rs`
**Action:** EDIT
**Why:** Remaining 18 call sites covering credentials, SIEM config, alert config, LDAP config,
agent config, and the health check.

**Call sites to migrate:**

**1. `ready` health check (line 417):**
Keep `pool.get()` + `execute_batch("SELECT 1")` directly in the handler. This is NOT
entity logic -- it is a DB connectivity probe. Per RESEARCH.md, keeping it in the handler
does NOT violate Decision A. No repository call needed.

**2. `set_agent_auth_hash` (line 776) -- WRITE:**
```rust
let mut conn = pool.get().map_err(AppError::from)?;
let uow = UnitOfWork::new(&mut *conn).map_err(AppError::Database)?;
CredentialsRepository::upsert(&uow, "DLPAuthHash", &hash_value, &now)
    .map_err(AppError::Database)?;
uow.commit().map_err(AppError::Database)?;
```

**3. `get_agent_auth_hash` (line 804) -- READ:**
```rust
let row = CredentialsRepository::get(&pool, "DLPAuthHash")
    .map_err(AppError::Database)?;
```

**4. `get_siem_config_handler` (line 832) -- READ:**
```rust
let row = SiemConfigRepository::get(&pool).map_err(AppError::Database)?;
```
Map to handler's response type.

**5. `update_siem_config_handler` (line 872) -- WRITE:**
```rust
let mut conn = pool.get().map_err(AppError::from)?;
let uow = UnitOfWork::new(&mut *conn).map_err(AppError::Database)?;
SiemConfigRepository::update(&uow, &record).map_err(AppError::Database)?;
uow.commit().map_err(AppError::Database)?;
```

**6. `get_alert_config_handler` (line 920) -- READ:**
```rust
let row = AlertRouterConfigRepository::get(&pool).map_err(AppError::Database)?;
```
The ME-01 secret masking (replacing password/secret with `****`) stays in the handler.

**7. `update_alert_config_handler` (line 1004) -- READ + WRITE (TOCTOU-critical):**
This handler does SELECT (to check mask sentinels) then UPDATE in one closure.
After migration, BOTH must be in one UnitOfWork:
```rust
let mut conn = pool.get().map_err(AppError::from)?;
let uow = UnitOfWork::new(&mut *conn).map_err(AppError::Database)?;

// Read current secrets for mask resolution
let stored = AlertRouterConfigRepository::get_secrets(&uow)
    .map_err(AppError::Database)?;

// Resolve masked values
let smtp_password_to_write = if p.smtp_password == ALERT_SECRET_MASK {
    stored.smtp_password
} else {
    p.smtp_password
};
// ... same for webhook_secret ...

// Write the resolved config
AlertRouterConfigRepository::update(&uow, &resolved_record)
    .map_err(AppError::Database)?;
uow.commit().map_err(AppError::Database)?;
```

Add `AlertRouterConfigRepository::get_secrets(uow: &UnitOfWork) -> rusqlite::Result<AlertSecretsRow>`
that reads only `smtp_password, webhook_secret` from the transaction. This reads within
the transaction to prevent TOCTOU.

**8. `get_agent_config_for_agent` (line 1104) -- READ (two tables):**
```rust
// Try override first, fallback to global
match AgentConfigRepository::get_override(&pool, &agent_id) {
    Ok(row) => { /* use override */ }
    Err(rusqlite::Error::QueryReturnedNoRows) => {
        let global = AgentConfigRepository::get_global(&pool)?;
        /* use global */
    }
    Err(e) => return Err(AppError::Database(e)),
}
```

**9. `get_ldap_config_handler` (line 1147) -- READ:**
```rust
let row = LdapConfigRepository::get(&pool).map_err(AppError::Database)?;
```

**10. `update_ldap_config_handler` (line 1197) -- WRITE:**
```rust
let mut conn = pool.get().map_err(AppError::from)?;
let uow = UnitOfWork::new(&mut *conn).map_err(AppError::Database)?;
LdapConfigRepository::update(&uow, &record).map_err(AppError::Database)?;
uow.commit().map_err(AppError::Database)?;
```

**11. `get_global_agent_config_handler` (line 1230) -- READ:**
```rust
let row = AgentConfigRepository::get_global(&pool).map_err(AppError::Database)?;
```

**12. `update_global_agent_config_handler` (line 1270) -- WRITE:**
```rust
let mut conn = pool.get().map_err(AppError::from)?;
let uow = UnitOfWork::new(&mut *conn).map_err(AppError::Database)?;
AgentConfigRepository::update_global(&uow, &record).map_err(AppError::Database)?;
uow.commit().map_err(AppError::Database)?;
```

**13. `get_agent_config_override_handler` (line 1302) -- READ:**
```rust
let row = AgentConfigRepository::get_override(&pool, &agent_id)
    .map_err(AppError::Database)?;
```

**14. `update_agent_config_override_handler` (line 1343) -- WRITE:**
```rust
let mut conn = pool.get().map_err(AppError::from)?;
let uow = UnitOfWork::new(&mut *conn).map_err(AppError::Database)?;
AgentConfigRepository::upsert_override(&uow, &agent_id, &record)
    .map_err(AppError::Database)?;
uow.commit().map_err(AppError::Database)?;
```

**15. `delete_agent_config_override_handler` (line 1377) -- WRITE:**
```rust
let mut conn = pool.get().map_err(AppError::from)?;
let uow = UnitOfWork::new(&mut *conn).map_err(AppError::Database)?;
let rows = AgentConfigRepository::delete_override(&uow, &agent_id)
    .map_err(AppError::Database)?;
uow.commit().map_err(AppError::Database)?;
```

**New repository methods needed (add to stubs from Wave 1):**

CredentialsRepository:
- `get(pool: &Pool, key: &str) -> rusqlite::Result<CredentialRow>`
- `upsert(uow: &UnitOfWork, key: &str, value: &str, updated_at: &str) -> rusqlite::Result<()>`

SiemConfigRepository:
- `update(uow: &UnitOfWork, record: &SiemConfigUpdateRow) -> rusqlite::Result<()>`

AlertRouterConfigRepository:
- `get_secrets(uow: &UnitOfWork) -> rusqlite::Result<AlertSecretsRow>`
- `update(uow: &UnitOfWork, record: &AlertRouterConfigUpdateRow) -> rusqlite::Result<()>`

AgentConfigRepository:
- `get_global(pool: &Pool) -> rusqlite::Result<GlobalAgentConfigRow>`
- `get_override(pool: &Pool, agent_id: &str) -> rusqlite::Result<AgentConfigOverrideRow>`
- `update_global(uow: &UnitOfWork, record: &GlobalAgentConfigUpdateRow) -> rusqlite::Result<()>`
- `upsert_override(uow: &UnitOfWork, agent_id: &str, record: &AgentConfigOverrideUpdateRow) -> rusqlite::Result<()>`
- `delete_override(uow: &UnitOfWork, agent_id: &str) -> rusqlite::Result<usize>`

LdapConfigRepository:
- `update(uow: &UnitOfWork, record: &LdapConfigUpdateRow) -> rusqlite::Result<()>`

<verify>
cargo test -p dlp-server --lib admin_api 2>&1 | tail -20
</verify>

---

### Task 3-03: Final verification -- zero raw SQL outside db/repositories/

**Files:** All files in `dlp-server/src/` (verification only, no edits)
**Action:** VERIFY
**Why:** Decision A requires zero raw SQL outside db/repositories/. This task is a
post-migration audit.

Run the following grep to confirm no raw SQL remains outside the repositories directory:

```bash
grep -rn "\.execute\b\|\.query_row\b\|\.prepare\b\|execute_batch" \
    dlp-server/src/ \
    --include="*.rs" \
    --exclude-dir="db" \
    | grep -v "#\[cfg(test)\]" \
    | grep -v "^.*:.*//.*" \
    | grep -v "SELECT 1"
```

Expected: zero matches (excluding the `ready` health check `SELECT 1` which is explicitly
kept in the handler per RESEARCH.md).

Also verify:
- `cargo test --workspace` passes
- `cargo clippy -p dlp-server -- -D warnings` passes
- `cargo fmt -p dlp-server --check` passes

<verify>
cargo test --workspace 2>&1 | tail -20
cargo clippy -p dlp-server -- -D warnings 2>&1 | tail -5
</verify>

---

## Verification

After all 3 tasks:

```
cargo test --workspace 2>&1 | tail -20              # full workspace green
cargo clippy -p dlp-server -- -D warnings            # no clippy warnings
cargo fmt -p dlp-server --check                      # formatting clean
```

Grep audit confirms zero raw SQL outside `db/repositories/` (except health check `SELECT 1`).

## Success Criteria

- All 26 `pool.get()` call sites in admin_api.rs replaced with repository calls
  (except `ready` health check which keeps `pool.get()` + `SELECT 1`)
- `update_alert_config_handler` uses a single `UnitOfWork` for SELECT + UPDATE (TOCTOU safe)
- All policy writes (create/update/delete) go through `UnitOfWork`
- All 3 audit `store_events_sync` calls use `UnitOfWork` (migrated signature from Wave 2)
- Credential operations (set/get auth hash) use `CredentialsRepository`
- Config operations (SIEM, alert, LDAP, agent) use their respective repositories
- No raw SQL exists outside `db/repositories/` (verified by grep, except health check)
- `cargo test --workspace` passes with zero failures
- `cargo clippy -p dlp-server -- -D warnings` passes
- All public items have doc comments
- No `.unwrap()` in library code
