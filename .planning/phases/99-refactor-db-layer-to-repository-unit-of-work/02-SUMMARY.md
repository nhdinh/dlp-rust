## PLAN COMPLETE

**Plan:** 02 — Migrate Small Modules
**Phase:** 99
**Status:** complete

### What was migrated

All 23 `pool.get()` + raw SQL call sites across 6 handler modules migrated to
repository methods. The repository layer (created in Wave 1/Plan 01) now owns
all SQL execution for these modules. Only `admin_api.rs` remains for Wave 3.

### Tasks completed

- **Task 2-01:** `siem_connector.rs` — `load_config` now calls `SiemConfigRepository::get(&pool)`;
  `SiemConfigRow` remains in the handler (maps from repo row). `smtp_port` in
  `AlertRouterConfigRow` changed from `i64` to `u16` with range-check conversion.
  `load_config` in both modules stays synchronous (NOT wrapped in spawn_blocking).

- **Task 2-02:** `alert_router.rs` — `load_config` now calls `AlertRouterConfigRepository::get(&pool)`.
  Port conversion (i64→u16) moved into the repository. `smtp_enabled`/`webhook_enabled`
  bool conversion moved to handler. Repository row `updated_at` field now included.

- **Task 2-03:** `audit_store.rs` — 4 call sites migrated:
  - `store_events_sync`: signature changed from `&rusqlite::Connection` to `&UnitOfWork<'_>`;
    delegates to `AuditEventRepository::insert_batch(uow, &rows)`.
  - `ingest_events`: replaced `conn.unchecked_transaction()` with `UnitOfWork::new(&mut conn)`;
    replaced raw SQL loop with `AuditEventRepository::insert_batch`.
  - `query_events`: replaced 80-line raw SQL with `AuditEventRepository::query(&pool, &filter)`.
    Added `AuditEventFilter` struct to `db/repositories/audit_events.rs`.
  - `get_event_count`: replaced with `AuditEventRepository::count(&pool)`.
  - Test updated to use `UnitOfWork` + `store_events_sync`.

- **Task 2-04:** `exception_store.rs` — 3 call sites migrated:
  - `create_exception`: UoW write via `ExceptionRepository::insert`.
  - `list_exceptions`: read via `ExceptionRepository::list`; handler maps `ExceptionRow → Exception`.
  - `get_exception`: read via `ExceptionRepository::get_by_id`; `QueryReturnedNoRows` → `NotFound`.
  Added `exception_repo_row` helper and `ExceptionRepository::get_by_id` method.

- **Task 2-05:** `agent_registry.rs` — 5 call sites migrated:
  - `register_agent`: UoW write via `AgentRepository::upsert`.
  - `heartbeat`: UoW write via `AgentRepository::update_heartbeat`.
  - `list_agents`: read via `AgentRepository::list`; handler maps `AgentRow → AgentInfoResponse`.
  - `get_agent`: read via `AgentRepository::get_by_id`; `QueryReturnedNoRows` → `NotFound`.
  - `spawn_offline_sweeper`: UoW write via `AgentRepository::mark_stale_offline`.
  Added `AgentRepository::get_by_id`, `update_heartbeat`, and `mark_stale_offline` methods.

- **Task 2-06:** `admin_auth.rs` — 5 call sites migrated:
  - `login` SELECT: replaced with `AdminUserRepository::get_password_hash(&pool, &uname)`.
  - `change_password` SELECT: same repo call.
  - `change_password` UPDATE: UoW write via `AdminUserRepository::update_password_hash`.
  - `change_password` audit: own `UnitOfWork` + `audit_store::store_events_sync(&uow, ...)`.
  - `has_admin_users` (sync startup): replaced with `AdminUserRepository::has_any(pool)`.
  - `create_admin_user` (sync startup): UoW write via `AdminUserRepository::insert`.
  Added `AdminUserRepository::update_password_hash` method.

### Repository methods added

- `SiemConfigRepository::get`: already existed; `smtp_port` changed from `i64` to `u16`
- `AlertRouterConfigRepository::get`: added u16 range check, added `updated_at` field
- `AuditEventRepository::count`: already existed
- `AuditEventRepository::insert_batch`: already existed
- `AuditEventRepository::query(pool, filter)`: **NEW** — dynamic filter query
- `AuditEventFilter`: **NEW** — filter params struct
- `AuditEventRow`: **NEW** — re-exported from `db/repositories/mod.rs`
- `ExceptionRepository::insert`: already existed
- `ExceptionRepository::list`: already existed
- `ExceptionRepository::get_by_id`: **NEW**
- `AgentRepository::list`: already existed
- `AgentRepository::upsert`: already existed
- `AgentRepository::get_by_id`: **NEW**
- `AgentRepository::update_heartbeat`: **NEW**
- `AgentRepository::mark_stale_offline`: **NEW**
- `AdminUserRepository::get_password_hash`: already existed
- `AdminUserRepository::has_any`: already existed
- `AdminUserRepository::insert`: already existed
- `AdminUserRepository::update_password_hash`: **NEW**

### Verification

```
cargo test -p dlp-server --lib       # 77 passed, 0 failed, 2 ignored
cargo clippy -p dlp-server -- -D warnings  # clean (no warnings, no errors)
```

The 8 `dlp-agent` comprehensive test failures are pre-existing (cloud_tc, detective_tc,
print_tc) and unrelated to this refactor — dlp-server is the only crate modified.

### Files modified

**Handler modules (repository calls replace raw SQL):**
- `dlp-server/src/siem_connector.rs`
- `dlp-server/src/alert_router.rs`
- `dlp-server/src/audit_store.rs`
- `dlp-server/src/exception_store.rs`
- `dlp-server/src/agent_registry.rs`
- `dlp-server/src/admin_auth.rs`

**Repository layer (new methods + re-exports):**
- `dlp-server/src/db/repositories/mod.rs` — added `AuditEventRow` re-export
- `dlp-server/src/db/repositories/audit_events.rs` — added `AuditEventFilter`, `query()`
- `dlp-server/src/db/repositories/alert_router_config.rs` — u16 port, `updated_at`
- `dlp-server/src/db/repositories/exceptions.rs` — added `get_by_id()`
- `dlp-server/src/db/repositories/agents.rs` — added `get_by_id`, `update_heartbeat`, `mark_stale_offline`
- `dlp-server/src/db/repositories/admin_users.rs` — added `update_password_hash`

**Cross-module callers updated for new store_events_sync signature:**
- `dlp-server/src/admin_api.rs` — 3 call sites updated to use `UnitOfWork` + `store_events_sync(&uow, ...)`
- `dlp-server/src/admin_auth.rs` — 1 call site updated

### Deviations

- **`to_agent_row` helper removed:** This helper was defined in `agent_registry.rs` as a
  conversion function but was never called (the handler directly constructs `AgentRow`
  inside the closure). Removed as dead code to satisfy clippy.
- **`session_id` type cast:** `AuditEvent::session_id` is `u32`; `AuditEventRow::session_id`
  is `i64`. Added `as i64` cast in both `store_events_sync` and `ingest_events`.
- **`store_events_sync` test update:** The test in `audit_store.rs` now acquires a
  `UnitOfWork` before calling `store_events_sync` (required since signature changed
  from `&Connection` to `&UnitOfWork`).
