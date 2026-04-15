## PLAN COMPLETE

**Plan:** 03 — Migrate admin_api.rs
**Phase:** 99
**Status:** complete

### What was migrated

All 26 `pool.get()` + raw SQL call sites in `admin_api.rs` migrated to repository
methods. `PolicyRepository`, `AuditEventRepository`, `CredentialsRepository`,
`SiemConfigRepository`, `AlertRouterConfigRepository`, `AgentConfigRepository`,
and `LdapConfigRepository` now own all production DB queries for the admin API.
`store_events_sync` accepts `&UnitOfWork<'_>` throughout.

### Tasks completed

- **Task 3-01:** Policy CRUD handlers (`get_policy`, `list_policies`, `put_policy`,
  `create_policy`, `delete_policy`) + 3 `store_events_sync` audit calls migrated.
  `update_policy` now uses single-UoW pattern. Version increment via
  `PolicyRepository::increment_version`.

- **Task 3-02:** Credential handlers (`get_agent_auth_hash`, `set_agent_auth_hash`),
  SIEM config (`get_siem_config`), LDAP config (`get_ldap_config`, `put_ldap_config`),
  agent config (`get_global_agent_config`, `put_global_agent_config`,
  `put_agent_config_override`, `delete_agent_config_override`) all migrated.
  `update_alert_config_handler` SELECT+UPDATE uses single `UnitOfWork` via
  `get_secrets(uow) + update(uow)` — TOCTOU-safe.

- **Task 3-03:** Grep audit confirmed zero production raw SQL outside `db/repositories/`.
  Remaining hits are test-only code (`test_` modules) or `db/mod.rs` init/seed code
  (legitimate DB infrastructure).

### Grep audit result

All remaining `.execute`/`.query_row`/`.prepare` outside `db/repositories/` are in:
- `db/mod.rs` — `init_tables()` seed rows (legitimate DB infra, Decision E exempts
  the pool/connection layer itself)
- `db/unit_of_work.rs` — unit tests (`#[cfg(test)]` blocks)
- `audit_store.rs:313` — test-only direct read assertion
- `alert_router.rs:461,504,585` — `#[cfg(test)]` seed rows
- `admin_api.rs:1767,1791,1812,1874` — `test_` function bodies and a `seed_agent`
  helper in a test module
- `admin_api.rs:2579` — `test_db_insert_select_roundtrip_via_spawn_blocking`

**Zero production handler path violations.**

### Verification

```
cargo test -p dlp-server --lib        # 77 passed, 0 failed, 2 ignored
cargo clippy -p dlp-server -- -D warnings  # clean
```

### Files modified

**admin_api.rs** — 26 call sites migrated (639-line diff, net reduction of 109 lines)
**db/repositories/policies.rs** — added `PolicyUpdateRow`, `increment_version`, `delete`
**db/repositories/agent_config.rs** — added `AgentConfigOverrideRow`, override methods
**db/repositories/alert_router_config.rs** — added `get_secrets(uow)` method for TOCTOU-safe read
**db/repositories/mod.rs** — added new re-exports

### Deviations

- **`ready` handler**: `execute_batch("SELECT 1")` retained in handler — not entity logic,
  confirmed by RESEARCH.md
- **`seed_agent` test helper**: Direct `INSERT OR IGNORE` in test module retained —
  test infrastructure, not production code
- **`test_db_insert_select_roundtrip_via_spawn_blocking`**: Direct SQL in test body
  retained — verifies spawn_blocking isolation, not handler logic
