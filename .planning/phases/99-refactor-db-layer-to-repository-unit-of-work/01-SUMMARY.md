## PLAN COMPLETE

**Plan:** 01 — Build db/ Submodule
**Phase:** 99
**Status:** complete

### What was built

Replaced the flat `dlp-server/src/db.rs` with a `dlp-server/src/db/` directory module
containing a typed `UnitOfWork<'conn>` struct, 10 stateless repository stubs (one per
database entity), and all existing pool/init logic preserved verbatim. Migrated the sole
raw SQL call outside the DB layer (`main.rs::load_ldap_config`) to use `LdapConfigRepository`.

### Tasks completed

- Task 1-01: Deleted `db.rs`, created `db/mod.rs` with identical pool/init code plus
  `pub mod repositories; pub mod unit_of_work; pub use unit_of_work::UnitOfWork;` declarations.
- Task 1-02: Created `db/unit_of_work.rs` with `UnitOfWork<'conn>` RAII struct (commit/rollback
  semantics via `rusqlite::Transaction`) and 2 unit tests (commit persists, drop rolls back).
- Task 1-03: Created `db/repositories/mod.rs` and 10 repository stub files — agents, policies,
  audit_events, exceptions, admin_users, ldap_config, siem_config, alert_router_config,
  agent_config, credentials — each with one read method (`&Pool`) and one write method
  (`&UnitOfWork`), full doc comments, and `rusqlite::params![]` throughout.
- Task 1-04: Replaced raw SQL in `main.rs::load_ldap_config` with `LdapConfigRepository::get(pool)`
  call; `i64 → bool` and `i64 → u64` conversions now live in the repository.

### Verification

```
cargo check -p dlp-server          # OK — no errors
cargo test -p dlp-server --lib     # 77 passed, 0 failed, 2 ignored
cargo clippy -p dlp-server -- -D warnings  # OK — no warnings
```

UnitOfWork tests specifically:
```
test db::unit_of_work::tests::test_uow_rollback_on_drop ... ok
test db::unit_of_work::tests::test_uow_commit ... ok
```

### Files created/modified

**Created:**
- `dlp-server/src/db/mod.rs` — Pool type alias, new_pool(), init_tables(), existing tests
- `dlp-server/src/db/unit_of_work.rs` — UnitOfWork<'conn> with 2 unit tests
- `dlp-server/src/db/repositories/mod.rs` — re-exports all 10 repository structs
- `dlp-server/src/db/repositories/agents.rs` — AgentRepository (list, upsert)
- `dlp-server/src/db/repositories/policies.rs` — PolicyRepository (list, insert)
- `dlp-server/src/db/repositories/audit_events.rs` — AuditEventRepository (count, insert_batch)
- `dlp-server/src/db/repositories/exceptions.rs` — ExceptionRepository (list, insert)
- `dlp-server/src/db/repositories/admin_users.rs` — AdminUserRepository (get_password_hash, has_any, count, insert)
- `dlp-server/src/db/repositories/ldap_config.rs` — LdapConfigRepository (get, update)
- `dlp-server/src/db/repositories/siem_config.rs` — SiemConfigRepository (get, update)
- `dlp-server/src/db/repositories/alert_router_config.rs` — AlertRouterConfigRepository (get, update)
- `dlp-server/src/db/repositories/agent_config.rs` — AgentConfigRepository (get_global, update_global)
- `dlp-server/src/db/repositories/credentials.rs` — CredentialsRepository (get, upsert)

**Deleted:**
- `dlp-server/src/db.rs`

**Modified:**
- `dlp-server/src/main.rs` — load_ldap_config uses LdapConfigRepository::get()

### Deviations

None — plan executed exactly as written. Tasks 1-01 through 1-03 were committed together
(all files were created as a unit before the first cargo check).
