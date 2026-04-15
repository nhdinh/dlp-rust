---
phase: "10"
plan: ""
subsystem: dlp-server / db
tags: [r2d2, connection-pool, sqlite, multi-connection]
key-files:
  created: [dlp-server/src/db.rs]
  modified: [dlp-server/src/lib.rs, dlp-server/src/main.rs, dlp-server/src/admin_auth.rs, dlp-server/src/agent_registry.rs, dlp-server/src/exception_store.rs, dlp-server/src/audit_store.rs, dlp-server/src/siem_connector.rs, dlp-server/src/alert_router.rs, dlp-server/src/admin_api.rs, dlp-server/tests/admin_audit_integration.rs, dlp-server/tests/ldap_config_api.rs]
metrics:
  files_affected: 12
  insertions: 195
  deletions: 183
  tests_passed: 75 server lib + 145 agent lib
---

## Summary

Phase 10 replaced the single-connection `parking_lot::Mutex<Connection>` in `dlp-server` with `r2d2`/`r2d2_sqlite` connection pool. All axum handlers now acquire connections via `pool.get()` instead of `db.conn().lock()`.

### What was built

- **`db.rs`**: `new_pool(path)` factory, `Pool`/`Connection` type aliases, 5 unit tests migrated to `new_pool(":memory:")`
- **`AppState`**: `pool: db::Pool` replaces `db: Arc<db::Database>`, derives `Clone`
- **9 source files**: all `conn().lock()` replaced with `pool.get().map_err(AppError::from)?`; spawn_blocking closures with explicit `-> Result<_, AppError>` return types
- **Test fixtures**: all `:memory:` Database fixtures replaced with `tempfile::NamedTempFile + db::new_pool()` to avoid pool isolation issues
- **Integration tests**: `admin_audit_integration.rs`, `ldap_config_api.rs` fully migrated
- **`impl From<r2d2::Error>`**: added for `AppError`, `SiemError`, `AlertError`

### Deviations / Auto-fixes

- `admin_api.rs` had 3 inline diagnostic tests with mismatched return types — fixed spawn_blocking signatures and query_result `map_err` chains
- `get_agent` in `agent_registry.rs` required `query_row(...)?; Ok(row)` pattern (no type annotation on Ok) due to complex type inference
- `exception_store.rs` get_exception: changed match from `rusqlite::Error::QueryReturnedNoRows` to `AppError::NotFound(_)` pattern since pool.get errors are `AppError`
- Removed redundant `&*conn` deref in `audit_store::store_events_sync` call (clippy explicit_auto_deref warning)

### Verification

| Check | Result |
|-------|--------|
| `cargo build -p dlp-server --lib` | PASS |
| `cargo test -p dlp-server --lib` | 75 pass |
| `cargo test -p dlp-agent --lib` | 145 pass |
| `cargo clippy -p dlp-server -p dlp-agent -- -D warnings` | PASS |
| No `conn().lock()` remaining | grep confirmed |
| `pub struct Database` removed | grep confirmed |
| `AppState.pool` field present | grep confirmed |

### Commits

| Hash | Description |
|------|-------------|
| `019fc0b` | refactor(dlp-server): replace Mutex<Connection> with r2d2 connection pool |