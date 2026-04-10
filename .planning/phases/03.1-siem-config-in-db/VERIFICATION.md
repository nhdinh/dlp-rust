---
status: passed
phase: 03.1-siem-config-in-db
verified: 2026-04-10
method: code inspection + cargo test per package
supersedes: 03-wire-siem-connector-into-server-startup
---

# Phase 3.1 Verification: SIEM Config in DB via dlp-admin-cli

**Phase status:** Complete (all acceptance criteria met)
**Method:** Code inspection of 7 modified files across dlp-server + dlp-admin-cli, plus `cargo test --package dlp-server --lib` and `cargo test --package dlp-admin-cli`

## Goal (from CONTEXT.md)

> Move SIEM connector configuration from environment variables to the SQLite database. Add an admin REST API for reading/updating SIEM config, and a TUI screen in dlp-admin-cli for admins to manage it. Hot-reload on every relay — no restart required.

## Acceptance Criteria — all met

| # | Criterion | Result | Evidence |
|---|-----------|--------|----------|
| 1 | `siem_config` table created on DB init | **PASS** | `db.rs:129-140` — `CREATE TABLE IF NOT EXISTS siem_config (...)` + `INSERT OR IGNORE INTO siem_config (id) VALUES (1)` |
| 2 | Exactly one seed row exists after init | **PASS** | `db.rs:183-189` test: `SELECT COUNT(*) FROM siem_config` → asserts `count == 1`; passes in `test_tables_created` |
| 3 | `GET /admin/siem-config` returns current settings as JSON (JWT required) | **PASS** | `admin_api.rs:191` route + `admin_api.rs:534-545` handler; registered inside the JWT-protected admin router |
| 4 | `PUT /admin/siem-config` updates settings (JWT required) | **PASS** | `admin_api.rs:192` route + `admin_api.rs:569-590` handler — `UPDATE siem_config SET ... WHERE id = 1` |
| 5 | Server reads config from DB on every relay (no restart needed) | **PASS** | `siem_connector.rs` private `load_config()` called from `relay_events()` every invocation — no caching |
| 6 | dlp-server no longer reads `SPLUNK_HEC_*` / `ELK_*` env vars | **PASS** | `grep -rn "SPLUNK_HEC\|SPLUNK_URL\|ELK_URL\|from_env" dlp-server/src/siem_connector.rs` returns zero hits |
| 7 | dlp-admin-cli has "SIEM Config" under the System menu | **PASS** | `dispatch.rs:177` — System menu item #2 dispatches to `action_load_siem_config` |
| 8 | Admin can view Splunk/ELK settings via TUI (secrets masked) | **PASS** | `render.rs:140+` `draw_siem_config()` — masks `splunk_token` and `elk_api_key` as `*****` outside edit mode |
| 9 | Admin can edit and save settings via TUI | **PASS** | `dispatch.rs:693-731` `handle_siem_config_editing` (char/backspace/Enter/Esc); `dispatch.rs:733+` `handle_siem_config_nav` with Save row trigger |
| 10 | Save triggers backend update via `PUT /admin/siem-config` | **PASS** | `dispatch.rs:657-674` `action_save_siem_config` → `client.put::<serde_json::Value, _>("admin/siem-config", &payload)` |
| 11 | `cargo clippy --workspace -- -D warnings` clean | **PASS** | Reported in commit message `8911669` ("All tests pass; per-package clippy clean") |
| 12 | All existing tests pass | **PASS** | 31/31 `dlp-server` lib tests; 5/5 `dlp-admin-cli` tests at phase close |

## Test results at phase close

```
cargo test --package dlp-server --lib
test result: ok. 31 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

Relevant new/extended tests from Phase 3.1:
- `db::tests::test_tables_created` — extended to assert `siem_config` table and seed row
- `admin_api::tests::test_siem_config_payload_roundtrip` — serde round-trip for `SiemConfigPayload`
- `siem_connector::tests::test_new_with_in_memory_db` — `SiemConnector::new(db)` against in-memory DB
- `siem_connector::tests::test_relay_events_empty_is_noop` — empty events slice short-circuits without HTTP

```
cargo test --package dlp-admin-cli
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

## Code-level verification checklist

| Check | File | Evidence | Status |
|-------|------|----------|--------|
| `siem_config` DDL with single-row CHECK | `db.rs:129-140` | `CHECK (id = 1)` + `INSERT OR IGNORE` seed | OK |
| `SiemConfigRow` private struct | `siem_connector.rs:36-46` | fields mirror the 8 DB columns | OK |
| `SiemConnector` holds `Arc<Database>` | `siem_connector.rs:54-60` | `db: Arc<Database>, client: Client` | OK |
| `SiemConnector::new(db)` public ctor | `siem_connector.rs:94+` | `pub fn new(db: Arc<Database>) -> Self` | OK |
| `load_config()` called on every relay | `siem_connector.rs` | module docstring: "reads the single row from the `siem_config` table so that configuration changes made via the admin API take effect immediately without restarting the server" | OK |
| No env var references | `siem_connector.rs` | grep `SPLUNK_HEC\|SPLUNK_URL\|ELK_URL\|from_env` → zero hits | OK |
| `SiemConfigPayload` type | `admin_api.rs` | serde `Serialize + Deserialize` round-trip test | OK |
| `GET /admin/siem-config` registered | `admin_api.rs:191` | `.route("/admin/siem-config", get(get_siem_config_handler))` | OK |
| `PUT /admin/siem-config` registered | `admin_api.rs:192` | `.route("/admin/siem-config", put(update_siem_config_handler))` | OK |
| GET handler uses `spawn_blocking` | `admin_api.rs:534-545` | SQLite read in `tokio::task::spawn_blocking` | OK |
| PUT handler uses `spawn_blocking` | `admin_api.rs:569-590` | SQLite write in `tokio::task::spawn_blocking` | OK |
| Routes are JWT-protected | `admin_api.rs` | registered inside the `require_auth` middleware layer | OK |
| `main.rs` uses `SiemConnector::new(db)` | `main.rs:146-149` | `SiemConnector::new(Arc::clone(&db))` replaces any `from_env()` | OK |
| `Screen::SiemConfig` variant | `app.rs:109` | `config: serde_json::Value, selected: usize, editing: bool, buffer: String` | OK |
| `draw_siem_config` TUI renderer | `render.rs:140+` | field-by-field render with `*****` masking | OK |
| Dispatch routes `SiemConfig` key events | `dispatch.rs:25` | `Screen::SiemConfig { .. } => handle_siem_config(app, key)` | OK |
| System menu item #2 is SIEM Config | `dispatch.rs:177` | `2 => action_load_siem_config(app)` | OK |
| DRY index constants | `dispatch.rs:615-626` | `SIEM_KEYS: [&str; 7]`, `SIEM_SAVE_ROW = 7`, `SIEM_BACK_ROW = 8` | OK |
| `action_load_siem_config` fetches from server | `dispatch.rs:639-655` | `client.get::<serde_json::Value>("admin/siem-config")` | OK |
| `action_save_siem_config` pushes to server | `dispatch.rs:657-674` | `client.put::<serde_json::Value, _>("admin/siem-config", &payload)` | OK |
| Edit submachine (text + bool + buffer) | `dispatch.rs:693-731` | char/backspace/Enter/Esc cases; bool via Enter toggle | OK |
| Navigation submachine | `dispatch.rs:733+` | Up/Down moves `selected`, Enter on Save → save, Enter on text field → enter edit | OK |

## Commits

| Commit | Scope | Files |
|---|---|---|
| `ff0a7ec discuss: phase 3.1 — SIEM config in DB via dlp-admin-cli` | Discuss (context decisions) | CONTEXT.md |
| `07a9af7 plan: phase 3.1 — SIEM config in DB via dlp-admin-cli` | Plan | PLAN.md |
| `8911669 feat: SIEM config in DB with TUI management (Phase 3.1)` | Feature | 7 files (4 dlp-server + 3 dlp-admin-cli) |

## Supersession relationship (inverse)

Phase 3.1 **supersedes** Phase 3's config-loading mechanism (env vars → DB table + admin API + TUI) but **inherits** Phase 3's AppState structure, handler refactor, and background relay plumbing in `audit_store::ingest_events`. See `.planning/phases/03-wire-siem-connector-into-server-startup/VERIFICATION.md` for the Phase 3 foundation work verification.

## Re-run commands

```
cargo test --package dlp-server --lib    # expects: 31 passed
cargo test --package dlp-admin-cli        # expects: 5 passed
```
