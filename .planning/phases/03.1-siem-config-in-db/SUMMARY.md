---
phase: 03.1-siem-config-in-db
plan: PLAN
subsystem: infra
tags: [siem, sqlite, admin-api, ratatui, tui, dlp-server, dlp-admin-cli, hot-reload]
supersedes: 03-wire-siem-connector-into-server-startup

# Dependency graph
requires:
  - phase: 3
    provides: "AppState { db, siem } + background relay plumbing in audit_store"
provides:
  - "siem_config single-row SQLite table with seed row"
  - "SiemConnector that hot-reloads config from DB on every relay call"
  - "GET/PUT /admin/siem-config authenticated admin endpoints"
  - "dlp-admin-cli TUI screen for managing SIEM config (navigate + edit + save)"
affects: [04-wire-alert-router-into-server, 06-wire-config-push-for-agent-config]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Single-row config table with CHECK (id = 1) + INSERT OR IGNORE seed — guarantees exactly one row"
    - "Hot-reload-on-every-call config loader — no caching, admin updates take effect immediately"
    - "Secret masking in TUI: render as ***** outside edit mode, reveal only while editing"
    - "DRY index constants (SIEM_KEYS, SIEM_SAVE_ROW, SIEM_BACK_ROW) to keep TUI form in sync with data model"

key-files:
  created: []
  modified:
    - dlp-server/src/db.rs
    - dlp-server/src/siem_connector.rs
    - dlp-server/src/admin_api.rs
    - dlp-server/src/main.rs
    - dlp-admin-cli/src/app.rs
    - dlp-admin-cli/src/screens/render.rs
    - dlp-admin-cli/src/screens/dispatch.rs

key-decisions:
  - "siem_config is a single-row table guarded by CHECK (id = 1) — one config per server, enforced at DB level"
  - "Secrets stored plaintext (consistent with admin password hash and agent credentials — dlp-server.db is admin-only access)"
  - "Hot-reload on every relay — no caching, no restart required when admin updates config via TUI"
  - "TUI uses generic client.get::<T>/put::<T, _>(\"admin/siem-config\", ...) instead of dedicated get_siem_config()/update_siem_config() methods — simpler, same behavior"
  - "SIEM Config is item #2 under the dlp-admin-cli System menu (position: Server Status, Agent List, SIEM Config, Back)"

patterns-established:
  - "Template for future DB-backed config subsystems (alert router, config push): single-row table + hot-reload loader + GET/PUT /admin/<subsystem>-config + TUI screen under System menu"
  - "SIEM_KEYS/SIEM_SAVE_ROW/SIEM_BACK_ROW constant pattern — any future form screen should follow the same DRY-index approach"

requirements-completed: [R-01]

# Metrics
duration: ~26 min (plan → feature commit)
completed: 2026-04-10
---

# Phase 3.1: SIEM Config in DB via dlp-admin-cli Summary

**SIEM connector config now lives in the SQLite `siem_config` table with hot-reload on every relay, managed via `GET/PUT /admin/siem-config` and a dedicated dlp-admin-cli TUI screen under the System menu — env vars are gone from the SIEM path entirely.**

## Performance

- **Duration:** ~26 min (plan `07a9af7` → feature `8911669`)
- **Started:** 2026-04-10T11:03 +0700 (discuss/plan after Phase 3)
- **Completed:** 2026-04-10T11:29:53+07:00 (feature commit)
- **Tasks:** 1 feature commit
- **Files modified:** 7 (4 dlp-server + 3 dlp-admin-cli)

## Accomplishments

- New `siem_config` single-row SQLite table with 8 columns (splunk_url/token/enabled, elk_url/index/api_key/enabled, updated_at), CHECK-constrained to `id = 1` and seeded with `INSERT OR IGNORE`.
- Rewrote `SiemConnector` to hold `Arc<Database>` instead of env-loaded config. On every `relay_events()` call, it executes a private `load_config()` that reads the single row — no caching, so admin changes take effect immediately.
- Added `GET /admin/siem-config` and `PUT /admin/siem-config` to the JWT-protected admin router, backed by a typed `SiemConfigPayload` struct.
- Added `Screen::SiemConfig` variant to dlp-admin-cli with selected/editing/buffer state machine, a 9-row form (7 fields + Save + Back), secret masking for token/api_key outside edit mode, Enter-to-toggle for booleans, Enter-to-edit-buffer for text fields.
- Wired "SIEM Config" into the dlp-admin-cli System menu as item #2 (order: Server Status, Agent List, SIEM Config, Back).
- Cleaned up the old env-var code path: `from_env()` removed, `SPLUNK_HEC_*` / `ELK_*` references dropped (grep returns zero hits anywhere in `dlp-server/src/*.rs`).

## Task Commits

1. **Feature** — `8911669` (feat: SIEM config in DB with TUI management (Phase 3.1))
   - `dlp-server/src/db.rs` — `siem_config` table + seed + `test_tables_created` assertion + new `test_siem_config_seed_row`
   - `dlp-server/src/siem_connector.rs` — rewrite: `Arc<Database>`, `load_config()`, `SiemConfigRow` struct, remove env var path
   - `dlp-server/src/admin_api.rs` — `SiemConfigPayload` type, `GET/PUT /admin/siem-config` handlers, route registration
   - `dlp-server/src/main.rs` — `SiemConnector::new(Arc::clone(&db))` replaces `from_env()`
   - `dlp-admin-cli/src/app.rs` — `Screen::SiemConfig { config, selected, editing, buffer }`
   - `dlp-admin-cli/src/screens/render.rs` — `draw_siem_config()` with field-by-field rendering + secret masking
   - `dlp-admin-cli/src/screens/dispatch.rs` — `action_load_siem_config`, `action_save_siem_config`, `handle_siem_config` + edit/nav submachines, `SIEM_KEYS`/`SIEM_SAVE_ROW`/`SIEM_BACK_ROW` constants

**Plan metadata:** `07a9af7` (plan: phase 3.1 — SIEM config in DB via dlp-admin-cli), `ff0a7ec` (discuss: phase 3.1)

## Files Created/Modified

### dlp-server
- `dlp-server/src/db.rs:129-140` — `CREATE TABLE IF NOT EXISTS siem_config (...)` + `INSERT OR IGNORE INTO siem_config (id) VALUES (1)`
- `dlp-server/src/db.rs:183-189` — test assertions for `siem_config` table existence and seed row
- `dlp-server/src/siem_connector.rs:36-46` — private `SiemConfigRow` struct
- `dlp-server/src/siem_connector.rs:54-60` — `SiemConnector { db: Arc<Database>, client: reqwest::Client }`
- `dlp-server/src/siem_connector.rs:94+` — `pub fn new(db: Arc<Database>) -> Self` ctor
- `dlp-server/src/siem_connector.rs` — `relay_events()` calls `load_config()` on entry, derives effective Splunk/ELK config from the row
- `dlp-server/src/admin_api.rs:96` — `SiemConfigRow` helper comment marker
- `dlp-server/src/admin_api.rs:191-192` — `GET /admin/siem-config` + `PUT /admin/siem-config` route registration
- `dlp-server/src/admin_api.rs:534-545` — `get_siem_config_handler` — `SELECT ... FROM siem_config WHERE id = 1` + JSON response
- `dlp-server/src/admin_api.rs:569-590` — `update_siem_config_handler` — `UPDATE siem_config SET ... WHERE id = 1`
- `dlp-server/src/admin_api.rs:655` — `test_siem_config_payload_roundtrip` unit test
- `dlp-server/src/main.rs:146-149` — `let siem = SiemConnector::new(Arc::clone(&db));`

### dlp-admin-cli
- `dlp-admin-cli/src/app.rs:109` — `Screen::SiemConfig { config: serde_json::Value, selected: usize, editing: bool, buffer: String }`
- `dlp-admin-cli/src/screens/render.rs:104-110` — `Screen::SiemConfig` match arm dispatching to `draw_siem_config`
- `dlp-admin-cli/src/screens/render.rs:140+` — `draw_siem_config()` — field-by-field rendering, bool toggles as `[x]`/`[ ]`, secrets as `*****` outside edit mode
- `dlp-admin-cli/src/screens/dispatch.rs:25` — dispatch `Screen::SiemConfig` → `handle_siem_config`
- `dlp-admin-cli/src/screens/dispatch.rs:177` — System menu item #2 → `action_load_siem_config`
- `dlp-admin-cli/src/screens/dispatch.rs:615-626` — `SIEM_KEYS` / `SIEM_SAVE_ROW` / `SIEM_BACK_ROW` constants
- `dlp-admin-cli/src/screens/dispatch.rs:639-655` — `action_load_siem_config()` → `client.get::<serde_json::Value>("admin/siem-config")`
- `dlp-admin-cli/src/screens/dispatch.rs:657-674` — `action_save_siem_config()` → `client.put::<serde_json::Value, _>("admin/siem-config", &payload)`
- `dlp-admin-cli/src/screens/dispatch.rs:676-692` — `handle_siem_config()` — dispatches to editing or nav submachine
- `dlp-admin-cli/src/screens/dispatch.rs:693-731` — `handle_siem_config_editing()` — char/backspace/Enter/Esc for text and bool fields
- `dlp-admin-cli/src/screens/dispatch.rs:733+` — `handle_siem_config_nav()` — Up/Down navigation, Save row triggers save, Back row returns to System menu

## Decisions Made

- **Single-row pattern with CHECK constraint.** The plan proposed this explicitly — implementation followed. `CHECK (id = 1)` + `INSERT OR IGNORE INTO siem_config (id) VALUES (1)` guarantees exactly one row without application-level locking.
- **Hot-reload, not cached.** `load_config()` runs on every `relay_events()` call. Slight per-request overhead (one SELECT from a single-row table) is acceptable because audit event relay frequency is bounded by DLP event rate, and operator config changes should take effect immediately without a server restart.
- **Secrets plaintext in DB.** Consistent with the admin password bcrypt hash and agent credentials also living in `dlp-server.db`. The database file itself is admin-only access (Windows ACL on `C:\ProgramData\DLP\`).
- **Generic client methods over dedicated wrappers.** Plan Step 5 proposed `get_siem_config()` / `update_siem_config()` methods on `EngineClient`. Implementation used the existing generic `client.get::<T>` / `client.put::<T, _>` directly. Simpler, fewer lines, same functionality.
- **SIEM Config is System menu item #2.** Before: Server Status / Agent List / Back. After: Server Status / Agent List / SIEM Config / Back. Keeps operational-diagnostics grouped together.

## Deviations from Plan

**1. Client methods — generic `get`/`put` instead of dedicated wrappers**
- **Found during:** Step 5 implementation (dlp-admin-cli client methods)
- **Issue:** Plan prescribed `pub async fn get_siem_config(&self) -> Result<serde_json::Value>` and `pub async fn update_siem_config(&self, payload: &serde_json::Value)` as named methods on `EngineClient`.
- **Fix:** Used `self.client.get::<serde_json::Value>("admin/siem-config").await` and `self.client.put::<serde_json::Value, _>("admin/siem-config", &payload).await` directly in `action_load_siem_config` / `action_save_siem_config`. No new methods added to the client struct.
- **Files modified:** `dlp-admin-cli/src/screens/dispatch.rs` only (no `client.rs` change)
- **Verification:** 5/5 dlp-admin-cli tests pass; TUI SIEM screen loads and saves in manual testing.
- **Committed in:** `8911669` (feature commit)

---

**Total deviations:** 1 (simplification — fewer lines, same behavior)
**Impact on plan:** Positive — less indirection for a single call site.

## Issues Encountered

- None. The plan was unusually clean because `ff0a7ec` (discuss) locked all the interesting decisions up front, and Phase 3's AppState refactor meant the new handlers plugged into an already-established state type.

## Next Phase Readiness

- **Template established** for Phase 4 (alert router) and Phase 6 (config push) — both must follow this same pattern per user decision in `CONTEXT.md`: single-row config table + hot-reload loader + `GET/PUT /admin/<subsystem>-config` + TUI screen under System menu.
- Phase 4's current PLAN.md still prescribes env-var loading (`AlertRouter::from_env()`, `SMTP_*`, `WEBHOOK_*`) — that plan is stale and must be updated before execution. Same for Phase 6 if/when it's planned.
- `alert_router.rs:75` and `policy_sync.rs:51` still have `from_env()` methods — these are future-phase work, left in place pending Phases 4 and 5.

---
*Phase: 03.1-siem-config-in-db*
*Supersedes: 03-wire-siem-connector-into-server-startup (config loading mechanism only)*
*Completed: 2026-04-10*
