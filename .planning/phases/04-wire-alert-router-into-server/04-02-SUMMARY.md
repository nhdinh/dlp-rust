---
phase: 04-wire-alert-router-into-server
plan: 02
subsystem: dlp-admin-cli / TUI screens
tags: [tui, ratatui, alert-config, r-02, phase-3.1-mirror]
dependency_graph:
  requires:
    - 04-01 (server-side GET/PUT /admin/alert-config routes + AlertRouterConfigPayload)
    - Screen::SiemConfig (Phase 3.1 structural template)
    - EngineClient generic get/put helpers (pre-existing)
  provides:
    - Screen::AlertConfig variant (12-row form shape)
    - draw_alert_config render function
    - ALERT_FIELD_LABELS + ALERT_KEYS constants (10 editable fields)
    - action_load_alert_config / action_save_alert_config dispatch actions
    - handle_alert_config + handle_alert_config_editing + handle_alert_config_nav
    - System menu extended from 4 to 5 items
  affects:
    - dlp-admin-cli System menu navigation (Back shifted from index 3 to 4)
tech-stack:
  added: []
  patterns:
    - Generic client.get/put::<serde_json::Value> (matches Phase 3.1 — no typed helpers)
    - u16 port parsing with edit-mode error recovery (new for alerts — SIEM has no numeric rows)
    - serde_json::Value::Number for numeric JSON fields (G9 — server PUT deserialization)
    - Secret masking via ***** outside edit mode (mirrors is_siem_secret)
key-files:
  created: []
  modified:
    - dlp-admin-cli/src/app.rs
    - dlp-admin-cli/src/screens/render.rs
    - dlp-admin-cli/src/screens/dispatch.rs
decisions:
  - "G8 followed: no typed client helpers added — uses generic get/put::<serde_json::Value> per Phase 3.1 precedent (CONTEXT.md's typed-method note was stale)"
  - "G1 reconciled: 12 rows (10 editable + Save + Back), NOT the 13 rows CONTEXT.md miscounted — acknowledged in plan's Gotchas section"
  - "G2 implemented: numeric smtp_port edit branch parses u16 and stays in edit mode on parse failure with a status error (so the user can correct without losing the buffer)"
  - "G9 implemented: smtp_port committed as serde_json::Value::Number, not String, so AlertRouterConfigPayload::smtp_port (u16) deserializes on PUT"
  - "System menu order: Server Status(0), Agent List(1), SIEM Config(2), Alert Config(3), Back(4) — SIEM Config index preserved, Back shifted"
  - "Unit test system_menu_has_alert_config pins the 12-row constants + KEYS order so future refactors catch drift at cargo test time"
metrics:
  duration: "~10 minutes"
  completed: "2026-04-10"
  tasks_completed: 3
  commits: 3
---

# Phase 4 Plan 02: Alert Config TUI Summary

One-liner: Adds a 12-row `Screen::AlertConfig` form to dlp-admin-cli's
System menu that calls Wave 1's `GET/PUT /admin/alert-config` routes via
the generic `serde_json::Value` client pattern, with secret masking for
`smtp_password` and `webhook_secret`, u16 parsing for `smtp_port` with
edit-mode error recovery, and Enter-toggle for `smtp_enabled` and
`webhook_enabled`.

## Overview

Plan 04-02 is the dlp-admin-cli wave of Phase 4. Plan 04-01 landed the
server side (DB-backed `AlertRouter`, admin endpoints with TM-02 SSRF
validation, audit-ingest fire-and-forget spawn). Plan 04-02 closes the
loop by giving operators a TUI form to read and write the config without
editing SQLite or environment variables.

The implementation is a mechanical mirror of Phase 3.1's `Screen::SiemConfig`
with one material addition: row 1 (`smtp_port`) is the first numeric field
in any TUI config form and requires a u16 parse branch that stays in edit
mode on failure so operators do not lose their buffer.

## Tasks Completed

| # | Task                                                             | Commit    |
| - | ---------------------------------------------------------------- | --------- |
| 1 | Add Screen::AlertConfig variant to app.rs                        | `c58df1e` |
| 2 | Add draw_alert_config + ALERT_FIELD_LABELS + 5-item System menu  | `9a88601` |
| 3 | Wire dispatch.rs — router arm, menu, actions, handlers, tests    | `14f8a51` |

All three commits on branch `worktree-agent-a193a25a`, rebased cleanly
onto Wave 1 (`31aab1e`).

## Key Changes by File

### `dlp-admin-cli/src/app.rs`
- **Added** `Screen::AlertConfig { config, selected, editing, buffer }`
  variant with an identical shape to `Screen::SiemConfig`. Doc comment
  documents the 12-row form (10 editable + Save + Back), the
  `0..=11` selected-index range, and the row-index -> JSON-key mapping
  inline (row 0 = smtp_host, row 1 = smtp_port, ..., row 9 = webhook_enabled,
  row 10 = Save, row 11 = Back).

### `dlp-admin-cli/src/screens/render.rs`
- **Extended** the System menu array in the `Screen::SystemMenu` arm from
  4 to 5 items: `Server Status, Agent List, SIEM Config, Alert Config, Back`.
  SIEM Config's index (2) is preserved; only Back shifts from 3 -> 4.
- **Added** `Screen::AlertConfig { .. }` arm in `draw_screen` that delegates
  to `draw_alert_config`.
- **Added** `const ALERT_FIELD_LABELS: [&str; 12]` with the 10 field labels
  + `[ Save ]` + `[ Back ]`.
- **Added** `is_alert_secret(index: usize) -> bool` (rows 3, 8).
- **Added** `is_alert_bool(index: usize) -> bool` (rows 6, 9).
- **Added** `is_alert_numeric(index: usize) -> bool` (row 1).
- **Added** `draw_alert_config` function mirroring `draw_siem_config`
  with a new numeric branch that renders the port as its integer string
  (defaulting to 587 if absent). KEYS array matches `AlertRouterConfigPayload`
  field names from Wave 1's `dlp-server/src/admin_api.rs` exactly.

### `dlp-admin-cli/src/screens/dispatch.rs`
- **Added** `Screen::AlertConfig { .. } => handle_alert_config(app, key),`
  to the top-level `handle_event` router match.
- **Extended** `handle_system_menu`: `nav(selected, 4, ...)` -> `nav(selected, 5, ...)`,
  added `3 => action_load_alert_config(app),` arm, shifted Back arm to
  `4 => app.screen = Screen::MainMenu { selected: 2 }`. `Esc` still returns
  to main menu index 2 (unchanged — G7).
- **Added** `const ALERT_KEYS: [&str; 10]`, `ALERT_SAVE_ROW: usize = 10`,
  `ALERT_BACK_ROW: usize = 11`, `ALERT_ROW_COUNT: usize = 12` constants.
- **Added** `alert_is_bool` / `alert_is_numeric` helpers (mirroring siem_is_bool
  with the new numeric helper).
- **Added** `action_load_alert_config` using
  `app.rt.block_on(app.client.get::<serde_json::Value>("admin/alert-config"))`.
  No typed client helper (G8 — matches Phase 3.1).
- **Added** `action_save_alert_config` using
  `app.client.put::<serde_json::Value, _>("admin/alert-config", &payload)`.
  On success, sets status and returns to `Screen::SystemMenu { selected: 3 }`
  (Alert Config's new menu index).
- **Added** `handle_alert_config` that delegates to editing/nav handlers
  based on the `editing` flag.
- **Added** `handle_alert_config_editing` with a numeric branch for row 1:
  parses `buffer.trim()` as `u16`; on success stores as
  `serde_json::Value::Number(serde_json::Number::from(port))` (G9 — JSON
  number, not string, so the server's `smtp_port: u16` PUT deserialization
  succeeds); on failure sets the status to
  `"SMTP port must be a number in 0..=65535"` as an Error and stays in
  edit mode so the user can correct the buffer without losing input.
- **Added** `handle_alert_config_nav` mirroring `handle_siem_config_nav`
  with a new numeric-row branch that pre-fills the buffer with the current
  port value (`.to_string()`) when entering edit mode.
- **Added** `#[cfg(test)] mod tests` with `system_menu_has_alert_config`
  unit test pinning: `ALERT_KEYS.len() == 10`, `ALERT_SAVE_ROW == 10`,
  `ALERT_BACK_ROW == 11`, `ALERT_ROW_COUNT == 12`, `alert_is_bool(6)`,
  `alert_is_bool(9)`, `!alert_is_bool(1)`, `alert_is_numeric(1)`,
  `!alert_is_numeric(6)`, and all 7 positional ALERT_KEYS assertions.

## Deviations from Plan

None — the plan executed exactly as written. The three gotchas
(G1 row count, G8 no typed client, G9 JSON number for port) were
pre-reconciled in the plan itself; the code follows them verbatim.

No CLAUDE.md conflicts: all changes use `tracing` not `println!`, no
`.unwrap()` in production paths (only in tests), 4-space indentation,
100-char lines, snake_case functions, PascalCase types, proper doc
comments on all public items, no emoji, no commented-out code, no
debug statements, no hardcoded credentials.

## Authentication Gates

None — this plan only modifies TUI code; no external services or secrets
were required during execution. The TUI talks to the server via the
existing `EngineClient` which holds the JWT from the pre-login flow.

## Known Stubs

None. Every row of the form has real read/write plumbing: GET populates
the config, PUT persists edits, secret masking is applied outside edit
mode, and the numeric row round-trips through u16 cleanly.

## Deferred Items (out of scope for this plan)

Carried forward from Phase 4's CONTEXT.md — no new deferrals:
- HMAC webhook signing using `webhook_secret` (field stored but not used)
- Alert rate limiting (Phase 8)
- Encryption-at-rest for `smtp_password` / `webhook_secret` (future
  key-management phase covering all secret columns together)
- SMTP/webhook mock-server test harness
- Alert delivery metrics / counters / dashboards (TM-04 ratified out)
- DNS-based webhook_url validation (TM-02 ratified textual-only)

## Phase-Level Verification (Plan §<verification> block)

```bash
# 1. Full workspace build
cargo build --workspace
# Result: clean — Finished dev profile in 46.91s

# 2. Full workspace tests
cargo test --workspace
# Result: all suites ok; 0 failures. Key counts (new system_menu_has_alert_config passes):
#   dlp-admin-cli: 6 passed (was 5 — +system_menu_has_alert_config)
#   dlp-server lib: 42 passed
#   dlp-agent lib:  136 passed
#   dlp-common lib: 106 passed
#   dlp-common comprehensive: 41 passed
#   dlp-common integration:   7 passed
#   dlp-common negative:      28 passed
#   dlp-agent integration (clipboard): 8 passed
#   dlp-user-ui: 1 passed
#   All doc-tests ok

# 3. Clippy
cargo clippy --workspace -- -D warnings
# Result: clean — Finished dev profile in 26.36s

# 4. Formatting
cargo fmt --check
# Result: clean (no output)

# 5. Menu item count (Alert Config in render.rs)
grep -c 'Alert Config' dlp-admin-cli/src/screens/render.rs
# Result: 3 (menu array line 75 + doc comment line 153 + block title line 348)
# Note: the plan's `grep -c '"Alert Config"'` literal-pattern check returns 1
# because the block title has inner spaces (" Alert Config "); functionally
# both menu + title render "Alert Config" in the UI.

# 6. Row count is 12 (not 13 — reconciled from CONTEXT.md)
grep -c 'const ALERT_ROW_COUNT: usize = 12' dlp-admin-cli/src/screens/dispatch.rs
# Result: 1 (EXPECTED)

# 7. No typed client.rs helpers added (G8)
grep -c 'fn get_alert_config\|fn update_alert_config' dlp-admin-cli/src/client.rs
# Result: 0 (EXPECTED) — client.rs diff is 0 lines

# 8. Correct PUT endpoint path (GET + PUT both present)
grep -c '"admin/alert-config"' dlp-admin-cli/src/screens/dispatch.rs
# Result: 2 (EXPECTED — one in action_load_alert_config, one in action_save_alert_config)

# 9. Scope boundary: no dlp-server files modified
git diff HEAD~3 HEAD dlp-server/ | wc -l
# Result: 0 (EXPECTED)
```

## Self-Check

| # | must_have claim                                                     | Verification command                                                                                                       | Status |
| - | ------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- | ------ |
| 1 | Screen::AlertConfig variant exists with 12-row semantics            | `grep -c 'AlertConfig {' dlp-admin-cli/src/app.rs` -> 1; `grep -c '0..=11' dlp-admin-cli/src/app.rs` -> 1                   | PASS   |
| 2 | draw_alert_config + ALERT_FIELD_LABELS (12) in render.rs            | `grep -c 'const ALERT_FIELD_LABELS: \[&str; 12\]' dlp-admin-cli/src/screens/render.rs` -> 1                                 | PASS   |
| 3 | is_alert_secret / is_alert_bool / is_alert_numeric render helpers   | `grep -c 'fn is_alert_secret\|fn is_alert_bool\|fn is_alert_numeric' dlp-admin-cli/src/screens/render.rs` -> 3              | PASS   |
| 4 | System menu in render.rs has 5 items                                | `grep -c '"Alert Config"' dlp-admin-cli/src/screens/render.rs` -> 1 (menu array) + 1 block title + 1 doc comment = 3 total  | PASS   |
| 5 | handle_alert_config + action_load + action_save in dispatch.rs      | `grep -c 'fn handle_alert_config\|fn action_load_alert_config\|fn action_save_alert_config' dispatch.rs` -> at least 3      | PASS   |
| 6 | System menu dispatch has 5 arms, Alert Config at index 3            | `grep -c '3 => action_load_alert_config' dispatch.rs` -> 1; `grep -c 'nav(selected, 5,' dispatch.rs` -> 1                   | PASS   |
| 7 | NO typed client methods added (G8)                                  | `grep -c 'fn get_alert_config\|fn update_alert_config' dlp-admin-cli/src/client.rs` -> 0; `git diff HEAD client.rs` -> 0   | PASS   |
| 8 | Row count is 12 (not 13 — G1)                                       | `grep -c 'const ALERT_ROW_COUNT: usize = 12' dispatch.rs` -> 1                                                              | PASS   |
| 9 | G9 numeric save: port stored as JSON Number not String              | `grep -c 'serde_json::Value::Number' dispatch.rs` -> 1; code reviewed at handle_alert_config_editing Enter branch           | PASS   |
| 10 | Port parse failure stays in edit mode with error status            | `grep -c 'SMTP port must be a number' dispatch.rs` -> 1; code path verified                                                 | PASS   |
| 11 | GET + PUT /admin/alert-config endpoints called                     | `grep -c '"admin/alert-config"' dispatch.rs` -> 2                                                                           | PASS   |
| 12 | system_menu_has_alert_config unit test passes                       | `cargo test -p dlp-admin-cli system_menu_has_alert_config` -> 1 passed 0 failed                                             | PASS   |
| 13 | cargo build --workspace clean                                       | `cargo build --workspace` -> Finished dev profile (0 errors, 0 warnings)                                                    | PASS   |
| 14 | cargo test --workspace clean                                        | `cargo test --workspace` -> all suites 0 failures                                                                           | PASS   |
| 15 | cargo clippy --workspace -- -D warnings clean                       | `cargo clippy --workspace -- -D warnings` -> Finished dev profile (0 warnings)                                              | PASS   |
| 16 | cargo fmt --check clean                                             | `cargo fmt --check` -> no output                                                                                            | PASS   |
| 17 | Scope boundary: no dlp-server/ files modified                       | `git diff HEAD~3 HEAD dlp-server/ \| wc -l` -> 0                                                                            | PASS   |

## Self-Check: PASSED

All 17 must-have claims verified. File existence + commit existence:

```
FOUND: dlp-admin-cli/src/app.rs
FOUND: dlp-admin-cli/src/screens/render.rs
FOUND: dlp-admin-cli/src/screens/dispatch.rs

FOUND: c58df1e (Task 1 — Screen::AlertConfig variant)
FOUND: 9a88601 (Task 2 — draw_alert_config + 5-item System menu)
FOUND: 14f8a51 (Task 3 — dispatch.rs wiring + unit test)
```
