---
phase: 14-policy-create
plan: "01"
subsystem: dlp-admin-cli
tags: [tui, policy, form, dispatch, abac, conditions-builder]
dependency_graph:
  requires: [13-conditions-builder]
  provides: [Screen::PolicyCreate, handle_policy_create, action_submit_policy, CallerScreen-Esc-dispatch]
  affects: [dlp-admin-cli/src/app.rs, dlp-admin-cli/src/screens/dispatch.rs, dlp-admin-cli/src/screens/render.rs]
tech_stack:
  added: [uuid = { version = "1", features = ["v4"] }]
  patterns: [two-phase-borrow, CallerScreen-round-trip, form-snapshot-in-ConditionsBuilder]
key_files:
  created: []
  modified:
    - dlp-admin-cli/Cargo.toml
    - dlp-admin-cli/src/app.rs
    - dlp-admin-cli/src/screens/dispatch.rs
    - dlp-admin-cli/src/screens/render.rs
    - dlp-admin-cli/src/client.rs
decisions:
  - "ACTION_OPTIONS uses DenyWithAlert (not DenyWithLog) — matches actual Decision enum in dlp-common"
  - "form_snapshot stored in Screen::ConditionsBuilder so form fields survive the modal round-trip"
  - "EngineClient::for_test() added under #[cfg(test)] to enable unit tests without network"
  - "CreatePolicyFromFile variant retained with #[allow(dead_code)] for Phase 17 import/export"
metrics:
  duration: "~20 minutes"
  completed: "2026-04-16T18:32:33Z"
  tasks_completed: 3
  tasks_total: 3
  files_changed: 5
---

# Phase 14 Plan 01: Policy Create State Model and Dispatch Summary

Policy create screen state model, full keyboard dispatch handler, validation, HTTP POST, CallerScreen round-trip, and 5 unit tests — all in dlp-admin-cli with no new files required.

## Tasks Completed

| Task | Name | Commit | Key Files |
|------|------|--------|-----------|
| 1 | State model: Screen::PolicyCreate, ACTION_OPTIONS, form_snapshot, uuid dep | 0ff9a14 | Cargo.toml, app.rs, render.rs |
| 2 | Dispatch: handle_policy_create, action_submit_policy, CallerScreen Esc fix, PolicyMenu entry | 685b857 | dispatch.rs |
| 3 | Unit tests: validation, wire format, CallerScreen dispatch | 3996218 | dispatch.rs, client.rs, app.rs, render.rs |

## What Was Built

**app.rs changes:**
- Added `ACTION_OPTIONS: [&str; 4] = ["ALLOW", "DENY", "AllowWithLog", "DenyWithAlert"]` constant
- Added `form_snapshot: PolicyFormState` field to `Screen::ConditionsBuilder` variant
- Added `Screen::PolicyCreate` variant with `form`, `selected`, `editing`, `buffer`, `validation_error` fields
- Fixed `PolicyFormState.action` doc comment: DenyWithAlert not DenyWithLog
- Removed broad `#[allow(dead_code)]` from `CallerScreen` and `PolicyFormState` — now actively used
- Added targeted `#[allow(dead_code)]` on `PolicyEdit` variant and `enabled` field (Phase 15 will use them)

**Cargo.toml:**
- Added `uuid = { version = "1", features = ["v4"] }` for UUID v4 policy ID generation

**dispatch.rs changes:**
- Updated imports to include `CallerScreen`, `PolicyFormState`, `ACTION_OPTIONS`
- Added `POLICY_NAME_ROW` through `POLICY_SUBMIT_ROW` constants and `POLICY_ROW_COUNT = 7`
- Added `Screen::PolicyCreate { .. } => handle_policy_create(app, key)` routing arm
- Replaced `PolicyMenu` item 2 `TextInput` with `Screen::PolicyCreate` navigation
- Updated temporary `'c'` key `ConditionsBuilder` construction with `form_snapshot: PolicyFormState::default()`
- Added `handle_policy_create` top-level dispatcher (editing vs nav)
- Added `handle_policy_create_editing` (char/backspace/enter/esc for text fields, two-phase borrow)
- Added `handle_policy_create_nav` (up/down/enter on all 7 rows, action cycling, ConditionsBuilder entry)
- Added `action_submit_policy` (validates name non-empty + priority as u32, builds UUID payload, POST admin/policies)
- Fixed both `ConditionsBuilder` Esc placeholder arms to use `CallerScreen` dispatch

**render.rs:**
- Added `Screen::PolicyCreate { .. } => {}` stub arm (Plan 14-02 implements the draw function)

**client.rs:**
- Added `EngineClient::for_test()` under `#[cfg(test)]` for unit test infrastructure

## Verification Results

```
cargo test -p dlp-admin-cli: 22 passed, 0 failed
cargo clippy -p dlp-admin-cli -- -D warnings: PASSED
cargo fmt -p dlp-admin-cli --check: PASSED
cargo check -p dlp-admin-cli: PASSED (no errors)
```

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical Functionality] Added targeted #[allow(dead_code)] attributes**
- **Found during:** Task 3 clippy run
- **Issue:** Removing the broad `#[allow(dead_code)]` from `CallerScreen` and `PolicyFormState` caused `clippy -D warnings` to fail on `PolicyEdit` variant, `enabled` field, and `CreatePolicyFromFile` variant — all legitimately needed by Phase 15 and 17 but not yet constructed.
- **Fix:** Added targeted `#[allow(dead_code)]` on each specific item with doc comments indicating which future phase consumes it.
- **Files modified:** `dlp-admin-cli/src/app.rs`
- **Commit:** 3996218

**2. [Rule 2 - Missing Critical Functionality] Added EngineClient::for_test() constructor**
- **Found during:** Task 3 test writing
- **Issue:** `App` requires an `EngineClient` which has only private fields and no test constructor — making it impossible to write unit tests for `action_submit_policy` without a running server.
- **Fix:** Added `#[cfg(test)] pub fn for_test() -> Self` to `EngineClient` that builds a `reqwest::Client` pointing at `127.0.0.1:0` (non-routable). Tests exercise only the validation path which returns before any network call.
- **Files modified:** `dlp-admin-cli/src/client.rs`
- **Commit:** 3996218

## Known Stubs

- `Screen::PolicyCreate { .. } => {}` in `render.rs` `draw_screen` — intentional stub for Plan 14-02 which implements `draw_policy_create`.

## Threat Surface Scan

No new network endpoints introduced. The POST to `admin/policies` uses the existing `EngineClient::post` which attaches the JWT from the authenticated session (mitigates T-14-02). UUID v4 generated at submit time (mitigates T-14-03). Priority parsed as u32 client-side (mitigates T-14-05). Conditions serialized from typed `Vec<PolicyCondition>` via serde — no raw JSON entry (mitigates T-14-01).

## Self-Check

**Created files:**
- `.planning/phases/14-policy-create/14-01-SUMMARY.md` — this file

**Commits exist:**
- 0ff9a14: feat(14-01): add Screen::PolicyCreate, ACTION_OPTIONS, form_snapshot, uuid dep
- 685b857: feat(14-01): add handle_policy_create, action_submit_policy, CallerScreen Esc fix
- 3996218: test(14-01): add 5 unit tests for validation, wire format, and CallerScreen dispatch

## Self-Check: PASSED
