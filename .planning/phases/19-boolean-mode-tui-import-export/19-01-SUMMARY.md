---
phase: 19-boolean-mode-tui-import-export
plan: 01
subsystem: ui
tags: [ratatui, serde, serde_json, dlp-admin-cli, policy, abac, PolicyMode]

# Dependency graph
requires:
  - phase: 18-boolean-mode-engine-wire-format
    provides: "PolicyMode enum in dlp_common::abac with Copy + Serialize + Deserialize + Default"

provides:
  - "PolicyFormState.mode field (in-memory, no serde) — Wave 2 can mutate it"
  - "PolicyResponse.mode field with #[serde(default)] — legacy import files tolerated"
  - "PolicyPayload.mode field with #[serde(default)] — export/import round-trip correct"
  - "From<PolicyResponse> for PolicyPayload copies mode (no clone needed, Copy type)"
  - "action_submit_policy POST body carries mode — silent-drop bug fixed"
  - "action_submit_policy_update PUT body carries mode — silent-drop bug fixed"
  - "action_load_policy_for_edit prefills form.mode from GET response"
  - "6 unit tests covering serde default, explicit, round-trip, legacy, From copy, form default"

affects:
  - 19-02-boolean-mode-tui-picker
  - any phase using PolicyFormState, PolicyResponse, PolicyPayload

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "policy_mode_to_wire() free function pattern: maps typed enum to &'static str for json! macro use"
    - "#[serde(default)] on wire struct fields for backward-compatible import of legacy JSON exports"
    - "TDD RED/GREEN: tests written before struct field additions, compile errors confirm RED phase"

key-files:
  created: []
  modified:
    - dlp-admin-cli/src/app.rs
    - dlp-admin-cli/src/screens/dispatch.rs

key-decisions:
  - "PolicyFormState.mode has NO #[serde(default)] — it is in-memory UI state, not a wire type (Research Pitfall 3)"
  - "policy_mode_to_wire() is a file-scope free function, not a method on PolicyMode, matching existing action_str pattern"
  - "Tolerant match with _ => PolicyMode::ALL fallback in load_policy_for_edit matches existing unwrap_or() pattern in that function"

patterns-established:
  - "policy_mode_to_wire(): maps PolicyMode enum to &'static str for serde_json::json! macro insertion"

requirements-completed: [POLICY-09]

# Metrics
duration: 25min
completed: 2026-04-21
---

# Phase 19 Plan 01: Wire Format and Submit Fix Summary

**PolicyMode field added to three admin-cli structs and wired into POST/PUT payloads, fixing the silent-drop bug where TUI always sent ALL regardless of authored mode**

## Performance

- **Duration:** 25 min
- **Started:** 2026-04-21T00:20:00Z
- **Completed:** 2026-04-21T00:45:00Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- Extended `PolicyFormState`, `PolicyResponse`, and `PolicyPayload` with `pub mode: dlp_common::abac::PolicyMode` — three struct fields total
- Fixed the silent-drop bug: `action_submit_policy` (POST) and `action_submit_policy_update` (PUT) now carry `"mode"` in the `serde_json::json!` payload via `policy_mode_to_wire(form.mode)`
- Wired `action_load_policy_for_edit` to prefill `form.mode` from the GET response (tolerant match, `_ => PolicyMode::ALL` fallback)
- Added 6 targeted unit tests passing all acceptance criteria; all 32 existing tests continue to pass

## Task Commits

Each task was committed atomically:

1. **Task 1: Extend PolicyResponse, PolicyPayload, PolicyFormState, and From impl with mode field** - `ffe703f` (feat)
2. **Task 2: Add mode to POST and PUT submit JSON payloads + prefill mode on load-for-edit** - `9326956` (feat)

**Plan metadata:** (docs commit — created during summary step)

## Files Created/Modified

- `dlp-admin-cli/src/app.rs` — Added `mode` field to `PolicyFormState` (no serde), `PolicyResponse` (`#[serde(default)]`), `PolicyPayload` (`#[serde(default)]`); extended `From` impl; added 6 tests in `mod tests`; fixed 2 existing test struct literals to include `mode`
- `dlp-admin-cli/src/screens/dispatch.rs` — Added `use dlp_common::abac::PolicyMode`; added `fn policy_mode_to_wire()`; added `"mode"` key to POST and PUT `json!` macros; added `mode` prefill in `action_load_policy_for_edit`

## Decisions Made

- `PolicyFormState.mode` has no `#[serde(default)]` — it is in-memory UI state, not a wire type (matches Research Pitfall 3 / PATTERNS §92-94)
- `policy_mode_to_wire()` is a free function at file scope rather than a `PolicyMode` method, keeping the admin-cli decoupled from dlp-common's internals and mirroring the `action_str` local-variable pattern already used in both submit functions

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed existing import_export_tests struct literals missing mode field**
- **Found during:** Task 1 (GREEN phase compile run)
- **Issue:** Two existing tests in `mod import_export_tests` constructed `PolicyResponse` and `PolicyPayload` without `mode`, which became a compile error after the struct field was added
- **Fix:** Added `mode: dlp_common::abac::PolicyMode::ALL` to both struct literals (`policy_response_to_payload_drops_version_and_updated_at` and `policy_payload_roundtrip`)
- **Files modified:** `dlp-admin-cli/src/app.rs`
- **Verification:** `cargo test -p dlp-admin-cli` — all 32 tests pass
- **Committed in:** `ffe703f` (Task 1 commit)

**2. [Rule 3 - Blocking] Implemented Task 2 dispatch.rs changes before Task 1 tests could pass**
- **Found during:** Task 1 GREEN phase — cargo test reported `missing field 'mode' in initializer of 'app::PolicyFormState'` in dispatch.rs
- **Issue:** `action_load_policy_for_edit` constructs `PolicyFormState` without `mode`; this is a separate file (dispatch.rs) but blocked Task 1 compilation
- **Fix:** Proceeded immediately to Task 2 changes (import, helper, POST/PUT fix, prefill) to unblock compilation
- **Files modified:** `dlp-admin-cli/src/screens/dispatch.rs`
- **Verification:** `cargo test -p dlp-admin-cli` — all 32 tests pass; `cargo clippy -p dlp-admin-cli -- -D warnings` clean
- **Committed in:** `9326956` (Task 2 commit)

---

**Total deviations:** 2 auto-fixed (1 Rule 1 bug fix, 1 Rule 3 blocking fix)
**Impact on plan:** Both auto-fixes were necessary for compilation correctness. No scope creep.

## Issues Encountered

- `cargo fmt --check` flagged a 2-line assertion in the new `test_policy_payload_roundtrips_all_three_modes` test (over 100-char line). Reformatted inline before final commit.

## Known Stubs

None — all new fields are fully wired. `PolicyFormState.mode` defaults to `PolicyMode::ALL` via `#[derive(Default)]`, which is the correct initial value (not a stub).

## Threat Surface Scan

No new network endpoints introduced. The `"mode"` field added to POST/PUT bodies is validated server-side by the existing `PolicyMode` serde enum (rejects any string not in `{"ALL","ANY","NONE"}`). No new trust boundaries.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Wave 2 (plan 19-02) can now insert `POLICY_MODE_ROW = 5` and the cycle-on-Enter arm in `handle_policy_create_nav` / `handle_policy_edit_nav` that mutates `form.mode`
- `PolicyFormState.mode`, `PolicyResponse.mode`, `PolicyPayload.mode`, and the submit path carrying `"mode"` all exist — Wave 2 is purely a TUI rendering/dispatch task

---
*Phase: 19-boolean-mode-tui-import-export*
*Completed: 2026-04-21*
