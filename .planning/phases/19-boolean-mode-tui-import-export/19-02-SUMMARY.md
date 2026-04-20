---
phase: 19-boolean-mode-tui-import-export
plan: 02
subsystem: ui
tags: [ratatui, serde, serde_json, dlp-admin-cli, dlp-server, policy, abac, PolicyMode, integration-tests, tokio]

# Dependency graph
requires:
  - phase: 19-01-wire-format-and-submit-fix
    provides: "PolicyFormState.mode field, PolicyResponse.mode, PolicyPayload.mode, submit payloads carry mode"
  - phase: 18-boolean-mode-engine-wire-format
    provides: "PolicyMode enum (ALL/ANY/NONE), evaluator boolean semantics in PolicyStore::evaluate"

provides:
  - "POLICY_MODE_ROW=5 const + renumbered trailing consts (6/7/8/9) in dispatch.rs"
  - "cycle_mode() helper cycling ALL->ANY->NONE->ALL"
  - "Enter + Space cyclers for POLICY_MODE_ROW in both PolicyCreate and PolicyEdit nav handlers"
  - "POLICY_FIELD_LABELS extended to 9 elements with 'Mode' at index 5"
  - "Mode render arm at index 5 in both draw_policy_create and draw_policy_edit"
  - "Footer advisory overlay in both Create and Edit (DarkGray hint when mode!=ALL && conditions empty && no validation error)"
  - "4 integration tests in dlp-server/tests/mode_end_to_end.rs proving three-mode HTTP semantics"

affects:
  - 20-operator-expansion
  - 21-in-place-condition-editing
  - any phase reading POLICY_*_ROW constants or POLICY_FIELD_LABELS

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "cycle_mode() free function pattern: typed enum -> typed enum (no string conversion, Copy type)"
    - "Footer advisory overlay: same Rect slot as validation_error but gated on validation_error.is_none()"
    - "Integration test with alternative CARGO_TARGET_DIR to avoid locked binary on Windows dev machines"

key-files:
  created:
    - dlp-server/tests/mode_end_to_end.rs
  modified:
    - dlp-admin-cli/src/screens/dispatch.rs
    - dlp-admin-cli/src/screens/render.rs
    - dlp-server/src/audit_store.rs

key-decisions:
  - "PolicyMode::ALL arm in footer advisory match is exhaustive-but-unreachable — Rust requires it, empty string renders nothing"
  - "conditions JSON uses 'attribute': 'access_context' (snake_case serde tag) not 'accesscontext' (plan template had a typo)"
  - "Integration tests use CARGO_TARGET_DIR=target-test to bypass Windows file-lock on dlp-server.exe held by elevated process"

patterns-established:
  - "cycle_mode(): exhaustive match returning next enum variant, no string intermediaries"
  - "Footer advisory: placed BEFORE validation_error block, gated on is_none() so errors take display priority"

requirements-completed: [POLICY-09]

# Metrics
duration: 45min
completed: 2026-04-21
---

# Phase 19 Plan 02: TUI Form and Integration Tests Summary

**POLICY_MODE_ROW added to 9-row policy form with Enter/Space cycler, footer advisory for empty-conditions modes, and three HTTP integration tests proving ALL/ANY/NONE boolean semantics via /evaluate**

## Performance

- **Duration:** 45 min
- **Started:** 2026-04-21T01:00:00Z
- **Completed:** 2026-04-21T01:45:00Z
- **Tasks:** 3
- **Files modified:** 4 (dispatch.rs, render.rs, mode_end_to_end.rs, audit_store.rs)

## Accomplishments

- Renumbered POLICY_*_ROW consts to insert POLICY_MODE_ROW=5 (trailing consts shifted to 6/7/8/9), added `cycle_mode()` helper, wired Enter and Space cyclers in both PolicyCreate and PolicyEdit nav handlers
- Extended POLICY_FIELD_LABELS from 8 to 9 elements, added Mode render arm at index 5 in both `draw_policy_create` and `draw_policy_edit`, added footer advisory overlays (DarkGray hint when mode is not ALL and conditions list is empty)
- Created `dlp-server/tests/mode_end_to_end.rs` with 4 tests: 3 HTTP integration tests exercising ALL/ANY/NONE against `/evaluate` + 1 data-layer round-trip test; all 4 pass

## Task Commits

Each task was committed atomically:

1. **Task 1: Renumber consts, add cycle_mode, wire Mode cyclers** - `aff9727` (feat)
2. **Task 2: Extend POLICY_FIELD_LABELS to 9 rows, Mode arm, footer advisory** - `bb6cf67` (feat)
3. **Task 3: Create mode_end_to_end.rs integration tests** - `d7233c0` (feat) + `32ef5ee` (style: fmt)

**Plan metadata:** (docs commit — created during summary step)

## Files Created/Modified

- `dlp-admin-cli/src/screens/dispatch.rs` — Renumbered 5 POLICY_*_ROW consts; added `cycle_mode()` helper with doc comment; inserted POLICY_MODE_ROW arm (Enter + Space) in both `handle_policy_create_nav` and `handle_policy_edit_nav`; migrated `selected > 2` guards to `selected > POLICY_PRIORITY_ROW`
- `dlp-admin-cli/src/screens/render.rs` — Added `use dlp_common::abac::PolicyMode`; extended POLICY_FIELD_LABELS to `[&str; 9]` with "Mode" at index 5; added Mode arm at `5 =>` in both Create and Edit; renumbered [Add Conditions]/Conditions/[Submit-Save] arms to 6/7/8; replaced `Vec::with_capacity(8)` with `Vec::with_capacity(POLICY_FIELD_LABELS.len())` in draw_policy_edit; added footer advisory overlay in both Create and Edit
- `dlp-server/tests/mode_end_to_end.rs` — New file: 3 async tokio HTTP tests + 1 sync serde round-trip test; uses identical test harness as admin_audit_integration.rs
- `dlp-server/src/audit_store.rs` — [Rule 1 - Bug] Fixed pre-existing `explicit-auto-deref` clippy warning (`&mut *conn` -> `&mut conn`) that blocked `cargo clippy --tests -D warnings`

## Decisions Made

- `PolicyMode::ALL` arm in the footer advisory match is exhaustive-but-unreachable. Rust requires all three variants be covered in a match on `PolicyMode`; the outer `form.mode != PolicyMode::ALL` guard makes the ALL arm unreachable in practice. The empty string `""` renders nothing.
- Conditions JSON in integration tests uses `"attribute": "access_context"` (snake_case from `#[serde(tag = "attribute", rename_all = "snake_case")]` on `PolicyCondition::AccessContext`). The plan template had a typo (`"accesscontext"`); verified against actual enum definition.
- `AccessContext` values in evaluate request use lowercase (`"local"`, `"smb"`) per `#[serde(rename_all = "lowercase")]` on that enum.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed pre-existing `explicit-auto-deref` clippy warning in audit_store.rs**
- **Found during:** Task 3 verification (`cargo clippy -p dlp-server --tests -D warnings`)
- **Issue:** `&mut *conn` in `audit_store.rs` test code triggered the `explicit-auto-deref` lint only when compiling with `--tests` flag; the plan's acceptance criteria require `cargo clippy --tests -D warnings` to pass
- **Fix:** Changed `&mut *conn` to `&mut conn` — a single-character removal that Rust auto-deref handles identically
- **Files modified:** `dlp-server/src/audit_store.rs`
- **Verification:** `cargo clippy -p dlp-server --tests -D warnings` passes cleanly
- **Committed in:** `d7233c0` (Task 3 commit)

**2. [Rule 3 - Blocking] conditions JSON attribute tag corrected from plan template typo**
- **Found during:** Task 3 implementation (reading dlp-common/src/abac.rs)
- **Issue:** Plan template used `"attribute": "accesscontext"` (no underscore) but the actual `PolicyCondition::AccessContext` variant serializes to `"access_context"` via `rename_all = "snake_case"`
- **Fix:** Used `"access_context"` in all conditions JSON literals; `"local"` and `"smb"` (lowercase) for AccessContext values
- **Files modified:** `dlp-server/tests/mode_end_to_end.rs`
- **Verification:** All 4 tests pass
- **Committed in:** `d7233c0` (Task 3 commit)

---

**Total deviations:** 2 auto-fixed (1 Rule 1 bug fix, 1 Rule 3 blocking fix)
**Impact on plan:** Both auto-fixes were necessary for correctness. No scope creep.

## Issues Encountered

- `dlp-server.exe` was locked by an elevated process (PID 58812, running since the previous dev session). `cargo test -p dlp-server` could not overwrite the binary during compilation. Workaround: set `CARGO_TARGET_DIR=target-test` to compile into a parallel output directory. All 4 tests passed cleanly in the alternate directory. The locked binary does not affect correctness of the test file.

## Known Stubs

None — all new fields are fully wired and rendered.

## Threat Surface Scan

No new network endpoints introduced. The Mode row dispatch only mutates `form.mode` in-memory; the server-side path was covered in Phase 18 (T-19-05, T-19-06 mitigations). The footer advisory is static text (T-19-07 accepted). No new trust boundaries.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- POLICY-09 is fully closed: mode picker renders and cycles in both Create and Edit, three HTTP integration tests prove boolean semantics end-to-end
- Phase 20 (Operator Expansion) can proceed: the `PolicyMode` enum and the 9-row form are stable
- Phase 21 (In-Place Condition Editing) can proceed: `POLICY_CONDITIONS_DISPLAY_ROW=7` and `POLICY_ADD_CONDITIONS_ROW=6` are the correct row indices post-renumber

---
*Phase: 19-boolean-mode-tui-import-export*
*Completed: 2026-04-21*
