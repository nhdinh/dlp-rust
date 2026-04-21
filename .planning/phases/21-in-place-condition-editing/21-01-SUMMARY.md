---
phase: 21-in-place-condition-editing
plan: "01"
subsystem: ui
tags: [ratatui, crossterm, tui, conditions-builder, abac, policy]

requires:
  - phase: 20-operator-expansion
    provides: operators_for() helper and SC-1 operator-reset guard used by edit mode

provides:
  - edit_index: Option<usize> field in Screen::ConditionsBuilder for tracking in-place edit mode
  - condition_to_prefill() helper — inverse of build_condition, decomposes PolicyCondition into picker pre-fill tuple
  - 'e'/'E' key handler in handle_conditions_pending that opens the 3-step picker pre-filled with existing condition data
  - Index-aware step-3 commit in both handle_conditions_step3_text and handle_conditions_step3_select
  - Conditional modal title: "Edit Condition" when edit_index.is_some(), "Conditions Builder" otherwise
  - 'e: Edit' hint in pending-focused hints bar
  - PartialEq derive on PolicyCondition in dlp-common (required for test assertions)
  - 4 new unit tests covering roundtrip, open, replace, and cancel behaviors

affects:
  - any future phase modifying Screen::ConditionsBuilder variant
  - any future phase touching handle_conditions_pending, step3_text, or step3_select

tech-stack:
  added: []
  patterns:
    - "Two-phase borrow pattern for reading pending[i] then mutating app.screen fields"
    - "condition_to_prefill as the inverse of build_condition for picker state restoration"
    - "match *edit_index pattern for in-place replace vs append commit branching"

key-files:
  created: []
  modified:
    - dlp-common/src/abac.rs
    - dlp-admin-cli/src/app.rs
    - dlp-admin-cli/src/screens/dispatch.rs
    - dlp-admin-cli/src/screens/render.rs

key-decisions:
  - "PartialEq added to PolicyCondition — all inner variant types already implement PartialEq; required for assert_eq! in test assertions (Rule 2 auto-fix)"
  - "Edit mode starts at Step 1 (pre-filled), not Step 3 — allows attribute change with SC-1 operator guard to fire naturally; simpler test coverage"
  - "edit_index cleared only on commit (Enter at Step 3), not on Esc — Esc leaves pending[i] untouched so no restore logic needed"
  - "picker_idx from condition_to_prefill not applied to picker_state in 'e' handler — picker_state is shared across all steps; Step 1 attr_idx is set; op pre-fill handled via selected_operator"

patterns-established:
  - "condition_to_prefill(): place adjacent to build_condition, use identical import block, exhaustive match on all 5 variants"
  - "Edit-mode commit: match *edit_index { Some(i) if i < pending.len() => replace; _ => push } before shared reset block"

requirements-completed: [POLICY-10]

duration: 25min
completed: 2026-04-21
---

# Phase 21 Plan 01: In-Place Condition Editing Summary

**In-place condition editing for ConditionsBuilder TUI modal: 'e' key pre-fills 3-step picker at existing condition's attribute/op/value, saving replaces at original index, Esc leaves pending list unchanged**

## Performance

- **Duration:** ~25 min
- **Started:** 2026-04-21T06:57:00Z
- **Completed:** 2026-04-21T07:21:59Z
- **Tasks:** 2 of 2
- **Files modified:** 4

## Accomplishments

- Added `edit_index: Option<usize>` to `Screen::ConditionsBuilder` as the single flag distinguishing edit mode from new-condition mode
- Implemented `condition_to_prefill()` as the inverse of `build_condition` for all 5 `PolicyCondition` variants with full roundtrip coverage
- Wired 'e'/'E' key in `handle_conditions_pending` using the two-phase borrow pattern; pre-fills attribute picker, operator, buffer, and sets `edit_index`
- Updated both step-3 commit blocks (`step3_text` and `step3_select`) with index-aware replace-vs-push logic
- Threaded `edit_index` through `draw_conditions_builder` signature for conditional "Edit Condition" modal title and 'e: Edit' hints bar entry
- Added `PartialEq` to `PolicyCondition` in `dlp-common` (required for test assertions — all inner types already implement it)
- 4 new unit tests pass: roundtrip, open pre-fill, replace-at-index, cancel-preserves

## Task Commits

1. **Task 1: Add edit_index state, condition_to_prefill helper, 'e' key handler, index-aware step-3 commit** - `8c6decb` (feat)
2. **Task 2: Thread edit_index into render.rs — conditional modal title and 'e: Edit' hint** - `fb665b0` (feat)

## Files Created/Modified

- `dlp-common/src/abac.rs` — Added `PartialEq` derive to `PolicyCondition`
- `dlp-admin-cli/src/app.rs` — Added `edit_index: Option<usize>` field with doc comment to `Screen::ConditionsBuilder` variant
- `dlp-admin-cli/src/screens/dispatch.rs` — Added `condition_to_prefill()`, 'e' key handler, index-aware step-3 commits, `edit_index: None` at both open call sites, 4 unit tests
- `dlp-admin-cli/src/screens/render.rs` — Updated `draw_conditions_builder` signature, conditional modal title, 'e: Edit' hints bar entry

## Decisions Made

- `PartialEq` added to `PolicyCondition` — all inner variant types already implement it; needed for `assert_eq!` in the 4 new unit tests. Rule 2 auto-fix (missing correctness requirement).
- Edit mode starts at Step 1 (pre-filled, not Step 3 jump) — operator reset SC-1 guard fires naturally on attribute change; cleaner test surface; matches "re-enter" UX pattern.
- `edit_index` is cleared only on commit (Enter at Step 3), not on Esc — Esc leaves `pending[i]` untouched, so no state restore logic is needed anywhere; original SC-3 guarantee holds automatically.
- `picker_idx` from `condition_to_prefill` is intentionally not applied to `picker_state` in the 'e' handler — `picker_state` is shared across steps; Step 1 sets `attr_idx`; the op wire string in `selected_operator` handles Step 2 pre-fill via `handle_conditions_step2` logic.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical] Added PartialEq to PolicyCondition in dlp-common**
- **Found during:** Task 1 (RED phase — writing tests)
- **Issue:** `PolicyCondition` only derived `Debug, Clone, Serialize, Deserialize`. All 4 new tests require `assert_eq!` on `PolicyCondition` values. Without `PartialEq`, the tests fail to compile with `error[E0369]: binary operation == cannot be applied to type PolicyCondition`.
- **Fix:** Added `PartialEq` to `#[derive(...)]` on `PolicyCondition` in `dlp-common/src/abac.rs`. All inner types (`Classification`, `DeviceTrust`, `NetworkLocation`, `AccessContext`) already implement `PartialEq`.
- **Files modified:** `dlp-common/src/abac.rs`
- **Verification:** `cargo build --all` zero warnings; `cargo test -p dlp-admin-cli` 42/42 pass; `cargo test -p dlp-server` 145/145 pass
- **Committed in:** `8c6decb` (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (Rule 2 — missing critical derive)
**Impact on plan:** Essential for test correctness. Zero scope creep. The fix is additive and backward-compatible (no existing code was broken by adding `PartialEq` to `PolicyCondition`).

## Issues Encountered

- `cargo fmt` required after implementation — return tuples in `condition_to_prefill` and some inline struct patterns exceeded 100-char line limit. Fixed by running `cargo fmt -p dlp-admin-cli` before Task 2 commit.

## User Setup Required

None — no external service configuration required. This is a TUI-only change with no server, network, or database involvement.

## Next Phase Readiness

- POLICY-10 complete: in-place condition editing is fully functional in the ConditionsBuilder modal
- v0.5.0 Boolean Logic milestone: all 4 requirements (POLICY-09 through POLICY-12) are now delivered
- Zero regressions: 42 dlp-admin-cli tests and 145 dlp-server tests pass; 8 pre-existing dlp-agent todo!() stubs unchanged
- Manual UAT required: launch TUI, open conditions builder, press 'e' on a condition — verify "Edit Condition" title, pre-filled fields, in-place replace on save

---
*Phase: 21-in-place-condition-editing*
*Completed: 2026-04-21*
