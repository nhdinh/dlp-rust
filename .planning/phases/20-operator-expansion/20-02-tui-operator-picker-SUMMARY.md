---
phase: 20-operator-expansion
plan: "02"
subsystem: ui
tags: [ratatui, tui, conditions-builder, operator-picker, dlp-admin-cli]

# Dependency graph
requires:
  - phase: 20-01-evaluator-operators
    provides: "operators_for extended in dispatch.rs, Wave 1 evaluator gt/lt/contains complete"
provides:
  - "operators_for() is pub(crate) returning per-attribute lists: Classification 4, MemberOf 3, DeviceTrust/NetworkLocation/AccessContext 2"
  - "Step 2 picker in render.rs now delegates to pick_operators(attr) via operators_for"
  - "SC-1 stale-operator reset guard in handle_conditions_step1 Enter arm"
  - "MemberOf Step 3 block title updated to 'AD Group SID (partial match)' per D-07"
  - "6 operator regression tests in operator_tests module"
affects: [phase-21-condition-editing, any-phase-touching-conditions-builder]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Attribute-type-aware picker: pick_operators(attr) in render.rs delegates to operators_for(attr) in dispatch.rs"
    - "SC-1 safety net: stale operator cleared on attribute switch via operators_for validity check"

key-files:
  created: []
  modified:
    - dlp-admin-cli/src/screens/dispatch.rs
    - dlp-admin-cli/src/screens/render.rs

key-decisions:
  - "operators_for is pub(crate) to allow render.rs import without exposing to external crates"
  - "pick_operators helper in render.rs keeps rendering logic co-located with the widget; dispatch.rs owns the data"
  - "SC-1 guard is a defensive safety net — normal navigation already clears selected_operator via Esc"
  - "Nested operator_tests mod inside tests mod follows existing test file structure"

patterns-established:
  - "Attribute-type-aware operator lists: operators_for(attr) is the single source of truth for valid operators per attribute"
  - "Render helpers that need dispatch data import specifically via use crate::screens::dispatch::fn_name"

requirements-completed: [POLICY-11]

# Metrics
duration: 15min
completed: 2026-04-21
---

# Phase 20 Plan 02: TUI Operator Picker Summary

**Attribute-type-aware Step 2 operator picker in conditions builder TUI, driven by `operators_for()` with SC-1 stale-operator reset and MemberOf partial-match hint**

## Performance

- **Duration:** ~15 min
- **Started:** 2026-04-21T00:00:00Z
- **Completed:** 2026-04-21T00:15:00Z
- **Tasks:** 6 (Steps 1-6 from plan, committed atomically)
- **Files modified:** 2

## Accomplishments

- Extended `operators_for()` from eq-only to per-attribute lists: Classification gets eq/neq/gt/lt (4 ops), MemberOf gets eq/neq/contains (3 ops), DeviceTrust/NetworkLocation/AccessContext get eq/neq (2 ops each)
- Replaced static `OPERATOR_EQ` constant in render.rs with `pick_operators(attr)` helper that delegates to `operators_for`, making the picker auto-size to the attribute
- Added SC-1 defensive stale-operator reset: when user re-enters Step 1 and picks a new attribute whose valid operator set excludes the previously selected operator, `selected_operator` is cleared before advancing to Step 2
- Updated MemberOf Step 3 block title to "AD Group SID (partial match)" per D-07, reflecting that `contains` is now a supported operator
- Added 6 regression tests in `operator_tests` module covering operator counts for all 5 attributes and condition_display rendering of gt/lt operators

## Task Commits

1. **All tasks (Steps 2-6)** - `d1509ef` (feat: operators_for extension, SC-1, pick_operators, partial-match title, regression tests)

## Files Created/Modified

- `dlp-admin-cli/src/screens/dispatch.rs` - operators_for extended + pub(crate), SC-1 reset in step1 Enter arm, operator_tests module added
- `dlp-admin-cli/src/screens/render.rs` - operators_for import, OPERATOR_EQ removed, pick_operators helper added, Step 2 picker arm updated, AD Group SID title updated

## Decisions Made

- Made `operators_for` `pub(crate)` (was private `fn`) so render.rs can import it without routing through an intermediate layer
- Kept `pick_operators` in render.rs (not dispatch.rs) because it returns `Vec<ListItem>`, a ratatui type — mixing UI types into dispatch would invert the dependency
- Used nested `mod operator_tests` inside `mod tests` (not a separate top-level module) to match the existing test organization in dispatch.rs

## Deviations from Plan

None - plan executed exactly as written. The test in Step 5 used `condition_display(ConditionAttribute, &str, &str)` (three args) in the plan spec but the actual function signature is `condition_display(&PolicyCondition)`. The tests were adapted to construct `PolicyCondition` values directly — this is the correct approach and matches the existing test pattern in the file.

## Issues Encountered

- `cargo fmt` reformatted multi-line static slice literals to compact single-line form and wrapped long assert messages. Applied `cargo fmt` before committing to ensure format compliance.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Step 2 operator picker is now attribute-type-aware; Wave 1 evaluator (plan 20-01) handles the new operators server-side
- Phase 21 (in-place condition editing) can build on the stable `operators_for` API as the source of truth for valid operators
- No blockers

---
*Phase: 20-operator-expansion*
*Completed: 2026-04-21*
