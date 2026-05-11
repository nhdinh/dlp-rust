---
phase: 41-browser-origin-clipboard-policies
plan: 04
subsystem: ui
tags: [ratatui, abac, policy-conditions, origin, clipboard]

requires:
  - phase: 41-01
    provides: SourceOrigin and DestinationOrigin PolicyCondition variants in dlp-common
  - phase: 41-02
    provides: ABAC evaluator origin condition matching in dlp-server

provides:
  - ConditionAttribute::SourceOrigin and DestinationOrigin labels in TUI attribute picker
  - Origin conditions use eq/ne/contains operators
  - Origin condition Step 3 is free-text input with "Origin URL" title
  - Origin conditions serialize as PolicyCondition::SourceOrigin/DestinationOrigin
  - Origin conditions display correctly in pending conditions list
  - In-place editing of origin conditions works (prefill + replace)

affects:
  - dlp-admin-cli conditions builder modal
  - Policy create/edit flows

tech-stack:
  added: []
  patterns:
    - "Free-text input path for non-picker attributes (same pattern as MemberOf)"
    - "Operator parity: origin conditions share eq/ne/contains with app-identity string fields"

key-files:
  created: []
  modified:
    - dlp-admin-cli/src/app.rs
    - dlp-admin-cli/src/screens/dispatch.rs
    - dlp-admin-cli/src/screens/render.rs

key-decisions:
  - "Origin conditions use free-text input (not a picker list) — URLs are too variable for a fixed list"
  - "Operator set eq/ne/matches matches app-identity string fields (Publisher/ImagePath/Aumid/PackageFamilyName)"
  - "Empty buffer returns None (fail-closed) — consistent with MemberOf and app-identity text fields"

patterns-established:
  - "Text-input attributes: value_count_for returns 0, picker_items returns vec![], handle_conditions_step3 routes to text path"

requirements-completed:
  - BRW-04.2

duration: 25min
completed: 2026-05-07
---

# Plan 41-04: Admin TUI Origin Conditions Builder

**Admin TUI conditions builder now supports SourceOrigin and DestinationOrigin attributes with eq/ne/contains operators and free-text URL input.**

## Performance

- **Duration:** 25 min
- **Started:** 2026-05-07T01:35:00Z
- **Completed:** 2026-05-07T01:59:00Z
- **Tasks:** 3
- **Files modified:** 3

## Accomplishments

- Added SourceOrigin and DestinationOrigin to ConditionAttribute::label() for TUI display
- Extended operators_for() to return eq/ne/contains for both origin attributes
- Extended value_count_for() to return 0 (text input) for origin attributes
- Extended build_condition() to construct PolicyCondition::SourceOrigin and DestinationOrigin from buffer
- Extended condition_to_prefill() to decompose origin conditions for in-place editing (already present from 41-01)
- Extended condition_display() to format origin conditions for pending list (already present from 41-01)
- Extended handle_conditions_step3() to route origin attributes to text input path
- Extended picker_items() in render.rs to return empty vec for origin attributes
- Added is_origin_text_step3 flag and "Origin URL" title for text input rendering
- Added 10 unit tests covering build, display, prefill round-trip, operators, and value count

## Task Commits

All tasks committed in a single commit (files are tightly coupled; atomic separation would create non-compiling intermediate states):

1. **Task 1-3: TUI conditions builder origin support** - `60b88b1` (feat)

## Files Created/Modified

- `dlp-admin-cli/src/app.rs` - Added SourceOrigin/DestinationOrigin label arms; updated doc comment to "nine" attributes
- `dlp-admin-cli/src/screens/dispatch.rs` - operators_for, value_count_for, build_condition, handle_conditions_step3 origin support; 10 new tests
- `dlp-admin-cli/src/screens/render.rs` - picker_items origin arms, is_origin_text_step3 flag, "Origin URL" title

## Decisions Made

- Followed existing free-text input pattern (same as MemberOf and app-identity Publisher/ImagePath/Aumid/PackageFamilyName)
- Operator parity with app-identity string fields: eq/ne/contains
- No sub-step for origin attributes (unlike app-identity which has AppField sub-picker)

## Deviations from Plan

### Auto-fixed Issues

**1. [Formatting] Aumid/PackageFamilyName line wrapping in match arms**
- **Found during:** Task 2 (dispatch.rs updates)
- **Issue:** Existing match arms with `AppField::Publisher | AppField::ImagePath | AppField::Aumid | AppField::PackageFamilyName` exceeded rustfmt line length
- **Fix:** cargo fmt split these across multiple lines automatically
- **Files modified:** dlp-admin-cli/src/screens/dispatch.rs, dlp-admin-cli/src/screens/render.rs
- **Verification:** cargo fmt --check passes
- **Committed in:** 60b88b1

**2. [Plan accuracy] condition_to_prefill and condition_display already had origin arms**
- **Found during:** Task 2 code review
- **Issue:** Plan 41-04 specified adding these arms, but they were already present from Plan 41-01 (ABAC origin types)
- **Fix:** Verified existing arms are correct; no changes needed
- **Files modified:** None
- **Verification:** cargo test passes, existing tests cover these paths

---

**Total deviations:** 1 auto-fixed (formatting)
**Impact on plan:** No functional deviations. Plan executed as specified.

## Issues Encountered

- None. All changes compiled and tested on first pass after adding missing match arms.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Phase 41 is now complete (plans 41-01 through 41-04 all delivered)
- Phase 42 (Audit Enrichment — App Identity Fields) is next
- All origin condition infrastructure is in place: types (41-01), evaluator (41-02), Chrome handler (41-03), TUI builder (41-04)

---
*Phase: 41-browser-origin-clipboard-policies*
*Completed: 2026-05-07*
