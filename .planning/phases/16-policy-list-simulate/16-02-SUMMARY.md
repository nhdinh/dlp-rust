---
phase: 16-policy-list-simulate
plan: "02"
subsystem: dlp-admin-cli
tags: [ratatui, tui, simulate, abac, policy, loading, validation]

# Dependency graph
requires:
  - phase: 16-policy-list-simulate
    provides: PolicyList screen with 5-column spec and global_mode parameter
  - phase: 16-policy-list-simulate
    provides: Verified Simulate types (SimulateCaller, SimulateOutcome, SimulateFormState)
provides:
  - SimulateOutcome::Loading variant with yellow "Submitting..." block rendering
  - App.terminal: Option<Tui> field for forced redraws during blocking operations
  - main.rs take/draw/restore event loop pattern
  - Client-side validation for empty user_sid and path
  - Group normalization: trim, dedupe preserving order, lowercase
  - Granular error classification: timeout/connection/decode/network/server
  - Loading guard preventing double-submission
  - Aligned planning artifacts (CONTEXT, RESEARCH, PATTERNS, VALIDATION)
affects:
  - dlp-admin-cli/src/app.rs
  - dlp-admin-cli/src/main.rs
  - dlp-admin-cli/src/screens/dispatch.rs
  - dlp-admin-cli/src/screens/render.rs
  - .planning/phases/16-policy-list-simulate/16-CONTEXT.md
  - .planning/phases/16-policy-list-simulate/16-RESEARCH.md
  - .planning/phases/16-policy-list-simulate/16-PATTERNS.md
  - .planning/phases/16-policy-list-simulate/16-VALIDATION.md

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Terminal ownership pattern: App stores Option<Tui>, main.rs passes by value, event loop uses take/draw/restore"
    - "Forced redraw pattern: set Loading state, take terminal, draw frame, restore terminal, then block_on"
    - "Client-side validation pattern: reject before network call, set SimulateOutcome::Error inline"
    - "Group normalization pattern: split(',') -> trim -> to_lowercase -> filter empty -> HashSet dedupe"
    - "Granular error classification: downcast_ref::<reqwest::Error> with is_timeout/is_connect/is_decode"

key-files:
  created:
    - .planning/phases/16-policy-list-simulate/16-VALIDATION.md
  modified:
    - dlp-admin-cli/src/app.rs - SimulateOutcome::Loading variant, App.terminal field
    - dlp-admin-cli/src/main.rs - run_tui takes terminal by value, take/draw/restore pattern
    - dlp-admin-cli/src/screens/dispatch.rs - validation, normalization, granular errors, loading guard, tests
    - dlp-admin-cli/src/screens/render.rs - Loading arm in draw_policy_simulate, Loading hints
    - .planning/phases/16-policy-list-simulate/16-CONTEXT.md - D-01, D-02, D-20, D-24 revised
    - .planning/phases/16-policy-list-simulate/16-RESEARCH.md - Open Questions marked (RESOLVED)
    - .planning/phases/16-policy-list-simulate/16-PATTERNS.md - Section A-1 updated to 5-column reality

key-decisions:
  - "Terminal ownership moved into App struct to enable forced redraws from dispatch handlers"
  - "Take/draw/restore pattern avoids borrow checker conflicts between &mut Terminal and &App"
  - "Client-side validation added despite original D-24 saying 'no validation' — cross-AI review identified UX gap"
  - "Group normalization includes lowercase + dedupe per cross-AI review feedback"
  - "Error classification uses reqwest::Error kind matching for precise operator feedback"
  - "Loading guard prevents double-submission via matches! on SimulateOutcome::Loading"

requirements-completed:
  - POLICY-06

# Metrics
duration: 18min
completed: 2026-06-16
---

# Phase 16 Plan 02: Policy Simulate Enhancements + Planning Artifact Alignment Summary

**Simulate screen enhanced with loading state, client-side validation, group normalization, granular errors, and double-submission guard. Planning artifacts aligned with shipped 5-column reality.**

---

## Performance

- **Duration:** 18 min
- **Started:** 2026-06-16T06:26:14Z
- **Completed:** 2026-06-16T06:44:14Z
- **Tasks:** 3
- **Files created:** 1 (16-VALIDATION.md)
- **Files modified:** 7 (4 planning artifacts + 3 source files)

---

## Accomplishments

### Task 0: Align Planning Artifacts

- Revised 16-CONTEXT.md D-01 to describe 5 columns (Priority/Name/Action/Enabled/Mode) dropping ID and Version
- Revised 16-CONTEXT.md D-02 to widths 12/38/15/12/23%
- Revised 16-CONTEXT.md D-20 to include dedupe and lowercase in group normalization
- Revised 16-CONTEXT.md D-24 to permit client-side validation for empty user_sid/path
- Marked 16-RESEARCH.md Open Questions as (RESOLVED) with plan references
- Updated 16-PATTERNS.md Section A-1 to describe 5-column reality with Mode, global_mode, override banner
- Created 16-VALIDATION.md with retrospective validation strategy

### Task 1: Add SimulateOutcome::Loading, App.terminal, and Restructure Event Loop

- Added `SimulateOutcome::Loading` variant to enum in app.rs with doc comment
- Added `App.terminal: Option<crate::tui::Tui>` field initialized to `None`
- Restructured `main.rs` `run_tui` to take terminal by value, store in `App`
- Implemented take/draw/restore pattern in event loop to avoid borrow checker conflicts
- Added `SimulateOutcome::Loading` match arm in `draw_policy_simulate` rendering yellow "Submitting..." block
- Added Loading-specific hint message "Submitting... | please wait"

### Task 2: Add Validation, Normalization, Granular Errors, Loading Guard, and Tests

- Rewrote `action_submit_simulate` with client-side validation for empty user_sid and path
- Added group normalization: split(',') -> trim -> to_lowercase -> filter empty -> HashSet dedupe preserving order
- Added forced terminal redraw after setting Loading and before `block_on`
- Added granular error classification: timeout/connection/decode/network/server via `reqwest::Error` kind matching
- Added loading guard in `handle_simulate_nav` to prevent double-submission
- Added 11 unit tests (5 group normalization + 5 validation + 1 error classification compile-check)
- All 221 dlp-admin-cli tests pass
- Build compiles with zero errors

---

## Task Commits

| Task | Commit | Message |
|------|--------|---------|
| 0 | f63020f | docs(phase-16-02): align planning artifacts with shipped 5-column reality |
| 1 | 6de22ba | feat(phase-16-02): add SimulateOutcome::Loading, App.terminal, and restructure event loop |
| 2 | 4fff200 | feat(phase-16-02): add validation, normalization, granular errors, loading guard, and tests |

---

## Files Modified

### Source Files

- `dlp-admin-cli/src/app.rs` — SimulateOutcome::Loading variant, App.terminal field
- `dlp-admin-cli/src/main.rs` — run_tui takes terminal by value, take/draw/restore pattern
- `dlp-admin-cli/src/screens/dispatch.rs` — action_submit_simulate rewrite, handle_simulate_nav loading guard, 11 tests
- `dlp-admin-cli/src/screens/render.rs` — Loading arm in draw_policy_simulate, Loading hints

### Planning Artifacts

- `.planning/phases/16-policy-list-simulate/16-CONTEXT.md` — D-01, D-02, D-20, D-24 revised
- `.planning/phases/16-policy-list-simulate/16-RESEARCH.md` — Open Questions marked (RESOLVED)
- `.planning/phases/16-policy-list-simulate/16-PATTERNS.md` — Section A-1 updated to 5-column reality
- `.planning/phases/16-policy-list-simulate/16-VALIDATION.md` — New retrospective validation strategy

---

## Decisions Made

1. **Terminal ownership moved into App:** The `App` struct now holds `terminal: Option<Tui>` so dispatch handlers can force redraws during blocking operations. This is a structural change that enables the Loading state to be visible.
2. **Take/draw/restore pattern:** The event loop takes ownership of the terminal from `app.terminal`, draws the frame, then restores it. This avoids borrow checker conflicts between `&mut Terminal` and `&App`.
3. **Client-side validation added:** Despite original D-24 saying "no client-side validation," the cross-AI review identified this as a UX gap. Empty `user_sid` and `path` are now rejected with inline errors before the server round-trip.
4. **Group normalization includes dedupe + lowercase:** Per cross-AI review feedback, the original `split(',')` + `trim()` + `filter(empty)` was enhanced with `to_lowercase()` and `HashSet` deduplication preserving first-occurrence order.
5. **Granular error classification:** Instead of just "Network error:" vs "Server error:", the code now distinguishes timeout, connection, decode, network, and server errors using `reqwest::Error` kind matching.

---

## Deviations from Plan

None — plan executed exactly as written. All must-have truths from the plan frontmatter are satisfied.

---

## Known Stubs

None. All functionality is fully implemented and wired.

---

## Threat Flags

None. No new security-relevant surface introduced.

---

## Self-Check: PASSED

- [x] `SimulateOutcome::Loading` variant exists in app.rs
- [x] Loading state renders yellow "Submitting..." block in render.rs
- [x] `App.terminal: Option<Tui>` field exists and is initialized to None
- [x] main.rs passes terminal ownership into App and uses take/draw/restore
- [x] action_submit_simulate forces terminal redraw after setting Loading
- [x] Client-side validation rejects empty user_sid and path
- [x] Group normalization uses trim + to_lowercase + HashSet dedupe
- [x] Error classification distinguishes timeout/connection/decode/network/server
- [x] Loading guard prevents double-submission in handle_simulate_nav
- [x] 11 unit tests pass (5 group + 5 validation + 1 error classification)
- [x] All 221 dlp-admin-cli tests pass
- [x] Build passes with zero errors
- [x] 16-CONTEXT.md D-01 revised to 5 columns
- [x] 16-CONTEXT.md D-02 revised to 12/38/15/12/23%
- [x] 16-CONTEXT.md D-24 revised to permit validation
- [x] 16-CONTEXT.md D-20 revised to include dedupe and lowercase
- [x] 16-RESEARCH.md Open Questions marked (RESOLVED)
- [x] 16-PATTERNS.md Section A-1 updated to 5-column reality
- [x] 16-VALIDATION.md created with retrospective strategy

---

*Phase: 16-policy-list-simulate*
*Completed: 2026-06-16*
