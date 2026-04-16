---
phase: 13-conditions-builder
plan: "01"
subsystem: dlp-admin-cli
tags: [tui, conditions-builder, state-machine, dispatch, abac]
completed: "2026-04-16T09:54:30Z"
duration_minutes: 45

dependency_graph:
  requires: []
  provides:
    - ConditionAttribute enum (app.rs)
    - CallerScreen enum (app.rs)
    - PolicyFormState struct (app.rs)
    - Screen::ConditionsBuilder variant (app.rs)
    - handle_conditions_builder handler (dispatch.rs)
    - condition_display helper (dispatch.rs)
    - build_condition helper (dispatch.rs)
    - operators_for helper (dispatch.rs)
    - value_count_for helper (dispatch.rs)
  affects:
    - dlp-admin-cli/src/app.rs
    - dlp-admin-cli/src/screens/dispatch.rs
    - dlp-admin-cli/src/screens/render.rs

tech_stack:
  added: []
  patterns:
    - two-phase read-then-mutate borrow pattern (avoids borrow conflicts in Screen enum mutations)
    - static slice operator table (operators_for returns &'static [(&'static str, bool)])
    - step-reset-to-top after each step transition (Pitfall 4 guard)

key_files:
  created: []
  modified:
    - dlp-admin-cli/src/app.rs
    - dlp-admin-cli/src/screens/dispatch.rs
    - dlp-admin-cli/src/screens/render.rs

decisions:
  - "Use #[allow(dead_code)] on forward-declared types (CallerScreen, PolicyFormState, ConditionsBuilder variant, label method, condition_display) rather than removing them — they are intentionally defined here for use by Plans 02, 14, and 15"
  - "Tab key is handled before step routing (returns early) to avoid double-dispatch; all other keys route to step sub-handlers"
  - "Stub ConditionsBuilder arm added to render.rs (Rule 3 deviation) to unblock compilation; Plan 02 replaces it with full draw_conditions_builder implementation"
  - "CallerScreen removed from dispatch.rs import (not yet referenced there); Phase 14/15 will re-add it when routing Esc back to the correct parent screen"

metrics:
  tasks_completed: 2
  tasks_total: 2
  files_created: 1
  files_modified: 3
  tests_added: 12
  tests_total_passing: 17
---

# Phase 13 Plan 01: Conditions Builder — Data Model and Dispatch Summary

**One-liner:** 3-step ABAC conditions builder state machine with typed ConditionAttribute/CallerScreen enums, Screen::ConditionsBuilder variant, full keyboard dispatch handler, and 12 unit tests covering all 5 PolicyCondition variants.

## What Was Built

### Task 1: Data model types in app.rs

Added to `dlp-admin-cli/src/app.rs`:

- `ConditionAttribute` enum — 5 variants (Classification, MemberOf, DeviceTrust, NetworkLocation, AccessContext) with `label()` method and `ATTRIBUTES` constant array
- `CallerScreen` enum — PolicyCreate and PolicyEdit variants for modal return routing (used by Phase 14/15)
- `PolicyFormState` struct — holds policy form fields plus `conditions: Vec<PolicyCondition>` for the accumulated conditions list
- `Screen::ConditionsBuilder` variant — 9 fields: `step: u8`, `selected_attribute`, `selected_operator`, `pending: Vec<PolicyCondition>`, `buffer`, `pending_focused`, `pending_state: ratatui::widgets::ListState`, `picker_state: ratatui::widgets::ListState`, `caller: CallerScreen`

### Task 2: Dispatch handler in dispatch.rs

Added to `dlp-admin-cli/src/screens/dispatch.rs`:

- `handle_conditions_builder` — two-phase read-then-mutate outer handler, Tab toggles focus
- `handle_conditions_pending` — Up/Down nav, d/Delete removes selected condition, Esc closes modal
- `handle_conditions_step1` — attribute picker nav, Enter advances to Step 2, Esc closes modal
- `handle_conditions_step2` — operator picker nav (operators_for), Enter advances to Step 3, Esc goes back to Step 1
- `handle_conditions_step3` — routes to text input (MemberOf) or select list (all others)
- `handle_conditions_step3_text` — Char/Backspace/Enter/Esc for free-text SID input
- `handle_conditions_step3_select` — Up/Down/Enter/Esc for picker-based value selection
- `operators_for` — static slice returning `[("eq", true)]` for all 5 attributes
- `value_count_for` — returns option count per attribute (MemberOf = 0, others 2 or 4)
- `build_condition` — constructs all 5 PolicyCondition variants; MemberOf uses `group_sid` (not `value`)
- `condition_display` (pub) — human-readable string for pending list; Classification uses Display, others use Debug
- 12 unit tests: all build_condition variants, operators_for enforcement, condition_display output, value_count_for

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Added stub ConditionsBuilder arm to render.rs**
- **Found during:** Task 1 verification build
- **Issue:** Adding `Screen::ConditionsBuilder` to app.rs made render.rs's `draw_screen` match non-exhaustive, blocking compilation. Plan 02 owns the full render implementation but hasn't run yet.
- **Fix:** Added a minimal stub arm (`Block::default().title(" Conditions Builder ")`) to render.rs so Task 1 and Task 2 can be compiled and tested
- **Files modified:** `dlp-admin-cli/src/screens/render.rs`
- **Commit:** aa6f120

**2. [Rule 2 - Dead Code Suppression] Added #[allow(dead_code)] to forward-declared types**
- **Found during:** Task 2 clippy check
- **Issue:** clippy -D warnings flagged 6 items as unused: CallerScreen variants, PolicyFormState fields, label method, condition_display function, ConditionsBuilder variant. All are intentionally defined for future plans.
- **Fix:** Added targeted `#[allow(dead_code)]` annotations. Removed CallerScreen from dispatch.rs imports (not yet referenced there; Phase 14 will re-add).
- **Files modified:** `dlp-admin-cli/src/app.rs`, `dlp-admin-cli/src/screens/dispatch.rs`
- **Commit:** e6f84b4

## Known Stubs

- `render.rs` `ConditionsBuilder` arm renders a blank titled block — intentional stub for Plan 02

## Verification Results

| Check | Result |
|-------|--------|
| `cargo build -p dlp-admin-cli` | PASS |
| `cargo test -p dlp-admin-cli` | PASS (17/17) |
| `cargo clippy -p dlp-admin-cli -- -D warnings` | PASS |
| `cargo fmt -p dlp-admin-cli --check` | PASS |

## Self-Check: PASSED

- `dlp-admin-cli/src/app.rs` — modified, contains ConditionAttribute, CallerScreen, PolicyFormState, Screen::ConditionsBuilder
- `dlp-admin-cli/src/screens/dispatch.rs` — modified, contains handle_conditions_builder and all helpers
- `dlp-admin-cli/src/screens/render.rs` — modified, contains stub ConditionsBuilder arm
- Commit aa6f120 exists (Task 1)
- Commit e6f84b4 exists (Task 2)
