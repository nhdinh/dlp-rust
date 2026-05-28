---
phase: 54-admin-tui-protected-paths-bypass-alerts-screens
plan: 01
subsystem: ui

tags: [ratatui, crossterm, serde_json, admin-cli]

# Dependency graph
requires:
  - phase: 52-admin-api-protected-paths
    provides: Admin API CRUD for protected paths (GET/POST/DELETE /admin/protected-paths)
  - phase: 53-bypass-alert-storage
    provides: Bypass alert SQLite table, repository, HTTP routes, SIEM relay
provides:
  - Screen enum variants for ProtectedPathList, BypassAlertList, BypassAlertDetail
  - BypassAlertSeverityFilter enum with cycle, as_str, label methods
  - InputPurpose::AddProtectedPath and ConfirmPurpose::DeleteProtectedPath
  - Constants files for hint strings and empty-state messages
  - Module declarations in screens/mod.rs
affects:
  - 54-02 (Protected Paths screen render + dispatch)
  - 54-03 (Bypass Alerts screen render + dispatch)
  - 54-04 (Menu wiring)
  - 54-05 (Client methods)
  - 54-06 (Integration tests)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Constants file pattern: pub const HINTS + #[cfg(test)] verification module"
    - "Filter enum pattern: next() cycle + as_str() wire format + label() display"
    - "Screen variant pattern: Vec<serde_json::Value> data + selected index + pagination fields"
    - "Stub match arm pattern: empty {} for dispatch, blank render for new Screen variants"

key-files:
  created:
    - dlp-admin-cli/src/screens/protected_paths.rs
    - dlp-admin-cli/src/screens/bypass_alerts.rs
  modified:
    - dlp-admin-cli/src/app.rs
    - dlp-admin-cli/src/screens/mod.rs
    - dlp-admin-cli/src/screens/dispatch.rs
    - dlp-admin-cli/src/screens/render.rs

key-decisions:
  - "Removed status_message from BypassAlertList per review feedback (dead code)"
  - "Added pending_ack_ids: HashSet<i64> to BypassAlertList for optimistic ack tracking per review feedback"
  - "BypassAlertSeverityFilter::as_str() returns None for All, Some for specific severities — matches API query param convention"
  - "Used #[allow(dead_code)] on new types/constants since downstream plans will construct them"

patterns-established:
  - "Filter enum: Default=All, next() cycles variants, as_str() returns Option for wire format"
  - "Constants file: HINTS + EMPTY + #[cfg(test)] substring verification"
  - "Screen variant with pagination: paths/alerts + selected + page + page_size + total"

requirements-completed: [UX-01, UX-02]

# Metrics
duration: 10min
completed: 2026-05-28
---

# Phase 54 Plan 01: TUI Screen Types Foundation Summary

**Added Screen enum variants, filter types, purpose types, and constants files for Protected Paths and Bypass Alerts TUI screens — the type foundation all downstream plans build on.**

## Performance

- **Duration:** 10 min
- **Started:** 2026-05-28T03:47:33Z
- **Completed:** 2026-05-28T03:58:05Z
- **Tasks:** 3
- **Files modified:** 6

## Accomplishments

- Created `protected_paths.rs` and `bypass_alerts.rs` constants files with hint strings and empty-state messages
- Added `BypassAlertSeverityFilter` enum with `next()` cycle, `as_str()` wire format, and `label()` display methods
- Added 3 new `Screen` variants: `ProtectedPathList`, `BypassAlertList` (with `pending_ack_ids`), `BypassAlertDetail`
- Added `InputPurpose::AddProtectedPath` and `ConfirmPurpose::DeleteProtectedPath` purpose variants
- Declared new modules in `screens/mod.rs` with alphabetical ordering
- Added stub match arms in `dispatch.rs` and `render.rs` to maintain exhaustive matching
- All 150 dlp-admin-cli tests pass, clippy clean (-D warnings)

## Task Commits

All tasks committed atomically in a single commit (foundation plan — all pieces are tightly coupled):

1. **Tasks 1-3: Constants files, app.rs types, mod.rs declarations** — `caad10d` (feat)

## Files Created/Modified

- `dlp-admin-cli/src/screens/protected_paths.rs` — Constants: PROTECTED_PATH_LIST_HINTS, PROTECTED_PATH_LIST_EMPTY
- `dlp-admin-cli/src/screens/bypass_alerts.rs` — Constants: BYPASS_ALERT_LIST_HINTS, BYPASS_ALERT_LIST_EMPTY, BYPASS_ALERT_DETAIL_HINTS
- `dlp-admin-cli/src/app.rs` — Screen variants, BypassAlertSeverityFilter, purpose variants, 9 unit tests
- `dlp-admin-cli/src/screens/mod.rs` — Module declarations for protected_paths and bypass_alerts
- `dlp-admin-cli/src/screens/dispatch.rs` — Stub match arms for new Screen variants and purposes
- `dlp-admin-cli/src/screens/render.rs` — Stub match arms for new Screen variants

## Decisions Made

- Followed exact pattern from existing `labels.rs` and `approvals.rs` constants files
- `BypassAlertSeverityFilter` cycles All -> Crit -> Warn -> Info -> All (matches severity escalation order)
- `as_str()` returns `None` for `All` (no query param sent) and `Some("crit"|"warn"|"info")` for specific filters
- Added `#[allow(dead_code)]` to new types since downstream plans will be the first consumers

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Added stub match arms in dispatch.rs and render.rs for new Screen variants**
- **Found during:** Task 2 (app.rs type additions)
- **Issue:** Adding new Screen enum variants broke exhaustive pattern matching in dispatch.rs (5 match expressions) and render.rs (1 match expression)
- **Fix:** Added stub match arms — empty `{}` for dispatch handlers, blank render for render.rs. Also added `InputPurpose::AddProtectedPath` and `ConfirmPurpose::DeleteProtectedPath` stubs in `on_text_confirmed`, `on_confirm_yes`, and `on_confirm_cancel`.
- **Files modified:** `dlp-admin-cli/src/screens/dispatch.rs`, `dlp-admin-cli/src/screens/render.rs`
- **Verification:** `cargo check -p dlp-admin-cli` passes with no warnings
- **Committed in:** `caad10d` (part of task commit)

**2. [Rule 1 - Bug] Added #[allow(dead_code)] to suppress warnings on unused new types**
- **Found during:** Task 2 (compilation verification)
- **Issue:** New constants, enum variants, and methods triggered dead_code warnings since downstream plans are the first consumers
- **Fix:** Added `#[allow(dead_code)]` attributes to constants, new enum variants, and the `impl BypassAlertSeverityFilter` block
- **Files modified:** `dlp-admin-cli/src/screens/protected_paths.rs`, `dlp-admin-cli/src/screens/bypass_alerts.rs`, `dlp-admin-cli/src/app.rs`
- **Verification:** `cargo check -p dlp-admin-cli` produces zero warnings
- **Committed in:** `caad10d` (part of task commit)

---

**Total deviations:** 2 auto-fixed (1 blocking, 1 bug)
**Impact on plan:** Both auto-fixes necessary for compilation correctness. No scope creep.

## Issues Encountered

- None beyond the expected compilation breaks from adding new enum variants (handled via Rule 3)

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- All type contracts are in place for downstream plans (54-02 through 54-06)
- Downstream plans can reference `Screen::ProtectedPathList`, `Screen::BypassAlertList`, `Screen::BypassAlertDetail` without modification
- `BypassAlertSeverityFilter` ready for use in client query params and render filter display
- `pending_ack_ids` field ready for optimistic ack UI pattern

## Known Stubs

| File | Line | Description | Resolution Plan |
|------|------|-------------|-----------------|
| dispatch.rs | Screen::ProtectedPathList arm | Empty handler — no key event processing | Plan 54-02 |
| dispatch.rs | Screen::BypassAlertList arm | Empty handler — no key event processing | Plan 54-03 |
| dispatch.rs | Screen::BypassAlertDetail arm | Empty handler — no key event processing | Plan 54-03 |
| dispatch.rs | InputPurpose::AddProtectedPath arm | Sets error status "not yet implemented" | Plan 54-05 |
| dispatch.rs | ConfirmPurpose::DeleteProtectedPath arms | Stub yes/no handlers | Plan 54-05 |
| render.rs | Screen::ProtectedPathList arm | Blank screen (no rendering) | Plan 54-02 |
| render.rs | Screen::BypassAlertList arm | Blank screen (no rendering) | Plan 54-03 |
| render.rs | Screen::BypassAlertDetail arm | Blank screen (no rendering) | Plan 54-03 |

## Self-Check: PASSED

- [x] `protected_paths.rs` exists with correct constants and tests
- [x] `bypass_alerts.rs` exists with correct constants and tests
- [x] `app.rs` has 3 new Screen variants, 1 filter enum, 2 purpose variants
- [x] `BypassAlertList` has `pending_ack_ids: HashSet<i64>` (not `status_message`)
- [x] `mod.rs` declares both new modules
- [x] All 150 tests pass
- [x] `cargo check` produces zero warnings
- [x] `cargo clippy -p dlp-admin-cli -- -D warnings` passes
- [x] Commit `caad10d` exists in git log

---
*Phase: 54-admin-tui-protected-paths-bypass-alerts-screens*
*Completed: 2026-05-28*
