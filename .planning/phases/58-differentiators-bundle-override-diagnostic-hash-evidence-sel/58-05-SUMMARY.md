---
phase: 58-differentiators-bundle-override-diagnostic-hash-evidence-sel
plan: 58-05
subsystem: ui

tags: [rust, ratatui, tui, diagnostics, health-monitoring, admin-cli]

requires:
  - phase: 58-differentiators-bundle-override-diagnostic-hash-evidence-sel
    provides: DiagnosticSnapshotStore, DiagnosticAggregator, HealthAggregator (DIFF-02, DIFF-04)

provides:
  - DiagnosticList TUI screen with 7-column table, severity filters, pagination, detail popup
  - SelfHealthDashboard TUI screen with two-panel layout, status badge, sparkline trends
  - DiagnosticSeverityFilter enum with next()/as_str()/label() methods
  - Client methods list_diagnostics() and get_self_health()
  - SystemMenu expanded to 16 items with Diagnostic Events (12) and Self-Health (13)

affects:
  - 58-differentiators-bundle-override-diagnostic-hash-evidence-sel
  - Any phase consuming diagnostic data via admin TUI

tech-stack:
  added: []
  patterns:
    - "BypassAlertList four-file pattern: constants module + app.rs variant + dispatch handler + render function"
    - "Table-based list screen with severity badges and pagination"
    - "Two-panel layout with status badge and text-based sparkline trends"

key-files:
  created:
    - dlp-admin-cli/src/screens/diagnostic_list.rs
    - dlp-admin-cli/src/screens/self_health_dashboard.rs
  modified:
    - dlp-admin-cli/src/app.rs
    - dlp-admin-cli/src/client.rs
    - dlp-admin-cli/src/screens/mod.rs
    - dlp-admin-cli/src/screens/dispatch.rs
    - dlp-admin-cli/src/screens/render.rs

key-decisions:
  - "DiagnosticSeverityFilter defined in both diagnostic_list.rs (screen constants) and app.rs (Screen enum field type) to avoid circular imports"
  - "Self-health dashboard uses text-based sparkline bars instead of ratatui::widgets::Sparkline to avoid type complexity with Option<&Value> lifetimes"
  - "SystemMenu item count updated from 14 to 16 with Diagnostic Events at index 12 and Self-Health at index 13"

patterns-established:
  - "Screen constant module pattern: hints, empty message, filter enum with #[cfg(test)] unit tests"
  - "Two-panel render layout with Layout::horizontal([Percentage(45), Percentage(55)])"
  - "Terminal size guard: render centered warning when area < 80x20"

requirements-completed: [DIFF-02, DIFF-04]

# Metrics
duration: 35min
completed: 2026-06-02
---

# Phase 58 Plan 05: Admin TUI Diagnostic List and Self-Health Dashboard Summary

**Admin TUI screens for Diagnostic Events (DIFF-02) and Self-Health Dashboard (DIFF-04) following the BypassAlertList four-file pattern with 7-column table, severity badges, detail popup with ABAC context, and two-panel health dashboard with status badge and sparkline trends**

## Performance

- **Duration:** 35 min
- **Started:** 2026-06-02T22:35:00+07:00
- **Completed:** 2026-06-02T23:10:00+07:00
- **Tasks:** 4 (combined into single atomic commit)
- **Files modified:** 7

## Accomplishments

- **Task 1:** Created diagnostic_list.rs and self_health_dashboard.rs constant modules with hints, empty messages, and DiagnosticSeverityFilter enum; added three new Screen variants to app.rs; added 10 unit tests
- **Task 2:** Added list_diagnostics() and get_self_health() client methods; implemented dispatch handlers (handle_diagnostic_list, handle_diagnostic_detail, handle_self_health_dashboard) and action loaders; expanded SystemMenu to 16 items
- **Task 3 & 4:** Implemented draw_diagnostic_list() with 7-column table (Severity, Time, User, Path, Tier, Policy, Latency), severity badges, pagination, and filter suffixes; implemented draw_diagnostic_detail() with full ABAC context per 58-UI-SPEC.md; implemented draw_self_health_dashboard() with two-panel layout, color-coded status badge, counter display, and text-based sparkline trends; added terminal size guard

## Task Commits

All tasks committed atomically in a single commit:

1. **Tasks 1-4: Complete TUI screens for diagnostics and self-health** - `0c478d7` (feat)

## Files Created/Modified

- `dlp-admin-cli/src/screens/diagnostic_list.rs` - Constants, DiagnosticSeverityFilter enum, 7 unit tests (119 lines)
- `dlp-admin-cli/src/screens/self_health_dashboard.rs` - Constants, 2 unit tests (26 lines)
- `dlp-admin-cli/src/app.rs` - DiagnosticSeverityFilter enum, DiagnosticList/DiagnosticDetail/SelfHealthDashboard Screen variants, 10 unit tests (147 lines added)
- `dlp-admin-cli/src/client.rs` - list_diagnostics() and get_self_health() methods (37 lines added)
- `dlp-admin-cli/src/screens/mod.rs` - Added diagnostic_list and self_health_dashboard module declarations
- `dlp-admin-cli/src/screens/dispatch.rs` - Three new handlers, two action loaders, SystemMenu expanded to 16 items, tests updated (177 lines added)
- `dlp-admin-cli/src/screens/render.rs` - draw_diagnostic_list, draw_diagnostic_detail, draw_self_health_dashboard with full rendering logic (557 lines added)

## Decisions Made

- **DiagnosticSeverityFilter duplication:** Defined in both diagnostic_list.rs (for render/dispatch imports) and app.rs (for Screen enum field type) to avoid circular import between app.rs and screen modules. The app.rs version is the canonical type used in the Screen enum.
- **Text-based sparklines:** Used character-bar sparklines (`_`, `-`, `=`, `+`, `#`) instead of ratatui::widgets::Sparkline to avoid lifetime complexity with `Option<&Value>` snapshot references and to keep the render function signature simple.
- **SystemMenu positioning:** Diagnostic Events at index 12 (after Bypass Alerts at 11), Self-Health at index 13, shifting Syslog Config to 14 and Back to 15. This follows the natural grouping of monitoring/diagnostic screens together.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Type mismatch between DiagnosticSeverityFilter definitions**
- **Found during:** Compilation after creating diagnostic_list.rs
- **Issue:** render.rs imported DiagnosticSeverityFilter from diagnostic_list.rs, but the Screen enum in app.rs used a different DiagnosticSeverityFilter type, causing E0308 type mismatch
- **Fix:** Removed the DiagnosticSeverityFilter import from render.rs and used `crate::app::DiagnosticSeverityFilter` everywhere the Screen enum field type was needed
- **Files modified:** dlp-admin-cli/src/screens/render.rs
- **Verification:** cargo build passes

**2. [Rule 3 - Blocking] Missing render and dispatch function stubs caused compilation failures**
- **Found during:** First cargo test after adding Screen variants
- **Issue:** Adding new Screen enum variants without corresponding match arms in render.rs draw_screen() and dispatch.rs handle_event() caused non-exhaustive pattern errors
- **Fix:** Added stub match arms in both files before implementing full functions; this is the standard Rust approach for incremental TUI screen development
- **Files modified:** dlp-admin-cli/src/screens/render.rs, dlp-admin-cli/src/screens/dispatch.rs
- **Verification:** cargo build passes after each incremental addition

**3. [Rule 1 - Bug] SystemMenu test assumed 14 items after adding 2 new items**
- **Found during:** cargo test after expanding SystemMenu
- **Issue:** The existing `system_menu_item_count_and_order` and `handle_system_menu_has_14_items` tests failed because they hardcoded 14 items
- **Fix:** Updated both tests to expect 16 items and renamed `handle_system_menu_has_14_items` to `handle_system_menu_has_16_items`
- **Files modified:** dlp-admin-cli/src/screens/dispatch.rs
- **Verification:** All 212 tests pass

**4. [Rule 1 - Bug] Rust format string does not support Python-style numeric grouping**
- **Found during:** cargo build after implementing self-health dashboard
- **Issue:** Used `{pipe_round_trips:,}` format string which is valid in Python but not in Rust
- **Fix:** Removed the `:` comma formatting, used plain `{pipe_round_trips}` instead
- **Files modified:** dlp-admin-cli/src/screens/render.rs
- **Verification:** cargo build passes

**5. [Rule 1 - Bug] Clippy warnings for useless_format and unnecessary_cast**
- **Found during:** clippy check
- **Issue:** `format!("{bars}")` is useless (should be `bars` directly); `(v * 100 / pipe_max) as u64` is an unnecessary cast since the expression already yields u64
- **Fix:** Applied both clippy suggestions
- **Files modified:** dlp-admin-cli/src/screens/render.rs
- **Verification:** cargo clippy -p dlp-admin-cli -- -D warnings passes

## Issues Encountered

- The plan specified 4 separate tasks but the work was naturally atomic across all files. All changes were committed in a single commit because the render functions, dispatch handlers, client methods, and app.rs variants are tightly coupled and must compile together.
- The dlp-hook-dll crate has pre-existing clippy warnings (not_unsafe_ptr_arg_deref) unrelated to this plan. These are out of scope.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Diagnostic List screen is ready for integration with GET /admin/diagnostics endpoint (shipped in Plan 58-04)
- Self-Health Dashboard is ready for integration with GET /admin/health endpoint (to be implemented in future plan)
- All TUI wiring complete: dispatch handlers, render functions, client methods, Screen enum variants, SystemMenu entries
- No blockers

---
*Phase: 58-differentiators-bundle-override-diagnostic-hash-evidence-sel*
*Completed: 2026-06-02*
