---
phase: 30-automated-uat-infrastructure
plan: "04"
subsystem: dlp-e2e
tags: [tui, headless-test, conditions-builder, app-identity, integration-test]
dependency_graph:
  requires: [30-01]
  provides: []
  affects: [dlp-e2e/tests/tui_conditions_builder.rs]
tech-stack:
  added: []
  patterns: [ratatui TestBackend, crossterm KeyEvent injection, mock axum server]
key-files:
  created:
    - dlp-e2e/tests/tui_conditions_builder.rs
  modified: []
decisions: []
metrics:
  duration: "6m"
  completed_date: "2026-04-28"
---

# Phase 30 Plan 04: Conditions Builder App-Identity Headless TUI Test Summary

**One-liner:** Headless TUI integration test exercising the full Conditions Builder 3-step flow for app-identity attributes (SourceApplication and DestinationApplication) via ratatui TestBackend and crossterm KeyEvent injection.

## What Was Built

A single integration test file (`dlp-e2e/tests/tui_conditions_builder.rs`) with three tests covering the most complex TUI flow in the system:

1. **`test_source_application_publisher_eq`** — Full SourceApplication -> Publisher -> eq -> text value flow. Navigates from MainMenu to PolicyCreate, opens ConditionsBuilder, selects SourceApplication (index 5), confirms Publisher field (index 0), selects eq operator, types "Microsoft Corporation", confirms, closes modal with Esc, and asserts the condition is returned to PolicyCreate. Render assertion confirms "SourceApplication" appears in the PolicyCreate buffer.

2. **`test_destination_application_imagepath_contains`** — DestinationApplication -> ImagePath -> contains -> text value flow. Same pattern but selects DestinationApplication (index 6), ImagePath field (index 1), contains operator (index 2), and types "chrome.exe". Render assertion confirms "DestinationApplication" appears in buffer.

3. **`test_source_application_trusttier_eq_picker`** — SourceApplication -> TrustTier -> eq -> picker value flow. Step 3 uses a list picker (not free-text) for TrustTier values. Selects "untrusted" (index 1) from the picker. Asserts the condition value is "untrusted" (lowercase, matching the wire format used by `build_condition`).

## Execution Notes

- All tests use the shared `dlp-e2e` helper infrastructure (`build_test_app()`, `build_test_app_with_mock_client()`, `render_to_buffer()`) established in Plan 30-01.
- A mock axum server is spawned on an ephemeral port for each test; the TUI App is wired to it via `EngineClient`.
- Tests are gated with `#![cfg(windows)]` and `#[cfg_attr(not(windows), ignore)]` because `dlp-admin-cli` depends on Win32 APIs.
- No HTTP calls are made during the ConditionsBuilder flow itself, so each test completes in under 0.5 seconds.

## Key Implementation Details

- **PolicyCreate row navigation:** The PolicyCreate form has 9 rows (0..=8). Row 6 is `[Add Conditions]`. The helper navigates from selected:0 to selected:6 with 6 Down keypresses.
- **PolicyMenu navigation:** PolicyMenu has 9 items (0..=8). Index 2 is "Create Policy". The helper uses Down x2 from selected:0.
- **AppField sub-step:** After selecting an app-identity attribute, the screen stays at `step: 1` but enters the AppField sub-picker. Enter on the field advances to `step: 2`.
- **TrustTier picker values:** The `build_condition` function maps picker indices to lowercase strings: 0="trusted", 1="untrusted", 2="unknown". The test asserts "untrusted" for index 1.

## Deviations from Plan

None — plan executed exactly as written.

## Known Stubs

None.

## Threat Flags

None — this is a test-only file with no production attack surface.

## Self-Check: PASSED

- [x] `dlp-e2e/tests/tui_conditions_builder.rs` exists (429 lines)
- [x] Commit `bcd6379` exists in git log
- [x] All 3 tests pass: `cargo test -p dlp-e2e --test tui_conditions_builder`
- [x] No file deletions in commit
- [x] No untracked generated files left behind
