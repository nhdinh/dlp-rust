---
phase: 53-etw-kernel-file-consumer-bypass-correlator-hook-journal-ring
plan: 06
subsystem: testing
tags: [siem, alert-router, bypass-alert, integration-test, etw, audit]

requires:
  - phase: 53-05
    provides: bypass_alerts table, repository, admin API routes, batch ingest handler

provides:
  - SIEM relay unit tests for BypassAlertDetected and EtwConsumerGatedOff events
  - Alert router unit test for crit severity BypassAlertDetected events
  - End-to-end integration tests for bypass alert pipeline (DB + routing predicates)
  - CR-08 file_object preservation verification
  - CR-09 EtwConsumerGatedOff routing semantics verification

affects:
  - 53-etw-kernel-file-consumer-bypass-correlator-hook-journal-ring
  - 54-admin-tui-bypass-alerts-screen

tech-stack:
  added: []
  patterns:
    - "Fire-and-forget tokio::spawn for SIEM/alert router routing after HTTP response"
    - "Unit tests verify connector/router accept events; integration tests verify handler constructs correct events"

key-files:
  created: []
  modified:
    - dlp-server/src/siem_connector.rs - 3 new unit tests
    - dlp-server/src/alert_router.rs - 1 new unit test
    - dlp-server/tests/bypass_alerts_integration.rs - 6 new integration tests

key-decisions:
  - "SIEM/alert router routing in fire-and-forget task is not synchronously testable at integration level; verified via unit tests plus code review of handler"
  - "Integration tests verify DB state and event construction logic rather than intercepted network calls"

requirements-completed:
  - ETW-05

metrics:
  duration: 25min
  completed: 2026-05-28
---

# Phase 53 Plan 06: SIEM + Alert Router Wiring Summary

**BypassAlertDetected and EtwConsumerGatedOff events route through SIEM relay and alert router with severity-based filtering, verified by 10 new tests (4 unit + 6 integration)**

## Performance

- **Duration:** 25 min
- **Started:** 2026-05-28T00:00:00Z
- **Completed:** 2026-05-28T00:25:00Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments

- Added 3 unit tests to `siem_connector.rs` verifying `BypassAlertDetected` and `EtwConsumerGatedOff` event relay
- Added 1 unit test to `alert_router.rs` verifying `BypassAlertDetected` crit severity event processing
- Added 6 integration tests to `bypass_alerts_integration.rs` covering:
  - `file_object` end-to-end preservation (CR-08)
  - Mixed severity batch DB state (2 crit + 3 warn)
  - SIEM payload JSON structure verification
  - Crit severity routing predicate
  - Warn severity routing predicate
  - `EtwConsumerGatedOff` routing semantics (CR-09)
- All 20 bypass alerts integration tests pass
- All dlp-server lib tests pass (549+)
- Full workspace lib tests pass
- Clippy clean on workspace libs (-D warnings)

## Task Commits

1. **Task 1: Verify and complete BypassAlertDetected + EtwConsumerGatedOff SIEM + alert router wiring** - `60ae581` (feat)
2. **Task 2: Create end-to-end integration tests for bypass alert pipeline** - `bc3715e` (feat)

## Files Created/Modified

- `dlp-server/src/siem_connector.rs` - Added `test_relay_bypass_alert_detected`, `test_relay_etw_consumer_gated_off`, `test_relay_skips_non_siem_events`
- `dlp-server/src/alert_router.rs` - Added `test_send_alert_crit_severity`
- `dlp-server/tests/bypass_alerts_integration.rs` - Added 6 integration tests for end-to-end bypass alert pipeline verification

## Decisions Made

- Followed plan as specified for unit tests
- For integration tests: the handler's SIEM/alert router calls happen in a `tokio::spawn` fire-and-forget task after the HTTP response returns. This architecture choice (from Plan 05) makes synchronous interception of SIEM/alert router calls impossible from integration tests. The integration tests verify the data flow up to the spawn point (DB state, event construction, routing predicates) while the unit tests verify the connectors accept the events.

## Deviations from Plan

### Integration Test Scope Adjustment

**1. [Rule 4 - Architectural] SIEM/alert router end-to-end interception not feasible with fire-and-forget architecture**
- **Found during:** Task 2 (integration test design)
- **Issue:** The `bypass_batch_ingest_handler` spawns SIEM/alert router calls in `tokio::spawn` after returning HTTP 200. Integration tests using `tower::ServiceExt::oneshot` cannot await or intercept these calls. Creating mock connectors would require trait abstractions or generics on `AppState`, which is an architectural change beyond this plan's scope.
- **Fix:** Integration tests verify: (a) DB state after ingest, (b) AuditEvent construction logic, (c) routing predicates (`routed_to_siem()`, `triggers_alert()`), and (d) severity-based filtering logic. The actual connector/router calls are verified by 4 unit tests that exercise `relay_events()` and `send_alert()` directly with `BypassAlertDetected` and `EtwConsumerGatedOff` events.
- **Files modified:** `dlp-server/tests/bypass_alerts_integration.rs`
- **Verification:** 20 integration tests pass, 4 unit tests pass
- **Committed in:** `bc3715e` (Task 2 commit)

---

**Total deviations:** 1 scope adjustment (architectural constraint)
**Impact on plan:** All success criteria met via combined unit + integration test coverage. No functionality gap.

## Issues Encountered

- Pre-existing clippy warnings in `bypass_alerts_integration.rs` (14 warnings including `let_unit_value` and unused `mut`). These are from the original file (Plan 05) and unrelated to this plan's changes. The workspace lib passes clippy clean (-D warnings).

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Phase 53 Plan 06 complete. All 6 Phase 53 plans are now complete.
- Phase 54 (Admin TUI Protected Paths + Bypass Alerts Screens) can begin.
- Phase 55 (Monitor-Only / Audit-Only Per-Policy Enforcement Mode) can begin in parallel.

---
*Phase: 53-etw-kernel-file-consumer-bypass-correlator-hook-journal-ring*
*Completed: 2026-05-28*
