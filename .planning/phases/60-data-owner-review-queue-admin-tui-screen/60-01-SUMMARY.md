---
phase: 60-data-owner-review-queue-admin-tui-screen
plan: 01
subsystem: api
tags: [rust, axum, sqlite, jwt, ratatui, audit, abac]

requires:
  - phase: 59-data-owner-review-queue-admin-tui-screen
    provides: LabelReviewQueue TUI screen, confirm/reject endpoints, LabelList/Detail/Form screens

provides:
  - SIEM audit events on label confirm/reject with before/after state tracking
  - Data Owner scoping via JWT SID claims (non-admins see only their labels)
  - scanner_confidence column in labels table (f32, nullable)
  - department column in labels table (TEXT, nullable) with DB-level filtering
  - ABAC cache invalidation on confirm via LabelService::invalidate_cache()
  - GET /admin/labels/departments endpoint for TUI dropdown population
  - TUI Confidence column displaying scanner_confidence as percentage
  - TUI department filter cycling with 'd' key

affects:
  - phase-61-approval-workflow-engine
  - phase-62-syslog-forwarder
  - phase-68-email-outlook

tech-stack:
  added: [urlencoding]
  patterns:
    - "Dynamic SQL with numbered placeholders for list_by_filters"
    - "JWT sid claim extraction for role-based scoping"
    - "Best-effort SIEM audit emission with local audit_events fallback"
    - "ABAC cache invalidation after label state mutation"

key-files:
  created: []
  modified:
    - dlp-server/src/db/mod.rs - labels table schema with scanner_confidence and department
    - dlp-server/src/db/repositories/labels.rs - list_by_filters with DB-level filtering
    - dlp-common/src/label.rs - Label struct with scanner_confidence
    - dlp-server/src/admin_api.rs - owner scoping, audit events, cache invalidation, departments endpoint
    - dlp-server/src/admin_auth.rs - Claims with sid field
    - dlp-server/src/lib.rs - AppError::Forbidden variant
    - dlp-admin-cli/src/client.rs - list_labels with department filter, list_departments
    - dlp-admin-cli/src/app.rs - LabelReviewQueue screen with department state
    - dlp-admin-cli/src/screens/dispatch.rs - department filter cycling
    - dlp-admin-cli/src/screens/render.rs - Confidence column, department in detail
    - dlp-admin-cli/src/screens/labels.rs - updated hints
    - dlp-admin-cli/Cargo.toml - urlencoding dependency
    - dlp-e2e/src/lib.rs - Claims with sid field

key-decisions:
  - "Added AppError::Forbidden variant for 403 responses instead of reusing Unauthorized"
  - "Used username == 'dlp-admin' as admin check for Phase 60 pragmatism; full RBAC in Phase 61"
  - "Stored audit events locally via audit_store::store_events_sync as fallback before SIEM relay"
  - "Department filter cycling fetches distinct values from server; no hardcoded list"

patterns-established:
  - "Owner scoping: extract caller_sid from JWT, apply DB-level filter when present and user != admin"
  - "Audit emission: construct AuditEvent, store locally, then relay to SIEM best-effort"
  - "Cache invalidation: state.label_service.invalidate_cache() immediately after DB commit"

requirements-completed: [LABEL-04]

duration: 45min
completed: 2026-05-12
---

# Phase 60: Data Owner Review Queue + Admin TUI Screen Summary

**SIEM audit events, Data Owner JWT scoping, scanner confidence tracking, department filtering, and ABAC cache invalidation for the label review workflow**

## Performance

- **Duration:** 45 min
- **Started:** 2026-05-12T00:00:00Z
- **Completed:** 2026-05-12T00:45:00Z
- **Tasks:** 3
- **Files modified:** 15

## Accomplishments
- Extended labels table with scanner_confidence (REAL, nullable) and department (TEXT, nullable) columns
- Replaced list_by_state with list_by_filters supporting DB-level filtering by state, tier, owner_sid, and department
- Added AppError::Forbidden variant and owner scoping in confirm/reject handlers
- confirm_label and reject_label emit SIEM audit events and invalidate ABAC cache
- Added GET /admin/labels/departments endpoint returning distinct department values
- TUI review queue displays scanner confidence as percentage (e.g., "85%") or "--"
- TUI supports department filter cycling with 'd' key

## Task Commits

Each task was committed atomically:

1. **Task 1: Extend DB schema and repository** - `d1ed3f1` (feat)
2. **Task 2: Admin API updates for owner scoping, audit events, and cache invalidation** - `ad283a5` (feat)
3. **Task 3: TUI updates for confidence column, department filter, and owner scoping** - `6bfc4e9` (feat)

## Files Created/Modified
- `dlp-server/src/db/mod.rs` - labels table schema with scanner_confidence and department columns
- `dlp-server/src/db/repositories/labels.rs` - LabelRow/LabelUpsertRow with new fields; list_by_filters method
- `dlp-common/src/label.rs` - Label struct with scanner_confidence: Option<f32>
- `dlp-server/src/admin_api.rs` - owner scoping, audit events, cache invalidation, departments endpoint
- `dlp-server/src/admin_auth.rs` - Claims with sid: Option<String>
- `dlp-server/src/lib.rs` - AppError::Forbidden variant
- `dlp-admin-cli/src/client.rs` - list_labels with department filter, list_departments
- `dlp-admin-cli/src/app.rs` - LabelReviewQueue with department state
- `dlp-admin-cli/src/screens/dispatch.rs` - department filter cycling
- `dlp-admin-cli/src/screens/render.rs` - Confidence column, department in detail view
- `dlp-admin-cli/src/screens/labels.rs` - updated footer hints
- `dlp-admin-cli/Cargo.toml` - urlencoding dependency
- `dlp-e2e/src/lib.rs` - Claims with sid field

## Decisions Made
- Added AppError::Forbidden variant for 403 responses instead of reusing Unauthorized (clearer semantics)
- Used username == "dlp-admin" as admin check for Phase 60 pragmatism; full RBAC with groups comes in Phase 61
- Stored audit events locally via audit_store::store_events_sync before SIEM relay (fallback if relay fails)
- Department filter cycling fetches distinct values from server via new endpoint (no hardcoded list)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed corrupted reject_label handler after sed replacement**
- **Found during:** Task 2
- **Issue:** sed replacement corrupted the owner scoping check in reject_label with malformed if statements
- **Fix:** Manually removed corrupted lines and inserted correct pattern with username2 clone
- **Files modified:** dlp-server/src/admin_api.rs
- **Verification:** cargo build passes
- **Committed in:** ad283a5

**2. [Rule 2 - Missing Critical] Added AppError::Forbidden variant**
- **Found during:** Task 2
- **Issue:** Plan referenced AppError::Forbidden but the variant did not exist in the enum
- **Fix:** Added Forbidden(String) variant to AppError with 403 status mapping in IntoResponse
- **Files modified:** dlp-server/src/lib.rs
- **Verification:** cargo build passes, clippy clean
- **Committed in:** ad283a5

**3. [Rule 3 - Blocking] Fixed username move errors in confirm/reject handlers**
- **Found during:** Task 2
- **Issue:** username String was moved into spawn_blocking closure, causing borrow checker errors when used later for audit events
- **Fix:** Cloned username to username2 before moving into closure
- **Files modified:** dlp-server/src/admin_api.rs
- **Verification:** cargo build passes
- **Committed in:** ad283a5

**4. [Rule 3 - Blocking] Added urlencoding dependency to dlp-admin-cli**
- **Found during:** Task 3
- **Issue:** client.rs needed URL encoding for department query parameters but no encoding crate was available
- **Fix:** Added urlencoding = "2" to dlp-admin-cli/Cargo.toml
- **Files modified:** dlp-admin-cli/Cargo.toml
- **Verification:** cargo build passes
- **Committed in:** 6bfc4e9

**5. [Rule 1 - Bug] Fixed UTF-8 encoding corruption in admin_api.rs**
- **Found during:** Task 2
- **Issue:** Python string replacement introduced a bad byte (0x97) in the doc comment for list_label_departments
- **Fix:** Replaced bad bytes with correct ASCII text
- **Files modified:** dlp-server/src/admin_api.rs
- **Verification:** cargo build passes
- **Committed in:** ad283a5

---

**Total deviations:** 5 auto-fixed (2 bugs, 2 blocking, 1 missing critical)
**Impact on plan:** All auto-fixes necessary for correctness and compilation. No scope creep.

## Issues Encountered
- sed command corrupted reject_label handler; required manual fix
- Multiple unused variable warnings for caller_sid in handlers that don't yet use it; prefixed with underscore
- Borrow checker challenges in TUI dispatch.rs when mixing screen state mutation with app method calls; resolved by cloning labels first and re-borrowing screen for mutations

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Phase 61 (Approval Workflow Engine) can build on the department filter and owner scoping
- Phase 62 (Syslog Forwarder) can consume the audit events already being emitted
- Phase 68 (Email/Outlook) can hook into the label review workflow

---
*Phase: 60-data-owner-review-queue-admin-tui-screen*
*Completed: 2026-05-12*
