---
phase: 53-etw-kernel-file-consumer-bypass-correlator-hook-journal-ring
plan: 05
subsystem: api
tags: [sqlite, axum, jwt, serde, etw, bypass-alerts, siem]

requires:
  - phase: 53-04
    provides: "BypassAlert v2 types with serde(default), BypassReason enum, batch_id support"
  - phase: 52-06
    provides: "Protected paths admin API pattern, AppState wiring pattern"
  - phase: 47
    provides: "Secrets encryption, SIEM connector, alert router infrastructure"

provides:
  - bypass_alerts SQLite table with dedup unique constraint and 5 indexes
  - BypassAlertsRepository with list_by_filters, insert, insert_batch, ack_by_id, get_by_id
  - POST /audit/bypass batch ingest endpoint (agent JWT, max 100 alerts)
  - GET /admin/bypass-alerts paginated filtered list endpoint (admin JWT)
  - POST /admin/bypass-alerts/{id}/ack idempotent ack endpoint (admin JWT)
  - v1+v2 BypassAlert deserialization with serde(default) backward compat
  - SIEM relay and alert router integration for crit severity alerts

affects:
  - 53-06 (SIEM + Alert Router Wiring)
  - 54 (Admin TUI Bypass Alerts Screen)

tech-stack:
  added: []
  patterns:
    - "Stateless repository pattern with associated functions (no &self)"
    - "INSERT OR IGNORE for deduplication via unique constraint"
    - "tokio::task::spawn_blocking for sync DB in async handlers"
    - "AdminUsername::extract_from_headers for inline JWT extraction"
    - "Batch ingest with (inserted, skipped) telemetry counts"

key-files:
  created:
    - dlp-server/src/db/repositories/bypass_alerts.rs
    - dlp-server/tests/bypass_alerts_integration.rs
  modified:
    - dlp-server/src/db/mod.rs
    - dlp-server/src/db/repositories/mod.rs
    - dlp-server/src/admin_api.rs
    - dlp-server/src/lib.rs
    - dlp-server/src/main.rs
    - dlp-e2e/src/lib.rs

key-decisions:
  - "Used INSERT OR IGNORE + tx.changes() == 0 for duplicate detection instead of last_insert_rowid() which returns existing row's ID"
  - "Default severity 'warn' for v1 alerts with empty severity field to satisfy CHECK constraint"
  - "Used AdminUsername::extract_from_headers(req.headers()) instead of axum extractor since AdminUsername is not an extractor type"
  - "Batch ingest routes to SIEM for all alerts and alert router only for crit severity"
  - "Limit capped at 500 with default 50 for pagination safety"

patterns-established:
  - "Repository batch insert: INSERT OR IGNORE per row, return (inserted, skipped) counts"
  - "Agent ID validation: compare batch.agent_id against JWT claim to prevent cross-agent injection"
  - "v1 compat: serde(default) on all new fields + DB DEFAULT for numeric fields"

requirements-completed:
  - ETW-04

# Metrics
duration: 45min
completed: 2026-05-28
---

# Phase 53 Plan 05: Server-Side Bypass Alert Storage Summary

**Bypass alerts SQLite schema with dedup, repository with batch insert/ack/filter, three HTTP routes (agent ingest + admin list/ack), and v1+v2 deserialization with SIEM/alert routing.**

## Performance

- **Duration:** 45 min
- **Started:** 2026-05-28
- **Completed:** 2026-05-28
- **Tasks:** 3
- **Files modified:** 9

## Accomplishments

- `bypass_alerts` table with CHECK constraints, 5 indexes (including pid per WR-05), composite unique constraint for dedup (WR-08)
- `BypassAlertsRepository` with 15 unit tests covering insert, batch, dedup, filter, pagination, ack, idempotency
- Three HTTP routes: POST /audit/bypass (agent), GET /admin/bypass-alerts (admin), POST /admin/bypass-alerts/{id}/ack (admin)
- 14 integration tests covering batch ingest, dedup, v1 compat, pagination, filtering, ack, auth requirements
- SIEM relay for all ingested alerts; alert router triggered only for crit severity
- v1 backward compatibility via serde(default) and DB DEFAULT 0 for file_object (WR-12)

## Task Commits

Each task was committed atomically:

1. **Task 1: Add bypass_alerts table to schema with dedup and pid index** - `bcea1bd` (feat)
2. **Task 2: Create BypassAlertsRepository with CRUD, ack, and batch dedup** - `67dbda1` (feat)
3. **Task 3: Add admin API routes and wire AppState with v1+v2 deserialization** - `821a658` (feat)
4. **Integration tests for bypass alerts + AppState wiring in all test suites** - `c508f65` (test)

## Files Created/Modified

- `dlp-server/src/db/mod.rs` - bypass_alerts table DDL in init_tables(), 7 schema validation tests
- `dlp-server/src/db/repositories/bypass_alerts.rs` - NEW: BypassAlertRow, BypassAlertInsertRow, BypassAlertFilter, BypassAlertsRepository with 15 unit tests
- `dlp-server/src/db/repositories/mod.rs` - Export bypass_alerts module
- `dlp-server/src/admin_api.rs` - Three handlers: bypass_batch_ingest_handler, list_bypass_alerts_handler, ack_bypass_alert_handler
- `dlp-server/src/lib.rs` - AppState.bypass_alerts field
- `dlp-server/src/main.rs` - AppState construction with bypass_alerts repository
- `dlp-server/tests/bypass_alerts_integration.rs` - NEW: 14 integration tests
- `dlp-e2e/src/lib.rs` - AppState construction with bypass_alerts field

## Decisions Made

- Used `INSERT OR IGNORE` with `tx.changes() == 0` for duplicate detection. The initial approach of using `last_insert_rowid()` returned the existing row's ID instead of 0, so `changes()` is the correct signal.
- Default severity "warn" for v1 alerts that have an empty severity field. The CHECK constraint rejects empty strings, so a sensible default is required for backward compatibility.
- Used `AdminUsername::extract_from_headers(req.headers())` instead of an axum extractor parameter because `AdminUsername` is not a type that implements `FromRequestParts`.
- Batch ingest routes all alerts to SIEM but only crit severity to the alert router, matching the existing pattern where crit triggers immediate operator notification.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed duplicate detection returning wrong value**
- **Found during:** Task 2 (Repository implementation)
- **Issue:** `INSERT OR IGNORE` + `last_insert_rowid()` returns the EXISTING row's ID, not 0, so duplicates were not detected
- **Fix:** Changed to check `uow.tx.changes() == 0` to detect ignored inserts
- **Files modified:** `dlp-server/src/db/repositories/bypass_alerts.rs`
- **Verification:** `test_insert_duplicate_ignored` passes
- **Committed in:** `67dbda1`

**2. [Rule 1 - Bug] Fixed SQL parameter binding count mismatch in list_by_filters**
- **Found during:** Task 2 (Repository implementation)
- **Issue:** `list_by_filters` incremented `param_count` for `acknowledged` filter even though it uses `IS NULL`/`IS NOT NULL` (no `?` placeholder), causing `InvalidParameterCount(1, 2)`
- **Fix:** Don't increment `param_count` for acknowledged filter
- **Files modified:** `dlp-server/src/db/repositories/bypass_alerts.rs`
- **Verification:** Filter tests pass
- **Committed in:** `67dbda1`

**3. [Rule 2 - Missing Critical] Added default severity for v1 alerts**
- **Found during:** Task 3 (Admin API implementation)
- **Issue:** v1 alerts have no `severity` field, so it defaults to `""` which fails `CHECK(severity IN ('info', 'warn', 'crit'))`
- **Fix:** Added `if alert.severity.is_empty() { "warn" } else { &alert.severity }` fallback
- **Files modified:** `dlp-server/src/admin_api.rs`
- **Verification:** `test_bypass_alert_v1_backward_compat` passes
- **Committed in:** `821a658`

**4. [Rule 3 - Blocking] Fixed AdminUsername not being an axum extractor**
- **Found during:** Task 3 (Admin API implementation)
- **Issue:** Tried to use `admin: AdminUsername` in handler signature, but it's not an axum extractor type
- **Fix:** Changed handler to take `req: axum::http::Request<axum::body::Body>` and call `AdminUsername::extract_from_headers(req.headers())?`
- **Files modified:** `dlp-server/src/admin_api.rs`
- **Verification:** Ack handler compiles and tests pass
- **Committed in:** `821a658`

**5. [Rule 3 - Blocking] Fixed siem.relay_event method name**
- **Found during:** Task 3 (Admin API implementation)
- **Issue:** Tried to call `state.siem.relay_event(&audit_event)` but method is `relay_events` (plural, takes `&[AuditEvent]`)
- **Fix:** Batched audit events and called `relay_events(&audit_events)`
- **Files modified:** `dlp-server/src/admin_api.rs`
- **Verification:** Batch ingest test passes
- **Committed in:** `821a658`

**6. [Rule 3 - Blocking] Fixed AppState missing bypass_alerts in integration tests**
- **Found during:** Task 3 (Integration tests)
- **Issue:** 8 integration test files construct AppState directly and were missing the new `bypass_alerts` field
- **Fix:** Added `bypass_alerts` field to all integration test harnesses and dlp-e2e
- **Files modified:** 8 test files + dlp-e2e/src/lib.rs
- **Verification:** All integration tests compile and pass
- **Committed in:** `c508f65`

---

**Total deviations:** 6 auto-fixed (2 bugs, 1 missing critical, 3 blocking)
**Impact on plan:** All auto-fixes necessary for correctness and compilation. No scope creep.

## Issues Encountered

- `SqliteConnectionManager::file(":memory:")` creates a NEW in-memory DB per connection. When `conn` was held across `pool.get()` calls, the second `get()` returned a connection to a brand new database. Fix: Wrap all `pool.get()` calls in blocks so connections are dropped before subsequent pool operations.
- FK constraint on `ack_by` references `admin_users(username)`. Tests failed because no admin user existed. Fix: Added `insert_admin_user()` helper in repository tests.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Phase 53-06 (SIEM + Alert Router Wiring) can proceed — the bypass alert storage is complete and the ingest endpoint is ready
- Phase 54 (Admin TUI Bypass Alerts Screen) can proceed — all admin API endpoints exist and are tested

---
*Phase: 53-etw-kernel-file-consumer-bypass-correlator-hook-journal-ring*
*Completed: 2026-05-28*
