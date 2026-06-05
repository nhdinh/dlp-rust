---
phase: 58-differentiators-bundle-override-diagnostic-hash-evidence-sel
plan: 58-04
subsystem: server + agent

tags: [rust, axum, sqlite, diagnostics, health-monitoring, evidence-hashing, ipc]

requires:
  - phase: 58-differentiators-bundle-override-diagnostic-hash-evidence-sel
    provides: DiagnosticSnapshotStore, DiagnosticAggregator, HealthAggregator (DIFF-02, DIFF-04)

provides:
  - GET /admin/diagnostics endpoint with JWT auth and pagination
  - audit_events.content_sha256 column for evidence integrity
  - Agent service startup wiring for DiagnosticAggregator and HealthAggregator
  - HookIpcServer with diagnostics and health handlers

affects:
  - 58-differentiators-bundle-override-diagnostic-hash-evidence-sel
  - Any phase consuming diagnostic data via admin API

tech-stack:
  added: []
  patterns:
    - "In-memory DashMap-backed diagnostic snapshot storage with per-DLL caps"
    - "SQLite schema migration via run_alter for content_sha256"
    - "Hook IPC server on dedicated std::thread with force-close shutdown"
    - "Stub HookResponse handler for future ABAC wiring"

key-files:
  created:
    - dlp-server/src/diagnostic_store.rs
  modified:
    - dlp-server/src/admin_api.rs
    - dlp-server/src/lib.rs
    - dlp-server/src/main.rs
    - dlp-server/src/db/mod.rs
    - dlp-server/src/db/repositories/audit_events.rs
    - dlp-server/src/audit_store.rs
    - dlp-agent/src/service.rs
    - dlp-server/tests/admin_audit_integration.rs
    - dlp-server/tests/bypass_alerts_integration.rs
    - dlp-server/tests/device_registry_integration.rs
    - dlp-server/tests/enforcement_mode_integration.rs
    - dlp-server/tests/ldap_config_api.rs
    - dlp-server/tests/managed_origins_integration.rs
    - dlp-server/tests/mode_end_to_end.rs
    - dlp-server/tests/secrets_encryption_integration.rs
    - dlp-server/tests/secrets_log_scan_integration.rs

key-decisions:
  - "DiagnosticSnapshotStore created in dlp-server (not dlp-agent) because dlp-server cannot depend on dlp-agent"
  - "HookResponse stub returns ALLOW with empty cache_hint — full ABAC evaluation wired in future phase"
  - "Health handler returns default HookHealthSnapshot when no history exists (unwrap_or_default)"
  - "Hook IPC server shutdown uses CreateFileW+CloseHandle to force-close named pipe and unblock ConnectNamedPipeW"
  - "Server push tasks (diagnostic/health to server) reserved as None fields — no server endpoints exist yet"

patterns-established:
  - "Server-side mirror of agent aggregators for standalone operation"
  - "Schema migration with run_alter for backward compatibility"
  - "Force-close named pipe technique for graceful thread shutdown"

requirements-completed: [DIFF-02, DIFF-04]

# Metrics
duration: 25min
completed: 2026-06-02
---

# Phase 58 Plan 04: Admin Diagnostics, Evidence Hashing, and Agent Aggregator Wiring Summary

**Admin diagnostics endpoint with JWT-protected pagination, audit_events schema extension for content SHA-256 evidence hashing, and agent service startup wiring for diagnostic and health aggregators with hook IPC server**

## Performance

- **Duration:** 25 min
- **Started:** 2026-06-02T22:06:00+07:00
- **Completed:** 2026-06-02T22:31:00+07:00
- **Tasks:** 3
- **Files modified:** 17

## Accomplishments

- **Task 1:** GET /admin/diagnostics endpoint with DiagnosticQuery (since, user_sid, policy_id, limit, offset), DiagnosticListResponse, list_diagnostics_handler with 1000-entry limit cap, and 4 integration tests (auth, empty store, with data, pagination/filtering)
- **Task 2:** audit_events schema extended with content_sha256 TEXT column, run_alter migration for existing tables, AuditEventRow updated, insert_batch and query methods updated, store_events_sync and ingest_events handlers updated, 2 new tests for hash roundtrip and null handling
- **Task 3:** Agent service startup wires DiagnosticAggregator and HealthAggregator into RunLoopContext, starts HookIpcServer on dedicated std::thread with diagnostics and health handlers, adds force-close named pipe shutdown logic

## Task Commits

Each task was committed atomically:

1. **Task 1: GET /admin/diagnostics endpoint** - `54fbc36` (feat)
2. **Task 2: Extend audit_events with content_sha256** - `dec3e8a` (feat)
3. **Task 3: Wire agent startup with aggregators** - `9afc1e4` (feat)

## Files Created/Modified

- `dlp-server/src/diagnostic_store.rs` - In-memory DiagnosticSnapshotStore with DashMap, filtering, pagination (343 lines, 7 tests)
- `dlp-server/src/admin_api.rs` - Added DiagnosticQuery, DiagnosticListResponse, list_diagnostics_handler, route registration, 4 integration tests
- `dlp-server/src/lib.rs` - Added `pub mod diagnostic_store;` and `diagnostic_store` field to AppState
- `dlp-server/src/main.rs` - Added `diagnostic_store: None` to AppState construction
- `dlp-server/src/db/mod.rs` - Added content_sha256 to CREATE TABLE and run_alter migration
- `dlp-server/src/db/repositories/audit_events.rs` - Added content_sha256 to AuditEventRow, insert_batch, query
- `dlp-server/src/audit_store.rs` - Populated content_sha256 in store_events_sync and ingest_events, added 2 tests
- `dlp-agent/src/service.rs` - Added aggregator init, HookIpcServer startup, shutdown handling (125 lines)
- 9 integration test files - Added `diagnostic_store: None` to AppState constructions

## Decisions Made

- **Server-side store mirror:** Created DiagnosticSnapshotStore in dlp-server rather than moving types to dlp-common, because dlp-server cannot depend on dlp-agent and dashmap in dlp-common would be inappropriate
- **HookResponse stub:** Returns ALLOW decision with empty cache_hint and cache_version=0 — full ABAC evaluation will be wired in a future phase when the classification cache integration is complete
- **Health handler default:** Uses unwrap_or_default() for HookHealthSnapshot when no history exists, ensuring the hook DLL always receives a valid response
- **Named pipe shutdown:** Uses CreateFileW to open a client handle to the pipe, then CloseHandle to force-close it, unblocking ConnectNamedPipeW in the server thread
- **Server push deferred:** Diagnostic and health push tasks to the server are reserved as None fields in RunLoopContext — the server does not yet have push endpoints

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Missing handler code and route registration in admin_api.rs**
- **Found during:** Task 1
- **Issue:** The previous session's context summary claimed DiagnosticQuery, DiagnosticListResponse, and list_diagnostics_handler were added, but they were missing from admin_api.rs (only tests were present)
- **Fix:** Added the full handler code, query/response types, and route registration
- **Files modified:** dlp-server/src/admin_api.rs

**2. [Rule 1 - Bug] Incorrect type assumptions for hook IPC types**
- **Found during:** Task 3
- **Issue:** Assumed PullDiagnosticsRequest had since/user_sid/policy_id/limit/offset fields, DiagnosticsResponse had total, HealthResponse had status/total, and HookResponse was an enum with Allow variant
- **Fix:** Corrected to actual types: max_entries only, snapshots only, snapshot only, struct with decision/reason/cache_hint/cache_version
- **Files modified:** dlp-agent/src/service.rs

**3. [Rule 1 - Bug] CreateFileW returns Result<HANDLE, Error> not HANDLE**
- **Found during:** Task 3
- **Issue:** Treated CreateFileW return value as HANDLE directly; it's actually a Result
- **Fix:** Wrapped in if-let-Ok and used FILE_FLAGS_AND_ATTRIBUTES(0) for the dwFlagsAndAttributes parameter
- **Files modified:** dlp-agent/src/service.rs

## Issues Encountered

- `push_diagnostics` and `push_health` methods do not exist on ServerClient — server push tasks deferred to future phase
- `DiagnosticListResponse` needed `Deserialize` derive for test deserialization
- 16 AppState constructions in admin_api.rs tests and 9 in integration test files needed `diagnostic_store: None` field

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Admin diagnostics endpoint is ready for hook DLL snapshot consumption
- Audit events now store content_sha256 for evidence integrity
- Agent service initializes diagnostic and health aggregators at startup
- Hook IPC server responds to PullDiagnostics and PullHealth requests
- No blockers

---
*Phase: 58-differentiators-bundle-override-diagnostic-hash-evidence-sel*
*Completed: 2026-06-02*
