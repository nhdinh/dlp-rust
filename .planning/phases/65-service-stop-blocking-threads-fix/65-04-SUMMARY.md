---
phase: 65-service-stop-blocking-threads-fix
plan: 04
subsystem: dlp-agent
 tags: [panic-safety, service-stop, password-challenge, powershell, testing]
dependency_graph:
  requires: [65-01, 65-02, 65-03]
  provides: [STOP-03]
  affects: [dlp-agent/src/password_stop.rs, dlp-agent/src/service.rs, scripts/Manage-DlpAgentService.ps1]
tech_stack:
  added: []
  patterns: [catch_unwind, AssertUnwindSafe, two-phase-lifecycle, state-polling]
key_files:
  created: []
  modified:
    - dlp-agent/src/password_stop.rs
    - dlp-agent/src/service.rs
    - scripts/Manage-DlpAgentService.ps1
decisions:
  - Extracted verify_stop_password() as standalone testable function to enable unit testing without thread spawning
  - Used parking_lot::Mutex non-poisoning property as AssertUnwindSafe safety justification
  - Removed request_shutdown() from Stop control handler to preserve two-phase lifecycle
  - PowerShell polling uses 1-second interval with 30-second max wait for responsive feedback
metrics:
  duration: "~35 minutes"
  completed_date: "2026-06-10"
---

# Phase 65 Plan 04: Panic Safety for Password-Protected Service Stop

**One-liner:** Added panic safety to password_stop::initiate_stop() with catch_unwind(AssertUnwindSafe), extracted testable verification functions, fixed two-phase lifecycle by removing premature request_shutdown(), and updated PowerShell management script with state polling and escalation guidance.

---

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Restructure initiate_stop for testability | 174c092 | dlp-agent/src/password_stop.rs |
| 2 | Remove request_shutdown() from Stop control handler | b1ef615 | dlp-agent/src/service.rs |
| 3 | Update PowerShell script stop handling with state polling | 3ec0116 | scripts/Manage-DlpAgentService.ps1 |
| 4 | Write unit tests for catch_unwind and verify_stop_password | 826fadf | dlp-agent/src/password_stop.rs |
| 5 | Add integration tests for service shutdown signal and BlockingThreads | e9b6f36 | dlp-agent/src/service.rs |

---

## What Was Built

### Panic-Safe Password Verification (Task 1)

- Extracted `verify_stop_password(request_id, response_path)` as a standalone testable function returning `Result<(), StopError>`
- Extracted `handle_file_response_for_verify(request_id, data)` for isolated response parsing
- Added `StopError` enum with `Cancelled` and `MaxAttempts` variants
- Wrapped `verify_stop_password()` in `std::panic::catch_unwind(std::panic::AssertUnwindSafe(...))`
- Documented AssertUnwindSafe safety justification in a SAFETY comment:
  - Closure captures only immutable `String` values (Send + UnwindSafe)
  - No MutexGuard or RAII guard held across panic boundary
  - `parking_lot::Mutex` does not poison on panic
  - On panic, `abort_stop()` resets all state atomically
- Response file cleanup happens in all paths (success, failure, panic)
- Removed unused `handle_file_response` and `cancel_stop` functions

### Two-Phase Lifecycle Fix (Task 2)

- **CRITICAL FIX:** Removed `request_shutdown()` call from `ServiceControl::Stop` handler
- The correct lifecycle is now:
  1. SCM Stop received -> Set `SERVICE_STATE = StopPending`
  2. `initiate_stop()` spawns password verification thread
  3. Password verified -> `STOP_CONFIRMED = true`
  4. `run_loop` sees `STOP_CONFIRMED` -> exits
  5. `run_service` continues to shutdown sequence
  6. `request_shutdown()` called ONLY after password verified
  7. `threads.shutdown_and_join()` called
  8. STOPPED reported to SCM
- Added detailed comment explaining why shutdown is NOT requested in the Stop handler
- If stop is cancelled or fails, service returns to Running without torn-down threads

### PowerShell State-Aware Stop (Task 3)

- `Stop-DlpAgentService` now detects `StopPending` before calling `Stop-Service`
- Detects `Stopped` state before calling `Stop-Service`
- After `Stop-Service`, polls every 1 second for up to 30 seconds
- Reports final state: `Stopped`, `Running` (reverted), `Removed`, or timeout
- On timeout, provides escalation guidance:
  1. Restart the machine (guaranteed recovery)
  2. From SYSTEM context: `psexec -s taskkill /F /IM dlp-agent.exe`
  3. Then re-register: `sc.exe delete dlp-agent; .\Manage-DlpAgentService.ps1 -Action Install`
- Uses `try/catch` for `Stop-Service` error handling

### Unit Tests (Task 4)

8 new tests in `password_stop::tests`:
- `test_catch_unwind_catches_panic` - verifies panic is caught
- `test_handle_file_response_for_verify_cancel` - cancel response handling
- `test_handle_file_response_for_verify_submit_no_password` - missing password handling
- `test_handle_file_response_for_verify_parse_error` - malformed JSON handling
- `test_abort_stop_resets_state` - verifies state reset on abort
- `test_assert_unwind_safe_soundness` - documents safety invariant
- `test_reset_stop_state` - verifies all state fields cleared
- `test_is_stop_confirmed_roundtrip` - verifies atomic flag read/write

### Service Shutdown Tests (Task 5)

3 new tests in `service.rs`:
- `test_shutdown_signal_roundtrip` - set/read/reset of shutdown signal
- `test_blocking_threads_empty_shutdown` - empty case completes cleanly
- `test_blocking_threads_joins_running_thread` - thread signal and join
- Added `reset_shutdown_signal()` helper for test isolation

---

## Deviations from Plan

### Auto-fixed Issues

**None** - plan executed exactly as written.

### Minor Adjustments

1. **Removed unused functions** (Task 1 follow-up): After extracting `verify_stop_password()` and `handle_file_response_for_verify()`, the old `handle_file_response()` and `cancel_stop()` became dead code. Removed them to maintain zero warnings.

2. **Test count**: The plan specified 4 tests in Task 4; delivered 8 tests for more complete coverage (added reset_stop_state, is_stop_confirmed_roundtrip, and additional handle_file_response_for_verify cases).

3. **BlockingThreads::shutdown_and_join signature**: The plan suggested passing a `Duration` timeout to `shutdown_and_join`, but the actual function takes no parameters. The test was adjusted to match the existing signature.

---

## Verification Results

- `cargo check -p dlp-agent` - zero warnings
- `cargo clippy -p dlp-agent -- -D warnings` - clean
- `cargo test -p dlp-agent --lib` - 772 passed, 0 failed, 0 ignored
- `cargo test -p dlp-agent password_stop::tests` - 8 passed
- PowerShell syntax validation - valid (tested with `powershell -NoProfile -ExecutionPolicy Bypass`)

---

## Known Stubs

None. All functionality is fully wired and tested.

---

## Threat Flags

None. No new security-relevant surface introduced.

---

## Self-Check: PASSED

- [x] `dlp-agent/src/password_stop.rs` modified (StopError, verify_stop_password, handle_file_response_for_verify, tests)
- [x] `dlp-agent/src/service.rs` modified (removed request_shutdown, added reset_shutdown_signal, shutdown tests)
- [x] `scripts/Manage-DlpAgentService.ps1` modified (state-aware Stop-DlpAgentService)
- [x] Commit 174c092 exists
- [x] Commit b1ef615 exists
- [x] Commit 3ec0116 exists
- [x] Commit 826fadf exists
- [x] Commit e9b6f36 exists
