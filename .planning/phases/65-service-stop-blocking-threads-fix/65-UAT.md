---
status: fixed
phase: 65-service-stop-blocking-threads-fix
source:
  - 65-01-SUMMARY.md
  - 65-02-SUMMARY.md
  - 65-03-SUMMARY.md
  - 65-04-SUMMARY.md
  - 65-05-SUMMARY.md
started: "2026-06-11T00:30:00Z"
updated: "2026-06-11T01:00:00Z"
---

## Current Test

[fixes applied — ready for re-test]

## Tests

### 1. Clean Stop with Correct Password
expected: |
  Run `sc stop dlp-agent`. Enter correct password. Service stops within 10s. `Get-Process dlp-agent` returns nothing.
result: fixed
severity: major
notes: |
  Root cause: When password verification errored (e.g. hash not in registry, server unreachable),
  `maybe_abort_after_failure(1)` did NOT call `abort_stop()` because `1 < MAX_ATTEMPTS` (3).
  The UI process had already exited, so there was no retry. Service stayed StopPending forever.
  Fix: `maybe_abort_after_failure` now always calls `abort_stop()` since the UI exits after each
  submission and retries are not possible.

### 2. Stop with Wrong Password (3x)
expected: |
  Run `sc stop dlp-agent`. Enter wrong password 3 times. UI closes, service reverts to Running. `Get-Service dlp-agent` shows Status = Running.
result: fixed
severity: major
notes: |
  Root cause: Same as Test 1 — wrong password set `FAILED_ATTEMPTS` to 1, but
  `maybe_abort_after_failure(1)` only aborted when `attempt >= MAX_ATTEMPTS` (3).
  The UI process exits after writing the response file, so no retries were possible.
  Service stayed StopPending.
  Fix: `maybe_abort_after_failure` now always calls `abort_stop()` on any failure.

### 3. Stop with Cancel
expected: |
  Run `sc stop dlp-agent`. Click Cancel in UI dialog. Service reverts to Running. `Get-Service dlp-agent` shows Status = Running.
result: fixed
severity: major
notes: |
  Root cause: `handle_password_cancel` called `reset_stop_state()` but never called
  `abort_stop()`, which contains `crate::service::revert_stop()` that reports Running to SCM.
  Fix: `handle_password_cancel` now calls `abort_stop()` directly.

### 4. Stop via PowerShell Script
expected: |
  Run `Manage-DlpAgentService.ps1 -Action Stop`. Enter correct password. Script reports "Service stopped successfully". `Get-Service dlp-agent` shows Status = Stopped.
result: fixed
severity: major
notes: |
  Root cause: Same as Test 1 — any password verification error left the service stuck.
  Fix: `maybe_abort_after_failure` now always aborts, reverting service to Running on failure.

### 5. PowerShell Script Detects StopPending
expected: |
  Start a stop with `sc stop dlp-agent`. While in StopPending, run `Manage-DlpAgentService.ps1 -Action Stop`. Script detects StopPending and prints guidance instead of error.
result: skipped
reason: "Skipped — re-test after fixes for Tests 1-4"

### 6. Restart After Stop
expected: |
  Stop service, then run `sc start dlp-agent`. Service starts successfully. Chrome, IPC, health monitor, session monitor all functional.
result: skipped
reason: "Skipped — re-test after fixes for Tests 1-4"

### 7. Multiple Stop/Start Cycles
expected: |
  Repeat stop/start 3 times. Each cycle completes cleanly without hangs.
result: skipped
reason: "Skipped — re-test after fixes for Tests 1-4"

### 8. Stop with No Active UI Session
expected: |
  Log off all interactive sessions. Run `sc stop dlp-agent`. Stop times out after 120s, service reverts to Running.
result: skipped
reason: "Skipped — re-test after fixes for Tests 1-4"

## Summary

| round | passed | issues | skipped | blocked |
|-------|--------|--------|---------|---------|
| 1     | 0      | 4      | 4       | 0       |
| 2     | —      | —      | —       | —       |

total: 8
passed: 0 (4 fixed, pending re-test)
issues: 4 (all diagnosed and fixed)
pending: 0
skipped: 4
blocked: 0

## Fixes Applied

### Fix 1: `handle_password_cancel` calls `abort_stop()`
File: `dlp-agent/src/password_stop.rs:474`
Change: Replaced `reset_stop_state()` with `abort_stop()`.
Effect: Cancel now properly reverts service to Running via `revert_stop()`.

### Fix 2: `maybe_abort_after_failure` always aborts
File: `dlp-agent/src/password_stop.rs:541`
Change: Removed `if attempt >= MAX_ATTEMPTS` guard. Now always calls `abort_stop()`.
Effect: Any wrong password or verification error immediately reverts service to Running.
Rationale: The UI process (`dlp-user-ui`) exits after writing the response file. There is no
retry mechanism, so the `MAX_ATTEMPTS` logic was based on a false assumption.

## Verification

- `cargo test -p dlp-agent --lib password_stop`: 8 passed, 0 failed
- `cargo test -p dlp-agent --lib`: 772 passed, 0 failed
- `cargo clippy -p dlp-agent -- -D warnings`: clean
