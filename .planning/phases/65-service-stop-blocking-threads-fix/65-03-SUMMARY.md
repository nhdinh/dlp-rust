---
phase: 65-service-stop-blocking-threads-fix
plan: 03
subsystem: infra
tags: [windows-service, shutdown, named-pipe, tokio, atomicbool]

requires:
  - phase: 65-service-stop-blocking-threads-fix
    provides: SHUTDOWN_REQUESTED atomic, shutdown_requested() helper, BlockingThreads struct

provides:
  - Shutdown-aware Chrome Content Analysis pipe server
  - Shutdown-aware health monitor with bounded exit latency (~500ms for pong task)
  - Shutdown-aware session monitor with pre-tick exit

affects:
  - 65-04-plan (panic safety + PowerShell)
  - service-stop UAT

tech-stack:
  added: []
  patterns:
    - "Poll AtomicBool shutdown signal before blocking I/O calls"
    - "tokio::select! with short sleep for bounded async task shutdown"
    - "Pre-tick shutdown check to avoid interval-bound latency"

key-files:
  created: []
  modified:
    - dlp-agent/src/chrome/handler.rs
    - dlp-agent/src/health_monitor.rs
    - dlp-agent/src/session_monitor.rs

key-decisions:
  - "pong_task uses 500ms sleep in tokio::select! to bound shutdown latency to ~500ms instead of waiting for channel recv"
  - "timeout_task checks shutdown at start of select! branch before timeout processing"
  - "session_monitor checks shutdown BEFORE interval.tick() to avoid up to 2s wait"
  - "Chrome follows same pipe-close pattern as IPC pipes (Plan 65-02) for consistency"

patterns-established:
  - "Named pipe accept_loop: check shutdown_requested() before ConnectNamedPipeW, call CloseHandle on exit"
  - "Async task shutdown: tokio::select! between work and short sleep that polls shutdown flag"
  - "Pre-tick shutdown: check flag before interval.tick() to minimize exit latency"

requirements-completed:
  - STOP-01
  - STOP-02

# Metrics
duration: 18 min
completed: 2026-06-10
---

# Phase 65 Plan 03: Chrome + Health Monitor + Session Monitor Shutdown

**Shutdown signal polling added to Chrome pipe server, health monitor (bounded ~500ms latency), and session monitor (pre-tick check) for clean thread termination during service stop.**

## Performance

- **Duration:** 18 min
- **Started:** 2026-06-10T12:33:00Z
- **Completed:** 2026-06-10T12:51:00Z
- **Tasks:** 3
- **Files modified:** 6 (3 primary + 3 formatting)

## Accomplishments
- Chrome accept_loop polls shutdown flag before ConnectNamedPipeW and closes pipe handle on exit
- Health monitor ping_task breaks loop on shutdown after interval.tick()
- Health monitor pong_task uses tokio::select! with 500ms sleep to check shutdown frequently, bounding exit latency to ~500ms
- Health monitor timeout_task checks shutdown at start of each select! branch
- Session monitor checks shutdown_requested() BEFORE interval.tick() to avoid waiting up to 2s
- All subsystems emit info! log at task exit for shutdown diagnostics

## Task Commits

All three tasks committed atomically in a single commit (they are tightly coupled and must compile together):

1. **Task 1: Add shutdown check to Chrome accept_loop** - `cc23288` (feat)
2. **Task 2: Add shutdown to health monitor with bounded latency** - `cc23288` (feat)
3. **Task 3: Add shutdown to session monitor with pre-tick check** - `cc23288` (feat)

## Files Created/Modified
- `dlp-agent/src/chrome/handler.rs` - Shutdown-aware accept_loop with pipe handle cleanup
- `dlp-agent/src/health_monitor.rs` - Shutdown-aware ping_task, pong_task (select! + 500ms), timeout_task
- `dlp-agent/src/session_monitor.rs` - Pre-tick shutdown check in session_loop
- `dlp-agent/src/ipc/pipe1.rs` - cargo fmt line wrapping (no functional change)
- `dlp-agent/src/ipc/pipe2.rs` - cargo fmt line wrapping (no functional change)
- `dlp-agent/src/ipc/pipe3.rs` - cargo fmt line wrapping (no functional change)

## Decisions Made
- pong_task uses 500ms sleep in tokio::select! to bound shutdown latency to ~500ms instead of waiting indefinitely for channel recv (addresses OpenCode MEDIUM-HIGH concern)
- timeout_task checks shutdown at start of select! branch before timeout processing (addresses Codex MEDIUM-HIGH concern about unpredictable timing)
- session_monitor checks shutdown BEFORE interval.tick() to avoid up to 2s wait (addresses OpenCode MEDIUM concern about WTS DC timeout edge case)
- Chrome follows same pipe-close pattern as IPC pipes (Plan 65-02) for consistency (addresses Codex HIGH concern)

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- cargo fmt modified pipe1/pipe2/pipe3.rs line wrapping from prior 65-02 commits; no functional change, staged alongside primary changes

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Plan 65-04 (panic safety + PowerShell stop handling) can now proceed; all blocking threads now respect shutdown signal
- All four blocking thread categories (IPC pipes, Chrome, health monitor, session monitor) are shutdown-aware

## Self-Check: PASSED

- [x] Chrome accept_loop checks shutdown_requested() between connections and closes pipe handle
- [x] Health monitor ping_task breaks loop on shutdown after interval.tick()
- [x] Health monitor pong_task uses tokio::select! with 500ms shutdown check
- [x] Health monitor timeout_task breaks loop on shutdown after interval.tick()
- [x] Session monitor checks shutdown_requested() before interval.tick()
- [x] All three subsystems emit info! log at task exit
- [x] dlp-agent compiles with zero warnings (`cargo check` clean)
- [x] clippy passes (`cargo clippy -- -D warnings` clean)
- [x] All 761 dlp-agent lib tests pass
- [x] Commit `cc23288` exists and contains all changes

---
*Phase: 65-service-stop-blocking-threads-fix*
*Completed: 2026-06-10*
