---
phase: 65-service-stop-blocking-threads-fix
plan: 02
subsystem: ipc

tags:
  - named-pipe
  - shutdown
  - windows
  - dlp-agent
  - ConnectNamedPipeW

requires:
  - phase: 65-01
    provides: shutdown_requested() signal infrastructure

provides:
  - Shutdown-aware accept_loop in pipe1, pipe2, and pipe3
  - Clean pipe handle cleanup on shutdown for all three IPC pipes
  - Inner-loop shutdown check in pipe3 handle_client for persistent connections

affects:
  - 65-03
  - 65-04

tech-stack:
  added: []
  patterns:
    - "Poll shutdown flag at top of blocking accept_loop before ConnectNamedPipeW"
    - "CloseHandle on pipe before returning from accept_loop on shutdown"
    - "Inner-loop shutdown check for persistent-connection handlers"

key-files:
  created: []
  modified:
    - dlp-agent/src/ipc/pipe1.rs
    - dlp-agent/src/ipc/pipe2.rs
    - dlp-agent/src/ipc/pipe3.rs

key-decisions:
  - "Shutdown check placed BEFORE ConnectNamedPipeW so threads blocked in the call will see the flag on the next loop iteration after the call completes"
  - "Pipe3 handle_client gets an additional inner-loop check because it supports persistent UI connections"

patterns-established:
  - "Consistent shutdown polling pattern across all IPC pipe accept loops"
  - "Info-level logging on shutdown detection for operational visibility"

requirements-completed:
  - STOP-01
  - STOP-02

duration: 8min
completed: 2026-06-10
---

# Phase 65 Plan 02: IPC Pipe Shutdown Awareness Summary

**Shutdown signal polling added to all three IPC pipe accept loops (pipe1, pipe2, pipe3) with clean handle cleanup and persistent-connection inner-loop coverage**

## Performance

- **Duration:** 8 min
- **Started:** 2026-06-10T12:15:00Z
- **Completed:** 2026-06-10T12:23:00Z
- **Tasks:** 4
- **Files modified:** 3

## Accomplishments

- Pipe1 accept_loop polls `shutdown_requested()` before each `ConnectNamedPipeW` call
- Pipe2 accept_loop polls `shutdown_requested()` before each `ConnectNamedPipeW` call
- Pipe3 accept_loop polls `shutdown_requested()` before each `ConnectNamedPipeW` call
- Pipe3 handle_client inner read loop polls `shutdown_requested()` for persistent connections
- All pipe handles are closed via `CloseHandle` before returning on shutdown
- `cargo check -p dlp-agent` compiles with zero warnings

## Task Commits

Each task was committed atomically:

1. **Task 1: Add shutdown check to pipe1 accept_loop** - `849ed84` (feat)
2. **Task 2: Add shutdown check to pipe2 accept_loop** - `ad56266` (feat)
3. **Task 3+4: Add shutdown checks to pipe3 accept_loop and handle_client** - `ee92f89` (feat)

## Files Created/Modified

- `dlp-agent/src/ipc/pipe1.rs` - Added shutdown check at top of accept_loop before ConnectNamedPipeW
- `dlp-agent/src/ipc/pipe2.rs` - Added shutdown check at top of accept_loop before ConnectNamedPipeW
- `dlp-agent/src/ipc/pipe3.rs` - Added shutdown check at top of accept_loop and in handle_client inner loop

## Decisions Made

- Followed the plan's specified pattern exactly: check `shutdown_requested()` before `ConnectNamedPipeW`, close pipe handle, return Ok(())
- Pipe3 handle_client has an inner read loop for persistent UI connections; added a second shutdown check there per Task 4 specification
- No deviation from plan required

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None. All three files compiled cleanly on first `cargo check -p dlp-agent` with zero warnings.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- All three IPC pipe servers now respond to shutdown signals
- Plan 65-03 can proceed with watchdog timer integration (fallback for threads still blocked in ConnectNamedPipeW with no client connected)
- Plan 65-04 can proceed with service.rs integration testing

## Known Limitations (Documented in Plan)

The shutdown thread (Plan 65-01's `BlockingThreads::shutdown_and_join`) does NOT have direct access to the pipe handles owned by worker threads. The primary mechanism is:

1. Shutdown thread sets `SHUTDOWN_REQUESTED = true`
2. If a client connects after shutdown, the worker thread sees the flag on the next loop iteration and exits
3. If no client connects, the thread remains blocked until the watchdog (Plan 65-03) forces process exit

This is an acknowledged limitation per the plan's context section. A future improvement would be to share pipe handles with the shutdown thread so it can close them directly (causing `ConnectNamedPipeW` to return `ERROR_OPERATION_ABORTED`), or to switch to overlapped I/O.

---

*Phase: 65-service-stop-blocking-threads-fix*
*Completed: 2026-06-10*
