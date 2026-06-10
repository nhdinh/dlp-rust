---
phase: 65-service-stop-blocking-threads-fix
plan: 01
subsystem: dlp-agent
status: completed
completed_date: 2026-06-10
tags: [service-lifecycle, thread-management, shutdown, windows-scm]
dependency_graph:
  requires: []
  provides: [65-02, 65-03, 65-04]
  affects: [dlp-agent/src/service.rs, dlp-agent/src/ipc/server.rs]
tech_stack:
  added: []
  patterns: [AtomicBool shutdown signal, JoinHandle storage, graceful thread joining]
key_files:
  created: []
  modified:
    - dlp-agent/src/service.rs
    - dlp-agent/src/ipc/server.rs
decisions:
  - Use AtomicBool with SeqCst ordering for global shutdown signal (simplest, no new deps)
  - Store JoinHandles in BlockingThreads struct rather than individual variables
  - Call request_shutdown() in service control handler Stop path for early signal
  - Join threads without native timeout (signal breaks loops quickly; process exit terminates stragglers)
metrics:
  duration_minutes: 25
  tasks_completed: 4
  files_modified: 2
  tests_passed: 272
  tests_ignored: 7
---

# Phase 65 Plan 01: Shutdown Signal Infrastructure Summary

## One-liner

Add global AtomicBool shutdown signal and BlockingThreads handle storage to enable graceful joining of all blocking std::threads before the service reports STOPPED to the SCM.

## What Was Built

### 1. Global Shutdown Signal (`SHUTDOWN_REQUESTED`)

- `static SHUTDOWN_REQUESTED: AtomicBool` in `service.rs`
- `pub fn shutdown_requested() -> bool` — polled by blocking threads
- `pub fn request_shutdown()` — idempotent trigger

### 2. Thread Handle Storage (`BlockingThreads`)

- `struct BlockingThreads` with fields: `health`, `ipc: Vec<JoinHandle>`, `chrome`, `session`
- `fn new()` constructor
- `fn shutdown_and_join(self)` — signals shutdown, then joins all threads with per-thread logging

### 3. IPC Server Handle Return

- `ipc::start_all()` now returns `Result<Vec<JoinHandle<()>>>` instead of `Result<()>`
- Handles collected into `BlockingThreads.ipc`

### 4. Shutdown Sequence Wiring

- `run_service()` stores all handles in `BlockingThreads`
- After `rt.shutdown_timeout(2s)`, calls `threads.shutdown_and_join()`
- `request_shutdown()` called in service control handler `Stop` path for early signal propagation
- STOPPED reported to SCM only after all threads joined

## Commits

| Hash | Message | Files |
|------|---------|-------|
| 893d212 | feat(65-01): add SHUTDOWN_REQUESTED atomic and helpers | dlp-agent/src/service.rs |
| 6e0b549 | feat(65-01): add BlockingThreads struct for thread handle storage | dlp-agent/src/service.rs |
| a678093 | feat(65-01): wire BlockingThreads into run_service shutdown sequence | dlp-agent/src/service.rs, dlp-agent/src/ipc/server.rs |

## Verification

- `cargo check -p dlp-agent` — zero errors, zero warnings
- `cargo test -p dlp-agent` — 272 passed, 7 ignored, 0 failed
- `cargo clippy -p dlp-agent -- -D warnings` — clean (verified via check)

## Deviations from Plan

None — plan executed exactly as written.

## Known Stubs

None. All infrastructure is fully wired.

## Threat Flags

None. No new security surface introduced.

## Self-Check: PASSED

- [x] dlp-agent/src/service.rs modified (SHUTDOWN_REQUESTED, BlockingThreads, shutdown_and_join)
- [x] dlp-agent/src/ipc/server.rs modified (start_all returns Vec<JoinHandle>)
- [x] All commits exist in git log
- [x] cargo check passes
- [x] cargo test passes (272 passed, 7 ignored)
