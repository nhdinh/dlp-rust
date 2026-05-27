---
phase: 52-dacl-tripwire-repair-watcher-protected-paths-dpapi-recovery-
plan: 02
subsystem: enforcement

tags:
  - ReadDirectoryChangesW
  - crossbeam
  - tokio
  - debounce
  - polling-backstop
  - DACL-repair
  - NTFS-security
  - Windows-API

requires:
  - phase: 52-01
    provides: CanonicalAclSnapshot + apply_tripwire_to_path for repair target
  - phase: 52-04
    provides: DaclStaging data layer for two-phase staged updates

provides:
  - DaclWatcher struct with new/register/unregister lifecycle (WfpManager pattern)
  - Per-path dedicated OS thread running ReadDirectoryChangesW(FILE_NOTIFY_CHANGE_SECURITY, bWatchSubtree=true)
  - crossbeam::channel bounded at 1024 events with drop-oldest backpressure
  - Debounced tokio repair task (500ms-2s window) batching rapid ACL changes
  - 60-second polling backstop with full subtree ACL comparison via GetFileSecurityW + SDDL
  - DaclTamperDetected audit event emission with triggers_alert=true routed to SIEM
  - Service lifecycle integration in run_loop_init/run_loop_shutdown

affects:
  - 52-03
  - 52-05
  - 52-06
  - 52-07

tech-stack:
  added: []
  patterns:
    - "WfpManager lifecycle pattern (new/register/unregister) applied to file-system watcher"
    - "crossbeam channel + dedicated OS thread pattern from process_watcher.rs"
    - "AtomicUsize cast from HANDLE for Send+Sync compatibility"
    - "CloseHandle in unregister to wake blocking ReadDirectoryChangesW"
    - "tokio::time debounce with HashMap<PathBuf, SecurityEvent> accumulation"

key-files:
  created:
    - dlp-agent/src/dacl_repair_watcher.rs — DaclWatcher core module
  modified:
    - dlp-agent/src/lib.rs — added #[cfg(windows)] pub mod dacl_repair_watcher
    - dlp-agent/src/service.rs — RunLoopContext fields, init_dacl_watcher, shutdown logic

key-decisions:
  - "Store directory handle as AtomicUsize (raw pointer cast) to keep WatcherHandle Send+Sync"
  - "Open CreateFileW handle in register() and pass to watcher thread; close in unregister() to wake ReadDirectoryChangesW"
  - "Use 2-second join timeout on unregister to avoid blocking indefinitely when CloseHandle doesn't immediately abort the syscall"
  - "Non-Windows stub: register stores placeholder, check_acl_mismatch returns false, watcher thread spins on sleep"

patterns-established:
  - "HANDLE-as-AtomicUsize: Windows HANDLE (raw pointer) stored as usize in AtomicUsize for Send+Sync structs"
  - "Syscall-abort via handle close: CloseHandle on a directory handle wakes a blocked ReadDirectoryChangesW with ERROR_OPERATION_ABORTED"
  - "Debounced repair: tokio::time::sleep + HashMap accumulation batches rapid events into single repair"

requirements-completed:
  - DACL-02

metrics:
  duration: 45min
  completed: 2026-05-27
---

# Phase 52 Plan 02: DACL Repair Watcher Summary

**DACL repair watcher with per-path ReadDirectoryChangesW threads, crossbeam channel, debounced repair, 60s polling backstop, and DaclTamperDetected SIEM alerts**

## Performance

- **Duration:** 45 min
- **Started:** 2026-05-27T12:00:00Z
- **Completed:** 2026-05-27T12:45:00Z
- **Tasks:** 3
- **Files modified:** 3

## Accomplishments

- DaclWatcher struct with WfpManager-style lifecycle (new/register/unregister/unregister_all)
- Per-path dedicated OS thread calling ReadDirectoryChangesW(FILE_NOTIFY_CHANGE_SECURITY, bWatchSubtree=true)
- crossbeam::channel (capacity 1024) for thread-to-tokio event flow with drop-oldest backpressure
- Debounced tokio repair task with 500ms-2s window batching rapid ACL changes
- 60-second polling backstop walking full subtree and comparing ACLs via GetFileSecurityW + SDDL conversion
- DaclTamperDetected audit event with triggers_alert=true routed to SIEM on repair failure
- Service lifecycle integration: starts after WfpManager, stops before WfpManager unregister
- 14 unit tests covering lifecycle, channel, debounce, backstop detection, subtree coverage, and audit emission

## Task Commits

1. **Task 1: Create dacl_repair_watcher.rs core module** — `d8e6bf0` (feat)
2. **Task 2: Integrate DaclWatcher into service.rs lifecycle** — `58dd9b5` (feat, part of 52-06)
3. **Task 3: Unit tests for dacl_repair_watcher** — included in `d8e6bf0`
4. **Post-execution fixes: test hangs + compiler warnings** — `d860e71` (fix)

## Files Created/Modified

- `dlp-agent/src/dacl_repair_watcher.rs` — DaclWatcher, WatcherHandle, SecurityEvent, DaclWatcherError; register/unregister; repair task; poll backstop; 14 unit tests
- `dlp-agent/src/lib.rs` — Added `#[cfg(windows)] pub mod dacl_repair_watcher;`
- `dlp-agent/src/service.rs` — RunLoopContext fields (dacl_watcher, dacl_watcher_shutdown, dacl_watcher_handle, dacl_poll_handle); init_dacl_watcher helper; shutdown logic

## Decisions Made

- **HANDLE-as-AtomicUsize:** Windows HANDLE is a raw pointer and not Send. We cast to usize and store in AtomicUsize so WatcherHandle can be moved across threads and stored in HashMap inside tokio tasks.
- **CloseHandle to abort ReadDirectoryChangesW:** On unregister, we close the directory handle. This causes ReadDirectoryChangesW to return with ERROR_OPERATION_ABORTED (995), allowing the watcher thread to exit cleanly.
- **2-second join timeout:** In some Windows configurations, CloseHandle does not immediately unblock ReadDirectoryChangesW if there is no pending filesystem activity. A 2-second timeout prevents tests and shutdown from hanging indefinitely.
- **Non-Windows stub:** On non-Windows targets, register stores a placeholder, check_acl_mismatch always returns false, and the watcher thread sleeps in a loop. This allows compilation and basic unit tests on all platforms.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed test hangs caused by blocking thread join in unregister**
- **Found during:** Task 3 (test execution)
- **Issue:** `unregister()` called `handle.thread.join()` while the watcher thread was blocked on `ReadDirectoryChangesW`. Without filesystem activity, the syscall never returned and tests hung indefinitely.
- **Fix:** Restructured `register()` to open the directory handle before spawning the thread, store it in `WatcherHandle.dir_handle` (as AtomicUsize), and close it in `unregister()` to wake the syscall. Added a 2-second join timeout before detaching.
- **Files modified:** `dlp-agent/src/dacl_repair_watcher.rs`
- **Verification:** All 14 tests pass in ~14s (was hanging indefinitely)
- **Committed in:** `d860e71`

**2. [Rule 1 - Bug] Fixed 3 compiler warnings in test code**
- **Found during:** Task 3 (clippy / test compilation)
- **Issue:** `unused import: AtomicUsize`, `unused variable: shutdown_rx`, `unused variable: i` in the `#[cfg(test)]` module.
- **Fix:** Commented out unused import, prefixed variables with underscore.
- **Files modified:** `dlp-agent/src/dacl_repair_watcher.rs`
- **Verification:** `cargo clippy --package dlp-agent -- -D warnings` passes
- **Committed in:** `d860e71`

**3. [Rule 3 - Blocking] Send bound violation on HANDLE in WatcherHandle**
- **Found during:** Task 1 (compilation after handle refactor)
- **Issue:** `WatcherHandle` containing `std::sync::Mutex<HANDLE>` could not be stored in `HashMap` inside a `tokio::spawn` async block because `HANDLE` (raw pointer) is not `Send`.
- **Fix:** Changed `dir_handle` field from `Mutex<HANDLE>` to `AtomicUsize`, storing the raw pointer cast to `usize`. This makes the struct `Send + Sync` while preserving the ability to close the handle.
- **Files modified:** `dlp-agent/src/dacl_repair_watcher.rs`
- **Verification:** `cargo clippy --package dlp-agent -- -D warnings` passes
- **Committed in:** `d860e71`

---

**Total deviations:** 3 auto-fixed (2 bugs, 1 blocking)
**Impact on plan:** All fixes necessary for correctness and testability. No scope creep.

## Issues Encountered

- **ReadDirectoryChangesW blocking behavior:** The Windows API blocks the calling thread until a filesystem event occurs. Closing the handle from another thread aborts the syscall, but the timing is not guaranteed. The 2-second join timeout is a pragmatic workaround.
- **Linker lock on Windows:** Running `cargo test` while a previous test binary is still executing causes `LNK1104: cannot open file`. Resolved by killing lingering processes before re-running tests.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- DaclWatcher is ready for Plan 52-03 (Protected Paths DB integration) to populate `monitored_paths` from the database instead of hardcoded paths.
- Plan 52-05 (Admin TUI Protected Paths screen) can configure paths that feed into DaclWatcher registration.
- Plan 52-07 (Config diff + staging integration) will use `update_snapshot()` after staged ACL changes are applied.

---
*Phase: 52-dacl-tripwire-repair-watcher-protected-paths-dpapi-recovery-*
*Completed: 2026-05-27*
