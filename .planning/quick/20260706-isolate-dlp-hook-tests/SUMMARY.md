---
phase: quick
plan: 20260706-isolate-dlp-hook-tests
subsystem: testing
tags:
  - rust
  - windows
  - named-pipes
  - test-isolation
  - serial_test
  - integration-tests

requires:
  - phase: 58.5
    provides: dlp-hook-dll unhook protocol and control/background thread lifecycle

provides:
  - Test-only named-pipe override with unique pipe names per test
  - Stoppable MockAgentServer Drop guard with shutdown token
  - reset_for_test() global state reset helper
  - cfg(any(test, feature = "test-helpers")) gated internals for integration tests
  - Heavy tests moved to separate dlp-hook-dll/tests/*.rs binaries
  - run-isolated-tests.ps1/.sh isolation scripts

affects:
  - dlp-hook-dll
  - dlp-agent

tech-stack:
  added:
    - serial_test = "3" (dev-dependency)
    - dlp-agent optional dependency for test-helpers feature
  patterns:
    - "Test-only code gated by cfg(any(test, feature = \"test-helpers\"))"
    - "Drop-guard mock servers that signal blocked named-pipe waits on teardown"
    - "Global reset_for_test() called at the start of every stateful test"
    - "#[serial_test::serial] for tests touching process-global Windows state"

key-files:
  created:
    - dlp-hook-dll/src/test_utils.rs
    - dlp-hook-dll/tests/pipe_client_integration.rs
    - dlp-hook-dll/tests/unhook_protocol.rs
    - dlp-hook-dll/tests/self_unload_safety.rs
    - dlp-hook-dll/tests/control_thread_integration.rs
    - dlp-hook-dll/tests/journal_chaos_test.rs
  modified:
    - dlp-agent/src/hook_ipc.rs
    - dlp-hook-dll/Cargo.toml
    - dlp-hook-dll/scripts/run-isolated-tests.ps1
    - dlp-hook-dll/scripts/run-isolated-tests.sh
    - dlp-hook-dll/src/lib.rs
    - dlp-hook-dll/src/background_thread.rs
    - dlp-hook-dll/src/control_thread.rs
    - dlp-hook-dll/src/trampolines.rs
    - dlp-hook-dll/src/fail_mode.rs
    - dlp-hook-dll/src/perf_telemetry.rs
    - dlp-hook-dll/src/ntdll_patcher.rs
    - dlp-hook-dll/src/hook_journal.rs
    - dlp-hook-dll/src/volume_class_cache.rs
    - dlp-hook-dll/src/diagnostic_ring.rs
    - dlp-hook-dll/src/pipe_client.rs
    - dlp-hook-dll/tests/isolated_resync_recovery.rs
    - dlp-hook-dll/tests/journal_degraded_test.rs
    - dlp-hook-dll/tests/journal_integration.rs

key-decisions:
  - "Used Mutex<Option<&'static str>> + Box::leak for TEST_PIPE_OVERRIDE so current_pipe_name() can return a &'static str without holding a lock on the hot path."
  - "Signaled the shutdown event in the forced background-thread timeout path and leaked the event handle so detached threads exit cleanly instead of busy-looping on a closed handle."

patterns-established:
  - "All production pipe call sites use current_pipe_name(); production compiles to the DEFAULT_PIPE_NAME constant."
  - "Integration tests enable the test-helpers feature and use public test-only re-exports."
  - "Stateful tests acquire PHASE_58_5_TEST_LOCK and call reset_for_test() before exercising global Windows state."

requirements-completed: []

duration: 2h
completed: 2026-07-06
status: complete
---

# Quick Plan: Isolate `dlp-hook-dll` Tests Summary

**Reliable, isolated `dlp-hook-dll` test suite using unique named pipes, a stoppable mock agent server, a global reset helper, and separate integration-test binaries serialized with `serial_test`.**

## Performance

- **Duration:** 2h
- **Started:** 2026-07-06
- **Completed:** 2026-07-06
- **Tasks:** 3
- **Files modified:** 24

## Accomplishments

- Added test-only pipe override so each test can target a unique `\\.\pipe\DlpHookPipeTest_*` endpoint.
- Replaced every production `DEFAULT_PIPE_NAME` call site with `current_pipe_name()` while keeping production code inlined to the constant.
- Built a `MockAgentServer` Drop guard that shuts down cleanly via an `Arc<AtomicBool>` token and a dummy client connection to wake `ConnectNamedPipe`.
- Added `reset_for_test()` that clears `FAIL_STATE`, `NTDLL_PATCHER`, diagnostic ring, LRU, volume-class cache, shared-memory mappings, control/background threads, and pipe mocks.
- Moved heavy integration-style tests from the lib test binary into `dlp-hook-dll/tests/*.rs`.
- Annotated stateful tests with `#[serial_test::serial]` to prevent concurrent mutation of process-global Windows state.
- Updated `run-isolated-tests.ps1` and `run-isolated-tests.sh` to cover all new integration tests and optional `cargo nextest` runs.

## Task Commits

The implementation was already integrated when execution resumed, so the code changes are captured in a single integrated commit rather than three separate task commits:

1. **Task 1: Unique pipe names and override plumbing** — `01e1b179` (feat)
2. **Task 2: Stoppable mock agent server and global reset helper** — `01e1b179` (feat)
3. **Task 3: Move heavy tests out of lib and add `#[serial]`** — `01e1b179` (feat)

**Plan metadata:** `01e1b179` (docs: complete plan)

## Files Created/Modified

- `dlp-agent/src/hook_ipc.rs` — Added optional `shutdown_token` to `HookIpcServer` for clean test teardown.
- `dlp-hook-dll/Cargo.toml` — Added `serial_test` dev-dependency and `dlp-agent` optional dependency for the `test-helpers` feature.
- `dlp-hook-dll/src/lib.rs` — Added `TEST_PIPE_OVERRIDE`, `current_pipe_name()`, `test_utils` module, test-only re-exports, and `#[serial_test::serial]` annotations.
- `dlp-hook-dll/src/test_utils.rs` — New test helpers: `unique_pipe_name`, `set_test_pipe_name`, `reset_for_test`, `MockAgentServer`, `wake_named_pipe`.
- `dlp-hook-dll/src/trampolines.rs` — Replaced `DEFAULT_PIPE_NAME` with `current_pipe_name()`; made `FAIL_STATE` resettable.
- `dlp-hook-dll/src/background_thread.rs` — Widened test gates; fixed forced-timeout path to signal event and avoid detached busy-loop.
- `dlp-hook-dll/src/control_thread.rs`, `fail_mode.rs`, `perf_telemetry.rs`, `ntdll_patcher.rs`, `hook_journal.rs`, `volume_class_cache.rs` — Switched to `current_pipe_name()`; widened test-only visibility.
- `dlp-hook-dll/src/hook_journal.rs` — Added test constructors and re-exports; moved chaos stress test out.
- `dlp-hook-dll/tests/*.rs` — New or updated integration tests with `#[serial_test::serial]` and `reset_for_test()` calls.
- `dlp-hook-dll/scripts/run-isolated-tests.ps1/.sh` — Added the new integration test binaries.

## Decisions Made

- Followed the plan's recommendation to use `Mutex<Option<&'static str>>` and `Box::leak` for the pipe override so `current_pipe_name()` remains lock-free on the hot path.
- Chose to signal and leak the event handle in the forced background-thread timeout path rather than closing it immediately, because closing the handle while a detached thread may still be waiting caused cross-test interference.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed `unhook_all_internal` reading original function pointers with the wrong type**
- **Found during:** Task 2 (unhook protocol integration tests)
- **Issue:** The function read `Option<fn pointer>` storage as `Option<usize>`, misinterpreting memory and writing zero instead of the saved original pointer during IAT restore.
- **Fix:** Read the raw `usize` value and check non-zero before restoring.
- **Files modified:** `dlp-hook-dll/src/lib.rs`
- **Verification:** `cargo test -p dlp-hook-dll --test unhook_protocol -- --test-threads=1` passes.
- **Committed in:** `01e1b179`

**2. [Rule 1 - Bug] Fixed detached background thread busy-loop after forced timeout**
- **Found during:** Final verification run of `cargo test -p dlp-hook-dll --lib -- --test-threads=1`
- **Issue:** The test-only forced-timeout path in `shutdown_background_thread` closed the shutdown event handle before the detached thread observed the signal, leaving it busy-looping on a closed handle and causing `shutdown_background_thread_returns_true_after_clean_start_stop` to fail.
- **Fix:** Signal the event in the forced-timeout path and intentionally leak the handle so the detached thread can wake and exit cleanly.
- **Files modified:** `dlp-hook-dll/src/background_thread.rs`
- **Verification:** Full serial lib test run passes reliably (329 passed, 8 ignored); repeated runs stable.
- **Committed in:** `01e1b179`

**3. [Rule 1 - Bug] Fixed integration tests connecting to a different pipe than the mock server**
- **Found during:** Task 3 (pipe_client_integration tests)
- **Issue:** Tests generated a unique pipe name but `MockAgentServer::start` generated a different one and installed the override after creation, so the trampoline targeted the override while assertions used the original name.
- **Fix:** Tests now read `dlp_hook_dll::current_pipe_name()` after starting the server for assertions.
- **Files modified:** `dlp-hook-dll/tests/pipe_client_integration.rs`
- **Verification:** `cargo test -p dlp-hook-dll --test pipe_client_integration -- --test-threads=1` passes.
- **Committed in:** `01e1b179`

---

**Total deviations:** 3 auto-fixed (all Rule 1 bugs)
**Impact on plan:** All fixes were necessary for test correctness and stability. No scope creep.

## Issues Encountered

- Orphaned `dlp_hook_dll-*.exe` processes from earlier test runs held the test executable open, producing linker error `LNK1104: cannot open file`. Resolved by terminating leftover processes via `wmic process delete` and `Stop-Process` before re-running.
- `cargo test -p dlp-hook-dll --lib -- --test-threads=1` failed deterministically on `shutdown_background_thread_returns_true_after_clean_start_stop` until the forced-timeout busy-loop was fixed (see deviation #2).

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- The `dlp-hook-dll` test suite is now reliable enough to run repeatedly without manual cleanup.
- Ready to resume Phase 58.5/58.6 work or CI integration with `run-isolated-tests.ps1`.

---
*Phase: quick / 20260706-isolate-dlp-hook-tests*
*Completed: 2026-07-06*
