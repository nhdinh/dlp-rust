---
slug: isolate-dlp-hook-tests
created: 2026-07-06
type: quick
---

# Isolate `dlp-hook-dll` Tests

Fix cross-test interference in `dlp-hook-dll` so the crate's test suite is reliable and no longer leaves stale state behind. All changes are test-only or behind `#[cfg(any(test, feature = "test-helpers"))]`; production code paths must keep using `DEFAULT_PIPE_NAME` and the existing hot-path performance characteristics.

## Goal

Eliminate ordering-dependent failures and named-pipe/global-state collisions in `dlp-hook-dll` tests. After this work:

- Library tests can run with `--test-threads=1` without leaking mock servers or stale pipe listeners.
- Heavy/integration tests run as separate test binaries in `dlp-hook-dll/tests/`.
- Global mutable state (`FAIL_STATE`, `NTDLL_PATCHER`, diagnostic ring, LRU, volume-class cache, shared-memory mappings, control/background threads) is reset at the start of each stateful test.
- Tests that touch exclusive Windows state are serialized with `#[serial_test::serial]`.

## Immediate Workaround Script

Create `dlp-hook-dll/scripts/run-isolated-tests.ps1`. This is the stop-gap that makes the current suite reliable until all code fixes land. It runs the lib tests and the heavy integration tests serially, and optionally runs `cargo nextest` if it is installed.

```powershell
# dlp-hook-dll/scripts/run-isolated-tests.ps1
$ErrorActionPreference = "Stop"

function Run-Test {
    param([string]$Command)
    Write-Host "Running: $Command"
    Invoke-Expression $Command
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed: $Command"
    }
}

# Library tests: serial to avoid pipe/global-state collisions.
Run-Test "cargo test -p dlp-hook-dll --lib -- --test-threads=1"

# Integration tests: each is already a separate process, but still force
# single-threaded execution inside each binary to keep global Windows state sane.
Run-Test "cargo test -p dlp-hook-dll --test isolated_resync_recovery -- --test-threads=1"
Run-Test "cargo test -p dlp-hook-dll --test journal_integration -- --test-threads=1"
Run-Test "cargo test -p dlp-hook-dll --test journal_degraded_test -- --test-threads=1"

# ntdll_chaos_test patches ntdll .text and is #[ignore] by default.
Run-Test "cargo test -p dlp-hook-dll --test ntdll_chaos_test -- --ignored --nocapture --test-threads=1"

# journal_chaos_test will be created/moved as part of this plan.
$journalChaos = "dlp-hook-dll/tests/journal_chaos_test.rs"
if (Test-Path $journalChaos) {
    Run-Test "cargo test -p dlp-hook-dll --test journal_chaos_test -- --test-threads=1"
}

# Optional: process-level isolation via cargo nextest.
if (Get-Command cargo-nextest -ErrorAction SilentlyContinue) {
    Run-Test "cargo nextest run -p dlp-hook-dll --lib"
    Run-Test "cargo nextest run -p dlp-hook-dll --test isolated_resync_recovery"
    Run-Test "cargo nextest run -p dlp-hook-dll --test journal_integration"
    Run-Test "cargo nextest run -p dlp-hook-dll --test journal_degraded_test"
    Run-Test "cargo nextest run -p dlp-hook-dll --test ntdll_chaos_test -- --ignored"
    if (Test-Path $journalChaos) {
        Run-Test "cargo nextest run -p dlp-hook-dll --test journal_chaos_test"
    }
} else {
    Write-Host "cargo-nextest not found; skipping nextest isolation run"
}
```

Also create a Unix equivalent `dlp-hook-dll/scripts/run-isolated-tests.sh` for CI runners if needed:

```bash
#!/usr/bin/env bash
set -euo pipefail

cargo test -p dlp-hook-dll --lib -- --test-threads=1
cargo test -p dlp-hook-dll --test isolated_resync_recovery -- --test-threads=1
cargo test -p dlp-hook-dll --test journal_integration -- --test-threads=1
cargo test -p dlp-hook-dll --test journal_degraded_test -- --test-threads=1
cargo test -p dlp-hook-dll --test ntdll_chaos_test -- --ignored --nocapture --test-threads=1

if [ -f dlp-hook-dll/tests/journal_chaos_test.rs ]; then
    cargo test -p dlp-hook-dll --test journal_chaos_test -- --test-threads=1
fi

if command -v cargo-nextest >/dev/null 2>&1; then
    cargo nextest run -p dlp-hook-dll --lib
    cargo nextest run -p dlp-hook-dll --test isolated_resync_recovery
    cargo nextest run -p dlp-hook-dll --test journal_integration
    cargo nextest run -p dlp-hook-dll --test journal_degraded_test
    cargo nextest run -p dlp-hook-dll --test ntdll_chaos_test -- --ignored
    if [ -f dlp-hook-dll/tests/journal_chaos_test.rs ]; then
        cargo nextest run -p dlp-hook-dll --test journal_chaos_test
    fi
fi
```

## Task 1: Unique Pipe Names and Override Plumbing

**Files to modify:**

- `dlp-hook-dll/src/lib.rs`
- `dlp-hook-dll/src/test_utils.rs` (new file)
- `dlp-hook-dll/src/trampolines.rs`
- `dlp-hook-dll/src/control_thread.rs`
- `dlp-hook-dll/src/fail_mode.rs`
- `dlp-hook-dll/src/perf_telemetry.rs`
- `dlp-hook-dll/src/ntdll_patcher.rs`
- `dlp-hook-dll/src/hook_journal.rs`
- `dlp-hook-dll/src/volume_class_cache.rs`

**Action:**

1. In `dlp-hook-dll/src/lib.rs`, keep `pub(crate) const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\DlpHookPipe";`. Add a test-only override:

   ```rust
   #[cfg(test)]
   static TEST_PIPE_OVERRIDE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
   ```

2. Add `pub fn current_pipe_name() -> &'static str`:
   - In `cfg(test)`: returns `TEST_PIPE_OVERRIDE.get().map(|s| s.as_str()).unwrap_or(DEFAULT_PIPE_NAME)`.
   - In non-test: returns `DEFAULT_PIPE_NAME` (inline/const friendly).

3. Create `dlp-hook-dll/src/test_utils.rs` (gated by `#[cfg(any(test, feature = "test-helpers"))]`) containing:
   - A `static PIPE_COUNTER: AtomicU64`.
   - `pub fn unique_pipe_name(prefix: &str) -> String` that returns `format!(r"\\.\pipe\DlpHookPipeTest_{prefix}_{}_{}", std::process::id(), counter)`.
   - `pub fn set_test_pipe_name(name: &str)` that installs the name into `crate::TEST_PIPE_OVERRIDE`.
   - Re-export `current_pipe_name` from `crate` for convenience.

4. Declare `mod test_utils;` in `dlp-hook-dll/src/lib.rs` under `#[cfg(any(test, feature = "test-helpers"))]` and re-export `unique_pipe_name`, `set_test_pipe_name`, and `current_pipe_name` so integration tests can use them.

5. Replace every production pipe call site that currently uses `crate::DEFAULT_PIPE_NAME` with `crate::current_pipe_name()`. The call sites are:
   - `dlp-hook-dll/src/trampolines.rs`: `classify_and_log_path` (three `classify_path` calls), `classify_and_log_handle`, `record_pipe_round_trip_and_maybe_emit` (`send_health_snapshot`), and the four `send_hash_evidence` calls in `HookWriteFile`, `HookWriteFileEx`, `HookNtWriteFile`, and `NtdllTrampolineNtWriteFile`.
   - `dlp-hook-dll/src/control_thread.rs`: `poll_control` and `send_unhook_ack` calls.
   - `dlp-hook-dll/src/fail_mode.rs`: `send_health_snapshot` call.
   - `dlp-hook-dll/src/perf_telemetry.rs`: `send_health_snapshot` call.
   - `dlp-hook-dll/src/ntdll_patcher.rs`: `send_raw_oneway` call.
   - `dlp-hook-dll/src/hook_journal.rs`: `send_raw_oneway` call.
   - `dlp-hook-dll/src/volume_class_cache.rs`: `send_raw_request` call.

   In non-test builds this must compile to the same constant pipe name, so `current_pipe_name()` must be a trivial inline function or `const` returning `DEFAULT_PIPE_NAME`.

6. Update unit tests in `dlp-hook-dll/src/lib.rs` and `dlp-hook-dll/src/trampolines.rs` that start a mock server to first call `set_test_pipe_name(&unique_pipe_name("..."))` so the server and the trampolines agree on the pipe.

**Verify:**

- `cargo build -p dlp-hook-dll` succeeds with no warnings.
- `cargo test -p dlp-hook-dll --lib -- --test-threads=1` still passes (pipe override is not set for tests that do not need a server).
- A temporary test that starts a mock server on a unique pipe and calls `classify_and_log_path` receives the mock response instead of failing closed.

**Done:**

- No `crate::DEFAULT_PIPE_NAME` literal is passed to a `pipe_client::*` function except through `current_pipe_name()`.
- `unique_pipe_name` is used by every test that spins up a mock agent server.
- Production `DEFAULT_PIPE_NAME` is unchanged.

## Task 2: Stoppable Mock Agent Server and Global Reset Helper

**Files to modify:**

- `dlp-agent/src/hook_ipc.rs`
- `dlp-hook-dll/src/lib.rs`
- `dlp-hook-dll/src/test_utils.rs`
- `dlp-hook-dll/src/trampolines.rs`

**Action:**

1. Make `dlp-agent/src/hook_ipc.rs::HookIpcServer` stoppable from tests:
   - Add a field `shutdown_token: Option<Arc<AtomicBool>>` to `HookIpcServer`.
   - Add builder `pub fn with_shutdown_token(mut self, token: Arc<AtomicBool>) -> Self`.
   - Thread the token into `accept_loop` as an additional parameter.
   - At the top of the `accept_loop` loop, if the token exists and is `true`, close the current pipe handle with `CloseHandle` and return `Ok(())`.

2. In `dlp-hook-dll/src/test_utils.rs`, replace the existing `start_agent_mock_server` helper with a `MockAgentServer` Drop guard:

   ```rust
   pub struct MockAgentServer {
       shutdown: Arc<AtomicBool>,
       thread: Option<std::thread::JoinHandle<()>>,
       pipe_name: String,
   }

   impl MockAgentServer {
       pub fn start(
           handler: Arc<dyn Fn(dlp_common::HookRequest) -> dlp_common::HookResponse + Send + Sync>,
       ) -> Self {
           let pipe_name = unique_pipe_name("mock_agent");
           set_test_pipe_name(&pipe_name);
           let shutdown = Arc::new(AtomicBool::new(false));
           let shutdown_clone = Arc::clone(&shutdown);
           let name = pipe_name.clone();
           let (ready_tx, ready_rx) = std::sync::mpsc::channel();
           let thread = std::thread::spawn(move || {
               let server = dlp_agent::hook_ipc::HookIpcServer::new(name, handler)
                   .with_shutdown_token(shutdown_clone);
               server.run_with_ready(|| {
                   let _ = ready_tx.send(());
               }).unwrap();
           });
           ready_rx.recv_timeout(Duration::from_secs(5)).expect("mock server ready");
           Self { shutdown, thread: Some(thread), pipe_name }
       }
   }

   impl Drop for MockAgentServer {
       fn drop(&mut self) {
           self.shutdown.store(true, Ordering::Relaxed);
           // Wake up the blocked ConnectNamedPipe by connecting a dummy client.
           wake_named_pipe(&self.pipe_name);
           if let Some(t) = self.thread.take() {
               let _ = t.join();
           }
       }
   }
   ```

   Implement `wake_named_pipe(pipe_name: &str)` with a best-effort `CreateFileW` call that immediately closes the handle.

3. Refactor the `FAIL_STATE` static in `dlp-hook-dll/src/trampolines.rs` so it can be reset between tests:
   - Change `static FAIL_STATE: OnceLock<Arc<FailModeState>> = OnceLock::new();` to `static FAIL_STATE: parking_lot::Mutex<Option<Arc<FailModeState>>> = parking_lot::Mutex::new(None);`.
   - Update `get_fail_state()` to read-lock and return the existing `Arc`; if `None`, write-lock, initialize a new `FailModeState`, start the background thread, store it, and return it.
   - Add `#[cfg(test)] pub(crate) fn reset_fail_state_for_test()` that locks `FAIL_STATE`, sets it to `None`, and ensures the background thread is shut down first.

4. In `dlp-hook-dll/src/test_utils.rs`, add a single `pub fn reset_for_test()` that restores a clean baseline:
   - `crate::set_shutting_down_for_test(false)`
   - `crate::reset_hook_globals()`
   - `crate::trampolines::reset_fail_state_for_test()`
   - `crate::perf_telemetry::reset_perf_counters()`
   - `crate::pipe_client::reset_pipe_client_mocks()`
   - `crate::diagnostic_ring::drain_all_snapshots()`
   - `crate::classification_cache::lru::clear_all()`
   - `crate::volume_class_cache::invalidate_cache()`
   - `crate::classification_cache::unmap_cache()`
   - `crate::hook_journal::unmap_journal()`
   - `crate::control_thread::shutdown_control_thread()`
   - `crate::background_thread::reset_background_thread_for_test()`
   - clear `crate::TEST_PIPE_OVERRIDE` (if `OnceLock` cannot be unset, overwrite by setting a sentinel empty string? Prefer a `Mutex<Option<String>>` for override so it can be cleared; update `current_pipe_name()` accordingly).

5. Replace all existing per-test reset blocks in `dlp-hook-dll/src/lib.rs` and `dlp-hook-dll/src/trampolines.rs` with `reset_for_test()` and, where applicable, `let _guard = crate::PHASE_58_5_TEST_LOCK.lock();`.

6. Replace every `_server = start_agent_mock_server(pipe_name, handler)` with `_server = MockAgentServer::start(handler)`.

**Verify:**

- `cargo clippy -p dlp-hook-dll -- -D warnings` passes.
- `cargo test -p dlp-hook-dll --lib -- --test-threads=1` passes and no test hangs waiting for a leaked pipe.
- Running the test suite twice in a row (`cargo test ... && cargo test ...`) produces the same results.

**Done:**

- Mock agent servers shut down when their guard drops.
- `reset_for_test()` exists and is called by every stateful test.
- `FAIL_STATE` is resettable.

## Task 3: Move Heavy Tests Out of the Lib Test Binary and Add `#[serial]`

**Files to modify:**

- `dlp-hook-dll/src/lib.rs`
- `dlp-hook-dll/src/hook_journal.rs`
- `dlp-hook-dll/Cargo.toml`
- `dlp-hook-dll/tests/pipe_client_integration.rs` (new)
- `dlp-hook-dll/tests/unhook_protocol.rs` (new)
- `dlp-hook-dll/tests/self_unload_safety.rs` (new)
- `dlp-hook-dll/tests/control_thread_integration.rs` (new)
- `dlp-hook-dll/tests/journal_chaos_test.rs` (new)

**Action:**

1. Add `serial_test = "3"` to `dlp-hook-dll/Cargo.toml` `[dev-dependencies]` (the same version used elsewhere in the workspace).

2. In `dlp-hook-dll/src/lib.rs`, ensure all helpers needed by integration tests are exported under `feature = "test-helpers"`:
   - `pub use test_utils::{unique_pipe_name, set_test_pipe_name, current_pipe_name, reset_for_test, MockAgentServer};`
   - Existing re-exports for `background_thread`, `hook_journal`, `ntdll_patcher`, `CacheHeader`, `JournalHeader`, etc. remain.

3. Move the following integration-style tests out of the `#[cfg(test)] mod tests` in `dlp-hook-dll/src/lib.rs` into new files under `dlp-hook-dll/tests/`. Each moved test must start with `dlp_hook_dll::reset_for_test()` and be annotated with `#[serial_test::serial]` if it touches global Windows state.

   - `tests/pipe_client_integration.rs`:
     - `pipe_client_connection_refused_when_no_server`
     - `pipe_client_roundtrip_deny`
     - `pipe_client_roundtrip_allow`
     - `hook_createfilew_fail_closed_on_deny`
     - `hook_createfilew_allow_when_allowed`
   - `tests/unhook_protocol.rs`:
     - `unhook_all_is_idempotent`
     - `unhook_all_sets_shutting_down`
     - `unhook_all_unpatches_ntdll_stubs`
     - `unhook_all_unmaps_shared_memory`
     - `unhook_all_infallible_per_stub`
     - `handle_unhook_command_sends_success_ack`
     - `handle_unhook_command_sends_failure_ack`
     - `handle_unhook_command_sends_failure_ack_when_background_thread_times_out`
   - `tests/self_unload_safety.rs`:
     - `self_unload_check_returns_captured_instance_or_none_in_tests`
     - `self_unload_aborts_when_active_calls_remain`
     - `self_unload_aborts_when_dll_instance_not_captured`
     - `unhook_all_drains_active_calls`
   - `tests/control_thread_integration.rs`:
     - `control_poll_thread_starts_from_post_attach_path`
     - `control_poll_thread_triggers_after_grace_and_failures`
     - `control_poll_thread_resets_on_success`
     - `control_poll_thread_handles_unhook_command`
     - `start_dlp_control_thread_export_is_reachable`
     - `start_dlp_control_thread_starts_thread_and_is_idempotent`

4. The following heavy tests already live in `dlp-hook-dll/tests/` and should be annotated with `#[serial_test::serial]` where they mutate shared Windows state:
   - `tests/isolated_resync_recovery.rs`: annotate mapping-creation tests (`isolated_to_resync_via_background_thread`, `full_cycle_end_to_end`, `cross_crate_checksum_validation`, `odd_version_during_rebuild_ignored`, `in_flight_decision_uses_old_cache`).
   - `tests/journal_degraded_test.rs`: annotate `test_journal_degraded_alert_pipe_send`.
   - `tests/journal_integration.rs`: annotate Windows-specific shared-memory tests.
   - `tests/ntdll_chaos_test.rs`: `ntdll_chaos_test` is already `#[ignore]`; the smoke test does not need serialization.

5. Move the concurrency stress test `test_concurrent_read_and_unmap_no_deadlock` from `dlp-hook-dll/src/hook_journal.rs` into a new `dlp-hook-dll/tests/journal_chaos_test.rs`. Re-export `JournalHeader`, `JournalEntry`, `HookJournal`, `set_journal_for_test`, `unmap_journal`, `is_journal_mapped`, and the cleanup helper from `dlp-hook-dll` under `feature = "test-helpers"` if they are not already accessible. Annotate the moved test with `#[serial_test::serial]`.

6. Inside the remaining `dlp-hook-dll/src/lib.rs` unit tests, annotate any test that mutates global state with `#[serial_test::serial]`. In practice this means all tests that acquire `PHASE_58_5_TEST_LOCK` or start mock servers/control threads.

**Verify:**

- `cargo test -p dlp-hook-dll --lib -- --test-threads=1` passes.
- Each new integration test file passes when run individually, e.g. `cargo test -p dlp-hook-dll --test pipe_client_integration -- --test-threads=1`.
- Running all `dlp-hook-dll` tests with `cargo test -p dlp-hook-dll -- --test-threads=1` passes.
- `cargo fmt --check` and `cargo clippy -p dlp-hook-dll -- -D warnings` pass.

**Done:**

- Heavy tests are in `dlp-hook-dll/tests/` and run as separate binaries.
- Stateful tests are annotated with `#[serial_test::serial]`.
- No integration test logic remains in the lib test binary except pure unit tests.

## Dependencies to Update

- `dlp-hook-dll/Cargo.toml`:
  - Add `serial_test = "3"` to `[dev-dependencies]`.
- `dlp-agent/Cargo.toml`: no new dependencies. The shutdown-token change uses `std::sync::{Arc, AtomicBool}`.

## Verification Checklist

Run these before considering the task complete:

1. `cargo fmt --check`
2. `cargo clippy -p dlp-hook-dll -- -D warnings`
3. `cargo test -p dlp-hook-dll --lib -- --test-threads=1`
4. `cargo test -p dlp-hook-dll --test pipe_client_integration -- --test-threads=1`
5. `cargo test -p dlp-hook-dll --test unhook_protocol -- --test-threads=1`
6. `cargo test -p dlp-hook-dll --test self_unload_safety -- --test-threads=1`
7. `cargo test -p dlp-hook-dll --test control_thread_integration -- --test-threads=1`
8. `cargo test -p dlp-hook-dll --test isolated_resync_recovery -- --test-threads=1`
9. `cargo test -p dlp-hook-dll --test journal_integration -- --test-threads=1`
10. `cargo test -p dlp-hook-dll --test journal_degraded_test -- --test-threads=1`
11. `cargo test -p dlp-hook-dll --test ntdll_chaos_test -- --ignored --nocapture --test-threads=1`
12. `cargo test -p dlp-hook-dll --test journal_chaos_test -- --test-threads=1`
13. On Windows: `powershell -ExecutionPolicy Bypass -File dlp-hook-dll/scripts/run-isolated-tests.ps1`
14. (Optional) `cargo nextest run -p dlp-hook-dll --lib` and the per-test integration commands if `cargo-nextest` is installed.

## Success Criteria

- `cargo test -p dlp-hook-dll --lib -- --test-threads=1` passes reliably across repeated runs.
- The `run-isolated-tests.ps1` script exists and runs the full suite successfully.
- Every mock agent server started in a test is stopped when the test ends (Drop guard).
- Every test that mutates process-global state calls `reset_for_test()` at the start.
- No two stateful tests run concurrently (use `#[serial_test::serial]`).
- Heavy tests live in `dlp-hook-dll/tests/` rather than inside the lib test binary.
- Production code still uses `DEFAULT_PIPE_NAME` and is not affected by test-only overrides.
