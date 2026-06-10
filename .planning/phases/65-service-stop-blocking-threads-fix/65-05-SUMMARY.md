---
plan: 65-05
phase: 65-service-stop-blocking-threads-fix
status: complete
gap_closure: true
---

## Summary

Fixed 5 verification gaps found in the initial Phase 65 execution.

## Gaps Fixed

1. **Watchdog timer added** — `BlockingThreads::shutdown_and_join` now spawns a watchdog thread that sleeps for `SHUTDOWN_TIMEOUT * 4 + 5s` (45s) and calls `std::process::exit(1)` if threads are still blocked. Prevents indefinite `StopPending` hangs.

2. **Ordering fixed to Acquire/Release** — Changed `SHUTDOWN_REQUESTED` operations from `SeqCst` to `Acquire` (load) and `Release` (store) as required by reviewers and project standards.

3. **unwrap() removed** — Replaced `.unwrap()` on `Option<JoinHandle>` thread ID logging with `if let Some(ref h)` pattern. No panics in shutdown code.

4. **Per-thread elapsed logging added** — `join_with_log` now logs per-thread join duration via `debug!` macro for operational diagnostics.

5. **reset_shutdown_signal() at startup** — Called at the start of `run_service()` with comment explaining in-process restart support. Removed `#[cfg(test)]` guard since it's now needed in production.

6. **Test race condition fixed** — Added `SHUTDOWN_TEST_MUTEX` to serialize tests that mutate the global `SHUTDOWN_REQUESTED` static, preventing non-deterministic failures under parallel test execution.

## Commits

- `9678260`: fix(65-05): add watchdog timer, Acquire/Release ordering, remove unwrap, per-thread logging, reset at startup

## Verification

- `cargo check -p dlp-agent`: zero warnings
- `cargo clippy -p dlp-agent -- -D warnings`: clean
- `cargo test -p dlp-agent`: 772 passed, 0 failed

## Key Files

- `dlp-agent/src/service.rs` — All fixes in one file
