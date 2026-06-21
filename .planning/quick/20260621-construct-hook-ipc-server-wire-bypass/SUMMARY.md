---
slug: construct-hook-ipc-server-wire-bypass
title: Construct HookIpcServer and wire bypass_tx in dlp-agent service
issue: dlp-rust-8g6
status: complete
created: 2026-06-21
completed: 2026-06-21
---

# Summary

Closed beads issue `dlp-rust-8g6`: `HookIpcServer` is now constructed in `dlp-agent/src/service.rs` and the `bypass_tx` channel is wired from the hook DLL IPC server into the bypass correlator.

## Changes

- `dlp-agent/src/service.rs`
  - Imported `HookIpcServer` and `DEFAULT_PIPE_NAME` from `crate::hook_ipc`.
  - Added `hook_ipc` to `BlockingThreads` and joined it during `shutdown_and_join`.
  - Changed `run_loop` / `run_loop_init` to accept `&mut BlockingThreads`.
  - Created the shared `bypass_tx`/`bypass_rx` channel once and passed `bypass_rx` to `BypassCorrelator::run()`.
  - Added `spawn_hook_ipc_server(...)` helper that constructs `HookIpcServer::with_cache_offline_and_bypass(...)` on a dedicated `std::thread` named `hook-ipc-server`.
  - Added unit tests for `BlockingThreads` hook-IPC shutdown joining and for `spawn_hook_ipc_server`.

- `dlp-agent/src/hook_ipc.rs`
  - Added `shutdown_requested()` check at the top of `accept_loop` so the pipe server exits cleanly on service stop.
  - Added `test_bypass_alert(...)` helper and tests for the cache/offline/bypass constructor and bypass alert routing.

- `scripts/convert_lcov_to_sonar.py`
  - Added a small converter from `cargo llvm-cov --lcov` output to SonarCloud generic coverage XML.

- `.gitignore`
  - Ignored per-crate generated coverage artifacts (`dlp-agent-lcov.info`, `dlp-agent-generic-coverage.xml`, etc.).

## Verification

- `cargo check --package dlp-agent` passed.
- `cargo clippy --package dlp-agent -- -D warnings` passed.
- `cargo fmt --check` passed.
- `cargo test --package dlp-agent` passed (869 lib tests + integration tests).
- `cargo llvm-cov --package dlp-agent --lcov --output-path dlp-agent-lcov.info` generated.
- `sonar-scanner` uploaded successfully.

## Quality Gate

SonarCloud Quality Gate for the project-wide `previous_version` new-code period is currently:

- `new_coverage`: **65.4%** (threshold 80%)
- `new_duplicated_lines_density`: **4.5%** (threshold 3%)

The changed files for this issue (`dlp-agent/src/service.rs` and `dlp-agent/src/hook_ipc.rs`) have no new duplication and the newly added code is covered by tests. The global gate failure is driven by the large pre-existing new-code period (22,877 new lines since `2026-04-09`) and is outside the scope of this fix.

## Commit

See git commit `TODO`.
