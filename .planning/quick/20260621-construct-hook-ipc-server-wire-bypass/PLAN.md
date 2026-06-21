---
slug: construct-hook-ipc-server-wire-bypass
title: Construct HookIpcServer and wire bypass_tx in dlp-agent service
issue: dlp-rust-8g6
status: in-progress
created: 2026-06-21
---

# Objective

Close issue dlp-rust-8g6: the v0.10.0 milestone audit found that `HookIpcServer` is never constructed in `dlp-agent/src/service.rs`, and the `bypass_tx` sender for ntdll/ETW BypassAlerts is discarded. This breaks the real-time hook DLL → agent → SIEM bypass alert pipeline.

# Changes

1. **service.rs imports**: add `HookIpcServer` and `DEFAULT_PIPE_NAME` from `crate::hook_ipc`.
2. **BlockingThreads**: add `hook_ipc: Option<std::thread::JoinHandle<()>>` field and include it in `shutdown_and_join`.
3. **run_loop/run_loop_init signature**: accept `&mut BlockingThreads` so the hook IPC thread handle can be registered with the blocking-thread shutdown group.
4. **bypass channel**: create the unbounded `crossbeam_channel` once, early enough to be shared by `HookIpcServer` and the bypass correlator.
5. **HookIpcServer construction**: after `OfflineManager` is initialized, construct `HookIpcServer::with_cache_offline_and_bypass(...)` with `classification_cache`, `offline`, and `bypass_tx`; spawn on a dedicated `std::thread` and store the handle.
6. **Correlator wiring**: pass the existing `bypass_rx` receiver to `BypassCorrelator::run()` instead of creating a new channel.
7. **hook_ipc.rs shutdown**: add `shutdown_requested()` check at the top of `accept_loop`, matching the existing IPC pipe server pattern (`pipe1.rs`).
8. **Tests**: add/update tests covering the new construction path and bypass alert routing from service initialization.

# Verification

- `cargo check --workspace`
- `cargo clippy --workspace -- -D warnings`
- `cargo fmt --check`
- `cargo test --workspace --lib hook_ipc service bypass_correlator`
- `sonar-scanner` (if SONAR_TOKEN is available)
