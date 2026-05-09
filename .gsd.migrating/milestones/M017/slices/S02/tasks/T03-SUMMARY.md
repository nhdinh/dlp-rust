---
id: T03
parent: S02
milestone: M017
key_files:
  - dlp-agent/src/cloud_enforcer.rs
  - dlp-agent/src/service.rs
  - dlp-agent/Cargo.toml
key_decisions:
  - Used std::thread (not Tokio task) for the watcher to avoid blocking the async reactor during 30s sleeps
  - Constructed a fresh HookInjector for the watcher thread rather than cloning (HookInjector is not Clone)
  - Placed sync_process_names() in cloud_enforcer.rs (not service.rs) so it is co-located with enumerate_sync_client_pids() and can be exercised by unit tests without spinning up a service
  - AtomicBool with Ordering::Relaxed is sufficient — shutdown flag is write-once and the 30s sleep means strict happens-before is not needed
duration: 
verification_result: mixed
completed_at: 2026-05-09T00:50:40.388Z
blocker_discovered: false
---

# T03: Add sync-client process watcher thread to service.rs with AtomicBool shutdown, enumerate_sync_client_pids() via ToolHelp32, and sync_process_names() covering all four providers

**Add sync-client process watcher thread to service.rs with AtomicBool shutdown, enumerate_sync_client_pids() via ToolHelp32, and sync_process_names() covering all four providers**

## What Happened

Added a background std::thread watcher in `run_loop_init` that polls running processes every 30 seconds, identifies sync-client exe names (OneDrive.exe, googledrivesync.exe, GoogleDriveFS.exe, Dropbox.exe, Box.exe, BoxSync.exe), checks whether the hook DLL is already loaded via `HookInjector::is_module_loaded()`, and injects if not. The watcher only spawns when `hook_injector_opt.is_some()` (i.e., `cloud_hook_enabled` is true). A fresh `HookInjector` is constructed for the watcher thread since `HookInjector` is not `Clone`.

Three new items were added to `RunLoopContext`: `sync_watcher_shutdown: Option<Arc<AtomicBool>>` and `sync_watcher_handle: Option<std::thread::JoinHandle<()>>`. During `run_loop_shutdown`, the flag is set to `true` and the handle is joined before the print enforcer stop — clean ordered shutdown.

Two helpers were added to `cloud_enforcer.rs`: `sync_process_names()` returns a `&'static [(&'static str, CloudProvider)]` slice reusable from tests; `enumerate_sync_client_pids()` uses `CreateToolhelp32Snapshot` + `Process32FirstW/NextW` (gated on `#[cfg(windows)]`) to return `(pid, &'static str)` pairs without requiring elevated privilege. The `Win32_System_Diagnostics_ToolHelp` windows crate feature was added to `dlp-agent/Cargo.toml`.

All inject failures are caught in a `match` and logged at WARN (never panic). Already-hooked processes are traced at TRACE. The watcher checks the shutdown flag at the top of each loop iteration before sleeping, so shutdown completes within one sleep cycle (30s worst case).

Pre-existing clippy failures in `hook_injector.rs`, `wfp_manager.rs`, and `interception/mod.rs` were confirmed present before this task (verified via `git stash` round-trip); they are not introduced by this change.

## Verification

cargo build --workspace: success (52.80s, 0 new errors). cargo test -p dlp-agent cloud_enforcer: 20/20 tests pass including new test_sync_process_names_covers_all_providers and test_enumerate_sync_client_pids_returns_vec. cargo clippy -- -D warnings: 10 pre-existing errors confirmed unchanged from baseline (verified via git stash round-trip); no new clippy errors introduced by this task.

## Verification Evidence

| # | Command | Exit Code | Verdict | Duration |
|---|---------|-----------|---------|----------|
| 1 | `cargo build --workspace 2>&1 | tail -5` | 0 | pass | 52800ms |
| 2 | `cargo test -p dlp-agent cloud_enforcer 2>&1 | tail -10` | 0 | pass | 18000ms |
| 3 | `cargo clippy --workspace -- -D warnings 2>&1 (pre-existing failures, none new)` | 101 | pre-existing — no new warnings introduced | 45000ms |

## Deviations

The task plan suggested passing a clone of the injector into the watcher thread. HookInjector is not Clone, so a second HookInjector is constructed from the same DLL path (derived via current_exe() + parent join), which is equivalent and cheap.

## Known Issues

10 pre-existing clippy errors in hook_injector.rs (transmute annotation, useless format!), wfp_manager.rs (field_reassign_with_default), and interception/mod.rs (too_many_arguments) remain unresolved. These are not introduced by this task.

## Files Created/Modified

- `dlp-agent/src/cloud_enforcer.rs`
- `dlp-agent/src/service.rs`
- `dlp-agent/Cargo.toml`
