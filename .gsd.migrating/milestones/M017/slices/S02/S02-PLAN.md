# S02: Cloud Sync Interception

**Goal:** Replace placeholder sync paths and heuristic classification in CloudEnforcer with registry-based dynamic path discovery and real ABAC classification; add a sync-client process watcher that injects the hook DLL into OneDrive/GDrive/Dropbox/Box processes.
**Demo:** Copy a T4 file to Dropbox → blocked with user toast. Copy a T1 file → allowed. Works for all four providers (OneDrive, GDrive, Dropbox, Box).

## Must-Haves

- `resolve_sync_paths()` returns correct `SyncPath` entries for each provider by reading `HKEY_USERS\{SID}\SOFTWARE\...` (with fallback to `%USERPROFILE%` defaults when registry key absent)
- `CloudEnforcer::check()` accepts an explicit `Classification` parameter; `provisional_sync_classification()` is deleted
- `interception/mod.rs` resolves classification via `AbacEvaluator` before calling `enforcer.check()`
- A background 30s watcher loop in `service.rs` discovers sync-client PIDs and calls `HookInjector::inject(pid)` for unhooked processes
- `cargo test -p dlp-agent cloud_enforcer` passes (11 unit tests updated to pass explicit `Classification`)
- `cargo test -p dlp-agent --test comprehensive -- cloud_tc` passes (TC-30..TC-33 updated)
- `cargo build --workspace` clean with no warnings
- `cargo clippy --workspace -- -D warnings` clean

## Proof Level

- This slice proves: Contract-level proof: registry discovery and ABAC wiring verified by unit tests with injected fixtures; process watcher verified by unit test with mock process list. Live sync client injection requires manual smoke test (out of automated scope for this slice).

## Integration Closure

Upstream consumed: `HookInjector::inject(pid)` and `is_module_loaded(pid, name)` from S01; `AbacEvaluator` already in interception event loop scope; SID string from `session_map.resolve_for_path()`. New wiring: sync-process watcher background task spawned in `run_loop_init` alongside `HookInjector`; `CloudEnforcer::check()` signature updated to accept `Classification`. What remains: S03 builds share-link detection on top of `resolve_sync_paths()` (already pub after this slice); S05 runs end-to-end UAT against live sync clients.

## Verification

- Registry discovery logs each provider's resolved path (or fallback reason) at INFO level via `tracing::info!`. Watcher loop logs injection attempts with pid, exe name, and success/failure. Failed registry opens log provider name + error code at WARN level. ABAC classification errors in the cloud check path log path_hash + error at ERROR level and fail-open (allow) to avoid blocking legitimate I/O on evaluator bugs.

## Tasks

- [x] **T01: Implement resolve_sync_paths() with registry discovery and fallback** `est:2h`
  Add `SyncPath`, `CloudProvider`, and `PathSource` types to `cloud_enforcer.rs`. Implement `pub fn resolve_sync_paths(user_sid: &str) -> Vec<SyncPath>` that reads sync folder locations from `HKEY_USERS\{SID}\SOFTWARE\...` for all four providers (OneDrive personal+business, Google Drive+DriveFS, Dropbox, Box), with `%USERPROFILE%`-based fallbacks when registry keys are absent. Update `CloudEnforcer::new()` to call `resolve_sync_paths()` using the current user's SID (enumerate active sessions via `WTSEnumerateSessions`/`LsaEnumerateLoggedOnUsers` or use the well-known session 1 SID). Update `detect_sync_provider()` to use `SyncPath.provider` field instead of substring heuristic.
  - Files: `dlp-agent/src/cloud_enforcer.rs`, `dlp-agent/Cargo.toml`
  - Verify: cargo test -p dlp-agent cloud_enforcer 2>&1 | tail -5

- [x] **T02: Wire real ABAC classification into CloudEnforcer::check() and update all call sites** `est:1.5h`
  Replace `provisional_sync_classification()` with an explicit `Classification` parameter on `check()`. Update `interception/mod.rs` to resolve classification via `AbacEvaluator` before calling `enforcer.check()`. Update all test call sites (11 unit tests in `cloud_enforcer.rs`, TC-30..TC-33 in `comprehensive.rs`) to pass explicit `Classification` values.
  - Files: `dlp-agent/src/cloud_enforcer.rs`, `dlp-agent/src/interception/mod.rs`, `dlp-agent/tests/comprehensive.rs`
  - Verify: cargo test -p dlp-agent cloud_enforcer && cargo test -p dlp-agent --test comprehensive -- cloud_tc 2>&1 | tail -10

- [x] **T03: Add sync-client process watcher loop to service.rs** `est:1.5h`
  Add a background watcher loop in `service.rs` that periodically discovers sync-client processes by exe name, checks if the hook DLL is loaded (via `HookInjector::is_module_loaded()`), and injects if not. Wire it into the existing `run_loop_init` / `run_loop_shutdown` lifecycle. Add `Win32_System_Diagnostics_ToolHelp` feature to `dlp-agent/Cargo.toml`.
  - Files: `dlp-agent/src/service.rs`, `dlp-agent/src/cloud_enforcer.rs`, `dlp-agent/Cargo.toml`
  - Verify: cargo build --workspace 2>&1 | tail -5 && cargo test -p dlp-agent cloud_enforcer 2>&1 | tail -5 && cargo clippy --workspace -- -D warnings 2>&1 | tail -10

## Files Likely Touched

- dlp-agent/src/cloud_enforcer.rs
- dlp-agent/Cargo.toml
- dlp-agent/src/interception/mod.rs
- dlp-agent/tests/comprehensive.rs
- dlp-agent/src/service.rs
