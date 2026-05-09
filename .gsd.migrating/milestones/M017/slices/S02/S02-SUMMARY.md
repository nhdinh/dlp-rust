---
id: S02
parent: M017
milestone: M017
provides:
  - ["resolve_sync_paths() — registry-driven sync folder path discovery for OneDrive/GDrive/Dropbox/Box with %USERPROFILE% fallback", "CloudEnforcer::check() with explicit Classification parameter — ABAC-wired cloud upload enforcement", "sync-client process watcher thread — background 30s poll that injects hook DLL into discovered sync client processes", "sync_process_names() + enumerate_sync_client_pids() — testable helpers for process discovery", "Action::CLOUD_UPLOAD ABAC variant wired end-to-end"]
requires:
  - slice: S01
    provides: HookInjector::inject(pid) and is_module_loaded(pid, name) — consumed by sync-client watcher in service.rs
  - slice: S01
    provides: Named pipe protocol — classification requests for cloud uploads via interception/mod.rs
affects:
  - ["S03 — can now call resolve_sync_paths() (pub) to discover sync folders for share-link scope; stricter ABAC context for sync-folder files is in place", "S05 — cloud upload interception end-to-end is verified at contract level; live sync client smoke test remains for S05 UAT"]
key_files:
  - ["dlp-agent/src/cloud_enforcer.rs", "dlp-agent/src/interception/mod.rs", "dlp-agent/src/service.rs", "dlp-agent/tests/comprehensive.rs", "dlp-agent/Cargo.toml"]
key_decisions:
  - ["CloudEnforcer::check() takes explicit Classification — interception layer owns resolution, enforcer only enforces", "with_paths(Vec<String>) preserved for backward compat — strings wrapped internally as OneDrive/Fallback SyncPath", "sync_process_names() placed in cloud_enforcer.rs (not service.rs) for unit testability without spinning up service", "std::thread (not tokio task) for watcher — avoids blocking async reactor during 30s sleep", "Fresh HookInjector constructed in watcher thread — HookInjector is not Clone", "AtomicBool Ordering::Relaxed for shutdown flag — write-once, 30s sleep granularity makes strict ordering unnecessary", "fail-open on ABAC evaluator errors in cloud check path — log path_hash + error at ERROR, return Allow to avoid blocking legitimate I/O"]
patterns_established:
  - ["Classification passed explicitly to enforcers rather than resolved internally — auditable at call site", "push_missing_fallbacks() ensures all providers always have a path entry even when registry is empty", "fnv1a_hex() private helper for non-sensitive path hashing in structured logs — avoids logging raw paths", "enumerate_sync_client_pids() + sync_process_names() separation — names list is static/testable, PID scan is Windows-gated"]
observability_surfaces:
  - ["tracing::info! logs each provider's resolved path or fallback reason during CloudEnforcer::new()", "tracing::warn! on failed registry key opens (provider name + error code)", "tracing::warn! on inject failures in watcher (pid + exe + error)", "tracing::trace! on already-hooked processes and on ALLOW cloud check events", "tracing::error! on ABAC classification errors in cloud check path (path_hash + error)"]
drill_down_paths:
  []
duration: ""
verification_result: passed
completed_at: 2026-05-09T00:54:33.036Z
blocker_discovered: false
---

# S02: Cloud Sync Interception

**Registry-driven sync path discovery, explicit ABAC classification wiring in CloudEnforcer, and background sync-client process watcher with hook injection for all four cloud providers.**

## What Happened

S02 replaced the placeholder cloud interception plumbing from S01 with production-quality components across three tasks.

**T01 — Registry-based sync path discovery:** Added `CloudProvider`, `PathSource`, and `SyncPath` types to `cloud_enforcer.rs`. `resolve_sync_paths(user_sid)` probes `HKEY_USERS\{SID}\SOFTWARE\...` for OneDrive (personal + business via account subkey enumeration), Google Drive (DriveFS + legacy), Dropbox, and Box. Both `REG_SZ` and `REG_EXPAND_SZ` values are handled; RAII `RegKey` guards prevent handle leaks. `push_missing_fallbacks()` ensures every provider has at least one `%USERPROFILE%`-based entry when the registry yields nothing. `active_user_sid()` resolves the current user via WTS → LookupAccountNameW → ConvertSidToStringSidW, falling back to HKEY_USERS enumeration in Session 0 (service boot). `with_paths(Vec<String>)` was preserved unchanged to keep the 11+ pre-existing tests passing; `with_sync_paths(Vec<SyncPath>)` was added for typed test construction. `detect_sync_provider()` now iterates over typed `Vec<SyncPath>` instead of substring matching. Three clippy lints fixed: `manual_strip`, manual `find` → `.find()`, and `Default` derive. 17 tests passed after T01.

**T02 — Explicit ABAC classification wiring:** `CloudEnforcer::check()` signature changed from `(path, action)` to `(path, action, classification: Classification)`. `provisional_sync_classification()` was deleted entirely. The block condition uses `classification >= Classification::T3` via `PartialOrd`. In `interception/mod.rs`, classification is resolved via `PolicyMapper::provisional_classification(&path)` before the cloud check call, with a private `fnv1a_hex()` helper for non-sensitive path hashing in TRACE logs. All 18 unit tests and TC-30..TC-33 in `comprehensive.rs` were updated to pass explicit `Classification` values. One additional test (`test_t2_file_in_sync_folder_returns_none`) was added to explicitly cover the T2 allow path. ALLOW branch log level was changed from INFO to TRACE to reduce noise. 18 unit tests + 4 integration tests passed after T02.

**T03 — Sync-client process watcher:** A background `std::thread` watcher (not tokio task, to avoid blocking the reactor on 30s sleep) was added to `run_loop_init` in `service.rs`. It discovers sync-client PIDs using `CreateToolhelp32Snapshot` + `Process32FirstW/NextW` (via `enumerate_sync_client_pids()` in `cloud_enforcer.rs`), checks hook DLL load status via `HookInjector::is_module_loaded()`, and injects if not. Shutdown uses `Arc<AtomicBool>` with `Ordering::Relaxed` (write-once, 30s granularity). `RunLoopContext` gains `sync_watcher_shutdown` and `sync_watcher_handle`; `run_loop_shutdown` joins the thread before stopping the print enforcer. `sync_process_names()` lives in `cloud_enforcer.rs` for unit testability. The `Win32_System_Diagnostics_ToolHelp` windows crate feature was added to `Cargo.toml`. 20/20 cloud_enforcer tests pass including two new watcher unit tests. Workspace build clean.

## Verification

- `cargo test -p dlp-agent --test comprehensive -- cloud_tc`: 4 passed (TC-30, TC-31, TC-32, TC-33), 0 failed, exit 0
- `cargo test -p dlp-agent cloud_enforcer`: 20 tests pass across cloud_enforcer module (unit tests in lib), exit 0
- `cargo build --workspace`: success, exit 0 (1 pre-existing dead_code warning in dlp-hook-dll, not introduced by this slice)
- Pre-existing clippy failures (10 errors in hook_injector.rs, wfp_manager.rs, interception/mod.rs) confirmed unchanged via git stash round-trip — none introduced by this slice

## Requirements Advanced

- R001 — S02 delivers dynamic registry-based sync path discovery and real ABAC classification wiring in CloudEnforcer::check(), completing the integration left pending after S01. TC-30..TC-33 now exercise the full enforcement path with explicit classification values.

## Requirements Validated

None.

## New Requirements Surfaced

None.

## Requirements Invalidated or Re-scoped

None.

## Operational Readiness

None.

## Deviations

T02: Added one extra test (test_t2_file_in_sync_folder_returns_none) beyond the 11 specified to explicitly cover T2 allow path. Changed ALLOW branch log from INFO to TRACE. Test paths cleaned of embedded classification keywords.

T03: HookInjector is not Clone — fresh injector constructed from DLL path rather than cloning, which is equivalent and cheap.

## Known Limitations

10 pre-existing clippy errors in hook_injector.rs (transmute annotation, useless format!), wfp_manager.rs (field_reassign_with_default), and interception/mod.rs (too_many_arguments) remain unresolved — not introduced by this slice. Live sync client injection (hooking a running OneDrive/GDrive/Dropbox/Box process) requires manual smoke test; it is out of automated scope for this slice and deferred to S05 UAT.

## Follow-ups

S03 can immediately consume resolve_sync_paths() for share-link detection scope. S05 must include a live smoke test: copy T4 file to a monitored sync folder and verify the block toast appears before the sync client uploads it.

## Files Created/Modified

- `dlp-agent/src/cloud_enforcer.rs` — Added CloudProvider/PathSource/SyncPath types, resolve_sync_paths(), active_user_sid(), enumerate_sync_client_pids(), sync_process_names(); updated check() signature; removed provisional_sync_classification()
- `dlp-agent/src/interception/mod.rs` — Added classification resolution via PolicyMapper before cloud check; added fnv1a_hex() helper; updated check() call site
- `dlp-agent/src/service.rs` — Added sync-client watcher thread with AtomicBool shutdown to run_loop_init/run_loop_shutdown; updated RunLoopContext
- `dlp-agent/tests/comprehensive.rs` — Updated TC-30..TC-33 to pass explicit Classification values
- `dlp-agent/Cargo.toml` — Added Win32_System_Diagnostics_ToolHelp windows crate feature
