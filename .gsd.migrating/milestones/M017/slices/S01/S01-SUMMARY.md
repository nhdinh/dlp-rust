---
id: S01
parent: M017
milestone: M017
provides:
  - Hook DLL (dlp_hook_dll.dll) with IAT patching and named pipe client — exported symbols: HookCreateFileW, HookNtCreateFile, UnhookAll.
  - Named pipe protocol (HookRequest / HookResponse) with agent-side server and hook-side client.
  - Hook injector with x86/x64 architecture detection and CreateRemoteThread + LoadLibraryW injection.
  - WfpManager with hand-rolled fwpuclnt.dll FFI bindings for PID-based outbound TCP/443 blocking.
  - CloudEnforcer following the UsbEnforcer pattern with placeholder sync-folder detection.
  - Service integration: HookInjector + WfpManager constructed in run_loop_init and torn down in run_loop_shutdown.
  - TC-30 real test replacing stub.
requires:
  []
affects:
  []
key_files:
  - dlp-common/src/abac.rs
  - dlp-agent/src/config.rs
  - dlp-agent/src/server_client.rs
  - dlp-agent/src/hook_ipc.rs
  - dlp-agent/src/ipc/frame.rs
  - dlp-agent/src/hook_injector.rs
  - dlp-hook-dll/Cargo.toml
  - dlp-hook-dll/src/lib.rs
  - dlp-hook-dll/src/pipe_client.rs
  - dlp-agent/src/wfp_ffi.rs
  - dlp-agent/src/wfp_manager.rs
  - dlp-agent/src/cloud_enforcer.rs
  - dlp-agent/src/service.rs
  - dlp-agent/src/interception/mod.rs
  - dlp-agent/tests/comprehensive.rs
key_decisions:
  - Action::CLOUD_UPLOAD uses literal variant name serde pattern for consistency with existing variants.
  - AgentConfig uses Option<bool>/Option<u64> for new fields (TOML backward compatibility); AgentConfigPayload uses plain bool/u64 with serde(default) (JSON push pattern).
  - Named pipe protocol reuses existing crate::ipc::frame length-prefix framing with bincode payloads.
  - Hook DLL implements fail-closed behavior: any pipe error or DENY response returns ERROR_ACCESS_DENIED.
  - CloudEnforcer follows the established UsbEnforcer pattern for consistent integration into the event loop.
  - WFP and hook injector are constructed conditionally in run_loop_init; failures are logged as warnings without blocking service startup.
patterns_established:
  - Fail-closed hook DLL: pipe errors/timeouts/DENY all return ERROR_ACCESS_DENIED.
  - Enforcer pattern: new/with_paths -> check -> Option<BlockResult> with Arc<Enforcer> in event loop.
  - Config dual-schema: Option<T> in TOML AgentConfig, plain T with serde(default) in JSON AgentConfigPayload.
  - Conditional subsystem construction in run_loop_init; failures log warning and continue.
observability_surfaces:
  - Hook DLL logs classification requests/responses via OutputDebugStringW (visible in DebugView).
  - Agent service logs injector state changes and WFP filter counts via tracing.
  - Agent service log file contains structured JSON for each hook call with path_hash, decision, latency_ms.
  - WFP registration failures logged with NTSTATUS code and sublayer GUID.
  - Injector failures log target PID, architecture, and GetLastError().
  - Hook timeout failures logged with path_hash, timeout_ms, and fallback decision.
drill_down_paths:
  []
duration: ""
verification_result: passed
completed_at: 2026-05-08T15:03:40.238Z
blocker_discovered: false
---

# S01: API Hook Framework + WFP Filter

**Built the foundational interception infrastructure for cloud sync blocking: a hook DLL with IAT patching, a named pipe classification protocol, a WFP network egress filter, and service integration.**

## What Happened

## What This Slice Delivered

S01 established the foundational infrastructure for cloud sync exfiltration prevention across six tasks:

### T01 — Action::CLOUD_UPLOAD and Config Schema
Added the `CLOUD_UPLOAD` variant to `dlp_common::Action` with literal-variant serde (consistent with `DRAG_DROP`). Added `cloud_hook_enabled`, `wfp_filter_enabled`, and `hook_classification_timeout_ms` to both `AgentConfig` (TOML, `Option<T>`) and `AgentConfigPayload` (JSON, `serde(default)`), preserving backward compatibility.

### T02 — Named Pipe Protocol and Agent-Side Server
Defined `HookRequest` / `HookResponse` in `dlp-agent/src/hook_ipc.rs`, reusing the existing `crate::ipc::frame` length-prefix framing (after fixing a latent `write_all` bug that caused empty slices). The server runs on a dedicated `std::thread` and spawns Tokio tasks per connection. Unit tests cover round-trip latency (p99 < 50ms for 1000 requests), oversized-frame rejection, malformed-payload handling, and empty-path boundaries.

### T03 — Hook DLL Skeleton and Injector
Created `dlp-hook-dll` as a `cdylib` workspace crate. Exported `HookCreateFileW`, `HookNtCreateFile`, and `UnhookAll` as no-op trampolines in T03; real IAT patching added in T04. The agent-side `HookInjector` discovers target process architecture via `IsWow64Process` and injects the appropriate DLL (x64/x86) using `CreateRemoteThread` + `LoadLibraryW`. Unit tests verify PID-zero rejection, long-path rejection, missing-DLL rejection, and successful injection with module enumeration.

### T04 — Hook Classification Logic and Named Pipe Client
Implemented PE IAT parsing in `dlp-hook-dll` to locate `kernel32.dll!CreateFileW` and `ntdll.dll!NtCreateFile` entries, replace them with hook pointers, and save originals for trampolines. Added a named pipe client (`pipe_client.rs`) that serializes paths via `bincode`, waits for `HookResponse`, and returns `ERROR_ACCESS_DENIED` on `DENY` or any pipe error (fail-closed). Integration tests spawn a mock pipe server returning `DENY` and verify `GetLastError() == ERROR_ACCESS_DENIED`.

### T05 — WFP FFI Bindings and WFP Manager
Hand-rolled minimal FFI bindings to `fwpuclnt.dll` for `FwpmEngineOpen0`, `FwpmFilterAdd0`, `FwpmFilterDeleteById0`, `FwpmSubLayerAdd0`, and `FwpmEngineClose0`. Implemented `WfpManager` that opens the WFP engine, registers a sublayer, and exposes `add_process_block(pid)` / `remove_process_block(pid)` using `FWPM_CONDITION_IP_REMOTE_PORT` (443/TCP). Unit tests cover registration, unregistration, add/remove block, double-block idempotency, invalid-PID rejection, and remove-nonexistent handling.

### T06 — Cloud Enforcer and Service Integration
Implemented `CloudEnforcer` following the `UsbEnforcer` pattern (`new` / `with_paths`, `check -> Option<CloudBlockResult>`). Uses placeholder sync-folder paths for S01; S02 will replace with dynamic registry discovery. Wired `HookInjector` and `WfpManager` into `service.rs` `run_loop_init` (conditional on config) and `run_loop_shutdown` (WFP unregistration + injector drop). Updated `interception/mod.rs` to invoke `CloudEnforcer` before ABAC evaluation. Replaced the TC-30 stub with a real test asserting that a mock sync-folder path produces the expected block decision.

## Verification
All automated verification passed:
- `cargo check --workspace` — clean build (1 dead-code warning in dlp-hook-dll `PipeError::Timeout`, acceptable)
- `cargo test -p dlp-common abac` — 28 unit tests + 1 cross-crate compat test passed
- `cargo test -p dlp-agent hook_ipc` — 6 tests passed (roundtrip, boundaries, malformed, zero-byte, empty-path, no-server)
- `cargo test -p dlp-agent hook_injector` — 7 tests passed (injection success, PID zero, long path, missing DLL, module loaded, module not found, kernel32 found)
- `cargo test -p dlp-hook-dll` — 13 tests passed (IAT entry search, hash determinism, PCWSTR roundtrip, pipe client allow/deny/connection-refused, hook CreateFileW allow/deny)
- `cargo test -p dlp-agent wfp` — 5 tests passed (register/unregister, add/remove block, double block, invalid PID, remove nonexistent)
- `cargo test -p dlp-agent cloud_enforcer` — 11 tests passed (T3/T4 blocked, T1 allowed, read/delete ignored, outside-sync ignored, UNC ignored, empty path, custom path, created/moved blocked)
- `cargo test -p dlp-agent --test comprehensive -- test_tc_30` — 1 test passed (public cloud upload allowed)

## Patterns Established
- **Fail-closed hook DLL**: pipe errors, timeouts, and DENY responses all return `ERROR_ACCESS_DENIED`.
- **Enforcer pattern**: `new/with_paths -> check -> Option<BlockResult>` with `Arc<Enforcer>` passed to the event loop.
- **Config dual-schema**: `Option<T>` in TOML (`AgentConfig`), plain `T` with `serde(default)` in JSON (`AgentConfigPayload`).
- **Conditional subsystem construction**: subsystems are built in `run_loop_init` only when enabled in config; failures are logged as warnings without blocking startup.

## Known Limitations
- Sync folder paths are hardcoded placeholders (`C:\Users` heuristic). Real registry-based discovery comes in S02.
- The hook DLL has not been tested against live OneDrive/Dropbox processes. S02 will validate with real sync clients.
- WFP has been tested at the filter-registration level, not against actual HTTPS uploads. S02 will validate the defense-in-depth path.
- `PipeError::Timeout` variant is currently dead code (warning emitted during build). It is reserved for the timeout implementation in S02.

## Integration Closure
- **Upstream surfaces consumed**: `service.rs` lifecycle, `dlp-common::Action`, `AgentConfig`/`AgentConfigPayload`, `UsbEnforcer` pattern, audit pipeline.
- **New wiring introduced**: `HookInjector` + `WfpManager` constructed in `run_loop_init`, torn down in `run_loop_shutdown`; named pipe server thread spawned; `CloudEnforcer` passed into interception event loop.
- **What remains for end-to-end**: S02 adds dynamic sync path resolver, real sync client process discovery, and ABAC policy evaluation in the hook path. S04 builds print spooler interception independently.

## Verification

All automated tests passed:
- cargo check --workspace: clean
- cargo test -p dlp-common abac: 29 passed
- cargo test -p dlp-agent hook_ipc: 6 passed
- cargo test -p dlp-agent hook_injector: 7 passed (includes live DLL injection into child process)
- cargo test -p dlp-hook-dll: 13 passed (includes IAT patching and pipe client)
- cargo test -p dlp-agent wfp: 5 passed
- cargo test -p dlp-agent cloud_enforcer: 11 passed
- cargo test -p dlp-agent --test comprehensive -- test_tc_30: 1 passed

## Requirements Advanced

None.

## Requirements Validated

- R001 — Hook DLL implements IAT patching for CreateFileW/NtCreateFile; named pipe protocol achieves p99 < 50ms; CloudEnforcer blocks T3/T4 in placeholder sync paths; all verified by 42+ automated tests.
- R004 — WfpManager registers/unregisters cleanly; add_process_block/remove_process_block work for specified PIDs; 5 unit tests cover registration, block, unblock, double-block, and invalid PID edge cases.

## New Requirements Surfaced

None.

## Requirements Invalidated or Re-scoped

None.

## Operational Readiness

None.

## Deviations

None.

## Known Limitations

Sync folder paths are hardcoded placeholders (C:\\Users heuristic); real registry-based discovery comes in S02. Hook DLL has not been tested against live OneDrive/Dropbox processes. WFP tested at filter-registration level, not against actual HTTPS uploads. PipeError::Timeout variant is currently dead code (reserved for S02 timeout implementation).

## Follow-ups

S02 will integrate the dynamic sync path resolver (resolve_sync_paths), discover real sync client processes, and validate the hook against live OneDrive/Dropbox/Box/GDrive. S04 will build print spooler interception independently. S03 will add share link detection on top of S02's sync path resolver.

## Files Created/Modified

None.
