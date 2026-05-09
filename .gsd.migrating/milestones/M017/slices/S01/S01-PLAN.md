# S01: API Hook Framework + WFP Filter

**Goal:** Build the foundational interception infrastructure for cloud sync blocking: a hook DLL that intercepts CreateFileW/NtCreateFile in sync client processes via IAT patching, a WFP network egress filter for defense-in-depth, a named pipe protocol for classification requests, and agent service integration.
**Demo:** Write a test file to a OneDrive folder — the hook blocks CreateFileW before the sync client sees it. Bypass the hook with a direct syscall → WFP catches the HTTPS upload attempt.

## Must-Haves

- ## Must-Haves
- [ ] `Action::CLOUD_UPLOAD` exists in `dlp-common/src/abac.rs` with correct serde round-trip.
- [ ] Agent config schema supports `cloud_hook_enabled`, `wfp_filter_enabled`, and `hook_classification_timeout_ms`.
- [ ] Named pipe protocol (`HookRequest` / `HookResponse`) is defined and the agent-side pipe server completes 1000 round-trips with p99 < 50ms.
- [ ] Hook DLL (`dlp-hook-dll`) exports `HookCreateFileW`, `HookNtCreateFile`, and `UnhookAll` as a `cdylib`.
- [ ] Hook injector loads the DLL into a test process via `CreateRemoteThread` + `LoadLibraryW` with x86/x64 architecture detection.
- [ ] Hook DLL implements actual IAT patching and calls the named pipe client; returns `ACCESS_DENIED` when the agent responds `DENY`.
- [ ] Hand-rolled WFP FFI bindings to `fwpuclnt.dll` compile and link.
- [ ] WFP manager registers a filter, blocks outbound TCP/443 from a test PID, and unregisters cleanly.
- [ ] `CloudEnforcer` follows the established `UsbEnforcer` pattern and is wired into the interception event loop.
- [ ] `HookInjector` and `WfpManager` are constructed in `run_loop_init` and torn down in `run_loop_shutdown`.
- [ ] TC-30 stub is replaced with a real test asserting that a mock hook block decision produces the expected `BlockResult`.
- ## Threat Surface
- **Abuse**: A malicious process could spoof the named pipe server to trick the hook into allowing blocked files. Mitigation: pipe ACL restricts access to the service SID.
- **Data exposure**: File paths sent over the named pipe may contain PII or sensitive folder names. Mitigation: pipe is local-only (`PIPE_ACCESS_DUPLEX` on `\\.\pipe\DlpHookPipe`) with restricted ACL.
- **Input trust**: The hook DLL receives file paths from arbitrary processes inside sync clients. Must validate UTF-16 length and reject paths exceeding `MAX_PATH` before sending over the pipe.
- ## Requirement Impact
- **Requirements touched**: R001 (cloud sync folder write interception), R004 (WFP defense-in-depth)
- **Re-verify**: Existing USB/disk interception (`UsbEnforcer`, `DiskEnforcer`) — no logic changes, but `service.rs` startup/shutdown sequence is extended; confirm no regressions.
- **Decisions revisited**: D009 (API hooking approach — IAT chosen). This slice validates that IAT patching is viable for `CreateFileW`/`NtCreateFile` in test processes.

## Proof Level

- This slice proves: ## Proof Level

- This slice proves: **contract + integration**
- Real runtime required: **yes** (Windows APIs, process injection, WFP filter registration)
- Human/UAT required: **no** (automated tests exercise the contracts and integration paths)
- Note: Live OneDrive/Dropbox processes are **not** targeted in this slice's tests. S02 will validate against real sync clients. This slice proves the infrastructure works against test processes and mock servers.

## Integration Closure

## Integration Closure

- **Upstream surfaces consumed**: `service.rs` `run_loop_init`/`run_loop_shutdown` lifecycle; `dlp-common` `Action` enum; `AgentConfig`/`AgentConfigPayload` schema; `UsbEnforcer` enforcer pattern; audit pipeline.
- **New wiring introduced**: `HookInjector` + `WfpManager` constructed in `run_loop_init`, torn down in `run_loop_shutdown`; named pipe server thread spawned and joined on shutdown; `CloudEnforcer` passed into interception event loop.
- **What remains before the milestone is truly usable end-to-end**: S02 will add sync folder path resolver (`sync_path_resolver.rs`), actual sync client process discovery, and real ABAC policy evaluation in the hook path (connecting `CloudEnforcer` to the engine client). S04 builds print spooler interception independently.

## Verification

- ## Observability / Diagnostics
- **Runtime signals**: Hook DLL logs classification requests/responses via `OutputDebugStringW` (visible in DebugView). Agent service logs injector state changes (PID list, DLL load results) and WFP filter counts via `tracing`.
- **Inspection surfaces**: Agent service log file (`dlp-agent.log`) contains structured JSON for each hook call with `path_hash`, `decision`, `latency_ms`. Agent admin CLI can query hook injector active PIDs and WFP block list.
- **Failure visibility**: Hook timeout failures logged with `path_hash`, `timeout_ms`, and fallback decision (`DENY`). WFP registration failures logged with NTSTATUS code and sublayer GUID. Injector failures log target PID, architecture, and `GetLastError()`.
- **Redaction constraints**: Full file paths are never written to persistent logs; only a truncated hash+filename suffix is logged.

## Tasks

- [x] **T01: Add Action::CLOUD_UPLOAD and cloud/WFP config fields** `est:30m`
  Add the `CLOUD_UPLOAD` variant to the `Action` enum in `dlp-common/src/abac.rs`, following the existing `DRAG_DROP` serde pattern (literal variant name). Add unit tests for serialization and deserialization. Add `cloud_hook_enabled`, `wfp_filter_enabled`, and `hook_classification_timeout_ms` fields to `AgentConfig` in `dlp-agent/src/config.rs` and to `AgentConfigPayload` in `dlp-agent/src/server_client.rs`, following the existing `Option<bool>` / `Option<u64>` patterns. Ensure all three crates compile.
  - Files: `dlp-common/src/abac.rs`, `dlp-agent/src/config.rs`, `dlp-agent/src/server_client.rs`
  - Verify: cargo check -p dlp-common -p dlp-agent && cargo test -p dlp-common abac

- [x] **T02: Named pipe protocol and agent-side pipe server** `est:1h`
  Define the `HookRequest` / `HookResponse` protocol types in `dlp-agent/src/hook_ipc.rs`. Implement an agent-side named pipe server using `CreateNamedPipeW` + `ConnectNamedPipeW` on `\\.\pipe\DlpHookPipe`. The server runs on a dedicated `std::thread` and spawns a short-lived Tokio task per connection for classification. Write unit tests that spawn a pipe client in-process, send 1000 requests, and assert p99 latency is under 50ms.
  - Files: `dlp-agent/src/hook_ipc.rs`, `dlp-agent/src/lib.rs`, `dlp-agent/Cargo.toml`
  - Verify: cargo test -p dlp-agent hook_ipc

- [x] **T03: Hook DLL skeleton and injector** `est:1.5h`
  Create a new `cdylib` crate `dlp-hook-dll` in the workspace. Export `HookCreateFileW`, `HookNtCreateFile`, and `UnhookAll` as no-op trampolines that simply call the original function (save/restore original pointers in statics). Implement `hook_injector.rs` in the agent that discovers a target process by PID, checks architecture via `IsWow64Process`, and injects the appropriate DLL (x64 or x86) using `CreateRemoteThread` + `LoadLibraryW`. Write a unit test that spawns a test child process, injects the DLL, and verifies the module is present via `EnumProcessModules`.
  - Files: `dlp-hook-dll/Cargo.toml`, `dlp-hook-dll/src/lib.rs`, `dlp-agent/src/hook_injector.rs`, `Cargo.toml`, `dlp-agent/src/lib.rs`
  - Verify: cargo build -p dlp-hook-dll && cargo test -p dlp-agent hook_injector

- [x] **T04: Hook classification logic and named pipe client** `est:2h`
  Implement actual IAT patching in `dlp-hook-dll`: parse the host module's PE Import Address Table to find `kernel32.dll!CreateFileW` and `ntdll.dll!NtCreateFile` entries, replace them with pointers to the hook functions, and save originals for trampolines. Implement a named pipe client (`dlp-hook-dll/src/pipe_client.rs`) that connects to `\\.\pipe\DlpHookPipe`, serializes the file path via `bincode`, waits for `HookResponse`, and returns `ERROR_ACCESS_DENIED` when `decision == DENY`. Write integration tests: spawn a mock pipe server that returns `DENY`, trigger the hooked `CreateFileW`, and verify `GetLastError() == ERROR_ACCESS_DENIED`.
  - Files: `dlp-hook-dll/src/lib.rs`, `dlp-hook-dll/src/pipe_client.rs`, `dlp-agent/src/hook_ipc.rs`, `dlp-hook-dll/Cargo.toml`
  - Verify: cargo test -p dlp-hook-dll && cargo test -p dlp-agent hook_classification

- [x] **T05: WFP FFI bindings and WFP manager** `est:2h`
  Hand-roll minimal FFI bindings to `fwpuclnt.dll` in `dlp-agent/src/wfp_ffi.rs` for `FwpmEngineOpen0`, `FwpmFilterAdd0`, `FwpmFilterDeleteById0`, `FwpmSubLayerAdd0`, and `FwpmEngineClose0`. Use `windows` crate `GUID` and `NTSTATUS` types. Implement `wfp_manager.rs` that opens the WFP engine, registers a sublayer, adds a filter blocking outbound TCP/443 from specified PIDs (using `FWPM_CONDITION_IP_LOCAL_ADDRESS`, `FWPM_CONDITION_IP_REMOTE_PORT`, `FWPM_CONDITION_IP_PROTOCOL`), and exposes `add_process_block(pid)` / `remove_process_block(pid)`. Write unit tests for registration, block, unblock, and unregistration. If `Win32_NetworkManagement_WindowsFilteringPlatform` is available in the `windows` crate, use it; otherwise rely entirely on the hand-rolled FFI module.
  - Files: `dlp-agent/src/wfp_ffi.rs`, `dlp-agent/src/wfp_manager.rs`, `dlp-agent/Cargo.toml`, `dlp-agent/src/lib.rs`
  - Verify: cargo test -p dlp-agent wfp

- [x] **T06: Cloud enforcer and service integration** `est:1.5h`
  Implement `CloudEnforcer` in `dlp-agent/src/cloud_enforcer.rs` following the `UsbEnforcer` pattern: `new(...) -> Self` and `check(&self, path: &str, action: &FileAction) -> Option<CloudBlockResult>`. The enforcer checks if the path is inside a sync folder (placeholder check for S01; S02 will add real path resolver) and returns a block result for T3/T4 `CLOUD_UPLOAD` actions. Wire `HookInjector` and `WfpManager` into `service.rs`: construct both in `run_loop_init`, store handles in `RunLoopContext`, and tear them down in `run_loop_shutdown`. Update `interception/mod.rs` to accept the cloud enforcer and invoke it before ABAC evaluation. Replace the TC-30 stub in `dlp-agent/tests/comprehensive.rs` with a real test that constructs a `CloudEnforcer`, passes a mock sync-folder path, and asserts the block decision and audit event shape.
  - Files: `dlp-agent/src/cloud_enforcer.rs`, `dlp-agent/src/service.rs`, `dlp-agent/src/interception/mod.rs`, `dlp-agent/tests/comprehensive.rs`, `dlp-agent/src/lib.rs`
  - Verify: cargo test -p dlp-agent cloud_enforcer && cargo test -p dlp-agent --test comprehensive -- test_tc_30

## Files Likely Touched

- dlp-common/src/abac.rs
- dlp-agent/src/config.rs
- dlp-agent/src/server_client.rs
- dlp-agent/src/hook_ipc.rs
- dlp-agent/src/lib.rs
- dlp-agent/Cargo.toml
- dlp-hook-dll/Cargo.toml
- dlp-hook-dll/src/lib.rs
- dlp-agent/src/hook_injector.rs
- Cargo.toml
- dlp-hook-dll/src/pipe_client.rs
- dlp-agent/src/wfp_ffi.rs
- dlp-agent/src/wfp_manager.rs
- dlp-agent/src/cloud_enforcer.rs
- dlp-agent/src/service.rs
- dlp-agent/src/interception/mod.rs
- dlp-agent/tests/comprehensive.rs
