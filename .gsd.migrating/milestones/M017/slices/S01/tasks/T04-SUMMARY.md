---
id: T04
parent: S01
milestone: M017
key_files:
  - dlp-common/src/hook_ipc.rs
  - dlp-common/src/lib.rs
  - dlp-agent/src/hook_ipc.rs
  - dlp-hook-dll/Cargo.toml
  - dlp-hook-dll/src/pipe_client.rs
  - dlp-hook-dll/src/lib.rs
key_decisions:
  - Moved HookRequest/HookResponse to dlp-common so both dlp-agent and dlp-hook-dll share the same types without circular dependencies
  - Used dlp_agent::hook_ipc::HookIpcServer for integration tests to avoid flakiness from raw Win32 pipe server in test threads
  - Implemented IAT patching with raw PE pointer arithmetic rather than external crate to keep the cdylib lightweight
duration: 
verification_result: passed
completed_at: 2026-05-08T14:17:58.776Z
blocker_discovered: false
---

# T04: Implemented PE IAT patching, named pipe client, and fail-closed hook classification in dlp-hook-dll with 13 passing integration tests

**Implemented PE IAT patching, named pipe client, and fail-closed hook classification in dlp-hook-dll with 13 passing integration tests**

## What Happened

Implemented the hook classification logic and named pipe client for the DLP API hook DLL (T04).

1. **Shared types**: Moved `HookRequest` and `HookResponse` from `dlp-agent/src/hook_ipc.rs` to a new `dlp-common/src/hook_ipc.rs` module so both the agent service and the hook DLL can use the same serialization contract. Updated `dlp-common/src/lib.rs` to export the new module and updated `dlp-agent/src/hook_ipc.rs` to import from `dlp-common` instead of defining them locally.

2. **Pipe client**: Created `dlp-hook-dll/src/pipe_client.rs` with `send_request(pipe_name, request, timeout_ms) -> Result<HookResponse, PipeError>`. The client connects via `CreateFileW` with a retry loop, writes length-prefixed bincode frames, reads the response, and closes the handle. Errors map to `PipeError::ConnectionRefused`, `PipeError::Timeout`, `PipeError::Malformed`, or `PipeError::Win32(code)`. Added `bincode` and `serde` to `dlp-hook-dll/Cargo.toml` and enabled the `Win32_System_Pipes` feature.

3. **IAT patching**: Added PE IAT parsing to `dlp-hook-dll/src/lib.rs`. `find_iat_entry` walks the host module's import directory using raw pointer arithmetic (DOS header → NT headers → import descriptors → IAT thunks) to locate the entries for `kernel32.dll!CreateFileW` and `ntdll.dll!NtCreateFile`. `patch_iat` uses `VirtualProtect` with `PAGE_EXECUTE_READWRITE` to replace the IAT pointer with the hook function, then restores protection. `UnhookAll` uses `restore_iat` to put the original pointers back.

4. **Hook classification**: `HookCreateFileW` extracts the file path via `pcwstr_to_string`, hashes it for privacy-preserving debug logging, calls `classify_path` with a 50 ms timeout, and on `DENY` sets `SetLastError(ERROR_ACCESS_DENIED)` and returns `INVALID_HANDLE_VALUE`. On `ALLOW` it calls the original trampoline. `HookNtCreateFile` does the same for `NtCreateFile`, extracting the path from `OBJECT_ATTRIBUTES` and returning `STATUS_ACCESS_DENIED` (0xC0000022) on denial. Both hooks log decision, path hash, and latency via `OutputDebugStringW`.

5. **Integration tests**: Wrote 13 unit/integration tests in `dlp-hook-dll/src/lib.rs`. Pipe roundtrip tests and hook classification tests use `dlp_agent::hook_ipc::HookIpcServer` (added as a dev-dependency) for a reliable mock server. Tests verify:
   - Hash determinism and `PCWSTR` conversion
   - `PipeError::ConnectionRefused` when no server exists
   - Roundtrip `DENY` and `ALLOW` over the pipe
   - `classify_path` returning `DENY` and `ALLOW`
   - `UnhookAll` not panicking when uninitialized
   - `find_iat_entry` returning `None` for invalid modules
   - `extract_nt_path` returning empty for null input

The `dlp-agent` test suite (all 65+ tests) continues to pass after the `HookRequest`/`HookResponse` relocation.

## Verification

All dlp-hook-dll tests pass (13/13). All dlp-agent hook_ipc unit tests pass (6/6). Full dlp-agent test suite passes (52 integration + 7 negative + 6 unit + 6 doc tests).

## Verification Evidence

| # | Command | Exit Code | Verdict | Duration |
|---|---------|-----------|---------|----------|
| 1 | `cargo test -p dlp-hook-dll` | 0 | ✅ pass | 18900ms |
| 2 | `cargo test -p dlp-agent --lib hook_ipc` | 0 | ✅ pass | 5600ms |
| 3 | `cargo test -p dlp-agent -- --test-threads=1` | 0 | ✅ pass | 89200ms |

## Deviations

Used `dlp_agent::hook_ipc::HookIpcServer` in integration tests instead of a custom mock server. The custom mock server (built with raw `CreateNamedPipeW`/`ConnectNamedPipe`) exhibited flaky behavior in parallel/sequential test runs due to Win32 named pipe state management. The agent's proven `HookIpcServer` (with proper `PipeSecurity`, accept-loop, and pipe recycling) provided reliable test execution without changing the hook DLL production code.

## Known Issues

None.

## Files Created/Modified

- `dlp-common/src/hook_ipc.rs`
- `dlp-common/src/lib.rs`
- `dlp-agent/src/hook_ipc.rs`
- `dlp-hook-dll/Cargo.toml`
- `dlp-hook-dll/src/pipe_client.rs`
- `dlp-hook-dll/src/lib.rs`
