---
estimated_steps: 41
estimated_files: 4
skills_used: []
---

# T04: Hook classification logic and named pipe client

Implement actual IAT patching in `dlp-hook-dll`: parse the host module's PE Import Address Table to find `kernel32.dll!CreateFileW` and `ntdll.dll!NtCreateFile` entries, replace them with pointers to the hook functions, and save originals for trampolines. Implement a named pipe client (`dlp-hook-dll/src/pipe_client.rs`) that connects to `\\.\pipe\DlpHookPipe`, serializes the file path via `bincode`, waits for `HookResponse`, and returns `ERROR_ACCESS_DENIED` when `decision == DENY`. Write integration tests: spawn a mock pipe server that returns `DENY`, trigger the hooked `CreateFileW`, and verify `GetLastError() == ERROR_ACCESS_DENIED`.

## Failure Modes
| Dependency | On error | On timeout | On malformed response |
|------------|----------|-----------|----------------------|
| Named pipe client | Fail-closed: return `ERROR_ACCESS_DENIED` | Fail-closed after `timeout_ms` | Log error, fail-closed |
| IAT patching | Return original function pointer, no hook installed | N/A | N/A |

## Load Profile
- **Shared resources**: Named pipe connection handle (one per hook call).
- **Per-operation cost**: One pipe round-trip + bincode encode/decode + IAT lookup (cached after first call).
- **10x breakpoint**: Pipe server saturation if many sync client threads call `CreateFileW` simultaneously. Mitigation: pipe timeout default is 50ms, fail-closed.

## Negative Tests
- **Malformed inputs**: Path with embedded nulls, path > 32KB, invalid UTF-16 surrogate pairs.
- **Error paths**: Pipe server offline → immediate `ERROR_ACCESS_DENIED`. Pipe server returns garbage → fail-closed.
- **Boundary conditions**: Timeout of 0ms, timeout of 5000ms, empty reason string.

## Steps
1. Implement PE IAT parser in `dlp-hook-dll/src/lib.rs` using `GetModuleHandleW(nullptr)` and walking the PE import directory.
2. Replace IAT entries for `CreateFileW` and `NtCreateFile` with hook function pointers.
3. Create `dlp-hook-dll/src/pipe_client.rs` with `send_request(path, timeout_ms) -> Result<HookResponse, PipeError>`.
4. In the hook function: call pipe client, on `DENY` set `SetLastError(ERROR_ACCESS_DENIED)` and return `INVALID_HANDLE_VALUE`; on `ALLOW` call original trampoline.
5. Write integration test with mock pipe server in `dlp-hook-dll` tests.
6. Update `dlp-agent/src/hook_ipc.rs` to expose a test helper that can mock responses.

## Must-Haves
- [ ] IAT patching finds and replaces `CreateFileW` and `NtCreateFile` entries.
- [ ] Hook returns `INVALID_HANDLE_VALUE` + `ERROR_ACCESS_DENIED` when pipe returns `DENY`.
- [ ] Hook calls original function when pipe returns `ALLOW`.
- [ ] Integration test with mock server passes.

## Verification
- `cargo test -p dlp-hook-dll`
- `cargo test -p dlp-agent hook_classification`

## Observability Impact
- Signals added: `OutputDebugStringW` on each hook invocation with path hash, decision, and latency.
- How a future agent inspects this: DebugView or `cargo test -- --nocapture` shows hook decisions.
- Failure state exposed: `PipeError::Timeout` and `PipeError::ConnectionRefused` are distinct; hook always fail-closed.

## Inputs
- `dlp-hook-dll/src/lib.rs`
- `dlp-agent/src/hook_ipc.rs`

## Expected Output
- `dlp-hook-dll/src/lib.rs` (updated with IAT patching)
- `dlp-hook-dll/src/pipe_client.rs`
- `dlp-agent/src/hook_ipc.rs` (updated with test helpers)
- `dlp-hook-dll/Cargo.toml` (if `bincode` added)

## Inputs

- `dlp-hook-dll/src/lib.rs`
- `dlp-agent/src/hook_ipc.rs`

## Expected Output

- `dlp-hook-dll/src/lib.rs`
- `dlp-hook-dll/src/pipe_client.rs`
- `dlp-agent/src/hook_ipc.rs`
- `dlp-hook-dll/Cargo.toml`

## Verification

cargo test -p dlp-hook-dll && cargo test -p dlp-agent hook_classification
