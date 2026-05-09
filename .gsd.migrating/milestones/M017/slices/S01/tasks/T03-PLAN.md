---
estimated_steps: 40
estimated_files: 5
skills_used: []
---

# T03: Hook DLL skeleton and injector

Create a new `cdylib` crate `dlp-hook-dll` in the workspace. Export `HookCreateFileW`, `HookNtCreateFile`, and `UnhookAll` as no-op trampolines that simply call the original function (save/restore original pointers in statics). Implement `hook_injector.rs` in the agent that discovers a target process by PID, checks architecture via `IsWow64Process`, and injects the appropriate DLL (x64 or x86) using `CreateRemoteThread` + `LoadLibraryW`. Write a unit test that spawns a test child process, injects the DLL, and verifies the module is present via `EnumProcessModules`.

## Failure Modes
| Dependency | On error | On timeout | On malformed response |
|------------|----------|-----------|----------------------|
| Target process | Injection skipped, logged | N/A (synchronous) | N/A |
| `CreateRemoteThread` | Log `GetLastError()`, skip PID | N/A | N/A |
| `LoadLibraryW` in target | Log error, skip PID | N/A | N/A |

## Negative Tests
- **Malformed inputs**: PID 0, PID of a protected process (requires elevation), non-existent PID.
- **Error paths**: x86 DLL not found on x64-only build; target process exits during injection.
- **Boundary conditions**: Very long DLL path (>MAX_PATH), path with spaces.

## Steps
1. Create `dlp-hook-dll/Cargo.toml` as a `cdylib` crate, add `windows` crate dependency with `Win32_Foundation`, `Win32_System_LibraryLoader`, `Win32_Storage_FileSystem`.
2. Create `dlp-hook-dll/src/lib.rs` with `extern "system"` exports and static storage for original function pointers.
3. Create `dlp-agent/src/hook_injector.rs` with `HookInjector::inject(pid, dll_path) -> Result<(), HookError>`.
4. Implement architecture detection: `IsWow64Process` + WOW check to choose x86 vs x64 DLL path.
5. Write unit test spawning `cmd.exe /c timeout 10` as test process, inject DLL, verify via `EnumProcessModules`.
6. Add `dlp-hook-dll` to workspace `Cargo.toml`.
7. Add `pub mod hook_injector;` to `dlp-agent/src/lib.rs`.

## Must-Haves
- [ ] `cargo build -p dlp-hook-dll` produces a `.dll` file.
- [ ] Hook exports are visible via `dumpbin /exports` or equivalent.
- [ ] Injector successfully loads the DLL into a test process.
- [ ] Architecture check correctly refuses x64→x86 injection.

## Verification
- `cargo build -p dlp-hook-dll`
- `cargo test -p dlp-agent hook_injector`

## Observability Impact
- Signals added: `tracing::info!` on each injection attempt with PID, architecture, DLL path, and result.
- How a future agent inspects this: agent logs contain `hook_injector` spans.
- Failure state exposed: `HookError::AccessDenied`, `HookError::ArchitectureMismatch`, `HookError::DllNotFound` are distinct error variants.

## Inputs
- `Cargo.toml` (workspace members)
- `dlp-agent/src/lib.rs`

## Expected Output
- `dlp-hook-dll/Cargo.toml`
- `dlp-hook-dll/src/lib.rs`
- `dlp-agent/src/hook_injector.rs`
- `Cargo.toml` (updated workspace members)
- `dlp-agent/src/lib.rs` (updated with `mod hook_injector`)

## Inputs

- `Cargo.toml`
- `dlp-agent/src/lib.rs`

## Expected Output

- `dlp-hook-dll/Cargo.toml`
- `dlp-hook-dll/src/lib.rs`
- `dlp-agent/src/hook_injector.rs`
- `Cargo.toml`
- `dlp-agent/src/lib.rs`

## Verification

cargo build -p dlp-hook-dll && cargo test -p dlp-agent hook_injector
