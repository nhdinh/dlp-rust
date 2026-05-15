# Phase 48: Hook DLL Surface Expansion + Crash Hardening + Build Harness - Context

**Gathered:** 2026-05-15
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 48 delivers a **unified, crash-hardened, dual-arch hook DLL** that exposes the full file-I/O API surface and ships through a signed release pipeline. This replaces the v0.9.0 cloud-sync `dlp-hook-dll` (which only patches `CreateFileW` and `NtCreateFile`) with a single DLL covering 11 file-I/O functions, ready for universal injection in Phase 49.

**Depends on:** Phase 47 (prerequisite — secrets at rest; agent reads encrypted SMTP/SIEM/JWT/LDAP creds in any new admin endpoint added here)
**Requirements:** BLOCK-01, BLOCK-02, BLOCK-03, BLOCK-04, BLOCK-10

**What Phase 48 builds:**
1. Expanded IAT hook surface: `WriteFile`, `WriteFileEx`, `MoveFileExW`, `CopyFileExW`, `CopyFile2`, `DeleteFileW`, `ReplaceFileW`, `SetFileInformationByHandle`, `NtOpenFile`, `NtWriteFile`, `NtSetInformationFile` — in addition to v0.9.0's `CreateFileW`/`CreateFileA`/`CreateFile2`/`NtCreateFile`
2. Crash hardening: `catch_unwind` + SEH wrappers in every patched stub; 32K-char cap on wide-string conversion; thread-local pre-allocated pipe buffers
3. Unified single hook DLL replaces v0.9.0 cloud-sync DLL (no parallel DLLs)
4. x86 sibling DLL (`dlp_hook_dll_x86.dll`) built from same source via `i686-pc-windows-msvc` target
5. Authenticode signing pipeline for every shipped binary with RFC-3161 timestamping

**What Phase 48 does NOT build:**
- Universal injection (Phase 49)
- Shared-memory classification cache (Phase 50)
- ntdll syscall-stub trampolines (Phase 51)
- ETW bypass detection (Phase 53)
- Admin TUI screens (Phase 54)

</domain>

<decisions>
## Implementation Decisions

### Hook Surface Implementation Strategy
- **D-01:** **Hybrid approach** — A `const HOOKS: &[HookDescriptor]` metadata table drives `UnhookAll`, debug logging, and hook enumeration. Each trampoline remains hand-written for precision (path extraction and return-value mapping differ per function).
- **D-02:** **Agent maintains handle->path map** — For HANDLE-based functions (`WriteFile`, `SetFileInformationByHandle`), the hook DLL sends the HANDLE value to the agent over the named pipe, and the agent resolves the path from its internal handle tracking map. This avoids extra syscalls in the hook DLL but requires the agent to track handle lifecycle (create/close/duplicate).
- **D-03:** **Generic macro for fail-closed returns** — A declarative macro generates the correct denial return value based on the trampoline's return type (`BOOL(false)`, `INVALID_HANDLE_VALUE`, `NTSTATUS(STATUS_ACCESS_DENIED)`). Each `HookDescriptor` carries a `deny_return: DenyReturn` constant.
- **D-04:** **Eager patching at DllMain** — All 11 IAT entries are patched during `DLL_PROCESS_ATTACH`. Lazy patching is deferred; the simpler eager approach is acceptable for now.

### Crash Hardening Boundaries
- **D-05:** **Layered crash protection** — SEH `__try/__except` around the entire trampoline entry (catches AVs in `unsafe` path extraction), `catch_unwind` around the Rust-side classification pipeline (catches panics in pipe client or decision logic). On any exception, route to the original function (fail-OPEN).
- **D-06:** **Fail-open only on crash** — No self-repair or re-patching after a crash. Log via `OutputDebugStringW` and call the original function. Prevents infinite crash loops.
- **D-07:** **32K-char cap in `pcwstr_to_string`** — Central enforcement point. All path-extraction paths go through this helper. Returns a truncated string if the input exceeds 32K characters.
- **D-08:** **catch_unwind includes pipe_client** — The `catch_unwind` boundary wraps the entire `classify_path` → `pipe_client::send_request` → decision pipeline, not just the high-level wrapper.
- **D-09:** **Thread-local pre-allocated buffer** — Each thread gets a 4KiB pre-allocated `Vec<u8>` in `thread_local!()`. The pipe client reuses it instead of allocating per call. Eliminates allocator pressure in hot paths.

### x86 Build Architecture
- **D-10:** **Output name:** `dlp_hook_dll_x86.dll` — Explicit architecture suffix for clarity in release packages and Process Hacker.
- **D-11:** **Same crate with `cfg(target_arch)`** — The `dlp-hook-dll` crate builds for both x64 and x86 from the same source. PE parsing differences (PE32+ magic `0x20B` vs PE32 magic `0x10B`, data directory offsets) are localized to `find_iat_entry` with `cfg` blocks.
- **D-12:** **Manual PE parsing** — Keep the current manual PE parsing (no `goblin`/`pelite` dependency). Add `cfg(target_arch)` blocks for the few architecture-specific constants.
- **D-13:** **Cross-compile on x64 CI runner** — Install the `i686-pc-windows-msvc` toolchain in the GitHub Actions workflow. No self-hosted x86 runner needed.
- **D-14:** **Hook ntdll on x86 too** — Patch `NtCreateFile`/`NtOpenFile` on x86 for completeness, even though the direct-syscall bypass threat model is x64-specific.
- **D-15:** **Architecture-agnostic tests** — The `#[cfg(test)]` module uses the same test logic regardless of architecture. CI runs tests on x64 only.
- **D-16:** **Full crash hardening on x86** — Same `catch_unwind` + SEH wrappers as x64. Consistent behavior across architectures.

### Signing Pipeline
- **D-17:** **Release tags only** — Signing is triggered only on release tags (e.g., `v0.10.0`), not on every push. Saves CI time and timestamp server quota.
- **D-18:** **Sign + verify gate** — After signing, run `signtool verify /pa` as a blocking gate. Catches incomplete cert chains and bad timestamp responses.
- **D-19:** **Sign test harness too** — `dlp-e2e` binaries are also signed, even though they're not shipped to customers. QA teams may need signed test binaries.
- **D-20:** **DigiCert primary + Sectigo fallback** — Use `http://timestamp.digicert.com` as the primary RFC-3161 timestamp server. If DigiCert fails, fall back to `http://timestamp.sectigo.com`.
- **D-21:** **GitHub secret (PFX + password)** — Store `AUTHENTICODE_PFX` and `AUTHENTICODE_PASSWORD` as GitHub repository secrets. Use `signtool sign /f` in the release workflow. Suitable for regular (non-EV) Authenticode certs.

### Claude's Discretion
- The `HookDescriptor` table should include: `fn_name`, `dll_name` ("kernel32.dll" or "ntdll.dll"), `original_ptr` (static mut), `iat_ptr` (static mut), `trampoline_ptr`, `deny_return`.
- The fail-closed macro should handle three return-value families: `BOOL(0)`, `INVALID_HANDLE_VALUE` (`HANDLE(-1)`), `NTSTATUS(0xC0000022)` (STATUS_ACCESS_DENIED).
- The thread-local buffer should use `RefCell<Vec<u8>>` with `with_capacity(4096)` to avoid reallocation.
- The x86 `find_iat_entry` needs: magic `0x10B` (PE32), optional header offset 24, data directory offset 96 (vs 112 for PE32+).
- The signing workflow should be a separate `.github/workflows/release.yml` that triggers on `push: tags: ['v*']`.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements & Architecture
- `.planning/REQUIREMENTS.md` §"Universal hook DLL + expanded surface (BLOCK)" — BLOCK-01..04, BLOCK-10 requirements
- `.planning/ROADMAP.md` §"Phase 48: Hook DLL Surface Expansion + Crash Hardening + Build Harness" — phase goal and success criteria
- `.planning/PROJECT.md` §"Current Milestone: v0.10.0 Real-Time File Access Prevention" — architecture commitments and constraints

### Existing Code Patterns
- `dlp-hook-dll/src/lib.rs` — Current hook DLL with `CreateFileW`/`NtCreateFile` IAT patching. **MUST expand** to 11 functions.
- `dlp-hook-dll/src/pipe_client.rs` — Named-pipe client with bincode framing. **Reuse** for expanded hook surface.
- `dlp-agent/src/hook_injector.rs` — `HookInjector` with `IsWow64Process` architecture detection. **Reuse** for Phase 49 universal injection.
- `dlp-e2e/` — v0.9.0 cloud-sync regression tests. **Must pass** with unified DLL (BLOCK-03).
- `installer/DLPAgent.wxs` — WiX installer source. **Must update** to package both x64 and x86 DLLs.

### Windows API References
- `windows` crate 0.62 documentation for `VirtualProtect`, `CreateRemoteThread`, `OutputDebugStringW`
- `std::panic::catch_unwind` for Rust panic handling in FFI boundaries
- `windows` crate SEH bindings (`__try`/`__except`) for access-violation handling

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`find_iat_entry` + `patch_iat`** (`dlp-hook-dll/src/lib.rs`): Manual PE IAT parsing. Expand to support both x64 (PE32+) and x86 (PE32) via `cfg(target_arch)`.
- **`pipe_client::send_request`** (`dlp-hook-dll/src/pipe_client.rs`): Named-pipe client with length-prefixed bincode framing. **Reuse** with thread-local pre-allocated buffer.
- **`HookInjector`** (`dlp-agent/src/hook_injector.rs`): Already supports x64/x86 DLL selection via `IsWow64Process`. Phase 48 only needs to provide the `dlp_hook_dll_x86.dll` artifact.
- **`HookRequest`/`HookResponse`** (`dlp-common`): Shared IPC types. May need minor extension for `op: HookOp` enum.

### Established Patterns
- **Manual IAT patching**: The current code walks the PE import table manually. This pattern scales to 11 functions with a metadata table.
- **Fail-closed**: Current code returns `ERROR_ACCESS_DENIED` / `STATUS_ACCESS_DENIED` on any error. This pattern must be preserved and extended to all 11 functions.
- **Debug logging via `OutputDebugStringW`**: Current pattern logs hash + latency. Extend to include operation type and function name.
- **`#[unsafe(no_mangle)]` trampolines**: Current pattern for `HookCreateFileW` and `HookNtCreateFile`. Replicate for 9 additional functions.

### Integration Points
- `dlp-hook-dll/Cargo.toml` — Add `i686-pc-windows-msvc` target support (same source, different target).
- `dlp-hook-dll/build.rs` — May need architecture-specific build logic.
- `.github/workflows/` — New or updated release workflow for signing.
- `installer/DLPAgent.wxs` — Package both `dlp_hook_dll.dll` and `dlp_hook_dll_x86.dll`.
- `dlp-e2e/` — Update cloud-sync tests to use unified DLL (remove any `dlp-cloud-hook.dll` references).

</code_context>

<specifics>
## Specific Ideas

- The `HookDescriptor` table should be a `static` array of structs, not a macro. It drives `init()` (patch all), `UnhookAll()` (restore all), and debug logging.
- For `CopyFile2` (COM-based API), the IAT entry may not exist in the traditional import table. If so, document it as a known limitation and defer to Phase 51 (ntdll trampolines) for coverage.
- The `SetFileInformationByHandle` hook needs special handling: the `FileInformationClass` parameter determines whether the operation is a rename, delete, or attribute change. Only block `FileRenameInfo`, `FileDispositionInfo`, and `FileEndOfFileInfo` classes.
- The thread-local buffer should be initialized with `Vec::with_capacity(4096)` and never shrink. On each `send_request`, clear with `.clear()` and reuse.
- The CI signing workflow should use a matrix strategy: build x64 first, then x86, then sign all artifacts in a single step.
- `signtool` command template: `signtool sign /f %AUTHENTICODE_PFX% /p %AUTHENTICODE_PASSWORD% /tr http://timestamp.digicert.com /td sha256 /fd sha256 <binary>`

</specifics>

<deferred>
## Deferred Ideas

- Hook protocol versioning with `pid`, `tid`, `file_object`, `journal_seq` (Phase 50 — CACHE)
- Shared-memory classification cache (Phase 50)
- Universal injection via ETW Process Watcher (Phase 49)
- ntdll syscall-stub trampolines (Phase 51)
- Installer auto-update for DLL replacement (Phase 57 — OPS)
- Azure Key Vault migration for EV code signing (post-v0.10.0)

</deferred>

---

*Phase: 48-Hook DLL Surface Expansion + Crash Hardening + Build Harness*
*Context gathered: 2026-05-15*
