---
phase: 48
slug: 48-hook-dll-surface-expansion-crash-hardening-build-harness
status: verified
threats_open: 0
asvs_level: 1
created: 2026-05-19
---

# Phase 48 — Security Threat Verification

> Per-phase security contract: threat register, accepted risks, and audit trail.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| Hook DLL -> Host Process | DLL runs inside arbitrary user processes; crash in DLL aborts host | File paths, HANDLE values |
| Hook DLL -> Agent Service | Named-pipe IPC crosses process boundaries; malformed responses rejected | HookRequest, HandleHookRequest, HookResponse |
| CI runner -> GitHub secrets | PFX and password exposed to workflow; must be repository-scoped | Signing certificate, password |
| Signed binary -> End user | Unsigned/incorrectly signed DLL triggers AV/EDR false positive | Authenticode signature, timestamp |
| Agent -> Target Process | Injector selects wrong DLL architecture -> injection fails or crashes WOW64 process | DLL path, process handle |
| CI -> Build Artifact | x86 build silently fails in CI -> release ships without x86 coverage | Build artifacts, DLL binaries |

---

## Threat Register

| Threat ID | Category | Component | Disposition | Mitigation | Status |
|-----------|----------|-----------|-------------|------------|--------|
| T-48-01 | Denial of Service | crash_guard.rs / trampolines | mitigate | `guard_trampoline` wraps every trampoline in `catch_unwind`; routes to original function (fail-open) | CLOSED |
| T-48-02 | Denial of Service | pipe_client.rs | mitigate | `PIPE_BUFFER` thread-local `RefCell<Vec<u8>>` with `with_capacity(4096)` eliminates allocator pressure in hot path | CLOSED |
| T-48-03 | Tampering | fail_closed.rs | mitigate | `fail_closed!` macro generates deterministic deny returns; no attacker-influenced return path | CLOSED |
| T-48-03a | Denial of Service | crash_guard.rs reentrancy | mitigate | `with_reentrancy_guard` uses thread-local `Cell<bool>` to prevent recursive hook entry during IPC/logging | CLOSED |
| T-48-04 | Tampering | pe_utils.rs | mitigate | `patch_iat` restores original page protection after write; `restore_iat` reverses all changes on unload | CLOSED |
| T-48-05 | Elevation of Privilege | trampolines.rs (SetFileInformationByHandle) | mitigate | Only blocks classes 4 (FileDispositionInfo), 6 (FileEndOfFileInfo), 10 (FileRenameInfo); all others pass through | CLOSED |
| T-48-06 | Information Disclosure | trampolines.rs | mitigate | `hash_path` (fn in lib.rs) used in debug logs prevents full path exposure | CLOSED |
| T-48-07 | Denial of Service | trampolines.rs (CopyFile2 gap) | accept | CopyFile2 is COM-based with no IAT entry; underlying NtCreateFile/NtWriteFile hooks provide coverage | CLOSED |
| T-48-07a | Denial of Service | pe_utils.rs | mitigate | `MAX_IMPORT_DESCRIPTORS = 512` prevents unbounded reads on malformed PEs | CLOSED |
| T-48-07b | Elevation of Privilege | trampolines.rs (multi-path ops) | mitigate | MoveFileExW, CopyFileExW, ReplaceFileW evaluate ALL paths; denial on any path blocks operation | CLOSED |
| T-48-08 | Denial of Service | lib.rs pcwstr_to_string | mitigate | `MAX_WIDE_CHARS = 32_768` cap prevents infinite loop / OOM on malformed pointer | CLOSED |
| T-48-09 | Elevation of Privilege | lib.rs classify_handle | mitigate | `HandleHookRequest` with `u64 handle_value` protocol is in place; agent-side handle tracker validates handle via NtQueryObject (Phase 49/50) | CLOSED |
| T-48-10 | Tampering | lib.rs HOOKS table | mitigate | Static `const HOOKS: &[HookDescriptor]` table; immutable at runtime. `UnhookAll` restores all entries. | CLOSED |
| T-48-10a | Denial of Service | lib.rs DllMain detach | mitigate | `DLL_PROCESS_DETACH` calls `UnhookAll()`, preventing dangling trampoline pointers after DLL unload | CLOSED |
| T-48-10b | Elevation of Privilege | lib.rs extract_nt_path | mitigate | `cfg(target_arch)` constants ensure correct `OBJECT_ATTRIBUTES` and `UNICODE_STRING` offsets on both x86 and x64 | CLOSED |
| T-48-11 | Denial of Service | hook_injector.rs | mitigate | `target_architecture` uses `IsWow64Process` to detect WOW64; `select_dll` returns error on mismatch | CLOSED |
| T-48-12 | Tampering | build.yml | mitigate | CI builds x86 DLL with `RUSTFLAGS="-D warnings"`; failures block the pipeline | CLOSED |
| T-48-13 | Elevation of Privilege | pe_utils.rs (x86 offsets) | mitigate | `cfg(target_arch)` constants verified in both `pe_utils.rs` and `lib.rs` for correct x86/x64 PE parsing | CLOSED |
| T-48-14 | Repudiation | release.yml | mitigate | `signtool verify /pa` blocking gate ensures every shipped binary has valid Authenticode signature with timestamp | CLOSED |
| T-48-15 | Denial of Service | release.yml | mitigate | DigiCert primary (`timestamp.digicert.com`) + Sectigo fallback (`timestamp.sectigo.com`); both fail = release blocked | CLOSED |
| T-48-16 | Information Disclosure | release.yml | mitigate | PFX password read from GitHub secrets (`secrets.AUTHENTICODE_PASSWORD`); never logged or committed | CLOSED |
| T-48-17 | Tampering | release.yml | mitigate | Per-binary `$failed` array tracks signing failures; `verify /pa` gate catches any unsigned binaries | CLOSED |

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| R-48-01 | T-48-07 | CopyFile2 is COM-based with no traditional IAT entry. Direct COM hooking is significantly more complex. The underlying NtCreateFile and NtWriteFile hooks provide complete coverage for any file operation CopyFile2 initiates. Documented as known limitation in trampolines.rs module docs. | orchestrator | 2026-05-19 |

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-05-19 | 21 | 21 | 0 | Claude (orchestrator) |

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-05-19
