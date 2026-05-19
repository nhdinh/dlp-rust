---
phase: 48
slug: hook-dll-surface-expansion-crash-hardening-build-harness
status: verified
nyquist_compliant: true
wave_0_complete: true
created: 2026-05-15
updated: 2026-05-19
---

# Phase 48 -- Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Built-in `#[test]` + `cargo test` (Rust standard) |
| **Config file** | None -- inline `#[cfg(test)]` modules |
| **Quick run command** | `cargo test -p dlp-hook-dll` |
| **Full suite command** | `cargo test --workspace` |
| **Estimated runtime** | ~30 seconds (unit) / ~120 seconds (workspace) |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p dlp-hook-dll`
- **After every plan wave:** Run `cargo test --workspace`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Test Location | Automated Command | Status |
|---------|------|------|-------------|------------|-----------------|-----------|---------------|-------------------|--------|
| 48-01-T1 | 01 | 1 | BLOCK-01 | T-48-01 | catch_unwind catches panic in trampoline | unit | crash_guard.rs | `cargo test -p dlp-hook-dll guard_trampoline` | green |
| 48-01-T1 | 01 | 1 | BLOCK-01 | T-48-01 | SEH guard compiles for BOOL/HANDLE/NTSTATUS | unit | crash_guard.rs | `cargo test -p dlp-hook-dll seh_guard` | green |
| 48-01-T1 | 01 | 1 | BLOCK-01 | T-48-03a | Reentrancy guard prevents nested hook entry | unit | crash_guard.rs | `cargo test -p dlp-hook-dll reentrancy_guard` | green |
| 48-01-T2 | 01 | 1 | BLOCK-01 | T-48-03 | fail_closed! macro returns correct deny values | unit | fail_closed.rs | `cargo test -p dlp-hook-dll fail_closed` | green |
| 48-01-T2 | 01 | 1 | BLOCK-01 | T-48-03 | apply_deny_return dispatches correctly at runtime | unit | fail_closed.rs | `cargo test -p dlp-hook-dll apply_deny_return` | green |
| 48-01-T3 | 01 | 1 | BLOCK-01 | T-48-02 | Thread-local buffer reused (capacity >= 4096) | unit | pipe_client.rs | `cargo test -p dlp-hook-dll thread_local_buffer` | green |
| 48-01-T3 | 01 | 1 | BLOCK-01 | T-48-02 | Thread-local buffer is thread-isolated | unit | pipe_client.rs | `cargo test -p dlp-hook-dll thread_local_buffer_is_thread` | green |
| 48-02-T1 | 02 | 1 | BLOCK-02 | T-48-07a | MAX_IMPORT_DESCRIPTORS=512 bound enforced | unit | pe_utils.rs | `cargo test -p dlp-hook-dll max_import_descriptors` | green |
| 48-02-T1 | 02 | 1 | BLOCK-02 | T-48-04 | patch_iat and restore_iat round-trip | unit | pe_utils.rs | `cargo test -p dlp-hook-dll patch_iat_and_restore` | green |
| 48-02-T1 | 02 | 1 | BLOCK-02 | T-48-04 | find_iat_entry respects bounds on malformed PE | unit | pe_utils.rs | `cargo test -p dlp-hook-dll find_iat_entry_respects` | green |
| 48-02-T2 | 02 | 1 | BLOCK-02 | T-48-05 | SetFileInformationByHandle blocks only classes 4,6,10 | unit | trampolines.rs | `cargo test -p dlp-hook-dll hook_setfileinfo` | green |
| 48-02-T3 | 02 | 1 | BLOCK-02 | T-48-06 | Path hashing prevents full path exposure in debug logs | unit | lib.rs | `cargo test -p dlp-hook-dll hash_path` | green |
| 48-02-T3 | 02 | 1 | BLOCK-02 | T-48-07b | Multi-path ops evaluate all paths (Move/Copy/Replace) | unit | trampolines.rs | `cargo test -p dlp-hook-dll hook_movefile` | green |
| 48-03-T1 | 03 | 2 | BLOCK-03 | T-48-08 | 32K cap truncates long PCWSTR paths | unit | lib.rs | `cargo test -p dlp-hook-dll pcwstr_32k_cap` | green |
| 48-03-T1 | 03 | 2 | BLOCK-03 | T-48-08 | 32K exact boundary handled correctly | unit | lib.rs | `cargo test -p dlp-hook-dll pcwstr_32k_exact` | green |
| 48-03-T1 | 03 | 2 | BLOCK-03 | T-48-10 | HOOKS table has exactly 12 entries | unit | lib.rs | `cargo test -p dlp-hook-dll hook_descriptor_table` | green |
| 48-03-T1 | 03 | 2 | BLOCK-03 | T-48-10 | Hook descriptors are valid (non-empty, non-null) | unit | lib.rs | `cargo test -p dlp-hook-dll hook_descriptors_are` | green |
| 48-03-T1 | 03 | 2 | BLOCK-03 | T-48-09 | HandleHookRequest bincode round-trip | unit | lib.rs | `cargo test -p dlp-hook-dll classify_handle_roundtrip` | green |
| 48-03-T1 | 03 | 2 | BLOCK-03 | T-48-10a | IAT patch and restore round-trip (smoke) | unit | lib.rs | `cargo test -p dlp-hook-dll iat_patch_and_restore` | green |
| 48-03-T1 | 03 | 2 | BLOCK-03 | T-48-10b | extract_nt_path null handling | unit | lib.rs | `cargo test -p dlp-hook-dll extract_nt_path` | green |
| 48-03-T2 | 03 | 2 | BLOCK-03 | -- | Workspace regression tests pass (no dlp-cloud-hook) | integration | workspace | `cargo test --workspace` | green |
| 48-04-T1 | 04 | 2 | BLOCK-04 | T-48-12 | x86 DLL builds successfully | build | CI + local | `cargo build --target i686-pc-windows-msvc -p dlp-hook-dll` | green |
| 48-04-T2 | 04 | 2 | BLOCK-04 | T-48-11 | HookInjector rejects invalid inputs (PID 0, missing DLL, long path) | unit | hook_injector.rs | `cargo test -p dlp-agent test_injector_rejects` | green |
| 48-04-T2 | 04 | 2 | BLOCK-04 | T-48-11 | HookInjector successfully injects DLL | unit | hook_injector.rs | `cargo test -p dlp-agent test_injector_successfully` | green |
| 48-04-T2 | 04 | 2 | BLOCK-04 | T-48-11 | IsModuleLoaded finds kernel32 | unit | hook_injector.rs | `cargo test -p dlp-agent test_is_module_loaded` | green |
| 48-05-T1 | 05 | 3 | BLOCK-10 | T-48-14..17 | Release workflow YAML structurally valid | static | release.yml | Manual review + python xml check | green |
| 48-05-T1 | 05 | 3 | BLOCK-10 | T-48-14..17 | WiX installer XML valid with both DLL components | static | DLPAgent.wxs | `python -c "import xml.etree.ElementTree as ET; ET.parse('installer/DLPAgent.wxs')"` | green |

*Status: pending | green | red | flaky*

---

## Wave 0 Requirements

- [x] `dlp-hook-dll/src/crash_guard.rs` -- SEH + catch_unwind test fixtures (13 tests)
- [x] `dlp-hook-dll/src/fail_closed.rs` -- DenyReturn enum + macro tests (12 tests)
- [x] `dlp-hook-dll/src/pe_utils.rs` -- x86 find_iat_entry test with mock PE (5 tests)
- [x] `.github/workflows/release.yml` -- signing workflow (BLOCK-10) -- validated
- [x] `rustup target add i686-pc-windows-msvc` -- CI toolchain install step (build.yml)
- [x] `installer/DLPAgent.wxs` -- add dlp_hook_dll.dll and dlp_hook_dll_x86.dll components

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Authenticode signature verification on physical binary | BLOCK-10 | Requires actual cert + tag push | 1. Push v0.10.0-test tag 2. Verify signtool verify /pa passes 3. Check Properties > Digital Signatures |
| x86 DLL injection into WOW64 process | BLOCK-04 | Requires 32-bit test binary + live injection | 1. Build 32-bit notepad clone 2. Run injector with IsWow64Process 3. Verify DllMain hello message in pipe |
| SEH access-violation full recovery (C __try/__except) | BLOCK-01 | Requires C-compiled shim + real process context | 1. Build C __try/__except wrapper 2. Inject AV-inducing stub 3. Verify host process survives without WerFault entry |

---

## Validation Audit 2026-05-19

| Metric | Count |
|--------|-------|
| Requirements mapped | 24 |
| Automated tests | 22 |
| Build/static validations | 3 |
| Manual-only | 3 |
| Gaps found | 0 |
| Resolved | 0 |
| Escalated | 0 |

---

## Validation Sign-Off

- [x] All tasks have automated verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 30s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** verified 2026-05-19
