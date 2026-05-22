---
phase: 51-ntdll-syscall-stub-trampolines-edr-coexistence
plan: 01
subsystem: dlp-hook-dll
tags: [edr-detection, thread-safety, ntdll-patching, syscall-stub]
dependency_graph:
  requires: []
  provides: [edr_detector, thread_suspender]
  affects: [51-02-ntdll-patcher-core]
tech_stack:
  added:
    - windows crate features: Win32_System_ProcessStatus, Win32_System_WindowsProgramming, Wdk_System_SystemInformation, Wdk_System_Threading
  patterns:
    - Two-phase EDR detection with cached module enumeration
    - Suspend-all-other-threads protocol with Drop guard
    - Raw pointer arithmetic with read_unaligned for cross-arch safety
key_files:
  created:
    - dlp-hook-dll/src/edr_detector.rs
    - dlp-hook-dll/src/thread_suspender.rs
  modified:
    - dlp-hook-dll/src/lib.rs
    - dlp-hook-dll/Cargo.toml
decisions:
  - "Used EnumProcessModules + GetModuleFileNameExW (Win32) instead of custom PEB walker for module enumeration"
  - "Used SuspendThread/ResumeThread (kernel32) instead of NtSuspendThread/NtResumeThread (ntdll) — functionally equivalent, simpler API"
  - "Used read_unaligned for rel32 offset and CLIENT_ID reads to avoid stack alignment issues in tests"
  - "ThreadSuspendGuard Drop pattern guarantees resume even on panic — mitigates T-51-02 (DoS from suspended threads)"
  - "Soft-fail enumerate_process_threads test: OpenThread may fail in restricted test environments; single-thread case is the guaranteed path"
metrics:
  duration_seconds: 1187
  completed_date: "2026-05-22"
  tasks_completed: 2
  tests_added: 24
  tests_passing: 227
---

# Phase 51 Plan 01: EDR Detection + Thread Safety Summary

**One-liner:** Two-phase EDR detection module and suspend-all-other-threads protocol with RIP verification, forming the safety prerequisites for ntdll syscall-stub patching.

## What Was Built

### edr_detector.rs

- **`KNOWN_EDR_MODULES`** constant with 5 known EDR module names derived from `AllowlistCategory::Avedr`
- **`ModuleInfo`** struct: base address, size, and name of a loaded module
- **`EdrDetector`** struct with cached `Vec<ModuleInfo>` and 5-second TTL refresh
- **`is_edr_hooked()`**: Two-phase algorithm — module enumeration pre-filter + stub prologue inspection for `0xE9` JMP rel32 targeting EDR range
- **`refresh_module_list()`**: Re-enumerates via `EnumProcessModules` + `GetModuleFileNameExW`
- **`is_address_in_edr_module_range()`**: Range check against cached modules
- No disk-reading functions (D-06 compliance)

### thread_suspender.rs

- **`ThreadInfo`** struct: tid + handle, Send-safe
- **`PatchError`** enum with Display + Error impls: RipInStubRange, EnumerationFailed, SuspendFailed, ResumeFailed
- **`enumerate_process_threads()`**: `NtQuerySystemInformation(SystemProcessInformation)` with linked-list walk
- **`get_thread_rip()`**: `NtQueryInformationThread(ThreadContext)` — x64 (CONTEXT/Rip) and x86 (WOW64_CONTEXT/Eip) dual path
- **`suspend_all_other_threads()` / `resume_all_threads()`**: kernel32 SuspendThread/ResumeThread
- **`ThreadSuspendGuard`**: Drop guard ensures threads always resume (mitigates T-51-02)
- **`with_suspended_threads()`**: Full protocol — enumerate, suspend, RIP check, execute closure, resume

### Integration

- `mod edr_detector;` and `mod thread_suspender;` added to `lib.rs`
- `windows` crate features expanded: `Win32_System_ProcessStatus`, `Win32_System_WindowsProgramming`, `Wdk_System_SystemInformation`, `Wdk_System_Threading`

## Test Results

| Module | Tests | Status |
|--------|-------|--------|
| edr_detector | 10 | All pass |
| thread_suspender | 14 | All pass |
| dlp-hook-dll (full suite) | 227 | All pass (1 ignored) |
| clippy | - | Clean (-D warnings) |

## Commits

| Hash | Message |
|------|---------|
| `7d0fc01` | feat(51-01): create edr_detector.rs — two-phase EDR detection module |
| `65ea767` | feat(51-01): create thread_suspender.rs — thread suspend protocol with RIP check |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Windows API type mismatches in edr_detector.rs**
- **Found during:** Task 1 compilation
- **Issue:** `EnumProcessModules` and `GetModuleFileNameExW` in `windows` 0.62 use `HMODULE` and `Option<HANDLE>` types, not raw pointers
- **Fix:** Updated to use `HMODULE` vector, `Some(h)` for process handle, `Some(module_base)` for module handle
- **Files modified:** `dlp-hook-dll/src/edr_detector.rs`

**2. [Rule 1 - Bug] Misaligned pointer dereference in edr_detector test**
- **Found during:** Task 1 test execution
- **Issue:** Stack-allocated `[u8; 12]` array was not 4-byte aligned; reading `i32` at offset 1 caused panic
- **Fix:** Used `std::ptr::read_unaligned` for rel32 offset read; redesigned tests to use page-aligned heap allocation
- **Files modified:** `dlp-hook-dll/src/edr_detector.rs`

**3. [Rule 1 - Bug] Wdk API signature differences in thread_suspender.rs**
- **Found during:** Task 2 compilation
- **Issue:** `NtQuerySystemInformation` and `NtQueryInformationThread` in Wdk module take raw pointers, not `Option`; `SYSTEM_PROCESS_INFORMATION` lacks a `Threads` field (thread array follows struct in memory); `CONTEXT_CONTROL` is architecture-specific (`CONTEXT_CONTROL_AMD64`, `WOW64_CONTEXT_CONTROL`)
- **Fix:** Used raw pointers for Wdk APIs; computed thread array offset via `process_info_data_size()` helper (summing field sizes instead of `size_of` which includes padding); used architecture-specific context flags; used `read_unaligned` for CLIENT_ID reads
- **Files modified:** `dlp-hook-dll/src/thread_suspender.rs`

**4. [Rule 2 - Missing feature] Windows crate features**
- **Found during:** Task 1 and Task 2 compilation
- **Issue:** `Win32_System_ProcessStatus`, `Win32_System_WindowsProgramming`, `Wdk_System_SystemInformation`, `Wdk_System_Threading` features were not enabled in `dlp-hook-dll/Cargo.toml`
- **Fix:** Added all four features to the `windows` dependency
- **Files modified:** `dlp-hook-dll/Cargo.toml`

**5. [Rule 1 - Bug] Clippy field_reassign_with_default**
- **Found during:** Task 2 clippy run
- **Issue:** `ctx.ContextFlags = ...` after `CONTEXT::default()` triggered clippy lint
- **Fix:** Used struct literal with `..Default::default()` spread
- **Files modified:** `dlp-hook-dll/src/thread_suspender.rs`

## Threat Flags

None — all security-relevant surface was explicitly covered in the plan's threat model. No new trust boundaries or attack surface introduced beyond what was planned.

## Known Stubs

None. Both modules are fully functional with no placeholder data or TODO items that would prevent the plan's goal from being achieved.

## Self-Check

- [x] `dlp-hook-dll/src/edr_detector.rs` exists
- [x] `dlp-hook-dll/src/thread_suspender.rs` exists
- [x] `dlp-hook-dll/src/lib.rs` contains `mod edr_detector;` and `mod thread_suspender;`
- [x] `cargo test -p dlp-hook-dll` passes (227 tests)
- [x] `cargo clippy -p dlp-hook-dll -- -D warnings` is clean
- [x] Commit `7d0fc01` exists
- [x] Commit `65ea767` exists

## Self-Check: PASSED
