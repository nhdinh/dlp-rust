---
phase: 48-hook-dll-surface-expansion-crash-hardening-build-harness
reviewed: 2026-05-16T00:00:00Z
depth: standard
files_reviewed: 14
files_reviewed_list:
  - dlp-hook-dll/src/crash_guard.rs
  - dlp-hook-dll/src/fail_closed.rs
  - dlp-hook-dll/src/pipe_client.rs
  - dlp-hook-dll/src/pe_utils.rs
  - dlp-hook-dll/src/trampolines.rs
  - dlp-common/src/hook_ipc.rs
  - dlp-hook-dll/src/lib.rs
  - dlp-hook-dll/Cargo.toml
  - dlp-agent/src/service.rs
  - .github/workflows/build.yml
  - dlp-common/src/usb.rs
  - dlp-common/src/disk.rs
  - .github/workflows/release.yml
  - installer/DLPAgent.wxs
findings:
  critical: 4
  warning: 7
  info: 3
  total: 14
status: issues_found
---

# Phase 48: Code Review Report

**Reviewed:** 2026-05-16
**Depth:** standard
**Files Reviewed:** 14
**Status:** issues_found

## Summary

This review covers the Phase 48 hook DLL surface expansion, crash hardening, and build harness changes. The code introduces 12 trampoline hooks for Windows file I/O APIs, SEH-based crash guards, IAT patching utilities, and CI/CD signing pipelines.

Key concerns:
- **SEH handler is fundamentally broken** -- it catches AVs but returns `EXCEPTION_CONTINUE_SEARCH`, which propagates the exception and crashes the process anyway. The handler cannot safely resume execution without a C `__try/__except` shim.
- **Reentrancy guard is not panic-safe** -- if the inner closure panics, `REENTRANT` stays `true`, permanently disabling hooks on that thread.
- **IAT patching has multiple safety gaps** -- missing bounds checks on DOS header, NT headers, and import descriptor fields; unbounded IAT inner loop; no validation of `e_lfanew`.
- **Trampoline signatures have ABI mismatches** -- `CopyFileExW` and `SetFileInformationByHandle` use incorrect parameter types that will cause stack corruption on x86.
- **Packed struct UB in usb.rs/disk.rs** -- raw pointer arithmetic on `SP_DEVICE_INTERFACE_DETAIL_DATA_W` is correct, but the `required` size calculation in `disk.rs` is off by `std::mem::size_of::<u32>()` vs `std::mem::size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>()`.
- **Authenticode signing pipeline has path mismatches** -- `release.yml` signs `dlp_hook_dll.dll` but `Cargo.toml` produces `dlp_hook_dll.dll` (underscores), while `DLPAgent.wxs` references `dlp_hook_dll.dll` and `dlp_hook_dll_x86.dll`. The crate name uses hyphens in Cargo.toml but underscores in the file references -- this is actually consistent with Cargo's auto-replacement, but the x86 variant name mismatch (`dlp_hook_dll_x86.dll` in WiX vs `dlp_hook_dll.dll` in the i686 target dir) is a real packaging bug.

## Critical Issues

### CR-01: SEH handler returns EXCEPTION_CONTINUE_SEARCH, crashing the process anyway

**File:** `dlp-hook-dll/src/crash_guard.rs:94-119`
**Issue:** The `seh_handler` vectored exception handler catches `EXCEPTION_ACCESS_VIOLATION`, stores `Err(())` in a thread-local, then returns `EXCEPTION_CONTINUE_SEARCH` (0). This means the exception **continues propagating** to the next handler. Since there is no `__try/__except` block around the faulting instruction, the OS will eventually invoke the default unhandled exception filter and terminate the process.

The code's own comment at line 110-114 acknowledges this: "A vectored exception handler alone cannot safely resume execution after an AV without modifying the execution context." But the function is still exposed as a public API with a doc comment claiming it "returns `Err(())` so the caller can return gracefully instead of crashing."

This is a **critical safety bug**: callers believe they are protected, but the process still crashes. The `seh_guard` function should either be marked `unsafe` with stronger warnings, or removed until the C `__try/__except` shim is implemented.

**Fix:**
```rust
// Option 1: Remove seh_guard from public API until C shim is ready.
// Option 2: Mark as unsafe with explicit warning that it does NOT prevent crashes.

/// # Safety
///
/// WARNING: This function DOES NOT prevent the process from crashing on AV.
/// It records that an AV occurred, but the exception still propagates.
/// Full AV recovery requires a C-compiled __try/__except shim.
pub unsafe fn seh_guard<T>(f: impl FnOnce() -> T) -> Result<T, ()> { ... }
```

### CR-02: Reentrancy guard leaks on panic -- permanently disables hooks on thread

**File:** `dlp-hook-dll/src/crash_guard.rs:226-234`
**Issue:** `with_reentrancy_guard` sets `REENTRANT.set(true)` before calling `f()`, then sets it back to `false` after. If `f()` panics (which is possible -- trampolines call `guard_trampoline` which uses `catch_unwind`, but `with_reentrancy_guard` is also called inside the closure passed to `guard_trampoline`), the panic is caught by `catch_unwind`. However, if `with_reentrancy_guard` is used *outside* `guard_trampoline` (or if a panic occurs in the fallback path), the `REENTRANT` flag is never reset.

More critically: `guard_trampoline` wraps the ENTIRE trampoline body including `with_reentrancy_guard`. If the inner `f()` panics, `catch_unwind` catches it and calls `fallback()`. But `REENTRANT` was set to `true` before the panic and is never reset because the `REENTRANT.set(false)` line is after the panic point. The fallback path then executes with `REENTRANT` still `true`, causing it to recursively call fallback again, which may or may not be a problem depending on nesting. But more importantly, on the NEXT call to any hook on this thread, `REENTRANT` is still `true`, so ALL hooks bypass classification permanently.

**Fix:**
```rust
pub fn with_reentrancy_guard<T>(f: impl FnOnce() -> T, fallback: impl FnOnce() -> T) -> T {
    if REENTRANT.get() {
        return fallback();
    }
    REENTRANT.set(true);
    // Use a guard struct to ensure cleanup on panic or normal return.
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            REENTRANT.set(false);
        }
    }
    let _guard = Guard;
    f()
}
```

### CR-03: IAT patching missing bounds checks -- OOB read/UB on malformed PE

**File:** `dlp-hook-dll/src/pe_utils.rs:61-129`
**Issue:** `find_iat_entry` performs raw pointer arithmetic on `module_base` without validating that the computed offsets lie within the module's mapped memory. Specifically:

1. **Line 70:** `e_lfanew` is read from offset `0x3C` without checking if `module_base` is at least `0x40` bytes long.
2. **Line 71:** `module_base.offset(e_lfanew)` -- `e_lfanew` could be negative, zero, or point outside the module.
3. **Line 72:** `nt_headers.offset(24)` -- no validation that this is within bounds.
4. **Line 80:** `optional_header.offset(DATA_DIRECTORY_OFFSET)` -- no validation.
5. **Line 82:** `data_directory.offset(8)` -- no validation.
6. **Line 98:** `desc.offset(12)` reads `name_rva` without checking descriptor bounds.
7. **Line 103-106:** `name_ptr` string scan is unbounded -- reads until null byte with no limit, potentially scanning across the entire address space.
8. **Line 112-121:** The inner IAT loop has NO bounds limit -- it scans `iat` entries until it finds a zero or a match, potentially reading unbounded memory.

While `MAX_IMPORT_DESCRIPTORS` limits the outer loop, the inner IAT loop and the name string scan are both unbounded. A malformed PE with a non-terminating IAT or a `name_rva` pointing to non-null memory could cause an infinite loop or read arbitrary memory.

**Fix:** Add bounds validation at every step. Track `module_size` (from `VirtualQuery` or passed in) and verify all offsets before dereferencing. Cap the inner IAT scan to a reasonable limit (e.g., 4096 entries). Cap the name string scan to `MAX_IMPORT_DESCRIPTORS` or similar.

### CR-04: Trampoline signatures mismatch Windows API -- stack corruption on x86

**File:** `dlp-hook-dll/src/trampolines.rs:536-613` and `777-864`
**Issue:** Two trampolines have parameter types that do not match the Windows API:

1. **`HookCopyFileExW`** (line 537): The `lpprogressroutine` parameter is declared as `*mut std::ffi::c_void`, but the actual Windows `CopyFileExW` signature uses `LPPROGRESS_ROUTINE` (a function pointer type). On x86, a function pointer and a `*mut c_void` have the same size (4 bytes), but the ABI calling convention may differ. More importantly, the `pbcancel` parameter is `*mut i32`, but Windows uses `LPBOOL` (`*mut BOOL`). `BOOL` is `i32` on Windows, so this happens to match, but it's semantically wrong and fragile.

2. **`HookSetFileInformationByHandle`** (line 778): The `fileinformationclass` parameter is declared as `i32`, but Windows uses `FILE_INFO_BY_HANDLE_CLASS` (a `u32` enum). On x86, `i32` and `u32` have the same size, but signed vs unsigned matters for comparisons and could cause issues with the class-filter logic at lines 795-797.

These mismatches are particularly dangerous because the trampolines are called via IAT patching -- the caller pushes arguments according to the original API signature, but the trampoline's parameter layout must match exactly. While these specific mismatches happen to have the same size, they are latent bugs that could break with future Windows API changes or on different architectures.

**Fix:** Use the exact Windows types from the `windows` crate:
```rust
// For HookCopyFileExW:
use windows::Win32::Storage::FileSystem::LPPROGRESS_ROUTINE;
// lpprogressroutine: LPPROGRESS_ROUTINE,
// pbcancel: *mut windows::core::BOOL,

// For HookSetFileInformationByHandle:
use windows::Win32::Storage::FileSystem::FILE_INFO_BY_HANDLE_CLASS;
// fileinformationclass: FILE_INFO_BY_HANDLE_CLASS,
```

## Warnings

### WR-01: `pcwstr_to_string` uses `ptr.0` directly -- field access on raw pointer

**File:** `dlp-hook-dll/src/lib.rs:617-627`
**Issue:** `pcwstr_to_string` accesses `ptr.0` where `ptr` is a `PCWSTR`. `PCWSTR` is a transparent wrapper around `*const u16`, but accessing `.0` on a raw pointer type is relying on implementation details. The `windows` crate provides `PCWSTR::as_ptr()` which is the correct public API.

**Fix:**
```rust
let mut len = 0usize;
while len < MAX_WIDE_CHARS && *ptr.as_ptr().add(len) != 0 {
    len += 1;
}
let slice = std::slice::from_raw_parts(ptr.as_ptr(), len);
```

### WR-02: `extract_nt_path` does not validate `ObjectName` buffer length

**File:** `dlp-hook-dll/src/lib.rs:632-652`
**Issue:** `extract_nt_path` reads a `UNICODE_STRING` from raw memory at architecture-specific offsets. It reads `length` from `object_name_ptr` (offset 0), then uses that length to construct a slice. However:
1. It does not validate that `length` is even (Unicode strings must have even length).
2. It does not validate that `length / 2` does not exceed `MAX_WIDE_CHARS` in a way that could cause overflow.
3. It trusts the `buffer` pointer without checking if it's null or within valid memory.

While `MAX_WIDE_CHARS` provides some protection, a malformed `OBJECT_ATTRIBUTES` could have a `length` value that causes `chars = length / 2` to overflow if `length` is `u16::MAX` (65535), giving `chars = 32767` which is under the cap. But if the actual buffer is shorter, this is an out-of-bounds read.

**Fix:** Add a check that `length <= MAX_WIDE_CHARS * 2` and that `buffer` is non-null before creating the slice.

### WR-03: `patch_iat` restores protection even when first VirtualProtect fails

**File:** `dlp-hook-dll/src/pe_utils.rs:144-165`
**Issue:** `patch_iat` calls `VirtualProtect` to make the IAT writable, writes the new pointer, then calls `VirtualProtect` again to restore the original protection. If the FIRST `VirtualProtect` succeeds but the second fails, the IAT remains with `PAGE_EXECUTE_READWRITE` permissions. While the function returns `true` (because `ok` was set from the first call), the restoration failure is silently ignored.

More importantly, if the first `VirtualProtect` fails, the function returns `false` before writing, which is correct. But if the write succeeds and the second `VirtualProtect` fails, there's no indication.

**Fix:** Check the return value of the second `VirtualProtect` and return `false` if restoration fails. Alternatively, document that restoration failure leaves the page in a more permissive state.

### WR-04: `pipe_client` uses `RefCell<Vec<u8>>` without try_borrow_mut -- could panic

**File:** `dlp-hook-dll/src/pipe_client.rs:17-25, 74-103`
**Issue:** The thread-local `PIPE_BUFFER` uses `RefCell<Vec<u8>>`. In `send_request`, it calls `buf.borrow_mut()`. If `send_request` were called recursively (e.g., from within a hook that triggers another hook), this would panic at runtime because `RefCell` does not allow reentrant mutable borrows.

While the reentrancy guard in `crash_guard.rs` is supposed to prevent this, the panic would occur BEFORE the reentrancy guard is checked (since `send_request` is called from within the `with_reentrancy_guard` closure). If the reentrancy guard ever fails or is bypassed, this would cause a panic instead of a graceful fallback.

**Fix:** Use `try_borrow_mut()` and handle the error gracefully:
```rust
let mut buffer = buf.try_borrow_mut().map_err(|_| PipeError::ConnectionRefused)?;
```

### WR-05: `send_raw_request` does not set pipe mode, and `send_request` ignores SetNamedPipeHandleState errors

**File:** `dlp-hook-dll/src/pipe_client.rs:68-71, 115-119`
**Issue:** `send_request` calls `SetNamedPipeHandleState` but ignores the result with `let _ =`. If this fails, the pipe remains in byte-read mode instead of message-read mode, which could cause `read_frame` to misparse length-prefixed frames. `send_raw_request` has the same issue.

**Fix:** Check the result of `SetNamedPipeHandleState` and return an error if it fails:
```rust
unsafe {
    let mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(pipe, Some(&mode), None, None)
        .map_err(|e| PipeError::Win32(e.code().0 as u32 & 0xFFFF))?;
}
```

### WR-06: `read_frame` allocates `Vec` based on untrusted length prefix -- potential DoS

**File:** `dlp-hook-dll/src/pipe_client.rs:183-196`
**Issue:** `read_frame` reads a 4-byte length prefix from the pipe and allocates a `Vec<u8>` of that size. While there is a `MAX_PAYLOAD` check (64 MiB), a malicious or buggy pipe server could send a length of 64 MiB, causing the hook DLL to allocate a large buffer. In a hooked process with many threads, this could cause memory pressure.

More importantly, the 64 MiB limit is quite high for a hook DLL that should be lightweight. The classification request/response payloads are typically small (path strings + metadata). A more reasonable limit would be 1 MiB or less.

**Fix:** Reduce `MAX_PAYLOAD` to a value appropriate for the expected payload size, e.g., `1_048_576` (1 MiB).

### WR-07: `DLPAgent.wxs` references `dlp_hook_dll_x86.dll` but release.yml produces `dlp_hook_dll.dll` for x86

**File:** `installer/DLPAgent.wxs:143-148`, `.github/workflows/release.yml:69,97`
**Issue:** The WiX installer expects the x86 hook DLL to be named `dlp_hook_dll_x86.dll` (line 145), but the release workflow builds it as `target/i686-pc-windows-msvc/release/dlp_hook_dll.dll` (line 69). The file is NOT renamed during the build or signing steps.

This means the MSI installer will fail to find `dlp_hook_dll_x86.dll` at install time, or will install a missing file. The agent's `HookInjector` (in `service.rs`) looks for `dlp_hook_dll_x86.dll` in the same directory as the executable, so the runtime will also fail to find it.

**Fix:** Either:
1. Rename the x86 DLL after building: `copy target\i686-pc-windows-msvc\release\dlp_hook_dll.dll target\i686-pc-windows-msvc\release\dlp_hook_dll_x86.dll` in the release workflow, OR
2. Change the WiX source and agent code to reference `dlp_hook_dll.dll` for both architectures (but this would cause collisions if both are installed side-by-side).

Option 1 is preferred.

## Info

### IN-01: `apply_deny_return` does not call `SetLastError` for BoolFalse/InvalidHandleValue

**File:** `dlp-hook-dll/src/fail_closed.rs:112-118`
**Issue:** The `apply_deny_return` function is documented as a runtime-dispatch version of the `fail_closed!` macro. However, while the macro calls `SetLastError(ERROR_ACCESS_DENIED)` for `BoolFalse` and `InvalidHandleValue`, the `apply_deny_return` function does not. This means trampolines that use `apply_deny_return` at runtime will return the correct value but with an incorrect `LastError`.

This is currently not a bug in practice because all trampolines use the `fail_closed!` macro directly. But if future code uses `apply_deny_return`, it will be subtly incorrect.

**Fix:** Add `SetLastError` calls to `apply_deny_return`, or document that it does not set `LastError` and callers must do so.

### IN-02: `build.yml` does not build `dlp-hook-dll` for x64 -- only x86

**File:** `.github/workflows/build.yml:47-50`
**Issue:** The build workflow builds the x86 hook DLL (`i686-pc-windows-msvc`) but does not explicitly build the x64 version. The workspace build (line 43) will build the default target (x64), but since `dlp-hook-dll` uses `crate-type = ["cdylib"]`, it will be built as part of the workspace. However, there is no explicit `cargo build -p dlp-hook-dll` for x64, which means the x64 DLL is not validated in CI with the same strictness as the x86 version.

**Fix:** Add an explicit x64 build step:
```yaml
- name: Build x64 hook DLL
  run: cargo build --target x86_64-pc-windows-msvc -p dlp-hook-dll
  env:
    RUSTFLAGS: "-D warnings"
```

### IN-03: `release.yml` does not verify Authenticode signatures with `/pa` after fallback signing

**File:** `.github/workflows/release.yml:111-127`
**Issue:** The release workflow has a `Verify signatures` step that runs `signtool verify /pa`. However, if the primary signing (DigiCert) fails and the fallback (Sectigo) succeeds, the verification step will still pass because `/pa` verifies that the file is signed with any valid Authenticode certificate, not specifically the DigiCert one.

This is not a bug per se, but it means the fallback path is not explicitly tested. If the fallback timestamp server is down or returns an invalid signature, the verification would catch it, but there's no separate verification that the fallback-signed binaries are actually valid.

**Fix:** The current verification is sufficient for production. No change needed, but consider adding a comment explaining that `/pa` accepts any valid signature.

---

_Reviewed: 2026-05-16_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
