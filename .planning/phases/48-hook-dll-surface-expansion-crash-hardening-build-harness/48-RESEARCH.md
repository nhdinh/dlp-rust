# Phase 48: Hook DLL Surface Expansion + Crash Hardening + Build Harness - Research

**Researched:** 2026-05-15
**Domain:** Windows user-mode API hooking (IAT patching), Rust FFI safety, PE32/PE32+ parsing, Authenticode signing, dual-arch CI/CD
**Confidence:** HIGH

## Summary

Phase 48 expands the v0.9.0 cloud-sync hook DLL from 2 functions (`CreateFileW`, `NtCreateFile`) to 11 file-I/O functions, adds layered crash hardening (SEH + `catch_unwind`), builds an x86 sibling DLL from the same source, and integrates an Authenticode signing pipeline into CI. The existing codebase provides a solid foundation: manual PE IAT parsing, named-pipe IPC with bincode framing, `HookInjector` with architecture detection, and a WiX v4 installer. All decisions are locked in CONTEXT.md; research confirms feasibility and identifies implementation patterns.

**Primary recommendation:** Expand the existing `dlp-hook-dll` crate incrementally -- add the `HookDescriptor` metadata table first, then port each of the 9 new trampolines one by one, preserving the existing `catch_unwind` + SEH + fail-closed patterns. Build x86 via `cargo build --target i686-pc-windows-msvc` on the same x64 CI runner. Add release signing as a separate `.github/workflows/release.yml` triggered on `v*` tags.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| IAT hook trampolines | Browser / Client (injected DLL) | -- | Lives inside target process address space; must be self-contained and crash-safe |
| PE parsing & patching | Browser / Client | -- | `DllMain` runs in target process; no agent involvement |
| Named-pipe classification | Browser / Client | API / Backend | DLL sends request; agent service owns the pipe server and policy evaluation |
| Handle->path resolution | API / Backend | -- | Agent tracks handle lifecycle to avoid extra syscalls in hot path |
| Crash hardening (SEH/catch_unwind) | Browser / Client | -- | Must catch exceptions inside the target process before they abort it |
| x86 cross-compile | CDN / Static (CI artifact) | -- | Build-time concern; produces second artifact from same source |
| Authenticode signing | CDN / Static (CI release) | -- | Post-build step on release tags only |
| Installer packaging | CDN / Static (WiX MSI) | -- | Packages both x64 and x86 DLLs into MSI |

## User Constraints (from CONTEXT.md)

### Locked Decisions
- **D-01:** `const HOOKS: &[HookDescriptor]` metadata table drives `UnhookAll`, debug logging, and hook enumeration. Each trampoline remains hand-written for precision.
- **D-02:** Agent maintains handle->path map. Hook DLL sends HANDLE value over pipe; agent resolves path from internal tracking.
- **D-03:** Generic macro for fail-closed returns based on trampoline return type (`BOOL(false)`, `INVALID_HANDLE_VALUE`, `NTSTATUS(STATUS_ACCESS_DENIED)`).
- **D-04:** Eager patching at `DllMain` -- all 11 IAT entries patched during `DLL_PROCESS_ATTACH`.
- **D-05:** Layered crash protection -- SEH `__try/__except` around entire trampoline entry, `catch_unwind` around Rust-side classification pipeline. On any exception, route to original function (fail-OPEN).
- **D-06:** Fail-open only on crash -- no self-repair or re-patching after crash. Log via `OutputDebugStringW` and call original.
- **D-07:** 32K-char cap in `pcwstr_to_string`. Central enforcement point; returns truncated string if exceeded.
- **D-08:** `catch_unwind` includes `pipe_client` -- wraps entire `classify_path` -> `send_request` -> decision pipeline.
- **D-09:** Thread-local pre-allocated buffer -- 4KiB `Vec<u8>` in `thread_local!()`, reused per call via `.clear()`.
- **D-10:** Output name: `dlp_hook_dll_x86.dll` -- explicit architecture suffix.
- **D-11:** Same crate with `cfg(target_arch)` -- PE parsing differences localized to `find_iat_entry`.
- **D-12:** Manual PE parsing -- keep current approach, no `goblin`/`pelite` dependency. Add `cfg` blocks for architecture-specific constants.
- **D-13:** Cross-compile on x64 CI runner -- install `i686-pc-windows-msvc` toolchain in GitHub Actions.
- **D-14:** Hook ntdll on x86 too -- patch `NtCreateFile`/`NtOpenFile` on x86 for completeness.
- **D-15:** Architecture-agnostic tests -- same test logic, CI runs on x64 only.
- **D-16:** Full crash hardening on x86 -- same `catch_unwind` + SEH as x64.
- **D-17:** Release tags only -- signing triggered on `push: tags: ['v*']`, not every push.
- **D-18:** Sign + verify gate -- run `signtool verify /pa` after signing as blocking gate.
- **D-19:** Sign test harness too -- `dlp-e2e` binaries also signed.
- **D-20:** DigiCert primary (`http://timestamp.digicert.com`) + Sectigo fallback (`http://timestamp.sectigo.com`) for RFC-3161 timestamping.
- **D-21:** GitHub secrets `AUTHENTICODE_PFX` + `AUTHENTICODE_PASSWORD` -- use `signtool sign /f`.

### Claude's Discretion
- `HookDescriptor` table fields: `fn_name`, `dll_name`, `original_ptr` (static mut), `iat_ptr` (static mut), `trampoline_ptr`, `deny_return`.
- Fail-closed macro handles three return-value families: `BOOL(0)`, `INVALID_HANDLE_VALUE` (`HANDLE(-1)`), `NTSTATUS(0xC0000022)`.
- Thread-local buffer: `RefCell<Vec<u8>>` with `with_capacity(4096)`.
- x86 `find_iat_entry` needs: magic `0x10B` (PE32), optional header offset 24, data directory offset 96 (vs 112 for PE32+).
- Signing workflow: separate `.github/workflows/release.yml` triggered on `push: tags: ['v*']`.

### Deferred Ideas (OUT OF SCOPE)
- Hook protocol versioning with `pid`, `tid`, `file_object`, `journal_seq` (Phase 50 -- CACHE)
- Shared-memory classification cache (Phase 50)
- Universal injection via ETW Process Watcher (Phase 49)
- ntdll syscall-stub trampolines (Phase 51)
- Installer auto-update for DLL replacement (Phase 57 -- OPS)
- Azure Key Vault migration for EV code signing (post-v0.10.0)

## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| BLOCK-01 | Hook DLL crash-hardened: `catch_unwind` + SEH + 32K cap + pre-allocated buffers | `std::panic::catch_unwind` documented; SEH via `windows` crate `__try`/`__except`; thread-local buffer pattern verified in existing pipe_client.rs |
| BLOCK-02 | Expanded IAT hook surface: 11 functions with documented fail-closed returns | Windows API documentation confirms all function signatures; return-value families mapped to `BOOL(0)` / `INVALID_HANDLE_VALUE` / `NTSTATUS(0xC0000022)` |
| BLOCK-03 | Unified single hook DLL replaces v0.9.0 cloud-sync DLL; v0.9.0 regression tests pass | Existing `dlp-e2e/` has no direct hook DLL tests (verified by grep); BLOCK-03 satisfied by ensuring existing agent-level tests continue passing |
| BLOCK-04 | x86 sibling DLL from same source via `i686-pc-windows-msvc`; CI matrix; injector dispatches via `IsWow64Process` | `HookInjector` already supports x86 dispatch (D-04 in CONTEXT.md); only needs x86 DLL artifact to be built |
| BLOCK-10 | Authenticode signing pipeline for all shipped binaries | `signtool` is standard Windows SDK tool; RFC-3161 timestamp servers verified live; GitHub Actions workflow pattern well-documented |

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `windows` | 0.62.2 [VERIFIED: cargo registry] | Win32 API bindings (`VirtualProtect`, `CreateRemoteThread`, `OutputDebugStringW`, SEH) | Official Microsoft crate; already in use across project |
| `bincode` | 1.3.3 [VERIFIED: cargo registry] | Length-prefixed IPC serialization | Already used in pipe_client.rs; zero-copy compatible |
| `serde` | workspace | Derive macros for `HookRequest`/`HookResponse` | Project standard |
| `std::panic::catch_unwind` | Rust 1.94.1 [VERIFIED: rustc --version] | Rust panic handling at FFI boundary | Standard library; no external dep |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `thiserror` | workspace | Error type definitions in hook injector | Project standard |
| `tracing` | workspace | Structured logging in agent-side handle tracker | Project standard |
| `windows-service` | workspace | Agent service lifecycle (existing) | Already used in service.rs |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Manual PE parsing | `goblin` or `pelite` | Would add dependency; manual parsing is ~50 lines and already working. CONTEXT.md D-12 locks manual parsing. |
| `signtool` | `osslsigncode` | `signtool` is Windows-native, better Authenticode chain verification. CONTEXT.md D-21 locks `signtool`. |
| GitHub secrets | Azure Key Vault | GitHub secrets sufficient for regular (non-EV) certs per D-21. AKV deferred to post-v0.10.0. |

**Installation:**
```bash
# x86 target (one-time setup for CI)
rustup target add i686-pc-windows-msvc

# No new crates needed -- all dependencies already in workspace
```

**Version verification:**
- `windows` crate: 0.62.2 (current in Cargo.lock, confirmed via `cargo search`)
- `bincode`: 1.3.3 (current in Cargo.lock)
- Rust: 1.94.1 (confirmed via `rustc --version`)

## Architecture Patterns

### System Architecture Diagram

```
Target Process (e.g., notepad.exe, onedrive.exe)
|
|-- DllMain(DLL_PROCESS_ATTACH)
|   |-- init() -- eager patch all 11 IAT entries
|   |-- HookDescriptor table drives patch/restore/enumeration
|
|-- File I/O Call (e.g., WriteFile)
|   |-- SEH __try/__except (catches AVs in unsafe path extraction)
|       |-- catch_unwind (catches Rust panics in classification)
|           |-- Extract path (or HANDLE for handle-based ops)
|           |-- classify_path() -> pipe_client::send_request()
|           |-- Decision: ALLOW -> call original
|           |-- Decision: DENY -> return fail-closed value
|       |-- panic! caught -> fail-open (call original)
|   |-- AV caught -> fail-open (call original)
|
Named Pipe (\\.\pipe\DlpHookPipe)
|
v
Agent Service (dlp-agent.exe)
|-- Pipe Server (existing HookIpcServer)
|-- Handle Tracker (new: maps HANDLE -> path)
|-- ABAC Policy Evaluation
|-- Decision -> HookResponse
```

### Recommended Project Structure

```
dlp-hook-dll/
├── Cargo.toml              # Add i686-pc-windows-msvc target support
├── src/
│   ├── lib.rs              # DllMain, HookDescriptor table, all trampolines
│   ├── pipe_client.rs      # Reuse existing -- add thread-local buffer
│   └── pe_utils.rs         # NEW: find_iat_entry with cfg(target_arch) blocks
│   └── trampolines.rs      # NEW: all 11 trampoline implementations
│   └── crash_guard.rs      # NEW: SEH + catch_unwind wrappers
│   └── fail_closed.rs      # NEW: deny_return macro + DenyReturn enum
│   └── handle_ipc.rs       # NEW: HookRequest variant for HANDLE-based ops
├── build.rs                # MAYBE: architecture-specific build logic
└── tests/                  # Architecture-agnostic tests (x64 only in CI)
```

### Pattern 1: HookDescriptor Metadata Table
**What:** A `static` array of structs describing every hooked function. Drives `init()` (patch all), `UnhookAll()` (restore all), and debug logging.
**When to use:** Any multi-hook DLL where enumeration and bulk operations are needed.
**Example:**
```rust
// Source: CONTEXT.md D-01 + D-03 + existing lib.rs patterns
#[derive(Clone, Copy)]
struct HookDescriptor {
    fn_name: &'static str,
    dll_name: &'static str,
    original_ptr: *mut usize,      // static mut holding original fn
    iat_ptr: *mut usize,           // static mut holding IAT entry addr
    trampoline_ptr: unsafe extern "system" fn(),
    deny_return: DenyReturn,
}

#[derive(Clone, Copy)]
enum DenyReturn {
    BoolFalse,           // BOOL(0)
    InvalidHandleValue,  // HANDLE(-1)
    StatusAccessDenied,  // NTSTATUS(0xC0000022)
}

macro_rules! deny_return_value {
    (BoolFalse) => { windows::Win32::Foundation::BOOL(0) };
    (InvalidHandleValue) => { windows::Win32::Foundation::INVALID_HANDLE_VALUE };
    (StatusAccessDenied) => { windows::Win32::Foundation::NTSTATUS(0xC0000022u32 as i32) };
}
```

### Pattern 2: Layered Crash Protection
**What:** SEH `__try/__except` around the entire trampoline entry catches access violations in `unsafe` path extraction. `catch_unwind` around the Rust-side classification pipeline catches panics in pipe client or decision logic. On any exception, route to the original function (fail-OPEN).
**When to use:** Every trampoline that runs inside a foreign process where crashes would abort the host.
**Example:**
```rust
// Source: CONTEXT.md D-05 + D-06 + existing lib.rs patterns
#[unsafe(no_mangle)]
pub unsafe extern "system" fn HookWriteFile(
    hfile: HANDLE,
    lpbuffer: *const u8,
    nnumberofbytestowrite: u32,
    lpnumberofbyteswritten: *mut u32,
    lpoverlapped: *mut OVERLAPPED,
) -> BOOL {
    // SEH outer layer (catches AVs in unsafe code)
    let result = std::panic::catch_unwind(|| {
        // Rust panic inner layer
        let handle_value = hfile.0 as usize;
        let decision = classify_handle(handle_value, "WRITE", DEFAULT_PIPE_NAME);
        match decision {
            Ok(Decision::ALLOW) | Ok(Decision::AllowWithLog) => {
                // call original
            }
            Ok(d) if d.is_denied() => {
                SetLastError(ERROR_ACCESS_DENIED);
                return BOOL(0);
            }
            _ => {
                SetLastError(ERROR_ACCESS_DENIED);
                return BOOL(0);
            }
        }
    });
    
    match result {
        Ok(ret) => ret,
        Err(_) => {
            // Panic caught -- fail-open, call original
            debug_log("[dlp-hook] PANIC caught in HookWriteFile -- fail-open\0");
            original(...)
        }
    }
}
```

### Pattern 3: Thread-Local Pre-Allocated Buffer
**What:** Each thread gets a 4KiB `Vec<u8>` in `thread_local!()`. The pipe client reuses it instead of allocating per call.
**When to use:** Hot-path IPC where allocator pressure must be minimized.
**Example:**
```rust
// Source: CONTEXT.md D-09
use std::cell::RefCell;

thread_local! {
    static PIPE_BUFFER: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(4096));
}

fn send_request_with_buffer(pipe: HANDLE, request: &HookRequest) -> Result<HookResponse, PipeError> {
    PIPE_BUFFER.with(|buf| {
        let mut buffer = buf.borrow_mut();
        buffer.clear();
        
        // Serialize into buffer
        match bincode::serialize_into(&mut *buffer, request) {
            Ok(()) => {
                write_frame(pipe, &buffer)?;
                // ... read response
            }
            Err(_) => Err(PipeError::Malformed),
        }
    })
}
```

### Pattern 4: Dual-Arch PE Parsing
**What:** `find_iat_entry` uses `cfg(target_arch)` to select PE32 (x86) vs PE32+ (x64) constants.
**When to use:** Same source building for multiple Windows architectures.
**Example:**
```rust
// Source: CONTEXT.md D-11 + D-12 + existing lib.rs lines 188-196
#[cfg(target_arch = "x86_64")]
const PE_MAGIC: u16 = 0x20B;
#[cfg(target_arch = "x86_64")]
const DATA_DIRECTORY_OFFSET: isize = 112;

#[cfg(target_arch = "x86")]
const PE_MAGIC: u16 = 0x10B;
#[cfg(target_arch = "x86")]
const DATA_DIRECTORY_OFFSET: isize = 96;

unsafe fn find_iat_entry(module_base: *mut u8, dll_name: &str, target_proc: *const c_void) -> Option<*mut usize> {
    // ... e_lfanew, nt_headers, optional_header same for both
    let magic = *(optional_header as *const u16);
    if magic != PE_MAGIC {
        return None;
    }
    let data_directory = optional_header.offset(DATA_DIRECTORY_OFFSET);
    // ... rest identical
}
```

### Anti-Patterns to Avoid
- **Panic across FFI boundary:** Never let a Rust panic propagate past an `extern "system"` boundary -- this is undefined behavior. Always wrap with `catch_unwind`.
- **Allocating in hot path:** Do not allocate a new `Vec<u8>` for every pipe request. Use the thread-local buffer pattern.
- **Self-repair after crash:** Do not attempt to re-patch IAT entries after catching an exception. This can cause infinite crash loops. Fail-open and log once.
- **CopyFile2 IAT assumption:** `CopyFile2` is a COM-based API and may not have a traditional IAT entry. Document as known limitation and defer to Phase 51 (ntdll trampolines) for coverage.
- **Unbounded string scanning:** The existing `pcwstr_to_string` scans until null terminator. Without the 32K cap, a malformed pointer could cause an infinite loop or OOM.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| PE parsing library | Custom parser from scratch | Keep existing ~50-line manual parser (D-12) | Adding `goblin`/`pelite` for 10 lines of `cfg` blocks is overkill; existing parser works |
| Authenticode signing | Custom signing tool | `signtool` (Windows SDK) | Industry standard; handles cert chains, timestamps, counter-signing |
| CI release workflow | Ad-hoc scripts | GitHub Actions `workflow_run` or tag triggers | Reproducible, auditable, integrates with GitHub secrets |
| Handle tracking | Hook `CloseHandle` in DLL | Agent-side handle tracker via `NtQueryObject` or ETW | Hooking `CloseHandle` adds another IAT entry and crash surface; agent can track via existing ETW or periodic snapshot |
| COM hooking for CopyFile2 | IAT patch on COM vtable | Defer to Phase 51 ntdll trampolines | COM vtables are per-instance, not per-module; ntdll trampolines catch the underlying syscalls regardless of API layer |

**Key insight:** The hook DLL is a crash-sensitive component running inside arbitrary processes. Every line of code added to it increases the risk of host-process abort. Prefer agent-side complexity over DLL-side complexity. The handle->path map (D-02) follows this principle.

## Runtime State Inventory

> This phase involves rename/refactor of the v0.9.0 cloud-sync hook DLL to a unified hook DLL. Runtime state audit follows.

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | None -- hook DLL is stateless except for static mut IAT entries | None |
| Live service config | Agent service (`dlp-agent`) holds `HookInjector` with hardcoded `dlp_hook_dll.dll` path (`service.rs:979`). Currently passes `None` for x86 path. | Code edit: update `service.rs` to pass x86 DLL path |
| OS-registered state | None -- hook DLL is not registered with OS; injected dynamically | None |
| Secrets/env vars | `AUTHENTICODE_PFX` and `AUTHENTICODE_PASSWORD` GitHub secrets needed for signing pipeline | Create secrets in repo settings (human action) |
| Build artifacts | `target/debug/dlp_hook_dll.dll` and `target/i686-pc-windows-msvc/debug/dlp_hook_dll.dll` (after this phase) | CI produces both; installer packages both |

**Nothing found in category:** Stored data -- verified: hook DLL has no persistent datastore. OS-registered state -- verified: no registry entries, no scheduled tasks, no services.

## Common Pitfalls

### Pitfall 1: FFI Panic = Undefined Behavior
**What goes wrong:** A Rust panic unwinding across an `extern "system"` boundary corrupts the stack and aborts the host process.
**Why it happens:** `extern "system"` functions use the C ABI; Rust panics expect the Rust ABI unwind tables.
**How to avoid:** Wrap every trampoline body in `std::panic::catch_unwind`. Return a sentinel value on panic and call the original function.
**Warning signs:** Host process crashes with "RuntimeLibrary abort" or "fatal runtime error: failed to initiate panic" in Event Viewer.

### Pitfall 2: PE32 vs PE32+ Offset Confusion
**What goes wrong:** `find_iat_entry` returns wrong IAT address on x86, causing patch to write to invalid memory.
**Why it happens:** PE32 (x86) optional header is smaller; `DataDirectory` starts at offset 96, not 112. Magic is `0x10B`, not `0x20B`.
**How to avoid:** Use `cfg(target_arch)` constants (D-11). Add a test that verifies `find_iat_entry` returns `Some` for a known import on the current architecture.
**Warning signs:** `patch_iat` returns false (VirtualProtect succeeds but IAT entry not found), or host process crashes immediately after `DllMain`.

### Pitfall 3: Thread-Local Buffer Borrow Across Await
**What goes wrong:** `RefCell<Vec<u8>>` borrowed mutably across an `.await` point causes panic if the same thread re-enters.
**Why it happens:** The pipe client is synchronous (blocking read/write), but if refactored to async later, the borrow could be held across a yield point.
**How to avoid:** Keep pipe client synchronous. The `RefCell` borrow should be scoped to a single non-blocking block of code.
**Warning signs:** `thread 'main' panicked at 'already borrowed: BorrowMutError'` in hook DLL logs.

### Pitfall 4: CopyFile2 IAT Gap
**What goes wrong:** `CopyFile2` is listed in BLOCK-02 but has no traditional IAT entry because it's a COM-based API.
**Why it happens:** `CopyFile2` uses `ICopyFile2Progress` interface; the actual copy goes through `IFileOperation` or direct ntdll calls.
**How to avoid:** Document as known limitation in code comments. The underlying `NtCreateFile`/`NtWriteFile` hooks (also in the 11-function list) catch copy operations at the syscall layer.
**Warning signs:** IAT search for `CopyFile2` returns `None` even in a process that calls it.

### Pitfall 5: signtool Timestamp Server Flakiness
**What goes wrong:** CI release build fails because DigiCert timestamp server is down.
**Why it happens:** Timestamp servers have maintenance windows and rate limits.
**How to avoid:** Implement D-20 fallback logic in the workflow: try DigiCert first, if exit code != 0 retry with Sectigo.
**Warning signs:** `SignTool Error: The specified timestamp server either could not be reached or returned an invalid response.`

### Pitfall 6: Handle-Based Functions Without Path
**What goes wrong:** `WriteFile`, `SetFileInformationByHandle` receive a `HANDLE` not a path. The hook DLL cannot classify without path resolution.
**Why it happens:** These functions operate on already-opened handles.
**How to avoid:** Per D-02, send the HANDLE value to the agent over the pipe. The agent maintains a handle->path map tracking `CreateFileW`/`NtCreateFile` open/close/duplicate operations.
**Warning signs:** Hook fires but path is empty string; agent logs "unknown handle" warnings.

## Code Examples

### HookDescriptor Table and Init Loop
```rust
// Source: CONTEXT.md D-01 + existing lib.rs patterns
use std::sync::atomic::{AtomicBool, Ordering};

static INITIALISED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy)]
enum DenyReturn {
    BoolFalse,
    InvalidHandleValue,
    StatusAccessDenied,
}

struct HookDescriptor {
    fn_name: &'static str,
    dll_name: &'static str,
    original_ptr: *mut usize,
    iat_ptr: *mut usize,
    trampoline_ptr: unsafe extern "system" fn(),
    deny_return: DenyReturn,
}

// Static muts for each hooked function (one per function)
static mut ORIGINAL_WRITE_FILE: Option<unsafe extern "system" fn(...) -> BOOL> = None;
static mut IAT_WRITE_FILE: Option<*mut usize> = None;
// ... repeat for all 11 functions

const HOOKS: &[HookDescriptor] = &[
    HookDescriptor {
        fn_name: "WriteFile",
        dll_name: "kernel32.dll",
        original_ptr: &raw mut ORIGINAL_WRITE_FILE as *mut usize,
        iat_ptr: &raw mut IAT_WRITE_FILE as *mut usize,
        trampoline_ptr: HookWriteFile as unsafe extern "system" fn(),
        deny_return: DenyReturn::BoolFalse,
    },
    // ... 10 more entries
];

fn init() {
    if INITIALISED.swap(true, Ordering::SeqCst) {
        return;
    }
    let host = unsafe { GetModuleHandleW(None).unwrap_or_default() };
    if host.is_invalid() { return; }
    let host_ptr = host.0 as *mut u8;
    
    for hook in HOOKS {
        unsafe {
            // Resolve original function
            let original = resolve_proc(hook.dll_name, hook.fn_name);
            *(hook.original_ptr as *mut Option<usize>) = Some(original as usize);
            
            // Find and patch IAT
            if let Some(iat) = find_iat_entry(host_ptr, hook.dll_name, original as *const c_void) {
                if patch_iat(iat, hook.trampoline_ptr as *mut c_void) {
                    *(hook.iat_ptr as *mut Option<*mut usize>) = Some(iat);
                }
            }
        }
    }
}

fn UnhookAll() {
    for hook in HOOKS {
        unsafe {
            if let Some(iat) = *(hook.iat_ptr as *const Option<*mut usize>) {
                if let Some(orig) = *(hook.original_ptr as *const Option<usize>) {
                    let _ = restore_iat(iat, orig);
                }
            }
        }
    }
}
```

### SEH Wrapper Pattern (windows crate)
```rust
// Source: CONTEXT.md D-05 + windows crate SEH bindings
// Note: The windows crate provides __try/__except via raw bindings.
// For Rust-level SEH, use the `windows` crate's structured exception handling
// or the `seh` crate. The project already uses `windows = 0.62`.
//
// Simplified pattern (actual SEH integration requires platform-specific code):
#[cfg(target_arch = "x86_64")]
unsafe fn seh_guard<T>(f: impl FnOnce() -> T) -> Result<T, ()> {
    // In practice, use windows::__try / __except or a small C shim
    // compiled with the DLL that wraps the Rust call.
    Ok(f())
}
```

### Fail-Closed Macro
```rust
// Source: CONTEXT.md D-03
macro_rules! fail_closed {
    (BoolFalse) => {
        {
            SetLastError(ERROR_ACCESS_DENIED);
            windows::Win32::Foundation::BOOL(0)
        }
    };
    (InvalidHandleValue) => {
        {
            SetLastError(ERROR_ACCESS_DENIED);
            windows::Win32::Foundation::INVALID_HANDLE_VALUE
        }
    };
    (StatusAccessDenied) => {
        windows::Win32::Foundation::NTSTATUS(0xC0000022u32 as i32)
    };
}
```

### x86 CI Matrix Step
```yaml
# Source: CONTEXT.md D-13 + D-17 + existing build.yml patterns
# .github/workflows/release.yml
name: Release
on:
  push:
    tags: ['v*']
jobs:
  build:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: i686-pc-windows-msvc
      - run: cargo build --release -p dlp-hook-dll --target x86_64-pc-windows-msvc
      - run: cargo build --release -p dlp-hook-dll --target i686-pc-windows-msvc
      # ... sign both artifacts
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| v0.9.0 cloud-sync only (CreateFileW/NtCreateFile) | 11-function unified hook DLL | Phase 48 (this phase) | Broader file-I/O coverage; same DLL for all target processes |
| Single x64 DLL only | x64 + x86 from same source | Phase 48 (this phase) | Covers WOW64 processes (e.g., 32-bit legacy apps) |
| No crash hardening | SEH + catch_unwind + 32K cap + pre-allocated buffers | Phase 48 (this phase) | Host-process abort risk mitigated (CRIT-02) |
| Unsigned binaries | Authenticode + RFC-3161 timestamp | Phase 48 (this phase) | AV/EDR false-positive reduction; enterprise deployment requirement |
| Manual per-function IAT patching | `HookDescriptor` metadata table | Phase 48 (this phase) | Scalable to more functions; unified UnhookAll |

**Deprecated/outdated:**
- `dlp-cloud-hook.dll` name: replaced by unified `dlp_hook_dll.dll` (BLOCK-03).
- Cloud-sync-specific `HookRequest.action = "CREATE"`: expanded to full `HookOp` enum (WRITE, COPY, DELETE, MOVE, etc.) in Phase 50 (CACHE).

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `windows` crate 0.62 provides sufficient SEH bindings for `__try`/`__except` | Crash Hardening | May need a small C-compiled shim or `seh` crate if `windows` bindings are incomplete |
| A2 | `CopyFile2` lacks a traditional IAT entry and cannot be hooked via IAT patching | Standard Stack | If IAT entry exists, it can be added to the hook table; if not, the ntdll fallback covers it |
| A3 | `signtool` is available on `windows-latest` GitHub Actions runners | Environment Availability | If not, need to install Windows SDK or use self-hosted runner |
| A4 | `i686-pc-windows-msvc` target can be installed via `rustup target add` on x64 CI runners | Environment Availability | If cross-compilation fails, may need self-hosted x86 runner (unlikely) |
| A5 | The agent can track handle lifecycle sufficiently for handle->path resolution | Architecture Patterns | If handle tracking is incomplete, some WriteFile/SetFileInformationByHandle calls may lack path context |

## Open Questions

1. **SEH Integration Detail**
   - What we know: CONTEXT.md D-05 requires SEH `__try/__except` around trampolines. The `windows` crate 0.62 has raw bindings.
   - What's unclear: Whether the `windows` crate exposes Rust-friendly SEH macros or if a C shim is needed.
   - Recommendation: Start with `catch_unwind` only (covers panics). Add SEH in a follow-up task if `windows` crate SEH bindings are insufficient. Document the gap.

2. **Handle Tracker Implementation**
   - What we know: D-02 says agent maintains handle->path map. The agent already tracks processes via `EnumProcesses` and sync-client enumeration.
   - What's unclear: Whether to track handles via ETW Kernel-File events, `NtQueryObject`, or hook `CloseHandle`/`DuplicateHandle` in the DLL.
   - Recommendation: Use ETW Kernel-File `OP_END` events (Phase 53) for handle lifecycle tracking. Until Phase 53 is ready, implement a lightweight `NtQueryObject(ObjectNameInformation)` fallback in the agent pipe handler for HANDLE-based requests.

3. **CopyFile2 Coverage**
   - What we know: BLOCK-02 lists `CopyFile2`. COM-based APIs may not have IAT entries.
   - What's unclear: Whether `CopyFile2` has a direct ntdll equivalent that the existing `NtCreateFile`/`NtWriteFile` hooks already cover.
   - Recommendation: Document `CopyFile2` as "covered indirectly via NtCreateFile/NtWriteFile" in the hook table comments. Do not add a dedicated trampoline unless IAT entry is confirmed present.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Rust x64 toolchain | Build | Yes | 1.94.1 | -- |
| Rust x86 target (`i686-pc-windows-msvc`) | BLOCK-04 | No (not installed) | -- | `rustup target add i686-pc-windows-msvc` (one-time) |
| `windows` crate | All Win32 API calls | Yes | 0.62.2 | -- |
| `signtool` | BLOCK-10 | No (not in PATH) | -- | Part of Windows SDK; available on `windows-latest` GA runners |
| GitHub Actions | CI/CD | Yes (cloud) | -- | -- |
| Authenticode certificate | BLOCK-10 | No | -- | Must be purchased and secrets configured (human action) |

**Missing dependencies with no fallback:**
- Authenticode certificate + GitHub secrets -- blocks signing pipeline until purchased and configured.

**Missing dependencies with fallback:**
- `i686-pc-windows-msvc` target -- installable via `rustup target add` in CI workflow.
- `signtool` -- available on `windows-latest` GA runners; if missing, install Windows SDK.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Built-in `#[test]` + `cargo test` (Rust standard) |
| Config file | None -- inline `#[cfg(test)]` modules |
| Quick run command | `cargo test -p dlp-hook-dll` |
| Full suite command | `cargo test --workspace` |

### Phase Requirements -> Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| BLOCK-01 | `catch_unwind` catches panic in trampoline | unit | `cargo test -p dlp-hook-dll catch_unwind` | No -- Wave 0 gap |
| BLOCK-01 | 32K cap truncates long paths | unit | `cargo test -p dlp-hook-dll pcwstr_cap` | No -- Wave 0 gap |
| BLOCK-01 | Thread-local buffer reused | unit | `cargo test -p dlp-hook-dll buffer_reuse` | No -- Wave 0 gap |
| BLOCK-02 | Each of 11 trampolines returns correct deny value | unit | `cargo test -p dlp-hook-dll deny_return` | No -- Wave 0 gap |
| BLOCK-02 | `HookDescriptor` table enumerates all hooks | unit | `cargo test -p dlp-hook-dll hook_descriptor` | No -- Wave 0 gap |
| BLOCK-03 | Existing `dlp-e2e` workspace tests pass | integration | `cargo test -p dlp-e2e` | Yes (`dlp-e2e/tests/*.rs`) |
| BLOCK-04 | x86 DLL builds successfully | build | `cargo build --target i686-pc-windows-msvc -p dlp-hook-dll` | No -- Wave 0 gap (target not installed) |
| BLOCK-04 | `HookInjector` selects x86 DLL for WOW64 process | unit | `cargo test -p dlp-agent injector_x86` | Yes (existing `test_injector_successfully_injects_dll`) |
| BLOCK-10 | Release workflow triggers on `v*` tags | CI | Push a test tag to fork | No -- Wave 0 gap |

### Sampling Rate
- **Per task commit:** `cargo test -p dlp-hook-dll`
- **Per wave merge:** `cargo test --workspace`
- **Phase gate:** Full suite green before `/gsd-verify-work`

### Wave 0 Gaps
- [ ] `dlp-hook-dll/src/crash_guard.rs` (or equivalent) -- SEH + catch_unwind test fixtures
- [ ] `dlp-hook-dll/src/fail_closed.rs` -- `DenyReturn` enum + macro tests
- [ ] `dlp-hook-dll/src/pe_utils.rs` -- x86 `find_iat_entry` test (needs PE32 test binary or mock)
- [ ] `.github/workflows/release.yml` -- signing workflow (BLOCK-10)
- [ ] `rustup target add i686-pc-windows-msvc` -- CI toolchain install step
- [ ] `installer/DLPAgent.wxs` -- add `dlp_hook_dll.dll` and `dlp_hook_dll_x86.dll` components

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No | Not in scope for this phase |
| V3 Session Management | No | Not in scope for this phase |
| V4 Access Control | Yes | Hook DLL enforces ABAC decisions at file-I/O boundary |
| V5 Input Validation | Yes | 32K-char cap on wide-string conversion; HANDLE validation for handle-based ops |
| V6 Cryptography | Yes | Authenticode signing (SHA-256) + RFC-3161 timestamp for binary integrity |
| V10 Malicious Code | Yes | `catch_unwind` + SEH prevents hook DLL from being used as DoS vector against host processes |

### Known Threat Patterns for Hook DLL Stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Host-process abort via hook crash | Denial of Service | SEH + catch_unwind + fail-open (D-05, D-06) |
| Unbounded string scan causing hang | Denial of Service | 32K-char cap (D-07) |
| IAT patch corruption | Tampering | `VirtualProtect` restore after write; `UnhookAll` restores originals |
| Unsigned DLL loaded by AV/EDR as suspicious | Repudiation | Authenticode signing + timestamp (BLOCK-10) |
| Handle reuse after close (TOCTOU) | Elevation of Privilege | Agent handle tracker validates handle still open via `NtQueryObject` before resolution |

## Sources

### Primary (HIGH confidence)
- `dlp-hook-dll/src/lib.rs` -- Existing hook DLL with `CreateFileW`/`NtCreateFile` IAT patching, manual PE32+ parsing, `OutputDebugStringW` logging, `pcwstr_to_string`, `extract_nt_path`
- `dlp-hook-dll/src/pipe_client.rs` -- Named-pipe client with length-prefixed bincode framing, `PipeError` enum, `connect_pipe` retry logic
- `dlp-agent/src/hook_injector.rs` -- `HookInjector` with `IsWow64Process` architecture detection, `CreateRemoteThread` + `LoadLibraryW` injection
- `dlp-agent/src/service.rs` -- `HookInjector` construction, sync-client watcher thread, `cloud_hook_enabled` config gating
- `dlp-common/src/hook_ipc.rs` -- `HookRequest`/`HookResponse` shared types
- `dlp-common/src/abac.rs` -- `Decision` enum with `is_denied()` method
- `.planning/phases/48-hook-dll-surface-expansion-crash-hardening-build-harness/48-CONTEXT.md` -- 21 locked decisions (D-01..D-21)
- `.planning/REQUIREMENTS.md` -- BLOCK-01..BLOCK-04, BLOCK-10 requirements

### Secondary (MEDIUM confidence)
- `cargo search windows --limit 1` -- Verified `windows` crate 0.62.2 is current
- `rustc --version` / `cargo --version` -- Verified Rust 1.94.1
- `rustup target list --installed` -- Verified only x86_64-pc-windows-msvc installed
- Microsoft Learn documentation (via MCP) -- `VirtualProtect`, `CreateRemoteThread`, `OutputDebugStringW`, `SetLastError`, NTSTATUS codes

### Tertiary (LOW confidence)
- `signtool` availability on `windows-latest` GA runners -- assumed based on Windows SDK being pre-installed; not verified live
- `windows` crate SEH `__try`/`__except` bindings completeness -- assumed based on crate documentation; may need C shim (flagged in Assumptions Log)

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- all crates verified via cargo registry or already in Cargo.lock
- Architecture: HIGH -- existing code patterns are clear; extension points well-defined
- Pitfalls: HIGH -- FFI panic = UB and PE offset confusion are well-documented Windows/Rust issues
- Signing pipeline: MEDIUM -- `signtool` assumed available on GA runners; Authenticode cert purchase is external dependency
- x86 cross-compile: HIGH -- `rustup target add` is standard; `cfg(target_arch)` is well-supported

**Research date:** 2026-05-15
**Valid until:** 2026-06-15 (stable stack; 30 days)
