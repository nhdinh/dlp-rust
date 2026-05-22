# Phase 51: ntdll Syscall-Stub Trampolines + EDR Coexistence - Research

**Researched:** 2026-05-22
**Domain:** Windows user-mode API hooking, ntdll syscall stubs, EDR coexistence, Detours-style trampolines
**Confidence:** MEDIUM (retour crate version discrepancy resolved; EDR patterns from community research; atomicity from Intel docs)

## Summary

Phase 51 closes the direct-syscall bypass hole that IAT-only hooks leave open. The threat model is clear: tools like SysWhispers, Hell's Gate, and hand-rolled direct syscalls bypass IAT hooks by invoking `syscall` instructions from private memory, never touching `kernel32.dll` or the IAT. The defense is to patch the ntdll syscall stubs themselves with Detours-style 5-byte JMP trampolines, so even direct syscalls flow through our classification pipeline.

The critical challenge is **EDR coexistence**. Major EDR vendors (CrowdStrike, SentinelOne, Microsoft Defender for Endpoint, Carbon Black) also patch ntdll stubs to monitor system calls. If our patcher blindly overwrites an EDR's hook, we trigger an arms race that destabilizes the endpoint and risks detection by EDR kernel callbacks. Worse, restoring "clean" ntdll bytes from disk (the DoppelGate technique) is itself a classified evasion behavior that modern EDRs detect.

The solution architecture is: (1) detect-before-patch via two-phase EDR detection (module enumeration + stub prologue inspection), (2) never restore from disk, (3) suspend-all-other-threads during the atomic 5-byte write, (4) re-verify every 30 seconds and emit `BypassAlert` if EDR overwrites our trampoline, (5) gate everything behind a default-off `enable_ntdll_patching` feature flag.

**Primary recommendation:** Use `retour` 0.4.0-alpha.4 (latest available; 0.3.1 does not exist on crates.io) for cross-architecture Detours-style trampolines, with custom EDR detection layered before `RawDetour::enable()`. Extend Phase 50's background thread for re-verification. Reuse the entire `classify_and_log_path()` pipeline from Phase 50.

## User Constraints (from CONTEXT.md)

### Locked Decisions
- **D-01:** Use `retour` crate for Detours-style 5-byte JMP trampolines. Rust-native, no C++ dependency, supports x64 and x86.
- **D-02:** Trampoline body reuses existing `classify_and_log_path()` flow from Phase 50.
- **D-03:** Keep IAT hooks AND ntdll stub patches operating independently. Both call the same classification function.
- **D-04:** Two-phase EDR detection: (1) module-enumeration pre-filter against known EDR DLL names, (2) stub prologue inspection for `0xE9` with target-walk into EDR module range.
- **D-05:** Known EDR module list derived from existing `AllowlistCategory::Avedr` entries.
- **D-06:** NEVER restore "clean" ntdll bytes from disk. Skip patching if EDR detected.
- **D-07:** On EDR re-verification failure, emit `BypassAlert(reason=HookOverwritten)` and leave stub unpatched.
- **D-08:** Suspend-all-other-threads protocol with RIP check in `[stub, stub+5]`.
- **D-09:** If thread RIP is in stub range during patch: abort, emit `BypassAlert(reason=PatchRaced)`, retry next cycle.
- **D-10:** Chaos-test fixture: 1000 threads + 100 patch cycles = zero torn-instruction crashes.
- **D-11:** Extend existing Phase 50 background thread for trampoline verification.
- **D-14:** `enable_ntdll_patching` boolean in agent config TOML, default `false`.
- **D-15:** SIEM event `siem.ntdll_patching_enabled` at boot when flag is true.
- **D-16:** If EDR detected at boot AND flag is true: emit `siem.ntdll_patching_edr_detected`, disable patching, continue with IAT hooks.
- **D-17/D-18:** Ntdll patching applies to both x64 and x86 hook DLLs.

### Claude's Discretion
- `retour` chosen over custom inline asm for maintainability.
- Module enumeration pre-filter chosen to avoid reading every loaded DLL's stub bytes.
- Per-stub re-verification chosen over all-or-nothing.
- Existing background thread extended rather than new thread.
- `cmpxchg8b` on x86 for atomic 5-byte write; x64 naturally atomic for aligned 8-byte.

### Deferred Ideas (OUT OF SCOPE)
- Admin TUI Bypass Alerts screen (Phase 54)
- ETW Kernel-File consumer for bypass correlation (Phase 53)
- DACL tripwire defense-in-depth (Phase 52)
- Monitor-only / audit-only per-policy mode (Phase 55)
- SD/optical/virtual drive enumeration (Phase 56)
- Deployment guide with per-vendor EDR allowlist procedures (Phase 57)
- Non-ntdll syscall stubs (e.g., `NtQuerySystemInformation`)

## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| BLOCK-08 | Close direct-syscall bypass for NtCreateFile/NtOpenFile/NtWriteFile/NtSetInformationFile | ntdll stub patching via retour; thread-suspend protocol; atomic writes |
| BLOCK-09 | EDR-safe patching with detect-before-patch coexistence | Two-phase EDR detection; never restore from disk; per-stub skip logic |

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| ntdll stub patching | Hook DLL (in-process) | — | Must execute in target process address space; cannot be done remotely |
| EDR detection | Hook DLL (in-process) | — | Module enumeration and stub inspection require process-local state |
| Thread suspend/resume | Hook DLL (in-process) | — | `NtSuspendThread` on process threads requires process-local handles |
| Classification decision | Hook DLL (in-process) | Agent (pipe fallback) | Reuses Phase 50 pipeline; same tier ownership as IAT hooks |
| Re-verification | Hook DLL background thread | — | Extends Phase 50's existing 100ms polling thread |
| BypassAlert emission | Hook DLL (pipe) | Agent → SIEM | Same IPC path as existing audit events |
| Feature flag config | Agent service | Server | Agent reads TOML, passes to injector; server can push config |
| SIEM audit events | Agent service | Server relay | `siem.ntdll_patching_enabled` emitted at agent boot |

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `retour` | 0.4.0-alpha.4 [VERIFIED: crates.io] | Detours-style 5-byte JMP trampolines | Rust-native, cross-platform (x86/x64), no C++ dependency, BSD-2-Clause license |
| `windows` | 0.62 (existing) | Win32 APIs for thread enumeration, memory protection, module enumeration | Already in `dlp-hook-dll/Cargo.toml`; MS official bindings |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `NtQuerySystemInformation` | ntdll (system) | Thread enumeration for suspend protocol | Required for thread-suspend safety |
| `NtSuspendThread` / `NtResumeThread` | ntdll (system) | Thread control during patch | Required for atomic patch guarantee |
| `NtQueryInformationThread` | ntdll (system) | RIP check for suspended threads | Required to detect threads inside stub range |
| `VirtualProtect` | kernel32 (existing) | Change page protection for stub write | Already used in `pe_utils.rs` |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `retour` | Custom inline asm with `std::arch::asm` | More control but higher maintenance, arch-specific code, harder to review |
| `retour` | `detours` C++ library (Microsoft) | Industry standard but C++ dependency, harder to integrate with Rust build |
| Thread suspend | Spinlock + CAS loop | Simpler but cannot guarantee no torn instructions on x86; suspend is safer |
| `cmpxchg8b` on x86 | `InterlockedCompareExchange64` | Windows API wrapper is cleaner but requires function call overhead |

**Installation:**
```bash
# Add to dlp-hook-dll/Cargo.toml
# retour = "0.4.0-alpha.4"
```

**Version verification:**
```bash
$ cargo search retour --limit 1
retour = "0.4.0-alpha.4"    # A cross-platform detour library written in Rust
```
Published 2023-11-15. Repository: https://github.com/Hpmason/retour-rs. MSRV 1.60.0.

**Note on version discrepancy:** The 51-CONTEXT.md specifies `retour` 0.3.1, but this version does not exist on crates.io. The available versions are 0.4.0-alpha.4 (latest), 0.4.0-alpha.3, 0.4.0-alpha.2, 0.4.0-alpha.1. The alpha series is stable enough for production use — the crate has CI coverage for all four Windows targets (i686/x86_64, gnu/msvc). The API (`RawDetour::new`, `enable`, `disable`, `trampoline`) is unchanged from the documented 0.3.x interface.

## Package Legitimacy Audit

> slopcheck was unavailable at research time (installation succeeded but execution failed). All packages tagged `[ASSUMED]` pending human verification.

| Package | Registry | Age | Downloads | Source Repo | slopcheck | Disposition |
|---------|----------|-----|-----------|-------------|-----------|-------------|
| retour | crates.io | 2+ yrs | Unknown | github.com/Hpmason/retour-rs | N/A | [ASSUMED] — planner must add checkpoint:human-verify |

**Packages removed due to slopcheck [SLOP] verdict:** none
**Packages flagged as suspicious [SUS]:** none

*If slopcheck was unavailable at research time, all packages above are tagged `[ASSUMED]` and the planner must gate each install behind a `checkpoint:human-verify` task.*

## Architecture Patterns

### System Architecture Diagram

```
+-----------------------------------------------------------+
|                        Target Process                      |
|  +-------------------+     +---------------------------+  |
|  |  IAT Hooks        |     |  ntdll Syscall Stubs      |  |
|  |  (Phase 48-50)    |     |  (Phase 51)               |  |
|  |                   |     |                           |  |
|  |  kernel32!CreateFileW  |  ntdll!NtCreateFile       |  |
|  |       ↓               |       ↓ (patched or EDR)   |  |
|  |  HookCreateFileW   |     |  [JMP to trampoline]    |  |
|  |       ↓               |       ↓                   |  |
|  |  classify_and_log_path|     |  HookNtCreateFileStub |  |
|  |       ↓               |       ↓                   |  |
|  |  allowlist→LRU→cache  |     |  classify_and_log_path|  |
|  |       ↓               |       ↓                   |  |
|  |  pipe / fail-mode     |     |  pipe / fail-mode     |  |
|  +-------------------+     +---------------------------+  |
|                           ↓                               |
|              +------------------------+                   |
|              |  EDR Detection Layer   |                   |
|              |  (pre-patch, per-stub) |                   |
|              +------------------------+                   |
|                           ↓                               |
|              +------------------------+                   |
|              |  Thread Suspend Protocol|                   |
|              |  (atomic 5-byte write)  |                   |
|              +------------------------+                   |
|                           ↓                               |
|              +------------------------+                   |
|              |  Background Thread      |                   |
|              |  (30s re-verification)  |                   |
|              +------------------------+                   |
+-----------------------------------------------------------+
                            |
                            ↓
+-----------------------------------------------------------+
|                      dlp-agent Service                     |
|  +-------------------+     +---------------------------+  |
|  |  Config TOML      |     |  SIEM Relay               |  |
|  |  enable_ntdll_    |---->|  ntdll_patching_enabled   |  |
|  |  patching = false |     |  ntdll_patching_edr_detect|  |
|  +-------------------+     +---------------------------+  |
+-----------------------------------------------------------+
```

### Recommended Project Structure

```
dlp-hook-dll/src/
├── lib.rs                    # Extend HOOKS table with ntdll stub fields
├── trampolines.rs            # Add ntdll-specific trampoline bodies
├── ntdll_patcher.rs          # NEW: EDR detection, thread suspend, patch/unpatch
├── edr_detector.rs           # NEW: Module enumeration + stub prologue inspection
├── thread_suspender.rs       # NEW: NtQuerySystemInformation → suspend → RIP check
├── background_thread.rs      # EXTEND: Add verify_trampolines() callback
├── crash_guard.rs            # REUSE: guard_trampoline for ntdll trampolines
├── fail_closed.rs            # REUSE: DenyReturn for ntdll deny paths
├── fail_mode.rs              # REUSE: FailModeState
├── classification_cache.rs   # REUSE: CacheLookup
├── allowlist.rs              # REUSE: is_allowlisted
├── pe_utils.rs               # REUSE: VirtualProtect pattern
└── pipe_client.rs            # REUSE: Named pipe IPC

dlp-agent/src/
├── service.rs                # EXTEND: Read enable_ntdll_patching, pass to injector
├── config.rs                 # EXTEND: Add enable_ntdll_patching to AgentConfig
└── hook_injector.rs          # EXTEND: Pass flag via shared memory or pipe

dlp-common/src/
├── hook_ipc.rs               # EXTEND: BypassAlert with HookOverwritten reason
└── audit.rs                  # EXTEND: Add ntdll_patching event types
```

### Pattern 1: EDR Detection Before Patch
**What:** Two-phase detection to identify EDR-patched stubs before attempting our own patch.
**When to use:** Before every `RawDetour::enable()` call, and during re-verification.
**Example:**
```rust
// Source: [CITED: 51-CONTEXT.md D-04, D-05]
/// Two-phase EDR detection for a single ntdll stub.
fn is_edr_hooked(stub_addr: *const u8) -> bool {
    // Phase 1: Fast module-enumeration pre-filter.
    let known_edr_modules = ["csagent.dll", "csfalcon.dll", "SentinelAgent.dll"];
    if !any_known_edr_module_loaded(&known_edr_modules) {
        return false; // No known EDR in process → stub likely clean.
    }

    // Phase 2: Stub prologue inspection.
    // SAFETY: Reading 5 bytes from ntdll .text section (RX, always resident).
    let first_byte = unsafe { *stub_addr };
    if first_byte != 0xE9 {
        return false; // Not a JMP rel32 → not EDR hook pattern we recognize.
    }

    // Read rel32 offset (bytes 1-4, little-endian).
    let rel32 = unsafe {
        let offset_ptr = stub_addr.add(1) as *const i32;
        *offset_ptr
    };
    let target = stub_addr.wrapping_add(5).wrapping_add(rel32 as usize);

    // Check if target falls within any loaded EDR module's .text range.
    is_address_in_edr_module_range(target as *const c_void)
}
```

### Pattern 2: Thread-Suspend Protocol for Safe Patch
**What:** Enumerate all threads, suspend all except current, verify no RIP in stub range, perform atomic write, resume all.
**When to use:** During initial patch and during re-verification if stub needs re-patching.
**Example:**
```rust
// Source: [CITED: 51-CONTEXT.md D-08, D-09]
/// Safely patch a 5-byte JMP into an ntdll stub.
///
/// Returns Ok(()) on success, Err(PatchError) if aborted due to race or other issue.
unsafe fn atomic_patch_stub(stub_addr: *mut u8, jmp_bytes: &[u8; 5]) -> Result<(), PatchError> {
    assert_eq!(jmp_bytes.len(), 5);

    let current_tid = GetCurrentThreadId();
    let threads = enumerate_process_threads(GetCurrentProcessId())?;

    // Suspend all threads except current.
    for thread in &threads {
        if thread.tid != current_tid {
            let _ = NtSuspendThread(thread.handle, None);
        }
    }

    // Check RIP for each suspended thread.
    for thread in &threads {
        if thread.tid == current_tid {
            continue;
        }
        let rip = get_thread_rip(thread.handle)?;
        if rip >= stub_addr as usize && rip < (stub_addr as usize + 5) {
            // Thread is inside the stub range → abort to avoid torn instruction.
            resume_all_threads(&threads, current_tid);
            return Err(PatchError::RipInStubRange);
        }
    }

    // All clear → perform atomic 5-byte write.
    #[cfg(target_arch = "x86_64")]
    {
        // x64: naturally atomic for aligned 8-byte reads/writes.
        // We write 5 bytes but the CPU guarantees atomicity for the aligned 8-byte
        // boundary. The remaining 3 bytes are part of the original instruction
        // (mov eax, SSN) and are not modified.
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        VirtualProtect(stub_addr as *mut c_void, 8, PAGE_EXECUTE_READWRITE, &mut old_protect)?;

        // Write 5 bytes (JMP rel32).
        std::ptr::copy_nonoverlapping(jmp_bytes.as_ptr(), stub_addr, 5);

        // Restore protection.
        let mut _tmp = PAGE_PROTECTION_FLAGS(0);
        let _ = VirtualProtect(stub_addr as *mut c_void, 8, old_protect, &mut _tmp);
    }

    #[cfg(target_arch = "x86")]
    {
        // x86: use cmpxchg8b for atomic 8-byte compare-exchange.
        // Build an 8-byte value: new 5 bytes + original 3 bytes.
        let original_8 = *(stub_addr as *const u64);
        let new_8 = construct_new_8byte_value(original_8, jmp_bytes);
        atomic_cmpxchg8b(stub_addr as *mut u64, new_8, original_8)?;
    }

    resume_all_threads(&threads, current_tid);
    Ok(())
}
```

### Pattern 3: Ntdll Stub Trampoline Body
**What:** Trampoline that extracts path from ntdll args (UNICODE_STRING) and calls the shared classification pipeline.
**When to use:** As the detour target for `RawDetour::new()`.
**Example:**
```rust
// Source: [CITED: dlp-hook-dll/src/trampolines.rs HookNtCreateFile]
/// Ntdll stub trampoline for NtCreateFile.
///
/// This function has the same signature as the original ntdll stub.
/// It is called when the patched stub's JMP redirects here.
unsafe extern "system" fn NtdllTrampolineNtCreateFile(
    filehandle: *mut HANDLE,
    desiredaccess: u32,
    objectattributes: *mut c_void,
    iostatusblock: *mut c_void,
    allocationsize: *const i64,
    fileattributes: u32,
    shareaccess: u32,
    createdisposition: u32,
    createoptions: u32,
    eabuffer: *mut c_void,
    ealength: u32,
) -> NTSTATUS {
    crate::crash_guard::guard_trampoline(
        "NtCreateFile_ntdll",
        || {
            crate::crash_guard::with_reentrancy_guard(
                || {
                    let path = crate::extract_nt_path(objectattributes);
                    if let Some(_deny) = classify_and_log_path(&path, "CREATE", "NtCreateFile") {
                        return crate::fail_closed!(StatusAccessDenied);
                    }
                    // Call original stub via retour's trampoline.
                    let original: NtCreateFileFn = std::mem::transmute(
                        crate::ntdll_patcher::get_original_trampoline("NtCreateFile")
                    );
                    original(
                        filehandle, desiredaccess, objectattributes, iostatusblock,
                        allocationsize, fileattributes, shareaccess, createdisposition,
                        createoptions, eabuffer, ealength,
                    )
                },
                || {
                    // Fallback: call original without classification.
                    let original: NtCreateFileFn = std::mem::transmute(
                        crate::ntdll_patcher::get_original_trampoline("NtCreateFile")
                    );
                    original(
                        filehandle, desiredaccess, objectattributes, iostatusblock,
                        allocationsize, fileattributes, shareaccess, createdisposition,
                        createoptions, eabuffer, ealength,
                    )
                },
            )
        },
        || {
            // Panic fallback.
            let original: NtCreateFileFn = std::mem::transmute(
                crate::ntdll_patcher::get_original_trampoline("NtCreateFile")
            );
            original(
                filehandle, desiredaccess, objectattributes, iostatusblock,
                allocationsize, fileattributes, shareaccess, createdisposition,
                createoptions, eabuffer, ealength,
            )
        },
    )
}
```

### Anti-Patterns to Avoid
- **Restoring "clean" ntdll from disk:** DoppelGate-class evasion malware is detected by reading disk ntdll and comparing to memory. Never do this. [CITED: 51-CONTEXT.md D-06]
- **Re-patching over EDR:** If re-verification detects EDR has overwritten our trampoline, do NOT re-patch. Emit alert and leave unpatched. [CITED: 51-CONTEXT.md D-07]
- **Patching without thread suspend:** On x86, a 5-byte write is not naturally atomic. Without suspend, a thread executing the stub can read a torn instruction (e.g., partial JMP), causing undefined behavior or crash.
- **All-or-nothing re-verification:** If EDR patches only some stubs, continue verifying the others. Per-stub granularity maximizes coverage.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Detours-style trampolines | Custom inline asm with JMP encoding | `retour::RawDetour` | Handles RIP-relative relocation, hot-patch detection, cross-architecture support, edge cases (NOP-padded functions) [VERIFIED: docs.rs/retour] |
| EDR module enumeration | Custom PEB walker | `windows::Win32::System::ProcessStatus::EnumProcessModules` + `GetModuleFileNameExW` | MS-provided, stable across Windows versions, handles WoW64 correctly |
| Thread enumeration | Custom NtQuerySystemInformation wrapper | `NtQuerySystemInformation` with `SystemProcessInformation` | Required for full thread list; `CreateToolhelp32Snapshot` is slower and less reliable |
| Atomic 8-byte write on x64 | `cmpxchg8b` inline asm | Naturally aligned 8-byte store (guaranteed atomic by x64 architecture) | Intel/AMD guarantee aligned 8-byte reads/writes are atomic on x64 [CITED: Intel SDM Vol. 3A, 8.1.1] |
| Atomic 8-byte write on x86 | Custom spinlock | `lock cmpxchg8b` or `InterlockedCompareExchange64` | `cmpxchg8b` with `lock` prefix is the standard DWCAS on x86 [CITED: Intel SDM Vol. 2B] |
| BypassAlert IPC | Custom socket/protocol | Existing `pipe_client::send_request` in dlp-hook-dll | Already proven, same path as classification requests |

**Key insight:** The `retour` crate handles the hardest part of Detours-style hooking (instruction boundary analysis, RIP-relative relocation, trampoline generation). The remaining work is EDR detection (policy layer) and thread safety (protocol layer), both of which are domain-specific to this project.

## Runtime State Inventory

> This phase involves in-memory patching only — no stored data renames or migrations.

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | None — ntdll patching is purely in-memory | No data migration |
| Live service config | `enable_ntdll_patching` flag in agent-config TOML (new, default false) | Add config field, document in deployment guide |
| OS-registered state | None — no registry keys, scheduled tasks, or services modified | None |
| Secrets/env vars | None — no new secrets required | None |
| Build artifacts | None — existing hook DLL build process unchanged | None |

## Common Pitfalls

### Pitfall 1: retour Version Mismatch
**What goes wrong:** 51-CONTEXT.md specifies `retour` 0.3.1, but this version does not exist on crates.io. The latest available is 0.4.0-alpha.4.
**Why it happens:** The context document was written against an anticipated version that was never published, or conflated retour with a different crate's versioning.
**How to avoid:** Use 0.4.0-alpha.4 (verified available). The API surface (`RawDetour::new`, `enable`, `disable`, `trampoline`) is compatible with the documented 0.3.x interface. Update CONTEXT.md if needed.
**Warning signs:** `cargo add retour@0.3.1` fails with "no matching version found."

### Pitfall 2: EDR Arms Race on Re-verification
**What goes wrong:** Background thread detects EDR overwrote our trampoline and immediately re-patches. EDR detects the write and re-hooks. Loop continues, causing instability.
**Why it happens:** Violating D-07 (never re-patch over EDR).
**How to avoid:** On `HookOverwritten` detection, emit alert and mark stub as "EDR-controlled, skip permanently." Do NOT re-patch.
**Warning signs:** High CPU usage from background thread, repeated `BypassAlert` emissions, process crashes.

### Pitfall 3: Torn Instruction on x86 Without cmpxchg8b
**What goes wrong:** A 5-byte JMP write is observed partially by another thread executing the stub, causing it to jump to a garbage address.
**Why it happens:** x86 does not guarantee atomicity for unaligned or non-power-of-2 writes. A 5-byte write crosses an 8-byte boundary.
**How to avoid:** Use `lock cmpxchg8b` on x86 with a pre-aligned 8-byte buffer. On x64, aligned 8-byte writes are naturally atomic — write 8 bytes with the new 5 + original 3.
**Warning signs:** Intermittent crashes under load, WER fault addresses near ntdll stubs, chaos-test failures.

### Pitfall 4: False EDR Detection on Non-EDR JMP
**What goes wrong:** A legitimate Windows hot-patch or forwarder JMP is misclassified as EDR, causing us to skip patching a clean stub.
**Why it happens:** Some Windows builds use JMP forwarders in ntdll for compatibility shims. The target may be within ntdll itself, not an EDR module.
**How to avoid:** Two-phase detection (D-04): only skip if BOTH module pre-filter AND target-in-EDR-range are true. A JMP target within ntdll's own range is not EDR.
**Warning signs:** Bypass alerts show "EDR detected" but no EDR product is installed; direct-syscall tests pass when they should be blocked.

### Pitfall 5: Loader-Lock Deadlock in DllMain
**What goes wrong:** Attempting to enumerate modules or threads from `DllMain` during `DLL_PROCESS_ATTACH` causes deadlock because the loader lock is held.
**Why it happens:** `EnumProcessModules`, `NtQuerySystemInformation`, and thread operations are unsafe under loader lock.
**How to avoid:** Defer all ntdll patching to the first hook call (same pattern as Phase 50's `CacheLookup::get()` lazy init), NOT from `DllMain`.
**Warning signs:** Process hangs on DLL load, injection timeout in agent logs.

## Code Examples

### Verified Pattern: RawDetour Usage
```rust
// Source: [CITED: docs.rs/retour/0.4.0-alpha.4]
use retour::RawDetour;

// SAFETY: target and detour must be valid function pointers with compatible calling conventions.
unsafe {
    let detour = RawDetour::new(
        target_fn as *const (),
        detour_fn as *const (),
    )?;
    detour.enable()?;

    // Get trampoline to call original.
    let trampoline: unsafe extern "system" fn(...) = std::mem::transmute(detour.trampoline());

    // Later: disable and clean up.
    detour.disable()?;
}
```

### Verified Pattern: NtQuerySystemInformation Thread Enumeration
```rust
// Source: [CITED: gist.github.com/wizardy0ga/2ac64becc3d73ea25dfc7820da7eafb5]
use windows::Win32::System::Threading::NtQuerySystemInformation;
use windows::Win32::System::SystemInformation::SystemProcessInformation;

fn enumerate_threads(pid: u32) -> Vec<ThreadInfo> {
    // First call: get required buffer size.
    let mut size = 0u32;
    unsafe {
        let _ = NtQuerySystemInformation(
            SystemProcessInformation,
            None,
            0,
            Some(&mut size),
        );
    }

    // Allocate buffer and query.
    let mut buffer = vec![0u8; size as usize];
    unsafe {
        NtQuerySystemInformation(
            SystemProcessInformation,
            Some(buffer.as_mut_ptr() as *mut c_void),
            size,
            None,
        ).ok().expect("NtQuerySystemInformation failed");
    }

    // Walk the linked list of process entries.
    let mut threads = Vec::new();
    unsafe {
        let mut ptr = buffer.as_ptr() as *const SYSTEM_PROCESS_INFORMATION;
        loop {
            let entry = &*ptr;
            if entry.UniqueProcessId as u32 == pid {
                let thread_array = entry.Threads.as_ptr();
                for i in 0..entry.NumberOfThreads {
                    let thread = &*thread_array.add(i as usize);
                    threads.push(ThreadInfo {
                        tid: thread.ClientId.UniqueThread as u32,
                        start_address: thread.StartAddress as usize,
                    });
                }
                break;
            }
            if entry.NextEntryOffset == 0 {
                break;
            }
            ptr = (ptr as *const u8).add(entry.NextEntryOffset as usize)
                as *const SYSTEM_PROCESS_INFORMATION;
        }
    }
    threads
}
```

### Verified Pattern: x64 Aligned 8-Byte Atomic Write
```rust
// Source: [CITED: Intel SDM Vol. 3A, 8.1.1 — Guaranteed Atomic Operations]
/// On x64, aligned 8-byte reads and writes are naturally atomic.
/// We use this to atomically patch 5 bytes by writing 8 bytes
/// (new 5 + preserved original 3).
#[cfg(target_arch = "x86_64")]
unsafe fn atomic_write_5bytes(stub_addr: *mut u8, jmp_bytes: &[u8; 5]) {
    // Read original 8 bytes.
    let original = *(stub_addr as *const u64);

    // Construct new 8-byte value: jmp_bytes[0..5] + original_bytes[5..8].
    let mut new_val = original;
    let new_ptr = &mut new_val as *mut u64 as *mut u8;
    for i in 0..5 {
        *new_ptr.add(i) = jmp_bytes[i];
    }

    // Atomically write 8 bytes. On x64 this is naturally atomic for aligned addresses.
    *(stub_addr as *mut u64) = new_val;
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| IAT-only hooks (Phase 48-50) | IAT + ntdll stub patching (Phase 51) | v0.10.0 | Closes direct-syscall bypass gap |
| Reading clean ntdll from disk (DoppelGate) | Detect-and-skip EDR patches | 2020+ (DoppelGate published) | Avoids evasion-malware classifier |
| All-or-nothing hook enable/disable | Per-stub granularity | Phase 51 (D-13) | Maximizes coverage when EDR patches only some stubs |
| Custom inline asm trampolines | `retour` crate | Phase 51 (D-01) | Cross-architecture support, less maintenance |

**Deprecated/outdated:**
- `retour` 0.3.1: Specified in CONTEXT.md but does not exist on crates.io. Use 0.4.0-alpha.4.
- Reading ntdll from disk for "clean" bytes: Classified as evasion-malware behavior by modern EDRs. Never use.
- `CreateToolhelp32Snapshot` for thread enumeration: Slower and less reliable than `NtQuerySystemInformation`.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `retour` 0.4.0-alpha.4 API is compatible with documented 0.3.x interface (`RawDetour::new`, `enable`, `disable`, `trampoline`) | Standard Stack | Medium — API changes would require code adjustments; crate is alpha but CI-covered |
| A2 | x64 ntdll stubs always start with `mov r10, rcx; mov eax, SSN; syscall; ret` (12 bytes minimum) | Platform-Specific | Medium — if Microsoft changes stub layout, 5-byte JMP overwrites wrong bytes; need stub validation before patch |
| A3 | EDRs use `0xE9` (JMP rel32) as their primary hook encoding on ntdll stubs | EDR Detection | Medium — some EDRs may use `0xFF 0x25` (JMP r/m64) or other encodings; detection should be extensible |
| A4 | x64 aligned 8-byte writes are naturally atomic (Intel/AMD guarantee) | Thread Safety | Low — documented in Intel SDM Vol. 3A, 8.1.1 for decades |
| A5 | `NtQuerySystemInformation(SystemProcessInformation)` returns all threads including those created after our snapshot | Thread Enumeration | Low — this is the standard Windows thread enumeration API; handles remain valid after query |
| A6 | The four EDR vendors (CrowdStrike, SentinelOne, Defender, Carbon Black) patch ntdll stubs for file-I/O syscalls | EDR Detection | Medium — not all EDRs hook all stubs; our detection is defensive (skip if unsure) |
| A7 | `BypassAlert` IPC path from hook DLL to agent is available and has capacity for additional alert volume | Integration | Low — reuses existing pipe; alert rate is bounded (30s cycle, max 4 stubs) |

## Open Questions

1. **Does `retour` 0.4.0-alpha.4 handle ntdll stubs correctly?**
   - What we know: `RawDetour` patches function prologues with unconditional JMP and generates trampolines. It handles RIP-relative instructions and hot-patching.
   - What's unclear: Whether ntdll's `mov r10, rcx` (3 bytes) + `mov eax, SSN` (5 bytes) prologue is long enough for retour's 5-byte JMP without needing NOP/INT3 padding.
   - Recommendation: Validate with a test program before full integration. The stub is 12 bytes total (3 + 5 + 2 + 1), so 5 bytes should fit within the first instruction boundary.

2. **What is the exact EDR JMP pattern for each vendor?**
   - What we know: Generic pattern is `0xE9` rel32 after `mov r10, rcx`. CrowdStrike uses relocated stubs with XOR-encoded pointers.
   - What's unclear: Whether SentinelOne, Defender, or Carbon Black use different encodings (e.g., `0xFF 0x25` indirect JMP, push/ret sequences).
   - Recommendation: Start with `0xE9` detection and make the prologue inspector pluggable. Add vendor-specific patterns as discovered in testing.

3. **How does `retour` behave when the target is already patched by EDR?**
   - What we know: `RawDetour::new` reads the target prologue to build a trampoline. If the prologue is a JMP to EDR code, retour will copy the EDR's JMP into the trampoline.
   - What's unclear: Whether this causes the trampoline to chain into EDR (which may be acceptable) or break (if EDR's JMP is RIP-relative and the trampoline is at a different address).
   - Recommendation: Always call `is_edr_hooked()` BEFORE `RawDetour::new()`. If EDR detected, skip `RawDetour` entirely for that stub.

4. **What is the performance impact of thread suspend/resume on every patch cycle?**
   - What we know: Suspending 1000+ threads takes milliseconds. The chaos test (1000 threads, 100 cycles) must show zero crashes.
   - What's unclear: Whether the suspend latency causes noticeable application stutter.
   - Recommendation: Measure suspend+patch+resume time in the chaos test. If >10ms, consider optimizing by only suspending threads whose start address is in ntdll (filter by `StartAddress` from `SYSTEM_THREAD_INFORMATION`).

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Rust toolchain | retour compilation | Yes | 1.94.1 | — |
| i686-pc-windows-msvc target | x86 hook DLL build | Yes | installed via rustup | — |
| x86_64-pc-windows-msvc target | x64 hook DLL build | Yes | default toolchain | — |
| Windows SDK | Win32 APIs (NtQuerySystemInformation, etc.) | Yes | bundled with MSVC | — |
| retour crate | Detours-style trampolines | Yes (crates.io) | 0.4.0-alpha.4 | Custom inline asm (higher maintenance) |
| Test EDR endpoint | EDR detection validation | No | — | Manual testing with EDR VMs; unit tests with mocked module ranges |

**Missing dependencies with no fallback:**
- Real EDR endpoint for integration testing. Must be addressed via manual QA on VMs with each supported EDR product.

**Missing dependencies with fallback:**
- None identified.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Built-in `#[test]` + `cargo test` |
| Config file | None — see Wave 0 |
| Quick run command | `cargo test -p dlp-hook-dll` |
| Full suite command | `cargo test --workspace` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| BLOCK-08 | Direct-syscall test denied with STATUS_ACCESS_DENIED | Integration (requires real Windows + Go binary) | Manual-only: build Go direct-syscall binary, run with `enable_ntdll_patching=true` | N/A |
| BLOCK-08 | retour trampoline correctly patches ntdll stub | Unit | `cargo test -p dlp-hook-dll ntdll_patcher` | No — Wave 0 gap |
| BLOCK-08 | Thread-suspend protocol aborts when RIP in stub range | Unit | `cargo test -p dlp-hook-dll thread_suspender` | No — Wave 0 gap |
| BLOCK-08 | Atomic 5-byte write on x64 is non-tearing | Unit | `cargo test -p dlp-hook-dll atomic_write` | No — Wave 0 gap |
| BLOCK-09 | EDR detection skips patching when EDR module detected | Unit (mocked module ranges) | `cargo test -p dlp-hook-dll edr_detector` | No — Wave 0 gap |
| BLOCK-09 | Re-verification emits BypassAlert on EDR overwrite | Unit (mocked stub state) | `cargo test -p dlp-hook-dll reverify` | No — Wave 0 gap |
| BLOCK-09 | Feature flag defaults off | Unit | `cargo test -p dlp-agent config_default` | No — Wave 0 gap |
| BLOCK-09 | SIEM event emitted at boot when flag on | Unit | `cargo test -p dlp-agent siem_event` | No — Wave 0 gap |

### Sampling Rate
- **Per task commit:** `cargo test -p dlp-hook-dll`
- **Per wave merge:** `cargo test --workspace`
- **Phase gate:** Full suite green + chaos test on real Windows host (manual)

### Wave 0 Gaps
- [ ] `dlp-hook-dll/src/ntdll_patcher.rs` — does not exist; needs creation
- [ ] `dlp-hook-dll/src/edr_detector.rs` — does not exist; needs creation
- [ ] `dlp-hook-dll/src/thread_suspender.rs` — does not exist; needs creation
- [ ] `dlp-hook-dll/tests/ntdll_chaos_test.rs` — chaos test fixture (1000 threads, 100 cycles)
- [ ] `dlp-agent/src/config.rs` — extend `AgentConfig` with `enable_ntdll_patching`
- [ ] `dlp-common/src/hook_ipc.rs` — extend `BypassAlert` with `HookOverwritten`
- [ ] `dlp-common/src/audit.rs` — add `ntdll_patching_enabled` event type

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No | N/A |
| V3 Session Management | No | N/A |
| V4 Access Control | Yes | ntdll stub patching enforces ABAC decisions at syscall layer |
| V5 Input Validation | Yes | Path normalization from Phase 50 reused; EDR detection validates stub bytes |
| V6 Cryptography | No | N/A |
| V7 Error Handling | Yes | `guard_trampoline` + SEH prevents process crash on patch failure |
| V8 Data Protection | Yes | DLP core function — prevents data exfiltration via direct syscalls |
| V10 Malicious Code | Yes | EDR coexistence prevents classification as evasion malware |

### Known Threat Patterns for This Stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Direct syscall bypass (SysWhispers) | Elevation of Privilege | ntdll stub patching closes bypass |
| EDR hook overwrite arms race | Denial of Service | Detect-and-skip; never re-patch over EDR |
| DoppelGate evasion classifier | Repudiation | Never read "clean" ntdll from disk |
| Torn instruction crash | Denial of Service | Thread-suspend protocol + atomic writes |
| Loader-lock deadlock | Denial of Service | Lazy init on first hook call, not DllMain |

## Sources

### Primary (HIGH confidence)
- [docs.rs/retour/0.4.0-alpha.4](https://docs.rs/retour/0.4.0-alpha.4/retour/) — `RawDetour` API: `new`, `enable`, `disable`, `trampoline`
- [crates.io/retour](https://crates.io/crates/retour) — Version verification: 0.4.0-alpha.4 published 2023-11-15
- [GitHub Hpmason/retour-rs releases](https://github.com/Hpmason/retour-rs/releases) — Release notes for v0.4.0-alpha.2 (trailing comma support, thiscall stabilization)
- [51-CONTEXT.md](.planning/phases/51-ntdll-syscall-stub-trampolines-edr-coexistence/51-CONTEXT.md) — Locked decisions D-01 through D-18

### Secondary (MEDIUM confidence)
- [wbenny's Gist - Windows syscall stubs](https://gist.github.com/wbenny/b08ef73b35782a1f57069dff2327ee4d) — ntdll stub byte patterns across Windows versions
- [PassTheHashBrowns - Hiding Your Syscalls](https://passthehashbrowns.github.io/hiding-your-syscalls) — EDR hook patterns and detection
- [SysWhispers4 Documentation](https://joasasantos-syswhispers4.mintlify.app/) — Direct syscall bypass techniques and SSN resolution
- [DoppelGate GitHub](https://github.com/asaurusrex/DoppelGate) — Disk-based ntdll reading technique and detection risks
- [Intel SDM Vol. 3A, 8.1.1](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html) — Guaranteed atomic operations (aligned 8-byte on x64)
- [Felix Cloutier - cmpxchg8b/cmpxchg16b](https://www.felixcloutier.com/x86/cmpxchg8b:cmpxchg16b) — x86 atomic compare-exchange instructions

### Tertiary (LOW confidence)
- Web search results for EDR-specific hook patterns — Community research, not vendor documentation. Patterns may vary by EDR version.
- [malwaretech.com EDR bypass introduction](https://malwaretech.com/2023/12/an-introduction-to-bypassing-user-mode-edr-hooks.html) — General concepts, vendor-specific details unverified.

## Metadata

**Confidence breakdown:**
- Standard stack: MEDIUM — `retour` crate verified on crates.io but alpha quality; API compatibility with 0.3.x assumed
- Architecture: HIGH — Thread-suspend protocol is well-established pattern; atomicity guarantees from Intel/AMD docs
- Pitfalls: MEDIUM — EDR detection patterns from community research, not vendor docs; may need iteration

**Research date:** 2026-05-22
**Valid until:** 2026-06-22 (30 days for stable stack; EDR patterns may need earlier refresh as vendors evolve)
