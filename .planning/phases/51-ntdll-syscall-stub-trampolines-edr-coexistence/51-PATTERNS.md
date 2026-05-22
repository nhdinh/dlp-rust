# Phase 51: ntdll Syscall-Stub Trampolines + EDR Coexistence - Pattern Map

**Mapped:** 2026-05-22
**Files analyzed:** 12
**Analogs found:** 11 / 12

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `dlp-hook-dll/src/ntdll_patcher.rs` | service | event-driven | `dlp-hook-dll/src/pe_utils.rs` | role-match |
| `dlp-hook-dll/src/edr_detector.rs` | utility | request-response | `dlp-agent/src/allowlist.rs` | partial-match |
| `dlp-hook-dll/src/thread_suspender.rs` | utility | request-response | `dlp-hook-dll/src/pe_utils.rs` | partial-match |
| `dlp-hook-dll/src/trampolines.rs` (modify) | component | request-response | `dlp-hook-dll/src/trampolines.rs` (existing `HookNtCreateFile`) | exact |
| `dlp-hook-dll/src/background_thread.rs` (modify) | component | event-driven | `dlp-hook-dll/src/background_thread.rs` | exact |
| `dlp-hook-dll/src/lib.rs` (modify) | component | request-response | `dlp-hook-dll/src/lib.rs` | exact |
| `dlp-agent/src/config.rs` (modify) | config | request-response | `dlp-agent/src/config.rs` (existing `cloud_hook_enabled`) | exact |
| `dlp-agent/src/service.rs` (modify) | service | request-response | `dlp-agent/src/service.rs` (existing hook injector init) | exact |
| `dlp-common/src/hook_ipc.rs` (modify) | model | request-response | `dlp-common/src/hook_ipc.rs` | exact |
| `dlp-common/src/audit.rs` (modify) | model | request-response | `dlp-common/src/audit.rs` | exact |
| `dlp-hook-dll/tests/ntdll_chaos_test.rs` | test | batch | `dlp-hook-dll/src/pe_utils.rs` tests | role-match |
| `dlp-hook-dll/Cargo.toml` (modify) | config | - | `dlp-hook-dll/Cargo.toml` | exact |

## Pattern Assignments

### `dlp-hook-dll/src/ntdll_patcher.rs` (service, event-driven)

**Analog:** `dlp-hook-dll/src/pe_utils.rs` (VirtualProtect pattern, atomic memory operations)

**Imports pattern** (lines 1-10 of pe_utils.rs):
```rust
use windows::Win32::System::Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE};
```

**Core patch pattern** (lines 144-165 of pe_utils.rs):
```rust
pub unsafe fn patch_iat(iat: *mut usize, new_fn: *mut std::ffi::c_void) -> bool {
    let mut old_protect = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
    let size = std::mem::size_of::<usize>();
    let ok = VirtualProtect(
        iat as *mut std::ffi::c_void,
        size,
        PAGE_EXECUTE_READWRITE,
        &mut old_protect,
    )
    .is_ok();

    if !ok {
        return false;
    }

    *iat = new_fn as usize;

    let mut _tmp = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
    let _ = VirtualProtect(iat as *mut std::ffi::c_void, size, old_protect, &mut _tmp);

    true
}
```

**Atomic write pattern** (from RESEARCH.md Pattern 2, x64):
```rust
#[cfg(target_arch = "x86_64")]
unsafe fn atomic_write_5bytes(stub_addr: *mut u8, jmp_bytes: &[u8; 5]) {
    let original = *(stub_addr as *const u64);
    let mut new_val = original;
    let new_ptr = &mut new_val as *mut u64 as *mut u8;
    for i in 0..5 {
        *new_ptr.add(i) = jmp_bytes[i];
    }
    *(stub_addr as *mut u64) = new_val;
}
```

**Error handling pattern:** Use `Result<T, E>` with custom error types. Follow `pe_utils.rs` pattern of returning `bool` for simple success/failure, or `Result` for rich error info.

---

### `dlp-hook-dll/src/edr_detector.rs` (utility, request-response)

**Analog:** `dlp-agent/src/allowlist.rs` (module enumeration, pattern matching)

**Imports pattern** (lines 1-13 of allowlist.rs):
```rust
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
```

**Module enumeration pattern** (from RESEARCH.md):
```rust
use windows::Win32::System::ProcessStatus::EnumProcessModules;
use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;
```

**Two-phase detection pattern** (from RESEARCH.md Pattern 1):
```rust
fn is_edr_hooked(stub_addr: *const u8) -> bool {
    let known_edr_modules = ["csagent.dll", "csfalcon.dll", "SentinelAgent.dll"];
    if !any_known_edr_module_loaded(&known_edr_modules) {
        return false;
    }

    let first_byte = unsafe { *stub_addr };
    if first_byte != 0xE9 {
        return false;
    }

    let rel32 = unsafe {
        let offset_ptr = stub_addr.add(1) as *const i32;
        *offset_ptr
    };
    let target = stub_addr.wrapping_add(5).wrapping_add(rel32 as usize);

    is_address_in_edr_module_range(target as *const c_void)
}
```

**Pattern matching style** (lines 119-138 of allowlist.rs):
```rust
for entry in &self.entries {
    match &entry.match_type {
        MatchType::ExactPath => {
            if image_path.eq_ignore_ascii_case(&entry.value) {
                return Some(entry.category);
            }
        }
        MatchType::PathGlob => {
            if glob_match(&entry.value, image_path) {
                return Some(entry.category);
            }
        }
        // ...
    }
}
```

---

### `dlp-hook-dll/src/thread_suspender.rs` (utility, request-response)

**Analog:** `dlp-hook-dll/src/pe_utils.rs` (Windows API calls, unsafe blocks)

**Thread enumeration pattern** (from RESEARCH.md):
```rust
use windows::Win32::System::Threading::NtQuerySystemInformation;
use windows::Win32::System::SystemInformation::SystemProcessInformation;

fn enumerate_threads(pid: u32) -> Vec<ThreadInfo> {
    let mut size = 0u32;
    unsafe {
        let _ = NtQuerySystemInformation(
            SystemProcessInformation,
            None,
            0,
            Some(&mut size),
        );
    }

    let mut buffer = vec![0u8; size as usize];
    unsafe {
        NtQuerySystemInformation(
            SystemProcessInformation,
            Some(buffer.as_mut_ptr() as *mut c_void),
            size,
            None,
        ).ok().expect("NtQuerySystemInformation failed");
    }
    // Walk linked list...
}
```

**Thread suspend/resume pattern:**
```rust
// Suspend all threads except current
for thread in &threads {
    if thread.tid != current_tid {
        let _ = NtSuspendThread(thread.handle, None);
    }
}

// RIP check
for thread in &threads {
    if thread.tid == current_tid { continue; }
    let rip = get_thread_rip(thread.handle)?;
    if rip >= stub_addr as usize && rip < (stub_addr as usize + 5) {
        resume_all_threads(&threads, current_tid);
        return Err(PatchError::RipInStubRange);
    }
}
```

---

### `dlp-hook-dll/src/trampolines.rs` (modify) (component, request-response)

**Analog:** `dlp-hook-dll/src/trampolines.rs` (existing `HookNtCreateFile`, lines 466-550)

**Ntdll trampoline body pattern** (lines 466-550):
```rust
#[unsafe(no_mangle)]
pub unsafe extern "system" fn HookNtCreateFile(
    filehandle: *mut HANDLE,
    desiredaccess: u32,
    objectattributes: *mut std::ffi::c_void,
    // ...
) -> NTSTATUS {
    crate::crash_guard::guard_trampoline(
        "NtCreateFile",
        || {
            crate::crash_guard::with_reentrancy_guard(
                || {
                    let path = crate::extract_nt_path(objectattributes);
                    if let Some(_deny) = classify_and_log_path(&path, "CREATE", "NtCreateFile") {
                        return crate::fail_closed!(StatusAccessDenied);
                    }
                    let original = crate::ORIGINAL_NT_CREATE_FILE.unwrap_or_else(|| {
                        crate::resolve_nt_create_file().unwrap_or_else(|| {
                            panic!("NtCreateFile original unavailable and resolution failed")
                        })
                    });
                    original(filehandle, desiredaccess, objectattributes, /* ... */)
                },
                || { /* fallback */ },
            )
        },
        || { /* panic fallback */ },
    )
}
```

**Key pattern for ntdll stub trampolines:** The new ntdll stub trampolines follow the EXACT same structure but call `crate::ntdll_patcher::get_original_trampoline("NtCreateFile")` instead of `crate::ORIGINAL_NT_CREATE_FILE` to get the retour-generated trampoline pointer.

---

### `dlp-hook-dll/src/background_thread.rs` (modify) (component, event-driven)

**Analog:** `dlp-hook-dll/src/background_thread.rs` (existing 100ms timer loop, lines 113-176)

**Timer loop pattern** (lines 126-175):
```rust
fn background_thread_loop(
    cache_header: *const CacheHeader,
    fail_state: Arc<FailModeState>,
    shutdown_event: windows::Win32::Foundation::HANDLE,
) {
    unsafe {
        use windows::Win32::Foundation::WAIT_OBJECT_0;
        use windows::Win32::System::Threading::WaitForSingleObject;

        loop {
            let wait_result = WaitForSingleObject(shutdown_event, 100);
            if wait_result == WAIT_OBJECT_0 {
                break;
            }

            let current_state = fail_state.current_state();
            match current_state {
                FailState::Isolated => {
                    // Check cache version...
                }
                _ => {}
            }
        }
    }
}
```

**Extension point:** Add a 30-second counter (300 iterations of 100ms) that calls `verify_trampolines()` every 300 cycles. The verification reads first 5 bytes of each patched stub and compares against expected JMP pattern.

---

### `dlp-hook-dll/src/lib.rs` (modify) (component, request-response)

**Analog:** `dlp-hook-dll/src/lib.rs` (existing `HookDescriptor`, `HOOKS` table, `init()`)

**HookDescriptor pattern** (lines 287-305):
```rust
#[derive(Clone, Copy)]
struct HookDescriptor {
    fn_name: &'static str,
    dll_name: &'static str,
    original_ptr: *mut usize,
    iat_ptr: *mut usize,
    trampoline_ptr: *const (),
    #[allow(dead_code)]
    deny_return: DenyReturn,
}
```

**Extension:** Add fields:
```rust
    /// Address of the ntdll syscall stub (resolved at runtime).
    ntdll_stub_addr: *mut u8,
    /// Original 5 bytes of the ntdll stub (saved before patching).
    original_ntdll_bytes: [u8; 5],
    /// retour RawDetour handle (for enable/disable/trampoline access).
    detour: Option<retour::RawDetour>,
```

**init() pattern** (lines 431-469):
```rust
fn init() {
    if INITIALISED.swap(true, Ordering::SeqCst) {
        return;
    }
    unsafe {
        let host = GetModuleHandleW(None).unwrap_or_default();
        // ... patch IAT entries driven by HOOKS table
    }
}
```

**Extension point:** After IAT patching, conditionally call `ntdll_patcher::patch_all_stubs()` if `enable_ntdll_patching` flag is set (passed via shared memory or read from a global set during injection).

**resolve_proc pattern** (lines 478-490):
```rust
unsafe fn resolve_proc(dll_name: &str, fn_name: &str) -> *const std::ffi::c_void {
    let dll_wide: Vec<u16> = dll_name.encode_utf16().chain(std::iter::once(0)).collect();
    let dll = GetModuleHandleW(windows::core::PCWSTR::from_raw(dll_wide.as_ptr()));
    let dll = match dll { Ok(h) => h, Err(_) => return std::ptr::null() };
    let name = windows::core::PCSTR::from_raw(fn_name.as_ptr());
    match GetProcAddress(dll, name) {
        Some(p) => p as *const std::ffi::c_void,
        None => std::ptr::null(),
    }
}
```

---

### `dlp-agent/src/config.rs` (modify) (config, request-response)

**Analog:** `dlp-agent/src/config.rs` (existing `cloud_hook_enabled` field, lines 219-220)

**Config field pattern** (lines 219-220):
```rust
    /// Whether the cloud sync hook DLL is enabled (M017/S01).
    /// When `None`, defaults to `false`. Populated by server config push.
    #[serde(default)]
    pub cloud_hook_enabled: Option<bool>,
```

**New field to add:**
```rust
    /// Phase 51: Enable ntdll syscall-stub patching for direct-syscall bypass defense.
    /// When `None`, defaults to `false`. Must be explicitly enabled by operator.
    #[serde(default)]
    pub enable_ntdll_patching: Option<bool>,
```

**Test pattern** (lines 603-608):
```rust
    #[test]
    fn test_agent_config_new_fields_default() {
        let config = AgentConfig::default();
        assert!(config.heartbeat_interval_secs.is_none());
        assert!(config.offline_cache_enabled.is_none());
    }
```

---

### `dlp-agent/src/service.rs` (modify) (service, request-response)

**Analog:** `dlp-agent/src/service.rs` (existing hook injector initialization, lines 1131-1156)

**Hook injector init pattern** (lines 1131-1156):
```rust
    let hook_injector_opt: Option<crate::hook_injector::HookInjector> =
        if agent_config.cloud_hook_enabled.unwrap_or(false) {
            let dll_path = /* ... */;
            let injector = crate::hook_injector::HookInjector::new(&dll_path, Some(dll_path_x86.clone()));
            Some(injector)
        } else {
            None
        };
```

**Extension point:** Pass `enable_ntdll_patching` flag to the injector, which passes it to the hook DLL via shared memory or pipe during injection. The hook DLL reads this flag before deciding whether to patch ntdll stubs.

---

### `dlp-common/src/hook_ipc.rs` (modify) (model, request-response)

**Analog:** `dlp-common/src/hook_ipc.rs` (existing `HookRequest`, `HookResponse` structs)

**Struct extension pattern** (lines 83-104):
```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct HookRequest {
    pub path: String,
    pub action: String,
    #[serde(default)]
    pub cache_version: u64,
    #[serde(default = "default_protocol_version")]
    pub protocol_version: u8,
    #[serde(default)]
    pub op: HookOp,
}
```

**New type to add:**
```rust
/// Alert emitted by the hook DLL when it detects a bypass attempt or EDR conflict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BypassAlert {
    /// The reason for the alert.
    pub reason: BypassReason,
    /// The affected ntdll stub name (e.g., "NtCreateFile").
    pub stub_name: String,
    /// Process ID where the alert occurred.
    pub pid: u32,
    /// Timestamp (Unix epoch seconds).
    pub timestamp_secs: u64,
}

/// Reasons a bypass alert can be emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BypassReason {
    /// Our trampoline was overwritten by EDR (or other hook).
    HookOverwritten,
    /// Thread RIP was inside the stub range during patch attempt.
    PatchRaced,
    /// EDR detected at boot, patching skipped for this stub.
    EdrDetected,
}
```

---

### `dlp-common/src/audit.rs` (modify) (model, request-response)

**Analog:** `dlp-common/src/audit.rs` (existing `EventType` enum, lines 28-68)

**Event type extension pattern** (lines 28-68):
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventType {
    Access,
    Block,
    Alert,
    ConfigChange,
    // ...
    DiskDiscovery,
    DiskMountBlocked,
    // ...
}
```

**New variants to add:**
```rust
    /// Phase 51: ntdll patching was enabled at agent boot.
    NtdllPatchingEnabled,
    /// Phase 51: EDR was detected at boot while ntdll patching is enabled.
    NtdllPatchingEdrDetected,
    /// Phase 51: A hook trampoline was overwritten (potential bypass or EDR conflict).
    HookOverwritten,
```

**SIEM routing pattern** (lines 73-94):
```rust
    pub fn routed_to_siem(self) -> bool {
        matches!(
            self,
            Self::Access
                | Self::Block
                | Self::Alert
                // ...
        )
    }
```

**Extension:** Add new variants to `routed_to_siem()` — all three new event types route to SIEM.

---

### `dlp-hook-dll/tests/ntdll_chaos_test.rs` (test, batch)

**Analog:** `dlp-hook-dll/src/pe_utils.rs` tests (VirtualAlloc-based test harness, lines 248-379)

**Test harness pattern** (lines 248-379):
```rust
#[test]
fn find_iat_entry_respects_max_descriptors_bound() {
    use windows::Win32::System::Memory::{
        VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    };

    unsafe {
        let pe_ptr = VirtualAlloc(
            None,
            BUF_SIZE,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        ) as *mut u8;
        assert!(!pe_ptr.is_null(), "VirtualAlloc failed");
        // ... setup test data ...
        // Cleanup
        let _ = windows::Win32::System::Memory::VirtualFree(
            pe_ptr as *mut std::ffi::c_void,
            0,
            windows::Win32::System::Memory::VIRTUAL_FREE_TYPE(0x8000),
        );
    }
}
```

**Chaos test pattern:** Spawn 1000 threads calling `NtCreateFile` in a loop. Main thread performs 100 patch/unpatch cycles. Verify zero crashes, zero WER events, zero torn reads.

---

### `dlp-hook-dll/Cargo.toml` (modify) (config, -)

**Analog:** `dlp-hook-dll/Cargo.toml` (existing dependencies)

**Dependency addition pattern:**
```toml
[dependencies]
# ... existing deps ...
retour = "0.4.0-alpha.4"
```

**Note:** RESEARCH.md verified `retour` 0.4.0-alpha.4 is the latest available on crates.io. The 0.3.1 version specified in CONTEXT.md does not exist.

---

## Shared Patterns

### Crash Guard Pattern
**Source:** `dlp-hook-dll/src/crash_guard.rs`
**Apply to:** All ntdll stub trampoline functions
```rust
crate::crash_guard::guard_trampoline(
    "NtCreateFile_ntdll",
    || {
        crate::crash_guard::with_reentrancy_guard(
            || { /* hook body */ },
            || { /* reentrancy fallback */ },
        )
    },
    || { /* panic fallback */ },
)
```

### Fail-Closed Return Pattern
**Source:** `dlp-hook-dll/src/fail_closed.rs`
**Apply to:** All ntdll stub trampolines on deny path
```rust
crate::fail_closed!(StatusAccessDenied);  // For NTSTATUS-returning stubs
crate::fail_closed!(BoolFalse);           // For BOOL-returning stubs
```

### Classification Pipeline Pattern
**Source:** `dlp-hook-dll/src/trampolines.rs` (lines 68-302)
**Apply to:** All ntdll stub trampolines
```rust
fn classify_and_log_path(
    path: &str,
    action: &str,
    fn_name: &str,
) -> Option<crate::fail_closed::DenyReturn> {
    // 1. Check allowlist
    // 2. Check shared-memory cache (includes LRU)
    // 3. Get fail_mode state
    // 4. Apply state-specific logic (Healthy/Degraded/Isolated/Resync)
    // 5. Return Some(deny) or None
}
```

### NT Path Extraction Pattern
**Source:** `dlp-hook-dll/src/lib.rs` (lines 638-658)
**Apply to:** NtCreateFile, NtOpenFile ntdll stub trampolines
```rust
pub(crate) unsafe fn extract_nt_path(objectattributes: *mut std::ffi::c_void) -> String {
    if objectattributes.is_null() { return String::new(); }
    let object_name_ptr = *(objectattributes.offset(OBJECT_ATTRIBUTES_OBJECT_NAME_OFFSET) as *mut *mut u8);
    // ... extract UNICODE_STRING.Buffer ...
}
```

### Lazy Initialization Pattern
**Source:** `dlp-hook-dll/src/classification_cache.rs` (lines 155-172)
**Apply to:** ntdll patcher initialization (MUST NOT call from DllMain)
```rust
static CACHE_LOOKUP: OnceLock<Option<CacheLookup>> = OnceLock::new();

impl CacheLookup {
    pub fn get() -> Option<&'static CacheLookup> {
        let opt = CACHE_LOOKUP.get_or_init(|| {
            unsafe { Self::try_init() }
        });
        opt.as_ref()
    }
}
```

### Atomic Operations on Shared Memory
**Source:** `dlp-hook-dll/src/classification_cache.rs` (lines 240-242)
**Apply to:** Re-verification thread reading stub bytes
```rust
pub fn current_version_word(&self) -> u64 {
    unsafe { (*self.header).version_word.load(Ordering::Acquire) }
}
```

### Debug Logging Pattern
**Source:** `dlp-hook-dll/src/lib.rs` (lines 605-608)
**Apply to:** All new modules
```rust
pub(crate) fn debug_log(msg: &str) {
    let wide: Vec<u16> = msg.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe { OutputDebugStringW(PCWSTR::from_raw(wide.as_ptr())) };
}
```

### Windows API Error Handling Pattern
**Source:** `dlp-hook-dll/src/lib.rs` (lines 478-490)
**Apply to:** All Windows API calls in new modules
```rust
let dll = GetModuleHandleW(windows::core::PCWSTR::from_raw(dll_wide.as_ptr()));
let dll = match dll {
    Ok(h) => h,
    Err(_) => return std::ptr::null(),
};
```

## No Analog Found

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| None | - | - | All files have at least partial analogs |

## Metadata

**Analog search scope:** `dlp-hook-dll/src/`, `dlp-agent/src/`, `dlp-common/src/`
**Files scanned:** 12
**Pattern extraction date:** 2026-05-22

### Key Patterns Identified

1. **All trampolines use `guard_trampoline` + `with_reentrancy_guard` + `fail_closed!` macro** — ntdll stub trampolines must follow identical pattern
2. **Lazy initialization via `OnceLock` (NOT from `DllMain`)** — critical for ntdll patcher to avoid loader-lock deadlock
3. **Classification pipeline (`classify_and_log_path`) is reused verbatim** — ntdll trampolines extract path then call same function
4. **Per-stub granularity** — each stub has independent patch state, EDR detection result, and re-verification status
5. **Atomic 5-byte write** — x64 uses naturally atomic aligned 8-byte write; x86 uses `cmpxchg8b`
6. **Background thread extends existing 100ms timer** — add 30-second (300-iteration) counter for trampoline verification
7. **AgentConfig uses `Option<bool>` with `#[serde(default)]`** — follow same pattern for `enable_ntdll_patching`
8. **Audit event types use `SCREAMING_SNAKE_CASE` serde rename** — new event types must follow same convention
9. **Hook IPC uses `bincode` for serialization** — `BypassAlert` must derive `Serialize + Deserialize`
10. **EDR module list derived from `AllowlistCategory::Avedr`** — reuse existing allowlist infrastructure
