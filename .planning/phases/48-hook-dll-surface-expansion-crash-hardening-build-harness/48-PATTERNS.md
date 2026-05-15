# Phase 48: Hook DLL Surface Expansion + Crash Hardening + Build Harness - Pattern Map

**Mapped:** 2026-05-15
**Files analyzed:** 14
**Analogs found:** 13 / 14

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `dlp-hook-dll/src/lib.rs` (modify) | library | event-driven | `dlp-hook-dll/src/lib.rs` (current) | exact |
| `dlp-hook-dll/src/pipe_client.rs` (modify) | service | request-response | `dlp-hook-dll/src/pipe_client.rs` (current) | exact |
| `dlp-hook-dll/src/pe_utils.rs` (new) | utility | transform | `dlp-hook-dll/src/lib.rs` lines 174-238 | exact |
| `dlp-hook-dll/src/trampolines.rs` (new) | component | event-driven | `dlp-hook-dll/src/lib.rs` lines 292-430 | exact |
| `dlp-hook-dll/src/crash_guard.rs` (new) | middleware | event-driven | `dlp-hook-dll/src/lib.rs` lines 292-357 | role-match |
| `dlp-hook-dll/src/fail_closed.rs` (new) | utility | transform | `dlp-hook-dll/src/lib.rs` lines 318-337, 393-410 | exact |
| `dlp-hook-dll/src/handle_ipc.rs` (new) | component | request-response | `dlp-common/src/hook_ipc.rs` | role-match |
| `dlp-hook-dll/Cargo.toml` (modify) | config | static | `dlp-hook-dll/Cargo.toml` (current) | exact |
| `dlp-hook-dll/build.rs` (modify) | config | static | none | no-analog |
| `.github/workflows/release.yml` (new) | config | batch | `.github/workflows/build.yml` | role-match |
| `installer/DLPAgent.wxs` (modify) | config | static | `installer/DLPAgent.wxs` (current) | exact |
| `dlp-agent/src/service.rs` (modify) | service | request-response | `dlp-agent/src/service.rs` lines 975-987 | exact |
| `dlp-common/src/hook_ipc.rs` (modify) | model | request-response | `dlp-common/src/hook_ipc.rs` (current) | exact |
| `dlp-e2e/` (modify tests) | test | request-response | `dlp-e2e/tests/*.rs` | role-match |

## Pattern Assignments

### `dlp-hook-dll/src/lib.rs` (library, event-driven) — MODIFY

**Analog:** `dlp-hook-dll/src/lib.rs` (current, lines 1-679)

**Imports pattern** (lines 1-30):
```rust
use std::sync::atomic::{AtomicBool, Ordering};
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{
    SetLastError, ERROR_ACCESS_DENIED, HANDLE, INVALID_HANDLE_VALUE, NTSTATUS,
};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::Storage::FileSystem::{
    FILE_CREATION_DISPOSITION, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE,
};
use windows::Win32::System::Diagnostics::Debug::OutputDebugStringW;
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE};

use dlp_common::{Decision, HookRequest};
```

**DllMain + init pattern** (lines 273-133):
```rust
#[unsafe(no_mangle)]
extern "system" fn DllMain(_inst: isize, reason: u32, _reserved: usize) -> i32 {
    const DLL_PROCESS_ATTACH: u32 = 1;
    if reason == DLL_PROCESS_ATTACH {
        init();
    }
    1
}

static INITIALISED: AtomicBool = AtomicBool::new(false);

fn init() {
    if INITIALISED.swap(true, Ordering::SeqCst) {
        return;
    }
    // ... patch all IAT entries
}
```

**Per-function static mut pattern** (lines 35-70):
```rust
static mut ORIGINAL_CREATE_FILE_W: Option<
    unsafe extern "system" fn(PCWSTR, u32, FILE_SHARE_MODE, *const SECURITY_ATTRIBUTES,
        FILE_CREATION_DISPOSITION, FILE_FLAGS_AND_ATTRIBUTES, HANDLE) -> HANDLE,
> = None;

static mut IAT_CREATE_FILE_W: Option<*mut usize> = None;
```

**Debug logging pattern** (lines 72-76):
```rust
fn debug_log(msg: &str) {
    let wide: Vec<u16> = msg.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe { OutputDebugStringW(PCWSTR::from_raw(wide.as_ptr())) };
}
```

**Path hash for privacy** (lines 78-85):
```rust
fn hash_path(path: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut s = DefaultHasher::new();
    path.hash(&mut s);
    s.finish()
}
```

**UnhookAll pattern** (lines 432-450):
```rust
#[unsafe(no_mangle)]
pub extern "system" fn UnhookAll() {
    debug_log("[dlp-hook] UnhookAll called — restoring IAT\0");
    unsafe {
        if let Some(iat) = IAT_CREATE_FILE_W {
            if let Some(orig) = ORIGINAL_CREATE_FILE_W {
                let _ = restore_iat(iat, orig as usize);
            }
        }
        // ... repeat for each hook
    }
}
```

**Test pattern** (lines 519-678):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use dlp_agent::hook_ipc::HookIpcServer;
    use dlp_common::{Decision, HookRequest, HookResponse};
    use std::sync::Arc;
    use std::time::Duration;

    fn start_agent_mock_server(
        pipe_name: &str,
        handler: Arc<dyn Fn(HookRequest) -> HookResponse + Send + Sync>,
    ) -> std::thread::JoinHandle<()> {
        let name = pipe_name.to_string();
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let handle = std::thread::spawn(move || {
            let server = HookIpcServer::new(name, handler);
            server.run_with_ready(|| { let _ = tx.send(()); }).unwrap();
        });
        rx.recv_timeout(Duration::from_secs(5)).expect("mock server did not become ready");
        handle
    }
}
```

---

### `dlp-hook-dll/src/pipe_client.rs` (service, request-response) — MODIFY

**Analog:** `dlp-hook-dll/src/pipe_client.rs` (current, lines 1-226)

**Imports pattern** (lines 1-15):
```rust
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_FLAGS_AND_ATTRIBUTES, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_SHARE_NONE, OPEN_EXISTING,
};
use windows::Win32::System::Pipes::{SetNamedPipeHandleState, PIPE_READMODE_MESSAGE};
use dlp_common::{HookRequest, HookResponse};
```

**Error type pattern** (lines 19-43):
```rust
#[derive(Debug, Clone, PartialEq)]
pub enum PipeError {
    ConnectionRefused,
    Timeout,
    Malformed,
    Win32(u32),
}

impl std::fmt::Display for PipeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PipeError::ConnectionRefused => write!(f, "pipe connection refused"),
            PipeError::Timeout => write!(f, "pipe request timed out"),
            PipeError::Malformed => write!(f, "malformed pipe response"),
            PipeError::Win32(c) => write!(f, "Win32 error {c}"),
        }
    }
}

impl std::error::Error for PipeError {}
```

**Thread-local buffer pattern** (to add, per D-09):
```rust
use std::cell::RefCell;

thread_local! {
    static PIPE_BUFFER: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(4096));
}
```

**send_request with buffer reuse** (current lines 51-93, to modify):
```rust
pub fn send_request(
    pipe_name: &str,
    request: &HookRequest,
    timeout_ms: u32,
) -> Result<HookResponse, PipeError> {
    let pipe = connect_pipe(pipe_name, timeout_ms)?;
    unsafe {
        let mode = PIPE_READMODE_MESSAGE;
        let _ = SetNamedPipeHandleState(pipe, Some(&mode), None, None);
    }
    let payload = match bincode::serialize(request) {
        Ok(p) => p,
        Err(_) => { let _ = unsafe { CloseHandle(pipe) }; return Err(PipeError::Malformed); }
    };
    if let Err(e) = write_frame(pipe, &payload) {
        let _ = unsafe { CloseHandle(pipe) };
        return Err(e);
    }
    let frame = match read_frame(pipe, timeout_ms) {
        Ok(f) => f,
        Err(e) => { let _ = unsafe { CloseHandle(pipe) }; return Err(e); }
    };
    let _ = unsafe { CloseHandle(pipe) };
    match bincode::deserialize(&frame) {
        Ok(resp) => Ok(resp),
        Err(_) => Err(PipeError::Malformed),
    }
}
```

**Frame I/O pattern** (lines 134-156):
```rust
fn write_frame(pipe: HANDLE, payload: &[u8]) -> Result<(), PipeError> {
    let len_bytes = (payload.len() as u32).to_le_bytes();
    write_all(pipe, &len_bytes)?;
    write_all(pipe, payload)?;
    Ok(())
}

fn read_frame(pipe: HANDLE, _timeout_ms: u32) -> Result<Vec<u8>, PipeError> {
    let mut len_buf = [0u8; 4];
    read_exact(pipe, &mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    const MAX_PAYLOAD: usize = 67_108_864; // 64 MiB
    if len > MAX_PAYLOAD { return Err(PipeError::Malformed); }
    let mut payload = vec![0u8; len];
    read_exact(pipe, &mut payload)?;
    Ok(payload)
}
```

---

### `dlp-hook-dll/src/pe_utils.rs` (utility, transform) — NEW

**Analog:** `dlp-hook-dll/src/lib.rs` lines 174-267

**PE parsing pattern** (lines 174-238):
```rust
unsafe fn find_iat_entry(
    module_base: *mut u8,
    dll_name: &str,
    target_proc: *const std::ffi::c_void,
) -> Option<*mut usize> {
    if module_base.is_null() || target_proc.is_null() { return None; }

    let e_lfanew = *(module_base.offset(0x3C) as *const i32) as isize;
    let nt_headers = module_base.offset(e_lfanew);
    let optional_header = nt_headers.offset(24);
    let magic = *(optional_header as *const u16);

    if magic != 0x20B { return None; } // PE32+ (x64)

    let data_directory = optional_header.offset(112);
    let import_dir = data_directory.offset(8);
    let import_rva = *(import_dir as *const u32) as isize;
    if import_rva == 0 { return None; }

    let mut desc = module_base.offset(import_rva);
    loop {
        let name_rva = *(desc.offset(12) as *const u32) as isize;
        if name_rva == 0 { break; }
        let name_ptr = module_base.offset(name_rva);
        let name_len = (0..).take_while(|i| *(name_ptr.offset(*i) as *const u8) != 0).count();
        let name_bytes = std::slice::from_raw_parts(name_ptr as *const u8, name_len);
        if let Ok(name_str) = std::str::from_utf8(name_bytes) {
            if name_str.eq_ignore_ascii_case(dll_name) {
                let first_thunk = *(desc.offset(16) as *const u32) as isize;
                let mut iat = module_base.offset(first_thunk) as *mut usize;
                loop {
                    let entry = *iat;
                    if entry == 0 { break; }
                    if entry == target_proc as usize { return Some(iat); }
                    iat = iat.offset(1);
                }
            }
        }
        desc = desc.offset(20);
    }
    None
}
```

**IAT patch pattern** (lines 240-267):
```rust
unsafe fn patch_iat(iat: *mut usize, new_fn: *mut std::ffi::c_void) -> bool {
    let mut old_protect = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
    let size = std::mem::size_of::<usize>();
    let ok = VirtualProtect(
        iat as *mut std::ffi::c_void, size, PAGE_EXECUTE_READWRITE, &mut old_protect,
    ).is_ok();
    if !ok { return false; }
    *iat = new_fn as usize;
    let mut _tmp = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
    let _ = VirtualProtect(iat as *mut std::ffi::c_void, size, old_protect, &mut _tmp);
    true
}

unsafe fn restore_iat(iat: *mut usize, original: usize) -> bool {
    patch_iat(iat, original as *mut std::ffi::c_void)
}
```

**x86 cfg constants to add** (per D-11/D-12):
```rust
#[cfg(target_arch = "x86_64")]
const PE_MAGIC: u16 = 0x20B;
#[cfg(target_arch = "x86_64")]
const DATA_DIRECTORY_OFFSET: isize = 112;

#[cfg(target_arch = "x86")]
const PE_MAGIC: u16 = 0x10B;
#[cfg(target_arch = "x86")]
const DATA_DIRECTORY_OFFSET: isize = 96;
```

---

### `dlp-hook-dll/src/trampolines.rs` (component, event-driven) — NEW

**Analog:** `dlp-hook-dll/src/lib.rs` lines 292-430

**Trampoline pattern (CreateFileW)** (lines 292-357):
```rust
#[unsafe(no_mangle)]
pub unsafe extern "system" fn HookCreateFileW(
    lpfilename: PCWSTR,
    dwdesiredaccess: u32,
    dwsharemode: FILE_SHARE_MODE,
    lpsecurityattributes: *const SECURITY_ATTRIBUTES,
    dwcreationdisposition: FILE_CREATION_DISPOSITION,
    dwflagsandattributes: FILE_FLAGS_AND_ATTRIBUTES,
    htemplatefile: HANDLE,
) -> HANDLE {
    let path = pcwstr_to_string(lpfilename);
    let path_hash = hash_path(&path);
    let start = std::time::Instant::now();

    let decision = classify_path(&path, "CREATE", DEFAULT_PIPE_NAME);
    let latency = start.elapsed();

    match decision {
        Ok(Decision::ALLOW) | Ok(Decision::AllowWithLog) => {
            let msg = format!("[dlp-hook] ALLOW CreateFileW hash={:016x} latency={}us\0",
                path_hash, latency.as_micros());
            debug_log(&msg);
        }
        Ok(d) if d.is_denied() => {
            let msg = format!("[dlp-hook] DENY CreateFileW hash={:016x} latency={}us\0",
                path_hash, latency.as_micros());
            debug_log(&msg);
            SetLastError(ERROR_ACCESS_DENIED);
            return INVALID_HANDLE_VALUE;
        }
        _ => {
            let msg = format!("[dlp-hook] DENY(fail-closed) CreateFileW hash={:016x} latency={}us\0",
                path_hash, latency.as_micros());
            debug_log(&msg);
            SetLastError(ERROR_ACCESS_DENIED);
            return INVALID_HANDLE_VALUE;
        }
    }

    let original = ORIGINAL_CREATE_FILE_W.unwrap_or_else(|| {
        std::mem::transmute(resolve_kernel32_proc(windows::core::s!("CreateFileW"))
            .map(|f| f as *const std::ffi::c_void).unwrap_or(std::ptr::null()))
    });
    original(lpfilename, dwdesiredaccess, dwsharemode, lpsecurityattributes,
        dwcreationdisposition, dwflagsandattributes, htemplatefile)
}
```

**Trampoline pattern (NtCreateFile)** (lines 363-430):
```rust
#[unsafe(no_mangle)]
pub unsafe extern "system" fn HookNtCreateFile(
    filehandle: *mut HANDLE, desiredaccess: u32, objectattributes: *mut std::ffi::c_void,
    iostatusblock: *mut std::ffi::c_void, allocationsize: *const i64, fileattributes: u32,
    shareaccess: u32, createdisposition: u32, createoptions: u32,
    eabuffer: *mut std::ffi::c_void, ealength: u32,
) -> NTSTATUS {
    let path = extract_nt_path(objectattributes);
    let path_hash = hash_path(&path);
    let start = std::time::Instant::now();
    let decision = classify_path(&path, "CREATE", DEFAULT_PIPE_NAME);
    let latency = start.elapsed();
    match decision {
        Ok(Decision::ALLOW) | Ok(Decision::AllowWithLog) => { /* log allow */ }
        Ok(d) if d.is_denied() => {
            debug_log(&format!("[dlp-hook] DENY NtCreateFile hash={:016x}\0", path_hash));
            return NTSTATUS(0xC0000022u32 as i32); // STATUS_ACCESS_DENIED
        }
        _ => {
            debug_log(&format!("[dlp-hook] DENY(fail-closed) NtCreateFile hash={:016x}\0", path_hash));
            return NTSTATUS(0xC0000022u32 as i32);
        }
    }
    let original = ORIGINAL_NT_CREATE_FILE.unwrap_or_else(|| {
        resolve_nt_create_file().unwrap_or(std::mem::transmute(std::ptr::null::<()>()))
    });
    original(filehandle, desiredaccess, objectattributes, iostatusblock, allocationsize,
        fileattributes, shareaccess, createdisposition, createoptions, eabuffer, ealength)
}
```

**pcwstr_to_string helper** (lines 472-483):
```rust
unsafe fn pcwstr_to_string(ptr: PCWSTR) -> String {
    if ptr.is_null() { return String::new(); }
    let mut len = 0usize;
    while *(ptr.0.offset(len as isize)) != 0 { len += 1; }
    let slice = std::slice::from_raw_parts(ptr.0, len);
    String::from_utf16_lossy(slice)
}
```

**extract_nt_path helper** (lines 485-514):
```rust
unsafe fn extract_nt_path(objectattributes: *mut std::ffi::c_void) -> String {
    if objectattributes.is_null() { return String::new(); }
    // OBJECT_ATTRIBUTES layout (x64): 0x00 Length, 0x08 RootDirectory, 0x10 ObjectName
    let object_name_ptr = *(objectattributes.offset(0x10) as *mut *mut u8);
    if object_name_ptr.is_null() { return String::new(); }
    // UNICODE_STRING: 0x00 Length, 0x02 MaximumLength, 0x08 Buffer
    let buffer = *(object_name_ptr.offset(0x08) as *mut *mut u16);
    let length = *(object_name_ptr as *const u16) as usize;
    if buffer.is_null() || length == 0 { return String::new(); }
    let chars = length / 2;
    let slice = std::slice::from_raw_parts(buffer, chars);
    String::from_utf16_lossy(slice)
}
```

---

### `dlp-hook-dll/src/crash_guard.rs` (middleware, event-driven) — NEW

**Analog:** `dlp-hook-dll/src/lib.rs` lines 292-357 (trampoline structure)

**catch_unwind wrapper pattern** (per D-05/D-08):
```rust
use std::panic::catch_unwind;

/// Wraps a trampoline body in catch_unwind. On panic, logs and fails open
/// by calling the original function.
pub fn guard_trampoline<T>(
    fn_name: &str,
    f: impl FnOnce() -> T,
    fallback: impl FnOnce() -> T,
) -> T {
    match catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(ret) => ret,
        Err(_) => {
            debug_log(&format!("[dlp-hook] PANIC caught in {} -- fail-open\0", fn_name));
            fallback()
        }
    }
}
```

**SEH wrapper pattern** (per D-05, to integrate with windows crate or C shim):
```rust
/// SEH guard around the entire trampoline entry.
/// On access violation, logs and fails open.
#[cfg(target_arch = "x86_64")]
pub unsafe fn seh_guard<T>(f: impl FnOnce() -> T) -> Result<T, ()> {
    // Use windows::__try / __except or a small C shim compiled with the DLL.
    // If windows crate SEH bindings are insufficient, document and defer.
    Ok(f())
}
```

---

### `dlp-hook-dll/src/fail_closed.rs` (utility, transform) — NEW

**Analog:** `dlp-hook-dll/src/lib.rs` lines 318-337, 393-410

**DenyReturn enum + macro pattern** (per D-03):
```rust
use windows::Win32::Foundation::{BOOL, HANDLE, INVALID_HANDLE_VALUE, NTSTATUS};
use windows::Win32::Foundation::SetLastError;
use windows::Win32::Foundation::ERROR_ACCESS_DENIED;

#[derive(Clone, Copy)]
pub enum DenyReturn {
    BoolFalse,
    InvalidHandleValue,
    StatusAccessDenied,
}

#[macro_export]
macro_rules! fail_closed {
    (BoolFalse) => {{
        SetLastError(ERROR_ACCESS_DENIED);
        BOOL(0)
    }};
    (InvalidHandleValue) => {{
        SetLastError(ERROR_ACCESS_DENIED);
        INVALID_HANDLE_VALUE
    }};
    (StatusAccessDenied) => {
        NTSTATUS(0xC0000022u32 as i32)
    };
}
```

---

### `dlp-hook-dll/src/handle_ipc.rs` (component, request-response) — NEW

**Analog:** `dlp-common/src/hook_ipc.rs`

**HookRequest extension pattern** (current HookRequest in `dlp-common/src/hook_ipc.rs`):
```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HookRequest {
    pub path: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HookResponse {
    pub decision: crate::Decision,
    pub reason: String,
}
```

**HANDLE-based request variant** (to add per D-02):
```rust
/// Variant for handle-based operations (WriteFile, SetFileInformationByHandle).
/// The agent resolves the path from its internal handle tracker.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HandleHookRequest {
    pub handle_value: usize,
    pub action: String,
    pub pid: u32,
}
```

---

### `.github/workflows/release.yml` (config, batch) — NEW

**Analog:** `.github/workflows/build.yml`

**CI workflow pattern** (lines 1-55):
```yaml
name: Build
on:
  push:
    branches: [master]
  pull_request:
    types: [opened, synchronize, reopened]
jobs:
  test:
    name: Test Workspace
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable
      - name: Cache cargo registry
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
            target
          key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}
      - name: Build workspace (zero warnings)
        run: cargo build --workspace
        env:
          RUSTFLAGS: "-D warnings"
```

**Release workflow to create** (per D-13/D-17):
```yaml
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

---

### `installer/DLPAgent.wxs` (config, static) — MODIFY

**Analog:** `installer/DLPAgent.wxs` (current)

**File component pattern** (lines 91-97):
```xml
<Component Id="DLPAGENTEXE" Guid="*">
    <File Id="DLPAGENTEXE_FILE"
          Name="dlp-agent.exe"
          Source="$(SourceDir)\target\release\dlp-agent.exe"
          KeyPath="yes" />
</Component>
```

**Feature reference pattern** (lines 140-152):
```xml
<Feature Id="ProductFeature" Title="DLP Agent" Level="1"
         ConfigurableDirectory="DLPINSTALLFOLDER" Display="expand" AllowAbsent="no">
    <ComponentRef Id="DLPAGENTEXE" />
    <ComponentRef Id="DLPUSERUIEXE" />
    <ComponentRef Id="DLPADMINCLIEXE" />
    <ComponentRef Id="DLP_CONFIG_DIR" />
    <ComponentRef Id="DLP_LOGS_DIR" />
</Feature>
```

---

### `dlp-agent/src/service.rs` (service, request-response) — MODIFY

**Analog:** `dlp-agent/src/service.rs` lines 975-987

**HookInjector construction pattern** (lines 975-987):
```rust
let hook_injector_opt: Option<crate::hook_injector::HookInjector> =
    if agent_config.cloud_hook_enabled.unwrap_or(false) {
        let dll_path = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("dlp_hook_dll.dll")))
            .unwrap_or_else(|| std::path::PathBuf::from("dlp_hook_dll.dll"));
        let injector = crate::hook_injector::HookInjector::new(&dll_path, None);
        info!(dll_path = %dll_path.display(), "hook injector constructed");
        Some(injector)
    } else {
        info!("cloud hook disabled -- skipping HookInjector");
        None
    };
```

**x86 DLL path to add** (per D-10):
```rust
let dll_path_x86 = std::env::current_exe()
    .ok()
    .and_then(|p| p.parent().map(|d| d.join("dlp_hook_dll_x86.dll")))
    .unwrap_or_else(|| std::path::PathBuf::from("dlp_hook_dll_x86.dll"));
let injector = crate::hook_injector::HookInjector::new(&dll_path, Some(dll_path_x86));
```

---

### `dlp-common/src/hook_ipc.rs` (model, request-response) — MODIFY

**Analog:** `dlp-common/src/hook_ipc.rs` (current)

**Serde derive pattern** (lines 1-18):
```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HookRequest {
    pub path: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HookResponse {
    pub decision: crate::Decision,
    pub reason: String,
}
```

---

### `dlp-hook-dll/Cargo.toml` (config, static) — MODIFY

**Analog:** `dlp-hook-dll/Cargo.toml` (current)

**Crate config pattern** (lines 1-31):
```toml
[package]
name = "dlp-hook-dll"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true
description = "DLP API hook DLL for cloud sync client interception"

[lib]
crate-type = ["cdylib"]

[dependencies]
windows = { version = "0.62", features = [
    "Win32_Foundation",
    "Win32_System_LibraryLoader",
    "Win32_Storage_FileSystem",
    "Win32_System_Diagnostics_Debug",
    "Win32_System_Threading",
    "Win32_System_Memory",
    "Win32_Security",
    "Win32_System_Pipes",
] }
serde = { workspace = true }
bincode = "1.3"

[dev-dependencies]
dlp-agent = { path = "../dlp-agent" }

[dependencies.dlp-common]
path = "../dlp-common"
```

---

## Shared Patterns

### Authentication / Authorization
Not applicable — hook DLL runs in-process and uses named-pipe IPC for policy decisions.

### Error Handling
**Source:** `dlp-hook-dll/src/pipe_client.rs` lines 19-43
**Apply to:** All hook DLL files that communicate over the pipe
```rust
#[derive(Debug, Clone, PartialEq)]
pub enum PipeError {
    ConnectionRefused,
    Timeout,
    Malformed,
    Win32(u32),
}

impl std::fmt::Display for PipeError { ... }
impl std::error::Error for PipeError {}
```

### Fail-Closed Pattern
**Source:** `dlp-hook-dll/src/lib.rs` lines 318-337, 393-410
**Apply to:** All trampoline files
```rust
match decision {
    Ok(Decision::ALLOW) | Ok(Decision::AllowWithLog) => { /* log allow */ }
    Ok(d) if d.is_denied() => {
        SetLastError(ERROR_ACCESS_DENIED);
        return INVALID_HANDLE_VALUE; // or NTSTATUS(0xC0000022)
    }
    _ => {
        SetLastError(ERROR_ACCESS_DENIED);
        return INVALID_HANDLE_VALUE; // fail-closed on any error
    }
}
```

### Debug Logging
**Source:** `dlp-hook-dll/src/lib.rs` lines 72-76
**Apply to:** All hook DLL source files
```rust
fn debug_log(msg: &str) {
    let wide: Vec<u16> = msg.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe { OutputDebugStringW(PCWSTR::from_raw(wide.as_ptr())) };
}
```

### Decision Checking
**Source:** `dlp-common/src/abac.rs` lines 88-106
**Apply to:** All trampolines
```rust
impl Decision {
    pub fn is_denied(self) -> bool {
        matches!(self, Self::DENY | Self::DenyWithAlert)
    }
    pub fn requires_audit(self) -> bool {
        matches!(self, Self::DENY | Self::DenyWithAlert | Self::AllowWithLog)
    }
}
```

### HookInjector Architecture Detection
**Source:** `dlp-agent/src/hook_injector.rs` lines 139-153, 155-185
**Apply to:** `dlp-agent/src/service.rs` modification
```rust
fn current_architecture() -> &'static str {
    #[cfg(target_arch = "x86_64")] { "x64" }
    #[cfg(target_arch = "x86")] { "x86" }
}

fn target_architecture(pid: u32) -> Result<&'static str, HookError> {
    #[cfg(target_arch = "x86")] { return Ok("x86"); }
    #[cfg(target_arch = "x86_64")] {
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
            .map_err(|_| HookError::AccessDenied { pid })? };
        let mut is_wow64 = windows::core::BOOL(0);
        let result = unsafe { IsWow64Process(handle, &mut is_wow64) };
        unsafe { let _ = CloseHandle(handle); }
        result.map_err(|_| HookError::AccessDenied { pid })?;
        if is_wow64.as_bool() { Ok("x86") } else { Ok("x64") }
    }
}
```

### Test Mock Server Pattern
**Source:** `dlp-hook-dll/src/lib.rs` lines 529-547
**Apply to:** All new test modules in `dlp-hook-dll`
```rust
fn start_agent_mock_server(
    pipe_name: &str,
    handler: Arc<dyn Fn(HookRequest) -> HookResponse + Send + Sync>,
) -> std::thread::JoinHandle<()> {
    let name = pipe_name.to_string();
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let handle = std::thread::spawn(move || {
        let server = HookIpcServer::new(name, handler);
        server.run_with_ready(|| { let _ = tx.send(()); }).unwrap();
    });
    rx.recv_timeout(Duration::from_secs(5)).expect("mock server did not become ready");
    handle
}
```

## No Analog Found

| File | Role | Data Flow | Reason |
|---|---|---|---|
| `dlp-hook-dll/build.rs` | config | static | No existing build.rs in dlp-hook-dll; architecture-specific build logic is new |

## Metadata

**Analog search scope:** `dlp-hook-dll/src/`, `dlp-agent/src/`, `dlp-common/src/`, `.github/workflows/`, `installer/`
**Files scanned:** 9 unique source files read
**Pattern extraction date:** 2026-05-15
