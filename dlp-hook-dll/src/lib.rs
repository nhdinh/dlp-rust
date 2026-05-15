//! DLP API Hook DLL — cloud sync client interception (T04).
//!
//! This DLL is injected into sync client processes (OneDrive, Dropbox, etc.)
//! to intercept file creation at `CreateFileW` and `NtCreateFile`.
//!
//! ## Exports
//!
//! | Symbol | Purpose |
//! |--------|---------|
//! | `HookCreateFileW` | Trampoline for `CreateFileW` |
//! | `HookNtCreateFile` | Trampoline for `NtCreateFile` |
//! | `UnhookAll` | Restores original function pointers |

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

pub mod crash_guard;
pub mod fail_closed;
mod pe_utils;
mod pipe_client;

/// Guard to ensure one-time initialisation.
static INITIALISED: AtomicBool = AtomicBool::new(false);

/// Original `CreateFileW` pointer saved before patching.
///
/// SAFETY: written once during `DllMain` / init, then read-only.
static mut ORIGINAL_CREATE_FILE_W: Option<
    unsafe extern "system" fn(
        PCWSTR,
        u32,
        FILE_SHARE_MODE,
        *const SECURITY_ATTRIBUTES,
        FILE_CREATION_DISPOSITION,
        FILE_FLAGS_AND_ATTRIBUTES,
        HANDLE,
    ) -> HANDLE,
> = None;

/// Original `NtCreateFile` pointer saved before patching.
///
/// SAFETY: written once during `DllMain` / init, then read-only.
static mut ORIGINAL_NT_CREATE_FILE: Option<
    unsafe extern "system" fn(
        *mut HANDLE,
        u32,
        *mut std::ffi::c_void, // OBJECT_ATTRIBUTES*
        *mut std::ffi::c_void, // IO_STATUS_BLOCK*
        *const i64,            // LARGE_INTEGER*
        u32,
        u32,
        u32,
        u32,
        *mut std::ffi::c_void, // EaBuffer*
        u32,
    ) -> NTSTATUS,
> = None;

/// Original `WriteFile` pointer saved before patching.
///
/// SAFETY: written once during `DllMain` / init, then read-only.
static mut ORIGINAL_WRITE_FILE: Option<
    unsafe extern "system" fn(
        HANDLE,
        *const u8,
        u32,
        *mut u32,
        *mut std::ffi::c_void,
    ) -> windows::core::BOOL,
> = None;

/// Original `WriteFileEx` pointer saved before patching.
///
/// SAFETY: written once during `DllMain` / init, then read-only.
static mut ORIGINAL_WRITE_FILE_EX: Option<
    unsafe extern "system" fn(
        HANDLE,
        *const u8,
        u32,
        *mut std::ffi::c_void,
        *mut std::ffi::c_void,
    ) -> windows::core::BOOL,
> = None;

/// Original `MoveFileExW` pointer saved before patching.
///
/// SAFETY: written once during `DllMain` / init, then read-only.
static mut ORIGINAL_MOVE_FILE_EX_W: Option<
    unsafe extern "system" fn(PCWSTR, PCWSTR, u32) -> windows::core::BOOL,
> = None;

/// Original `CopyFileExW` pointer saved before patching.
///
/// SAFETY: written once during `DllMain` / init, then read-only.
static mut ORIGINAL_COPY_FILE_EX_W: Option<
    unsafe extern "system" fn(
        PCWSTR,
        PCWSTR,
        *mut std::ffi::c_void,
        *mut std::ffi::c_void,
        *mut i32,
        u32,
    ) -> windows::core::BOOL,
> = None;

/// Original `DeleteFileW` pointer saved before patching.
///
/// SAFETY: written once during `DllMain` / init, then read-only.
static mut ORIGINAL_DELETE_FILE_W: Option<
    unsafe extern "system" fn(PCWSTR) -> windows::core::BOOL,
> = None;

/// Original `ReplaceFileW` pointer saved before patching.
///
/// SAFETY: written once during `DllMain` / init, then read-only.
static mut ORIGINAL_REPLACE_FILE_W: Option<
    unsafe extern "system" fn(
        PCWSTR,
        PCWSTR,
        PCWSTR,
        u32,
        *mut std::ffi::c_void,
        *mut std::ffi::c_void,
    ) -> windows::core::BOOL,
> = None;

/// Original `SetFileInformationByHandle` pointer saved before patching.
///
/// SAFETY: written once during `DllMain` / init, then read-only.
static mut ORIGINAL_SET_FILE_INFORMATION_BY_HANDLE: Option<
    unsafe extern "system" fn(HANDLE, i32, *mut std::ffi::c_void, u32) -> windows::core::BOOL,
> = None;

/// Original `NtOpenFile` pointer saved before patching.
///
/// SAFETY: written once during `DllMain` / init, then read-only.
static mut ORIGINAL_NT_OPEN_FILE: Option<
    unsafe extern "system" fn(
        *mut HANDLE,
        u32,
        *mut std::ffi::c_void,
        *mut std::ffi::c_void,
        u32,
        u32,
    ) -> NTSTATUS,
> = None;

/// Original `NtWriteFile` pointer saved before patching.
///
/// SAFETY: written once during `DllMain` / init, then read-only.
static mut ORIGINAL_NT_WRITE_FILE: Option<
    unsafe extern "system" fn(
        HANDLE,
        HANDLE,
        *mut std::ffi::c_void,
        *mut std::ffi::c_void,
        *mut std::ffi::c_void,
        *const u8,
        u32,
        *const i64,
        *mut u32,
    ) -> NTSTATUS,
> = None;

/// Original `NtSetInformationFile` pointer saved before patching.
///
/// SAFETY: written once during `DllMain` / init, then read-only.
static mut ORIGINAL_NT_SET_INFORMATION_FILE: Option<
    unsafe extern "system" fn(
        HANDLE,
        *mut std::ffi::c_void,
        *mut std::ffi::c_void,
        u32,
        u32,
    ) -> NTSTATUS,
> = None;

/// Saved IAT entry addresses so `UnhookAll` can restore them.
static mut IAT_CREATE_FILE_W: Option<*mut usize> = None;
static mut IAT_NT_CREATE_FILE: Option<*mut usize> = None;
static mut IAT_WRITE_FILE: Option<*mut usize> = None;
static mut IAT_WRITE_FILE_EX: Option<*mut usize> = None;
static mut IAT_MOVE_FILE_EX_W: Option<*mut usize> = None;
static mut IAT_COPY_FILE_EX_W: Option<*mut usize> = None;
static mut IAT_DELETE_FILE_W: Option<*mut usize> = None;
static mut IAT_REPLACE_FILE_W: Option<*mut usize> = None;
static mut IAT_SET_FILE_INFORMATION_BY_HANDLE: Option<*mut usize> = None;
static mut IAT_NT_OPEN_FILE: Option<*mut usize> = None;
static mut IAT_NT_WRITE_FILE: Option<*mut usize> = None;
static mut IAT_NT_SET_INFORMATION_FILE: Option<*mut usize> = None;

/// Logs a wide-string message via `OutputDebugStringW`.
fn debug_log(msg: &str) {
    let wide: Vec<u16> = msg.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe { OutputDebugStringW(PCWSTR::from_raw(wide.as_ptr())) };
}

/// Hash a path for logging without exposing the full value.
fn hash_path(path: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut s = DefaultHasher::new();
    path.hash(&mut s);
    s.finish()
}

/// Initialises the hook DLL.
///
/// Saves original function pointers and patches the host module's IAT.
fn init() {
    if INITIALISED.swap(true, Ordering::SeqCst) {
        return;
    }

    unsafe {
        ORIGINAL_CREATE_FILE_W =
            std::mem::transmute(resolve_kernel32_proc(windows::core::s!("CreateFileW")));
        ORIGINAL_NT_CREATE_FILE = resolve_nt_create_file();

        let host = GetModuleHandleW(None).unwrap_or_default();
        if !host.is_invalid() {
            let host_ptr = host.0 as *mut u8;

            if let Some(iat) = find_iat_entry(
                host_ptr,
                "kernel32.dll",
                resolve_kernel32_proc(windows::core::s!("CreateFileW"))
                    .map(|f| f as *const std::ffi::c_void)
                    .unwrap_or(std::ptr::null()),
            ) {
                if patch_iat(iat, HookCreateFileW as *mut std::ffi::c_void) {
                    IAT_CREATE_FILE_W = Some(iat);
                    debug_log("[dlp-hook] IAT patched: CreateFileW\0");
                }
            }

            if let Some(iat) = find_iat_entry(
                host_ptr,
                "ntdll.dll",
                resolve_ntdll_proc(windows::core::s!("NtCreateFile"))
                    .map(|f| f as *const std::ffi::c_void)
                    .unwrap_or(std::ptr::null()),
            ) {
                if patch_iat(iat, HookNtCreateFile as *mut std::ffi::c_void) {
                    IAT_NT_CREATE_FILE = Some(iat);
                    debug_log("[dlp-hook] IAT patched: NtCreateFile\0");
                }
            }
        }
    }

    debug_log("[dlp-hook] initialised — IAT hooks active\0");
}

/// Resolves a function from `kernel32.dll` by name.
unsafe fn resolve_kernel32_proc(name: windows::core::PCSTR) -> Option<unsafe extern "system" fn()> {
    let kernel32 = GetModuleHandleW(w!("kernel32.dll")).ok()?;
    let proc = GetProcAddress(kernel32, name)?;
    Some(std::mem::transmute(proc))
}

/// Resolves a function from `ntdll.dll` by name.
unsafe fn resolve_ntdll_proc(name: windows::core::PCSTR) -> Option<unsafe extern "system" fn()> {
    let ntdll = GetModuleHandleW(w!("ntdll.dll")).ok()?;
    let proc = GetProcAddress(ntdll, name)?;
    Some(std::mem::transmute(proc))
}

/// Resolves `NtCreateFile` from `ntdll.dll`.
unsafe fn resolve_nt_create_file() -> Option<
    unsafe extern "system" fn(
        *mut HANDLE,
        u32,
        *mut std::ffi::c_void,
        *mut std::ffi::c_void,
        *const i64,
        u32,
        u32,
        u32,
        u32,
        *mut std::ffi::c_void,
        u32,
    ) -> NTSTATUS,
> {
    let ntdll = GetModuleHandleW(w!("ntdll.dll")).ok()?;
    let proc = GetProcAddress(ntdll, windows::core::s!("NtCreateFile"))?;
    Some(std::mem::transmute(proc))
}

// ─────────────────────────────────────────────────────────────────────────────
// PE IAT helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Finds the IAT entry in the host module that currently points to
/// `target_proc` inside `dll_name`.
unsafe fn find_iat_entry(
    module_base: *mut u8,
    dll_name: &str,
    target_proc: *const std::ffi::c_void,
) -> Option<*mut usize> {
    if module_base.is_null() || target_proc.is_null() {
        return None;
    }

    let e_lfanew = *(module_base.offset(0x3C) as *const i32) as isize;
    let nt_headers = module_base.offset(e_lfanew);
    let optional_header = nt_headers.offset(24); // after Signature + FileHeader
    let magic = *(optional_header as *const u16);

    if magic != 0x20B {
        // Not PE32+ (x64).
        return None;
    }

    // DataDirectory starts at offset 112 in IMAGE_OPTIONAL_HEADER64.
    let data_directory = optional_header.offset(112);
    // Import directory is index 1.
    let import_dir = data_directory.offset(8);
    let import_rva = *(import_dir as *const u32) as isize;

    if import_rva == 0 {
        return None;
    }

    let mut desc = module_base.offset(import_rva);
    loop {
        let name_rva = *(desc.offset(12) as *const u32) as isize;
        if name_rva == 0 {
            break; // null terminator
        }

        let name_ptr = module_base.offset(name_rva);
        let name_len = (0..)
            .take_while(|i| *(name_ptr.offset(*i) as *const u8) != 0)
            .count();
        let name_bytes = std::slice::from_raw_parts(name_ptr as *const u8, name_len);
        if let Ok(name_str) = std::str::from_utf8(name_bytes) {
            if name_str.eq_ignore_ascii_case(dll_name) {
                let first_thunk = *(desc.offset(16) as *const u32) as isize;
                let mut iat = module_base.offset(first_thunk) as *mut usize;
                loop {
                    let entry = *iat;
                    if entry == 0 {
                        break;
                    }
                    if entry == target_proc as usize {
                        return Some(iat);
                    }
                    iat = iat.offset(1);
                }
            }
        }

        desc = desc.offset(20); // sizeof(IMAGE_IMPORT_DESCRIPTOR)
    }

    None
}

/// Temporarily makes `iat` writable and overwrites it with `new_fn`.
unsafe fn patch_iat(iat: *mut usize, new_fn: *mut std::ffi::c_void) -> bool {
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

/// Restores an IAT entry to its original value.
unsafe fn restore_iat(iat: *mut usize, original: usize) -> bool {
    patch_iat(iat, original as *mut std::ffi::c_void)
}

// ─────────────────────────────────────────────────────────────────────────────
// DLL entry point
// ─────────────────────────────────────────────────────────────────────────────

/// DLL entry point.
#[unsafe(no_mangle)]
extern "system" fn DllMain(_inst: isize, reason: u32, _reserved: usize) -> i32 {
    const DLL_PROCESS_ATTACH: u32 = 1;
    if reason == DLL_PROCESS_ATTACH {
        init();
    }
    1
}

// ─────────────────────────────────────────────────────────────────────────────
// Exported trampolines
// ─────────────────────────────────────────────────────────────────────────────

/// Classification hook for `CreateFileW`.
///
/// Sends the file path to the agent via named pipe.  If the agent denies
/// the operation, returns `INVALID_HANDLE_VALUE` with `ERROR_ACCESS_DENIED`.
/// Otherwise delegates to the original `CreateFileW`.
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
            let msg = format!(
                "[dlp-hook] ALLOW CreateFileW hash={:016x} latency={}us\0",
                path_hash,
                latency.as_micros()
            );
            debug_log(&msg);
        }
        Ok(d) if d.is_denied() => {
            let msg = format!(
                "[dlp-hook] DENY CreateFileW hash={:016x} latency={}us\0",
                path_hash,
                latency.as_micros()
            );
            debug_log(&msg);
            SetLastError(ERROR_ACCESS_DENIED);
            return INVALID_HANDLE_VALUE;
        }
        _ => {
            let msg = format!(
                "[dlp-hook] DENY(fail-closed) CreateFileW hash={:016x} latency={}us\0",
                path_hash,
                latency.as_micros()
            );
            debug_log(&msg);
            SetLastError(ERROR_ACCESS_DENIED);
            return INVALID_HANDLE_VALUE;
        }
    }

    let original = ORIGINAL_CREATE_FILE_W.unwrap_or_else(|| {
        std::mem::transmute(
            resolve_kernel32_proc(windows::core::s!("CreateFileW"))
                .map(|f| f as *const std::ffi::c_void)
                .unwrap_or(std::ptr::null()),
        )
    });

    original(
        lpfilename,
        dwdesiredaccess,
        dwsharemode,
        lpsecurityattributes,
        dwcreationdisposition,
        dwflagsandattributes,
        htemplatefile,
    )
}

/// Classification hook for `NtCreateFile`.
///
/// Sends the file path (extracted from `OBJECT_ATTRIBUTES`) to the agent.
/// Fail-closed on any error or denial.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn HookNtCreateFile(
    filehandle: *mut HANDLE,
    desiredaccess: u32,
    objectattributes: *mut std::ffi::c_void,
    iostatusblock: *mut std::ffi::c_void,
    allocationsize: *const i64,
    fileattributes: u32,
    shareaccess: u32,
    createdisposition: u32,
    createoptions: u32,
    eabuffer: *mut std::ffi::c_void,
    ealength: u32,
) -> NTSTATUS {
    let path = extract_nt_path(objectattributes);
    let path_hash = hash_path(&path);
    let start = std::time::Instant::now();

    let decision = classify_path(&path, "CREATE", DEFAULT_PIPE_NAME);
    let latency = start.elapsed();

    match decision {
        Ok(Decision::ALLOW) | Ok(Decision::AllowWithLog) => {
            let msg = format!(
                "[dlp-hook] ALLOW NtCreateFile hash={:016x} latency={}us\0",
                path_hash,
                latency.as_micros()
            );
            debug_log(&msg);
        }
        Ok(d) if d.is_denied() => {
            let msg = format!(
                "[dlp-hook] DENY NtCreateFile hash={:016x} latency={}us\0",
                path_hash,
                latency.as_micros()
            );
            debug_log(&msg);
            return NTSTATUS(0xC0000022u32 as i32); // STATUS_ACCESS_DENIED
        }
        _ => {
            let msg = format!(
                "[dlp-hook] DENY(fail-closed) NtCreateFile hash={:016x} latency={}us\0",
                path_hash,
                latency.as_micros()
            );
            debug_log(&msg);
            return NTSTATUS(0xC0000022u32 as i32); // STATUS_ACCESS_DENIED
        }
    }

    let original = ORIGINAL_NT_CREATE_FILE.unwrap_or_else(|| {
        resolve_nt_create_file().unwrap_or(std::mem::transmute(std::ptr::null::<()>()))
    });

    original(
        filehandle,
        desiredaccess,
        objectattributes,
        iostatusblock,
        allocationsize,
        fileattributes,
        shareaccess,
        createdisposition,
        createoptions,
        eabuffer,
        ealength,
    )
}

/// Restores original function pointers.
///
/// Called by the agent before unloading the DLL from a target process.
#[unsafe(no_mangle)]
pub extern "system" fn UnhookAll() {
    debug_log("[dlp-hook] UnhookAll called — restoring IAT\0");
    unsafe {
        if let Some(iat) = IAT_CREATE_FILE_W {
            if let Some(orig) = ORIGINAL_CREATE_FILE_W {
                let _ = restore_iat(iat, orig as usize);
            }
        }
        if let Some(iat) = IAT_NT_CREATE_FILE {
            if let Some(orig) = ORIGINAL_NT_CREATE_FILE {
                let _ = restore_iat(iat, orig as usize);
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Sends a classification request to the agent via named pipe.
fn classify_path(
    path: &str,
    action: &str,
    pipe_name: &str,
) -> Result<Decision, pipe_client::PipeError> {
    let req = HookRequest {
        path: path.to_string(),
        action: action.to_string(),
    };
    let resp = pipe_client::send_request(
        pipe_name, &req, 50, // 50 ms timeout per task spec
    )?;
    Ok(resp.decision)
}

/// Sends a handle-based classification request to the agent via named pipe.
///
/// The agent resolves the file path from its internal handle tracker using
/// the provided `handle_value`.  This avoids extra syscalls in the hook DLL
/// but requires the agent to track handle lifecycle (create/close/duplicate).
///
/// # Arguments
///
/// * `handle_value` — The raw HANDLE value cast to `u64` for cross-architecture
///   safety.
/// * `action` — The operation being performed (e.g., `"WRITE"`, `"SET_INFO"`).
/// * `pipe_name` — The named pipe path to connect to.
///
/// # Returns
///
/// The [`Decision`] from the agent, or a [`pipe_client::PipeError`] if the
/// request fails.
fn classify_handle(
    _handle_value: u64,
    _action: &str,
    _pipe_name: &str,
) -> Result<Decision, pipe_client::PipeError> {
    // Stub: handle-based classification requires agent-side handle tracker
    // (Phase 49/50).  Until then, return ALLOW so existing behavior is not
    // broken.  This function is called by handle-based trampolines
    // (WriteFile, SetFileInformationByHandle, etc.).
    Ok(Decision::ALLOW)
}

/// Converts a `PCWSTR` to a Rust `String`.
unsafe fn pcwstr_to_string(ptr: PCWSTR) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while *(ptr.0.offset(len as isize)) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(ptr.0, len);
    String::from_utf16_lossy(slice)
}

/// Extracts the path from `OBJECT_ATTRIBUTES.ObjectName`.
unsafe fn extract_nt_path(objectattributes: *mut std::ffi::c_void) -> String {
    if objectattributes.is_null() {
        return String::new();
    }

    // OBJECT_ATTRIBUTES layout (x64):
    //   0x00 Length: u32
    //   0x08 RootDirectory: HANDLE
    //   0x10 ObjectName: *mut UNICODE_STRING
    //   ...
    let object_name_ptr = *(objectattributes.offset(0x10) as *mut *mut u8);
    if object_name_ptr.is_null() {
        return String::new();
    }

    // UNICODE_STRING layout:
    //   0x00 Length: u16
    //   0x02 MaximumLength: u16
    //   0x08 Buffer: *mut u16
    let buffer = *(object_name_ptr.offset(0x08) as *mut *mut u16);
    let length = *(object_name_ptr as *const u16) as usize;
    if buffer.is_null() || length == 0 {
        return String::new();
    }

    let chars = length / 2;
    let slice = std::slice::from_raw_parts(buffer, chars);
    String::from_utf16_lossy(slice)
}

// Re-export pipe constants so tests can use them.
pub use pipe_client::DEFAULT_PIPE_NAME;

#[cfg(test)]
mod tests {
    use super::*;
    use dlp_agent::hook_ipc::HookIpcServer;
    use dlp_common::{Decision, HookRequest, HookResponse};
    use std::sync::Arc;
    use std::time::Duration;

    /// Starts a [`HookIpcServer`] on a dedicated thread using the given
    /// handler, waits until the pipe is ready, and returns the thread handle.
    fn start_agent_mock_server(
        pipe_name: &str,
        handler: Arc<dyn Fn(HookRequest) -> HookResponse + Send + Sync>,
    ) -> std::thread::JoinHandle<()> {
        let name = pipe_name.to_string();
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let handle = std::thread::spawn(move || {
            let server = HookIpcServer::new(name, handler);
            server
                .run_with_ready(|| {
                    let _ = tx.send(());
                })
                .unwrap();
        });

        rx.recv_timeout(Duration::from_secs(5))
            .expect("mock server did not become ready");
        handle
    }

    #[test]
    fn hash_path_is_deterministic() {
        let h1 = hash_path(r"C:\Users\test\file.txt");
        let h2 = hash_path(r"C:\Users\test\file.txt");
        assert_eq!(h1, h2);
        let h3 = hash_path(r"C:\Users\test\other.txt");
        assert_ne!(h1, h3);
    }

    #[test]
    fn pcwstr_roundtrip() {
        let wide: Vec<u16> = "Hello World"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let s = unsafe { pcwstr_to_string(PCWSTR::from_raw(wide.as_ptr())) };
        assert_eq!(s, "Hello World");
    }

    #[test]
    fn pcwstr_null_returns_empty() {
        let s = unsafe { pcwstr_to_string(PCWSTR::from_raw(std::ptr::null())) };
        assert_eq!(s, "");
    }

    #[test]
    fn pipe_client_connection_refused_when_no_server() {
        let req = HookRequest {
            path: r"C:\test.txt".to_string(),
            action: "CREATE".to_string(),
        };
        let result = pipe_client::send_request(r"\\.\pipe\DlpHookPipeTestNoServer", &req, 100);
        assert!(
            matches!(result, Err(pipe_client::PipeError::ConnectionRefused)),
            "expected ConnectionRefused, got {:?}",
            result
        );
    }

    #[test]
    fn pipe_client_roundtrip_deny() {
        let pipe_name = r"\\.\pipe\DlpHookPipeTestDeny";
        let handler = Arc::new(|req: HookRequest| HookResponse {
            decision: Decision::DENY,
            reason: format!("blocked: {}", req.path),
        });
        let _server = start_agent_mock_server(pipe_name, handler);
        std::thread::sleep(Duration::from_millis(50));

        let req = HookRequest {
            path: r"C:\secret.txt".to_string(),
            action: "CREATE".to_string(),
        };
        let resp =
            pipe_client::send_request(pipe_name, &req, 1000).expect("send_request should succeed");
        assert_eq!(resp.decision, Decision::DENY);
        assert_eq!(resp.reason, "blocked: C:\\secret.txt");
    }

    #[test]
    fn pipe_client_roundtrip_allow() {
        let pipe_name = r"\\.\pipe\DlpHookPipeTestAllow";
        let handler = Arc::new(|_req: HookRequest| HookResponse {
            decision: Decision::ALLOW,
            reason: "allowed".to_string(),
        });
        let _server = start_agent_mock_server(pipe_name, handler);
        std::thread::sleep(Duration::from_millis(50));

        let req = HookRequest {
            path: r"C:\public.txt".to_string(),
            action: "CREATE".to_string(),
        };
        let resp =
            pipe_client::send_request(pipe_name, &req, 1000).expect("send_request should succeed");
        assert_eq!(resp.decision, Decision::ALLOW);
        assert_eq!(resp.reason, "allowed");
    }

    #[test]
    fn hook_createfilew_fail_closed_on_deny() {
        let pipe_name = r"\\.\pipe\DlpHookPipeTestHookDeny";
        let handler = Arc::new(|_req: HookRequest| HookResponse {
            decision: Decision::DENY,
            reason: "denied".to_string(),
        });
        let _server = start_agent_mock_server(pipe_name, handler);
        std::thread::sleep(Duration::from_millis(50));

        let result = classify_path(r"C:\secret.txt", "CREATE", pipe_name);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Decision::DENY);
    }

    #[test]
    fn hook_createfilew_allow_when_allowed() {
        let pipe_name = r"\\.\pipe\DlpHookPipeTestHookAllow";
        let handler = Arc::new(|_req: HookRequest| HookResponse {
            decision: Decision::ALLOW,
            reason: "allowed".to_string(),
        });
        let _server = start_agent_mock_server(pipe_name, handler);
        std::thread::sleep(Duration::from_millis(50));

        let result = classify_path(r"C:\public.txt", "CREATE", pipe_name);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Decision::ALLOW);
    }

    #[test]
    fn unhook_all_does_not_panic_when_not_initialised() {
        UnhookAll();
    }

    #[test]
    fn find_iat_entry_returns_none_for_invalid_module() {
        unsafe {
            let result = find_iat_entry(std::ptr::null_mut(), "kernel32.dll", std::ptr::null());
            assert!(result.is_none());
        }
    }

    #[test]
    fn extract_nt_path_null() {
        unsafe {
            let s = extract_nt_path(std::ptr::null_mut());
            assert_eq!(s, "");
        }
    }
}
