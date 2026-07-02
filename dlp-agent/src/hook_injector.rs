//! Hook injector — loads the DLP hook DLL into target processes.
//!
//! Uses classic DLL injection (`CreateRemoteThread` + `LoadLibraryW`) to
//! load `dlp-hook-dll` into sync client processes.  Architecture is checked
//! before injection to avoid x64→x86 mismatches.

use std::path::PathBuf;

use tracing::{debug, info, warn};
use windows::core::w;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HMODULE, WAIT_OBJECT_0};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, PAGE_READWRITE,
};
use windows::Win32::System::ProcessStatus::{EnumProcessModules, GetModuleBaseNameW};
use windows::Win32::System::Threading::{
    CreateRemoteThread, GetExitCodeThread, IsWow64Process, OpenProcess, WaitForSingleObject,
    PROCESS_ACCESS_RIGHTS, PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
};

/// Errors returned by the hook injector.
#[derive(Debug, thiserror::Error)]
pub enum HookError {
    #[error("target PID {pid} not found or access denied")]
    AccessDenied { pid: u32 },

    #[error(
        "architecture mismatch: target PID {pid} is {target_arch}, injector is {injector_arch}"
    )]
    ArchitectureMismatch {
        pid: u32,
        target_arch: String,
        injector_arch: String,
    },

    #[error("DLL not found: {path}")]
    DllNotFound { path: String },

    #[error("DLL path exceeds MAX_PATH (260 chars): {path}")]
    PathTooLong { path: String },

    #[error("remote memory allocation failed for PID {pid}: {detail}")]
    RemoteAllocFailed { pid: u32, detail: String },

    #[error("remote write failed for PID {pid}: {detail}")]
    RemoteWriteFailed { pid: u32, detail: String },

    #[error("remote thread creation failed for PID {pid}: {detail}")]
    RemoteThreadFailed { pid: u32, detail: String },

    #[error("remote thread did not complete for PID {pid}")]
    RemoteThreadTimeout { pid: u32 },

    #[error("injection into PID {pid} failed with exit code {exit_code}")]
    InjectionFailed { pid: u32, exit_code: u32 },

    #[error("process enumeration failed: {0}")]
    EnumFailed(String),
}

/// Injects the DLP hook DLL into a target process.
pub struct HookInjector {
    /// Path to the x64 hook DLL.
    dll_path_x64: PathBuf,
    /// Path to the x86 hook DLL (if available).
    dll_path_x86: Option<PathBuf>,
    /// Phase 58.5: Cached RVA of `StartDlpControlThread` in the x64 DLL.
    control_thread_rva_x64: Option<usize>,
    /// Phase 58.5: Cached RVA of `StartDlpControlThread` in the x86 DLL.
    control_thread_rva_x86: Option<usize>,
}

impl HookInjector {
    /// Creates a new injector with the given DLL paths.
    pub fn new(dll_path_x64: impl Into<PathBuf>, dll_path_x86: Option<PathBuf>) -> Self {
        let dll_path_x64 = dll_path_x64.into();

        // Pre-compute the StartDlpControlThread export RVA for each configured
        // DLL. Loading with DONT_RESOLVE_DLL_REFERENCES avoids executing DllMain
        // in the agent process (which would patch the agent's IAT).
        let control_thread_rva_x64 = Self::compute_control_thread_rva(&dll_path_x64);
        let control_thread_rva_x86 = dll_path_x86
            .as_ref()
            .and_then(|p| Self::compute_control_thread_rva(p));

        Self {
            dll_path_x64,
            dll_path_x86,
            control_thread_rva_x64,
            control_thread_rva_x86,
        }
    }

    /// Phase 58.5: Load `dll_path` locally without executing DllMain and return
    /// the RVA of the `StartDlpControlThread` export.
    fn compute_control_thread_rva(dll_path: &std::path::Path) -> Option<usize> {
        use std::os::windows::ffi::OsStrExt;
        use windows::Win32::System::LibraryLoader::{
            GetProcAddress, LoadLibraryExW, DONT_RESOLVE_DLL_REFERENCES,
        };

        let wide: Vec<u16> = dll_path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // SAFETY: LoadLibraryExW with DONT_RESOLVE_DLL_REFERENCES maps the DLL
        // as a data image without calling DllMain or resolving imports, so it
        // does not patch the agent's IAT. The handle is intentionally leaked
        // because windows-rs 0.62 does not expose FreeLibrary in this build.
        let module = unsafe {
            LoadLibraryExW(
                windows::core::PCWSTR(wide.as_ptr()),
                None,
                DONT_RESOLVE_DLL_REFERENCES,
            )
            .ok()?
        };

        let module_base = module.0 as usize;
        let proc = unsafe { GetProcAddress(module, windows::core::s!("StartDlpControlThread"))? };
        let export_addr = proc as usize;

        if export_addr <= module_base {
            return None;
        }
        Some(export_addr - module_base)
    }

    /// Injects the appropriate DLL into the process identified by `pid`.
    ///
    /// # Errors
    ///
    /// Returns [`HookError::AccessDenied`] if the process cannot be opened.
    /// Returns [`HookError::ArchitectureMismatch`] if the target architecture
    /// does not match the available DLL.
    /// Returns [`HookError::DllNotFound`] if the DLL file does not exist.
    pub fn inject(&self, pid: u32) -> Result<(), HookError> {
        info!(pid, "hook injection attempt");

        if pid == 0 {
            return Err(HookError::AccessDenied { pid });
        }

        // Determine target architecture.
        let target_arch = Self::target_architecture(pid)?;
        let injector_arch = Self::current_architecture();

        debug!(pid, target_arch, injector_arch, "architecture check");

        // Select the correct DLL path.
        let dll_path = self.select_dll(target_arch, injector_arch, pid)?;
        let dll_path_str = dll_path.to_str().ok_or_else(|| HookError::DllNotFound {
            path: dll_path.display().to_string(),
        })?;

        if dll_path_str.len() > 260 {
            return Err(HookError::PathTooLong {
                path: dll_path.display().to_string(),
            });
        }

        if !dll_path.exists() {
            return Err(HookError::DllNotFound {
                path: dll_path.display().to_string(),
            });
        }

        // Open target process.
        let process = unsafe {
            OpenProcess(PROCESS_ALL_ACCESS, false, pid)
                .map_err(|_| HookError::AccessDenied { pid })?
        };

        let result = self.inject_into_process(
            process,
            pid,
            dll_path_str,
            self.control_thread_rva_for_path(dll_path_str),
        );

        unsafe {
            let _ = CloseHandle(process);
        }

        match &result {
            Ok(()) => info!(pid, "hook injection successful"),
            Err(e) => warn!(pid, error = %e, "hook injection failed"),
        }

        result
    }

    /// Returns the architecture of the current process.
    fn current_architecture() -> &'static str {
        #[cfg(target_arch = "x86_64")]
        {
            "x64"
        }
        #[cfg(target_arch = "x86")]
        {
            "x86"
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
        {
            "unknown"
        }
    }

    /// Determines the architecture of a remote process.
    fn target_architecture(pid: u32) -> Result<&'static str, HookError> {
        // On x64 Windows, a 32-bit process appears as WOW64.
        // On x86 Windows, all processes are x86.
        #[cfg(target_arch = "x86")]
        {
            return Ok("x86");
        }

        #[cfg(target_arch = "x86_64")]
        {
            let handle = unsafe {
                OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
                    .map_err(|_| HookError::AccessDenied { pid })?
            };

            let mut is_wow64 = windows::core::BOOL(0);
            let result = unsafe { IsWow64Process(handle, &mut is_wow64) };
            unsafe {
                let _ = CloseHandle(handle);
            }

            result.map_err(|_| HookError::AccessDenied { pid })?;

            if is_wow64.as_bool() {
                Ok("x86")
            } else {
                Ok("x64")
            }
        }
    }

    /// Selects the correct DLL path based on target and injector architecture.
    fn select_dll(
        &self,
        target_arch: &str,
        injector_arch: &str,
        pid: u32,
    ) -> Result<PathBuf, HookError> {
        match (target_arch, injector_arch) {
            ("x64", "x64") => Ok(self.dll_path_x64.clone()),
            ("x86", "x86") => self
                .dll_path_x86
                .clone()
                .ok_or_else(|| HookError::DllNotFound {
                    path: "x86 DLL not configured".to_string(),
                }),
            (target, injector) => Err(HookError::ArchitectureMismatch {
                pid,
                target_arch: target.to_string(),
                injector_arch: injector.to_string(),
            }),
        }
    }

    /// Returns the cached `StartDlpControlThread` RVA for the selected DLL path.
    fn control_thread_rva_for_path(&self, dll_path: &str) -> Option<usize> {
        if self.dll_path_x64.to_str() == Some(dll_path) {
            self.control_thread_rva_x64
        } else if self.dll_path_x86.as_ref().and_then(|p| p.to_str()) == Some(dll_path) {
            self.control_thread_rva_x86
        } else {
            None
        }
    }

    /// Performs the actual remote-thread injection.
    fn inject_into_process(
        &self,
        process: HANDLE,
        pid: u32,
        dll_path: &str,
        control_thread_rva: Option<usize>,
    ) -> Result<(), HookError> {
        // Encode DLL path as wide string (including null terminator).
        let dll_wide: Vec<u16> = dll_path.encode_utf16().chain(std::iter::once(0)).collect();
        let dll_bytes = unsafe {
            std::slice::from_raw_parts(
                dll_wide.as_ptr() as *const u8,
                dll_wide.len() * std::mem::size_of::<u16>(),
            )
        };

        // Allocate remote memory for the DLL path.
        let remote_mem =
            unsafe { VirtualAllocEx(process, None, dll_bytes.len(), MEM_COMMIT, PAGE_READWRITE) };

        if remote_mem.is_null() {
            return Err(HookError::RemoteAllocFailed {
                pid,
                detail: "VirtualAllocEx returned null".to_string(),
            });
        }

        // Write DLL path into target process.
        let write_result = unsafe {
            WriteProcessMemory(
                process,
                remote_mem,
                dll_bytes.as_ptr() as *const std::ffi::c_void,
                dll_bytes.len(),
                None,
            )
        };

        if let Err(e) = write_result {
            unsafe {
                let _ = VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
            }
            return Err(HookError::RemoteWriteFailed {
                pid,
                detail: e.to_string(),
            });
        }

        // Resolve LoadLibraryW address via GetProcAddress so we obtain a
        // raw function pointer suitable for CreateRemoteThread.
        let load_library_w_addr = unsafe {
            let kernel32 =
                windows::Win32::System::LibraryLoader::GetModuleHandleW(w!("kernel32.dll"))
                    .map_err(|e| HookError::RemoteThreadFailed {
                        pid,
                        detail: format!("GetModuleHandleW failed: {}", e),
                    })?;
            let proc = windows::Win32::System::LibraryLoader::GetProcAddress(
                kernel32,
                windows::core::s!("LoadLibraryW"),
            )
            .ok_or_else(|| HookError::RemoteThreadFailed {
                pid,
                detail: "GetProcAddress(LoadLibraryW) returned null".to_string(),
            })?;
            proc as usize
        };

        // Create remote thread that calls LoadLibraryW(dll_path).
        let thread = unsafe {
            CreateRemoteThread(
                process,
                None,
                0,
                Some(std::mem::transmute::<
                    usize,
                    unsafe extern "system" fn(*mut core::ffi::c_void) -> u32,
                >(load_library_w_addr)),
                Some(remote_mem),
                0,
                None,
            )
            .map_err(|e| HookError::RemoteThreadFailed {
                pid,
                detail: e.to_string(),
            })?
        };

        // Wait for the remote thread to complete (up to 10 seconds).
        let wait_result = unsafe { WaitForSingleObject(thread, 10_000) };

        if wait_result != WAIT_OBJECT_0 {
            unsafe {
                let _ = CloseHandle(thread);
                let _ = VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
            }
            return Err(HookError::RemoteThreadTimeout { pid });
        }

        // Retrieve the thread exit code (module handle on success, 0 on failure).
        let mut exit_code: u32 = 0;
        unsafe {
            GetExitCodeThread(thread, &mut exit_code).map_err(|e| {
                HookError::RemoteThreadFailed {
                    pid,
                    detail: e.to_string(),
                }
            })?;
        }

        // The remote thread handle can be closed; the DLL remains loaded.
        unsafe {
            let _ = CloseHandle(thread);
        }

        if exit_code == 0 {
            unsafe {
                let _ = VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
            }
            return Err(HookError::InjectionFailed { pid, exit_code });
        }

        debug!(pid, exit_code, "remote LoadLibraryW completed");

        // Phase 58.5: On 64-bit Windows the real module base may have non-zero
        // upper 32 bits, but GetExitCodeThread only returns a DWORD. Enumerate
        // the remote process modules to obtain the full HMODULE value.
        let remote_module_base = match Self::remote_module_base(process, "dlp_hook_dll.dll") {
            Some(base) => base,
            None => {
                warn!(
                    pid,
                    "control thread start: could not resolve remote module base"
                );
                // Free the remote DLL path memory; LoadLibraryW already copied it.
                unsafe {
                    let _ = VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
                }
                return Ok(());
            }
        };

        // Free the remote DLL path memory; LoadLibraryW already copied it.
        unsafe {
            let _ = VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
        }

        // Phase 58.5: Start the hook DLL control-poll thread immediately so
        // idle injected processes receive UnhookCommand during agent shutdown.
        if let Some(rva) = control_thread_rva {
            Self::start_remote_control_thread(process, pid, remote_module_base, rva);
        } else {
            warn!(
                pid,
                "control thread start: export RVA not available; lazy start will be used"
            );
        }

        Ok(())
    }

    /// Phase 58.5: Create a second remote thread that calls the hook DLL's
    /// `StartDlpControlThread` export.
    ///
    /// This is best-effort: if the remote thread fails or returns non-zero, a
    /// warning is logged but the overall injection is considered successful
    /// because the DLL is already loaded and will lazily start the control
    /// thread on the first hooked API call.
    fn start_remote_control_thread(
        process: HANDLE,
        pid: u32,
        remote_module_base: usize,
        export_rva: usize,
    ) {
        let remote_start_addr = remote_module_base.saturating_add(export_rva);
        if remote_start_addr == 0 {
            warn!(pid, "control thread start: computed remote address is null");
            return;
        }

        // Create remote thread at StartDlpControlThread RVA.
        let thread = unsafe {
            match CreateRemoteThread(
                process,
                None,
                0,
                Some(std::mem::transmute::<
                    usize,
                    unsafe extern "system" fn(*mut core::ffi::c_void) -> u32,
                >(remote_start_addr)),
                None,
                0,
                None,
            ) {
                Ok(t) => t,
                Err(e) => {
                    warn!(pid, error = %e, "control thread start: CreateRemoteThread failed");
                    return;
                }
            }
        };

        let wait_result = unsafe { WaitForSingleObject(thread, 10_000) };
        let mut control_exit_code: u32 = 0;
        let exit_code_ok = unsafe { GetExitCodeThread(thread, &mut control_exit_code).is_ok() };

        unsafe {
            let _ = CloseHandle(thread);
        }

        if wait_result != WAIT_OBJECT_0 {
            warn!(
                pid,
                "control thread start: remote thread did not complete within 10 seconds"
            );
            return;
        }

        if !exit_code_ok {
            warn!(
                pid,
                "control thread start: could not read remote thread exit code"
            );
            return;
        }

        if control_exit_code != 0 {
            warn!(
                pid,
                exit_code = control_exit_code,
                "control thread start: remote export returned failure"
            );
            return;
        }

        debug!(
            pid,
            "control thread start: StartDlpControlThread completed successfully"
        );
    }

    /// Returns the base address of `module_name` in `process`, or `None` if not
    /// found. This is needed for 64-bit injection because `GetExitCodeThread`
    /// only returns a 32-bit value, which may truncate the real `HMODULE`.
    fn remote_module_base(process: HANDLE, module_name: &str) -> Option<usize> {
        let mut needed: u32 = 0;
        let mut modules: [HMODULE; 1024] = [HMODULE(std::ptr::null_mut()); 1024];

        let enum_result = unsafe {
            EnumProcessModules(
                process,
                modules.as_mut_ptr(),
                (modules.len() * std::mem::size_of::<HMODULE>()) as u32,
                &mut needed,
            )
        };

        if enum_result.is_err() {
            return None;
        }

        let count = (needed as usize) / std::mem::size_of::<HMODULE>();
        for &h in &modules[..count] {
            if h.0.is_null() {
                continue;
            }
            let mut buf = [0u16; 260];
            let ok = unsafe { GetModuleBaseNameW(process, Some(h), &mut buf) };
            if ok == 0 {
                continue;
            }
            let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
            let name = String::from_utf16_lossy(&buf[..len]);
            if name.to_lowercase().contains(&module_name.to_lowercase()) {
                return Some(h.0 as usize);
            }
        }

        None
    }

    /// Returns `true` if the given module name is loaded in the target process.
    ///
    /// Used by tests to verify injection succeeded.
    pub fn is_module_loaded(pid: u32, module_name: &str) -> Result<bool, HookError> {
        let process = unsafe {
            OpenProcess(
                PROCESS_ACCESS_RIGHTS(PROCESS_QUERY_INFORMATION.0 | PROCESS_VM_READ.0),
                false,
                pid,
            )
            .map_err(|_| HookError::AccessDenied { pid })?
        };

        let mut needed: u32 = 0;
        let mut modules: [HMODULE; 1024] = [HMODULE(std::ptr::null_mut()); 1024];

        let enum_result = unsafe {
            EnumProcessModules(
                process,
                modules.as_mut_ptr(),
                (modules.len() * std::mem::size_of::<HMODULE>()) as u32,
                &mut needed,
            )
        };

        if enum_result.is_err() {
            unsafe {
                let _ = CloseHandle(process);
            }
            return Err(HookError::EnumFailed(
                "EnumProcessModules failed".to_string(),
            ));
        }

        let count = (needed as usize) / std::mem::size_of::<HMODULE>();
        let module_names: Vec<String> = modules[..count]
            .iter()
            .filter_map(|&h| {
                if h.0.is_null() {
                    return None;
                }
                let mut buf = [0u16; 260];
                let ok = unsafe { GetModuleBaseNameW(process, Some(h), &mut buf) };
                if ok == 0 {
                    return None;
                }
                let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
                Some(String::from_utf16_lossy(&buf[..len]))
            })
            .collect();

        unsafe {
            let _ = CloseHandle(process);
        }

        Ok(module_names
            .iter()
            .any(|n| n.to_lowercase().contains(&module_name.to_lowercase())))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    /// Builds the DLL path for the current target profile.
    fn hook_dll_path() -> PathBuf {
        // cargo test runs from the workspace root; the DLL is built to
        // target/<profile>/dlp_hook_dll.dll
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir.parent().expect("workspace root");
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        workspace_root
            .join("target")
            .join(profile)
            .join("dlp_hook_dll.dll")
    }

    #[test]
    fn test_compute_control_thread_rva_for_built_dll() {
        let dll_path = hook_dll_path();
        if !dll_path.exists() {
            eprintln!(
                "Skipping RVA test: DLL not found at {}. Run `cargo build -p dlp-hook-dll` first.",
                dll_path.display()
            );
            return;
        }

        let rva = HookInjector::compute_control_thread_rva(&dll_path);
        assert!(
            rva.is_some(),
            "StartDlpControlThread export should be resolvable"
        );
        assert!(rva.unwrap() > 0, "export RVA should be positive");
    }

    #[test]
    fn test_compute_control_thread_rva_missing_dll() {
        let rva = HookInjector::compute_control_thread_rva(std::path::Path::new(
            "C:\\NonExistent\\hook.dll",
        ));
        assert!(rva.is_none());
    }

    #[test]
    fn test_injector_rejects_pid_zero() {
        let injector = HookInjector::new("C:\\dummy.dll", None);
        let result = injector.inject(0);
        assert!(
            matches!(result, Err(HookError::AccessDenied { pid: 0 })),
            "expected AccessDenied for PID 0, got {:?}",
            result
        );
    }

    #[test]
    fn test_injector_rejects_missing_dll() {
        let injector = HookInjector::new("C:\\NonExistent\\hook.dll", None);
        // We need a real process to test against; use the current process.
        let current_pid = std::process::id();
        let result = injector.inject(current_pid);
        assert!(
            matches!(result, Err(HookError::DllNotFound { .. })),
            "expected DllNotFound for missing DLL, got {:?}",
            result
        );
    }

    #[test]
    fn test_injector_rejects_long_path() {
        let long_path = "C:\\".to_string() + &"a".repeat(300) + ".dll";
        let injector = HookInjector::new(&long_path, None);
        let current_pid = std::process::id();
        let result = injector.inject(current_pid);
        assert!(
            matches!(result, Err(HookError::PathTooLong { .. })),
            "expected PathTooLong, got {:?}",
            result
        );
    }

    #[test]
    fn test_injector_successfully_injects_dll() {
        let dll_path = hook_dll_path();
        if !dll_path.exists() {
            eprintln!(
                "Skipping injection test: DLL not found at {}. Run `cargo build -p dlp-hook-dll` first.",
                dll_path.display()
            );
            return;
        }

        // Spawn a child process that stays alive long enough for injection.
        let mut child = Command::new("cmd.exe")
            .args(["/c", "timeout", "10"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn test process");

        let child_pid = child.id();
        eprintln!("Spawned test process PID {}", child_pid);

        // Small delay so the process is fully initialised.
        std::thread::sleep(Duration::from_millis(200));

        let injector = HookInjector::new(&dll_path, None);
        let result = injector.inject(child_pid);

        // Clean up child regardless of injection result.
        let _ = child.kill();
        let _ = child.wait();

        match result {
            Ok(()) => {}
            Err(HookError::AccessDenied { .. })
            | Err(HookError::RemoteAllocFailed { .. })
            | Err(HookError::RemoteWriteFailed { .. })
            | Err(HookError::RemoteThreadFailed { .. }) => {
                // Injection often requires elevated privileges (SeDebugPrivilege).
                // Skip the test rather than fail when running unelevated.
                eprintln!(
                    "Skipping injection test: insufficient privileges or security restriction"
                );
            }
            Err(other) => panic!("injection should succeed: {:?}", other),
        }
    }

    #[test]
    fn test_is_module_loaded_finds_kernel32() {
        let current_pid = std::process::id();
        let found = HookInjector::is_module_loaded(current_pid, "kernel32.dll")
            .expect("is_module_loaded should succeed");
        assert!(found, "kernel32.dll should be loaded in current process");
    }

    #[test]
    fn test_is_module_loaded_not_found() {
        let current_pid = std::process::id();
        let found = HookInjector::is_module_loaded(current_pid, "definitely_not_a_real_dll.dll")
            .expect("is_module_loaded should succeed");
        assert!(!found, "fake DLL should not be found");
    }
}
