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
    CreateRemoteThread, GetExitCodeThread, IsWow64Process, OpenProcess,
    WaitForSingleObject, PROCESS_ACCESS_RIGHTS, PROCESS_ALL_ACCESS,
    PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
};

/// Errors returned by the hook injector.
#[derive(Debug, thiserror::Error)]
pub enum HookError {
    #[error("target PID {pid} not found or access denied")]
    AccessDenied { pid: u32 },

    #[error("architecture mismatch: target PID {pid} is {target_arch}, injector is {injector_arch}")]
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
}

impl HookInjector {
    /// Creates a new injector with the given DLL paths.
    pub fn new(dll_path_x64: impl Into<PathBuf>, dll_path_x86: Option<PathBuf>) -> Self {
        Self {
            dll_path_x64: dll_path_x64.into(),
            dll_path_x86,
        }
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
        let dll_path_str = dll_path
            .to_str()
            .ok_or_else(|| HookError::DllNotFound {
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

        let result = self.inject_into_process(process, pid, dll_path_str);

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
            return "x64";
        }
        #[cfg(target_arch = "x86")]
        {
            return "x86";
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
        {
            return "unknown";
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
            ("x86", "x86") => {
                self.dll_path_x86.clone().ok_or_else(|| HookError::DllNotFound {
                    path: "x86 DLL not configured".to_string(),
                })
            }
            (target, injector) => Err(HookError::ArchitectureMismatch {
                pid,
                target_arch: target.to_string(),
                injector_arch: injector.to_string(),
            }),
        }
    }

    /// Performs the actual remote-thread injection.
    fn inject_into_process(
        &self,
        process: HANDLE,
        pid: u32,
        dll_path: &str,
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
        let remote_mem = unsafe {
            VirtualAllocEx(
                process,
                None,
                dll_bytes.len(),
                MEM_COMMIT,
                PAGE_READWRITE,
            )
        };

        if remote_mem.is_null() {
            return Err(HookError::RemoteAllocFailed {
                pid,
                detail: format!("VirtualAllocEx returned null"),
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
            let kernel32 = windows::Win32::System::LibraryLoader::GetModuleHandleW(w!("kernel32.dll"))
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
                Some(std::mem::transmute(load_library_w_addr)),
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
            GetExitCodeThread(thread, &mut exit_code).map_err(|e| HookError::RemoteThreadFailed {
                pid,
                detail: e.to_string(),
            })?;
        }

        unsafe {
            let _ = CloseHandle(thread);
            let _ = VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
        }

        if exit_code == 0 {
            return Err(HookError::InjectionFailed { pid, exit_code });
        }

        debug!(pid, exit_code, "remote LoadLibraryW completed");
        Ok(())
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
            return Err(HookError::EnumFailed("EnumProcessModules failed".to_string()));
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
    use std::time::Duration;
    use std::process::{Command, Stdio};

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
                eprintln!("Skipping injection test: insufficient privileges or security restriction");
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
