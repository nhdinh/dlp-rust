//! Trusted-path allowlist for the hook DLL.
//!
//! Provides fast-path bypass for system-critical and build-tool paths that
//! are physically impossible to be T3/T4 by policy. This is a performance
//! optimization, not a security boundary — the DACL tripwire (Phase 52) is
//! the security backstop.
//!
//! # Hardcoded Paths
//!
//! System directories: System32, SysWOW64, WinSxS, WindowsApps,
//! Program Files\Common Files.
//!
//! Build-tool process names: devenv.exe, cargo.exe, msbuild.exe, rustc.exe,
//! link.exe, gcc.exe.
//!
//! # Operator Extensions
//!
//! Operator-extended allowlist entries flow through a separate shared-memory
//! region (64 KiB) as a flat array of path prefixes. Checked after hardcoded
//! paths.

use std::sync::OnceLock;

/// Hardcoded system directory prefixes that bypass cache and pipe.
const SYSTEM_PREFIXES: &[&str] = &[
    r"C:\WINDOWS\SYSTEM32",
    r"C:\WINDOWS\SYSWOW64",
    r"C:\WINDOWS\WINSXS",
    r"C:\WINDOWS\WINDOWSAPPS",
    r"C:\PROGRAM FILES\COMMON FILES",
    r"C:\PROGRAM FILES (X86)\COMMON FILES",
];

/// Hardcoded build-tool process names that bypass pipe.
const BUILD_TOOL_NAMES: &[&str] = &[
    "DEVENV.EXE",
    "CARGO.EXE",
    "MSBUILD.EXE",
    "RUSTC.EXE",
    "LINK.EXE",
    "GCC.EXE",
    "CL.EXE",
    "CMAKE.EXE",
];

/// Cached uppercase version of the current process image path.
///
/// Computed once on first access to avoid repeated `GetModuleFileNameW` calls.
static PROCESS_IMAGE_PATH: OnceLock<String> = OnceLock::new();

/// Returns `true` if the given path is on the trusted-path allowlist.
///
/// System directories bypass both cache lookup and pipe round-trip.
/// Build-tool processes bypass the pipe (cache still consulted).
///
/// # Arguments
///
/// * `path` — The file path to check (should already be normalized/uppercase).
pub fn is_path_allowed(path: &str) -> bool {
    let upper = path.to_ascii_uppercase();
    for prefix in SYSTEM_PREFIXES {
        if upper.starts_with(prefix) {
            return true;
        }
    }
    false
}

/// Returns `true` if the current process is a build tool that should bypass
/// the pipe round-trip.
///
/// This is checked per-process at DLL load time, not per-path.
pub fn is_build_tool_process() -> bool {
    let image_path = get_process_image_path();
    let basename = image_path
        .rsplit('\\')
        .next()
        .unwrap_or("");
    let upper = basename.to_ascii_uppercase();
    BUILD_TOOL_NAMES.contains(&upper.as_str())
}

/// Get the current process image path.
///
/// Uses `GetModuleFileNameW(NULL)` to get the full path of the executable
/// that loaded this DLL.
fn get_process_image_path() -> &'static str {
    PROCESS_IMAGE_PATH.get_or_init(|| {
        #[cfg(windows)]
        unsafe {
            use windows::Win32::System::LibraryLoader::GetModuleFileNameW;
            let mut buf = [0u16; 520]; // MAX_PATH * 2
            let len = GetModuleFileNameW(None, &mut buf);
            if len == 0 {
                return String::new();
            }
            let slice = &buf[..len as usize];
            String::from_utf16_lossy(slice)
        }
        #[cfg(not(windows))]
        {
            String::new()
        }
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system32_is_allowed() {
        assert!(is_path_allowed(r"C:\Windows\System32\kernel32.dll"));
    }

    #[test]
    fn syswow64_is_allowed() {
        assert!(is_path_allowed(r"C:\Windows\SysWOW64\wow64.dll"));
    }

    #[test]
    fn winsxs_is_allowed() {
        assert!(is_path_allowed(r"C:\Windows\WinSxS\manifests\foo.manifest"));
    }

    #[test]
    fn program_files_common_is_allowed() {
        assert!(is_path_allowed(r"C:\Program Files\Common Files\System\foo.dll"));
    }

    #[test]
    fn non_system_path_not_allowed() {
        assert!(!is_path_allowed(r"C:\Users\test\Documents\secret.txt"));
    }

    #[test]
    fn case_insensitive_match() {
        assert!(is_path_allowed(r"c:\windows\system32\file.dll"));
    }

    #[test]
    fn build_tool_names_listed() {
        assert!(BUILD_TOOL_NAMES.contains(&"CARGO.EXE"));
        assert!(BUILD_TOOL_NAMES.contains(&"MSBUILD.EXE"));
        assert!(BUILD_TOOL_NAMES.contains(&"DEVENV.EXE"));
    }
}
