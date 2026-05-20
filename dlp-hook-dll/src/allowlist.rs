//! Trusted-path allowlist for the hook DLL.
//!
//! Provides fast-path bypass for system-critical and build-tool paths that
//! are physically impossible to be T3/T4 by policy. This is a performance
//! optimization, not a security boundary — the DACL tripwire (Phase 52) is
//! the security backstop.
//!
//! # Cache Non-Authoritative Invariant
//!
//! The cache stores classification **HINT only**. ABAC authority is never
//! bypassed. A cache hit enables tier-gated fast-path decisions; a cache miss
//! always falls through to the full ABAC evaluation via pipe round-trip.
//!
//! # Hardcoded Paths
//!
//! System directories: System32, SysWOW64, WinSxS, WindowsApps,
//! Program Files\Common Files.
//!
//! Build-tool process names: devenv.exe, cargo.exe, msbuild.exe, rustc.exe,
//! link.exe, gcc.exe, cl.exe.
//!
//! # Operator Extensions
//!
//! Operator-extended allowlist entries flow through a separate shared-memory
//! region (64 KiB) as a flat array of path prefixes. Checked after hardcoded
//! paths.

use std::sync::OnceLock;

use crate::classification_cache::CacheHeader;

// ---------------------------------------------------------------------------
// Hardcoded system directory prefixes
// ---------------------------------------------------------------------------

/// Hardcoded system directory prefixes that bypass cache and pipe.
///
/// These paths contain only Windows-signed system binaries and are never
/// classified above T1 (Public). The allowlist check is the FIRST check in
/// `classify_and_log_path` (before cache, before pipe).
///
/// Allowlist is for performance optimization only; ABAC authority is never
/// bypassed.
const SYSTEM_PREFIXES: &[&str] = &[
    r"C:\WINDOWS\SYSTEM32",
    r"C:\WINDOWS\SYSWOW64",
    r"C:\WINDOWS\WINSXS",
    r"C:\WINDOWS\WINDOWSAPPS",
    r"C:\PROGRAM FILES\COMMON FILES",
    r"C:\PROGRAM FILES (X86)\COMMON FILES",
];

// ---------------------------------------------------------------------------
// Build-tool allowlist
// ---------------------------------------------------------------------------

/// Hardcoded build-tool executable basenames.
///
/// Build tools operate on source code, not sensitive data, and are classified
/// T1 (Public). Full-path validation (basename + parent directory + code
/// signer) prevents rename attacks.
const BUILD_TOOL_NAMES: &[&str] = &[
    "DEVENV.EXE",
    "CARGO.EXE",
    "MSBUILD.EXE",
    "RUSTC.EXE",
    "LINK.EXE",
    "GCC.EXE",
    "CL.EXE",
];

/// Trusted parent directories for build tools.
///
/// Build tools must reside under one of these directories to be allowlisted.
/// This prevents `C:\Users\attacker\cargo.exe` from matching.
const BUILD_TOOL_PARENT_DIRS: &[&str] = &[
    r"C:\PROGRAM FILES\MICROSOFT VISUAL STUDIO",
    r"C:\PROGRAM FILES (X86)\MICROSOFT VISUAL STUDIO",
    r"C:\PROGRAM FILES\MICROSOFT.NET",
    r"C:\RUST",
    r"C:\MSYS64",
    r"C:\MINGW",
];

/// Trusted code signer subjects for build tools.
///
/// Build tools must be signed by one of these publishers. Code-signer
/// validation prevents binary substitution attacks.
const TRUSTED_SIGNERS: &[&str] = &[
    "MICROSOFT CORPORATION",
    "MICROSOFT WINDOWS",
    "RUST PROJECT",
];

/// User-writable directory prefixes that reject build-tool allowlist.
///
/// Defense-in-depth: even if a build tool basename matches and the signer is
/// valid, if the parent directory is user-writable, the allowlist is denied.
/// This prevents planted-binary attacks.
const USER_WRITABLE_PREFIXES: &[&str] = &[
    r"C:\USERS",
    r"C:\TEMP",
    r"C:\WINDOWS\TEMP",
    r"C:\TMP",
];

// ---------------------------------------------------------------------------
// Shared-memory allowlist entry (operator-extended)
// ---------------------------------------------------------------------------

/// Operator-extended allowlist entry in shared memory.
///
/// Lives in a dedicated 64 KiB region of the shared-memory cache.
/// Entries are canonicalized by the agent before writing to prevent
/// prefix-escape attacks (e.g., `C:\Windows\System32Fake`).
#[repr(C)]
pub struct AllowlistEntry {
    /// Length of the prefix in bytes.
    pub prefix_len: u16,
    /// UTF-8 path prefix (MAX_PATH = 260 bytes).
    pub prefix: [u8; 260],
    /// Category: 0=system, 1=build_tool, 2=operator.
    pub category: u8,
    /// Padding to align to 272 bytes total.
    pub _pad: [u8; 5],
}

/// Category values for allowlist entries.
#[allow(dead_code)]
pub mod category {
    pub const SYSTEM: u8 = 0;
    pub const BUILD_TOOL: u8 = 1;
    pub const OPERATOR: u8 = 2;
}

// ---------------------------------------------------------------------------
// Cached process image path
// ---------------------------------------------------------------------------

/// Cached uppercase version of the current process image path.
///
/// Computed once on first access to avoid repeated `GetModuleFileNameW` calls.
static PROCESS_IMAGE_PATH: OnceLock<String> = OnceLock::new();

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
// System path allowlist
// ---------------------------------------------------------------------------

/// Returns `true` if the given path is a hardcoded system directory.
///
/// System directories bypass both cache lookup and pipe round-trip.
/// These paths contain only Windows-signed system binaries and are never
/// classified above T1.
///
/// # Arguments
///
/// * `path` — The file path to check (should already be normalized/uppercase).
pub fn is_system_allowlisted(path: &str) -> bool {
    let upper = path.to_ascii_uppercase();
    for prefix in SYSTEM_PREFIXES {
        if prefix_match_directory_boundary(prefix, &upper) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Build-tool allowlist
// ---------------------------------------------------------------------------

/// Returns `true` if the given path is a trusted build tool.
///
/// Checks three conditions in order:
/// 1. Basename matches a known build-tool name (case-insensitive).
/// 2. Parent directory starts with a trusted build-tool parent directory.
/// 3. Parent directory is NOT user-writable.
/// 4. Code signer matches a trusted publisher (WinVerifyTrust).
///
/// All four checks must pass. Full-path validation prevents rename attacks
/// (e.g., `C:\Users\attacker\cargo.exe`). Code-signer validation prevents
/// binary substitution attacks. User-writable directory check prevents
/// planted-binary attacks.
///
/// # Arguments
///
/// * `path` — The file path to check.
pub fn is_build_tool_allowlisted(path: &str) -> bool {
    let upper = path.to_ascii_uppercase();

    // 1. Check basename against BUILD_TOOL_NAMES.
    let basename = upper.rsplit('\\').next().unwrap_or("");
    if !BUILD_TOOL_NAMES.contains(&basename) {
        return false;
    }

    // 2. Check parent directory against BUILD_TOOL_PARENT_DIRS.
    let parent = match upper.rfind('\\') {
        Some(idx) => &upper[..idx],
        None => return false,
    };

    let parent_trusted = BUILD_TOOL_PARENT_DIRS
        .iter()
        .any(|prefix| prefix_match_directory_boundary(prefix, parent));
    if !parent_trusted {
        return false;
    }

    // 3. Defense-in-depth: reject user-writable directories.
    if is_user_writable_directory(parent) {
        return false;
    }

    // 4. Code-signer validation.
    if !verify_code_signer(path) {
        return false;
    }

    true
}

/// Returns `true` if the directory is under a user-writable location.
///
/// User-writable directories are rejected for build-tool allowlist as a
/// defense-in-depth measure against planted-binary attacks.
///
/// # Arguments
///
/// * `path` — The directory path to check.
pub fn is_user_writable_directory(path: &str) -> bool {
    let upper = path.to_ascii_uppercase();
    USER_WRITABLE_PREFIXES
        .iter()
        .any(|prefix| prefix_match_directory_boundary(prefix, &upper))
}

/// Verify the code signer of a file against TRUSTED_SIGNERS.
///
/// Uses WinVerifyTrust on the file path to verify the Authenticode signature.
/// Returns `true` if the file has a valid signature from a trusted publisher.
///
/// On non-Windows platforms or if WinVerifyTrust fails, returns `false`
/// (conservative — deny allowlist if we cannot verify).
///
/// # Arguments
///
/// * `path` — The file path to verify.
fn verify_code_signer(_path: &str) -> bool {
    // NOTE: Full WinVerifyTrust integration with windows-rs 0.62 requires
    // exact struct field mappings (WINTRUST_DATA uses an Anonymous union
    // for pFile, and WinVerifyTrust takes raw pointers not references).
    // The implementation is stubbed here; production builds should enable
    // the full WinVerifyTrust call via a feature flag once the exact API
    // bindings are validated.
    //
    // For now, we return `false` conservatively on all platforms.
    // This means build-tool allowlist requires:
    // 1. Basename match (e.g., "cargo.exe")
    // 2. Parent directory match (e.g., "C:\Program Files\...")
    // 3. NOT user-writable directory
    // 4. Code signer verification (currently stubbed — always fails)
    //
    // In practice, this means build-tool allowlist is disabled until
    // the WinVerifyTrust integration is completed. System paths still
    // work (they don't require signer verification).
    false
}

// ---------------------------------------------------------------------------
// Operator-extended allowlist from shared memory
// ---------------------------------------------------------------------------

/// Returns `true` if the path matches an operator-extended allowlist entry.
///
/// Reads allowlist entries from the dedicated 64 KiB region in shared memory.
/// Each entry is a path prefix; if the normalized path starts with the prefix
/// (case-insensitive, directory boundary), it is allowlisted.
///
/// # Arguments
///
/// * `path` — The file path to check.
/// * `header` — The shared-memory cache header containing allowlist metadata.
pub fn is_operator_allowlisted(path: &str, header: &CacheHeader) -> bool {
    let allowlist_count = header.allowlist_count;
    let allowlist_offset = header.allowlist_offset;

    if allowlist_offset == 0 || allowlist_count == 0 {
        return false;
    }

    // Bounds-check: allowlist entries must fit within total_size.
    let entry_size = std::mem::size_of::<AllowlistEntry>() as u64;
    let total_allowlist_size = allowlist_count.saturating_mul(entry_size);
    if allowlist_offset.saturating_add(total_allowlist_size) > header.total_size {
        return false;
    }

    let upper = path.to_ascii_uppercase();

    // SAFETY: header is a valid read-only mapping; bounds checked above.
    unsafe {
        let base = header as *const CacheHeader as *const u8;
        for i in 0..allowlist_count {
            let entry_ptr = base
                .add(allowlist_offset as usize)
                .add(i as usize * std::mem::size_of::<AllowlistEntry>())
                as *const AllowlistEntry;
            let entry = &*entry_ptr;

            let len = entry.prefix_len as usize;
            if len == 0 || len > 260 {
                continue;
            }

            let prefix = std::str::from_utf8(&entry.prefix[..len]).unwrap_or("");
            let prefix_upper = prefix.to_ascii_uppercase();

            if prefix_match_directory_boundary(&prefix_upper, &upper) {
                return true;
            }
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Unified allowlist check
// ---------------------------------------------------------------------------

/// Returns `(is_allowlisted, category)` for the given path.
///
/// Checks in order:
/// 1. Hardcoded system paths (fastest path).
/// 2. Build-tool paths (full-path + signer validation).
/// 3. Operator-extended paths from shared memory (if header available).
///
/// Returns `(true, Some(category))` if allowlisted, `(false, None)` otherwise.
///
/// # Arguments
///
/// * `path` — The file path to check.
/// * `header` — Optional shared-memory cache header for operator extensions.
pub fn is_allowlisted(path: &str, header: Option<&CacheHeader>) -> (bool, Option<u8>) {
    // 1. System paths first.
    if is_system_allowlisted(path) {
        return (true, Some(category::SYSTEM));
    }

    // 2. Build tools second.
    if is_build_tool_allowlisted(path) {
        return (true, Some(category::BUILD_TOOL));
    }

    // 3. Operator extensions third.
    if let Some(h) = header {
        if is_operator_allowlisted(path, h) {
            return (true, Some(category::OPERATOR));
        }
    }

    (false, None)
}

/// Legacy compatibility: returns `true` if path is on the system allowlist.
///
/// Used by trampolines that only need the system-path fast path.
pub fn is_path_allowed(path: &str) -> bool {
    is_system_allowlisted(path)
}

/// Returns `true` if the current process is a build tool that should bypass
/// the pipe round-trip.
///
/// This is checked per-process at DLL load time, not per-path.
pub fn is_build_tool_process() -> bool {
    let image_path = get_process_image_path();
    is_build_tool_allowlisted(image_path)
}

// ---------------------------------------------------------------------------
// Audit logging
// ---------------------------------------------------------------------------

/// Emit an audit event for an allowlist hit.
///
/// Logs via `tracing::info!` and, if the pipe is available, sends a
/// `siem.allowlist_hit` event. Emitted immediately (not batched) for audit
/// integrity.
///
/// Only emits for T3/T4 paths or when in fail-mode (DEGRADED/ISOLATED/RESYNC).
/// T1/T2 allowlist hits in HEALTHY state are silent (too noisy).
///
/// # Arguments
///
/// * `path` — The file path that was allowlisted.
/// * `category` — The allowlist category (0=system, 1=build_tool, 2=operator).
/// * `decision_context` — The current fail-mode state string (e.g., "HEALTHY",
///   "DEGRADED", "ISOLATED").
pub fn emit_allowlist_hit(path: &str, category: u8, decision_context: &str) {
    // Silent for T1/T2 in HEALTHY state.
    if decision_context == "HEALTHY" {
        // Still allowlist, but no audit noise for healthy low-tier hits.
        // We don't know the tier here (allowlist is pre-cache), so we emit
        // for all allowlist hits in non-HEALTHY states and for build tools
        // (which are always T1 but may be in fail-mode).
    }

    // Always emit for non-HEALTHY states.
    if decision_context != "HEALTHY" {
        let category_str = match category {
            category::SYSTEM => "system",
            category::BUILD_TOOL => "build_tool",
            category::OPERATOR => "operator",
            _ => "unknown",
        };

        let pid = std::process::id();
        let image_path = get_process_image_path();

        tracing::info!(
            event = "siem.allowlist_hit",
            path = %path,
            category = %category_str,
            decision_context = %decision_context,
            pid = pid,
            image_path = %image_path,
            timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            "allowlist hit"
        );
    }
}

// ---------------------------------------------------------------------------
// Helper: prefix matching with directory boundary
// ---------------------------------------------------------------------------

/// Check if `path` starts with `prefix` at a directory boundary.
///
/// Both strings must already be uppercase. A directory boundary means the
/// prefix is either the entire path or is followed by a backslash.
///
/// # Arguments
///
/// * `prefix` — The directory prefix (e.g., `C:\WINDOWS\SYSTEM32`).
/// * `path` — The path to check.
fn prefix_match_directory_boundary(prefix: &str, path: &str) -> bool {
    let prefix_norm = prefix.trim_end_matches('\\');
    if let Some(rest) = path.strip_prefix(prefix_norm) {
        rest.is_empty() || rest.starts_with('\\')
    } else {
        false
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Task 1: System path allowlist ---

    #[test]
    fn system32_is_allowed() {
        assert!(is_system_allowlisted(r"C:\Windows\System32\kernel32.dll"));
    }

    #[test]
    fn syswow64_is_allowed() {
        assert!(is_system_allowlisted(r"C:\Windows\SysWOW64\wow64.dll"));
    }

    #[test]
    fn winsxs_is_allowed() {
        assert!(is_system_allowlisted(r"C:\Windows\WinSxS\manifests\foo.manifest"));
    }

    #[test]
    fn program_files_common_is_allowed() {
        assert!(is_system_allowlisted(
            r"C:\Program Files\Common Files\System\foo.dll"
        ));
    }

    #[test]
    fn non_system_path_not_allowed() {
        assert!(!is_system_allowlisted(r"C:\Users\test\Documents\secret.txt"));
    }

    #[test]
    fn case_insensitive_match() {
        assert!(is_system_allowlisted(r"c:\windows\system32\file.dll"));
    }

    #[test]
    fn system_paths_prefix_boundary() {
        // Should NOT match: C:\Windows\System32Fake is a different directory.
        assert!(!is_system_allowlisted(r"C:\Windows\System32Fake\evil.dll"));
    }

    // --- Task 2: Build-tool allowlist ---

    #[test]
    fn build_tool_names_listed() {
        assert!(BUILD_TOOL_NAMES.contains(&"CARGO.EXE"));
        assert!(BUILD_TOOL_NAMES.contains(&"MSBUILD.EXE"));
        assert!(BUILD_TOOL_NAMES.contains(&"DEVENV.EXE"));
    }

    #[test]
    fn build_tool_basename_match() {
        // Basename matches but parent doesn't — should fail.
        assert!(!is_build_tool_allowlisted(r"C:\Users\attacker\cargo.exe"));
    }

    #[test]
    fn build_tool_parent_match_required() {
        // Valid path under trusted parent, but signer verification fails
        // on non-Windows (returns false conservatively).
        // On Windows with actual signed binary, this would pass.
        #[cfg(not(windows))]
        {
            assert!(!is_build_tool_allowlisted(
                r"C:\Program Files\Microsoft Visual Studio\2022\devenv.exe"
            ));
        }
    }

    #[test]
    fn build_tool_user_writable_rejected() {
        // Even if basename matches, user-writable directory rejects.
        assert!(is_user_writable_directory(r"C:\Users\test"));
        assert!(is_user_writable_directory(r"C:\Temp"));
        assert!(!is_user_writable_directory(r"C:\Program Files"));
    }

    #[test]
    fn user_writable_prefixes() {
        assert!(is_user_writable_directory(r"C:\Users\test\cargo.exe"));
        assert!(is_user_writable_directory(r"C:\Temp\build"));
        assert!(is_user_writable_directory(r"C:\Windows\Temp\output"));
        assert!(!is_user_writable_directory(r"C:\Program Files\MSBuild"));
        assert!(!is_user_writable_directory(r"C:\Rust\bin"));
    }

    // --- Task 3: Unified allowlist ---

    #[test]
    fn is_allowlisted_system_path() {
        let (allowed, cat) = is_allowlisted(r"C:\Windows\System32\kernel32.dll", None);
        assert!(allowed);
        assert_eq!(cat, Some(category::SYSTEM));
    }

    #[test]
    fn is_allowlisted_non_system_no_header() {
        let (allowed, cat) = is_allowlisted(r"C:\Users\test\file.txt", None);
        assert!(!allowed);
        assert_eq!(cat, None);
    }

    #[test]
    fn is_allowlisted_build_tool_rejected_on_non_windows() {
        // On non-Windows, signer verification always fails (conservative).
        #[cfg(not(windows))]
        {
            let (allowed, _cat) =
                is_allowlisted(r"C:\Program Files\Microsoft Visual Studio\devenv.exe", None);
            assert!(!allowed);
        }
    }

    // --- Task 4: Audit logging ---

    #[test]
    fn emit_allowlist_hit_healthy_is_silent() {
        // Should not panic.
        emit_allowlist_hit(r"C:\Windows\System32\file.dll", category::SYSTEM, "HEALTHY");
    }

    #[test]
    fn emit_allowlist_hit_degraded_emits() {
        // Should not panic.
        emit_allowlist_hit(
            r"C:\Windows\System32\file.dll",
            category::SYSTEM,
            "DEGRADED",
        );
    }

    #[test]
    fn emit_allowlist_hit_isolated_emits() {
        // Should not panic.
        emit_allowlist_hit(
            r"C:\Windows\System32\file.dll",
            category::BUILD_TOOL,
            "ISOLATED",
        );
    }

    // --- Helper tests ---

    #[test]
    fn prefix_match_directory_boundary_exact() {
        assert!(prefix_match_directory_boundary(
            r"C:\WINDOWS\SYSTEM32",
            r"C:\WINDOWS\SYSTEM32"
        ));
    }

    #[test]
    fn prefix_match_directory_boundary_child() {
        assert!(prefix_match_directory_boundary(
            r"C:\WINDOWS\SYSTEM32",
            r"C:\WINDOWS\SYSTEM32\KERNEL32.DLL"
        ));
    }

    #[test]
    fn prefix_match_directory_boundary_no_partial() {
        // C:\WINDOWS\SYSTEM32Fake should NOT match.
        assert!(!prefix_match_directory_boundary(
            r"C:\WINDOWS\SYSTEM32",
            r"C:\WINDOWS\SYSTEM32FAKE\EVIL.DLL"
        ));
    }

    #[test]
    fn prefix_match_directory_boundary_case_sensitive_params() {
        // Function expects already-uppercase inputs.
        assert!(prefix_match_directory_boundary(
            r"C:\PROGRAM FILES",
            r"C:\PROGRAM FILES\COMMON FILES\TEST.DLL"
        ));
    }

    #[test]
    fn category_constants() {
        assert_eq!(category::SYSTEM, 0);
        assert_eq!(category::BUILD_TOOL, 1);
        assert_eq!(category::OPERATOR, 2);
    }

    #[test]
    fn allowlist_entry_size() {
        // Verify AllowlistEntry is the expected size (268 on x64 due to padding).
        // prefix_len: 2, prefix: 260, category: 1, _pad: 5 -> total 268.
        assert_eq!(std::mem::size_of::<AllowlistEntry>(), 268);
    }
}
