//! Path normalization and FNV-1a hashing for cross-boundary path correlation.
//!
//! This module provides hardened Windows path normalization and fast
//! non-cryptographic hashing used by both the hook DLL (user mode) and the
//! bypass correlator (agent service) to ensure identical path-hash computation
//! across the user/kernel boundary.
//!
//! # Security Note
//!
//! Any divergence between the hook DLL and correlator normalization will cause
//! hash mismatches and false bypass alerts. This module is the single source of
//! truth for both sides.

use std::borrow::Cow;

// Re-export FNV-1a from the hash module for convenience.
pub use crate::hash::fnv1a_64;

/// Hardened Windows path normalization.
///
/// Returns `Some(Cow<str>)` with the normalized path, or `None` if the path
/// cannot be safely normalized. A `None` result forces pipe fallback in the
/// hook DLL and skipped correlation in the bypass correlator.
///
/// # Normalization steps
///
/// 1. Strip NT path prefix `\\?\` or `\\.\`.
/// 2. Reject device paths (`\\.\PhysicalDisk0` etc.).
/// 3. Detect and reject ADS streams (contains `:` after drive letter).
/// 4. Detect and reject volume GUID paths.
/// 5. Reject 8.3 short names.
/// 6. Replace forward slashes with backslashes.
/// 7. Collapse multiple consecutive backslashes (preserve UNC prefix).
/// 8. Convert to uppercase for case-insensitive comparison.
/// 9. Strip trailing backslashes (except root `C:\`).
/// 10. Reject trailing dots or spaces in path components.
///
/// # Arguments
///
/// * `path` — The raw Windows path to normalize.
///
/// # Returns
///
/// `Some(Cow::Owned(String))` with the normalized path, or `None` if the path
/// is empty, malformed, or contains unsafe patterns.
///
/// # Examples
///
/// ```
/// use dlp_common::path_hash::normalize_path;
///
/// let normalized = normalize_path(r"C:\Windows\System32").unwrap();
/// assert_eq!(normalized, r"C:\WINDOWS\SYSTEM32");
///
/// let nt_prefixed = normalize_path(r"\\?\C:\Windows").unwrap();
/// assert_eq!(nt_prefixed, r"C:\WINDOWS");
/// ```
pub fn normalize_path(path: &str) -> Option<Cow<'_, str>> {
    if path.is_empty() {
        return None;
    }

    // Step 1: Strip NT path prefix.
    let s = if path.starts_with(r"\\?\") || path.starts_with(r"\\.\") {
        &path[4..]
    } else {
        path
    };

    // Step 2: Detect device paths (\\.\PhysicalDisk0 etc.) — reject.
    if path.starts_with(r"\\.\") {
        return None;
    }

    // Step 3 (early): Detect ADS streams (contains `:` after drive letter).
    // ADS format: C:\file.txt:secret or C:\file.txt:$DATA
    if let Some(colon_pos) = s.find(':') {
        // Allow drive-letter colon at position 1 (e.g., "C:\").
        if colon_pos != 1 || s.len() < 2 || s.as_bytes()[1] != b':' {
            return None;
        }
        // Check for additional colons after the drive letter.
        if s[2..].contains(':') {
            return None;
        }
    }

    // Step 4: Detect volume GUID paths.
    if s.to_ascii_uppercase().contains("VOLUME{") {
        return None;
    }

    // Step 5: Reject 8.3 short names.
    if is_eight_three_short_name(s) {
        return None;
    }

    // Step 6: Replace forward slashes with backslashes.
    let mut result = s.replace('/', "\\");

    // Step 7: Collapse multiple consecutive backslashes.
    // Preserve UNC prefix (leading `\\`).
    let is_unc = result.starts_with("\\\\");
    let mut collapsed = String::with_capacity(result.len());
    let mut prev_was_backslash = false;
    for (i, ch) in result.chars().enumerate() {
        if ch == '\\' {
            if is_unc && i < 2 {
                // Keep the first two backslashes for UNC.
                collapsed.push(ch);
                prev_was_backslash = true;
            } else if !prev_was_backslash {
                collapsed.push(ch);
                prev_was_backslash = true;
            }
            // Skip consecutive backslashes.
        } else {
            collapsed.push(ch);
            prev_was_backslash = false;
        }
    }
    result = collapsed;

    // Step 8: Convert to uppercase for case-insensitive comparison.
    result = result.to_ascii_uppercase();

    // Step 9: Strip trailing backslashes (except root `C:\`).
    if result.len() > 3 && result.ends_with('\\') {
        result.truncate(result.len() - 1);
    }

    // Step 10: Reject trailing dots or spaces in path components.
    for component in result.split('\\') {
        if component.ends_with('.') || component.ends_with(' ') {
            return None;
        }
    }

    Some(Cow::Owned(result))
}

/// Check if a path contains an 8.3 short name.
///
/// 8.3 short names contain `~` followed by a digit (e.g., `PROGRA~1`).
///
/// # Arguments
///
/// * `path` — The path to check.
///
/// # Returns
///
/// `true` if the path contains an 8.3 short name pattern.
fn is_eight_three_short_name(path: &str) -> bool {
    for (i, ch) in path.char_indices() {
        if ch == '~' {
            // Check if next char is a digit.
            if let Some(next) = path[i + 1..].chars().next() {
                if next.is_ascii_digit() {
                    return true;
                }
            }
        }
    }
    false
}

/// Compute the FNV-1a 64-bit hash of a normalized path.
///
/// This is a convenience function that normalizes the path and then hashes it.
/// Both the hook DLL and the bypass correlator use this function to ensure
/// identical hash values for the same logical path.
///
/// # Arguments
///
/// * `path` — The raw Windows path to hash.
///
/// # Returns
///
/// `Some(u64)` containing the FNV-1a hash of the normalized path, or `None`
/// if the path cannot be normalized.
///
/// # Examples
///
/// ```
/// use dlp_common::path_hash::path_hash;
///
/// let h1 = path_hash(r"C:\Windows\System32").unwrap();
/// let h2 = path_hash(r"c:\windows\system32").unwrap();
/// assert_eq!(h1, h2); // Case-insensitive
/// ```
pub fn path_hash(path: &str) -> Option<u64> {
    let normalized = normalize_path(path)?;
    Some(fnv1a_64(normalized.as_bytes()))
}

/// Convert an NT device path to a DOS path.
///
/// ETW Kernel-File events sometimes report paths in NT device namespace
/// (e.g., `\Device\HarddiskVolume1\Windows\file.txt`). This function
/// attempts to map the device prefix to a DOS drive letter using
/// `QueryDosDeviceW`.
///
/// # Arguments
///
/// * `nt_path` — The NT device path to convert.
///
/// # Returns
///
/// `Some(String)` with the DOS path if conversion succeeded, or the original
/// path (possibly with prefixes stripped) if no mapping was found.
///
/// # Platform Behavior
///
/// * **Windows**: Calls `QueryDosDeviceW` to resolve device names.
/// * **Non-Windows**: Returns the path unchanged (compile stub).
///
/// # Examples
///
/// ```
/// use dlp_common::path_hash::nt_path_to_dos_path;
///
/// // Already a DOS path — passes through.
/// let dos = nt_path_to_dos_path(r"C:\Windows\file.txt").unwrap();
/// assert_eq!(dos, r"C:\Windows\file.txt");
/// ```
pub fn nt_path_to_dos_path(nt_path: &str) -> Option<String> {
    if nt_path.is_empty() {
        return None;
    }

    // Strip NT prefix if present.
    let stripped = if nt_path.starts_with(r"\\?\") || nt_path.starts_with(r"\\.\") {
        &nt_path[4..]
    } else {
        nt_path
    };

    // Already a DOS path — return as-is.
    if stripped.len() >= 2
        && stripped.as_bytes()[1] == b':'
        && stripped.as_bytes()[0].is_ascii_alphabetic()
    {
        return Some(stripped.to_string());
    }

    #[cfg(windows)]
    {
        nt_path_to_dos_path_windows(stripped)
    }
    #[cfg(not(windows))]
    {
        // Non-Windows: return the path unchanged (no QueryDosDeviceW available).
        Some(stripped.to_string())
    }
}

#[cfg(windows)]
fn nt_path_to_dos_path_windows(stripped: &str) -> Option<String> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::QueryDosDeviceW;

    // Parse \Device\HarddiskVolumeN\... format.
    let prefix = r"\Device\HarddiskVolume";
    if !stripped.starts_with(prefix) {
        // Not a HarddiskVolume path — return unchanged.
        return Some(stripped.to_string());
    }

    let after_prefix = &stripped[prefix.len()..];
    let volume_num_end = after_prefix
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(after_prefix.len());
    let volume_num_str = &after_prefix[..volume_num_end];
    let volume_num: u32 = volume_num_str.parse().ok()?;

    let remainder = if after_prefix.len() > volume_num_end {
        &after_prefix[volume_num_end..]
    } else {
        ""
    };

    // Build device name: \Device\HarddiskVolumeN
    let device_name = format!("{}\\Device\\HarddiskVolume{}", prefix, volume_num);
    let device_wide: Vec<u16> = device_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // QueryDosDeviceW: pass a large buffer to receive all mappings.
    // windows 0.62 returns u32 directly (0 on failure; call GetLastError).
    let mut buffer = vec![0u16; 1024];
    let len = unsafe { QueryDosDeviceW(PCWSTR::from_raw(device_wide.as_ptr()), Some(&mut buffer)) }
        as usize;

    if len == 0 {
        return Some(stripped.to_string());
    }

    // QueryDosDeviceW returns a sequence of null-terminated strings.
    // The first mapping is typically the drive letter (e.g., "C:")
    let first_mapping: String = buffer[..len]
        .iter()
        .take_while(|&&c| c != 0)
        .copied()
        .collect::<Vec<u16>>()
        .into_iter()
        .map(|c| char::from_u32(u32::from(c)).unwrap_or('\u{FFFD}'))
        .collect();

    if first_mapping.is_empty() {
        return Some(stripped.to_string());
    }

    // Build DOS path: drive letter + remainder.
    let dos_path = format!("{}{}", first_mapping, remainder);
    Some(dos_path)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- normalize_path tests ---

    #[test]
    fn test_normalize_empty_path() {
        assert!(normalize_path("").is_none());
    }

    #[test]
    fn test_normalize_nt_prefix_stripped() {
        let result = normalize_path(r"\\?\C:\foo").unwrap();
        assert_eq!(result, r"C:\FOO");
    }

    #[test]
    fn test_normalize_unc_path() {
        let result = normalize_path(r"\\server\share\file.txt").unwrap();
        assert_eq!(result, r"\\SERVER\SHARE\FILE.TXT");
    }

    #[test]
    fn test_normalize_dos_path() {
        let result = normalize_path(r"C:\foo\bar").unwrap();
        assert_eq!(result, r"C:\FOO\BAR");
    }

    #[test]
    fn test_normalize_forward_slashes() {
        let result = normalize_path(r"C:/foo/bar").unwrap();
        assert_eq!(result, r"C:\FOO\BAR");
    }

    #[test]
    fn test_normalize_backslash_collapse() {
        let result = normalize_path(r"C:\\\\foo").unwrap();
        assert_eq!(result, r"C:\FOO");
    }

    #[test]
    fn test_normalize_trailing_backslash() {
        let result = normalize_path(r"C:\foo\").unwrap();
        assert_eq!(result, r"C:\FOO");
    }

    #[test]
    fn test_normalize_root_kept() {
        let result = normalize_path(r"C:\").unwrap();
        assert_eq!(result, r"C:\");
    }

    #[test]
    fn test_normalize_rejects_device_namespace() {
        assert!(normalize_path(r"\\.\PhysicalDrive0").is_none());
    }

    #[test]
    fn test_normalize_rejects_volume_guid() {
        assert!(normalize_path(r"\\?\Volume{1234-1234-1234-1234-123456789abc}\file.txt").is_none());
    }

    #[test]
    fn test_normalize_rejects_ads() {
        assert!(normalize_path(r"C:\foo:stream").is_none());
    }

    #[test]
    fn test_normalize_rejects_8_3_short_name() {
        assert!(normalize_path(r"C:\PROGRA~1").is_none());
    }

    #[test]
    fn test_normalize_allows_long_name() {
        let result = normalize_path(r"C:\Program Files").unwrap();
        assert_eq!(result, r"C:\PROGRAM FILES");
    }

    // --- path_hash tests ---

    #[test]
    fn test_path_hash_consistency() {
        let h1 = path_hash(r"C:\Windows\System32").unwrap();
        let h2 = path_hash(r"C:\Windows\System32").unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_path_hash_case_insensitive() {
        let h1 = path_hash(r"C:\FOO").unwrap();
        let h2 = path_hash(r"C:\foo").unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_path_hash_different_paths_different_hash() {
        let h1 = path_hash(r"C:\foo").unwrap();
        let h2 = path_hash(r"C:\bar").unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_path_hash_none_on_invalid() {
        assert!(path_hash(r"C:\PROGRA~1").is_none());
        assert!(path_hash("").is_none());
    }

    // --- fnv1a_64 tests ---

    #[test]
    fn test_fnv1a_64_known_value() {
        assert_eq!(fnv1a_64(b"hello"), 0xa430d84680aabd0b);
    }

    #[test]
    fn test_fnv1a_64_empty() {
        assert_eq!(fnv1a_64(b""), 0xcbf29ce484222325);
    }

    // --- nt_path_to_dos_path tests ---

    #[test]
    fn test_nt_path_to_dos_path_already_dos() {
        let result = nt_path_to_dos_path(r"C:\foo\bar").unwrap();
        assert_eq!(result, r"C:\foo\bar");
    }

    #[test]
    fn test_nt_path_to_dos_path_unknown_volume() {
        // A path that doesn't match \Device\HarddiskVolumeN passes through.
        let result = nt_path_to_dos_path(r"\Device\Unknown\path").unwrap();
        assert_eq!(result, r"\Device\Unknown\path");
    }

    #[test]
    fn test_nt_path_to_dos_path_empty() {
        assert!(nt_path_to_dos_path("").is_none());
    }

    #[test]
    fn test_nt_path_to_dos_path_strips_nt_prefix() {
        let result = nt_path_to_dos_path(r"\\?\C:\foo").unwrap();
        assert_eq!(result, r"C:\foo");
    }

    #[cfg(windows)]
    #[test]
    fn test_nt_path_to_dos_path_harddisk_volume() {
        // On Windows, this test exercises the QueryDosDeviceW path.
        // We can't predict the exact drive letter mapping, but we can verify
        // the function doesn't panic and returns a plausible result.
        let result = nt_path_to_dos_path(r"\Device\HarddiskVolume1\Windows\file.txt");
        // Should return Some(...) — either mapped or original fallback.
        assert!(result.is_some());
    }

    // --- is_eight_three_short_name tests ---

    #[test]
    fn is_eight_three_short_name_detects() {
        assert!(is_eight_three_short_name(r"C:\PROGRA~1"));
        assert!(is_eight_three_short_name(r"C:\DOCUME~2"));
    }

    #[test]
    fn is_eight_three_short_name_allows_normal() {
        assert!(!is_eight_three_short_name(r"C:\Program Files"));
        assert!(!is_eight_three_short_name(r"C:\test~file"));
        assert!(!is_eight_three_short_name(r"C:\no_tilde"));
    }

    // --- Additional edge case tests from classification_cache.rs ---

    #[test]
    fn test_normalize_multiple_separators_collapsed() {
        let result = normalize_path(r"C:\\\\Windows\\\\System32").unwrap();
        assert_eq!(result, r"C:\WINDOWS\SYSTEM32");
    }

    #[test]
    fn test_normalize_trailing_dots_rejected() {
        assert!(normalize_path(r"C:\file.txt...").is_none());
    }

    #[test]
    fn test_normalize_trailing_spaces_rejected() {
        assert!(normalize_path(r"C:\file.txt   ").is_none());
    }

    #[test]
    fn test_normalize_ads_with_drive_letter_allowed() {
        // C:\file.txt is fine — the colon after drive letter is expected.
        let result = normalize_path(r"C:\file.txt").unwrap();
        assert_eq!(result, r"C:\FILE.TXT");
    }

    #[test]
    fn test_normalize_ads_alternate_data_stream_rejected() {
        // C:\file.txt:secret is an ADS — reject.
        assert!(normalize_path(r"C:\file.txt:secret").is_none());
        assert!(normalize_path(r"C:\file.txt:$DATA").is_none());
    }

    #[test]
    fn test_normalize_case_insensitive_match() {
        let r1 = normalize_path(r"C:\WINDOWS\SYSTEM32").unwrap();
        let r2 = normalize_path(r"C:\windows\system32").unwrap();
        assert_eq!(r1, r2);
    }
}
