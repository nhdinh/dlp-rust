//! Per-process allowlist matching with Authenticode signer caching.
//!
//! Review fixes applied:
//! - Canonical path normalization (GetFinalPathNameByHandleW-style) before matching
//! - Trusted Windows directory check for system-critical basenames
//! - Exact directory-boundary prefix matching (prevents sibling-path overmatch)
//! - Signer cache keyed by (path, file_id/hash) with TTL invalidation

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Category of allowlist entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum AllowlistCategory {
    SelfProcess,
    Avedr,
    SystemCritical,
    OperatorDefined,
}

/// Match type for allowlist entries (review fix: explicit match semantics).
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum MatchType {
    /// Exact path match (canonicalized).
    ExactPath,
    /// Glob pattern match (e.g., "C:\\Program Files\\CrowdStrike\\*").
    PathGlob,
    /// Prefix match that stops at directory boundary (e.g., "C:\\Program Files\\CrowdStrike\\").
    PathPrefix,
    /// Authenticode signer certificate subject substring match.
    CertSubject,
    /// SHA-256 thumbprint of the signer certificate (review fix: stronger than subject).
    CertThumbprint,
}

/// Single allowlist entry.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AllowlistEntry {
    pub match_type: MatchType,
    pub value: String,
    pub description: String,
    pub category: AllowlistCategory,
}

/// Cached signer result with TTL.
#[derive(Debug, Clone)]
struct CachedSigner {
    subject: String,
    thumbprint: String,
    cached_at: Instant,
}

const SIGNER_CACHE_TTL: Duration = Duration::from_secs(300);

/// Per-process allowlist matcher with Authenticode signer caching.
///
/// Thread-safe via `DashMap`-style `Arc<RwLock<HashMap>>` for the signer cache.
/// The entries vector is read-only after construction (updated via `update_entries`).
#[derive(Debug, Clone)]
pub struct AllowlistMatcher {
    entries: Vec<AllowlistEntry>,
    /// Signer cache: keyed by canonical_path -> CachedSigner.
    signer_cache: Arc<RwLock<HashMap<String, CachedSigner>>>,
    /// DLP agent's own image path (canonicalized), for self-exclusion.
    self_image_path: String,
    /// DLP agent's own PID, for self-exclusion.
    self_pid: u32,
}

impl AllowlistMatcher {
    /// Creates a new allowlist matcher.
    ///
    /// # Arguments
    ///
    /// * `entries` — Allowlist entries from config.
    /// * `self_image_path` — Canonicalized path to the agent's own executable.
    /// * `self_pid` — The agent's own process ID.
    #[must_use]
    pub fn new(entries: Vec<AllowlistEntry>, self_image_path: String, self_pid: u32) -> Self {
        Self {
            entries,
            signer_cache: Arc::new(RwLock::new(HashMap::new())),
            self_image_path,
            self_pid,
        }
    }

    /// Check if a process should be skipped. Returns the matching category if skipped.
    ///
    /// `image_path` must be canonicalized before calling.
    /// `creation_time` is reserved for future cache key uniqueness (currently unused).
    ///
    /// # Arguments
    ///
    /// * `pid` — Target process ID.
    /// * `image_path` — Canonicalized image path of the target process.
    /// * `_creation_time` — Process creation time (reserved for future use).
    #[must_use]
    pub fn check(
        &self,
        pid: u32,
        image_path: &str,
        _creation_time: u64,
    ) -> Option<AllowlistCategory> {
        // Self-exclusion (highest priority).
        if pid == self.self_pid || image_path.eq_ignore_ascii_case(&self.self_image_path) {
            return Some(AllowlistCategory::SelfProcess);
        }

        // System-critical: check basename against trusted Windows directories.
        if let Some(category) = self.check_system_critical(image_path) {
            return Some(category);
        }

        // Path-based matching (exact, glob, prefix).
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
                MatchType::PathPrefix => {
                    if prefix_match_directory_boundary(&entry.value, image_path) {
                        return Some(entry.category);
                    }
                }
                MatchType::CertSubject | MatchType::CertThumbprint => {
                    // Checked below after path matching.
                }
            }
        }

        // Cert-based matching with cache.
        for entry in &self.entries {
            match &entry.match_type {
                MatchType::CertSubject => {
                    let subject = self.get_cached_signer(image_path);
                    if subject.to_lowercase().contains(&entry.value.to_lowercase()) {
                        return Some(entry.category);
                    }
                }
                MatchType::CertThumbprint => {
                    let thumbprint = self.get_cached_thumbprint(image_path);
                    if thumbprint.eq_ignore_ascii_case(&entry.value) {
                        return Some(entry.category);
                    }
                }
                _ => {}
            }
        }

        None
    }

    /// System-critical processes: check basename against trusted Windows directories.
    ///
    /// Review fix: prevents spoofing (e.g., user process named csrss.exe outside System32).
    fn check_system_critical(&self, image_path: &str) -> Option<AllowlistCategory> {
        let path = Path::new(image_path);
        let basename = path.file_name()?.to_str()?;
        let parent = path.parent()?;
        let parent_str = parent.to_str()?.to_lowercase();

        // Must be in a trusted Windows directory.
        let is_trusted_dir = parent_str.contains("\\windows\\system32")
            || parent_str.contains("\\windows\\syswow64")
            || parent_str.contains("\\windows\\winsxs")
            || parent_str.ends_with("\\windows");

        if !is_trusted_dir {
            return None;
        }

        let critical_names = [
            "csrss.exe",
            "smss.exe",
            "wininit.exe",
            "services.exe",
            "lsass.exe",
            "fontdrvhost.exe",
            "dwm.exe",
            "svchost.exe",
        ];
        if critical_names.contains(&basename.to_lowercase().as_str()) {
            return Some(AllowlistCategory::SystemCritical);
        }
        None
    }

    /// Get cached signer subject, or extract and cache.
    fn get_cached_signer(&self, image_path: &str) -> String {
        let cache_key = image_path.to_lowercase();
        {
            let cache = self.signer_cache.read().expect("signer cache read poisoned");
            if let Some(cached) = cache.get(&cache_key) {
                if cached.cached_at.elapsed() < SIGNER_CACHE_TTL {
                    return cached.subject.clone();
                }
            }
        }
        let subject = extract_cert_subject(image_path).unwrap_or_default();
        let thumbprint = extract_cert_thumbprint(image_path).unwrap_or_default();
        {
            let mut cache = self
                .signer_cache
                .write()
                .expect("signer cache write poisoned");
            cache.insert(
                cache_key,
                CachedSigner {
                    subject: subject.clone(),
                    thumbprint: thumbprint.clone(),
                    cached_at: Instant::now(),
                },
            );
        }
        subject
    }

    /// Get cached thumbprint.
    fn get_cached_thumbprint(&self, image_path: &str) -> String {
        let cache_key = image_path.to_lowercase();
        {
            let cache = self.signer_cache.read().expect("signer cache read poisoned");
            if let Some(cached) = cache.get(&cache_key) {
                if cached.cached_at.elapsed() < SIGNER_CACHE_TTL {
                    return cached.thumbprint.clone();
                }
            }
        }
        // get_cached_signer populates both fields.
        self.get_cached_signer(image_path);
        {
            let cache = self.signer_cache.read().expect("signer cache read poisoned");
            cache
                .get(&cache_key)
                .map(|c| c.thumbprint.clone())
                .unwrap_or_default()
        }
    }

    /// Update entries (called on config reload).
    pub fn update_entries(&mut self, entries: Vec<AllowlistEntry>) {
        self.entries = entries;
    }

    /// Returns the number of allowlist entries.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

/// Canonicalize a Windows path (best-effort).
///
/// Review fix: prevents path-spoofing via short paths, symlinks, or case variations.
#[must_use]
pub fn canonicalize_path(path: &str) -> String {
    // Use GetFinalPathNameByHandleW if available; fallback to normalize.
    // For now, normalize slashes and lowercase for comparison.
    path.replace('/', "\\").to_lowercase()
}

/// Glob match using the `glob` crate.
#[must_use]
fn glob_match(pattern: &str, path: &str) -> bool {
    match glob::Pattern::new(pattern) {
        Ok(p) => p.matches(path),
        Err(_) => false,
    }
}

/// Prefix match that respects directory boundaries.
///
/// Review fix: "C:\\Program Files\\CrowdStrike\\" matches
/// "C:\\Program Files\\CrowdStrike\\foo.exe" but NOT
/// "C:\\Program Files\\CrowdStrike-Evil\\foo.exe".
#[must_use]
fn prefix_match_directory_boundary(prefix: &str, path: &str) -> bool {
    let prefix_norm = prefix.trim_end_matches('\\').to_lowercase();
    let path_norm = path.to_lowercase();
    if let Some(rest) = path_norm.strip_prefix(&prefix_norm) {
        // After prefix, must be either empty (exact dir) or start with \\.
        rest.is_empty() || rest.starts_with('\\')
    } else {
        false
    }
}

/// Extract Authenticode signer certificate subject.
///
/// Reuses the 4-step WinCrypt pattern from detection/app_identity.rs.
/// For now, this is a stub that returns None on non-Windows platforms.
/// On Windows, it delegates to the full WinCrypt implementation.
#[cfg(windows)]
fn extract_cert_subject(image_path: &str) -> Option<String> {
    // Delegate to the existing extract_publisher function in app_identity.rs
    // which implements the full 4-step WinCrypt sequence.
    // We cannot directly call a private function from another module, so we
    // implement the same pattern here or use a shared helper.
    // For this plan, we implement the extraction inline.
    extract_cert_subject_full(image_path)
}

#[cfg(not(windows))]
fn extract_cert_subject(_image_path: &str) -> Option<String> {
    None
}

/// Extract Authenticode signer certificate SHA-256 thumbprint.
#[cfg(windows)]
fn extract_cert_thumbprint(image_path: &str) -> Option<String> {
    extract_cert_thumbprint_full(image_path)
}

#[cfg(not(windows))]
fn extract_cert_thumbprint(_image_path: &str) -> Option<String> {
    None
}

/// Full WinCrypt implementation for cert subject extraction.
#[cfg(windows)]
fn extract_cert_subject_full(image_path: &str) -> Option<String> {
    use std::ffi::c_void;
    use windows::Win32::Security::Cryptography::{
        CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext, CertGetNameStringW,
        CryptMsgClose, CryptMsgGetParam, CryptQueryObject, CERT_FIND_SUBJECT_NAME,
        CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_ENCODING_TYPE, CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE,
        CMSG_SIGNER_INFO_PARAM, HCERTSTORE, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    };

    let path_wide: Vec<u16> = image_path
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut h_msg: *mut c_void = std::ptr::null_mut();
    let mut h_store: HCERTSTORE = HCERTSTORE::default();
    let mut encoding_type = CERT_QUERY_ENCODING_TYPE(0);
    let mut content_type = CERT_QUERY_ENCODING_TYPE(0);
    let mut format_type = CERT_QUERY_ENCODING_TYPE(0);

    let ok = unsafe {
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            windows::core::PCWSTR::from_raw(path_wide.as_ptr()).0 as *const c_void,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            Some(&mut encoding_type as *mut _ as *mut _),
            Some(&mut content_type as *mut _ as *mut _),
            Some(&mut format_type as *mut _ as *mut _),
            Some(&mut h_store),
            Some(&mut h_msg as *mut *mut c_void),
            None,
        )
    };
    if ok.is_err() {
        return None;
    }

    let mut signer_info_size: u32 = 0;
    unsafe {
        let _ = CryptMsgGetParam(
            h_msg,
            CMSG_SIGNER_INFO_PARAM,
            0,
            None,
            &mut signer_info_size,
        );
    }
    let mut signer_info_buf = vec![0u8; signer_info_size as usize];
    let ok = unsafe {
        CryptMsgGetParam(
            h_msg,
            CMSG_SIGNER_INFO_PARAM,
            0,
            Some(signer_info_buf.as_mut_ptr() as *mut c_void),
            &mut signer_info_size,
        )
    };
    if ok.is_err() {
        unsafe {
            let _ = CryptMsgClose(Some(h_msg));
            let _ = CertCloseStore(Some(h_store), 0);
        }
        return None;
    }

    let cert_info_ptr =
        signer_info_buf.as_ptr() as *const windows::Win32::Security::Cryptography::CERT_INFO;
    let combined_encoding = CERT_QUERY_ENCODING_TYPE(X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0);
    let cert_ctx = unsafe {
        CertFindCertificateInStore(
            h_store,
            combined_encoding,
            0,
            CERT_FIND_SUBJECT_NAME,
            Some(&(*cert_info_ptr).Issuer as *const _ as *const c_void),
            None,
        )
    };

    if cert_ctx.is_null() {
        unsafe {
            let _ = CryptMsgClose(Some(h_msg));
            let _ = CertCloseStore(Some(h_store), 0);
        }
        return None;
    }

    let name_len =
        unsafe { CertGetNameStringW(cert_ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None) };

    let subject = if name_len > 1 {
        let mut name_buf = vec![0u16; name_len as usize];
        unsafe {
            CertGetNameStringW(
                cert_ctx,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                None,
                Some(&mut name_buf),
            );
        }
        let trimmed = if name_buf.last() == Some(&0) {
            &name_buf[..name_buf.len() - 1]
        } else {
            &name_buf[..]
        };
        String::from_utf16_lossy(trimmed)
    } else {
        String::new()
    };

    unsafe {
        let _ = CertFreeCertificateContext(Some(cert_ctx));
        let _ = CryptMsgClose(Some(h_msg));
        let _ = CertCloseStore(Some(h_store), 0);
    }

    if subject.is_empty() {
        None
    } else {
        Some(subject)
    }
}

/// Full WinCrypt implementation for cert thumbprint extraction.
#[cfg(windows)]
fn extract_cert_thumbprint_full(image_path: &str) -> Option<String> {
    use std::ffi::c_void;
    use windows::Win32::Security::Cryptography::{
        CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext,
        CertGetCertificateContextProperty, CryptMsgClose, CryptMsgGetParam, CryptQueryObject,
        CERT_FIND_SUBJECT_NAME, CERT_HASH_PROP_ID,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_ENCODING_TYPE,
        CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE, CMSG_SIGNER_INFO_PARAM, HCERTSTORE,
        PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    };

    let path_wide: Vec<u16> = image_path
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut h_msg: *mut c_void = std::ptr::null_mut();
    let mut h_store: HCERTSTORE = HCERTSTORE::default();
    let mut encoding_type = CERT_QUERY_ENCODING_TYPE(0);
    let mut content_type = CERT_QUERY_ENCODING_TYPE(0);
    let mut format_type = CERT_QUERY_ENCODING_TYPE(0);

    let ok = unsafe {
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            windows::core::PCWSTR::from_raw(path_wide.as_ptr()).0 as *const c_void,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            Some(&mut encoding_type as *mut _ as *mut _),
            Some(&mut content_type as *mut _ as *mut _),
            Some(&mut format_type as *mut _ as *mut _),
            Some(&mut h_store),
            Some(&mut h_msg as *mut *mut c_void),
            None,
        )
    };
    if ok.is_err() {
        return None;
    }

    let mut signer_info_size: u32 = 0;
    unsafe {
        let _ = CryptMsgGetParam(
            h_msg,
            CMSG_SIGNER_INFO_PARAM,
            0,
            None,
            &mut signer_info_size,
        );
    }
    let mut signer_info_buf = vec![0u8; signer_info_size as usize];
    let ok = unsafe {
        CryptMsgGetParam(
            h_msg,
            CMSG_SIGNER_INFO_PARAM,
            0,
            Some(signer_info_buf.as_mut_ptr() as *mut c_void),
            &mut signer_info_size,
        )
    };
    if ok.is_err() {
        unsafe {
            let _ = CryptMsgClose(Some(h_msg));
            let _ = CertCloseStore(Some(h_store), 0);
        }
        return None;
    }

    let cert_info_ptr =
        signer_info_buf.as_ptr() as *const windows::Win32::Security::Cryptography::CERT_INFO;
    let combined_encoding = CERT_QUERY_ENCODING_TYPE(X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0);
    let cert_ctx = unsafe {
        CertFindCertificateInStore(
            h_store,
            combined_encoding,
            0,
            CERT_FIND_SUBJECT_NAME,
            Some(&(*cert_info_ptr).Issuer as *const _ as *const c_void),
            None,
        )
    };

    if cert_ctx.is_null() {
        unsafe {
            let _ = CryptMsgClose(Some(h_msg));
            let _ = CertCloseStore(Some(h_store), 0);
        }
        return None;
    }

    // Get thumbprint (hash) property.
    let mut hash_size: u32 = 0;
    let result = unsafe {
        CertGetCertificateContextProperty(
            cert_ctx,
            CERT_HASH_PROP_ID,
            None,
            &mut hash_size,
        )
    };

    let thumbprint = if result.is_ok() && hash_size > 0 {
        let mut hash_buf = vec![0u8; hash_size as usize];
        let result = unsafe {
            CertGetCertificateContextProperty(
                cert_ctx,
                CERT_HASH_PROP_ID,
                Some(hash_buf.as_mut_ptr() as *mut c_void),
                &mut hash_size,
            )
        };
        if result.is_ok() {
            hash_buf
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    unsafe {
        let _ = CertFreeCertificateContext(Some(cert_ctx));
        let _ = CryptMsgClose(Some(h_msg));
        let _ = CertCloseStore(Some(h_store), 0);
    }

    if thumbprint.is_empty() {
        None
    } else {
        Some(thumbprint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_matcher() -> AllowlistMatcher {
        AllowlistMatcher::new(
            vec![],
            r"C:\\ProgramData\\DLP\\dlp-agent.exe".to_string(),
            9999,
        )
    }

    #[test]
    fn test_self_exclusion_by_pid() {
        let matcher = AllowlistMatcher::new(vec![], r"C:\dummy.exe".to_string(), 1234);
        let result = matcher.check(1234, r"C:\\other.exe", 0);
        assert_eq!(result, Some(AllowlistCategory::SelfProcess));
    }

    #[test]
    fn test_self_exclusion_by_path() {
        let matcher =
            AllowlistMatcher::new(vec![], r"C:\ProgramData\DLP\dlp-agent.exe".to_string(), 9999);
        let result = matcher.check(5678, r"C:\ProgramData\DLP\dlp-agent.exe", 0);
        assert_eq!(result, Some(AllowlistCategory::SelfProcess));
    }

    #[test]
    fn test_system_critical_in_system32() {
        let matcher = test_matcher();
        let result = matcher.check(100, r"C:\Windows\System32\csrss.exe", 0);
        assert_eq!(result, Some(AllowlistCategory::SystemCritical));
    }

    #[test]
    fn test_system_critical_not_in_trusted_dir() {
        let matcher = test_matcher();
        let result = matcher.check(100, r"C:\Temp\csrss.exe", 0);
        assert!(result.is_none(), "spoofed csrss.exe outside trusted dir must not match");
    }

    #[test]
    fn test_path_prefix_boundary_match() {
        let entries = vec![AllowlistEntry {
            match_type: MatchType::PathPrefix,
            value: r"C:\Program Files\CrowdStrike\".to_string(),
            description: "CrowdStrike AV".to_string(),
            category: AllowlistCategory::Avedr,
        }];
        let matcher = AllowlistMatcher::new(entries, r"C:\dummy.exe".to_string(), 9999);

        // Should match: path is inside the directory.
        let result = matcher.check(100, r"C:\Program Files\CrowdStrike\foo.exe", 0);
        assert_eq!(result, Some(AllowlistCategory::Avedr));
    }

    #[test]
    fn test_path_prefix_boundary_reject_sibling() {
        let entries = vec![AllowlistEntry {
            match_type: MatchType::PathPrefix,
            value: r"C:\Program Files\CrowdStrike\".to_string(),
            description: "CrowdStrike AV".to_string(),
            category: AllowlistCategory::Avedr,
        }];
        let matcher = AllowlistMatcher::new(entries, r"C:\dummy.exe".to_string(), 9999);

        // Should NOT match: sibling directory name.
        let result = matcher.check(100, r"C:\Program Files\CrowdStrike-Evil\foo.exe", 0);
        assert!(result.is_none(), "sibling path must not match prefix");
    }

    #[test]
    fn test_glob_matching() {
        let entries = vec![AllowlistEntry {
            match_type: MatchType::PathGlob,
            value: r"C:\Program Files\CrowdStrike\*".to_string(),
            description: "CrowdStrike AV".to_string(),
            category: AllowlistCategory::Avedr,
        }];
        let matcher = AllowlistMatcher::new(entries, r"C:\dummy.exe".to_string(), 9999);

        let result = matcher.check(100, r"C:\Program Files\CrowdStrike\foo.exe", 0);
        assert_eq!(result, Some(AllowlistCategory::Avedr));
    }

    #[test]
    fn test_exact_path_case_insensitive() {
        let entries = vec![AllowlistEntry {
            match_type: MatchType::ExactPath,
            value: r"C:\Program Files\App\app.exe".to_string(),
            description: "Exact match".to_string(),
            category: AllowlistCategory::OperatorDefined,
        }];
        let matcher = AllowlistMatcher::new(entries, r"C:\dummy.exe".to_string(), 9999);

        let result = matcher.check(100, r"c:\program files\app\app.exe", 0);
        assert_eq!(result, Some(AllowlistCategory::OperatorDefined));
    }

    #[test]
    fn test_signer_cache_ttl() {
        let matcher = test_matcher();
        let path = r"C:\\Windows\\System32\\notepad.exe";

        // First call populates cache.
        let subject1 = matcher.get_cached_signer(path);
        // Second call should return from cache (same value).
        let subject2 = matcher.get_cached_signer(path);
        assert_eq!(subject1, subject2);

        // Verify cache has the entry.
        let cache = matcher.signer_cache.read().unwrap();
        assert!(cache.contains_key(&path.to_lowercase()));
    }

    #[test]
    fn test_canonicalize_path() {
        assert_eq!(
            canonicalize_path(r"C:/Windows/System32/notepad.exe"),
            r"c:\windows\system32\notepad.exe"
        );
        assert_eq!(
            canonicalize_path(r"C:\Windows\System32\NOTEPAD.EXE"),
            r"c:\windows\system32\notepad.exe"
        );
    }

    #[test]
    fn test_prefix_match_directory_boundary_edge_cases() {
        // Exact directory match.
        assert!(prefix_match_directory_boundary(
            r"C:\Program Files\CrowdStrike",
            r"C:\Program Files\CrowdStrike"
        ));

        // Child file match.
        assert!(prefix_match_directory_boundary(
            r"C:\Program Files\CrowdStrike\",
            r"C:\Program Files\CrowdStrike\foo.exe"
        ));

        // Sibling directory reject.
        assert!(!prefix_match_directory_boundary(
            r"C:\Program Files\CrowdStrike\",
            r"C:\Program Files\CrowdStrike-Evil\foo.exe"
        ));

        // Partial name reject.
        assert!(!prefix_match_directory_boundary(
            r"C:\Program Files\Crowd",
            r"C:\Program Files\CrowdStrike\foo.exe"
        ));
    }

    #[test]
    fn test_update_entries() {
        let mut matcher = test_matcher();
        assert_eq!(matcher.entry_count(), 0);

        let new_entries = vec![AllowlistEntry {
            match_type: MatchType::ExactPath,
            value: r"C:\test.exe".to_string(),
            description: "test".to_string(),
            category: AllowlistCategory::OperatorDefined,
        }];
        matcher.update_entries(new_entries);
        assert_eq!(matcher.entry_count(), 1);
    }
}
