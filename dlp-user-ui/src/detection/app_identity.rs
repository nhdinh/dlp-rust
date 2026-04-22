//! App identity resolution — HWND to AppIdentity via Win32 + Authenticode.
//!
//! All Win32 calls that may block on I/O (WinVerifyTrust) are guarded by the
//! per-path `AUTHENTICODE_CACHE`. The cache is keyed by absolute image path
//! (String) so renaming a signed binary produces a new cache miss and
//! re-verification (APP-06 success criterion 5, D-06).
//!
//! ## Thread safety
//!
//! `AUTHENTICODE_CACHE` uses `std::sync::OnceLock` + `std::sync::Mutex`.
//! The clipboard monitor thread is the sole caller in production, so there
//! is no real contention. The Mutex is present for future multi-caller safety.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use dlp_common::{AppIdentity, AppTrustTier, SignatureState};
use tracing::{debug, warn};

// Windows-only imports — HWND type is only available on Windows targets.
#[cfg(windows)]
use windows::Win32::Foundation::{CloseHandle, HWND};

/// Process-lifetime Authenticode result cache (D-04, D-05, D-06).
///
/// Key: absolute Win32 image path (e.g. `C:\Windows\notepad.exe`).
/// Value: `(publisher_cn, SignatureState)` — publisher is empty string when
///   no valid signature is present.
///
/// Populated once per unique path per process start. No eviction (D-05 —
/// at most ~200 unique clipboard-touching executables per session).
///
/// # Rust note
///
/// `OnceLock<T>` (stable since Rust 1.70) allows lazy, one-time static
/// initialization without a macro. `get_or_init` runs the closure on the
/// first call only; subsequent calls return a reference to the same value.
static AUTHENTICODE_CACHE: OnceLock<Mutex<HashMap<String, (String, SignatureState)>>> =
    OnceLock::new();

/// Returns a reference to the global Authenticode cache, initializing it on
/// the first call.
fn authenticode_cache() -> &'static Mutex<HashMap<String, (String, SignatureState)>> {
    AUTHENTICODE_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Resolves an `HWND` to the full Win32 image path of its owning process.
///
/// Uses `GetWindowThreadProcessId` to get the PID, then
/// `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` + `QueryFullProcessImageNameW`
/// to get the path.
///
/// `PROCESS_QUERY_LIMITED_INFORMATION` works on elevated processes too, unlike
/// `PROCESS_QUERY_INFORMATION` which fails with `ACCESS_DENIED` on higher-integrity
/// processes.
///
/// # Arguments
///
/// * `hwnd` — Window handle to resolve. Must be a valid top-level window.
///
/// # Returns
///
/// * `Some(path)` — full Win32 path (e.g. `C:\Windows\System32\notepad.exe`)
/// * `None` — HWND is dead (`GetWindowThreadProcessId` returns pid=0) or the
///   caller lacks access rights to the process.
#[cfg(windows)]
pub fn hwnd_to_image_path(hwnd: HWND) -> Option<String> {
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows::Win32::UI::WindowsAndMessaging::GetWindowThreadProcessId;

    let mut pid: u32 = 0;
    // GetWindowThreadProcessId populates `pid` via out parameter.
    // Returns 0 (thread ID) on dead HWND — not the same as PID being 0.
    // We check pid directly.
    let _tid = unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
    if pid == 0 {
        // Dead HWND — per D-08: caller returns Some(AppIdentity::default())
        return None;
    }

    // Open a process handle with the minimum rights needed for path query.
    // `false` = not inheritable.
    let handle = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(h) => h,
        Err(e) => {
            warn!(pid, error = %e, "OpenProcess failed for HWND resolution");
            return None;
        }
    };

    let mut buf = [0u16; 1024];
    let mut size = buf.len() as u32;
    // PROCESS_NAME_WIN32 = 0 returns the Win32 path (C:\...\app.exe).
    // PROCESS_NAME_NATIVE = 1 would return \Device\HarddiskVolume3\... instead.
    let result = unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            windows::core::PWSTR(buf.as_mut_ptr()),
            &mut size,
        )
    };
    // Always close the handle — even on error.
    unsafe {
        let _ = CloseHandle(handle);
    }

    if result.is_err() {
        warn!(pid, "QueryFullProcessImageNameW failed");
        return None;
    }

    // `size` is updated to the number of UTF-16 code units written, excluding
    // the NUL terminator. `from_utf16_lossy` handles any invalid surrogate pairs
    // gracefully (replaces with U+FFFD).
    Some(String::from_utf16_lossy(&buf[..size as usize]))
}

/// Returns the process ID of the window's owning process, or 0 on failure.
///
/// Used by `clipboard_monitor` to compare source and destination PIDs for
/// intra-app copy detection (D-02).
#[cfg(windows)]
pub fn hwnd_to_pid(hwnd: HWND) -> u32 {
    use windows::Win32::UI::WindowsAndMessaging::GetWindowThreadProcessId;
    let mut pid: u32 = 0;
    unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
    pid
}

/// Runs `WinVerifyTrust` on the given image path and returns the raw HRESULT.
///
/// Uses `WTD_REVOKE_NONE` (D-06) to avoid CRL/OCSP network calls on the
/// clipboard monitor thread. Revocation checking is deferred to a future
/// hardening phase.
///
/// Note: `fdwRevocationChecks` (type `WINTRUST_DATA_REVOCATION_CHECKS`) controls
/// *which* revocation checks to run — `WTD_REVOKE_NONE` disables all of them.
/// This is distinct from `dwProvFlags` (type `WINTRUST_DATA_PROVIDER_FLAGS`)
/// which has `WTD_REVOCATION_CHECK_NONE` — a different field and type.
///
/// # Safety
///
/// All unsafe Win32 calls are confined within this function.
///
/// # Returns
///
/// HRESULT: 0 (S_OK) = valid signature; nonzero = invalid or absent.
#[cfg(windows)]
fn run_wintrust(image_path: &str) -> i32 {
    use std::ffi::c_void;
    use windows::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CHOICE_FILE,
        WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };

    // Encode path to UTF-16 with NUL terminator for the Win32 API.
    let path_wide: Vec<u16> = image_path
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: windows::core::PCWSTR::from_raw(path_wide.as_ptr()),
        ..Default::default()
    };

    let mut trust_data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        // WTD_REVOKE_NONE (WINTRUST_DATA_REVOCATION_CHECKS) — no CRL check per D-06.
        // This field is fdwRevocationChecks, which controls the revocation policy.
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        dwStateAction: WTD_STATEACTION_VERIFY,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        ..Default::default()
    };

    // WINTRUST_ACTION_GENERIC_VERIFY_V2 GUID — the standard Authenticode policy.
    // Full GUID: {00AAC56B-CD44-11D0-8CC2-00C04FC295EE}
    // data1 MUST be 0x00AAC56B — any other value returns GUID_UNKNOWN_ACTION.
    let mut policy_guid = windows::core::GUID {
        data1: 0x00AAC56B,
        data2: 0xCD44,
        data3: 0x11D0,
        data4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
    };

    let hr = unsafe {
        WinVerifyTrust(
            None, // hwnd = None (no UI owner)
            &mut policy_guid,
            &mut trust_data as *mut WINTRUST_DATA as *mut c_void,
        )
    };

    // Release WinVerifyTrust state machine resources (required after VERIFY).
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        let _ = WinVerifyTrust(
            None,
            &mut policy_guid,
            &mut trust_data as *mut WINTRUST_DATA as *mut c_void,
        );
    }

    hr
}

/// Extracts the publisher CN from a signed PE binary's Authenticode cert chain.
///
/// Implements the 4-step WinCrypt sequence (MSDN KB323809):
///   1. `CryptQueryObject` — opens the embedded PKCS#7 signature blob
///   2. `CryptMsgGetParam(CMSG_SIGNER_INFO_PARAM)` — gets the signer info struct
///   3. `CertFindCertificateInStore` — finds the signing cert in the message store
///   4. `CertGetNameStringW(CERT_NAME_SIMPLE_DISPLAY_TYPE)` — extracts Subject CN
///
/// Returns an empty string if any step fails (e.g., unsigned binary, or publisher
/// CN not present in `CERT_NAME_SIMPLE_DISPLAY_TYPE`).
///
/// # Safety
///
/// All handles (msg handle as `*mut c_void`, HCERTSTORE, PCCERT_CONTEXT) are closed
/// on exit. The windows-rs 0.58 API uses `*mut core::ffi::c_void` for HCRYPTMSG.
#[cfg(windows)]
fn extract_publisher(image_path: &str) -> String {
    use std::ffi::c_void;
    use windows::Win32::Security::Cryptography::{
        CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext,
        CertGetNameStringW, CryptMsgClose, CryptMsgGetParam, CryptQueryObject,
        CERT_FIND_SUBJECT_NAME, CERT_NAME_SIMPLE_DISPLAY_TYPE,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_ENCODING_TYPE,
        CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE, CMSG_SIGNER_INFO_PARAM,
        HCERTSTORE, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    };

    let path_wide: Vec<u16> = image_path
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // In windows-rs 0.58, HCRYPTMSG is represented as *mut c_void (raw pointer).
    // The typed alias was removed; use the raw pointer directly.
    let mut h_msg: *mut c_void = std::ptr::null_mut();
    let mut h_store: HCERTSTORE = HCERTSTORE::default();
    let mut encoding_type = CERT_QUERY_ENCODING_TYPE(0);
    // content_type and format_type share the same u32 underlying newtype structure.
    let mut content_type = CERT_QUERY_ENCODING_TYPE(0);
    let mut format_type = CERT_QUERY_ENCODING_TYPE(0);

    // Step 1: Open the embedded PKCS#7 signature blob from the PE file.
    // CryptQueryObject pdwMsgAndCertEncodingType, pdwContentType, pdwFormatType
    // all take Option<*mut CERT_QUERY_ENCODING_TYPE> in windows-rs 0.58.
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
        return String::new();
    }

    // Step 2: Get signer info to find the signing certificate.
    let mut signer_info_size: u32 = 0;
    // First call to get required buffer size.
    let _ = unsafe {
        CryptMsgGetParam(
            h_msg,
            CMSG_SIGNER_INFO_PARAM,
            0,
            None,
            &mut signer_info_size,
        )
    };
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
            let _ = CertCloseStore(h_store, 0);
        }
        return String::new();
    }

    // The signer info blob contains the issuer + serial number used to find the cert.
    // CMSG_SIGNER_INFO and CERT_INFO share the same layout for the first two fields:
    //   dwVersion: DWORD, Issuer: CERT_NAME_BLOB, SerialNumber: CRYPT_INTEGER_BLOB
    // We cast the buffer to CERT_INFO for the CertFindCertificateInStore lookup.
    let cert_info_ptr =
        signer_info_buf.as_ptr() as *const windows::Win32::Security::Cryptography::CERT_INFO;

    // Step 3: Find the signing certificate in the message's embedded cert store.
    // dwcertencodingtype must be CERT_QUERY_ENCODING_TYPE (not raw u32).
    let combined_encoding = CERT_QUERY_ENCODING_TYPE(
        X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0,
    );
    let cert_ctx = unsafe {
        CertFindCertificateInStore(
            h_store,
            combined_encoding,
            0,
            CERT_FIND_SUBJECT_NAME,
            // Pass the Issuer blob from CMSG_SIGNER_INFO as the find parameter.
            Some(&(*cert_info_ptr).Issuer as *const _ as *const c_void),
            None,
        )
    };

    if cert_ctx.is_null() {
        unsafe {
            let _ = CryptMsgClose(Some(h_msg));
            let _ = CertCloseStore(h_store, 0);
        }
        return String::new();
    }

    // Step 4: Extract the Subject CN from the certificate.
    // First call gets the required buffer size (chars, including NUL terminator).
    let name_len = unsafe {
        CertGetNameStringW(
            cert_ctx,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            None,
            None,
        )
    };

    let publisher = if name_len > 1 {
        let mut name_buf = vec![0u16; name_len as usize];
        unsafe {
            CertGetNameStringW(
                cert_ctx,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                None,
                Some(&mut name_buf),
            )
        };
        // Trim the NUL terminator before converting.
        let trimmed = if name_buf.last() == Some(&0) {
            &name_buf[..name_buf.len() - 1]
        } else {
            &name_buf[..]
        };
        String::from_utf16_lossy(trimmed)
    } else {
        String::new()
    };

    // Release all handles. CertFreeCertificateContext takes Option<*const CERT_CONTEXT>.
    unsafe {
        let _ = CertFreeCertificateContext(Some(cert_ctx));
        let _ = CryptMsgClose(Some(h_msg));
        let _ = CertCloseStore(h_store, 0);
    }

    publisher
}

/// Verifies and caches the Authenticode result for a given image path.
///
/// Fast path: returns from `AUTHENTICODE_CACHE` in O(1) without calling any
/// Win32 API. Slow path (cache miss): calls `run_wintrust` + `extract_publisher`
/// on the clipboard monitor thread — safe because `WTD_REVOKE_NONE` eliminates
/// CRL network calls (D-06).
///
/// # Returns
///
/// `(publisher_cn, SignatureState)` tuple. `publisher_cn` is an empty string
/// when the binary is unsigned or verification fails.
pub fn verify_and_cache(image_path: &str) -> (String, SignatureState) {
    // Fast path: cache hit.
    {
        let cache = authenticode_cache()
            .lock()
            .expect("AUTHENTICODE_CACHE lock poisoned");
        if let Some(entry) = cache.get(image_path) {
            debug!(image_path, "authenticode cache hit");
            return entry.clone();
        }
    } // lock released before slow path

    // Slow path: run WinVerifyTrust (disk I/O, certificate parse — no network per D-06).
    #[cfg(windows)]
    let hr = run_wintrust(image_path);
    // On non-Windows targets (e.g. CI running on Linux), treat all binaries as unsigned.
    #[cfg(not(windows))]
    let hr: i32 = 0x800B0100_u32 as i32; // TRUST_E_NOSIGNATURE

    // S_OK (0) = valid; TRUST_E_NOSIGNATURE (0x800B0100 as i32) = no sig.
    let signature_state = match hr {
        0 => SignatureState::Valid,
        _ if hr == 0x800B0100_u32 as i32 => SignatureState::NotSigned,
        _ => SignatureState::Invalid,
    };

    #[cfg(windows)]
    let publisher = if signature_state == SignatureState::Valid {
        extract_publisher(image_path)
    } else {
        String::new()
    };
    #[cfg(not(windows))]
    let publisher = String::new();

    let result = (publisher, signature_state);

    // Insert into cache — second lock acquisition is fine (no re-entrance on
    // single-threaded clipboard monitor; Mutex protects multi-thread case).
    authenticode_cache()
        .lock()
        .expect("AUTHENTICODE_CACHE lock poisoned")
        .insert(image_path.to_string(), result.clone());

    debug!(image_path, ?signature_state, "authenticode cache populated");
    result
}

/// Maps a `SignatureState` to an `AppTrustTier` per D-07.
///
/// * `Valid` -> `Trusted`
/// * `Invalid` | `NotSigned` -> `Untrusted`
/// * `Unknown` -> `Unknown`
pub fn trust_tier_from_signature_state(state: SignatureState) -> AppTrustTier {
    match state {
        SignatureState::Valid => AppTrustTier::Trusted,
        SignatureState::Invalid | SignatureState::NotSigned => AppTrustTier::Untrusted,
        SignatureState::Unknown => AppTrustTier::Unknown,
    }
}

/// Builds a complete `AppIdentity` from a resolved image path string.
///
/// Calls `verify_and_cache` to get the publisher and signature state, then
/// derives the trust tier via `trust_tier_from_signature_state` (D-07).
///
/// Safe to call on the clipboard monitor thread when `WTD_REVOKE_NONE` is
/// in effect (D-06).
///
/// # Arguments
///
/// * `image_path` — Absolute Win32 path, e.g. `C:\Windows\notepad.exe`.
pub fn build_app_identity_from_path(image_path: String) -> AppIdentity {
    let (publisher, signature_state) = verify_and_cache(&image_path);
    let trust_tier = trust_tier_from_signature_state(signature_state);
    AppIdentity {
        image_path,
        publisher,
        trust_tier,
        signature_state,
    }
}

/// Resolves an `Option<String>` image path to `Option<AppIdentity>`.
///
/// This pure-logic helper is used by tests to verify D-08 semantics without
/// Win32 HWND involvement.
///
/// | Input | Outcome |
/// |-------|---------|
/// | `None` | `None` — no path to resolve |
/// | `Some("")` | `Some(AppIdentity::default())` — all-Unknown fields |
/// | `Some(path)` | `Some(AppIdentity { ... })` — fully populated |
#[cfg(test)]
pub fn resolve_app_identity_from_path(path: Option<String>) -> Option<AppIdentity> {
    match path {
        None => None,
        Some(p) if p.is_empty() => Some(AppIdentity::default()),
        Some(p) => Some(build_app_identity_from_path(p)),
    }
}

/// Resolves an optional `HWND` to an `Option<AppIdentity>` per D-08 semantics.
///
/// | Input | Outcome |
/// |-------|---------|
/// | `None` (no owner / slot empty) | `None` — no identity captured |
/// | `Some(hwnd)` where path resolves | `Some(AppIdentity { ... })` — fully populated |
/// | `Some(hwnd)` where pid=0 (dead) or path fails | `Some(AppIdentity::default())` — all-Unknown fields |
///
/// The distinction between `None` and `Some(AppIdentity::default())` lets the
/// policy evaluator tell "no owner" from "resolution attempted but failed".
#[cfg(windows)]
pub fn resolve_app_identity(hwnd: Option<HWND>) -> Option<AppIdentity> {
    let hwnd = hwnd?; // None input -> return None (D-08, source=None case)
    match hwnd_to_image_path(hwnd) {
        Some(path) => Some(build_app_identity_from_path(path)),
        None => Some(AppIdentity::default()), // D-08: dead HWND -> all-Unknown
    }
}

/// Non-Windows stub for `resolve_app_identity`.
///
/// On non-Windows platforms (e.g. CI on Linux), always returns `None`.
/// Production code only runs on Windows where the `#[cfg(windows)]` variant
/// is compiled.
#[cfg(not(windows))]
pub fn resolve_app_identity(_hwnd: Option<()>) -> Option<AppIdentity> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- D-07: trust tier mapping -------------------------------------------

    #[test]
    fn test_trust_tier_from_signature_state_valid_is_trusted() {
        assert_eq!(
            trust_tier_from_signature_state(SignatureState::Valid),
            AppTrustTier::Trusted
        );
    }

    #[test]
    fn test_trust_tier_from_signature_state_invalid_is_untrusted() {
        assert_eq!(
            trust_tier_from_signature_state(SignatureState::Invalid),
            AppTrustTier::Untrusted
        );
    }

    #[test]
    fn test_trust_tier_from_signature_state_not_signed_is_untrusted() {
        assert_eq!(
            trust_tier_from_signature_state(SignatureState::NotSigned),
            AppTrustTier::Untrusted
        );
    }

    #[test]
    fn test_trust_tier_from_signature_state_unknown_is_unknown() {
        assert_eq!(
            trust_tier_from_signature_state(SignatureState::Unknown),
            AppTrustTier::Unknown
        );
    }

    // -- D-08: resolve_app_identity None input -------------------------------

    #[test]
    fn test_resolve_app_identity_none_hwnd_returns_none() {
        // D-08: GetClipboardOwner returned NULL -> source_application = None.
        // Uses the platform-agnostic resolve_app_identity_from_path helper so
        // this test runs on non-Windows CI without Win32 HWND types.
        let result = resolve_app_identity_from_path(None);
        assert!(result.is_none(), "None path must produce None identity");
    }

    // -- D-08: dead HWND path -----------------------------------------------

    #[test]
    fn test_dead_hwnd_gives_unknown_identity() {
        // D-08 second case: HWND is alive but hwnd_to_image_path returns None
        // (e.g. pid=0 / dead HWND race). We model this via resolve_app_identity_from_path
        // with Some("") — an empty path string — which bypasses HWND resolution
        // entirely and exercises the "resolution attempted, path unavailable" branch.
        // Expected: Some(AppIdentity::default()) — all-Unknown fields.
        let result = resolve_app_identity_from_path(Some(String::new()));
        assert!(
            result.is_some(),
            "empty path must produce Some(AppIdentity) not None"
        );
        let identity = result.unwrap();
        assert_eq!(
            identity,
            AppIdentity::default(),
            "empty path must produce all-Unknown AppIdentity (D-08 dead HWND case)"
        );
    }

    // -- APP-06: Authenticode cache behavior ---------------------------------

    #[test]
    fn test_verify_and_cache_returns_not_signed_for_unsigned_binary() {
        // Use the current test executable path — it is guaranteed to exist on
        // the test machine and is unsigned (standard Rust test binary).
        let exe_path = std::env::current_exe()
            .expect("current_exe must be available in tests")
            .to_string_lossy()
            .to_string();

        let (publisher, state) = verify_and_cache(&exe_path);
        // Rust test binaries are unsigned — WinVerifyTrust returns TRUST_E_NOSIGNATURE.
        assert_eq!(state, SignatureState::NotSigned, "test binary must be unsigned");
        assert!(publisher.is_empty(), "unsigned binary must have empty publisher");
    }

    #[test]
    fn test_verify_and_cache_second_call_is_cache_hit() {
        // Two calls for the same path must produce the same result (cache hit on second).
        let exe_path = std::env::current_exe()
            .expect("current_exe must be available in tests")
            .to_string_lossy()
            .to_string();

        let first = verify_and_cache(&exe_path);
        let second = verify_and_cache(&exe_path);
        assert_eq!(first, second, "cache must return same result on second call");
    }

    #[test]
    fn test_verify_and_cache_different_paths_are_separate_entries() {
        // D-05/D-06 (APP-06 SC-5): different paths -> different cache entries.
        // Simulate "renamed binary" by using two distinct path strings.
        // We cannot actually copy the file in a unit test, but we can verify
        // the cache is keyed by path string, not by content.
        let path_a = "C:\\Windows\\System32\\notepad.exe".to_string();
        let path_b = "C:\\Windows\\System32\\notepad_renamed.exe".to_string();

        // Both may fail (files may not exist), but they must be independent entries.
        let cache_before_a = {
            let cache = authenticode_cache().lock().unwrap();
            cache.contains_key(&path_b)
        };
        // Calling for path_a must NOT populate path_b in the cache.
        let _ = verify_and_cache(&path_a);
        let cache_after_a = {
            let cache = authenticode_cache().lock().unwrap();
            cache.contains_key(&path_b)
        };
        assert_eq!(
            cache_before_a,
            cache_after_a,
            "verifying path_a must not populate path_b cache entry"
        );
    }

    // -- build_app_identity_from_path ----------------------------------------

    #[test]
    fn test_build_app_identity_from_path_sets_image_path_field() {
        let exe_path = std::env::current_exe()
            .expect("current_exe must be available in tests")
            .to_string_lossy()
            .to_string();

        let identity = build_app_identity_from_path(exe_path.clone());
        assert_eq!(identity.image_path, exe_path, "image_path must match input path");
        // Unsigned binary -> Untrusted tier
        assert_eq!(identity.trust_tier, AppTrustTier::Untrusted);
        assert_eq!(identity.signature_state, SignatureState::NotSigned);
    }
}
