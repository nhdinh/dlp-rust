//! Password-protected service stop (T-38).
//!
//! When the SCM issues a `sc stop` command, the service transitions to
//! `StopPending` and initiates a password challenge over Pipe 1:
//!
//! 1. A `PASSWORD_DIALOG` is sent to the UI.
//! 2. The UI displays a password prompt to the dlp-admin.
//! 3. The UI returns `PASSWORD_SUBMIT` or `PASSWORD_CANCEL`.
//! 4. On `PASSWORD_SUBMIT`: the DPAPI-wrapped blob from the UI is
//!    unwrapped via `CryptUnprotectData`, and the plaintext password is used
//!    to bind to AD as the dlp-admin DN via LDAP simple bind.
//! 5. On 3 failed attempts or `PASSWORD_CANCEL`: log and abort stop.
//! 6. On success: proceed with clean shutdown.
//!
//! The dlp-admin DN is stored in the Windows registry at
//! `HKLM\SOFTWARE\DLP\Agent\Credentials`.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use anyhow::{anyhow, Context, Result};
use parking_lot::Mutex;
use tracing::{error, info, warn};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, HLOCAL, LocalFree, WIN32_ERROR};
use windows::Win32::Security::Cryptography::{
    CryptUnprotectData, CRYPT_INTEGER_BLOB,
};
use windows::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_SZ,
    REG_VALUE_TYPE,
};

use crate::ipc::pipe1::send_password_dialog;

// ─────────────────────────────────────────────────────────────────────────────
// Configuration (stored in registry)
// ─────────────────────────────────────────────────────────────────────────────

/// Registry path where dlp-admin DN is stored.
const REG_KEY_PATH: &str = r"SOFTWARE\DLP\Agent\Credentials";

/// Maximum password attempts before aborting the stop.
const MAX_ATTEMPTS: u32 = 3;

/// Shared password-stop state.
static STOP_STATE: Mutex<StopState> = Mutex::new(StopState {
    pending: false,
    attempts: 0,
});

/// Flag set when a successful stop has been confirmed.
static STOP_CONFIRMED: AtomicBool = AtomicBool::new(false);

/// Number of failed attempts this stop cycle.
static FAILED_ATTEMPTS: AtomicU32 = AtomicU32::new(0);

/// Resolved dlp-admin LDAP DN (read once from registry).
static ADMIN_DN: Mutex<Option<String>> = Mutex::new(None);

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` if the service stop is confirmed (password verified).
pub fn is_stop_confirmed() -> bool {
    STOP_CONFIRMED.load(Ordering::Acquire)
}

/// Resets stop state between stop cycles.
fn reset_stop_state() {
    STOP_CONFIRMED.store(false, Ordering::Release);
    FAILED_ATTEMPTS.store(0, Ordering::SeqCst);
    *STOP_STATE.lock() = StopState {
        pending: false,
        attempts: 0,
    };
}

/// Initiates the password-challenge stop sequence.
///
/// Returns immediately — the actual verification happens asynchronously
/// via [`handle_password_response`](handle_password_submit).
pub fn initiate_stop() {
    let mut state = STOP_STATE.lock();
    if state.pending {
        info!("password stop already in progress");
        return;
    }
    state.pending = true;
    state.attempts = 0;
    drop(state);

    let request_id = uuid::Uuid::new_v4().to_string();
    let request_id_clone = request_id.clone();

    set_pending_request(&request_id);

    std::thread::spawn(move || {
        info!(
            request_id = request_id_clone,
            "sending PASSWORD_DIALOG to UI"
        );
        if let Err(e) = send_password_dialog(&request_id_clone) {
            error!(error = %e, "failed to send PASSWORD_DIALOG — aborting stop");
            cancel_stop();
        }
    });
}

/// Handles a `PASSWORD_CANCEL` response from the UI.
pub fn handle_password_cancel(request_id: &str) {
    if !matches_pending_request(request_id) {
        warn!(request_id, "PASSWORD_CANCEL: stale or unknown request_id");
        return;
    }
    clear_pending_request();
    warn!("dlp-admin cancelled password dialog — aborting service stop");
    reset_stop_state();
}

/// Handles a `PASSWORD_SUBMIT` response from the UI.
pub fn handle_password_submit(request_id: &str, password: String) {
    if !matches_pending_request(request_id) {
        warn!(request_id, "PASSWORD_SUBMIT: stale or unknown request_id");
        return;
    }

    let attempt = FAILED_ATTEMPTS.fetch_add(1, Ordering::AcqRel) + 1;

    match verify_credentials(&password) {
        Ok(true) => {
            info!("dlp-admin password verified — proceeding with stop");
            STOP_CONFIRMED.store(true, Ordering::Release);
            clear_pending_request();
            reset_stop_state();
            confirm_stop();
        }
        Ok(false) => {
            warn!(attempt, max = MAX_ATTEMPTS, "incorrect dlp-admin password");
            if attempt >= MAX_ATTEMPTS {
                log_failure(attempt);
                abort_stop();
            }
        }
        Err(e) => {
            error!(error = %e, "LDAP bind failed");
            if attempt >= MAX_ATTEMPTS {
                log_failure(attempt);
                abort_stop();
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Registry access
// ─────────────────────────────────────────────────────────────────────────────

/// Reads a REG_SZ string value from `HKLM\{subkey}\{name}`.
fn read_registry_string(subkey: &str, name: &str) -> Result<String> {
    unsafe {
        let mut hkey: HKEY = HKEY::default();
        let subkey_wide: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();

        let result = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR::from_raw(subkey_wide.as_ptr()),
            0,
            KEY_READ,
            &mut hkey,
        );

        if result == ERROR_FILE_NOT_FOUND {
            return Err(anyhow!("registry key not found: HKLM\\{}", subkey));
        }
        if result != WIN32_ERROR(0) {
            return Err(anyhow!("RegOpenKeyExW failed: {}", result.0));
        }

        let name_wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

        // Query the required buffer size.
        let mut data_size = 0u32;
        let mut value_type = REG_VALUE_TYPE::default();
        let size_result = RegQueryValueExW(
            hkey,
            PCWSTR::from_raw(name_wide.as_ptr()),
            None,
            Some(std::ptr::null_mut()),
            None,
            Some(&mut data_size),
        );

        if size_result != WIN32_ERROR(0) {
            let _ = RegCloseKey(hkey);
            return Err(anyhow!(
                "RegQueryValueExW (size query) failed: {}",
                size_result.0
            ));
        }

        if data_size == 0 {
            let _ = RegCloseKey(hkey);
            return Ok(String::new());
        }

        // Allocate buffer (size includes null terminator for REG_SZ).
        let mut data = vec![0u8; data_size as usize];

        let result = RegQueryValueExW(
            hkey,
            PCWSTR::from_raw(name_wide.as_ptr()),
            None,
            Some(&mut value_type),
            Some(data.as_mut_ptr()),
            Some(&mut data_size),
        );

        let _ = RegCloseKey(hkey);

        if result != WIN32_ERROR(0) {
            return Err(anyhow!("RegQueryValueExW failed: {}", result.0));
        }

        if value_type.0 != REG_SZ.0 {
            return Err(anyhow!(
                "unexpected registry type {} for {} (expected REG_SZ)",
                value_type.0,
                name
            ));
        }

        // Data is UTF-16 LE, null-terminated.
        let wide: &[u16] =
            std::slice::from_raw_parts(data.as_ptr() as *const u16, (data_size as usize) / 2);
        Ok(String::from_utf16_lossy(wide)
            .trim_end_matches('\0')
            .to_string())
    }
}

/// Returns the dlp-admin LDAP DN from registry (cached after first call).
pub fn get_admin_dn() -> Result<String> {
    {
        let guard = ADMIN_DN.lock();
        if let Some(ref dn) = *guard {
            return Ok(dn.clone());
        }
    }

    let dn = read_registry_string(REG_KEY_PATH, "AdminDN")?;
    let mut guard = ADMIN_DN.lock();
    *guard = Some(dn.clone());
    Ok(dn)
}

// ─────────────────────────────────────────────────────────────────────────────
// DPAPI unprotect
// ─────────────────────────────────────────────────────────────────────────────

/// Decrypts a DPAPI-protected blob (`CryptUnprotectData`).
///
/// The UI side wrapped the password with `CryptProtectData`; the agent must
/// unwrap it before passing the plaintext to LDAP.  This closes the security
/// gap where the DPAPI protection was bypassed by sending the raw blob to LDAP.
///
/// Returns the plaintext password as a UTF-16 `Vec<u16>` (matching the format
/// used by the UI dialog's `GetWindowTextW`).
fn dpapi_unprotect(protected: &[u8]) -> anyhow::Result<Vec<u16>> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: protected.len() as u32,
        pbData: protected.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    // SAFETY: CryptUnprotectData reads the input blob and writes the output blob.
    // The output buffer is allocated by the function and must be freed via LocalFree.
    unsafe {
        CryptUnprotectData(
            &input,
            None,
            None,
            None,
            None,
            0,
            &mut output,
        )
        .ok()
        .map_err(|e| anyhow::anyhow!("CryptUnprotectData failed: {}", e))?;

        let plaintext = std::slice::from_raw_parts(output.pbData, output.cbData as usize)
            .to_vec();
        let _ = LocalFree(HLOCAL(output.pbData as *mut _));
        Ok(plaintext)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Base64 decode (no external dep)
// ─────────────────────────────────────────────────────────────────────────────

/// Decodes a base64 string into bytes.  Used to decode the DPAPI blob received
/// from the UI before passing it to `dpapi_unprotect`.
fn base64_decode(input: &str) -> anyhow::Result<Vec<u8>> {
    const DECODE_TABLE: [i8; 256] = {
        let mut table = [-1i8; 256];
        let b64 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut i = 0u8;
        while i < 64 {
            table[b64[i] as usize] = i as i8;
            i += 1;
        }
        table
    };

    // Remove whitespace.
    let filtered: Vec<u8> = input
        .bytes()
        .filter(|&b| b != b' ' && b != b'\n' && b != b'\r' && b != b'\t')
        .collect();

    let mut out = Vec::with_capacity(filtered.len() / 4 * 3);
    let chunks: Vec<&[u8]> = filtered.chunks(4).collect();

    for chunk in chunks {
        let mut buf = [0u8; 4];
        for (i, &b) in chunk.iter().enumerate() {
            if b == b'=' {
                buf[i] = 0;
            } else {
                let v = DECODE_TABLE[b as usize];
                if v < 0 {
                    return Err(anyhow::anyhow!("invalid base64 character: {:?}", b as char));
                }
                buf[i] = v as u8;
            }
        }

        out.push((buf[0] << 2) | (buf[1] >> 4));
        if chunk.len() > 2 && chunk[2] != b'=' {
            out.push((buf[1] << 4) | (buf[2] >> 2));
        }
        if chunk.len() > 3 && chunk[3] != b'=' {
            out.push((buf[2] << 6) | buf[3]);
        }
    }

    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// LDAP verification
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies the dlp-admin password received from the UI.
///
/// The UI sends a DPAPI-protected, base64-encoded blob.  This function:
/// 1. Base64-decodes the blob.
/// 2. Calls `CryptUnprotectData` to recover the plaintext password.
/// 3. Converts the plaintext UTF-16 bytes to a UTF-8 string.
/// 4. Performs an LDAP simple bind to verify the credentials.
///
/// Returns `Ok(true)` on successful bind, `Ok(false)` on invalid credentials,
/// and `Err(...)` on a connection, decoding, or DPAPI error.
fn verify_credentials(password_b64: &str) -> Result<bool> {
    use ldap3::LdapConn;

    // Step 1: Base64-decode the DPAPI blob.
    let protected_bytes = base64_decode(password_b64)
        .context("base64 decode of DPAPI blob from UI")?;

    // Step 2: DPAPI-unprotect to recover UTF-16 password bytes.
    let password_utf16 = dpapi_unprotect(&protected_bytes)
        .context("CryptUnprotectData failed")?;

    // Step 3: Convert UTF-16 LE to UTF-8 string (passwords are ASCII/Latin-1 compatible).
    let password = String::from_utf16_lossy(&password_utf16);

    // Step 4: LDAP simple bind.
    let admin_dn = get_admin_dn().context("get dlp-admin DN")?;
    let ldap_url =
        std::env::var("DLP_LDAP_URL").unwrap_or_else(|_| "ldaps://localhost:636".to_string());

    let mut ldap =
        LdapConn::new(&ldap_url).with_context(|| format!("invalid LDAP URL: {}", ldap_url))?;

    let result = ldap.simple_bind(&admin_dn, &password);

    match result {
        Ok(res) if res.rc == 0 => Ok(true),
        Ok(res) => {
            warn!(rc = res.rc, "LDAP bind failed — invalid credentials");
            Ok(false)
        }
        Err(e) => Err(anyhow::anyhow!("LDAP bind error: {}", e)),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pending request tracking
// ─────────────────────────────────────────────────────────────────────────────

struct StopState {
    pending: bool,
    attempts: u32,
}

/// The currently pending password request ID.
static PENDING_REQUEST: Mutex<Option<String>> = Mutex::new(None);

fn set_pending_request(id: &str) {
    *PENDING_REQUEST.lock() = Some(id.to_string());
}

fn matches_pending_request(id: &str) -> bool {
    PENDING_REQUEST
        .lock()
        .as_ref()
        .is_some_and(|current| current == id)
}

fn clear_pending_request() {
    *PENDING_REQUEST.lock() = None;
}

// ─────────────────────────────────────────────────────────────────────────────
// Stop signalling
// ─────────────────────────────────────────────────────────────────────────────

/// Confirmed password — signal the service run loop to proceed with shutdown.
fn confirm_stop() {
    // The service run loop polls is_stop_confirmed() every 500 ms.
    // No additional channel needed — the atomic flag is sufficient.
    info!("dlp-admin stop confirmed");
}

/// Aborts the stop sequence and returns the service to Running state.
fn abort_stop() {
    error!(
        "EVENT_DLP_ADMIN_STOP_FAILED: max password attempts exceeded — \
         aborting service stop"
    );
    clear_pending_request();
    reset_stop_state();
    crate::service::revert_stop();
}

fn cancel_stop() {
    clear_pending_request();
    reset_stop_state();
    crate::service::revert_stop();
}

/// Logs a failed stop attempt.
fn log_failure(attempt: u32) {
    error!(
        event_id = "EVENT_DLP_ADMIN_STOP_FAILED",
        attempt, "dlp-admin stop failed after {} attempts", attempt
    );
}
