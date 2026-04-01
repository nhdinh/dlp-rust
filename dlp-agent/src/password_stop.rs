//! Password-protected service stop (T-38).
//!
//! When the SCM issues a `sc stop` command, the service transitions to
//! `StopPending` and initiates a password challenge over Pipe 1:
//!
//! 1. A `PASSWORD_DIALOG` is sent to the UI.
//! 2. The UI displays a password prompt to the dlp-admin.
//! 3. The UI returns `PASSWORD_SUBMIT` or `PASSWORD_CANCEL`.
//! 4. On `PASSWORD_SUBMIT`: bind to AD as dlp-admin DN, verify credentials
//!    via LDAP simple bind.
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
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, WIN32_ERROR};
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
// LDAP verification
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies the dlp-admin password by performing an LDAP simple bind.
///
/// `LdapConn::new()` creates its own internal tokio runtime and manages
/// the connection synchronously — no explicit thread spawning needed.
///
/// Returns `Ok(true)` on successful bind, `Ok(false)` on invalid credentials,
/// and `Err(...)` on a connection or protocol error.
fn verify_credentials(password: &str) -> Result<bool> {
    use ldap3::LdapConn;

    let admin_dn = get_admin_dn().context("get dlp-admin DN")?;
    let ldap_url =
        std::env::var("DLP_LDAP_URL").unwrap_or_else(|_| "ldaps://localhost:636".to_string());

    let mut ldap =
        LdapConn::new(&ldap_url).with_context(|| format!("invalid LDAP URL: {}", ldap_url))?;

    let result = ldap.simple_bind(&admin_dn, password);

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
