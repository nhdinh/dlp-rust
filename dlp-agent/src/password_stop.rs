//! Password-protected service stop (T-38).
//!
//! When the SCM issues a `sc stop` command, the service transitions to
//! `StopPending` and initiates a password challenge over Pipe 1:
//!
//! 1. A `PASSWORD_DIALOG` is sent to the UI.
//! 2. The UI displays a password prompt to the dlp-admin.
//! 3. The UI returns `PASSWORD_SUBMIT` or `PASSWORD_CANCEL`.
//! 4. On `PASSWORD_SUBMIT`: the DPAPI-wrapped blob from the UI is
//!    unwrapped via `CryptUnprotectData`, and the plaintext password is
//!    verified against the bcrypt hash stored in the registry.
//! 5. On 3 failed attempts or `PASSWORD_CANCEL`: log and abort stop.
//! 6. On success: proceed with clean shutdown.
//!
//! ## dlp-admin is not an Active Directory account
//!
//! `dlp-admin` is a DLP superuser credential that is independent of Windows
//! and Active Directory.  It has no SID, no AD group membership, and cannot
//! authenticate to AD.  All AD identity management remains the responsibility
//! of Windows/AD for normal users.
//!
//! ## Credential storage
//!
//! The bcrypt hash of the dlp-admin password is managed centrally by
//! dlp-server. On startup and periodically, the agent fetches the hash
//! via `GET /agent-credentials/auth-hash` and caches it locally:
//!
//! - **In-memory**: the `AUTH_HASH` static (fastest, process lifetime).
//! - **Registry**: `HKLM\SOFTWARE\DLP\Agent\Credentials\DLPAuthHash`
//!   (offline fallback across restarts).
//!
//! If the server is unreachable, the agent falls back to the registry.
//! The plaintext password is never stored.  Setting or changing the password
//! is done via `dlp-admin-cli set-password`, which pushes the hash to the
//! server.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use anyhow::{anyhow, Context, Result};
use parking_lot::Mutex;
use std::io::Write;
use tracing::{error, info, warn};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{LocalFree, ERROR_FILE_NOT_FOUND, HLOCAL, WIN32_ERROR};
use windows::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};
use windows::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_SZ,
    REG_VALUE_TYPE,
};

// ─────────────────────────────────────────────────────────────────────────────
// Configuration (stored in registry)
// ─────────────────────────────────────────────────────────────────────────────

/// Registry path where dlp-admin password hash is stored.
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

/// Cached bcrypt hash of the dlp-admin password.
static AUTH_HASH: Mutex<Option<String>> = Mutex::new(None);

/// Global reference to the server client for on-demand hash fetching.
static SERVER_CLIENT: Mutex<Option<crate::server_client::ServerClient>> = Mutex::new(None);

/// Stores the server client so `get_auth_hash` can fetch on demand.
///
/// Called once during agent startup after the `ServerClient` is created.
pub fn set_server_client(sc: crate::server_client::ServerClient) {
    *SERVER_CLIENT.lock() = Some(sc);
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` if the service stop is confirmed (password verified).
pub fn is_stop_confirmed() -> bool {
    STOP_CONFIRMED.load(Ordering::Acquire)
}

/// Immediately confirms the stop without password verification.
///
/// Used in debug builds (`cfg(debug_assertions)`) to allow `sc stop`
/// without an AD server.  Never compiled into release binaries.
pub fn confirm_stop_immediate() {
    info!("stop confirmed without password (debug mode)");
    STOP_CONFIRMED.store(true, Ordering::Release);
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

/// Writes a diagnostic line to `C:\ProgramData\DLP\logs\stop-debug.log`.
///
/// Used to diagnose password-stop issues since the service runs in Session 0
/// where tracing output is invisible.
pub fn debug_log(msg: &str) {
    let _ = std::fs::create_dir_all(r"C:\ProgramData\DLP\logs");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(r"C:\ProgramData\DLP\logs\stop-debug.log")
    {
        let now = chrono::Local::now().format("%H:%M:%S%.3f");
        let _ = writeln!(f, "[{now}] {msg}");
    }
}

/// Maximum time (seconds) the password stop can remain pending before
/// aborting automatically (guards against the service staying in
/// StopPending forever if the UI never responds).
const STOP_TIMEOUT_SECS: u64 = 120;

/// Initiates the password-challenge stop sequence.
///
/// Spawns a background thread that:
/// 1. Tries to send PASSWORD_DIALOG to an already-connected UI.
/// 2. If no UI is connected, spawns one in the active console session
///    and waits up to [`UI_CONNECT_TIMEOUT_SECS`] for it to connect.
/// 3. Retries sending PASSWORD_DIALOG.
/// 4. If still no UI, aborts the stop.
///
/// The actual password verification happens asynchronously via
/// [`handle_password_submit`].
pub fn initiate_stop() {
    let mut state = STOP_STATE.lock();
    if state.pending {
        info!("password stop already in progress");
        return;
    }
    state.pending = true;
    state.attempts = 0;
    drop(state);

    // Clear the cached hash so the next verification re-fetches the
    // latest value from the server (handles late password setup).
    *AUTH_HASH.lock() = None;

    let request_id = uuid::Uuid::new_v4().to_string();
    set_pending_request(&request_id);

    std::thread::spawn(move || {
        debug_log("=== initiate_stop START ===");
        info!(request_id, "initiating password-protected stop");

        // Build the response file path.  The spawned UI writes its result
        // here instead of going through Pipe 1 (which deadlocks because
        // synchronous ReadFile/WriteFile on the same handle are serialised).
        let response_path = format!(r"C:\ProgramData\DLP\logs\stop-response-{}.json", request_id);
        let _ = std::fs::create_dir_all(r"C:\ProgramData\DLP\logs");
        // Remove any stale response file.
        let _ = std::fs::remove_file(&response_path);

        // Step 1: spawn a lightweight stop-password UI in the active session.
        debug_log(&format!(
            "step 1: spawning stop-password UI (request_id={request_id})"
        ));
        if !try_spawn_password_ui(&request_id, &response_path) {
            debug_log("step 1: FAILED to spawn UI — aborting stop");
            error!("failed to spawn password UI — aborting stop");
            cancel_stop();
            return;
        }
        debug_log("step 1: UI process created successfully");

        // Step 2: poll the response file.
        debug_log("step 2: polling for response file...");
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(STOP_TIMEOUT_SECS);
        loop {
            std::thread::sleep(std::time::Duration::from_millis(500));

            if let Ok(data) = std::fs::read_to_string(&response_path) {
                debug_log(&format!(
                    "step 2: response file found ({} bytes)",
                    data.len()
                ));
                let _ = std::fs::remove_file(&response_path);
                handle_file_response(&request_id, &data);
                return;
            }

            if std::time::Instant::now() >= deadline {
                debug_log(&format!(
                    "step 2: TIMEOUT after {}s — aborting stop",
                    STOP_TIMEOUT_SECS
                ));
                error!("password stop timed out after {}s", STOP_TIMEOUT_SECS);
                let _ = std::fs::remove_file(&response_path);
                abort_stop();
                return;
            }
        }
    });
}

/// Spawns a lightweight `dlp-user-ui --stop-password <request_id>` process
/// in the active console session.
///
/// This mode skips all iced/tray initialization — it only shows the password
/// dialog, sends the result over Pipe 1, and exits.
///
/// Returns `true` if the process was successfully created.
/// Handles the JSON response written by the stop-password UI process.
///
/// Expected format:
/// - `{"result":"submit","password":"<dpapi_base64>"}` → verify credentials
/// - `{"result":"cancel"}` → abort stop
fn handle_file_response(request_id: &str, data: &str) {
    #[derive(serde::Deserialize)]
    struct StopResponse {
        result: String,
        #[serde(default)]
        password: Option<String>,
        /// `"base64-utf8"` = plaintext password base64-encoded (no DPAPI).
        /// `None` / absent = legacy DPAPI-wrapped blob.
        #[serde(default)]
        encoding: Option<String>,
    }

    match serde_json::from_str::<StopResponse>(data) {
        Ok(resp) if resp.result == "submit" => {
            if let Some(password) = resp.password {
                let is_plaintext = resp.encoding.as_deref() == Some("base64-utf8");
                debug_log(&format!(
                    "handle_file_response: PasswordSubmit received (encoding={:?})",
                    resp.encoding.as_deref().unwrap_or("dpapi")
                ));
                handle_password_submit(request_id, password, is_plaintext);
            } else {
                debug_log("handle_file_response: submit with no password — treating as cancel");
                handle_password_cancel(request_id);
            }
        }
        Ok(_) => {
            debug_log("handle_file_response: PasswordCancel received");
            handle_password_cancel(request_id);
        }
        Err(e) => {
            debug_log(&format!("handle_file_response: parse error: {e}"));
            error!(error = %e, "failed to parse stop response");
            handle_password_cancel(request_id);
        }
    }
}

fn try_spawn_password_ui(request_id: &str, response_path: &str) -> bool {
    let binary = match crate::ui_spawner::ui_binary() {
        Some(b) => b,
        None => {
            debug_log("try_spawn: UI binary path not configured");
            error!("UI binary path not configured");
            return false;
        }
    };

    debug_log(&format!("try_spawn: binary = {}", binary.display()));

    // Check binary exists.
    if !binary.exists() {
        debug_log(&format!(
            "try_spawn: binary does NOT exist at {}",
            binary.display()
        ));
        error!(path = %binary.display(), "UI binary not found");
        return false;
    }

    // Find the active console session.
    let sessions = match crate::ui_spawner::enumerate_active_sessions_pub() {
        Ok(s) => s,
        Err(e) => {
            debug_log(&format!("try_spawn: enumerate sessions failed: {e}"));
            error!(error = %e, "failed to enumerate sessions");
            return false;
        }
    };

    debug_log(&format!("try_spawn: active sessions = {sessions:?}"));

    // Build command line: "dlp-user-ui.exe" --stop-password <request_id> <response_path>
    let cmd = format!(
        "\"{}\" --stop-password {} \"{}\"",
        binary.display(),
        request_id,
        response_path,
    );

    debug_log(&format!("try_spawn: cmd = {cmd}"));

    // Try each active session (skip session 0).
    for session_id in sessions {
        if session_id == 0 {
            continue;
        }
        debug_log(&format!("try_spawn: attempting session {session_id}"));
        match spawn_process_in_session(session_id, &cmd) {
            Ok(pid) => {
                debug_log(&format!(
                    "try_spawn: SUCCESS pid={pid} session={session_id}"
                ));
                info!(session_id, pid, "spawned stop-password UI");
                return true;
            }
            Err(e) => {
                debug_log(&format!("try_spawn: FAILED session {session_id}: {e}"));
                warn!(session_id, error = %e, "failed to spawn stop-password UI");
            }
        }
    }

    debug_log("try_spawn: all sessions failed");
    false
}

/// Spawns a process with the given command line in the specified session
/// using `CreateProcessAsUserW`.
fn spawn_process_in_session(session_id: u32, cmd: &str) -> Result<u32> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::RemoteDesktop::WTSQueryUserToken;
    use windows::Win32::System::Threading::{
        CreateProcessAsUserW, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW,
    };

    if session_id == 0 {
        anyhow::bail!("session 0 has no interactive desktop");
    }

    // Get user token for the session.
    let mut token = HANDLE::default();
    unsafe {
        WTSQueryUserToken(session_id, &mut token)
            .ok()
            .ok_or_else(|| anyhow::anyhow!("WTSQueryUserToken failed for session {session_id}"))?;
    }

    // Build wide command line (must be mutable for CreateProcessAsUserW).
    let mut cmd_wide: Vec<u16> = std::ffi::OsStr::new(cmd)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // Target the interactive desktop.
    let desktop: Vec<u16> = "WinSta0\\Default\0".encode_utf16().collect();

    let startup_info = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        lpDesktop: windows::core::PWSTR::from_raw(desktop.as_ptr() as _),
        ..Default::default()
    };

    let mut proc_info = PROCESS_INFORMATION::default();

    unsafe {
        let result = CreateProcessAsUserW(
            token,
            PCWSTR::null(),
            windows::core::PWSTR::from_raw(cmd_wide.as_mut_ptr()),
            None,
            None,
            false,
            PROCESS_CREATION_FLAGS(0),
            None,
            PCWSTR::null(),
            &startup_info,
            &mut proc_info,
        );

        let _ = CloseHandle(token);

        if result.is_err() {
            return Err(anyhow::anyhow!(
                "CreateProcessAsUserW failed for session {session_id}"
            ));
        }

        let _ = CloseHandle(proc_info.hThread);
        let _ = CloseHandle(proc_info.hProcess);

        Ok(proc_info.dwProcessId)
    }
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
pub fn handle_password_submit(request_id: &str, password: String, is_plaintext: bool) {
    if !matches_pending_request(request_id) {
        warn!(request_id, "PASSWORD_SUBMIT: stale or unknown request_id");
        return;
    }

    let attempt = FAILED_ATTEMPTS.fetch_add(1, Ordering::AcqRel) + 1;

    debug_log(&format!(
        "handle_password_submit: verifying (attempt {attempt})"
    ));
    let result = if is_plaintext {
        verify_credentials_plaintext(&password)
    } else {
        verify_credentials_dpapi(&password)
    };
    match result {
        Ok(true) => {
            debug_log("handle_password_submit: password CORRECT — confirming stop");
            info!("dlp-admin password verified — proceeding with stop");
            // Clear pending state but do NOT call reset_stop_state() —
            // that would reset STOP_CONFIRMED back to false before the
            // main loop polls it.
            clear_pending_request();
            FAILED_ATTEMPTS.store(0, Ordering::SeqCst);
            STOP_CONFIRMED.store(true, Ordering::Release);
            confirm_stop();
        }
        Ok(false) => {
            debug_log(&format!(
                "handle_password_submit: password INCORRECT (attempt {attempt}/{MAX_ATTEMPTS})"
            ));
            warn!(attempt, max = MAX_ATTEMPTS, "incorrect dlp-admin password");
            if attempt >= MAX_ATTEMPTS {
                log_failure(attempt);
                abort_stop();
            }
        }
        Err(e) => {
            debug_log(&format!("handle_password_submit: ERROR: {e}"));
            error!(error = %e, "password verification failed");
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

/// Returns the bcrypt hash of the agent password.
///
/// Resolution order:
/// 1. In-memory cache (fastest).
/// 2. On-demand fetch from dlp-server (always up-to-date).
/// 3. Local registry fallback (offline resilience).
///
/// The result is cached in memory so subsequent calls within the same
/// stop cycle are fast.
pub fn get_auth_hash() -> Result<String> {
    // 1. Check in-memory cache.
    {
        let guard = AUTH_HASH.lock();
        if let Some(ref hash) = *guard {
            return Ok(hash.clone());
        }
    }

    // 2. Try fetching from the server (on-demand, handles late password setup).
    if let Some(hash) = try_fetch_hash_from_server() {
        let mut guard = AUTH_HASH.lock();
        *guard = Some(hash.clone());
        // Best-effort: update the registry cache for offline use.
        if let Err(e) = write_registry_auth_hash(&hash) {
            warn!(error = %e, "failed to cache auth hash in local registry");
        }
        return Ok(hash);
    }

    // 3. Fall back to the local registry.
    let hash = read_registry_string(REG_KEY_PATH, "DLPAuthHash").context(
        "agent password hash not found. \
                  Set it via dlp-admin-cli or ensure dlp-server is reachable.",
    )?;
    let hash = hash.trim().to_string();
    if hash.is_empty() {
        anyhow::bail!(
            "agent password hash is empty. \
             Set it via dlp-admin-cli or ensure dlp-server is reachable."
        );
    }
    let mut guard = AUTH_HASH.lock();
    *guard = Some(hash.clone());
    Ok(hash)
}

/// Attempts a blocking fetch of the auth hash from dlp-server.
///
/// Returns `None` if the server is unreachable or no hash is stored.
/// This is called synchronously so it builds a one-shot tokio runtime.
fn try_fetch_hash_from_server() -> Option<String> {
    let sc = {
        let guard = SERVER_CLIENT.lock();
        guard.clone()?
    };

    // Build a one-shot runtime for this blocking call.
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            warn!(error = %e, "failed to create runtime for hash fetch");
            return None;
        }
    };

    match rt.block_on(sc.fetch_auth_hash()) {
        Ok(hash) => {
            info!("fetched auth hash from server on demand");
            Some(hash)
        }
        Err(e) => {
            warn!(error = %e, "on-demand hash fetch from server failed");
            None
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Server-managed auth hash sync
// ─────────────────────────────────────────────────────────────────────────────

/// Syncs the agent auth hash from dlp-server.
///
/// Fetches the bcrypt hash from `GET /agent-credentials/auth-hash`, then:
/// - Stores it in the in-memory cache (`AUTH_HASH`).
/// - Writes it to the local registry as an offline fallback.
///
/// If the server is unreachable or returns 404, falls back silently to
/// whatever is in the registry.
pub async fn sync_auth_hash_from_server(sc: &crate::server_client::ServerClient) {
    match sc.fetch_auth_hash().await {
        Ok(hash) => {
            // Update the in-memory cache.
            {
                let mut guard = AUTH_HASH.lock();
                *guard = Some(hash.clone());
            }

            // Best-effort: cache in local registry for offline use.
            if let Err(e) = write_registry_auth_hash(&hash) {
                warn!(error = %e, "failed to cache auth hash in local registry");
            }

            info!("agent auth hash synced from server");
        }
        Err(e) => {
            warn!(
                error = %e,
                "could not fetch auth hash from server -- using local registry"
            );
        }
    }
}

/// Writes the bcrypt hash to the local registry as a cached fallback.
///
/// Creates the registry key if it does not exist.
fn write_registry_auth_hash(hash: &str) -> Result<()> {
    use windows::Win32::System::Registry::{
        RegCreateKeyExW, RegSetValueExW, KEY_WRITE, REG_OPTION_NON_VOLATILE,
    };

    unsafe {
        let subkey_wide: Vec<u16> = REG_KEY_PATH
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let name_wide: Vec<u16> = "DLPAuthHash"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let value_wide: Vec<u16> = hash.encode_utf16().chain(std::iter::once(0)).collect();
        let value_bytes: &[u8] =
            std::slice::from_raw_parts(value_wide.as_ptr().cast(), value_wide.len() * 2);

        let mut hkey = HKEY::default();
        let result = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR::from_raw(subkey_wide.as_ptr()),
            0,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        );
        if result.is_err() {
            return Err(anyhow!(
                "RegCreateKeyExW failed for HKLM\\{}: {:?}",
                REG_KEY_PATH,
                result
            ));
        }

        let result = RegSetValueExW(
            hkey,
            PCWSTR::from_raw(name_wide.as_ptr()),
            0,
            REG_SZ,
            Some(value_bytes),
        );
        let _ = RegCloseKey(hkey);

        if result.is_err() {
            return Err(anyhow!(
                "RegSetValueExW failed for DLPAuthHash: {:?}",
                result
            ));
        }

        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DPAPI unprotect
// ─────────────────────────────────────────────────────────────────────────────

/// Decrypts a DPAPI-protected blob (`CryptUnprotectData`).
///
/// The UI side wrapped the password with `CryptProtectData`; the agent must
/// unwrap it before passing the plaintext to bcrypt for verification.
///
/// Returns the plaintext password as a `Vec<u8>` (UTF-8 bytes).
fn dpapi_unprotect(protected: &[u8]) -> anyhow::Result<Vec<u8>> {
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
        CryptUnprotectData(&input, None, None, None, None, 0, &mut output)
            .ok()
            .context("CryptUnprotectData failed")?;

        let plaintext = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = LocalFree(HLOCAL(output.pbData as *mut _));
        Ok(plaintext)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Base64 decode (no external dep)
// ─────────────────────────────────────────────────────────────────────────────

/// Lookup table mapping ASCII byte values to their 6-bit base64 index.
/// Invalid characters are represented as `-1`.
const BASE64_DECODE_TABLE: [i8; 256] = {
    let mut table = [-1i8; 256];
    let b64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut i = 0u8;
    while i < 64 {
        table[b64[i as usize] as usize] = i as i8;
        i += 1;
    }
    table
};

/// Decodes a single base64 chunk (up to 4 bytes) into its 6-bit values.
///
/// Padding characters (`=`) are decoded as 0.  Returns `Err` if a non-padding
/// byte is not a valid base64 character.
fn decode_base64_chunk(chunk: &[u8]) -> anyhow::Result<[u8; 4]> {
    let mut buf = [0u8; 4];
    for (i, &b) in chunk.iter().enumerate() {
        if b == b'=' {
            continue; // buf[i] is already 0
        }
        let v = BASE64_DECODE_TABLE[b as usize];
        if v < 0 {
            return Err(anyhow::anyhow!("invalid base64 character: {:?}", b as char));
        }
        buf[i] = v as u8;
    }
    Ok(buf)
}

/// Emits 1-3 decoded bytes from a base64 chunk, respecting padding.
///
/// A full 4-byte chunk with no padding yields 3 output bytes. Trailing `=`
/// padding reduces the count.
fn emit_decoded_bytes(chunk: &[u8], buf: &[u8; 4], out: &mut Vec<u8>) {
    out.push((buf[0] << 2) | (buf[1] >> 4));
    if chunk.len() > 2 && chunk[2] != b'=' {
        out.push((buf[1] << 4) | (buf[2] >> 2));
    }
    if chunk.len() > 3 && chunk[3] != b'=' {
        out.push((buf[2] << 6) | buf[3]);
    }
}

/// Decodes a base64 string into bytes.  Used to decode the DPAPI blob received
/// from the UI before passing it to `dpapi_unprotect`.
fn base64_decode(input: &str) -> anyhow::Result<Vec<u8>> {
    // Remove whitespace.
    let filtered: Vec<u8> = input
        .bytes()
        .filter(|&b| !b.is_ascii_whitespace())
        .collect();

    let mut out = Vec::with_capacity(filtered.len() / 4 * 3);

    for chunk in filtered.chunks(4) {
        let buf = decode_base64_chunk(chunk)?;
        emit_decoded_bytes(chunk, &buf, &mut out);
    }

    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// Password verification
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies the dlp-admin password received from the UI.
///
/// The UI sends a DPAPI-protected, base64-encoded blob.  This function:
/// 1. Base64-decodes the blob.
/// 2. Calls `CryptUnprotectData` to recover the plaintext password.
/// 3. Converts the plaintext bytes to a UTF-8 string.
/// 4. Verifies the plaintext against the stored bcrypt hash.
///
/// Returns `Ok(true)` on successful match, `Ok(false)` on wrong password,
/// and `Err(...)` on a decoding, DPAPI, or bcrypt error.
/// Verifies a plaintext password (base64-encoded UTF-8, no DPAPI).
///
/// Used by the file-based stop flow where the UI and agent run under
/// different user contexts (user session vs SYSTEM).
fn verify_credentials_plaintext(password_b64: &str) -> Result<bool> {
    debug_log("verify_plaintext: step 1 — base64 decode");
    let password_bytes =
        base64_decode(password_b64).context("base64 decode of plaintext password")?;
    debug_log(&format!(
        "verify_plaintext: step 1 OK — {} bytes",
        password_bytes.len()
    ));

    let password = String::from_utf8_lossy(&password_bytes).into_owned();
    debug_log(&format!(
        "verify_plaintext: step 2 — password length = {} chars",
        password.len()
    ));

    bcrypt_verify_against_server(&password)
}

/// Verifies a DPAPI-wrapped password (legacy pipe-based flow).
fn verify_credentials_dpapi(password_b64: &str) -> Result<bool> {
    debug_log("verify_dpapi: step 1 — base64 decode");
    let protected_bytes = base64_decode(password_b64).context("base64 decode of DPAPI blob")?;

    debug_log("verify_dpapi: step 2 — DPAPI unprotect");
    let password_bytes = dpapi_unprotect(&protected_bytes).context("CryptUnprotectData failed")?;

    let password = String::from_utf8_lossy(&password_bytes).into_owned();
    debug_log(&format!(
        "verify_dpapi: step 3 — password length = {} chars",
        password.len()
    ));

    bcrypt_verify_against_server(&password)
}

/// Common bcrypt verification against the server-managed hash.
fn bcrypt_verify_against_server(password: &str) -> Result<bool> {
    debug_log("bcrypt_verify: fetching stored hash");
    let stored_hash = match get_auth_hash() {
        Ok(hash) => {
            debug_log(&format!(
                "bcrypt_verify: hash obtained ({}...)",
                &hash[..hash.len().min(10)]
            ));
            hash
        }
        Err(e) => {
            debug_log(&format!("bcrypt_verify: hash fetch FAILED — {e}"));
            return Err(e);
        }
    };

    debug_log("bcrypt_verify: comparing");
    match bcrypt::verify(password, &stored_hash) {
        Ok(true) => {
            debug_log("bcrypt_verify: MATCH");
            Ok(true)
        }
        Ok(false) => {
            debug_log("bcrypt_verify: NO MATCH");
            Ok(false)
        }
        Err(e) => {
            debug_log(&format!("bcrypt_verify: FAILED — {e}"));
            Err(anyhow::anyhow!("bcrypt verify error: {e}"))
        }
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
