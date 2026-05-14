//! Cloud sync enforcement layer (M017/S01 + S02).
//!
//! [`CloudEnforcer`] bridges the file interception event loop and cloud sync
//! folder detection to enforce DLP policies on files stored in sync client
//! folders (OneDrive, Google Drive, Dropbox, Box).
//!
//! ## Decision logic
//!
//! 1. Check if the file path is inside a known sync folder.
//! 2. If the action is a write/create/move that targets a T3/T4 file inside a
//!    sync folder, return a [`CloudBlockResult`] with `Decision::DENY`.
//! 3. Otherwise return `None` (fall through to ABAC).
//!
//! ## Sync folder detection (S02)
//!
//! [`resolve_sync_paths`] reads the actual sync-folder paths from
//! `HKEY_USERS\{SID}\SOFTWARE\...` for each provider.  When a registry key is
//! absent the function falls back to `%USERPROFILE%`-based defaults so the
//! enforcer degrades gracefully on non-standard installations.

use std::path::PathBuf;

use dlp_common::{Classification, Decision};

use crate::interception::FileAction;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Identifies which cloud sync provider owns a sync folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudProvider {
    /// Microsoft OneDrive (personal or business).
    OneDrive,
    /// Google Drive / Drive for Desktop.
    GoogleDrive,
    /// Dropbox.
    Dropbox,
    /// Box Drive.
    Box,
}

impl CloudProvider {
    /// Returns the human-readable display name used in block-reason strings.
    fn display_name(&self) -> &'static str {
        match self {
            Self::OneDrive => "OneDrive",
            Self::GoogleDrive => "Google Drive",
            Self::Dropbox => "Dropbox",
            Self::Box => "Box",
        }
    }
}

/// Indicates how a [`SyncPath`] was discovered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathSource {
    /// Path was read directly from the Windows registry.
    Registry,
    /// Registry key was absent; a `%USERPROFILE%`-based default was used.
    Fallback,
}

/// A resolved cloud-sync folder path for a specific provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncPath {
    /// Which cloud provider owns this folder.
    pub provider: CloudProvider,
    /// Absolute path string with a trailing backslash.
    pub path: String,
    /// How the path was discovered.
    pub source: PathSource,
}

// ---------------------------------------------------------------------------
// Registry-based path resolution
// ---------------------------------------------------------------------------

/// Resolves the actual cloud sync folder paths for all four providers
/// from `HKEY_USERS\{user_sid}\SOFTWARE\...`.
///
/// # Arguments
///
/// * `user_sid` - The SID string of the logged-on user (e.g. `S-1-5-21-...`).
///   Pass an empty string to skip registry probing and return only fallbacks.
///
/// # Returns
///
/// A `Vec<SyncPath>` with one entry per discovered folder.  When a registry
/// key is absent the function pushes a fallback entry using `%USERPROFILE%`.
/// Failures to open a key are logged at WARN level; the function never panics.
pub fn resolve_sync_paths(user_sid: &str) -> Vec<SyncPath> {
    let mut paths: Vec<SyncPath> = Vec::with_capacity(8);

    #[cfg(windows)]
    {
        if !user_sid.is_empty() {
            resolve_onedrive(user_sid, &mut paths);
            resolve_google_drive(user_sid, &mut paths);
            resolve_dropbox(user_sid, &mut paths);
            resolve_box(user_sid, &mut paths);
        }
    }
    #[cfg(not(windows))]
    let _ = user_sid; // suppress unused-variable warning on non-Windows

    // Fill in any provider that did not get a registry hit.
    push_missing_fallbacks(&mut paths);

    paths
}

/// Ensures every provider has at least one fallback entry when registry
/// discovery did not produce a result for that provider.
fn push_missing_fallbacks(paths: &mut Vec<SyncPath>) {
    let userprofile =
        std::env::var("USERPROFILE").unwrap_or_else(|_| r"C:\Users\Default".to_string());

    let providers: &[(&CloudProvider, &str)] = &[
        (&CloudProvider::OneDrive, "OneDrive"),
        (&CloudProvider::GoogleDrive, "Google Drive"),
        (&CloudProvider::Dropbox, "Dropbox"),
        (&CloudProvider::Box, "Box"),
    ];

    for (provider, folder_name) in providers {
        let already_present = paths.iter().any(|sp| &sp.provider == *provider);
        if !already_present {
            let raw = format!(r"{}\{}", userprofile, folder_name);
            paths.push(SyncPath {
                provider: (*provider).clone(),
                path: normalize_path(&raw),
                source: PathSource::Fallback,
            });
        }
    }
}

/// Normalises a raw path string: converts separators via `PathBuf` and appends
/// a trailing backslash so prefix checks work correctly.
fn normalize_path(raw: &str) -> String {
    let expanded = expand_env_vars(raw);
    let mut s = PathBuf::from(expanded.as_ref())
        .to_string_lossy()
        .into_owned();
    if !s.ends_with('\\') {
        s.push('\\');
    }
    s
}

/// Expands a single leading `%VARNAME%` token if present.
///
/// Only handles the common case where `%USERPROFILE%` appears in registry
/// strings returned by cloud clients.  Full `ExpandEnvironmentStringsW` would
/// be ideal but adding it here avoids another unsafe block for a narrow case.
fn expand_env_vars(raw: &str) -> std::borrow::Cow<'_, str> {
    if let Some(after_pct) = raw.strip_prefix('%') {
        if let Some(end) = after_pct.find('%') {
            let var_name = &after_pct[..end];
            if let Ok(value) = std::env::var(var_name) {
                let rest = &after_pct[end + 1..];
                return std::borrow::Cow::Owned(format!("{}{}", value, rest));
            }
        }
    }
    std::borrow::Cow::Borrowed(raw)
}

// ---------------------------------------------------------------------------
// Windows-only registry helpers
// ---------------------------------------------------------------------------

#[cfg(windows)]
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::WIN32_ERROR,
        System::Registry::{
            RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_USERS,
            KEY_READ, REG_EXPAND_SZ, REG_SZ, REG_VALUE_TYPE,
        },
    },
};

/// RAII guard that calls `RegCloseKey` when dropped.
#[cfg(windows)]
struct RegKey(HKEY);

#[cfg(windows)]
impl Drop for RegKey {
    fn drop(&mut self) {
        // SAFETY: HKEY came from a successful RegOpenKeyExW; RegCloseKey is
        // safe on any valid owned HKEY.
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}

/// Opens `HKEY_USERS\{sid}\{subkey}` for read access.
///
/// Returns `None` and logs a WARN when the key does not exist or cannot be
/// opened.
#[cfg(windows)]
fn open_user_key(sid: &str, subkey: &str) -> Option<RegKey> {
    let path = format!(r"{}\{}", sid, subkey);
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let mut hkey = HKEY::default();
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_USERS,
            PCWSTR::from_raw(wide.as_ptr()),
            Some(0),
            KEY_READ,
            &mut hkey,
        )
    };
    if status.is_err() {
        tracing::warn!(
            provider_path = %path,
            error_code = status.0,
            "cloud enforcer: registry key not found or inaccessible"
        );
        return None;
    }
    Some(RegKey(hkey))
}

/// Reads a `REG_SZ` or `REG_EXPAND_SZ` string value from an open `HKEY`.
///
/// Returns `None` and logs WARN on any failure.
#[cfg(windows)]
fn read_reg_string(hkey: HKEY, value_name: &str) -> Option<String> {
    let name_wide: Vec<u16> = value_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // First call: query required buffer size.
    let mut data_size = 0u32;
    let mut value_type = REG_VALUE_TYPE::default();
    let size_result = unsafe {
        RegQueryValueExW(
            hkey,
            PCWSTR::from_raw(name_wide.as_ptr()),
            None,
            Some(std::ptr::null_mut()),
            None,
            Some(&mut data_size),
        )
    };
    if size_result != WIN32_ERROR(0) || data_size == 0 {
        tracing::warn!(
            value = %value_name,
            error_code = size_result.0,
            "cloud enforcer: registry value size query failed or empty"
        );
        return None;
    }

    // Second call: read the data.
    let mut data = vec![0u8; data_size as usize];
    let read_result = unsafe {
        RegQueryValueExW(
            hkey,
            PCWSTR::from_raw(name_wide.as_ptr()),
            None,
            Some(&mut value_type),
            Some(data.as_mut_ptr()),
            Some(&mut data_size),
        )
    };
    if read_result != WIN32_ERROR(0) {
        tracing::warn!(
            value = %value_name,
            error_code = read_result.0,
            "cloud enforcer: registry value read failed"
        );
        return None;
    }
    if value_type != REG_SZ && value_type != REG_EXPAND_SZ {
        tracing::warn!(
            value = %value_name,
            type_id = value_type.0,
            "cloud enforcer: unexpected registry value type (expected REG_SZ/REG_EXPAND_SZ)"
        );
        return None;
    }

    // Data is UTF-16 LE; data_size is in bytes.
    let wide: &[u16] = unsafe {
        // SAFETY: data buffer holds data_size bytes of valid UTF-16 written by
        // RegQueryValueExW.  data_size / 2 gives the u16 count.
        std::slice::from_raw_parts(data.as_ptr().cast::<u16>(), (data_size as usize) / 2)
    };
    Some(
        String::from_utf16_lossy(wide)
            .trim_end_matches('\0')
            .to_string(),
    )
}

/// Enumerates immediate subkey names of an open `HKEY`.
///
/// Returns an empty `Vec` on failure.
#[cfg(windows)]
fn enum_subkeys(hkey: HKEY) -> Vec<String> {
    let mut names = Vec::new();
    // Buffer large enough for a registry key name (max 255 chars + null).
    let mut name_buf = vec![0u16; 256];
    let mut index = 0u32;
    loop {
        let mut name_len = name_buf.len() as u32;
        let status = unsafe {
            RegEnumKeyExW(
                hkey,
                index,
                // lpname: Option<PWSTR>, lpcchname: *mut u32
                Some(windows::core::PWSTR::from_raw(name_buf.as_mut_ptr())),
                &mut name_len,
                None, // lpreserved
                None, // lpclass
                None, // lpcchclass
                None, // lpftlastwritetime
            )
        };
        if status.is_err() {
            break;
        }
        let name = String::from_utf16_lossy(&name_buf[..name_len as usize]).to_string();
        names.push(name);
        index += 1;
    }
    names
}

// ---------------------------------------------------------------------------
// Per-provider resolution
// ---------------------------------------------------------------------------

/// Probes OneDrive personal and business accounts by enumerating
/// `HKEY_USERS\{sid}\SOFTWARE\Microsoft\OneDrive\Accounts` subkeys.
#[cfg(windows)]
fn resolve_onedrive(sid: &str, out: &mut Vec<SyncPath>) {
    let accounts_subkey = r"SOFTWARE\Microsoft\OneDrive\Accounts";
    let Some(accounts_key) = open_user_key(sid, accounts_subkey) else {
        tracing::info!(
            sid = %sid,
            "cloud enforcer: OneDrive Accounts key absent — will use fallback"
        );
        return;
    };
    let subkeys = enum_subkeys(accounts_key.0);
    for account_name in subkeys {
        let sub = format!(r"{}\{}", accounts_subkey, account_name);
        let Some(acct_key) = open_user_key(sid, &sub) else {
            continue;
        };
        if let Some(raw) = read_reg_string(acct_key.0, "UserFolder") {
            if !raw.is_empty() {
                tracing::info!(
                    sid = %sid,
                    account = %account_name,
                    path = %raw,
                    "cloud enforcer: OneDrive path resolved from registry"
                );
                out.push(SyncPath {
                    provider: CloudProvider::OneDrive,
                    path: normalize_path(&raw),
                    source: PathSource::Registry,
                });
            }
        }
    }
}

/// Probes Google Drive for Desktop (DriveFS) then legacy Google Drive.
#[cfg(windows)]
fn resolve_google_drive(sid: &str, out: &mut Vec<SyncPath>) {
    // Drive for Desktop (preferred).
    let drivefs_key = r"SOFTWARE\Google\DriveFS";
    if let Some(key) = open_user_key(sid, drivefs_key) {
        if let Some(raw) = read_reg_string(key.0, "DefaultMountPoint") {
            if !raw.is_empty() {
                tracing::info!(
                    sid = %sid, path = %raw,
                    "cloud enforcer: Google DriveFS path resolved from registry"
                );
                out.push(SyncPath {
                    provider: CloudProvider::GoogleDrive,
                    path: normalize_path(&raw),
                    source: PathSource::Registry,
                });
                return;
            }
        }
    }
    // Legacy Google Drive Backup & Sync.
    let legacy_key = r"SOFTWARE\Google\Drive";
    if let Some(key) = open_user_key(sid, legacy_key) {
        if let Some(raw) = read_reg_string(key.0, "Path") {
            if !raw.is_empty() {
                tracing::info!(
                    sid = %sid, path = %raw,
                    "cloud enforcer: Google Drive (legacy) path resolved from registry"
                );
                out.push(SyncPath {
                    provider: CloudProvider::GoogleDrive,
                    path: normalize_path(&raw),
                    source: PathSource::Registry,
                });
            }
        }
    }
}

/// Probes Dropbox sync folder from `HKEY_USERS\{sid}\SOFTWARE\Dropbox\ks`.
#[cfg(windows)]
fn resolve_dropbox(sid: &str, out: &mut Vec<SyncPath>) {
    let dropbox_key = r"SOFTWARE\Dropbox\ks";
    if let Some(key) = open_user_key(sid, dropbox_key) {
        if let Some(raw) = read_reg_string(key.0, "dropbox_path") {
            if !raw.is_empty() {
                tracing::info!(
                    sid = %sid, path = %raw,
                    "cloud enforcer: Dropbox path resolved from registry"
                );
                out.push(SyncPath {
                    provider: CloudProvider::Dropbox,
                    path: normalize_path(&raw),
                    source: PathSource::Registry,
                });
            }
        }
    }
}

/// Probes Box Drive folder path from `HKEY_USERS\{sid}\SOFTWARE\Box\Box`.
#[cfg(windows)]
fn resolve_box(sid: &str, out: &mut Vec<SyncPath>) {
    let box_key = r"SOFTWARE\Box\Box";
    if let Some(key) = open_user_key(sid, box_key) {
        if let Some(raw) = read_reg_string(key.0, "FolderPath") {
            if !raw.is_empty() {
                tracing::info!(
                    sid = %sid, path = %raw,
                    "cloud enforcer: Box path resolved from registry"
                );
                out.push(SyncPath {
                    provider: CloudProvider::Box,
                    path: normalize_path(&raw),
                    source: PathSource::Registry,
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Active-session SID detection
// ---------------------------------------------------------------------------

/// Returns the SID string of the user logged on at the active console session.
///
/// Uses `WTSGetActiveConsoleSessionId` + `WTSQuerySessionInformationW`
/// (username) + `LookupAccountNameW` to obtain a SID string.  Falls back to
/// scanning `HKEY_USERS` subkeys and returning the first non-system hive when
/// the WTS path fails (service running in Session 0 during boot, etc.).
///
/// Returns an empty `String` when no active user can be determined, which
/// causes [`resolve_sync_paths`] to skip registry probing and return only
/// fallbacks.
pub fn active_user_sid() -> String {
    #[cfg(windows)]
    {
        active_user_sid_windows()
    }
    #[cfg(not(windows))]
    {
        String::new()
    }
}

#[cfg(windows)]
fn active_user_sid_windows() -> String {
    use windows::Win32::{
        Security::{Authorization::ConvertSidToStringSidW, LookupAccountNameW, PSID},
        System::RemoteDesktop::{
            WTSFreeMemory, WTSGetActiveConsoleSessionId, WTSQuerySessionInformationW, WTSUserName,
            WTS_CURRENT_SERVER_HANDLE,
        },
    };

    // Step 1: get active console session ID.
    let session_id = unsafe { WTSGetActiveConsoleSessionId() };

    // Step 2: get the username for that session.
    let mut buf_ptr = windows::core::PWSTR::null();
    let mut buf_len: u32 = 0;
    // WTSQuerySessionInformationW takes Option<HANDLE> for the server parameter.
    let ok = unsafe {
        WTSQuerySessionInformationW(
            Some(WTS_CURRENT_SERVER_HANDLE),
            session_id,
            WTSUserName,
            &mut buf_ptr,
            &mut buf_len,
        )
    };
    if ok.is_err() || buf_ptr.is_null() {
        tracing::warn!(
            "cloud enforcer: WTSQuerySessionInformationW failed — using HKEY_USERS scan fallback"
        );
        return scan_hkey_users_for_sid();
    }

    // Convert the wide-char username (buf_len is in bytes, including null terminator).
    let char_count = (buf_len as usize / 2).saturating_sub(1);
    let username_wide: &[u16] = unsafe { std::slice::from_raw_parts(buf_ptr.as_ptr(), char_count) };
    let username = String::from_utf16_lossy(username_wide).to_string();
    unsafe { WTSFreeMemory(buf_ptr.as_ptr().cast()) };

    if username.is_empty() {
        tracing::warn!("cloud enforcer: empty username from WTS — using HKEY_USERS scan fallback");
        return scan_hkey_users_for_sid();
    }

    // Step 3: LookupAccountNameW to get PSID.
    let username_wide2: Vec<u16> = username.encode_utf16().chain(std::iter::once(0)).collect();
    let mut sid_buf = vec![0u8; 256];
    let mut sid_size = sid_buf.len() as u32;
    let mut domain_buf = vec![0u16; 256];
    let mut domain_size = domain_buf.len() as u32;
    let mut sid_name_use = windows::Win32::Security::SID_NAME_USE::default();

    let lookup_ok = unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR::from_raw(username_wide2.as_ptr()),
            Some(PSID(sid_buf.as_mut_ptr().cast())),
            &mut sid_size,
            // referenceddomainname: Option<PWSTR>
            Some(windows::core::PWSTR::from_raw(domain_buf.as_mut_ptr())),
            &mut domain_size,
            &mut sid_name_use,
        )
    };
    if lookup_ok.is_err() {
        tracing::warn!(
            username = %username,
            "cloud enforcer: LookupAccountNameW failed — using HKEY_USERS scan fallback"
        );
        return scan_hkey_users_for_sid();
    }

    // Step 4: ConvertSidToStringSidW → SID string.
    let psid = PSID(sid_buf.as_mut_ptr().cast());
    let mut sid_str_ptr = windows::core::PWSTR::null();
    let conv_ok = unsafe { ConvertSidToStringSidW(psid, &mut sid_str_ptr) };
    if conv_ok.is_err() || sid_str_ptr.is_null() {
        tracing::warn!("cloud enforcer: ConvertSidToStringSidW failed");
        return String::new();
    }

    let sid_string = unsafe { sid_str_ptr.to_string().unwrap_or_default() };
    // ConvertSidToStringSidW allocates via LocalAlloc; free with LocalFree.
    unsafe {
        let _ = windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(
            sid_str_ptr.as_ptr().cast(),
        )));
    }
    sid_string
}

/// Fallback: scan `HKEY_USERS` subkeys and return the first entry that looks
/// like a real user SID (starts with `S-1-5-21-`, not `.DEFAULT` or `_Classes`).
#[cfg(windows)]
fn scan_hkey_users_for_sid() -> String {
    let subkeys = enum_subkeys(HKEY_USERS);
    for name in subkeys {
        if name.starts_with("S-1-5-21-") && !name.ends_with("_Classes") {
            tracing::info!(sid = %name, "cloud enforcer: resolved SID via HKEY_USERS scan");
            return name;
        }
    }
    tracing::warn!("cloud enforcer: no user SID found in HKEY_USERS");
    String::new()
}

// ---------------------------------------------------------------------------
// CloudEnforcer
// ---------------------------------------------------------------------------

/// Result returned by [`CloudEnforcer::check`] when a cloud sync operation is
/// blocked.
#[derive(Debug, Clone, PartialEq)]
pub struct CloudBlockResult {
    /// The enforcement decision — currently always `Decision::DENY`.
    pub decision: Decision,
    /// Human-readable reason for the block.
    pub reason: String,
    /// The detected sync provider display name (e.g., "OneDrive").
    pub provider: String,
    /// `true` if the UI should display a toast.
    pub notify: bool,
}

/// Enforces DLP policies on file operations inside cloud sync folders.
///
/// Held behind `Arc` so it can be shared between the event loop and future
/// cloud notification handlers without cloning the underlying state.
pub struct CloudEnforcer {
    /// Resolved cloud sync folder paths with provider metadata.
    sync_paths: Vec<SyncPath>,
}

impl Default for CloudEnforcer {
    fn default() -> Self {
        Self::new()
    }
}

impl CloudEnforcer {
    /// Constructs a new [`CloudEnforcer`] by calling [`resolve_sync_paths`]
    /// with the active console user's SID.
    ///
    /// Falls back to `%USERPROFILE%`-based defaults when the active user
    /// cannot be determined or registry keys are absent.
    pub fn new() -> Self {
        let sid = active_user_sid();
        let sync_paths = resolve_sync_paths(&sid);
        tracing::info!(
            sid = %sid,
            path_count = sync_paths.len(),
            "cloud enforcer: sync paths resolved"
        );
        Self { sync_paths }
    }

    /// Constructs a new [`CloudEnforcer`] with explicit sync folder prefixes.
    ///
    /// Each `String` is wrapped as a `SyncPath` with provider `OneDrive` and
    /// source `Fallback`.  This preserves backward compatibility with the
    /// existing test suite (TC-30..TC-33) which injects raw path strings.
    pub fn with_paths(paths: Vec<String>) -> Self {
        let sync_paths = paths
            .into_iter()
            .map(|p| {
                let path = normalize_path(&p);
                SyncPath {
                    provider: CloudProvider::OneDrive,
                    path,
                    source: PathSource::Fallback,
                }
            })
            .collect();
        Self { sync_paths }
    }

    /// Constructs a [`CloudEnforcer`] with fully typed [`SyncPath`] entries.
    ///
    /// Used by unit tests that need to exercise provider-specific routing.
    pub fn with_sync_paths(sync_paths: Vec<SyncPath>) -> Self {
        Self { sync_paths }
    }

    /// Evaluates whether the given file operation should be blocked based on
    /// cloud sync folder policies.
    ///
    /// Returns `Some(CloudBlockResult)` for T3/T4 write operations inside a
    /// sync folder. All other operations return `None` (fall through to ABAC).
    ///
    /// # Arguments
    ///
    /// * `path` - Full file path of the operation.
    /// * `action` - The [`FileAction`] being evaluated.
    /// * `classification` - The ABAC classification resolved by the caller
    ///   before invoking this check. The caller is responsible for obtaining
    ///   this via `PolicyMapper::provisional_classification` or the live ABAC
    ///   evaluator and for logging any resolution failures before falling back
    ///   to a safe default (e.g. `Classification::T2`).
    ///
    /// # Returns
    ///
    /// - `Some(CloudBlockResult)` — T3/T4 file in sync folder; block.
    /// - `None` — not a sync path, or non-sensitive classification; proceed to ABAC.
    #[must_use]
    pub fn check(
        &self,
        path: &str,
        action: &FileAction,
        classification: Classification,
    ) -> Option<CloudBlockResult> {
        if !is_write_like_action(action) {
            return None;
        }

        let sync_path = self.detect_sync_provider(path)?;
        let provider_name = sync_path.provider.display_name().to_string();

        // Use the >= operator: T3 and T4 are both sensitive per is_sensitive().
        // PartialOrd is derived on Classification (T1 < T2 < T3 < T4).
        if classification >= Classification::T3 {
            tracing::info!(
                path = %path,
                provider = %provider_name,
                classification = ?classification,
                decision = ?Decision::DENY,
                "cloud enforcer decision"
            );
            Some(CloudBlockResult {
                decision: Decision::DENY,
                reason: format!(
                    "Cloud sync blocked: {classification} file in {provider_name} folder"
                ),
                provider: provider_name,
                notify: true,
            })
        } else {
            tracing::trace!(
                path = %path,
                provider = %provider_name,
                classification = ?classification,
                decision = ?Decision::ALLOW,
                "cloud enforcer decision"
            );
            None
        }
    }

    /// Returns the [`SyncPath`] whose `path` prefix matches `path`, or `None`.
    fn detect_sync_provider(&self, path: &str) -> Option<&SyncPath> {
        let lower = path.to_lowercase();
        self.sync_paths
            .iter()
            .find(|sp| lower.starts_with(&sp.path.to_lowercase()))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns `true` for actions that represent a file being written or created
/// in a way that could trigger a cloud upload.
fn is_write_like_action(action: &FileAction) -> bool {
    matches!(
        action,
        FileAction::Created { .. } | FileAction::Written { .. } | FileAction::Moved { .. }
    )
}

// ---------------------------------------------------------------------------
// Sync-client process watcher helpers
// ---------------------------------------------------------------------------

/// Returns the mapping of sync-client exe names to their cloud providers.
///
/// Used by [`enumerate_sync_client_pids`] and unit tests to enumerate running
/// sync processes without hard-coding the list at each call site.
///
/// Google Drive ships under two exe names depending on the version (legacy
/// `googledrivesync.exe` vs current DriveFS `GoogleDriveFS.exe`).
pub fn sync_process_names() -> &'static [(&'static str, CloudProvider)] {
    &[
        ("OneDrive.exe", CloudProvider::OneDrive),
        ("googledrivesync.exe", CloudProvider::GoogleDrive),
        ("GoogleDriveFS.exe", CloudProvider::GoogleDrive),
        ("Dropbox.exe", CloudProvider::Dropbox),
        ("Box.exe", CloudProvider::Box),
        ("BoxSync.exe", CloudProvider::Box),
    ]
}

/// Walks the system process list and returns `(pid, exe_name)` pairs for every
/// process whose executable name matches an entry in [`sync_process_names`].
///
/// Uses `CreateToolhelp32Snapshot` + `Process32FirstW` / `Process32NextW` so
/// no elevated privilege is required to enumerate running processes.
///
/// # Returns
///
/// An empty `Vec` when the snapshot cannot be created; individual process
/// entries that fail `Process32NextW` are silently skipped.
pub fn enumerate_sync_client_pids() -> Vec<(u32, &'static str)> {
    #[cfg(windows)]
    {
        enumerate_sync_client_pids_windows()
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

#[cfg(windows)]
fn enumerate_sync_client_pids_windows() -> Vec<(u32, &'static str)> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let known = sync_process_names();
    let mut results = Vec::new();

    // SAFETY: CreateToolhelp32Snapshot is a safe Win32 API; the snapshot handle
    // is owned and cleaned up via CloseHandle on drop.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    let snapshot = match snapshot {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!(
                error = ?e,
                "sync-process watcher: CreateToolhelp32Snapshot failed"
            );
            return results;
        }
    };

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    // First entry.
    // SAFETY: snapshot is a valid HANDLE from CreateToolhelp32Snapshot; entry
    // is initialised with the correct dwSize per the Win32 contract.
    if unsafe { Process32FirstW(snapshot, &mut entry) }.is_err() {
        // No processes at all — close handle and return.
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(snapshot);
        }
        return results;
    }

    loop {
        // szExeFile is a null-terminated UTF-16 array of length MAX_PATH (260).
        let len = entry
            .szExeFile
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(entry.szExeFile.len());
        let exe = String::from_utf16_lossy(&entry.szExeFile[..len]);

        // Case-insensitive match against the known sync-client list.
        if let Some((static_name, _)) = known
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(&exe))
        {
            results.push((entry.th32ProcessID, *static_name));
        }

        // Advance to the next entry; ERROR_NO_MORE_FILES (18) signals end.
        // SAFETY: same safety preconditions as Process32FirstW above.
        if unsafe { Process32NextW(snapshot, &mut entry) }.is_err() {
            break;
        }
    }

    unsafe {
        let _ = windows::Win32::Foundation::CloseHandle(snapshot);
    }
    results
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Helper constructors for FileAction variants
    // ------------------------------------------------------------------

    fn written_action(path: &str) -> FileAction {
        FileAction::Written {
            path: path.to_string(),
            process_id: 1,
            related_process_id: 1,
            byte_count: 100,
        }
    }

    fn created_action(path: &str) -> FileAction {
        FileAction::Created {
            path: path.to_string(),
            process_id: 1,
            related_process_id: 1,
        }
    }

    fn read_action(path: &str) -> FileAction {
        FileAction::Read {
            path: path.to_string(),
            process_id: 1,
            related_process_id: 1,
            byte_count: 0,
        }
    }

    fn moved_action(old: &str, new_path: &str) -> FileAction {
        FileAction::Moved {
            old_path: old.to_string(),
            new_path: new_path.to_string(),
            process_id: 1,
            related_process_id: 1,
        }
    }

    // ------------------------------------------------------------------
    // Legacy tests (must still pass after refactor)
    // ------------------------------------------------------------------

    #[test]
    fn test_empty_path_returns_none() {
        let enforcer = CloudEnforcer::with_paths(vec![r"C:\Users".to_string()]);
        assert_eq!(
            enforcer.check("", &written_action(""), Classification::T4),
            None
        );
    }

    #[test]
    fn test_unc_path_returns_none() {
        let enforcer = CloudEnforcer::with_paths(vec![r"C:\Users".to_string()]);
        assert_eq!(
            enforcer.check(
                r"\\server\share\file.txt",
                &written_action(r"\\server\share\file.txt"),
                Classification::T4,
            ),
            None
        );
    }

    #[test]
    fn test_path_outside_sync_folder_returns_none() {
        let enforcer = CloudEnforcer::with_paths(vec![r"C:\Users".to_string()]);
        assert_eq!(
            enforcer.check(
                r"C:\Windows\file.txt",
                &written_action(r"C:\Windows\file.txt"),
                Classification::T4,
            ),
            None
        );
    }

    #[test]
    fn test_read_action_returns_none() {
        let enforcer = CloudEnforcer::with_paths(vec![r"C:\Users".to_string()]);
        assert_eq!(
            enforcer.check(
                r"C:\Users\Alice\OneDrive\secret.txt",
                &read_action(r"C:\Users\Alice\OneDrive\secret.txt"),
                // Read actions are short-circuited before classification matters,
                // but we pass T4 to show that even the highest sensitivity
                // returns None for a non-write action.
                Classification::T4,
            ),
            None
        );
    }

    #[test]
    fn test_t1_file_in_sync_folder_returns_none() {
        let enforcer = CloudEnforcer::with_paths(vec![r"C:\Users".to_string()]);
        assert_eq!(
            enforcer.check(
                r"C:\Users\Alice\OneDrive\public.txt",
                &written_action(r"C:\Users\Alice\OneDrive\public.txt"),
                Classification::T1,
            ),
            None
        );
    }

    #[test]
    fn test_t2_file_in_sync_folder_returns_none() {
        let enforcer = CloudEnforcer::with_paths(vec![r"C:\Users".to_string()]);
        assert_eq!(
            enforcer.check(
                r"C:\Users\Alice\OneDrive\internal_notes.txt",
                &written_action(r"C:\Users\Alice\OneDrive\internal_notes.txt"),
                Classification::T2,
            ),
            None
        );
    }

    #[test]
    fn test_t3_file_in_sync_folder_blocked() {
        let enforcer = CloudEnforcer::with_paths(vec![r"C:\Users".to_string()]);
        let result = enforcer.check(
            r"C:\Users\Alice\OneDrive\report.docx",
            &written_action(r"C:\Users\Alice\OneDrive\report.docx"),
            Classification::T3,
        );
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.decision, Decision::DENY);
        assert_eq!(r.provider, "OneDrive");
        assert!(r.reason.contains("Cloud sync blocked"));
        assert!(r.notify);
    }

    #[test]
    fn test_t4_file_in_sync_folder_blocked() {
        let enforcer = CloudEnforcer::with_paths(vec![r"C:\Users".to_string()]);
        let result = enforcer.check(
            r"C:\Users\Alice\OneDrive\Payroll\payroll.xlsx",
            &written_action(r"C:\Users\Alice\OneDrive\Payroll\payroll.xlsx"),
            Classification::T4,
        );
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.decision, Decision::DENY);
        assert_eq!(r.provider, "OneDrive");
    }

    #[test]
    fn test_created_action_blocked() {
        let enforcer = CloudEnforcer::with_paths(vec![r"C:\Users".to_string()]);
        let result = enforcer.check(
            r"C:\Users\Alice\OneDrive\new_file.docx",
            &created_action(r"C:\Users\Alice\OneDrive\new_file.docx"),
            Classification::T3,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().decision, Decision::DENY);
    }

    #[test]
    fn test_moved_action_blocked() {
        let enforcer = CloudEnforcer::with_paths(vec![r"C:\Users".to_string()]);
        let result = enforcer.check(
            r"C:\Users\Alice\OneDrive\moved_file.docx",
            &moved_action(
                r"C:\Data\moved_file.docx",
                r"C:\Users\Alice\OneDrive\moved_file.docx",
            ),
            Classification::T3,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().decision, Decision::DENY);
    }

    #[test]
    fn test_custom_sync_path() {
        let enforcer = CloudEnforcer::with_paths(vec![r"D:\GoogleDrive".to_string()]);
        let result = enforcer.check(
            r"D:\GoogleDrive\report.docx",
            &written_action(r"D:\GoogleDrive\report.docx"),
            Classification::T3,
        );
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.decision, Decision::DENY);
        // with_paths wraps all entries as OneDrive for backward compat.
        assert_eq!(r.provider, "OneDrive");
    }

    #[test]
    fn test_deleted_action_returns_none() {
        let enforcer = CloudEnforcer::with_paths(vec![r"C:\Users".to_string()]);
        let action = FileAction::Deleted {
            path: r"C:\Users\Alice\OneDrive\report.docx".to_string(),
            process_id: 1,
            related_process_id: 1,
        };
        assert_eq!(
            enforcer.check(
                r"C:\Users\Alice\OneDrive\report.docx",
                &action,
                Classification::T4,
            ),
            None
        );
    }

    // ------------------------------------------------------------------
    // New S02 tests
    // ------------------------------------------------------------------

    /// resolve_sync_paths with an empty SID must return at least one fallback
    /// for each provider (OneDrive, GoogleDrive, Dropbox, Box).
    #[test]
    fn test_resolve_sync_paths_empty_sid_returns_fallbacks() {
        let paths = resolve_sync_paths("");
        let has = |p: &CloudProvider| paths.iter().any(|sp| &sp.provider == p);
        assert!(has(&CloudProvider::OneDrive), "missing OneDrive fallback");
        assert!(
            has(&CloudProvider::GoogleDrive),
            "missing GoogleDrive fallback"
        );
        assert!(has(&CloudProvider::Dropbox), "missing Dropbox fallback");
        assert!(has(&CloudProvider::Box), "missing Box fallback");
        assert!(
            paths.iter().all(|sp| sp.source == PathSource::Fallback),
            "expected all PathSource::Fallback for empty SID"
        );
    }

    /// normalize_path must always append a trailing backslash.
    #[test]
    fn test_sync_path_normalizes_trailing_backslash() {
        assert!(
            normalize_path(r"C:\Users\Alice\OneDrive").ends_with('\\'),
            "normalize_path must append trailing backslash"
        );
        // Already-terminated path must not produce a double backslash.
        let p = normalize_path(r"C:\Users\Alice\OneDrive\");
        assert!(
            p.ends_with('\\') && !p.ends_with(r"\\"),
            "double trailing backslash produced"
        );
    }

    /// detect_sync_provider must use the enum variant, not a substring heuristic.
    #[test]
    fn test_detect_provider_by_sync_path_type() {
        let enforcer = CloudEnforcer::with_sync_paths(vec![
            SyncPath {
                provider: CloudProvider::Dropbox,
                path: normalize_path(r"C:\Users\Alice\Dropbox"),
                source: PathSource::Fallback,
            },
            SyncPath {
                provider: CloudProvider::GoogleDrive,
                path: normalize_path(r"G:\My Drive"),
                source: PathSource::Fallback,
            },
        ]);

        let dropbox_match = enforcer.detect_sync_provider(r"C:\Users\Alice\Dropbox\file.txt");
        assert!(dropbox_match.is_some());
        assert_eq!(dropbox_match.unwrap().provider, CloudProvider::Dropbox);

        let gdrive_match = enforcer.detect_sync_provider(r"G:\My Drive\file.txt");
        assert!(gdrive_match.is_some());
        assert_eq!(gdrive_match.unwrap().provider, CloudProvider::GoogleDrive);

        assert!(enforcer
            .detect_sync_provider(r"C:\Windows\system32\file.dll")
            .is_none());
    }

    /// with_paths(Vec<String>) backward compat: existing tests must still pass
    /// after the sync_paths refactor.
    #[test]
    fn test_with_paths_still_works_after_sync_path_refactor() {
        let enforcer = CloudEnforcer::with_paths(vec![
            r"C:\Users\Alice\OneDrive".to_string(),
            r"C:\Users\Alice\Dropbox".to_string(),
        ]);
        assert!(enforcer
            .detect_sync_provider(r"C:\Users\Alice\OneDrive\file.txt")
            .is_some());
        assert!(enforcer
            .detect_sync_provider(r"C:\Users\Alice\Dropbox\file.txt")
            .is_some());
        assert!(enforcer
            .detect_sync_provider(r"D:\archive\file.txt")
            .is_none());
    }

    /// Blocked file in a Dropbox folder must report "Dropbox" as provider name.
    #[test]
    fn test_dropbox_provider_name_in_block_result() {
        let enforcer = CloudEnforcer::with_sync_paths(vec![SyncPath {
            provider: CloudProvider::Dropbox,
            path: normalize_path(r"C:\Users\Alice\Dropbox"),
            source: PathSource::Fallback,
        }]);
        let result = enforcer.check(
            r"C:\Users\Alice\Dropbox\report.docx",
            &written_action(r"C:\Users\Alice\Dropbox\report.docx"),
            Classification::T3,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().provider, "Dropbox");
    }

    /// Blocked file in a Box folder must report "Box" as provider name.
    #[test]
    fn test_box_provider_name_in_block_result() {
        let enforcer = CloudEnforcer::with_sync_paths(vec![SyncPath {
            provider: CloudProvider::Box,
            path: normalize_path(r"C:\Users\Alice\Box"),
            source: PathSource::Fallback,
        }]);
        let result = enforcer.check(
            r"C:\Users\Alice\Box\payroll.xlsx",
            &written_action(r"C:\Users\Alice\Box\payroll.xlsx"),
            Classification::T4,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().provider, "Box");
    }

    // ------------------------------------------------------------------
    // Sync-client process watcher helpers (T03)
    // ------------------------------------------------------------------

    /// sync_process_names must include at least one entry for every provider.
    #[test]
    fn test_sync_process_names_covers_all_providers() {
        let names = sync_process_names();

        let has = |p: CloudProvider| names.iter().any(|(_, provider)| *provider == p);

        assert!(has(CloudProvider::OneDrive), "missing OneDrive entry");
        assert!(has(CloudProvider::GoogleDrive), "missing GoogleDrive entry");
        assert!(has(CloudProvider::Dropbox), "missing Dropbox entry");
        assert!(has(CloudProvider::Box), "missing Box entry");
    }

    /// enumerate_sync_client_pids must return without panic even when no sync
    /// clients are running (as in CI).  We only verify the call succeeds.
    #[test]
    fn test_enumerate_sync_client_pids_returns_vec() {
        // This is a smoke test — we do not assert specific PIDs because
        // sync clients are not guaranteed to be running in CI.
        let pids = enumerate_sync_client_pids();
        // A Vec (including empty) is a valid result; no panic = pass.
        // All returned exe names must appear in sync_process_names().
        let known: std::collections::HashSet<&'static str> =
            sync_process_names().iter().map(|(name, _)| *name).collect();
        for (_, exe) in &pids {
            assert!(
                known.contains(exe),
                "unexpected exe name from enumerate_sync_client_pids: {exe}"
            );
        }
    }
}
