//! BitLocker encryption verification (Phase 34, CRYPT-01 / CRYPT-02).
//!
//! Verifies BitLocker encryption status for every fixed disk enumerated by
//! Phase 33's [`DiskEnumerator`]. Uses WMI's `Win32_EncryptableVolume` as the
//! primary source and the Windows Registry (`HKLM\SYSTEM\CurrentControlSet\
//! Control\BitLockerStatus\BootStatus`) as a fallback when the WMI namespace
//! is unavailable (D-01a — fallback fires only on namespace-not-found errors,
//! never on per-volume timeouts).
//!
//! ## Lifecycle
//!
//! 1. `service.rs` constructs an `EncryptionChecker`, registers it via
//!    [`set_encryption_checker`], and calls [`spawn_encryption_check_task`]
//!    immediately after [`crate::detection::disk::spawn_disk_enumeration_task`].
//! 2. The spawned task waits for [`crate::detection::disk::DiskEnumerator::is_ready`],
//!    then runs the first verification across all disks.
//! 3. If the FIRST verification fails for ALL disks, a single
//!    [`EventType::Alert`] event is emitted (D-16). Subsequent periodic
//!    failures do NOT emit Alerts — `Unknown` carries the signal.
//! 4. The task then loops every `recheck_interval` (default 6 h, clamped
//!    by [`crate::config::AgentConfig::resolved_recheck_interval`]). On each
//!    poll, status changes versus the cached value emit a fresh
//!    [`EventType::DiskDiscovery`] with `justification = "encryption status
//!    changed: ..."` (D-25). Unchanged statuses silently update only
//!    `encryption_checked_at` (D-12).
//!
//! ## Threading
//!
//! Every WMI / Registry call runs inside [`tokio::task::spawn_blocking`]
//! wrapped in [`tokio::time::timeout`] (Pitfall A + B). The blocking thread
//! is sacrificial — `tokio::time::timeout` does NOT cancel `spawn_blocking`,
//! so a wedged WMI call leaks the worker until DCOM's own internal timeout
//! fires. With at most ~32 disks per check every 6 h, this is acceptable
//! debt (Pitfall B in 34-RESEARCH.md).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use chrono::{DateTime, Utc};
use dlp_common::{DiskIdentity, EncryptionMethod, EncryptionStatus};
use parking_lot::RwLock;
use tracing::{debug, error, info, warn};

// wmi 0.14.x does not expose `set_proxy_blanket` / `AuthLevel::PktPrivacy` —
// those were added in wmi 0.18. wmi 0.14 uses `windows 0.59` internally while
// this workspace targets `windows 0.62`, making the COM interface types
// incompatible at the Rust trait level. We call the underlying `CoSetProxyBlanket`
// Win32 API via raw FFI, using the object's vtable pointer extracted with
// `as_raw()` from `windows-core 0.59`. This achieves the identical auth upgrade
// to `PktPrivacy` that wmi 0.18's `set_proxy_blanket(wmi::AuthLevel::PktPrivacy)`
// performs. Documented as a deviation in the plan SUMMARY.

// Windows-only Registry imports used by `WindowsEncryptionBackend`.
#[cfg(windows)]
use windows::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_DWORD,
    REG_VALUE_TYPE,
};

// ---------------------------------------------------------------------------
// EncryptionError enum
// ---------------------------------------------------------------------------

/// Errors produced during BitLocker verification.
///
/// Variants are separated by the source layer so callers can apply the
/// D-01a Registry-fallback gate without string matching.
#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    /// `CoInitializeEx` / `wmi::COMLibrary::new()` failed.
    #[error("COM init failed: {0}")]
    ComInitFailed(String),
    /// `wmi::WMIConnection::with_namespace_path` or `set_proxy_blanket` failed.
    #[error("WMI connection failed: {0}")]
    WmiConnectionFailed(String),
    /// The WMI namespace `ROOT\\CIMV2\\Security\\MicrosoftVolumeEncryption` is not
    /// available on this host (e.g., Windows Home, BitLocker not installed).
    /// This is the ONE error class that triggers the Registry fallback (D-01a).
    #[error("WMI namespace unavailable: {0}")]
    WmiNamespaceUnavailable(String),
    /// `WMIConnection::query` returned an error other than namespace-not-found.
    /// Per D-01a, this does NOT trigger the Registry fallback — it yields Unknown directly.
    #[error("WMI query failed: {0}")]
    WmiQueryFailed(String),
    /// Per-volume `tokio::time::timeout` of 5 s elapsed (D-03).
    /// Does NOT trigger Registry fallback per D-01a.
    #[error("WMI query timed out after 5s")]
    Timeout,
    /// `RegOpenKeyExW` failed.
    #[error("Registry open failed: {0}")]
    RegistryOpenFailed(String),
    /// `RegQueryValueExW` failed or returned an unexpected value type.
    #[error("Registry read failed: {0}")]
    RegistryReadFailed(String),
    /// No `Win32_EncryptableVolume` row matched the queried drive letter.
    #[error("volume not found in Win32_EncryptableVolume")]
    VolumeNotFound,
    /// The blocking task panicked.
    #[error("spawn_blocking task panicked: {0}")]
    TaskPanicked(String),
}

impl EncryptionError {
    /// Returns `true` if this error variant warrants triggering the Registry
    /// fallback per D-01a (only namespace-unavailable; never timeouts or
    /// transient WMI errors).
    #[must_use]
    pub fn warrants_registry_fallback(&self) -> bool {
        matches!(self, Self::WmiNamespaceUnavailable(_))
    }
}

// ---------------------------------------------------------------------------
// EncryptionBackend trait
// ---------------------------------------------------------------------------

/// Pluggable backend for the WMI primary path and the Registry fallback path.
///
/// Production code uses [`WindowsEncryptionBackend`]. Unit tests
/// inject a mock via [`spawn_encryption_check_task_with_backend`].
/// The trait isolates COM/WMI/Registry from the orchestration logic so the
/// status derivation, change detection, justification building, and Pitfall E
/// first-check semantics can be tested deterministically on any platform.
pub trait EncryptionBackend: Send + Sync + 'static {
    /// Query a single drive letter via WMI's `Win32_EncryptableVolume`.
    ///
    /// Returns `(EncryptionStatus, Option<EncryptionMethod>)` on success.
    /// The 5-second per-volume timeout (D-03) is the implementor's contract.
    ///
    /// # Errors
    ///
    /// Returns `EncryptionError` if the WMI query fails, times out, or the
    /// volume is not found.
    fn query_volume(
        &self,
        drive_letter: char,
    ) -> Result<(EncryptionStatus, Option<EncryptionMethod>), EncryptionError>;

    /// Read `HKLM\\SYSTEM\\CurrentControlSet\\Control\\BitLockerStatus\\BootStatus`.
    ///
    /// Returns the DWORD value: 0 = unencrypted boot, 1 = encrypted boot.
    /// Boot volume only — best-effort fallback per D-01a.
    ///
    /// # Errors
    ///
    /// Returns `EncryptionError` if the Registry key cannot be opened or read.
    fn read_boot_status_registry(&self) -> Result<u32, EncryptionError>;
}

// ---------------------------------------------------------------------------
// EncryptionChecker struct + global singleton
// ---------------------------------------------------------------------------

/// Singleton holding the most recent BitLocker verification snapshot.
///
/// Mutated via interior `RwLock`s by the background task spawned via
/// [`spawn_encryption_check_task`]. Read by Phase 36 enforcement code,
/// Phase 35 allowlist persistence, and Phase 38 admin TUI — all of which
/// access `DiskEnumerator` directly per D-20 (the encryption fields ride
/// on the shared `DiskIdentity` records).
#[derive(Debug)]
pub struct EncryptionChecker {
    /// Per-disk encryption status, keyed by `instance_id`.
    pub encryption_status_map: RwLock<HashMap<String, EncryptionStatus>>,
    /// Timestamp of the most recent verification *attempt* across all disks.
    /// Set whether the attempt succeeded or yielded Unknown.
    pub last_check_at: RwLock<Option<DateTime<Utc>>>,
    /// `true` once the first verification has completed (success or failure).
    pub check_complete: RwLock<bool>,
    /// `true` until the first verification attempt completes (any outcome).
    /// Used by D-16/D-16a Alert-emission rule. After the first attempt,
    /// regardless of outcome, this flag is flipped to `false` and never
    /// re-set — preventing repeat Alert events on subsequent failures
    /// (Pitfall E).
    pub is_first_check: RwLock<bool>,
}

impl EncryptionChecker {
    /// Create an empty checker. Used at agent startup.
    #[must_use]
    pub fn new() -> Self {
        Self {
            encryption_status_map: RwLock::new(HashMap::new()),
            last_check_at: RwLock::new(None),
            check_complete: RwLock::new(false),
            is_first_check: RwLock::new(true),
        }
    }

    /// `true` once the first verification has completed.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        *self.check_complete.read()
    }

    /// `true` until the first verification has run (flipped by
    /// [`mark_first_check_complete`]).
    #[must_use]
    pub fn is_first_check(&self) -> bool {
        *self.is_first_check.read()
    }

    /// Snapshot the cached status for a given instance ID.
    ///
    /// Returns `None` if no status has been recorded for this disk yet.
    #[must_use]
    pub fn status_for_instance_id(&self, instance_id: &str) -> Option<EncryptionStatus> {
        self.encryption_status_map.read().get(instance_id).copied()
    }

    /// Test-only seed accessor, mirroring `DeviceRegistryCache::seed_for_test`.
    ///
    /// Inserts a synthetic status directly into the in-memory map so unit tests
    /// can set up state without running the full WMI/Registry code path.
    #[cfg(test)]
    pub fn seed_for_test(&self, instance_id: &str, status: EncryptionStatus) {
        self.encryption_status_map
            .write()
            .insert(instance_id.to_string(), status);
    }

    /// Marks the first check complete (idempotent). Pitfall E: flag flips
    /// after the FIRST attempt regardless of outcome — never re-set.
    ///
    /// Called exactly once per verification cycle, in
    /// `run_one_verification_cycle` after all emit decisions.
    pub(crate) fn mark_first_check_complete(&self) {
        // WR-03: Two sequential writes — not atomic. Between the two lines,
        // is_first_check is false but check_complete is still false. A concurrent
        // reader sees is_ready() == false, which is correct (conservative). There is
        // no reader that observes is_first_check == false AND is_ready() == true
        // prematurely, so this ordering is safe in a single-writer context.
        // Write is_first_check first so readers never see is_ready() before
        // is_first_check is cleared.
        *self.is_first_check.write() = false;
        *self.check_complete.write() = true;
    }
}

impl Default for EncryptionChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// Global `EncryptionChecker` reference, set once during service startup.
static ENCRYPTION_CHECKER: OnceLock<Arc<EncryptionChecker>> = OnceLock::new();

/// Register the singleton at agent startup.
///
/// Subsequent calls are silently ignored (OnceLock contract).
///
/// # Arguments
///
/// * `checker` — the `Arc<EncryptionChecker>` to store globally.
pub fn set_encryption_checker(checker: Arc<EncryptionChecker>) {
    let _ = ENCRYPTION_CHECKER.set(checker);
}

/// Get the singleton (None until [`set_encryption_checker`] has been called).
///
/// Returns a cloned `Arc` so callers can hold a reference without the
/// OnceLock remaining borrowed.
#[must_use]
pub fn get_encryption_checker() -> Option<Arc<EncryptionChecker>> {
    ENCRYPTION_CHECKER.get().cloned()
}

// ---------------------------------------------------------------------------
// Pure-logic helpers (the testable orchestration core)
// ---------------------------------------------------------------------------

/// Parse a WMI `DriveLetter` string (e.g., `"C:"`) into a `char`.
///
/// Returns `None` for empty strings, non-alphabetic first characters, or
/// strings whose first character is not in `A..=Z` / `a..=z`. Lowercase
/// inputs are uppercased. Pitfall C in 34-RESEARCH.md — centralized to
/// prevent silent join-key mismatches against `DiskEnumerator.drive_letter_map`.
///
/// # Examples
///
/// ```
/// # use dlp_agent::detection::encryption::parse_drive_letter;
/// assert_eq!(parse_drive_letter("C:"), Some('C'));
/// assert_eq!(parse_drive_letter("e:"), Some('E'));
/// assert_eq!(parse_drive_letter(""), None);
/// ```
#[must_use]
pub fn parse_drive_letter(s: &str) -> Option<char> {
    s.chars()
        .next()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_uppercase())
}

/// Map raw WMI `(ProtectionStatus, ConversionStatus)` to [`EncryptionStatus`].
///
/// Truth table per CONTEXT.md `<specifics>`. Defensive default for any
/// unrecognized combination is `Unknown` — never `Encrypted` (D-14).
///
/// # Arguments
///
/// * `protection_status` — raw `ProtectionStatus` field from `Win32_EncryptableVolume`.
/// * `conversion_status` — raw `ConversionStatus` field from `Win32_EncryptableVolume`.
///
/// # Returns
///
/// The derived [`EncryptionStatus`]; never returns `Encrypted` on ambiguous input.
#[must_use]
pub fn derive_encryption_status(
    protection_status: Option<u32>,
    conversion_status: Option<u32>,
) -> EncryptionStatus {
    match (protection_status, conversion_status) {
        (Some(1), Some(1)) => EncryptionStatus::Encrypted,
        (Some(0), Some(1)) => EncryptionStatus::Suspended,
        (Some(0), Some(0)) => EncryptionStatus::Unencrypted,
        // ConversionStatus 2/3/4/5 = encrypting/decrypting/paused — surfaces
        // as Unencrypted because the disk is not currently fully ciphertext
        // with active key protection.
        (Some(0), Some(2)) => EncryptionStatus::Unencrypted,
        (Some(0), Some(3)) => EncryptionStatus::Unencrypted,
        (Some(0), Some(4)) => EncryptionStatus::Unencrypted,
        (Some(0), Some(5)) => EncryptionStatus::Unencrypted,
        (Some(2), _) => EncryptionStatus::Unknown,
        // WR-05: ProtectionStatus=1 (Protected) but ConversionStatus=0 (FullyDecrypted).
        // This transient WMI state appears during BitLocker key-protector re-enablement
        // on a partially decrypted volume. Treat as Unknown per D-14 defensive policy.
        (Some(1), Some(0)) => EncryptionStatus::Unknown,
        // Defensive fallback (D-14).
        _ => EncryptionStatus::Unknown,
    }
}

/// One status transition emitted per status-change.
///
/// Used by [`compute_changed_transitions`] and [`build_change_justification`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusTransition {
    /// The instance ID of the disk that changed.
    pub instance_id: String,
    /// Previous status (`None` if this is the first observation).
    pub old: Option<EncryptionStatus>,
    /// New (current) status.
    pub new: EncryptionStatus,
}

/// Compare two snapshots and return only the transitions.
///
/// A transition is any instance whose status differs between snapshots.
/// Per Pitfall D, `None -> Some(Unknown)` (first observation) IS a transition;
/// `Some(Unknown) -> Some(Unknown)` is NOT.
///
/// # Arguments
///
/// * `old_snapshot` — previous encryption status map (instance_id -> status).
/// * `new_snapshot` — current encryption status map (instance_id -> status).
///
/// # Returns
///
/// A vector of [`StatusTransition`] for every instance whose status changed.
#[must_use]
pub fn compute_changed_transitions(
    old_snapshot: &HashMap<String, EncryptionStatus>,
    new_snapshot: &HashMap<String, EncryptionStatus>,
) -> Vec<StatusTransition> {
    let mut out = Vec::new();
    for (id, &new) in new_snapshot {
        let old = old_snapshot.get(id).copied();
        // `Some(new)` != `old` covers both None->Some(X) and Some(X)->Some(Y).
        // `Some(Unknown) -> Some(Unknown)` is excluded because old == Some(Unknown)
        // and new == Unknown, so `Some(new) == old` is true.
        if old != Some(new) {
            out.push(StatusTransition {
                instance_id: id.clone(),
                old,
                new,
            });
        }
    }
    out
}

/// Build the `justification` field for a `DiskDiscovery` event when at
/// least one disk is `Unknown` (D-15).
///
/// Format: one `<instance_id>: <reason>` per line. Gives the admin actionable
/// diagnosis when reviewing the audit feed.
///
/// # Arguments
///
/// * `failed` — slice of `(instance_id, reason)` pairs for disks that returned `Unknown`.
///
/// # Returns
///
/// A multi-line string, one entry per disk.
#[must_use]
pub fn build_unknown_justification(failed: &[(String, String)]) -> String {
    failed
        .iter()
        .map(|(id, reason)| format!("{id}: {reason}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Build the `justification` field for a status-change `DiskDiscovery`
/// event (D-25).
///
/// Format: `encryption status changed: <id1> <old1> -> <new1>; <id2> ...`
///
/// # Arguments
///
/// * `transitions` — slice of [`StatusTransition`] describing changed disks.
///
/// # Returns
///
/// A single-line justification string beginning with `"encryption status changed: "`.
#[must_use]
pub fn build_change_justification(transitions: &[StatusTransition]) -> String {
    let parts: Vec<String> = transitions
        .iter()
        .map(|t| {
            // Format EncryptionStatus debug names in lowercase for readable SIEM logs.
            let old = t
                .old
                .map(|s| format!("{s:?}").to_ascii_lowercase())
                .unwrap_or_else(|| "none".to_string());
            let new = format!("{:?}", t.new).to_ascii_lowercase();
            format!("{} {} -> {}", t.instance_id, old, new)
        })
        .collect();
    format!("encryption status changed: {}", parts.join("; "))
}

// ---------------------------------------------------------------------------
// WindowsEncryptionBackend (production backend)
// ---------------------------------------------------------------------------

/// Wire DTO for the WMI `Win32_EncryptableVolume` class. PascalCase per WMI naming.
/// Verified shape per RESEARCH.md "wmi-rs 0.14 Wire-up §Struct-based query".
///
/// `#[cfg(windows)]` ensures this struct and its WMI deserialization code
/// are excluded from non-Windows builds that cannot use wmi-rs COM bindings.
#[cfg(windows)]
#[derive(serde::Deserialize, Debug, Clone)]
#[serde(rename = "Win32_EncryptableVolume")]
#[serde(rename_all = "PascalCase")]
struct EncryptableVolume {
    /// WMI `DeviceID` — unique volume identifier.
    #[allow(dead_code)]
    device_id: String,
    /// WMI `DriveLetter` — e.g., `"C:"` (with colon). See Pitfall C.
    drive_letter: Option<String>,
    /// WMI `ProtectionStatus` — 0=Unprotected, 1=Protected, 2=Unknown.
    protection_status: Option<u32>,
    /// WMI `ConversionStatus` — 0=FullyDecrypted..5=DecryptionPaused.
    conversion_status: Option<u32>,
    /// WMI `EncryptionMethod` — 0=None..7=XtsAes256.
    encryption_method: Option<u32>,
}

/// Upgrade a WMI proxy blanket to `PktPrivacy` authentication level (D-02).
///
/// `wmi 0.14` uses `windows 0.59` internally while this workspace targets
/// `windows 0.62`. The `IWbemServices` type from 0.59 does not implement the
/// `Interface` trait from 0.62, making `CoSetProxyBlanket` from our `windows`
/// crate unusable. We call the underlying `ole32.dll` export directly via a raw
/// function pointer, passing the COM object as `*mut c_void` (the stable ABI).
///
/// This is equivalent to `wmi 0.18`'s `set_proxy_blanket(wmi::AuthLevel::PktPrivacy)`.
///
/// # Safety
///
/// `svc_raw` must be a valid `IWbemServices` vtable pointer owned by the caller.
/// The `CoSetProxyBlanket` Win32 function is declared `system` and does not throw.
#[cfg(windows)]
unsafe fn upgrade_to_pkt_privacy(svc_raw: *mut std::ffi::c_void) -> Result<(), EncryptionError> {
    // CoSetProxyBlanket signature (ole32.dll, stable ABI since Win2000):
    // HRESULT CoSetProxyBlanket(IUnknown*, DWORD, DWORD, OLECHAR*, DWORD, DWORD, RPC_AUTH_IDENTITY_HANDLE, DWORD)
    #[allow(non_snake_case)]
    #[link(name = "ole32")]
    extern "system" {
        fn CoSetProxyBlanket(
            pProxy: *mut std::ffi::c_void,
            dwAuthnSvc: u32,
            dwAuthzSvc: u32,
            pServerPrincName: *const u16,
            dwAuthnLevel: u32,
            dwImpLevel: u32,
            pAuthInfo: *mut std::ffi::c_void,
            dwCapabilities: u32,
        ) -> i32; // HRESULT
    }
    // Constants (stable Win32 ABI values, verified against windows-core 0.62 constants).
    const RPC_C_AUTHN_WINNT: u32 = 10; // NTLM Security Support Provider
    const RPC_C_AUTHZ_NONE: u32 = 0; // No authorization service
    const RPC_C_AUTHN_LEVEL_PKT_PRIVACY: u32 = 6; // Encrypt + sign (PktPrivacy)
    const RPC_C_IMP_LEVEL_IMPERSONATE: u32 = 3; // Impersonate client
    const EOAC_NONE: u32 = 0; // No extra proxy capabilities

    let hr = CoSetProxyBlanket(
        svc_raw,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        std::ptr::null(), // default principal name
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        std::ptr::null_mut(), // no auth identity (use process token)
        EOAC_NONE,
    );
    if hr < 0 {
        return Err(EncryptionError::WmiConnectionFailed(format!(
            "CoSetProxyBlanket(PktPrivacy) HRESULT 0x{hr:08X}"
        )));
    }
    Ok(())
}

/// Open a WMI connection to the BitLocker namespace with `PktPrivacy`
/// auth (D-02). Centralized per Pitfall F — every fresh connection MUST
/// have `set_proxy_blanket(wmi::AuthLevel::PktPrivacy)` level applied or
/// queries return ACCESS_DENIED from the `MicrosoftVolumeEncryption` namespace.
///
/// Implementation note: wmi 0.14 (pinned per D-21a) does not expose
/// `set_proxy_blanket(wmi::AuthLevel::PktPrivacy)` — those types exist only
/// in wmi 0.18. The equivalent is achieved via [`upgrade_to_pkt_privacy`]
/// which calls `CoSetProxyBlanket` directly on the raw COM vtable pointer.
///
/// # Errors
///
/// Returns `EncryptionError::WmiNamespaceUnavailable` when the namespace is not
/// registered (triggers Registry fallback per D-01a).
/// Returns `EncryptionError::ComInitFailed` or `EncryptionError::WmiConnectionFailed`
/// for other failures.
#[cfg(windows)]
fn open_bitlocker_connection() -> Result<wmi::WMIConnection, EncryptionError> {
    let com = wmi::COMLibrary::new().map_err(|e| EncryptionError::ComInitFailed(e.to_string()))?;
    let conn = wmi::WMIConnection::with_namespace_path(
        r"ROOT\CIMV2\Security\MicrosoftVolumeEncryption",
        com,
    )
    .map_err(classify_wmi_connection_error)?;
    // Upgrade from the default CALL-level set by wmi 0.14 to PktPrivacy.
    // `conn.svc` is `pub IWbemServices` from windows 0.59; `as_raw()` yields
    // the stable COM vtable pointer (`*mut c_void`) regardless of crate version.
    // SAFETY: `conn` owns the IWbemServices; the object is alive for the
    // duration of this call. The raw pointer is never stored beyond this scope.
    // `wmi 0.14` uses `windows-core 0.59` internally; `Interface::as_raw()`
    // returns `*mut c_void` — same stable COM ABI regardless of crate version.
    // We import `windows_core::Interface` from the 0.59 edition (declared as a
    // direct dep in Cargo.toml) to make `as_raw()` callable on the 0.59-typed
    // `IWbemServices` that wmi 0.14 returns.
    unsafe {
        // Import windows_core 0.59 Interface trait (matches the version wmi 0.14 uses)
        // so that `as_raw()` is available on the wmi-returned `IWbemServices`.
        use windows_core::Interface;
        upgrade_to_pkt_privacy(conn.svc.as_raw())?;
    }
    Ok(conn)
}

/// Classify a wmi-rs connection error. Per D-01a, only namespace-unavailable
/// errors trigger the Registry fallback. Other connection errors yield Unknown directly.
///
/// Detection heuristic: the WMI error message for `WBEM_E_INVALID_NAMESPACE`
/// (0x8004100E) typically contains "namespace" or the hex code. This is a
/// best-effort classification — false negatives land in `WmiConnectionFailed`
/// which still yields `Unknown`, not a wrong positive.
#[cfg(windows)]
fn classify_wmi_connection_error(e: wmi::WMIError) -> EncryptionError {
    let msg = e.to_string();
    let lc = msg.to_ascii_lowercase();
    // WBEM_E_INVALID_NAMESPACE = 0x8004100E; messages typically include
    // "namespace" or the hex code string.
    if lc.contains("namespace") || lc.contains("0x8004100e") || lc.contains("invalid namespace") {
        EncryptionError::WmiNamespaceUnavailable(msg)
    } else {
        EncryptionError::WmiConnectionFailed(msg)
    }
}

/// Production backend wrapping `wmi-rs` and `windows::Win32::System::Registry`.
///
/// On non-Windows targets, both methods return errors immediately so the
/// orchestration layer can still exercise all code paths via the trait.
pub struct WindowsEncryptionBackend;

impl EncryptionBackend for WindowsEncryptionBackend {
    fn query_volume(
        &self,
        drive_letter: char,
    ) -> Result<(EncryptionStatus, Option<EncryptionMethod>), EncryptionError> {
        #[cfg(windows)]
        {
            let conn = open_bitlocker_connection()?;
            // `query()` fetches all Win32_EncryptableVolume rows; we then filter
            // by drive letter. Using typed `query()` is simpler than `raw_query()`
            // and negligible overhead for <= 32 volumes per machine.
            let volumes: Vec<EncryptableVolume> = conn
                .query()
                .map_err(|e| EncryptionError::WmiQueryFailed(e.to_string()))?;
            let target = volumes
                .iter()
                .find(|v| {
                    // Pitfall C: parse_drive_letter is the ONLY string-to-char
                    // path for DriveLetter — centralized to prevent join-key mismatches.
                    v.drive_letter.as_deref().and_then(parse_drive_letter) == Some(drive_letter)
                })
                .ok_or(EncryptionError::VolumeNotFound)?;
            let status =
                derive_encryption_status(target.protection_status, target.conversion_status);
            let method = target.encryption_method.map(EncryptionMethod::from);
            Ok((status, method))
        }
        #[cfg(not(windows))]
        {
            let _ = drive_letter;
            Err(EncryptionError::WmiQueryFailed(
                "non-Windows build".to_string(),
            ))
        }
    }

    fn read_boot_status_registry(&self) -> Result<u32, EncryptionError> {
        #[cfg(windows)]
        {
            use windows::core::w;

            /// RAII handle for `HKEY` so `RegCloseKey` is always called.
            struct RegKey(HKEY);
            impl Drop for RegKey {
                fn drop(&mut self) {
                    // SAFETY: HKEY came from a successful RegOpenKeyExW;
                    // RegCloseKey is safe to call on any valid HKEY that we own.
                    unsafe {
                        let _ = RegCloseKey(self.0);
                    }
                }
            }

            let mut hkey: HKEY = HKEY::default();
            let status = unsafe {
                RegOpenKeyExW(
                    HKEY_LOCAL_MACHINE,
                    w!(r"SYSTEM\CurrentControlSet\Control\BitLockerStatus"),
                    None,
                    KEY_READ,
                    &mut hkey,
                )
            };
            if status.is_err() {
                return Err(EncryptionError::RegistryOpenFailed(format!("{status:?}")));
            }
            // `_key` ensures RegCloseKey is called when this scope exits.
            let _key = RegKey(hkey);

            let mut value: u32 = 0;
            let mut size: u32 = std::mem::size_of::<u32>() as u32;
            let mut value_type = REG_VALUE_TYPE(0);
            let read = unsafe {
                RegQueryValueExW(
                    hkey,
                    w!("BootStatus"),
                    None,
                    Some(&mut value_type),
                    // SAFETY: casting &mut u32 to *mut u8 is valid for a DWORD read;
                    // size is set to sizeof(u32) bytes above. Windows writes exactly
                    // 4 bytes into this buffer for a REG_DWORD value.
                    Some((&mut value as *mut u32).cast::<u8>()),
                    Some(&mut size),
                )
            };
            if read.is_err() || value_type != REG_DWORD {
                return Err(EncryptionError::RegistryReadFailed(format!(
                    "status={read:?} type={value_type:?}"
                )));
            }
            Ok(value)
        }
        #[cfg(not(windows))]
        {
            Err(EncryptionError::RegistryReadFailed(
                "non-Windows build".to_string(),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// spawn_encryption_check_task (public entry point for Plan 34-04)
// ---------------------------------------------------------------------------

/// Spawn the BitLocker verification background task.
///
/// Waits for [`DiskEnumerator::is_ready`], runs an initial verification across
/// all enumerated disks, then loops on `recheck_interval`. Status changes are
/// emitted as `DiskDiscovery` events; a total first-check failure emits one
/// `Alert` (D-16). Subsequent failures are silent (Pitfall E).
///
/// # Arguments
///
/// * `runtime_handle` — tokio runtime `Handle` for spawning the async task.
/// * `audit_ctx` — [`EmitContext`] for audit event emission.
/// * `recheck_interval` — how often to re-verify after the initial check (D-10/D-11).
pub fn spawn_encryption_check_task(
    runtime_handle: tokio::runtime::Handle,
    audit_ctx: crate::audit_emitter::EmitContext,
    recheck_interval: Duration,
) {
    // Default to the production Windows backend (Task 2).
    spawn_encryption_check_task_with_backend(
        runtime_handle,
        audit_ctx,
        recheck_interval,
        Arc::new(WindowsEncryptionBackend),
    );
}

/// Same as [`spawn_encryption_check_task`] but with an injectable backend.
///
/// Used by integration tests in Plan 34-05 to deterministically stub WMI/Registry.
/// The `backend` is captured by the spawned async task and lives for the lifetime
/// of the agent process.
///
/// # Arguments
///
/// * `runtime_handle` — tokio runtime `Handle`.
/// * `audit_ctx` — [`EmitContext`] for audit event emission.
/// * `recheck_interval` — period between re-checks (D-10).
/// * `backend` — the [`EncryptionBackend`] implementation to use (arc-shared
///   because the task may fan out concurrent `spawn_blocking` calls).
pub fn spawn_encryption_check_task_with_backend(
    runtime_handle: tokio::runtime::Handle,
    audit_ctx: crate::audit_emitter::EmitContext,
    recheck_interval: Duration,
    backend: Arc<dyn EncryptionBackend>,
) {
    runtime_handle.spawn(async move {
        // ── Wait for Phase 33 enumeration to finish (D-04) ─────────────
        wait_for_disk_enumerator_ready().await;
        let enumerator = match crate::detection::disk::get_disk_enumerator() {
            Some(e) => e,
            None => {
                error!("DiskEnumerator singleton missing -- encryption check aborted");
                return;
            }
        };

        // ── Initial verification ────────────────────────────────────────
        let disks = enumerator.all_disks();
        if disks.is_empty() {
            info!("no fixed disks enumerated -- encryption verification skipped");
            if let Some(checker) = get_encryption_checker() {
                checker.mark_first_check_complete();
            }
            return;
        }
        run_one_verification_cycle(
            &disks,
            Arc::clone(&backend),
            &audit_ctx,
            /* is_initial = */ true,
        )
        .await;

        // ── Periodic re-check loop (D-10) ───────────────────────────────
        let mut ticker = tokio::time::interval(recheck_interval);
        // Consume the immediate tick — initial check above already ran.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let disks = enumerator.all_disks();
            if disks.is_empty() {
                debug!("periodic encryption check: no disks");
                continue;
            }
            run_one_verification_cycle(
                &disks,
                Arc::clone(&backend),
                &audit_ctx,
                /* is_initial = */ false,
            )
            .await;
        }
    });
}

/// Poll [`crate::detection::disk::get_disk_enumerator`] / `is_ready`
/// until enumeration completes (D-04). Sleeps 250 ms between polls to
/// avoid spinning the CPU.
async fn wait_for_disk_enumerator_ready() {
    loop {
        if let Some(e) = crate::detection::disk::get_disk_enumerator() {
            if e.is_ready() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Run one full verification cycle across all disks.
///
/// On `is_initial == true` and total failure: emit one Alert (D-16/D-16a).
/// On any cycle with status changes: emit a `DiskDiscovery` with
/// `justification = "encryption status changed: ..."` (D-25).
/// Unchanged statuses silently update only `encryption_checked_at` (D-12).
///
/// # Arguments
///
/// * `disks` — snapshot of all enumerated disks from `DiskEnumerator.all_disks()`.
/// * `backend` — the [`EncryptionBackend`] to call per disk.
/// * `audit_ctx` — context for audit emission.
/// * `is_initial` — `true` on the first call after startup (controls Alert gate).
async fn run_one_verification_cycle(
    disks: &[DiskIdentity],
    backend: Arc<dyn EncryptionBackend>,
    audit_ctx: &crate::audit_emitter::EmitContext,
    is_initial: bool,
) {
    // ── Fan-out per-disk WMI queries (Pattern A) ────────────────────────
    let mut new_statuses: HashMap<String, EncryptionStatus> = HashMap::new();
    let mut new_methods: HashMap<String, EncryptionMethod> = HashMap::new();
    let mut failed: Vec<(String, String)> = Vec::new();

    // Fan-out per-disk WMI queries: one spawn per disk (COM is per-thread, Pitfall A).
    // CR-01 fix: store instance_id alongside the JoinHandle so a task panic (which
    // consumes the return value) cannot silently drop a disk from new_statuses. Using
    // Vec<(id, JoinHandle)> instead of JoinSet retains the id regardless of panic.
    type DiskHandleResult = Result<(EncryptionStatus, Option<EncryptionMethod>), EncryptionError>;
    let mut handles: Vec<(
        String,
        Option<char>,
        tokio::task::JoinHandle<DiskHandleResult>,
    )> = Vec::with_capacity(disks.len());

    for disk in disks {
        let id = disk.instance_id.clone();
        let letter = disk.drive_letter;
        let backend_clone = Arc::clone(&backend);
        let handle = tokio::task::spawn(async move {
            match letter {
                Some(l) => check_one_disk(l, Arc::clone(&backend_clone)).await,
                None => Err(EncryptionError::VolumeNotFound),
            }
        });
        handles.push((id, letter, handle));
    }

    for (id, _letter, handle) in handles {
        match handle.await {
            Ok(Ok((status, method))) => {
                new_statuses.insert(id.clone(), status);
                if let Some(m) = method {
                    new_methods.insert(id, m);
                }
            }
            Ok(Err(e)) => {
                // D-01a: namespace-unavailable triggers Registry fallback (boot disk only).
                // CR-02: try_registry_fallback calls blocking Win32 Registry APIs
                // (RegOpenKeyExW / RegQueryValueExW). Wrap in spawn_blocking so the
                // tokio executor thread is not stalled. Identical protection to the
                // WMI path in check_one_disk (Pitfall A).
                let resolved = if e.warrants_registry_fallback() {
                    let backend_clone = Arc::clone(&backend);
                    let id_clone = id.clone();
                    let disks_vec = disks.to_vec();
                    let fallback_task = tokio::task::spawn_blocking(move || {
                        try_registry_fallback(&id_clone, &disks_vec, backend_clone)
                    });
                    match tokio::time::timeout(Duration::from_secs(2), fallback_task).await {
                        Ok(Ok(status)) => status,
                        Ok(Err(_join_err)) => EncryptionStatus::Unknown,
                        Err(_elapsed) => EncryptionStatus::Unknown,
                    }
                } else {
                    EncryptionStatus::Unknown
                };
                new_statuses.insert(id.clone(), resolved);
                if resolved == EncryptionStatus::Unknown {
                    failed.push((id, e.to_string()));
                }
            }
            Err(join_err) => {
                // CR-01: The id is preserved in the outer Vec so it is always
                // recoverable here, even when the spawned async block panics and the
                // return value is lost. Insert Unknown so the disk is not silently
                // dropped from new_statuses, which would cause encryption_checked_at
                // to advance falsely (WR-01) and all_failed to misfire (WR-02).
                error!(error = %join_err, "encryption check task panicked -- disk status unknown");
                new_statuses.insert(id.clone(), EncryptionStatus::Unknown);
                failed.push((id, format!("task panicked: {join_err}")));
            }
        }
    }

    // ── Update DiskEnumerator state in place (D-20) ─────────────────────
    let now = Utc::now();
    if let Some(enumerator) = crate::detection::disk::get_disk_enumerator() {
        let mut discovered = enumerator.discovered_disks.write();
        let mut id_map = enumerator.instance_id_map.write();
        let mut letter_map = enumerator.drive_letter_map.write();
        for d in discovered.iter_mut() {
            if let Some(s) = new_statuses.get(&d.instance_id).copied() {
                d.encryption_status = Some(s);
            }
            if let Some(m) = new_methods.get(&d.instance_id).copied() {
                d.encryption_method = Some(m);
            }
            // WR-01: Only update timestamp if this disk was actually checked this cycle.
            // Disks absent from new_statuses (e.g. due to CR-01 task panic) must not
            // receive a fresh timestamp that would falsely indicate a successful check.
            if new_statuses.contains_key(&d.instance_id) {
                d.encryption_checked_at = Some(now);
            }
        }
        // Re-sync the secondary maps to keep them consistent with discovered_disks.
        for d in discovered.iter() {
            id_map.insert(d.instance_id.clone(), d.clone());
            if let Some(l) = d.drive_letter {
                letter_map.insert(l, d.clone());
            }
        }
    }

    // ── Update EncryptionChecker cache + flags ──────────────────────────
    let old_snapshot = if let Some(c) = get_encryption_checker() {
        let snap = c.encryption_status_map.read().clone();
        *c.encryption_status_map.write() = new_statuses.clone();
        *c.last_check_at.write() = Some(now);
        snap
    } else {
        HashMap::new()
    };

    // ── Decide whether to emit ──────────────────────────────────────────
    let transitions = compute_changed_transitions(&old_snapshot, &new_statuses);
    // WR-02: Guard against vacuous-truth: if new_statuses is empty (all tasks
    // panicked at the JoinSet level), .all() returns true on an empty iterator.
    // That would emit a misleading total-failure alert with no per-disk details.
    let all_failed = !disks.is_empty()
        && !new_statuses.is_empty()
        && new_statuses
            .values()
            .all(|s| *s == EncryptionStatus::Unknown);

    if is_initial && all_failed {
        // D-16/D-16a: single Alert on initial total failure.
        emit_total_failure_alert(audit_ctx, &failed);
    }

    if !transitions.is_empty() {
        // D-25: status-change DiskDiscovery with combined justification.
        let updated_disks = if let Some(enumerator) = crate::detection::disk::get_disk_enumerator()
        {
            enumerator.all_disks()
        } else {
            disks.to_vec()
        };
        let mut justification = build_change_justification(&transitions);
        if !failed.is_empty() {
            let unknown_lines = build_unknown_justification(&failed);
            justification.push('\n');
            justification.push_str(&unknown_lines);
        }
        emit_status_change_discovery(audit_ctx, &updated_disks, justification);
    }

    // ── Pitfall E: flip is_first_check after the FIRST attempt regardless of outcome ─
    if let Some(checker) = get_encryption_checker() {
        checker.mark_first_check_complete();
    }
}

/// Try the Registry fallback for the boot disk only.
///
/// Returns `EncryptionStatus::Unknown` if the disk is not the boot disk
/// or if the Registry read fails. Per D-01a, the fallback is best-effort
/// for the boot volume only — non-boot disks cannot be inferred from the
/// single `BootStatus` DWORD.
///
/// # Arguments
///
/// * `instance_id` — instance ID of the disk to check.
/// * `disks` — full disk list (used to check `is_boot_disk`).
/// * `backend` — the [`EncryptionBackend`] to use for the Registry read.
fn try_registry_fallback(
    instance_id: &str,
    disks: &[DiskIdentity],
    backend: Arc<dyn EncryptionBackend>,
) -> EncryptionStatus {
    let is_boot = disks
        .iter()
        .find(|d| d.instance_id == instance_id)
        .map(|d| d.is_boot_disk)
        .unwrap_or(false);
    if !is_boot {
        return EncryptionStatus::Unknown;
    }
    match backend.read_boot_status_registry() {
        Ok(0) => EncryptionStatus::Unencrypted,
        Ok(1) => EncryptionStatus::Encrypted,
        Ok(other) => {
            debug!(
                value = other,
                "unexpected BootStatus DWORD -- treating as Unknown"
            );
            EncryptionStatus::Unknown
        }
        Err(e) => {
            warn!(error = %e, "registry fallback failed");
            EncryptionStatus::Unknown
        }
    }
}

/// Per-disk WMI query wrapped in `spawn_blocking` + `tokio::time::timeout` (Pitfall A + B).
///
/// `spawn_blocking` gives the WMI call a dedicated OS thread so COM per-thread
/// initialization is valid. `timeout` ensures a single wedged volume cannot
/// stall the JoinSet for more than 5 s.
///
/// # Arguments
///
/// * `drive_letter` — uppercase drive letter (e.g., `'C'`).
/// * `backend` — the [`EncryptionBackend`] to call (arc-cloned into the blocking task).
async fn check_one_disk(
    drive_letter: char,
    backend: Arc<dyn EncryptionBackend>,
) -> Result<(EncryptionStatus, Option<EncryptionMethod>), EncryptionError> {
    let task = tokio::task::spawn_blocking(move || backend.query_volume(drive_letter));
    match tokio::time::timeout(Duration::from_secs(5), task).await {
        Ok(Ok(inner)) => inner,
        Ok(Err(join_err)) => Err(EncryptionError::TaskPanicked(join_err.to_string())),
        Err(_elapsed) => {
            warn!(drive_letter = %drive_letter, "WMI query timeout (5s) -- yielding Unknown");
            Err(EncryptionError::Timeout)
        }
    }
}

/// Emit a `DiskDiscovery` event on encryption status change (D-25).
///
/// Sets `justification = "encryption status changed: ..."` for SIEM correlation.
fn emit_status_change_discovery(
    ctx: &crate::audit_emitter::EmitContext,
    disks: &[DiskIdentity],
    justification: String,
) {
    use dlp_common::{Action, AuditEvent, Classification, Decision, EventType};
    let mut event = AuditEvent::new(
        EventType::DiskDiscovery,
        ctx.user_sid.clone(),
        ctx.user_name.clone(),
        "disk://encryption-status-change".to_string(),
        Classification::T1,
        Action::READ,
        Decision::ALLOW,
        ctx.agent_id.clone(),
        ctx.session_id,
    )
    .with_discovered_disks(Some(disks.to_vec()))
    .with_justification(justification);
    crate::audit_emitter::emit_audit(ctx, &mut event);
}

/// Emit an `Alert` event when all disks fail verification on the first check (D-16/D-16a).
///
/// This fires at most once per agent cold-start (Pitfall E — subsequent poll
/// failures stay quiet because `is_first_check` is flipped to `false` after
/// this initial attempt).
fn emit_total_failure_alert(ctx: &crate::audit_emitter::EmitContext, failed: &[(String, String)]) {
    use dlp_common::{Action, AuditEvent, Classification, Decision, EventType};
    let justification = format!(
        "BitLocker verification failed for ALL disks at startup:\n{}",
        build_unknown_justification(failed)
    );
    let mut event = AuditEvent::new(
        EventType::Alert,
        ctx.user_sid.clone(),
        ctx.user_name.clone(),
        "encryption://verification-failed".to_string(),
        Classification::T4,
        Action::READ,
        Decision::DENY,
        ctx.agent_id.clone(),
        ctx.session_id,
    )
    .with_justification(justification);
    crate::audit_emitter::emit_audit(ctx, &mut event);
}

// ---------------------------------------------------------------------------
// Unit tests (platform-agnostic — no WMI or Registry calls)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Test 1: parse_drive_letter ──────────────────────────────────────

    #[test]
    fn test_parse_drive_letter() {
        assert_eq!(parse_drive_letter("C:"), Some('C'));
        assert_eq!(parse_drive_letter("e:"), Some('E'));
        assert_eq!(parse_drive_letter(""), None);
        assert_eq!(parse_drive_letter("3:"), None);
        // Only the first character is considered (Pitfall C guard).
        assert_eq!(parse_drive_letter("CD:"), Some('C'));
    }

    // ── Test 2: derive_encryption_status truth table ────────────────────

    #[test]
    fn test_derive_encryption_status_truth_table() {
        // Protected + fully encrypted -> Encrypted.
        assert_eq!(
            derive_encryption_status(Some(1), Some(1)),
            EncryptionStatus::Encrypted
        );
        // Unprotected + fully encrypted -> Suspended (key protectors disabled).
        assert_eq!(
            derive_encryption_status(Some(0), Some(1)),
            EncryptionStatus::Suspended
        );
        // Fully decrypted -> Unencrypted.
        assert_eq!(
            derive_encryption_status(Some(0), Some(0)),
            EncryptionStatus::Unencrypted
        );
        // Encrypting/decrypting/paused rows all -> Unencrypted.
        assert_eq!(
            derive_encryption_status(Some(0), Some(2)),
            EncryptionStatus::Unencrypted
        );
        assert_eq!(
            derive_encryption_status(Some(0), Some(3)),
            EncryptionStatus::Unencrypted
        );
        assert_eq!(
            derive_encryption_status(Some(0), Some(4)),
            EncryptionStatus::Unencrypted
        );
        assert_eq!(
            derive_encryption_status(Some(0), Some(5)),
            EncryptionStatus::Unencrypted
        );
        // ProtectionStatus == 2 (Unknown) with any ConversionStatus -> Unknown.
        assert_eq!(
            derive_encryption_status(Some(2), Some(0)),
            EncryptionStatus::Unknown
        );
        assert_eq!(
            derive_encryption_status(Some(2), None),
            EncryptionStatus::Unknown
        );
        // Both None (D-14 defensive default) -> Unknown.
        assert_eq!(
            derive_encryption_status(None, None),
            EncryptionStatus::Unknown
        );
        // Unrecognized combination -> Unknown (defensive).
        assert_eq!(
            derive_encryption_status(Some(99), Some(99)),
            EncryptionStatus::Unknown
        );
        // WR-05: Protected + FullyDecrypted transient state (key-protector re-enablement)
        // must map to Unknown per D-14. Explicit arm added to prevent future maintainer
        // from assuming the catch-all is unreachable and adding a panic there.
        assert_eq!(
            derive_encryption_status(Some(1), Some(0)),
            EncryptionStatus::Unknown,
            "Protected + FullyDecrypted transient state must map to Unknown"
        );
    }

    // ── Test 3: EncryptionChecker default state ─────────────────────────

    #[test]
    fn test_encryption_checker_default() {
        let c = EncryptionChecker::new();
        assert!(!c.is_ready(), "fresh checker should not be ready");
        assert!(
            c.is_first_check(),
            "fresh checker should be in first-check state"
        );
        assert!(
            c.encryption_status_map.read().is_empty(),
            "fresh checker should have empty map"
        );
        assert!(
            c.last_check_at.read().is_none(),
            "fresh checker should have no timestamp"
        );
    }

    // ── Test 4: global singleton roundtrip ──────────────────────────────

    #[test]
    fn test_global_static_get_set() {
        // OnceLock is process-global; set_encryption_checker is let _ = .set()
        // so re-runs after first set are no-ops. We only assert the singleton
        // holds the expected first-check invariant.
        let c = Arc::new(EncryptionChecker::new());
        set_encryption_checker(Arc::clone(&c));
        let fetched = get_encryption_checker().expect("singleton must be set after set call");
        assert!(
            fetched.is_first_check(),
            "freshly-set checker should still be in first-check state"
        );
    }

    // ── Test 5: status_for_instance_id after seed ───────────────────────

    #[test]
    fn test_status_lookup_after_update() {
        let c = EncryptionChecker::new();
        assert_eq!(
            c.status_for_instance_id("X"),
            None,
            "unknown ID should return None"
        );
        c.seed_for_test("X", EncryptionStatus::Encrypted);
        assert_eq!(
            c.status_for_instance_id("X"),
            Some(EncryptionStatus::Encrypted),
            "seeded ID should return the seeded value"
        );
    }

    // ── Test 6: compute_changed_transitions — changed statuses ──────────

    #[test]
    fn test_compute_changed_transitions_unchanged_excluded() {
        let mut old = HashMap::new();
        old.insert("A".to_string(), EncryptionStatus::Encrypted);
        old.insert("B".to_string(), EncryptionStatus::Unencrypted);
        let mut new_snap = HashMap::new();
        new_snap.insert("A".to_string(), EncryptionStatus::Encrypted); // unchanged
        new_snap.insert("B".to_string(), EncryptionStatus::Suspended); // changed

        let trans = compute_changed_transitions(&old, &new_snap);
        assert_eq!(trans.len(), 1, "only changed disks should be returned");
        assert_eq!(trans[0].instance_id, "B");
        assert_eq!(trans[0].old, Some(EncryptionStatus::Unencrypted));
        assert_eq!(trans[0].new, EncryptionStatus::Suspended);
    }

    // ── Test 7: Pitfall D — None vs Some(Unknown) ───────────────────────

    #[test]
    fn test_compute_changed_transitions_first_observation_is_change() {
        // Pitfall D: None -> Some(Unknown) IS a transition (first observation).
        let old: HashMap<String, EncryptionStatus> = HashMap::new();
        let mut new_snap = HashMap::new();
        new_snap.insert("X".to_string(), EncryptionStatus::Unknown);
        let trans = compute_changed_transitions(&old, &new_snap);
        assert_eq!(
            trans.len(),
            1,
            "first observation of any status should be a transition"
        );
        assert_eq!(trans[0].old, None);
        assert_eq!(trans[0].new, EncryptionStatus::Unknown);
    }

    #[test]
    fn test_compute_changed_transitions_unknown_to_unknown_is_unchanged() {
        // Pitfall D: Some(Unknown) -> Some(Unknown) is NOT a transition.
        let mut old = HashMap::new();
        old.insert("X".to_string(), EncryptionStatus::Unknown);
        let mut new_snap = HashMap::new();
        new_snap.insert("X".to_string(), EncryptionStatus::Unknown);
        let trans = compute_changed_transitions(&old, &new_snap);
        assert!(
            trans.is_empty(),
            "Unknown -> Unknown should NOT be a transition"
        );
    }

    // ── Test 8: Pitfall E — mark_first_check_complete idempotency ───────

    #[test]
    fn test_mark_first_check_complete_idempotent() {
        let c = EncryptionChecker::new();
        assert!(c.is_first_check(), "should start as first check");
        c.mark_first_check_complete();
        assert!(!c.is_first_check(), "should flip after first call");
        assert!(c.is_ready(), "should be ready after first call");
        // Idempotent — calling twice does not re-set the flag.
        c.mark_first_check_complete();
        assert!(
            !c.is_first_check(),
            "flag should remain false on second call"
        );
        assert!(c.is_ready(), "should still be ready on second call");
    }

    // ── Test 9: build_unknown_justification ─────────────────────────────

    #[test]
    fn test_build_unknown_justification() {
        let failed = vec![
            ("A".to_string(), "WMI timeout".to_string()),
            ("B".to_string(), "namespace unavailable".to_string()),
        ];
        let s = build_unknown_justification(&failed);
        assert!(s.contains("A: WMI timeout"));
        assert!(s.contains("B: namespace unavailable"));
        assert_eq!(s.lines().count(), 2, "one line per failed disk");
    }

    // ── Test 10: build_change_justification ─────────────────────────────

    #[test]
    fn test_build_change_justification() {
        let trans = vec![StatusTransition {
            instance_id: "X".to_string(),
            old: Some(EncryptionStatus::Suspended),
            new: EncryptionStatus::Encrypted,
        }];
        let s = build_change_justification(&trans);
        assert!(
            s.starts_with("encryption status changed:"),
            "prefix must match D-25"
        );
        assert!(
            s.contains("X suspended -> encrypted"),
            "transition must be readable"
        );
    }

    // ── Test 11: warrants_registry_fallback gate ─────────────────────────

    #[test]
    fn test_warrants_registry_fallback() {
        assert!(
            EncryptionError::WmiNamespaceUnavailable("x".into()).warrants_registry_fallback(),
            "namespace unavailable should trigger fallback"
        );
        assert!(
            !EncryptionError::WmiQueryFailed("x".into()).warrants_registry_fallback(),
            "query failure should NOT trigger fallback"
        );
        assert!(
            !EncryptionError::Timeout.warrants_registry_fallback(),
            "timeout should NOT trigger fallback"
        );
        assert!(
            !EncryptionError::RegistryOpenFailed("x".into()).warrants_registry_fallback(),
            "registry failure should NOT trigger fallback"
        );
    }
}
