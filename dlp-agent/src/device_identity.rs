//! Agent-side device information collection for Phase 64.
//!
//! This module provides Windows API wrappers for collecting MAC addresses,
//! detecting VPN state, checking domain join status, computing a stable
//! device fingerprint, and reading/writing the fingerprint to the registry.
//!
//! All Windows API calls are gated with `#[cfg(windows)]` / `#[cfg(not(windows))]`
//! so the module compiles and tests pass on non-Windows platforms.

use dlp_common::{DeviceHealthStatus, EndpointIdentity};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU8, Ordering};

// ---------------------------------------------------------------------------
// Health state machine (Phase 64)
// ---------------------------------------------------------------------------

/// Current device health status as an atomic u8 (maps to DeviceHealthStatus ordinal).
///
/// Ordinal mapping: 0 = Healthy, 1 = Degraded, 2 = Offline, 3 = Tampered.
/// This ordering matches the derived `Ord` on `DeviceHealthStatus`:
/// Healthy < Degraded < Offline < Tampered.
static HEALTH_STATUS: AtomicU8 = AtomicU8::new(0); // 0 = Healthy

/// Converts a `DeviceHealthStatus` to its u8 ordinal.
fn health_to_u8(h: DeviceHealthStatus) -> u8 {
    match h {
        DeviceHealthStatus::Healthy => 0,
        DeviceHealthStatus::Degraded => 1,
        DeviceHealthStatus::Offline => 2,
        DeviceHealthStatus::Tampered => 3,
    }
}

/// Converts a u8 ordinal to a `DeviceHealthStatus`.
///
/// Values outside the valid range default to `Healthy` (defensive).
fn u8_to_health(v: u8) -> DeviceHealthStatus {
    match v {
        0 => DeviceHealthStatus::Healthy,
        1 => DeviceHealthStatus::Degraded,
        2 => DeviceHealthStatus::Offline,
        3 => DeviceHealthStatus::Tampered,
        _ => DeviceHealthStatus::Healthy,
    }
}

/// Atomically transitions the device health status in memory.
///
/// Returns the previous health status. Emits a tracing log if the status changed.
/// This function does NOT perform registry I/O -- it only updates the in-memory atomic.
/// Callers MUST pair this with a persistence call (see `persist_health_to_registry` or
/// use `transition_health_async` from async contexts).
///
/// All tamper/connectivity detection paths MUST call this function to avoid races.
///
/// # Eventual Consistency Note
///
/// The health status read by `current_health()` is a point-in-time snapshot. Between
/// the read and the heartbeat send, the status may change. This is intentional -- the
/// stale-read window is minimized by calling `current_health()` immediately before
/// serialization, but true snapshot consistency across the full send path is not
/// guaranteed. Consumers MUST treat health status as eventually consistent.
pub fn transition_health(new_status: DeviceHealthStatus) -> DeviceHealthStatus {
    let new_u8 = health_to_u8(new_status);
    let prev_u8 = HEALTH_STATUS.swap(new_u8, Ordering::SeqCst);
    let prev_status = u8_to_health(prev_u8);
    if prev_u8 != new_u8 {
        tracing::info!(prev = ?prev_status, new = ?new_status, "device health status changed");
        emit_health_change_audit_event(prev_status, new_status);
    }
    prev_status
}

/// Emits an audit event for a device health status change.
///
/// Best-effort: errors are logged but not propagated. Audit failures must never
/// interfere with health state transitions.
fn emit_health_change_audit_event(prev: DeviceHealthStatus, new: DeviceHealthStatus) {
    use dlp_common::{Action, AuditEvent, Classification, Decision, EventType};

    let agent_id = std::env::var("DLP_AGENT_ID").unwrap_or_else(|_| "unknown".to_string());
    let mut event = AuditEvent::new(
        EventType::DeviceHealthChange,
        "SYSTEM".to_string(),
        "agent".to_string(),
        format!("{:?} -> {:?}", prev, new),
        Classification::T1,
        Action::PolicyUpdate,
        Decision::ALLOW,
        agent_id,
        0,
    );
    if let Err(e) = crate::audit_emitter::emit(&mut event) {
        tracing::warn!(error = %e, "failed to emit DeviceHealthChange audit event");
    }
}

/// Persists the current health status to the registry.
///
/// Call this after `transition_health` to save state. Sync callers call directly;
/// async callers wrap in `spawn_blocking` via `transition_health_async`.
pub fn persist_health_to_registry() -> anyhow::Result<()> {
    let current = current_health();
    write_health_status_to_registry(&current)
}

/// Async-safe wrapper for health transition + persistence.
///
/// Atomically transitions health in memory, then wraps the registry write in
/// `spawn_blocking` to avoid blocking the async runtime. Use this from the heartbeat
/// loop or other async contexts.
pub async fn transition_health_async(new_status: DeviceHealthStatus) -> DeviceHealthStatus {
    let prev = transition_health(new_status);
    let _ = tokio::task::spawn_blocking(persist_health_to_registry).await;
    prev
}

/// Returns the current device health status.
#[must_use]
pub fn current_health() -> DeviceHealthStatus {
    u8_to_health(HEALTH_STATUS.load(Ordering::SeqCst))
}

/// Reads health status from registry at startup.
///
/// Call this in service.rs init to restore state after restart.
/// Returns `Some(DeviceHealthStatus)` if a valid value was found, `None` otherwise.
#[cfg(windows)]
pub fn read_health_from_registry() -> Option<DeviceHealthStatus> {
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, HKEY_LOCAL_MACHINE, KEY_READ,
    };

    let mut hkey = windows::Win32::System::Registry::HKEY::default();
    let result = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::w!(r"SOFTWARE\DLP\Agent"),
            None,
            KEY_READ,
            &mut hkey,
        )
    };

    if result.is_err() {
        return None;
    }

    let value = read_reg_string(hkey, "health_status");

    unsafe {
        let _ = RegCloseKey(hkey);
    }

    value.and_then(|s| match s.as_str() {
        "healthy" => Some(DeviceHealthStatus::Healthy),
        "degraded" => Some(DeviceHealthStatus::Degraded),
        "offline" => Some(DeviceHealthStatus::Offline),
        "tampered" => Some(DeviceHealthStatus::Tampered),
        _ => None,
    })
}

#[cfg(not(windows))]
pub fn read_health_from_registry() -> Option<DeviceHealthStatus> {
    None
}

/// Writes health status to the registry.
///
/// On Windows, creates/opens `HKLM\SOFTWARE\DLP\Agent` and writes
/// `health_status` as REG_SZ with the snake_case variant name.
///
/// On non-Windows, this is a no-op that returns `Ok(())`.
#[cfg(windows)]
fn write_health_status_to_registry(status: &DeviceHealthStatus) -> anyhow::Result<()> {
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY_LOCAL_MACHINE, KEY_WRITE, REG_SZ,
    };

    let mut hkey = windows::Win32::System::Registry::HKEY::default();
    let result = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::w!(r"SOFTWARE\DLP\Agent"),
            None,
            windows::core::PCWSTR::null(),
            windows::Win32::System::Registry::REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        )
    };

    if result.is_err() {
        return Err(anyhow::anyhow!("RegCreateKeyExW failed: {:?}", result));
    }

    let status_str = serde_json::to_string(status)
        .map_err(|e| anyhow::anyhow!("failed to serialize health status: {e}"))?;
    // serde_json produces quoted string like "healthy" -- strip quotes for REG_SZ
    let status_str = status_str.trim_matches('"');

    let wide: Vec<u16> = status_str
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let wide_bytes = unsafe {
        std::slice::from_raw_parts(
            wide.as_ptr() as *const u8,
            wide.len() * std::mem::size_of::<u16>(),
        )
    };
    let set_result = unsafe {
        RegSetValueExW(
            hkey,
            windows::core::w!("health_status"),
            None,
            REG_SZ,
            Some(wide_bytes),
        )
    };

    unsafe {
        let _ = RegCloseKey(hkey);
    }

    if set_result.is_err() {
        return Err(anyhow::anyhow!("RegSetValueExW failed: {:?}", set_result));
    }

    Ok(())
}

#[cfg(not(windows))]
fn write_health_status_to_registry(_status: &DeviceHealthStatus) -> anyhow::Result<()> {
    Ok(())
}

/// Called by tamper detection subsystems (e.g., Phase 63 hash chain verification).
///
/// Immediately sets health status to `Tampered`. This is a one-way transition --
/// recovery to `Healthy` requires a successful heartbeat (see heartbeat loop).
///
/// NOTE: No caller in this phase. Phase 63 hash chain verification will call this.
/// See Phase 63 plan for the hash chain integrity check that triggers this.
///
/// Dependency: Phase 63 (hash-chain-verification) -- this function is the integration
/// point. When Phase 63 detects a hash chain break, it calls `report_tamper_detected()`.
pub fn report_tamper_detected() {
    let prev = transition_health(DeviceHealthStatus::Tampered);
    if prev != DeviceHealthStatus::Tampered {
        let _ = persist_health_to_registry();
    }
}

// ---------------------------------------------------------------------------
// VPN keyword list
// ---------------------------------------------------------------------------

/// Keywords used to heuristically detect VPN adapters from their description.
///
/// This list is intentionally conservative. A match on any keyword (combined
/// with `IfOperStatusUp` and either `IF_TYPE_TUNNEL` or the keyword match)
/// indicates an active VPN connection.
///
/// # Limitations
///
/// - Custom or enterprise VPNs with generic descriptions may not be detected.
/// - False negatives are possible; defense-in-depth with IP subnet checks
///   (see `get_network_location()`) is recommended.
const VPN_KEYWORDS: &[&str] = &[
    "TAP",
    "WireGuard",
    "OpenVPN",
    "RAS",
    "VPN",
    "Cisco AnyConnect",
    "PANGP",
    "Fortinet",
    "SonicWall",
    "Juniper",
    "Pulse Secure",
];

// ---------------------------------------------------------------------------
// MAC address collection
// ---------------------------------------------------------------------------

/// Collects all physical MAC addresses from active network adapters.
///
/// On Windows, uses `GetAdaptersAddresses` with `AF_UNSPEC` (IPv4 + IPv6) and
/// `GAA_FLAG_INCLUDE_PREFIX`. Filters for adapters that are:
/// - Up and running (`OperStatus == IfOperStatusUp`)
/// - Have a physical address (`PhysicalAddressLength > 0`)
///
/// MACs are normalized to uppercase hex with no separators (e.g. `AABBCCDDEEFF`)
/// and sorted lexicographically before returning.
///
/// On non-Windows, returns a single stub MAC for test compatibility.
#[cfg(windows)]
pub fn collect_mac_addresses() -> Vec<String> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_PREFIX, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::Networking::WinSock::AF_UNSPEC;

    let family = AF_UNSPEC.0 as u32;
    let flags = GAA_FLAG_INCLUDE_PREFIX;

    unsafe {
        let mut buf_size: u32 = 0;
        let _ = GetAdaptersAddresses(family, flags, None, None, &mut buf_size);
        if buf_size == 0 {
            return Vec::new();
        }

        let layout =
            std::alloc::Layout::from_size_align(buf_size as usize, 1).expect("valid layout");
        let buf = std::alloc::alloc(layout) as *mut IP_ADAPTER_ADDRESSES_LH;

        if GetAdaptersAddresses(family, flags, None, Some(&mut *buf), &mut buf_size) != 0 {
            std::alloc::dealloc(buf as *mut u8, layout);
            return Vec::new();
        }

        let mut macs = Vec::new();
        let mut curr = buf;
        while !curr.is_null() {
            let addr = &*curr;
            if addr.OperStatus.0 == 1 && addr.PhysicalAddressLength > 0 {
                // IfOperStatusUp == 1
                let mac_bytes = std::slice::from_raw_parts(
                    addr.PhysicalAddress.as_ptr(),
                    addr.PhysicalAddressLength as usize,
                );
                let mac = mac_bytes
                    .iter()
                    .map(|b| format!("{:02X}", b))
                    .collect::<String>();
                macs.push(mac);
            }
            curr = addr.Next;
        }

        std::alloc::dealloc(buf as *mut u8, layout);
        macs.sort();
        macs
    }
}

#[cfg(not(windows))]
pub fn collect_mac_addresses() -> Vec<String> {
    vec!["000000000000".to_string()]
}

// ---------------------------------------------------------------------------
// VPN detection
// ---------------------------------------------------------------------------

/// Detects whether an active VPN connection is present.
///
/// On Windows, enumerates network adapters via `GetAdaptersAddresses` and
/// checks for adapters that are:
/// - Up and running (`OperStatus == IfOperStatusUp`)
/// - AND either have `IfType == IF_TYPE_TUNNEL` (131) OR their description
///   contains a case-insensitive match against [`VPN_KEYWORDS`].
///
/// Returns `true` if any matching adapter is found.
///
/// On non-Windows, returns `false`.
#[cfg(windows)]
pub fn detect_vpn_active() -> bool {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_PREFIX, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::Networking::WinSock::AF_UNSPEC;

    let family = AF_UNSPEC.0 as u32;
    let flags = GAA_FLAG_INCLUDE_PREFIX;

    unsafe {
        let mut buf_size: u32 = 0;
        let _ = GetAdaptersAddresses(family, flags, None, None, &mut buf_size);
        if buf_size == 0 {
            return false;
        }

        let layout =
            std::alloc::Layout::from_size_align(buf_size as usize, 1).expect("valid layout");
        let buf = std::alloc::alloc(layout) as *mut IP_ADAPTER_ADDRESSES_LH;

        if GetAdaptersAddresses(family, flags, None, Some(&mut *buf), &mut buf_size) != 0 {
            std::alloc::dealloc(buf as *mut u8, layout);
            return false;
        }

        let mut curr = buf;
        while !curr.is_null() {
            let addr = &*curr;
            if addr.OperStatus.0 == 1 {
                // IfOperStatusUp == 1
                let is_tunnel = addr.IfType == 131u32; // IF_TYPE_TUNNEL
                let desc_matches_keyword = addr
                    .Description
                    .to_string()
                    .map(|desc| {
                        let desc_upper = desc.to_uppercase();
                        VPN_KEYWORDS
                            .iter()
                            .any(|kw| desc_upper.contains(&kw.to_uppercase()))
                    })
                    .unwrap_or(false);

                if is_tunnel || desc_matches_keyword {
                    std::alloc::dealloc(buf as *mut u8, layout);
                    return true;
                }
            }
            curr = addr.Next;
        }

        std::alloc::dealloc(buf as *mut u8, layout);
        false
    }
}

#[cfg(not(windows))]
pub fn detect_vpn_active() -> bool {
    false
}

// ---------------------------------------------------------------------------
// Domain join detection
// ---------------------------------------------------------------------------

/// Checks whether the machine is joined to an Active Directory domain.
///
/// On Windows, uses `NetGetJoinInformation` from `Win32_NetworkManagement_NetManagement`.
/// Returns `true` if the join status is `NetSetupDomainName` (3).
///
/// On non-Windows, returns `false`.
#[cfg(windows)]
pub fn get_domain_joined() -> bool {
    use windows::core::PWSTR;
    use windows::Win32::NetworkManagement::NetManagement::{
        NetApiBufferFree, NetGetJoinInformation, NETSETUP_JOIN_STATUS,
    };

    unsafe {
        let mut name_buf = PWSTR::null();
        let mut status = NETSETUP_JOIN_STATUS::default();
        let result = NetGetJoinInformation(None, &mut name_buf, &mut status);
        if result != 0 {
            return false;
        }
        let is_domain_joined = !name_buf.is_null() && status == NETSETUP_JOIN_STATUS(3); // NetSetupDomainName = 3
        if !name_buf.is_null() {
            let _ = NetApiBufferFree(Some(name_buf.as_ptr() as *const _));
        }
        is_domain_joined
    }
}

#[cfg(not(windows))]
pub fn get_domain_joined() -> bool {
    false
}

// ---------------------------------------------------------------------------
// OS version string (stable)
// ---------------------------------------------------------------------------

/// Returns a stable OS version string.
///
/// On Windows, reads `CurrentMajorVersionNumber`, `CurrentMinorVersionNumber`,
/// and `CurrentBuildNumber` from
/// `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`.
///
/// These values are stable across Windows feature updates (unlike
/// `DisplayVersion`, which rotates every feature update). This stability is
/// critical for fingerprint determinism.
///
/// Format: `"{major}.{minor}.{build}"`
///
/// On non-Windows, returns `"non-windows (test)"`.
#[cfg(windows)]
pub fn get_os_version_string() -> String {
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, HKEY_LOCAL_MACHINE, KEY_READ,
    };

    let mut hkey = windows::Win32::System::Registry::HKEY::default();
    let result = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::w!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"),
            None,
            KEY_READ,
            &mut hkey,
        )
    };

    if result.is_err() {
        return std::env::var("OS").unwrap_or_else(|_| "Windows".to_string());
    }

    let major = read_reg_dword(hkey, "CurrentMajorVersionNumber");
    let minor = read_reg_dword(hkey, "CurrentMinorVersionNumber");
    let build = read_reg_string(hkey, "CurrentBuildNumber");

    unsafe {
        let _ = RegCloseKey(hkey);
    }

    match (major, minor, build) {
        (Some(maj), Some(min), Some(bld)) => format!("{}.{}.{}", maj, min, bld),
        _ => std::env::var("OS").unwrap_or_else(|_| "Windows".to_string()),
    }
}

#[cfg(not(windows))]
pub fn get_os_version_string() -> String {
    "non-windows (test)".to_string()
}

// ---------------------------------------------------------------------------
// Install date from registry
// ---------------------------------------------------------------------------

/// Reads the Windows install date from the registry.
///
/// On Windows, reads `InstallDate` (DWORD, Unix epoch seconds) from
/// `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` and converts it to
/// an ISO-8601 date string (e.g. `"2024-01-15"`).
///
/// On non-Windows, returns `None`.
#[cfg(windows)]
pub fn read_install_date_from_registry() -> Option<String> {
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, HKEY_LOCAL_MACHINE, KEY_READ,
    };

    let mut hkey = windows::Win32::System::Registry::HKEY::default();
    let result = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::w!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"),
            None,
            KEY_READ,
            &mut hkey,
        )
    };

    if result.is_err() {
        return None;
    }

    let install_date = read_reg_dword(hkey, "InstallDate");

    unsafe {
        let _ = RegCloseKey(hkey);
    }

    install_date.and_then(|epoch| {
        let dt = chrono::DateTime::from_timestamp(i64::from(epoch), 0)?;
        Some(dt.date_naive().to_string())
    })
}

#[cfg(not(windows))]
pub fn read_install_date_from_registry() -> Option<String> {
    None
}

// ---------------------------------------------------------------------------
// Fingerprint computation
// ---------------------------------------------------------------------------

/// Computes a version-locked device fingerprint from stable hardware attributes.
///
/// The fingerprint is a SHA-256 hash of a version-prefixed string containing:
/// - `hostname`
/// - Sorted MAC addresses (lexicographic order)
/// - Stable OS version string (from [`get_os_version_string`])
/// - Install date string
///
/// The returned value has the format `v1:{64-char lowercase hex}` to allow
/// future format migrations without breaking existing fingerprints.
///
/// # Arguments
///
/// * `hostname` — The machine hostname.
/// * `mac_addresses` — Slice of MAC address strings (will be sorted).
/// * `os_version` — The stable OS version string.
/// * `install_date` — The install date string.
///
/// # Returns
///
/// A version-prefixed SHA-256 hex string.
pub fn compute_fingerprint(
    hostname: &str,
    mac_addresses: &[String],
    os_version: &str,
    install_date: &str,
) -> String {
    let mut macs = mac_addresses.to_vec();
    macs.sort();
    let macs_joined = macs.join(",");
    let preimage = format!(
        "v1:{}|{}|{}|{}",
        hostname, macs_joined, os_version, install_date
    );
    let mut hasher = Sha256::new();
    hasher.update(preimage.as_bytes());
    let hash = hasher.finalize();
    format!("v1:{:x}", hash)
}

// ---------------------------------------------------------------------------
// Registry I/O for fingerprint persistence
// ---------------------------------------------------------------------------

/// Reads the persisted device fingerprint from the registry.
///
/// On Windows, reads `device_fingerprint` (REG_SZ) from
/// `HKLM\SOFTWARE\DLP\Agent`.
///
/// Returns `Some(fingerprint)` on success, `None` on any error.
#[cfg(windows)]
pub fn read_fingerprint_from_registry() -> Option<String> {
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, HKEY_LOCAL_MACHINE, KEY_READ,
    };

    let mut hkey = windows::Win32::System::Registry::HKEY::default();
    let result = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::w!(r"SOFTWARE\DLP\Agent"),
            None,
            KEY_READ,
            &mut hkey,
        )
    };

    if result.is_err() {
        return None;
    }

    let fingerprint = read_reg_string(hkey, "device_fingerprint");

    unsafe {
        let _ = RegCloseKey(hkey);
    }

    fingerprint
}

#[cfg(not(windows))]
pub fn read_fingerprint_from_registry() -> Option<String> {
    None
}

/// Writes the device fingerprint to the registry.
///
/// On Windows, creates/opens `HKLM\SOFTWARE\DLP\Agent` and writes
/// `device_fingerprint` as REG_SZ.
///
/// On non-Windows, this is a no-op that returns `Ok(())`.
#[cfg(windows)]
pub fn write_fingerprint_to_registry(fingerprint: &str) -> anyhow::Result<()> {
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY_LOCAL_MACHINE, KEY_WRITE, REG_SZ,
    };

    let mut hkey = windows::Win32::System::Registry::HKEY::default();
    let result = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::w!(r"SOFTWARE\DLP\Agent"),
            None,
            windows::core::PCWSTR::null(),
            windows::Win32::System::Registry::REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        )
    };

    if result.is_err() {
        return Err(anyhow::anyhow!("RegCreateKeyExW failed: {:?}", result));
    }

    let wide: Vec<u16> = fingerprint
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let wide_bytes = unsafe {
        std::slice::from_raw_parts(
            wide.as_ptr() as *const u8,
            wide.len() * std::mem::size_of::<u16>(),
        )
    };
    let set_result = unsafe {
        RegSetValueExW(
            hkey,
            windows::core::w!("device_fingerprint"),
            None,
            REG_SZ,
            Some(wide_bytes),
        )
    };

    unsafe {
        let _ = RegCloseKey(hkey);
    }

    if set_result.is_err() {
        return Err(anyhow::anyhow!("RegSetValueExW failed: {:?}", set_result));
    }

    Ok(())
}

#[cfg(not(windows))]
pub fn write_fingerprint_to_registry(_fingerprint: &str) -> anyhow::Result<()> {
    Ok(())
}

// ---------------------------------------------------------------------------
// build_endpoint_identity
// ---------------------------------------------------------------------------

/// Builds an [`EndpointIdentity`] by composing all device information functions.
///
/// This function is NOT gated by `#[cfg(windows)]` — it calls the cfg-gated
/// subfunctions which return safe defaults on non-Windows platforms.
///
/// The fingerprint is read from the registry first; if not present, it is
/// computed and written back.
///
/// # Returns
///
/// A fully populated [`EndpointIdentity`] with [`DeviceHealthStatus::Healthy`].
pub fn build_endpoint_identity() -> EndpointIdentity {
    let hostname = std::env::var("COMPUTERNAME")
        .ok()
        .or_else(|| {
            hostname::get()
                .map(|h| h.to_string_lossy().into_owned())
                .ok()
        })
        .unwrap_or_else(|| "unknown".to_string());

    let os_version = get_os_version_string();
    let mac_addresses = collect_mac_addresses();
    let install_date = read_install_date_from_registry().unwrap_or_default();

    let fingerprint = read_fingerprint_from_registry().unwrap_or_else(|| {
        let fp = compute_fingerprint(&hostname, &mac_addresses, &os_version, &install_date);
        if let Err(e) = write_fingerprint_to_registry(&fp) {
            tracing::warn!(error = %e, "failed to write fingerprint to registry");
        }
        fp
    });

    let vpn_active = detect_vpn_active();
    let domain_joined = get_domain_joined();

    EndpointIdentity {
        fingerprint,
        mac_addresses,
        vpn_active,
        domain_joined,
        health_status: current_health(),
    }
}

// ---------------------------------------------------------------------------
// Registry helpers (shared between Windows cfg blocks)
// ---------------------------------------------------------------------------

/// Read a REG_SZ value from an open registry key.
#[cfg(windows)]
fn read_reg_string(
    hkey: windows::Win32::System::Registry::HKEY,
    value_name: &str,
) -> Option<String> {
    use windows::Win32::System::Registry::{RegQueryValueExW, REG_SZ};

    let name_wide: Vec<u16> = value_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut buf = vec![0u8; 512];
    let mut buf_size: u32 = buf.len() as u32;
    let mut reg_type = windows::Win32::System::Registry::REG_VALUE_TYPE(0);

    let result = unsafe {
        RegQueryValueExW(
            hkey,
            windows::core::PCWSTR::from_raw(name_wide.as_ptr()),
            None,
            Some(&mut reg_type),
            Some(buf.as_mut_ptr()),
            Some(&mut buf_size),
        )
    };

    if result.is_err() || reg_type != REG_SZ {
        return None;
    }

    let chars = (buf_size as usize) / 2;
    let u16_slice = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u16, chars) };

    let trimmed = if u16_slice.last() == Some(&0) {
        &u16_slice[..u16_slice.len().saturating_sub(1)]
    } else {
        u16_slice
    };

    Some(String::from_utf16_lossy(trimmed))
}

/// Read a REG_DWORD value from an open registry key.
#[cfg(windows)]
fn read_reg_dword(hkey: windows::Win32::System::Registry::HKEY, value_name: &str) -> Option<u32> {
    use windows::Win32::System::Registry::{RegQueryValueExW, REG_DWORD};

    let name_wide: Vec<u16> = value_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut value: u32 = 0;
    let mut buf_size: u32 = std::mem::size_of::<u32>() as u32;
    let mut reg_type = windows::Win32::System::Registry::REG_VALUE_TYPE(0);

    let result = unsafe {
        RegQueryValueExW(
            hkey,
            windows::core::PCWSTR::from_raw(name_wide.as_ptr()),
            None,
            Some(&mut reg_type),
            Some((&mut value as *mut u32).cast::<u8>()),
            Some(&mut buf_size),
        )
    };

    if result.is_err() || reg_type != REG_DWORD {
        return None;
    }

    Some(value)
}

// ---------------------------------------------------------------------------
// Test-only synchronization lock
// ---------------------------------------------------------------------------

/// Tests that mutate the global HEALTH_STATUS static must be serialised
/// to avoid race conditions.  parking_lot::Mutex is used because it
/// does not poison on panic (unlike std::sync::Mutex).
#[cfg(test)]
pub(crate) static HEALTH_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_fingerprint_deterministic() {
        let fp1 = compute_fingerprint(
            "host1",
            &["AABBCCDDEEFF".to_string(), "001122334455".to_string()],
            "10.0.19045",
            "2024-01-15",
        );
        let fp2 = compute_fingerprint(
            "host1",
            &["AABBCCDDEEFF".to_string(), "001122334455".to_string()],
            "10.0.19045",
            "2024-01-15",
        );
        assert_eq!(fp1, fp2, "same inputs must produce same fingerprint");
    }

    #[test]
    fn test_compute_fingerprint_different_hostnames() {
        let fp1 = compute_fingerprint(
            "host1",
            &["AABBCCDDEEFF".to_string()],
            "10.0.19045",
            "2024-01-15",
        );
        let fp2 = compute_fingerprint(
            "host2",
            &["AABBCCDDEEFF".to_string()],
            "10.0.19045",
            "2024-01-15",
        );
        assert_ne!(
            fp1, fp2,
            "different hostnames must produce different fingerprints"
        );
    }

    #[test]
    fn test_compute_fingerprint_mac_sorting() {
        let macs1 = vec!["ZZZZZZZZZZZZ".to_string(), "000000000000".to_string()];
        let macs2 = vec!["000000000000".to_string(), "ZZZZZZZZZZZZ".to_string()];
        let fp1 = compute_fingerprint("host1", &macs1, "10.0.19045", "2024-01-15");
        let fp2 = compute_fingerprint("host1", &macs2, "10.0.19045", "2024-01-15");
        assert_eq!(fp1, fp2, "MAC order must not affect fingerprint");
    }

    #[test]
    fn test_compute_fingerprint_v1_prefix() {
        let fp = compute_fingerprint(
            "host1",
            &["AABBCCDDEEFF".to_string()],
            "10.0.19045",
            "2024-01-15",
        );
        assert!(
            fp.starts_with("v1:"),
            "fingerprint must start with v1: prefix"
        );
    }

    #[test]
    fn test_compute_fingerprint_stable_os_version() {
        let fp = compute_fingerprint(
            "host1",
            &["AABBCCDDEEFF".to_string()],
            "10.0.19045",
            "2024-01-15",
        );
        assert!(fp.starts_with("v1:"));
        // Verify consistency.
        let fp2 = compute_fingerprint(
            "host1",
            &["AABBCCDDEEFF".to_string()],
            "10.0.19045",
            "2024-01-15",
        );
        assert_eq!(fp, fp2);
    }

    #[test]
    fn test_collect_mac_addresses_non_windows() {
        let macs = collect_mac_addresses();
        assert!(!macs.is_empty(), "must return non-empty MAC list");
        // On Windows, MACs are real; on non-Windows, they are stub.
        // Verify format contract: uppercase hex, no separators.
        for mac in &macs {
            assert!(
                mac.chars().all(|c| c.is_ascii_hexdigit()),
                "MAC must be hex digits only: {}",
                mac
            );
            assert!(
                mac.chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()),
                "MAC must be uppercase: {}",
                mac
            );
        }
    }

    #[test]
    fn test_detect_vpn_active_non_windows() {
        assert!(!detect_vpn_active(), "non-Windows must return false");
    }

    #[test]
    fn test_get_domain_joined_non_windows() {
        assert!(!get_domain_joined(), "non-Windows must return false");
    }

    #[test]
    fn test_build_endpoint_identity() {
        let _guard = HEALTH_TEST_LOCK.lock();
        // Ensure known state before building.
        HEALTH_STATUS.store(0, Ordering::SeqCst);
        let identity = build_endpoint_identity();
        assert!(!identity.fingerprint.is_empty());
        assert!(!identity.mac_addresses.is_empty());
        assert_eq!(identity.health_status, DeviceHealthStatus::Healthy);
    }

    #[test]
    fn test_fingerprint_is_v1_plus_64_hex_chars() {
        let fp = compute_fingerprint(
            "host1",
            &["AABBCCDDEEFF".to_string()],
            "10.0.19045",
            "2024-01-15",
        );
        assert!(fp.starts_with("v1:"));
        let hex_part = &fp[3..];
        assert_eq!(hex_part.len(), 64, "SHA-256 hex must be 64 chars");
        assert!(
            hex_part.chars().all(|c| c.is_ascii_hexdigit()),
            "hex part must contain only hex digits"
        );
    }

    #[test]
    fn test_mac_normalization_uppercase_no_colon() {
        // The stub returns uppercase no-colon; verify the format contract.
        let macs = collect_mac_addresses();
        for mac in &macs {
            assert!(
                mac.chars().all(|c| c.is_ascii_hexdigit()),
                "MAC must be hex digits only: {}",
                mac
            );
            assert!(
                mac.chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()),
                "MAC must be uppercase: {}",
                mac
            );
        }
    }

    #[test]
    fn test_os_version_stable_format() {
        let os = get_os_version_string();
        #[cfg(windows)]
        {
            // Should match "major.minor.build" format.
            let parts: Vec<&str> = os.split('.').collect();
            assert_eq!(parts.len(), 3, "OS version must have 3 dot-separated parts");
            assert!(
                parts.iter().all(|p| p.parse::<u64>().is_ok()),
                "all parts must be numeric"
            );
        }
        #[cfg(not(windows))]
        {
            assert_eq!(os, "non-windows (test)");
        }
    }

    // --- Phase 64: Health state machine tests ---

    #[test]
    fn test_current_health_default() {
        let _guard = HEALTH_TEST_LOCK.lock();
        HEALTH_STATUS.store(0, Ordering::SeqCst);
        assert_eq!(current_health(), DeviceHealthStatus::Healthy);
    }

    #[test]
    fn test_transition_health_healthy_to_degraded() {
        let _guard = HEALTH_TEST_LOCK.lock();
        HEALTH_STATUS.store(0, Ordering::SeqCst);
        let prev = transition_health(DeviceHealthStatus::Degraded);
        assert_eq!(prev, DeviceHealthStatus::Healthy);
        assert_eq!(current_health(), DeviceHealthStatus::Degraded);
    }

    #[test]
    fn test_transition_health_degraded_to_offline() {
        let _guard = HEALTH_TEST_LOCK.lock();
        HEALTH_STATUS.store(1, Ordering::SeqCst);
        let prev = transition_health(DeviceHealthStatus::Offline);
        assert_eq!(prev, DeviceHealthStatus::Degraded);
        assert_eq!(current_health(), DeviceHealthStatus::Offline);
    }

    #[test]
    fn test_transition_health_any_to_healthy() {
        let _guard = HEALTH_TEST_LOCK.lock();
        HEALTH_STATUS.store(2, Ordering::SeqCst);
        let prev = transition_health(DeviceHealthStatus::Healthy);
        assert_eq!(prev, DeviceHealthStatus::Offline);
        assert_eq!(current_health(), DeviceHealthStatus::Healthy);
    }

    #[test]
    fn test_transition_health_tampered() {
        let _guard = HEALTH_TEST_LOCK.lock();
        HEALTH_STATUS.store(0, Ordering::SeqCst);
        let prev = transition_health(DeviceHealthStatus::Tampered);
        assert_eq!(prev, DeviceHealthStatus::Healthy);
        assert_eq!(current_health(), DeviceHealthStatus::Tampered);
    }

    #[test]
    fn test_transition_health_idempotent() {
        let _guard = HEALTH_TEST_LOCK.lock();
        HEALTH_STATUS.store(0, Ordering::SeqCst);
        let prev1 = transition_health(DeviceHealthStatus::Degraded);
        assert_eq!(prev1, DeviceHealthStatus::Healthy);
        let prev2 = transition_health(DeviceHealthStatus::Degraded);
        assert_eq!(prev2, DeviceHealthStatus::Degraded);
        assert_eq!(current_health(), DeviceHealthStatus::Degraded);
    }

    #[test]
    fn test_health_to_u8_roundtrip() {
        assert_eq!(health_to_u8(DeviceHealthStatus::Healthy), 0);
        assert_eq!(health_to_u8(DeviceHealthStatus::Degraded), 1);
        assert_eq!(health_to_u8(DeviceHealthStatus::Offline), 2);
        assert_eq!(health_to_u8(DeviceHealthStatus::Tampered), 3);
    }

    #[test]
    fn test_u8_to_health_roundtrip() {
        assert_eq!(u8_to_health(0), DeviceHealthStatus::Healthy);
        assert_eq!(u8_to_health(1), DeviceHealthStatus::Degraded);
        assert_eq!(u8_to_health(2), DeviceHealthStatus::Offline);
        assert_eq!(u8_to_health(3), DeviceHealthStatus::Tampered);
    }

    #[test]
    fn test_u8_to_health_invalid_defaults_to_healthy() {
        assert_eq!(u8_to_health(255), DeviceHealthStatus::Healthy);
        assert_eq!(u8_to_health(4), DeviceHealthStatus::Healthy);
    }

    #[test]
    fn test_persist_health_to_registry_idempotent() {
        let _guard = HEALTH_TEST_LOCK.lock();
        HEALTH_STATUS.store(0, Ordering::SeqCst);
        transition_health(DeviceHealthStatus::Degraded);
        // Registry write may fail in test environments (non-admin, non-Windows).
        // We only assert it does not panic; success is environment-dependent.
        let _ = persist_health_to_registry();
        let _ = persist_health_to_registry();
    }

    #[test]
    fn test_health_persistence_roundtrip() {
        let _guard = HEALTH_TEST_LOCK.lock();
        HEALTH_STATUS.store(0, Ordering::SeqCst);
        transition_health(DeviceHealthStatus::Offline);
        // Registry write may fail in test environments (non-admin, non-Windows).
        // We only assert it does not panic; roundtrip verification is environment-dependent.
        let write_ok = persist_health_to_registry().is_ok();
        if write_ok {
            let read_back = read_health_from_registry();
            assert_eq!(read_back, Some(DeviceHealthStatus::Offline));
        }
    }

    #[test]
    fn test_report_tamper_detected_sets_tampered() {
        let _guard = HEALTH_TEST_LOCK.lock();
        HEALTH_STATUS.store(0, Ordering::SeqCst);
        report_tamper_detected();
        assert_eq!(current_health(), DeviceHealthStatus::Tampered);
    }

    #[test]
    fn test_report_tamper_detected_idempotent() {
        let _guard = HEALTH_TEST_LOCK.lock();
        HEALTH_STATUS.store(0, Ordering::SeqCst);
        report_tamper_detected();
        assert_eq!(current_health(), DeviceHealthStatus::Tampered);
        // Second call should be a no-op (already Tampered).
        report_tamper_detected();
        assert_eq!(current_health(), DeviceHealthStatus::Tampered);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_transition_health_async_does_not_panic() {
        let _guard = HEALTH_TEST_LOCK.lock();
        HEALTH_STATUS.store(0, Ordering::SeqCst);
        let prev = transition_health_async(DeviceHealthStatus::Degraded).await;
        assert_eq!(prev, DeviceHealthStatus::Healthy);
        assert_eq!(current_health(), DeviceHealthStatus::Degraded);
    }

    #[test]
    fn test_build_endpoint_identity_uses_current_health() {
        let _guard = HEALTH_TEST_LOCK.lock();
        HEALTH_STATUS.store(2, Ordering::SeqCst); // Offline
        let identity = build_endpoint_identity();
        assert_eq!(identity.health_status, DeviceHealthStatus::Offline);
    }

    #[test]
    fn test_health_to_u8_and_u8_to_health_consistency() {
        for (status, expected_u8) in [
            (DeviceHealthStatus::Healthy, 0u8),
            (DeviceHealthStatus::Degraded, 1u8),
            (DeviceHealthStatus::Offline, 2u8),
            (DeviceHealthStatus::Tampered, 3u8),
        ] {
            assert_eq!(health_to_u8(status), expected_u8);
            assert_eq!(u8_to_health(expected_u8), status);
        }
    }
}
