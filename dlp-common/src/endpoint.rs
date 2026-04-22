//! Endpoint-identity types shared across the v0.6.0 enforcement tracks (APP, USB, BRW).
//!
//! This module defines the wire-format and internal types that identify
//! applications (`AppIdentity`, `AppTrustTier`, `SignatureState`) and USB
//! devices (`DeviceIdentity`, `UsbTrustTier`). All types derive `serde`
//! Serialize/Deserialize and are safe to include in JSON wire payloads
//! (`EvaluateRequest`, `AuditEvent`, `Pipe3UiMsg::ClipboardAlert`).
//!
//! ## Defaults (Default Deny principle -- CLAUDE.md section 3.1)
//!
//! * `UsbTrustTier::default()` -> `Blocked` (unknown device = most restrictive).
//! * `AppTrustTier::default()` -> `Unknown` (callers treat as untrusted).
//! * `SignatureState::default()` -> `Unknown` (callers treat as unsigned).
//!
//! ## Wire format
//!
//! * `UsbTrustTier` serializes as `"blocked"`, `"read_only"`, `"full_access"` to match
//!   the Phase 24 `device_registry.trust_tier` DB CHECK constraint (REQUIREMENTS.md USB-02).
//! * `AppTrustTier` serializes as `"trusted"`, `"untrusted"`, `"unknown"`.
//! * `SignatureState` serializes as `"valid"`, `"invalid"`, `"not_signed"`, `"unknown"`.

use serde::{Deserialize, Serialize};

/// The Authenticode signature verification result for a process image.
///
/// Populated by Phase 25's `WinVerifyTrust` caller. `Unknown` is the safe
/// default and must be treated as untrusted by downstream policy evaluators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SignatureState {
    /// Authenticode signature is cryptographically valid.
    Valid,
    /// Authenticode signature is present but invalid (tampered, revoked, or expired).
    Invalid,
    /// No Authenticode signature is present on the binary.
    NotSigned,
    /// Signature state could not be determined (default -- safe untrusted).
    #[default]
    Unknown,
}

/// Application trust tier -- distinct from [`UsbTrustTier`].
///
/// Assigned by the publisher-verification pipeline in Phase 25.
/// `Unknown` is the default and is treated as untrusted by the policy evaluator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AppTrustTier {
    /// Publisher matches a trusted publisher list entry (Phase 25).
    Trusted,
    /// Publisher does not match any trusted entry.
    Untrusted,
    /// Trust tier has not been resolved (default -- treat as untrusted).
    #[default]
    Unknown,
}

/// USB device trust tier.
///
/// Serialized as the exact strings `"blocked"`, `"read_only"`, `"full_access"`
/// to match the Phase 24 `device_registry.trust_tier` DB `CHECK` constraint
/// (REQUIREMENTS.md USB-02). `Blocked` is the default for unknown devices
/// (Default Deny -- CLAUDE.md section 3.1).
///
/// `PartialOrd`/`Ord` are derived so Phase 26 enforcement code can express
/// `tier >= UsbTrustTier::ReadOnly` comparisons. The ordering is
/// `Blocked < ReadOnly < FullAccess` (variant declaration order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UsbTrustTier {
    /// All I/O to this device is denied (default for unknown devices).
    #[default]
    Blocked,
    /// Reads allowed; writes denied.
    ReadOnly,
    /// Full read/write access.
    FullAccess,
}

/// Resolved identity of a running application on the endpoint.
///
/// Constructed by Phase 25's clipboard-time resolver:
/// `GetForegroundWindow` -> `QueryFullProcessImageNameW` -> `WinVerifyTrust`.
///
/// All fields are non-optional inside the struct -- an unresolved application
/// is represented as `Option<AppIdentity>::None` at the call site (per D-03).
/// The struct derives `Default` so missing JSON keys yield empty strings
/// and `Unknown` tiers (safe defaults) when `#[serde(default)]` is in effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AppIdentity {
    /// Full NT image path of the process, e.g. `C:\Program Files\App\app.exe`.
    pub image_path: String,
    /// Publisher common name extracted from Authenticode signature, e.g. `Microsoft Corporation`.
    /// Empty string when no valid signature is present.
    pub publisher: String,
    /// Trust tier assigned by the publisher-verification pipeline (Phase 25).
    pub trust_tier: AppTrustTier,
    /// Authenticode verification outcome (Phase 25).
    pub signature_state: SignatureState,
}

/// Captured identity of a USB device.
///
/// Populated by Phase 23's `SetupDiGetClassDevsW` / `SetupDiGetDeviceInstanceIdW`
/// handler on `DBT_DEVICEARRIVAL`. All fields are `String` (not `u16` for VID/PID)
/// to avoid hex-formatting friction at the wire layer (D-06). Phase 24 normalizes
/// these to the DB row format (hex-uppercase strings).
///
/// Devices without a serial number are stored with `serial = "(none)"`
/// (ROADMAP.md Phase 23 Success Criterion 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DeviceIdentity {
    /// USB Vendor ID as a hex string, e.g. `"0951"`.
    pub vid: String,
    /// USB Product ID as a hex string, e.g. `"1666"`.
    pub pid: String,
    /// Device serial number, or `"(none)"` for devices without one.
    pub serial: String,
    /// Human-readable device description from the USB descriptor.
    pub description: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_usb_trust_tier_serde_values() {
        // DB CHECK constraint (REQUIREMENTS.md USB-02) demands exact snake_case values.
        assert_eq!(
            serde_json::to_string(&UsbTrustTier::Blocked).unwrap(),
            "\"blocked\""
        );
        assert_eq!(
            serde_json::to_string(&UsbTrustTier::ReadOnly).unwrap(),
            "\"read_only\""
        );
        assert_eq!(
            serde_json::to_string(&UsbTrustTier::FullAccess).unwrap(),
            "\"full_access\""
        );
    }

    #[test]
    fn test_usb_trust_tier_deserialize_snake_case() {
        let blocked: UsbTrustTier = serde_json::from_str("\"blocked\"").unwrap();
        let read_only: UsbTrustTier = serde_json::from_str("\"read_only\"").unwrap();
        let full_access: UsbTrustTier = serde_json::from_str("\"full_access\"").unwrap();
        assert_eq!(blocked, UsbTrustTier::Blocked);
        assert_eq!(read_only, UsbTrustTier::ReadOnly);
        assert_eq!(full_access, UsbTrustTier::FullAccess);
    }

    #[test]
    fn test_usb_trust_tier_default_is_blocked() {
        assert_eq!(UsbTrustTier::default(), UsbTrustTier::Blocked);
    }

    #[test]
    fn test_usb_trust_tier_ordering() {
        // PartialOrd/Ord derive: Blocked < ReadOnly < FullAccess (declaration order).
        assert!(UsbTrustTier::Blocked < UsbTrustTier::ReadOnly);
        assert!(UsbTrustTier::ReadOnly < UsbTrustTier::FullAccess);
        assert!(UsbTrustTier::FullAccess >= UsbTrustTier::ReadOnly);
    }

    #[test]
    fn test_app_trust_tier_default_is_unknown() {
        assert_eq!(AppTrustTier::default(), AppTrustTier::Unknown);
    }

    #[test]
    fn test_app_trust_tier_serde_values() {
        assert_eq!(
            serde_json::to_string(&AppTrustTier::Trusted).unwrap(),
            "\"trusted\""
        );
        assert_eq!(
            serde_json::to_string(&AppTrustTier::Untrusted).unwrap(),
            "\"untrusted\""
        );
        assert_eq!(
            serde_json::to_string(&AppTrustTier::Unknown).unwrap(),
            "\"unknown\""
        );
    }

    #[test]
    fn test_signature_state_default_is_unknown() {
        assert_eq!(SignatureState::default(), SignatureState::Unknown);
    }

    #[test]
    fn test_signature_state_serde_values() {
        assert_eq!(
            serde_json::to_string(&SignatureState::Valid).unwrap(),
            "\"valid\""
        );
        assert_eq!(
            serde_json::to_string(&SignatureState::Invalid).unwrap(),
            "\"invalid\""
        );
        assert_eq!(
            serde_json::to_string(&SignatureState::NotSigned).unwrap(),
            "\"not_signed\""
        );
        assert_eq!(
            serde_json::to_string(&SignatureState::Unknown).unwrap(),
            "\"unknown\""
        );
    }

    #[test]
    fn test_app_identity_serde_round_trip() {
        let original = AppIdentity {
            image_path: r"C:\Program Files\Contoso\app.exe".to_string(),
            publisher: "Contoso Corporation".to_string(),
            trust_tier: AppTrustTier::Trusted,
            signature_state: SignatureState::Valid,
        };
        let json = serde_json::to_string(&original).unwrap();
        let round_trip: AppIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(original, round_trip);
    }

    #[test]
    fn test_app_identity_deserialize_empty_object() {
        // #[serde(default)] at struct level lets `{}` deserialize with all-default fields.
        let parsed: AppIdentity = serde_json::from_str("{}").unwrap();
        assert_eq!(parsed.image_path, "");
        assert_eq!(parsed.publisher, "");
        assert_eq!(parsed.trust_tier, AppTrustTier::Unknown);
        assert_eq!(parsed.signature_state, SignatureState::Unknown);
    }

    #[test]
    fn test_device_identity_serde_round_trip() {
        let original = DeviceIdentity {
            vid: "0951".to_string(),
            pid: "1666".to_string(),
            serial: "ABCDEF1234".to_string(),
            description: "Kingston DataTraveler 3.0".to_string(),
        };
        let json = serde_json::to_string(&original).unwrap();
        let round_trip: DeviceIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(original, round_trip);
    }

    #[test]
    fn test_device_identity_deserialize_empty_object() {
        let parsed: DeviceIdentity = serde_json::from_str("{}").unwrap();
        assert_eq!(parsed.vid, "");
        assert_eq!(parsed.pid, "");
        assert_eq!(parsed.serial, "");
        assert_eq!(parsed.description, "");
    }

    #[test]
    fn test_device_identity_serial_none_sentinel() {
        // ROADMAP.md Phase 23 SC-2: devices without a serial use "(none)" sentinel.
        let d = DeviceIdentity {
            vid: "046d".to_string(),
            pid: "c52b".to_string(),
            serial: "(none)".to_string(),
            description: "Logitech USB Receiver".to_string(),
        };
        let json = serde_json::to_string(&d).unwrap();
        assert!(json.contains("\"serial\":\"(none)\""));
    }
}
