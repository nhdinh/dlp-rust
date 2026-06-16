//! `dlp-common` -- Shared types for the Enterprise DLP System.
//!
//! This crate contains all types that are shared between the Policy Engine,
//! dlp-agent, and dlp-server components. It has no runtime dependencies
//! and is designed to be a pure type library.

pub mod abac;
pub mod ad_client;
pub mod approval;
pub mod audit;
pub mod classification;
pub mod classifier;
pub mod crypto;
pub mod disk;
pub mod endpoint;
pub mod hash;
pub mod hook_ipc;
pub mod label;
pub mod path_hash;
pub mod usb;

pub use abac::*;
pub use ad_client::{
    get_device_trust, get_network_location, AdClient, AdClientError, LdapBindCredentials,
    LdapConfig,
};
pub use approval::*;
pub use audit::*;
pub use classification::*;
pub use classifier::classify_text;
pub use disk::{
    enumerate_fixed_disks, get_boot_drive_letter, is_usb_bridged, BusType, DiskError, DiskIdentity,
    EncryptionMethod, EncryptionStatus,
};
pub use endpoint::{
    AppIdentity, AppTrustTier, DeviceHealthStatus, DeviceIdentity, EndpointIdentity,
    SignatureState, UsbTrustTier,
};
pub use hash::fnv1a_64;
pub use hook_ipc::{HookRequest, HookResponse};
pub use label::{Label, LabelState, ObjectType, Tier};
pub use path_hash::{normalize_path, nt_path_to_dos_path, path_hash};
pub use usb::{
    enumerate_connected_usb_devices, parse_usb_device_path, DEFAULT_USB_BLOCKED_FAILURE_MODE,
    DEFAULT_USB_NONE_SERIAL_POLICY, DEFAULT_USB_STARTUP_RESOLUTION_MODE, USB_FAILURE_MODES,
    USB_NONE_SERIAL_POLICIES, USB_RESOLUTION_MODES,
};
