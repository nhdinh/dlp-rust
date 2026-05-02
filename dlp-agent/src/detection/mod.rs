//! Exfiltration detection modules (Sprint 14, T-13–T-14; Phase 34).
//!
//! Monitors USB mass storage, outbound SMB connections, and fixed-disk
//! BitLocker encryption state.
//!
//! - [`usb`] — USB mass storage detection via `GetDriveTypeW` (T-13).
//! - [`network_share`] — SMB outbound connection whitelisting (T-14).
//! - [`disk`] — Fixed-disk enumeration and in-memory registry (Phase 33).
//! - [`encryption`] — BitLocker verification via WMI + Registry fallback (Phase 34).

pub mod disk;
pub mod encryption;
pub mod network_share;
pub mod usb;

pub use disk::{
    get_disk_enumerator, set_disk_enumerator, spawn_disk_enumeration_task, DiskEnumerator,
};
pub use encryption::{
    get_encryption_checker, set_encryption_checker, spawn_encryption_check_task, EncryptionBackend,
    EncryptionChecker, EncryptionError,
};
pub use network_share::{NetworkShareDetector, SmbMonitor, SmbShareEvent};
pub use usb::UsbDetector;
