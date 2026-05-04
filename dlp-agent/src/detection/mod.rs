//! Exfiltration detection modules (Sprint 14, T-13–T-14; Phase 34–36).
//!
//! Monitors USB mass storage, outbound SMB connections, fixed-disk
//! BitLocker encryption state, and dispatches WM_DEVICECHANGE events.
//!
//! - [`usb`] — USB mass storage detection via `GetDriveTypeW` (T-13).
//! - [`network_share`] — SMB outbound connection whitelisting (T-14).
//! - [`disk`] — Fixed-disk enumeration and in-memory registry (Phase 33).
//! - [`encryption`] — BitLocker verification via WMI + Registry fallback (Phase 34).
//! - [`device_watcher`] — Hidden Win32 window + WM_DEVICECHANGE dispatcher (Phase 36).

pub mod device_watcher;
pub mod disk;
pub mod encryption;
pub mod network_share;
pub mod usb;

pub use device_watcher::{
    extract_disk_instance_id, spawn_device_watcher_task, unregister_device_watcher,
};
pub use disk::{
    get_disk_enumerator, set_disk_enumerator, spawn_disk_enumeration_task, DiskEnumerator,
};
pub use encryption::{
    get_encryption_checker, set_encryption_checker, spawn_encryption_check_task,
    spawn_encryption_check_task_with_backend, EncryptionBackend, EncryptionChecker,
    EncryptionError,
};
pub use network_share::{NetworkShareDetector, SmbMonitor, SmbShareEvent};
pub use usb::UsbDetector;
