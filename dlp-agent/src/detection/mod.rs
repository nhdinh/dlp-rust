//! Exfiltration detection modules (Sprint 14, T-13–T-14).
//!
//! Monitors USB mass storage and outbound SMB connections.
//!
//! - [`usb`] — USB mass storage detection via `GetDriveTypeW` (T-13).
//! - [`network_share`] — SMB outbound connection whitelisting (T-14).

pub mod disk;
pub mod network_share;
pub mod usb;

pub use disk::{
    get_disk_enumerator, set_disk_enumerator, spawn_disk_enumeration_task, DiskEnumerator,
};
pub use network_share::{NetworkShareDetector, SmbMonitor, SmbShareEvent};
pub use usb::UsbDetector;
