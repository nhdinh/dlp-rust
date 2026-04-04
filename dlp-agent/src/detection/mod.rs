//! Exfiltration detection modules (Sprint 14, T-13–T-14).
//!
//! Monitors USB mass storage and outbound SMB connections.
//!
//! - [`usb`] — USB mass storage detection via `GetDriveTypeW` (T-13).
//! - [`network_share`] — SMB outbound connection whitelisting (T-14).

pub mod network_share;
pub mod usb;

pub use network_share::{NetworkShareDetector, SmbShareEvent, SmbMonitor};
pub use usb::UsbDetector;
