//! Exfiltration detection modules (Sprint 14, T-13–T-15).
//!
//! Monitors USB mass storage, outbound SMB connections, and ETW bypass attempts.
//!
//! - [`usb`] — USB mass storage detection via WMI volume-change events (T-13).
//! - [`network_share`] — SMB outbound connection detection via ETW (T-14).
//! - [`etw_bypass`] — ETW bypass detection for file operations missed by hooks (T-15).

pub mod etw_bypass;
pub mod network_share;
pub mod usb;

pub use etw_bypass::EtwBypassDetector;
pub use network_share::NetworkShareDetector;
pub use usb::UsbDetector;
