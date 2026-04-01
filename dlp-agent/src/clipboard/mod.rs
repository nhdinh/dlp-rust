//! Clipboard interception and content classification (Sprint 16, T-20, F-AGT-17).
//!
//! Monitors clipboard operations via a Windows message hook and classifies
//! clipboard text content against the four-tier sensitivity model (T1–T4).
//!
//! - [`listener`] — `SetWindowsHookExW(WH_GETMESSAGE)` to intercept `WM_PASTE`
//!   and clipboard read events.
//! - [`classifier`] — Regex-based text content classifier that assigns a
//!   provisional classification tier to clipboard text.

pub mod classifier;
pub mod listener;

pub use classifier::ClipboardClassifier;
pub use listener::ClipboardListener;
