//! Process identity resolution and Authenticode verification.
//!
//! This module provides Win32-backed helpers for resolving window handles to
//! `AppIdentity` structs. Used by `clipboard_monitor` to populate
//! `source_application` and `destination_application` in `ClipboardAlert`.

pub mod app_identity;
