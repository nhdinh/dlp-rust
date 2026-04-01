//! File interception engine (T-11).
//!
//! Monitors file system operations on the endpoint by subscribing to the
//! `Microsoft-Windows-FileSystem-ETW` trace session.  Captures CreateFile,
//! WriteFile, DeleteFile, and Rename/Move operations in real time and
//! forwards them as [`FileAction`] events to the registered callback.

pub mod file_monitor;
pub mod policy_mapper;

pub use file_monitor::{FileAction, InterceptionEngine};
pub use policy_mapper::PolicyMapper;
