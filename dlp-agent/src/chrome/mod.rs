//! Chrome Enterprise Connector modules.
//!
//! Provides managed-origins cache and Content Analysis API handler
//! for browser-integrated DLP enforcement (BRW-01, BRW-03).

#[cfg(windows)]
pub mod cache;

#[cfg(windows)]
pub mod frame;

#[cfg(windows)]
pub mod handler;

#[cfg(windows)]
pub mod proto;

#[cfg(windows)]
pub mod registry;
