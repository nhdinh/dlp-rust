//! Chrome Enterprise Connector modules.
//!
//! Provides managed-origins cache and Content Analysis API handler
//! for browser-integrated DLP enforcement (BRW-01, BRW-03).

pub mod cache;
pub mod frame;
pub mod handler;
pub mod proto;
pub mod registry;
