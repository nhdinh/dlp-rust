//! `dlp-common` — Shared types for the Enterprise DLP System.
//!
//! This crate contains all types that are shared between the Policy Engine,
//! dlp-agent, and dlp-server components. It has no runtime dependencies
//! and is designed to be a pure type library.

pub mod abac;
pub mod ad_client;
pub mod audit;
pub mod classification;
pub mod classifier;

pub use abac::*;
pub use ad_client::{get_device_trust, get_network_location, AdClient, AdClientError, LdapConfig};
pub use audit::*;
pub use classification::*;
pub use classifier::classify_text;
