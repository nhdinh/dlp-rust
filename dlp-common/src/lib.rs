//! `dlp-common` — Shared types for the Enterprise DLP System.
//!
//! This crate contains all types that are shared between the Policy Engine,
//! dlp-agent, and dlp-server components. It has no runtime dependencies
//! and is designed to be a pure type library.

pub mod abac;
pub mod audit;
pub mod classification;

pub use abac::*;
pub use audit::*;
pub use classification::*;
