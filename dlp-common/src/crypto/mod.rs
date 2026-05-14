//! Cryptographic utilities shared across the DLP workspace.
//!
//! Provides DPAPI machine-scope encryption for agent-side offline queue.

#[cfg(windows)]
pub mod dpapi;

#[cfg(windows)]
pub use dpapi::{dpapi_protect_machine, dpapi_unprotect_machine, DpapiError};
