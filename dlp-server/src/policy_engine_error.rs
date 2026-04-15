//! Error types emitted by the policy engine layer.

use thiserror::Error;

/// Errors that can occur during policy engine operations.
#[derive(Debug, Error)]
pub enum PolicyEngineError {
    /// The requested policy was not found.
    #[error("policy not found: {0}")]
    PolicyNotFound(String),
}
