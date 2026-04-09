//! Error types for the ABAC policy engine subsystem.
//!
//! These were previously in the `policy-engine` crate. Now that the engine
//! lives inside `dlp-server`, they are defined here and converted into
//! the top-level [`crate::AppError`] at the HTTP boundary.

use thiserror::Error;

/// Errors that can occur during ABAC policy evaluation.
#[derive(Debug, Error)]
pub enum PolicyEngineError {
    /// No matching policy was found for the request.
    #[error("no matching policy found")]
    NoMatchingPolicy,

    /// The policy store is unavailable or unreadable.
    #[error("policy store error: {0}")]
    PolicyStoreError(String),

    /// A policy failed validation during load or reload.
    #[error("policy validation error: {0}")]
    PolicyValidationError(String),

    /// The requested policy does not exist.
    #[error("policy not found: {0}")]
    PolicyNotFound(String),

    /// Active Directory lookup failed.
    #[error("AD lookup failed: {0}")]
    AdError(String),

    /// The AD cache is unavailable.
    #[error("AD cache error: {0}")]
    AdCacheError(String),

    /// A file system operation failed.
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// A JSON serialization or deserialization error.
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// The policy store watcher encountered an error.
    #[error("watcher error: {0}")]
    WatcherError(String),

    /// Internal error used for invariants that should never be violated.
    #[error("internal error: {0}")]
    Internal(String),
}

/// Errors specific to the AD LDAP client.
#[derive(Debug, Error)]
pub enum AdClientError {
    /// The AD server could not be reached.
    #[error("AD connection failed to {0}: {1}")]
    ConnectionFailed(String, String),

    /// DNS resolution for the AD server hostname failed.
    #[error("DNS resolution failed for {0}: {1}")]
    DnsResolutionError(String, String),

    /// The LDAP bind (authentication) failed.
    #[error("LDAP bind failed: {0}")]
    BindFailed(String),

    /// A LDAP search or attribute query failed.
    #[error("AD query failed: {0}")]
    AdQueryError(String),

    /// The LDAP connection could not be initialised.
    #[error("LDAP init error: {0}")]
    LdapInitError(String),

    /// The async task for a blocking LDAP operation panicked.
    #[error("task join error: {0}")]
    TaskJoinError(String),
}

impl From<AdClientError> for PolicyEngineError {
    fn from(e: AdClientError) -> Self {
        match e {
            AdClientError::ConnectionFailed(_, _)
            | AdClientError::BindFailed(_)
            | AdClientError::AdQueryError(_)
            | AdClientError::LdapInitError(_)
            | AdClientError::DnsResolutionError(_, _)
            | AdClientError::TaskJoinError(_) => Self::AdError(e.to_string()),
        }
    }
}

impl PolicyEngineError {
    /// Returns `true` if this error represents a client-facing HTTP 4xx
    /// condition.
    #[must_use]
    pub fn is_client_error(&self) -> bool {
        matches!(
            self,
            Self::PolicyNotFound(_)
                | Self::PolicyValidationError(_)
                | Self::JsonError(_)
        )
    }
}

/// Converts a [`PolicyEngineError`] into the top-level [`crate::AppError`].
impl From<PolicyEngineError> for crate::AppError {
    fn from(err: PolicyEngineError) -> Self {
        match err {
            PolicyEngineError::PolicyNotFound(ref id) => {
                crate::AppError::NotFound(format!(
                    "policy not found: {id}"
                ))
            }
            _ if err.is_client_error() => {
                crate::AppError::BadRequest(err.to_string())
            }
            _ => {
                crate::AppError::Internal(anyhow::anyhow!(err))
            }
        }
    }
}

/// Result type alias using `PolicyEngineError`.
pub type Result<T> = std::result::Result<T, PolicyEngineError>;
