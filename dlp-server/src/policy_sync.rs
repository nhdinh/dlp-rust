//! Push policies to dlp-server replicas (P5-T07).
//!
//! When a policy is created, updated, or deleted via the admin API,
//! this module pushes the change to all configured dlp-server
//! replicas so they evaluate with the latest rules.

use dlp_common::abac::Policy;
use reqwest::Client;

/// Synchronizes policies to remote dlp-server replicas.
///
/// Reads replica URLs from the `DLP_SERVER_REPLICAS` environment
/// variable (comma-separated). If not set, sync calls are no-ops.
#[derive(Debug, Clone)]
pub struct PolicySyncer {
    /// List of dlp-server replica base URLs.
    replicas: Vec<String>,
    /// Shared HTTP client.
    client: Client,
}

/// Error type for policy sync operations.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// An HTTP request to a replica failed.
    #[error("sync HTTP error for {url}: {source}")]
    Http {
        /// The replica URL that failed.
        url: String,
        /// The underlying reqwest error.
        source: reqwest::Error,
    },

    /// A replica returned a non-success status code.
    #[error("replica {url} returned {status}: {body}")]
    ReplicaError {
        /// The replica URL.
        url: String,
        /// HTTP status code.
        status: u16,
        /// Response body text.
        body: String,
    },
}

impl PolicySyncer {
    /// Constructs a `PolicySyncer` from environment variables.
    ///
    /// Reads `DLP_SERVER_REPLICAS` as a comma-separated list of
    /// base URLs (e.g., `http://pe1:8080,http://pe2:8080`).
    pub fn from_env() -> Self {
        let replicas: Vec<String> = std::env::var("DLP_SERVER_REPLICAS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        if !replicas.is_empty() {
            tracing::info!(count = replicas.len(), "policy sync replicas configured");
        }

        Self {
            replicas,
            client: Client::new(),
        }
    }

    /// Pushes a policy to all replicas via `PUT /policies/{id}`.
    ///
    /// # Arguments
    ///
    /// * `policy` - The policy to create or update on each replica.
    ///
    /// # Errors
    ///
    /// Returns the first error encountered. All replicas are attempted
    /// even if some fail.
    pub async fn sync_policy(&self, policy: &Policy) -> Result<(), SyncError> {
        let mut first_error: Option<SyncError> = None;

        for base_url in &self.replicas {
            let url = format!("{}/policies/{}", base_url, policy.id);

            let result = self.client.put(&url).json(policy).send().await;

            match result {
                Ok(resp) if resp.status().is_success() => {
                    tracing::info!(
                        replica = %base_url,
                        policy_id = %policy.id,
                        "policy synced"
                    );
                }
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let body = resp.text().await.unwrap_or_default();
                    let err = SyncError::ReplicaError {
                        url: url.clone(),
                        status,
                        body,
                    };
                    tracing::error!("{err}");
                    if first_error.is_none() {
                        first_error = Some(err);
                    }
                }
                Err(e) => {
                    let err = SyncError::Http {
                        url: url.clone(),
                        source: e,
                    };
                    tracing::error!("{err}");
                    if first_error.is_none() {
                        first_error = Some(err);
                    }
                }
            }
        }

        match first_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Deletes a policy from all replicas via `DELETE /policies/{id}`.
    ///
    /// # Arguments
    ///
    /// * `id` - The policy ID to delete.
    ///
    /// # Errors
    ///
    /// Returns the first error encountered.
    pub async fn delete_policy(&self, id: &str) -> Result<(), SyncError> {
        let mut first_error: Option<SyncError> = None;

        for base_url in &self.replicas {
            let url = format!("{}/policies/{}", base_url, id);

            let result = self.client.delete(&url).send().await;

            match result {
                Ok(resp) if resp.status().is_success() => {
                    tracing::info!(
                        replica = %base_url,
                        policy_id = %id,
                        "policy deleted from replica"
                    );
                }
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let body = resp.text().await.unwrap_or_default();
                    let err = SyncError::ReplicaError {
                        url: url.clone(),
                        status,
                        body,
                    };
                    tracing::error!("{err}");
                    if first_error.is_none() {
                        first_error = Some(err);
                    }
                }
                Err(e) => {
                    let err = SyncError::Http {
                        url: url.clone(),
                        source: e,
                    };
                    tracing::error!("{err}");
                    if first_error.is_none() {
                        first_error = Some(err);
                    }
                }
            }
        }

        match first_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_replicas() {
        let syncer = PolicySyncer {
            replicas: Vec::new(),
            client: Client::new(),
        };
        assert!(syncer.replicas.is_empty());
    }

    #[test]
    fn test_parse_replicas() {
        let raw = "http://pe1:8080, http://pe2:8080, ";
        let replicas: Vec<String> = raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        assert_eq!(replicas.len(), 2);
        assert_eq!(replicas[0], "http://pe1:8080");
        assert_eq!(replicas[1], "http://pe2:8080");
    }
}
