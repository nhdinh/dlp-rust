//! Push agent configuration to endpoints (P5-T13).
//!
//! After an admin updates agent configuration (e.g., monitored paths,
//! classification rules), this module pushes the new config to each
//! registered agent's local HTTP endpoint.

use reqwest::Client;
use serde::{Deserialize, Serialize};

/// Agent-side configuration payload pushed from the server.
///
/// Contains the settings that control agent behavior on the endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// List of directory paths the agent should monitor.
    pub monitored_paths: Vec<String>,
    /// DLP server URL the agent should use for evaluations.
    pub server_url: String,
    /// Heartbeat interval in seconds.
    pub heartbeat_interval_secs: u64,
    /// Whether offline caching is enabled.
    pub offline_cache_enabled: bool,
}

/// Pushes configuration to remote agent endpoints.
///
/// Construct with `ConfigPusher::new()`.
#[derive(Debug, Clone)]
pub struct ConfigPusher {
    /// Shared HTTP client.
    client: Client,
}

/// Error type for config push operations.
#[derive(Debug, thiserror::Error)]
pub enum ConfigPushError {
    /// An HTTP request to an agent failed.
    #[error("config push HTTP error for {url}: {source}")]
    Http {
        /// The agent URL that failed.
        url: String,
        /// The underlying reqwest error.
        source: reqwest::Error,
    },

    /// An agent returned a non-success status code.
    #[error("agent {url} returned {status}")]
    AgentError {
        /// The agent URL.
        url: String,
        /// HTTP status code.
        status: u16,
    },
}

impl ConfigPusher {
    /// Creates a new `ConfigPusher` with a default HTTP client.
    pub fn new() -> Self {
        Self {
            client: Client::new(),
        }
    }

    /// Pushes configuration to a list of agent endpoints.
    ///
    /// Sends `PUT /config` to each agent URL. Errors for individual
    /// agents are logged but do not stop delivery to remaining agents.
    ///
    /// # Arguments
    ///
    /// * `agent_urls` - Base URLs of agent HTTP endpoints.
    /// * `config` - The configuration payload to push.
    ///
    /// # Errors
    ///
    /// Returns the first error encountered across all agents.
    pub async fn push_config(
        &self,
        agent_urls: &[String],
        config: &AgentConfig,
    ) -> Result<(), ConfigPushError> {
        let mut first_error: Option<ConfigPushError> = None;

        for base_url in agent_urls {
            let url = format!("{}/config", base_url);

            let result = self.client.put(&url).json(config).send().await;

            match result {
                Ok(resp) if resp.status().is_success() => {
                    tracing::info!(
                        agent = %base_url,
                        "config pushed"
                    );
                }
                Ok(resp) => {
                    let err = ConfigPushError::AgentError {
                        url: url.clone(),
                        status: resp.status().as_u16(),
                    };
                    tracing::error!("{err}");
                    if first_error.is_none() {
                        first_error = Some(err);
                    }
                }
                Err(e) => {
                    let err = ConfigPushError::Http {
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

impl Default for ConfigPusher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_config_serde() {
        let cfg = AgentConfig {
            monitored_paths: vec![r"C:\Data".to_string(), r"D:\Shared".to_string()],
            server_url: "http://dlp-server:9090".to_string(),
            heartbeat_interval_secs: 30,
            offline_cache_enabled: true,
        };
        let json = serde_json::to_string(&cfg).expect("serialize");
        let rt: AgentConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rt.monitored_paths.len(), 2);
        assert_eq!(rt.heartbeat_interval_secs, 30);
    }

    #[test]
    fn test_config_pusher_default() {
        let pusher = ConfigPusher::default();
        // Just verify it constructs without panic.
        drop(pusher);
    }
}
