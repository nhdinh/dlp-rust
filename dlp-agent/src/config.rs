//! Agent runtime configuration (F-AGT-12).
//!
//! Loads monitoring configuration from a TOML file at
//! [`DEFAULT_CONFIG_PATH`].  If the file is missing or unparseable the
//! agent falls back to built-in defaults (all drives, built-in exclusions
//! only).
//!
//! ## Config file format
//!
//! ```toml
//! # DLP Server URL (required for remote deployments).
//! # If omitted, defaults to http://127.0.0.1:9090.
//! server_url = 'http://10.0.1.5:9090'
//!
//! # Folders to monitor recursively.  Empty list = all drives A-Z.
//! monitored_paths = [
//!     'C:\Data\',
//!     'C:\Confidential\',
//! ]
//!
//! # Additional folders to exclude (case-insensitive substring match).
//! # These are MERGED with the built-in exclusions, not replacing them.
//! excluded_paths = [
//!     'C:\BuildOutput\',
//! ]
//! ```

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// Default config file location.
pub const DEFAULT_CONFIG_PATH: &str = r"C:\ProgramData\DLP\agent-config.toml";

/// Agent runtime configuration.
///
/// Controls which directories the file monitor watches and which paths
/// are excluded from monitoring.
///
/// # Defaults
///
/// - `monitored_paths`: empty (= watch all mounted drives A-Z)
/// - `excluded_paths`: empty (= only built-in exclusions apply)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AgentConfig {
    /// DLP Server URL for agent-to-server communication.
    ///
    /// When empty or omitted, the agent reads `DLP_SERVER_URL` env var,
    /// then falls back to `http://127.0.0.1:9090`.
    #[serde(default)]
    pub server_url: Option<String>,

    /// Directories to watch recursively.
    ///
    /// When empty the agent monitors all mounted drives (A-Z).
    /// When non-empty only these directories are watched.
    #[serde(default)]
    pub monitored_paths: Vec<String>,

    /// Additional exclusion prefixes (case-insensitive substring match).
    ///
    /// These are merged with the built-in exclusion list — they do not
    /// replace it.  Use this to suppress noisy directories that are not
    /// relevant to DLP enforcement (e.g., build output, IDE caches).
    #[serde(default)]
    pub excluded_paths: Vec<String>,

    /// Machine hostname, resolved once at startup.
    /// Not persisted to the config file.
    #[serde(skip)]
    pub machine_name: Option<String>,
}

impl AgentConfig {
    /// Loads configuration from a TOML file.
    ///
    /// Returns [`Default`] if the file does not exist (first-run scenario).
    /// Logs a warning and returns [`Default`] if the file exists but cannot
    /// be parsed.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the TOML config file.
    pub fn load(path: &Path) -> Self {
        if !path.exists() {
            info!(
                path = %path.display(),
                "config file not found — using defaults"
            );
            return Self::default();
        }

        let raw = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    path = %path.display(),
                    error = %e,
                    "failed to read config — using defaults"
                );
                return Self::default();
            }
        };

        // Strip UTF-8 BOM if present (PowerShell 5 writes one by default).
        let content = raw.strip_prefix('\u{FEFF}').unwrap_or(&raw);

        match toml::from_str::<Self>(content) {
            Ok(config) => {
                info!(
                    path = %path.display(),
                    server_url = ?config.server_url,
                    monitored = config.monitored_paths.len(),
                    excluded = config.excluded_paths.len(),
                    "agent config loaded"
                );
                config
            }
            Err(e) => {
                warn!(
                    path = %path.display(),
                    error = %e,
                    "failed to parse config — using defaults"
                );
                Self::default()
            }
        }
    }

    /// Loads configuration from the default path ([`DEFAULT_CONFIG_PATH`]).
    pub fn load_default() -> Self {
        Self::load(Path::new(DEFAULT_CONFIG_PATH))
    }

    /// Returns the resolved list of paths to watch.
    ///
    /// If `monitored_paths` is empty, returns all existing drive roots
    /// (A:\ through Z:\).  Otherwise returns the configured paths.
    pub fn resolve_watch_paths(&self) -> Vec<PathBuf> {
        if self.monitored_paths.is_empty() {
            // Default: all mounted drives.
            (b'A'..=b'Z')
                .map(|letter| PathBuf::from(format!("{}:\\", letter as char)))
                .filter(|p| p.exists())
                .collect()
        } else {
            self.monitored_paths.iter().map(PathBuf::from).collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AgentConfig::default();
        assert!(config.monitored_paths.is_empty());
        assert!(config.excluded_paths.is_empty());
    }

    #[test]
    fn test_load_missing_file_returns_default() {
        let config = AgentConfig::load(Path::new(r"C:\nonexistent\config.toml"));
        assert_eq!(config, AgentConfig::default());
    }

    #[test]
    fn test_deserialize_toml() {
        let toml_str = r#"
            monitored_paths = ['C:\Data\', 'D:\Shares\']
            excluded_paths = ['C:\BuildOutput\']
        "#;
        let config: AgentConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.monitored_paths, vec![r"C:\Data\", r"D:\Shares\"]);
        assert_eq!(config.excluded_paths, vec![r"C:\BuildOutput\"]);
    }

    #[test]
    fn test_deserialize_server_url() {
        let toml_str = "server_url = 'http://10.0.1.5:9090'\n";
        let config: AgentConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.server_url.as_deref(), Some("http://10.0.1.5:9090"));
    }

    #[test]
    fn test_bom_stripped_before_parse() {
        // Simulate a UTF-8 BOM prefix (PowerShell 5 writes this).
        let toml_str = "\u{FEFF}server_url = 'http://10.0.1.5:9090'\n";
        let content = toml_str.strip_prefix('\u{FEFF}').unwrap_or(toml_str);
        let config: AgentConfig = toml::from_str(content).unwrap();
        assert_eq!(config.server_url.as_deref(), Some("http://10.0.1.5:9090"));
    }

    #[test]
    fn test_deserialize_empty_toml() {
        let config: AgentConfig = toml::from_str("").unwrap();
        assert!(config.monitored_paths.is_empty());
        assert!(config.excluded_paths.is_empty());
    }

    #[test]
    fn test_deserialize_partial_toml() {
        let toml_str = r#"
            monitored_paths = ['C:\Restricted\']
        "#;
        let config: AgentConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.monitored_paths, vec![r"C:\Restricted\"]);
        assert!(config.excluded_paths.is_empty());
    }

    #[test]
    fn test_resolve_watch_paths_default() {
        let config = AgentConfig::default();
        let paths = config.resolve_watch_paths();
        // Should return at least C:\
        assert!(!paths.is_empty());
        assert!(paths.iter().any(|p| p.to_string_lossy().starts_with("C:")));
    }

    #[test]
    fn test_resolve_watch_paths_configured() {
        let config = AgentConfig {
            server_url: None,
            monitored_paths: vec![r"C:\Data\".to_string()],
            excluded_paths: Vec::new(),
            machine_name: None,
        };
        let paths = config.resolve_watch_paths();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], PathBuf::from(r"C:\Data\"));
    }
}
