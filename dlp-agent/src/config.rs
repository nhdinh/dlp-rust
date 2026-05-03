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
//! # Minimum log level written to C:\ProgramData\DLP\logs\dlp-agent.log.
//! # Accepted values (case-insensitive): trace, debug, info, warn, error.
//! # Default (when omitted): trace — all log lines are written.
//! log_level = 'info'
//!
//! # Folders to monitor recursively.  Empty list = all drives A-Z.
//! monitored_paths = [
//!     'C:\Data\',
//!     'C:\Confidential\',
//! ]
//!
//! # Additional folders to exclude (case-insensitive substring match).
//! # These are MERGED with the built-in exclusions, not replacing them.
//! #
//! # Built-in exclusions (always active, not configurable):
//! #   \appdata\           — all per-user app caches, browser data, IDE state
//! #   c:\windows\         — OS internals
//! #   c:\programdata\     — system service data (includes DLP audit logs)
//! #   c:\program files\   — installed application binaries
//! #   c:\$recycle.bin\    — recycle bin
//! #
//! # Use excluded_paths to suppress additional noisy directories:
//! excluded_paths = [
//!     'C:\BuildOutput\',
//!     'C:\Users\dev\node_modules\',
//! ]
//!
//! # Heartbeat interval in seconds (populated by server config push).
//! heartbeat_interval_secs = 30
//!
//! # Whether offline event caching is enabled (populated by server config push).
//! offline_cache_enabled = true
//! ```

use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// Default config file location.
pub const DEFAULT_CONFIG_PATH: &str = r"C:\ProgramData\DLP\agent-config.toml";

/// Default re-check interval for BitLocker encryption verification (D-11).
/// 6 hours (21,600 seconds).
pub const ENCRYPTION_RECHECK_DEFAULT_SECS: u64 = 21_600;

/// Minimum valid `[encryption].recheck_interval_secs` (D-11). 5 minutes.
/// Values below this are clamped up and a `warn!` log line is emitted at load time.
pub const ENCRYPTION_RECHECK_MIN_SECS: u64 = 300;

/// Maximum valid `[encryption].recheck_interval_secs` (D-11). 24 hours.
/// Values above this are clamped down and a `warn!` log line is emitted at load time.
pub const ENCRYPTION_RECHECK_MAX_SECS: u64 = 86_400;

/// Phase 34 BitLocker re-check cadence (D-11).
///
/// Loaded from the `[encryption]` section of `agent-config.toml`. The
/// section may be omitted entirely; defaults are applied at use site.
///
/// # Example
///
/// ```toml
/// [encryption]
/// recheck_interval_secs = 21600   # 6h default; clamped to [300, 86400]
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct EncryptionConfig {
    /// Periodic BitLocker re-check interval in seconds.
    ///
    /// `None` implies use of [`ENCRYPTION_RECHECK_DEFAULT_SECS`] (21,600 s = 6 h).
    /// Out-of-range values are clamped to `[ENCRYPTION_RECHECK_MIN_SECS,
    /// ENCRYPTION_RECHECK_MAX_SECS]` and a `warn!` log is emitted at the
    /// time `AgentConfig::resolved_recheck_interval()` is called.
    #[serde(default)]
    pub recheck_interval_secs: Option<u64>,
}

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

    /// Heartbeat interval in seconds. When `None`, the agent uses its
    /// compiled default (30 seconds). Populated by server config push.
    #[serde(default)]
    pub heartbeat_interval_secs: Option<u64>,

    /// Whether offline event caching is enabled. When `None`, defaults
    /// to `true`. Populated by server config push.
    #[serde(default)]
    pub offline_cache_enabled: Option<bool>,

    /// Minimum log level for the rolling log file.
    ///
    /// Accepted values (case-insensitive): `"trace"`, `"debug"`, `"info"`,
    /// `"warn"`, `"error"`. When `None` or omitted the agent defaults to
    /// `TRACE` so every log line is visible — useful for diagnosing issues
    /// without redeploying the binary.
    ///
    /// Set to `"info"` for production deployments to reduce log volume.
    #[serde(default)]
    pub log_level: Option<String>,

    /// Phase 34 BitLocker verification settings (D-11).
    ///
    /// When the `[encryption]` section is absent, defaults are applied at
    /// use site via [`AgentConfig::resolved_recheck_interval`].
    #[serde(default)]
    pub encryption: EncryptionConfig,

    /// LDAP/AD configuration for group resolution. When `None`, AD features
    /// are disabled (fallback to placeholder identity values). Populated by
    /// server config push and persisted to the TOML config file.
    #[serde(default)]
    pub ldap_config: Option<crate::server_client::LdapConfigPayload>,

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

    /// Loads configuration from the effective config path.
    ///
    /// Checks the `DLP_CONFIG_PATH` environment variable first.  If set and
    /// non-empty, that path is used; otherwise falls back to [`DEFAULT_CONFIG_PATH`].
    ///
    /// This allows integration tests to redirect the agent to a temp directory
    /// without requiring admin privileges or touching the production config file.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// // In a test: set DLP_CONFIG_PATH to a temp file before spawning the agent.
    /// std::env::set_var("DLP_CONFIG_PATH", "/tmp/test/agent-config.toml");
    /// ```
    pub fn load_default() -> Self {
        Self::load(Path::new(&Self::effective_config_path()))
    }

    /// Returns the config file path honoring the `DLP_CONFIG_PATH` env override.
    ///
    /// Used by both [`load_default`] and the config poll loop's save path.
    pub fn effective_config_path() -> String {
        std::env::var("DLP_CONFIG_PATH")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_CONFIG_PATH.to_string())
    }

    /// Persists the current config to a TOML file.
    ///
    /// All fields (including `server_url` and server-pushed fields) are
    /// written. `machine_name` is `#[serde(skip)]` and will not appear.
    ///
    /// # Arguments
    ///
    /// * `path` - Destination path (typically [`DEFAULT_CONFIG_PATH`]).
    ///
    /// # Errors
    ///
    /// Returns an error if TOML serialization or file write fails.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let toml_str = toml::to_string(self).context("failed to serialize AgentConfig to TOML")?;
        std::fs::write(path, toml_str)
            .with_context(|| format!("failed to write config to {}", path.display()))?;
        Ok(())
    }

    /// Returns the [`tracing::Level`] configured by `log_level`.
    ///
    /// Parses the `log_level` string case-insensitively.  Unknown values and
    /// `None` both resolve to [`tracing::Level::TRACE`] so that all diagnostic
    /// output is visible by default.
    ///
    /// # Examples
    ///
    /// ```
    /// use dlp_agent::config::AgentConfig;
    /// let cfg = AgentConfig { log_level: Some("info".to_string()), ..Default::default() };
    /// assert_eq!(cfg.resolved_log_level(), tracing::Level::INFO);
    /// ```
    pub fn resolved_log_level(&self) -> tracing::Level {
        match self
            .log_level
            .as_deref()
            .unwrap_or("trace")
            .to_ascii_lowercase()
            .as_str()
        {
            "error" => tracing::Level::ERROR,
            "warn" => tracing::Level::WARN,
            "info" => tracing::Level::INFO,
            "debug" => tracing::Level::DEBUG,
            _ => tracing::Level::TRACE,
        }
    }

    /// Returns the clamped BitLocker re-check interval as a [`std::time::Duration`].
    ///
    /// # Behavior (D-11)
    ///
    /// - `None` defaults to [`ENCRYPTION_RECHECK_DEFAULT_SECS`] (6 hours).
    /// - In-range values pass through unchanged.
    /// - Out-of-range values are clamped to `[ENCRYPTION_RECHECK_MIN_SECS,
    ///   ENCRYPTION_RECHECK_MAX_SECS]` and a `warn!` log line is emitted.
    ///   The agent does NOT refuse to start on bad input — it logs and continues
    ///   with the clamped value (CONTEXT.md D-11 explicit).
    ///
    /// # Returns
    ///
    /// A [`std::time::Duration`] in the range `[300s, 86400s]`.
    pub fn resolved_recheck_interval(&self) -> std::time::Duration {
        // Unwrap the Option<u64>, defaulting to 6 hours when the field is absent.
        // In Rust, `unwrap_or` on Option<T> returns the contained value or the
        // provided default — analogous to Python's `value or default`.
        let raw = self
            .encryption
            .recheck_interval_secs
            .unwrap_or(ENCRYPTION_RECHECK_DEFAULT_SECS);

        // `clamp` is a Rust built-in that bounds a value within [min, max],
        // equivalent to `max(min, min(value, max))` in Python.
        let clamped = raw.clamp(ENCRYPTION_RECHECK_MIN_SECS, ENCRYPTION_RECHECK_MAX_SECS);

        if clamped != raw {
            warn!(
                requested = raw,
                applied = clamped,
                min = ENCRYPTION_RECHECK_MIN_SECS,
                max = ENCRYPTION_RECHECK_MAX_SECS,
                "encryption.recheck_interval_secs out of range -- clamped"
            );
        }
        std::time::Duration::from_secs(clamped)
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
            heartbeat_interval_secs: None,
            offline_cache_enabled: None,
            log_level: None,
            encryption: EncryptionConfig::default(),
            ldap_config: None,
            machine_name: None,
        };
        let paths = config.resolve_watch_paths();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], PathBuf::from(r"C:\Data\"));
    }

    #[test]
    fn test_agent_config_new_fields_default() {
        let config = AgentConfig::default();
        assert!(config.heartbeat_interval_secs.is_none());
        assert!(config.offline_cache_enabled.is_none());
    }

    #[test]
    fn test_agent_config_new_fields_deserialize() {
        let toml_str = "heartbeat_interval_secs = 60\noffline_cache_enabled = false\n";
        let config: AgentConfig = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(config.heartbeat_interval_secs, Some(60u64));
        assert_eq!(config.offline_cache_enabled, Some(false));
    }

    #[test]
    fn test_agent_config_save_roundtrip() {
        // Write a fully-populated config to a temp file and load it back.
        let original = AgentConfig {
            server_url: Some("http://10.0.1.5:9090".to_string()),
            monitored_paths: vec![r"C:\Data\".to_string()],
            excluded_paths: vec![r"C:\Temp\".to_string()],
            heartbeat_interval_secs: Some(45),
            offline_cache_enabled: Some(true),
            log_level: Some("info".to_string()),
            encryption: EncryptionConfig::default(),
            ldap_config: None,
            // machine_name is #[serde(skip)] — not written or loaded
            machine_name: Some("MY-PC".to_string()),
        };

        let tmp_path = std::env::temp_dir().join("test_agent_config_save_roundtrip.toml");
        original.save(&tmp_path).expect("save should succeed");

        let loaded = AgentConfig::load(&tmp_path);
        let _ = std::fs::remove_file(&tmp_path);

        // machine_name is skip-serialized so it will be None after reload.
        let expected = AgentConfig {
            machine_name: None,
            ..original
        };
        assert_eq!(loaded, expected);
    }

    #[test]
    fn test_agent_config_save_preserves_server_url() {
        let config = AgentConfig {
            server_url: Some("http://10.0.1.5:9090".to_string()),
            monitored_paths: Vec::new(),
            excluded_paths: Vec::new(),
            heartbeat_interval_secs: None,
            offline_cache_enabled: None,
            log_level: None,
            encryption: EncryptionConfig::default(),
            ldap_config: None,
            machine_name: None,
        };

        let tmp_path = std::env::temp_dir().join("test_agent_config_save_server_url.toml");
        config.save(&tmp_path).expect("save should succeed");

        let contents = std::fs::read_to_string(&tmp_path).expect("read back");
        let _ = std::fs::remove_file(&tmp_path);

        assert!(
            contents.contains("server_url"),
            "TOML must contain server_url; got:\n{contents}"
        );
        assert!(contents.contains("10.0.1.5"));
    }

    #[test]
    fn test_agent_config_backwards_compatible() {
        // A TOML without the new fields must still parse successfully.
        let toml_str = r#"
            monitored_paths = ['C:\Restricted\']
        "#;
        let config: AgentConfig = toml::from_str(toml_str).expect("backwards-compat parse");
        assert_eq!(config.monitored_paths, vec![r"C:\Restricted\"]);
        assert!(config.heartbeat_interval_secs.is_none());
        assert!(config.offline_cache_enabled.is_none());
    }

    #[test]
    fn test_resolved_log_level_none_defaults_to_trace() {
        let config = AgentConfig::default();
        assert_eq!(config.resolved_log_level(), tracing::Level::TRACE);
    }

    #[test]
    fn test_resolved_log_level_known_values() {
        for (input, expected) in [
            ("trace", tracing::Level::TRACE),
            ("debug", tracing::Level::DEBUG),
            ("info", tracing::Level::INFO),
            ("warn", tracing::Level::WARN),
            ("error", tracing::Level::ERROR),
            ("INFO", tracing::Level::INFO),
            ("Warn", tracing::Level::WARN),
        ] {
            let config = AgentConfig {
                log_level: Some(input.to_string()),
                ..Default::default()
            };
            assert_eq!(config.resolved_log_level(), expected, "input: {input}");
        }
    }

    #[test]
    fn test_resolved_log_level_unknown_falls_back_to_trace() {
        let config = AgentConfig {
            log_level: Some("verbose".to_string()),
            ..Default::default()
        };
        assert_eq!(config.resolved_log_level(), tracing::Level::TRACE);
    }

    #[test]
    fn test_disk_allowlist_backwards_compat() {
        // A TOML config from before Phase 35 (no [[disk_allowlist]] section)
        // must still parse and yield an empty allowlist.
        let toml_str = r#"
            monitored_paths = ['C:\Restricted\']
        "#;
        let config: AgentConfig = toml::from_str(toml_str).expect("backwards-compat parse");
        assert!(config.disk_allowlist.is_empty());
        // Sanity: existing fields still parse correctly.
        assert_eq!(config.monitored_paths, vec![r"C:\Restricted\"]);
    }

    #[test]
    fn test_disk_allowlist_toml_roundtrip() {
        // Round-trip an AgentConfig with two DiskIdentity entries through TOML.
        // Covers Pitfall 3 (drive_letter Option<char> in TOML) and D-06
        // (disconnected disk -- drive_letter is None).
        use dlp_common::{BusType, DiskIdentity};

        let original = AgentConfig {
            disk_allowlist: vec![
                DiskIdentity {
                    instance_id: "PCIIDE\\IDECHANNEL\\4&1234".to_string(),
                    bus_type: BusType::Sata,
                    model: "WDC WD10EZEX-00BN5A0".to_string(),
                    drive_letter: Some('C'),
                    serial: Some("WD-12345678".to_string()),
                    size_bytes: Some(1_000_204_886_016),
                    is_boot_disk: true,
                    encryption_status: None,
                    encryption_method: None,
                    encryption_checked_at: None,
                },
                DiskIdentity {
                    // Disconnected disk: drive_letter = None per D-06.
                    instance_id: "NVME\\GEN31X4\\5&ABC".to_string(),
                    bus_type: BusType::Nvme,
                    model: "Samsung SSD 980 Pro".to_string(),
                    drive_letter: None,
                    serial: None,
                    size_bytes: None,
                    is_boot_disk: false,
                    encryption_status: None,
                    encryption_method: None,
                    encryption_checked_at: None,
                },
            ],
            ..Default::default()
        };

        let tmp_path = std::env::temp_dir().join("test_disk_allowlist_toml_roundtrip.toml");
        original.save(&tmp_path).expect("save should succeed");
        let loaded = AgentConfig::load(&tmp_path);
        let _ = std::fs::remove_file(&tmp_path);

        assert_eq!(loaded.disk_allowlist.len(), 2);
        // Note: TOML save+load may reorder entries depending on serde HashMap
        // semantics, but Vec serialization preserves order. Assert by index.
        assert_eq!(loaded.disk_allowlist[0].instance_id, "PCIIDE\\IDECHANNEL\\4&1234");
        assert_eq!(loaded.disk_allowlist[0].drive_letter, Some('C'));
        assert_eq!(loaded.disk_allowlist[0].bus_type, BusType::Sata);
        assert!(loaded.disk_allowlist[0].is_boot_disk);

        assert_eq!(loaded.disk_allowlist[1].instance_id, "NVME\\GEN31X4\\5&ABC");
        assert_eq!(loaded.disk_allowlist[1].drive_letter, None);
        assert_eq!(loaded.disk_allowlist[1].bus_type, BusType::Nvme);
        assert!(!loaded.disk_allowlist[1].is_boot_disk);
    }

    #[test]
    fn test_disk_allowlist_omits_none_encryption_fields() {
        // Verifies the existing #[serde(skip_serializing_if = "Option::is_none")]
        // on DiskIdentity's encryption fields propagates correctly through the
        // [[disk_allowlist]] array of tables (D-08 + Phase 35 specifics block).
        use dlp_common::{BusType, DiskIdentity};

        let cfg = AgentConfig {
            disk_allowlist: vec![DiskIdentity {
                instance_id: "USB\\VID_1234&PID_5678\\001".to_string(),
                bus_type: BusType::Usb,
                model: "USB External Drive".to_string(),
                drive_letter: Some('E'),
                serial: None,
                size_bytes: None,
                is_boot_disk: false,
                encryption_status: None,
                encryption_method: None,
                encryption_checked_at: None,
            }],
            ..Default::default()
        };

        let serialized = toml::to_string(&cfg).expect("serialize");
        // Encryption fields must be ABSENT in the TOML output when None.
        assert!(
            !serialized.contains("encryption_status"),
            "TOML should not contain encryption_status when None; got:\n{serialized}"
        );
        assert!(
            !serialized.contains("encryption_method"),
            "TOML should not contain encryption_method when None; got:\n{serialized}"
        );
        assert!(
            !serialized.contains("encryption_checked_at"),
            "TOML should not contain encryption_checked_at when None; got:\n{serialized}"
        );
        // Sanity: required fields are present.
        assert!(serialized.contains("[[disk_allowlist]]"));
        assert!(serialized.contains("instance_id"));
        assert!(serialized.contains("USB\\\\VID_1234&PID_5678\\\\001"));
    }

    #[test]
    fn test_log_level_roundtrip_toml() {
        let toml_str = "log_level = 'debug'\n";
        let config: AgentConfig = toml::from_str(toml_str).expect("parse");
        assert_eq!(config.resolved_log_level(), tracing::Level::DEBUG);
    }

    #[test]
    fn test_effective_config_path_no_env_uses_default() {
        // Temporarily clear the env var (if set) and verify fallback.
        // Using a separate env key to avoid interfering with running tests.
        let path = {
            std::env::remove_var("DLP_CONFIG_PATH");
            AgentConfig::effective_config_path()
        };
        assert_eq!(path, DEFAULT_CONFIG_PATH);
    }

    #[test]
    fn test_effective_config_path_env_override() {
        // Use std::env::set_var inside a block so we restore after the test.
        // Note: parallel test execution can race on env vars — acceptable for
        // this unit test because we restore immediately after reading.
        std::env::set_var("DLP_CONFIG_PATH", r"C:\TestData\override.toml");
        let path = AgentConfig::effective_config_path();
        std::env::remove_var("DLP_CONFIG_PATH");
        assert_eq!(path, r"C:\TestData\override.toml");
    }

    // --- Phase 34 / BitLocker re-check cadence tests (D-11) ---

    #[test]
    fn test_encryption_section_absent_uses_default() {
        // No [encryption] block in TOML → resolved_recheck_interval == 21600s.
        let toml_str = "";
        let config: AgentConfig = toml::from_str(toml_str).expect("deserialize empty");
        assert_eq!(config.encryption.recheck_interval_secs, None);
        assert_eq!(
            config.resolved_recheck_interval(),
            std::time::Duration::from_secs(ENCRYPTION_RECHECK_DEFAULT_SECS)
        );
    }

    #[test]
    fn test_encryption_recheck_interval_passes_through_in_range() {
        let toml_str = "[encryption]\nrecheck_interval_secs = 600\n";
        let config: AgentConfig = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(config.encryption.recheck_interval_secs, Some(600));
        assert_eq!(
            config.resolved_recheck_interval(),
            std::time::Duration::from_secs(600)
        );
    }

    #[test]
    fn test_encryption_recheck_interval_default_value_passes_through() {
        let toml_str = "[encryption]\nrecheck_interval_secs = 21600\n";
        let config: AgentConfig = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(
            config.resolved_recheck_interval(),
            std::time::Duration::from_secs(21_600)
        );
    }

    #[test]
    fn test_encryption_recheck_interval_clamp_low() {
        let toml_str = "[encryption]\nrecheck_interval_secs = 0\n";
        let config: AgentConfig = toml::from_str(toml_str).expect("deserialize");
        // 0 is below MIN; expect clamped UP to 300.
        assert_eq!(
            config.resolved_recheck_interval(),
            std::time::Duration::from_secs(ENCRYPTION_RECHECK_MIN_SECS)
        );
    }

    #[test]
    fn test_encryption_recheck_interval_clamp_high() {
        let toml_str = "[encryption]\nrecheck_interval_secs = 999999\n";
        let config: AgentConfig = toml::from_str(toml_str).expect("deserialize");
        // 999999 is above MAX; expect clamped DOWN to 86400.
        assert_eq!(
            config.resolved_recheck_interval(),
            std::time::Duration::from_secs(ENCRYPTION_RECHECK_MAX_SECS)
        );
    }

    #[test]
    fn test_encryption_recheck_interval_boundary_values_pass_through() {
        // Exactly at MIN — not clamped.
        let toml_min = format!(
            "[encryption]\nrecheck_interval_secs = {}\n",
            ENCRYPTION_RECHECK_MIN_SECS
        );
        let config_min: AgentConfig = toml::from_str(&toml_min).expect("deserialize min");
        assert_eq!(
            config_min.resolved_recheck_interval(),
            std::time::Duration::from_secs(ENCRYPTION_RECHECK_MIN_SECS)
        );
        // Exactly at MAX — not clamped.
        let toml_max = format!(
            "[encryption]\nrecheck_interval_secs = {}\n",
            ENCRYPTION_RECHECK_MAX_SECS
        );
        let config_max: AgentConfig = toml::from_str(&toml_max).expect("deserialize max");
        assert_eq!(
            config_max.resolved_recheck_interval(),
            std::time::Duration::from_secs(ENCRYPTION_RECHECK_MAX_SECS)
        );
    }
}
