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
use dlp_common::DiskIdentity;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// Default config file location.
pub const DEFAULT_CONFIG_PATH: &str = r"C:\ProgramData\DLP\agent-config.toml";

/// Default re-check interval for BitLocker encryption verification (D-11).
/// 6 hours (21,600 seconds).
pub const ENCRYPTION_RECHECK_DEFAULT_SECS: u64 = 21_600;

/// Minimum valid `[encryption].recheck_interval_secs` (OP-03). 1 minute.
/// Values below this are clamped up and a `warn!` log line is emitted at load time.
pub const ENCRYPTION_RECHECK_MIN_SECS: u64 = 60;

/// Maximum valid `[encryption].recheck_interval_secs` (D-11 / OP-03). 24 hours.
/// Values above this are clamped down and a `warn!` log line is emitted at load time.
pub const ENCRYPTION_RECHECK_MAX_SECS: u64 = 86_400;

/// Minimum valid `cache_ttl_secs` in `[ldap]` section (OP-03). 1 minute.
pub const LDAP_CACHE_TTL_MIN_SECS: u64 = 60;
/// Maximum valid `cache_ttl_secs` in `[ldap]` section (OP-03). 1 hour.
pub const LDAP_CACHE_TTL_MAX_SECS: u64 = 3_600;
/// Minimum valid `poll_interval_secs` (OP-03). 5 seconds.
pub const POLL_INTERVAL_MIN_SECS: u64 = 5;
/// Default poll interval when not specified (OP-03).
pub const POLL_INTERVAL_DEFAULT_SECS: u64 = 30;

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

    /// Disk allowlist persisted across agent restarts (Phase 35 / DISK-03 / D-03).
    ///
    /// Loaded from `[[disk_allowlist]]` TOML array of tables. Each entry is a
    /// [`DiskIdentity`] keyed canonically by `instance_id`. `drive_letter` is
    /// stored as informational metadata only — it is NOT a key.
    ///
    /// When the section is absent (first run, or pre-Phase-35 config files),
    /// `#[serde(default)]` yields an empty `Vec` (D-08, backwards compat).
    ///
    /// Phase 36 enforcement reads from `DiskEnumerator.instance_id_map`; this
    /// field is the persistence backing for that map. Disconnected disks are
    /// retained per D-06 (allowlist is additive — admin removes via Phase 37/38).
    #[serde(default)]
    pub disk_allowlist: Vec<DiskIdentity>,

    /// LDAP/AD configuration for group resolution. When `None`, AD features
    /// are disabled (fallback to placeholder identity values). Populated by
    /// server config push and persisted to the TOML config file.
    #[serde(default)]
    pub ldap_config: Option<crate::server_client::LdapConfigPayload>,

    /// Agent-side polling interval in seconds (OP-03).
    ///
    /// Controls how frequently the agent checks for configuration updates or
    /// performs housekeeping. Values below 5 seconds are rejected (the default
    /// of 30 seconds is used instead) to prevent excessive server load.
    #[serde(default)]
    pub poll_interval_secs: Option<u64>,

    /// USB enforcement failure mode (USB-09). "Hard error", "Warning only",
    /// or "Retry then error".
    #[serde(default)]
    pub usb_blocked_failure_mode: Option<String>,

    /// USB startup scan resolution strategy (USB-07).
    /// "Volume GUID resolution" or "VID/PID/serial fallback".
    #[serde(default)]
    pub usb_startup_resolution_mode: Option<String>,

    /// Policy for USB devices without serial descriptors (USB-08).
    /// "Always Blocked", "Port-based disambiguation", or "Allow unregistered".
    #[serde(default)]
    pub usb_none_serial_policy: Option<String>,

    /// Grace period in seconds before mount-time block engages for unregistered disks.
    /// Default 0 = immediate block (backward compatible with Phase 44 behavior).
    /// During grace period: disk is accessible but writes are blocked.
    /// After grace period expires: mount-time block engages (drive letter removed).
    ///
    /// Config validation: max 3600 seconds (1 hour) per T-45-01 threat mitigation.
    #[serde(default)]
    pub disk_grace_period_seconds: u64,

    /// Whether the cloud sync hook DLL is enabled (M017/S01).
    /// When `None`, defaults to `false`. Populated by server config push.
    #[serde(default)]
    pub cloud_hook_enabled: Option<bool>,

    /// Whether the WFP network egress filter is enabled (M017/S01).
    /// When `None`, defaults to `false`. Populated by server config push.
    #[serde(default)]
    pub wfp_filter_enabled: Option<bool>,

    /// Timeout in milliseconds for hook classification pipe requests (M017/S01).
    /// When `None`, defaults to 5000 ms. Populated by server config push.
    #[serde(default)]
    pub hook_classification_timeout_ms: Option<u64>,

    /// Whether print spooler interception is enabled (M017/S04).
    /// When `None`, defaults to `false`. Populated by server config push.
    #[serde(default)]
    pub print_enabled: Option<bool>,

    /// Timeout in milliseconds for XPS spool file parsing (M017/S04).
    /// When `None`, defaults to 5000 ms. Populated by server config push.
    #[serde(default)]
    pub print_xps_timeout_ms: Option<u64>,

    /// Action to take when a print job cannot be classified (M017/S04).
    /// When `None`, defaults to `"Block"`. Populated by server config push.
    #[serde(default)]
    pub print_unclassifiable_action: Option<String>,

    /// Maximum number of pages to parse from an XPS spool file (M017/S04).
    /// When `None`, defaults to 100. Populated by server config push.
    #[serde(default)]
    pub print_max_pages: Option<usize>,

    /// Machine hostname, resolved once at startup.
    /// Not persisted to the config file.
    #[serde(skip)]
    pub machine_name: Option<String>,

    /// Phase 49: Enable universal injection (ETW process watcher + universal injector).
    /// When `None`, defaults to `false`.
    #[serde(default)]
    pub universal_injection_enabled: Option<bool>,

    /// Phase 49: Allowlist entries for universal injection.
    #[serde(default)]
    pub allowlist_entries: Vec<crate::allowlist::AllowlistEntry>,

    /// Phase 49: Version of the allowlist config (for change detection).
    #[serde(default)]
    pub allowlist_version: i64,

    /// Phase 51: Enable ntdll syscall-stub patching for direct-syscall bypass defense.
    /// When `None`, defaults to `false`. Must be explicitly enabled by operator.
    #[serde(default)]
    pub enable_ntdll_patching: Option<bool>,
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

        // Use serde_ignored to detect unknown TOML keys without aborting load (OP-03).
        let mut unknown_keys: Vec<String> = Vec::new();
        let deserializer = toml::de::Deserializer::new(content);
        let config: AgentConfig =
            match serde_ignored::deserialize::<_, _, AgentConfig>(deserializer, |path| {
                unknown_keys.push(path.to_string());
            }) {
                Ok(config) => {
                    if !unknown_keys.is_empty() {
                        warn!(
                            path = %path.display(),
                            keys = ?unknown_keys,
                            "unknown TOML keys in config -- ignored"
                        );
                    }
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
            };
        config
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

    /// Returns the clamped LDAP cache TTL as a Duration (OP-03).
    ///
    /// # Behavior
    ///
    /// - `None` (no LDAP config) returns `None`.
    /// - In-range values pass through unchanged.
    /// - Out-of-range values are clamped to [`LDAP_CACHE_TTL_MIN_SECS`,
    ///   [`LDAP_CACHE_TTL_MAX_SECS`]] and a `warn!` is emitted.
    pub fn resolved_cache_ttl(&self) -> Option<std::time::Duration> {
        let ldap = self.ldap_config.as_ref()?;
        let raw = ldap.cache_ttl_secs;
        let clamped = raw.clamp(LDAP_CACHE_TTL_MIN_SECS, LDAP_CACHE_TTL_MAX_SECS);
        if clamped != raw {
            warn!(
                requested = raw,
                applied = clamped,
                min = LDAP_CACHE_TTL_MIN_SECS,
                max = LDAP_CACHE_TTL_MAX_SECS,
                "ldap.cache_ttl_secs out of range -- clamped"
            );
        }
        Some(std::time::Duration::from_secs(clamped))
    }

    /// Returns the validated poll interval as a Duration (OP-03).
    ///
    /// # Behavior
    ///
    /// - `None` defaults to [`POLL_INTERVAL_DEFAULT_SECS`] (30 seconds).
    /// - Values < [`POLL_INTERVAL_MIN_SECS`] (5 seconds) are rejected (return
    ///   default) and a `warn!` is emitted.
    /// - In-range values pass through unchanged.
    pub fn resolved_poll_interval(&self) -> std::time::Duration {
        let raw = self
            .poll_interval_secs
            .unwrap_or(POLL_INTERVAL_DEFAULT_SECS);
        if raw < POLL_INTERVAL_MIN_SECS {
            warn!(
                requested = raw,
                applied = POLL_INTERVAL_DEFAULT_SECS,
                min = POLL_INTERVAL_MIN_SECS,
                "agent.poll_interval_secs below minimum -- using default"
            );
            std::time::Duration::from_secs(POLL_INTERVAL_DEFAULT_SECS)
        } else {
            std::time::Duration::from_secs(raw)
        }
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
            monitored_paths: vec![r"C:\Data\".to_string()],
            ..Default::default()
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
    fn test_agent_config_enable_ntdll_patching_default() {
        let config = AgentConfig::default();
        assert!(config.enable_ntdll_patching.is_none());
    }

    #[test]
    fn test_agent_config_enable_ntdll_patching_deserialize() {
        let toml_str = "enable_ntdll_patching = true\n";
        let config: AgentConfig = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(config.enable_ntdll_patching, Some(true));
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
            disk_allowlist: Vec::new(),
            ldap_config: None,
            poll_interval_secs: None,
            usb_blocked_failure_mode: None,
            usb_startup_resolution_mode: None,
            usb_none_serial_policy: None,
            disk_grace_period_seconds: 0,
            cloud_hook_enabled: None,
            wfp_filter_enabled: None,
            hook_classification_timeout_ms: None,
            print_enabled: None,
            print_xps_timeout_ms: None,
            print_unclassifiable_action: None,
            print_max_pages: None,
            universal_injection_enabled: None,
            allowlist_entries: Vec::new(),
            allowlist_version: 0,
            enable_ntdll_patching: None,
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
            disk_allowlist: Vec::new(),
            ldap_config: None,
            poll_interval_secs: None,
            usb_blocked_failure_mode: None,
            usb_startup_resolution_mode: None,
            usb_none_serial_policy: None,
            disk_grace_period_seconds: 0,
            cloud_hook_enabled: None,
            wfp_filter_enabled: None,
            hook_classification_timeout_ms: None,
            print_enabled: None,
            print_xps_timeout_ms: None,
            print_unclassifiable_action: None,
            print_max_pages: None,
            machine_name: None,
            universal_injection_enabled: None,
            allowlist_entries: Vec::new(),
            allowlist_version: 0,
            enable_ntdll_patching: None,
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
        assert_eq!(
            loaded.disk_allowlist[0].instance_id,
            "PCIIDE\\IDECHANNEL\\4&1234"
        );
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
        // Note: the toml 0.8 crate serializes strings containing backslashes using
        // TOML literal strings (single-quoted), where backslashes are NOT escaped.
        // So `USB\VID_1234&PID_5678\001` appears verbatim in the output.
        assert!(serialized.contains("[[disk_allowlist]]"));
        assert!(serialized.contains("instance_id"));
        assert!(serialized.contains("USB\\VID_1234&PID_5678\\001"));
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

    // --- OP-03: Agent Config TOML Field-Range Validation tests ---

    #[test]
    fn test_recheck_interval_clamp_low_to_60() {
        // recheck_interval = 30 is below new MIN of 60; clamped UP to 60.
        let config = AgentConfig {
            encryption: EncryptionConfig {
                recheck_interval_secs: Some(30),
            },
            ..Default::default()
        };
        assert_eq!(
            config.resolved_recheck_interval(),
            std::time::Duration::from_secs(60)
        );
    }

    #[test]
    fn test_recheck_interval_clamp_high_to_86400() {
        // recheck_interval = 100_000 is above MAX of 86_400; clamped DOWN.
        let config = AgentConfig {
            encryption: EncryptionConfig {
                recheck_interval_secs: Some(100_000),
            },
            ..Default::default()
        };
        assert_eq!(
            config.resolved_recheck_interval(),
            std::time::Duration::from_secs(86_400)
        );
    }

    #[test]
    fn test_cache_ttl_clamp_low_to_60() {
        let config = AgentConfig {
            ldap_config: Some(crate::server_client::LdapConfigPayload {
                ldap_url: "ldaps://dc.corp.internal:636".to_string(),
                base_dn: "DC=corp,DC=internal".to_string(),
                require_tls: true,
                cache_ttl_secs: 30,
                vpn_subnets: "10.0.0.0/8".to_string(),
            }),
            ..Default::default()
        };
        assert_eq!(
            config.resolved_cache_ttl(),
            Some(std::time::Duration::from_secs(60))
        );
    }

    #[test]
    fn test_cache_ttl_clamp_high_to_3600() {
        let config = AgentConfig {
            ldap_config: Some(crate::server_client::LdapConfigPayload {
                ldap_url: "ldaps://dc.corp.internal:636".to_string(),
                base_dn: "DC=corp,DC=internal".to_string(),
                require_tls: true,
                cache_ttl_secs: 5000,
                vpn_subnets: "10.0.0.0/8".to_string(),
            }),
            ..Default::default()
        };
        assert_eq!(
            config.resolved_cache_ttl(),
            Some(std::time::Duration::from_secs(3600))
        );
    }

    #[test]
    fn test_poll_interval_rejects_below_5() {
        // poll_interval = 3 is below MIN of 5; rejected, returns default 30.
        let config = AgentConfig {
            poll_interval_secs: Some(3),
            ..Default::default()
        };
        assert_eq!(
            config.resolved_poll_interval(),
            std::time::Duration::from_secs(30)
        );
    }

    #[test]
    fn test_poll_interval_passes_through() {
        // poll_interval = 10 is valid; passes through.
        let config = AgentConfig {
            poll_interval_secs: Some(10),
            ..Default::default()
        };
        assert_eq!(
            config.resolved_poll_interval(),
            std::time::Duration::from_secs(10)
        );
    }

    #[test]
    fn test_poll_interval_defaults_to_30() {
        // poll_interval = None defaults to 30.
        let config = AgentConfig::default();
        assert_eq!(
            config.resolved_poll_interval(),
            std::time::Duration::from_secs(30)
        );
    }

    // --- Phase 43: USB enforcement config fields (USB-07, USB-08, USB-09) ---

    #[test]
    fn test_agent_config_usb_fields_default() {
        // Default AgentConfig must have None for all three USB fields.
        let config = AgentConfig::default();
        assert!(config.usb_blocked_failure_mode.is_none());
        assert!(config.usb_startup_resolution_mode.is_none());
        assert!(config.usb_none_serial_policy.is_none());
    }

    #[test]
    fn test_agent_config_usb_fields_deserialize() {
        let toml_str = r#"
            usb_blocked_failure_mode = "Hard error"
            usb_startup_resolution_mode = "VID/PID/serial fallback"
            usb_none_serial_policy = "Allow unregistered"
        "#;
        let config: AgentConfig = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(
            config.usb_blocked_failure_mode,
            Some("Hard error".to_string())
        );
        assert_eq!(
            config.usb_startup_resolution_mode,
            Some("VID/PID/serial fallback".to_string())
        );
        assert_eq!(
            config.usb_none_serial_policy,
            Some("Allow unregistered".to_string())
        );
    }

    #[test]
    fn test_agent_config_usb_fields_backwards_compatible() {
        // A TOML config without USB fields must parse successfully.
        let toml_str = r#"
            monitored_paths = ['C:\Restricted\']
        "#;
        let config: AgentConfig = toml::from_str(toml_str).expect("backwards-compat parse");
        assert_eq!(config.monitored_paths, vec![r"C:\Restricted\"]);
        assert!(config.usb_blocked_failure_mode.is_none());
        assert!(config.usb_startup_resolution_mode.is_none());
        assert!(config.usb_none_serial_policy.is_none());
    }

    #[test]
    fn test_unknown_toml_key_warns_but_loads() {
        // Unknown TOML key must not abort config loading.
        let toml_str = r#"
            monitored_paths = ['C:\Data\']
            unknown_field = 42
        "#;
        let config = load_from_str(toml_str);
        assert_eq!(config.monitored_paths, vec![r"C:\Data\"]);
        // unknown_field is ignored; other fields use defaults.
        assert!(config.excluded_paths.is_empty());
    }

    #[test]
    fn test_invalid_toml_syntax_falls_back_to_defaults() {
        // Invalid TOML syntax must fall back to defaults.
        let toml_str = "monitored_paths = ['C:\\Data\\'\n"; // missing closing quote/bracket
        let config = load_from_str(toml_str);
        assert_eq!(config, AgentConfig::default());
    }

    /// Helper: parse TOML from a string (for tests that need serde_ignored).
    fn load_from_str(content: &str) -> AgentConfig {
        let mut unknown_keys: Vec<String> = Vec::new();
        let deserializer = toml::de::Deserializer::new(content);
        match serde_ignored::deserialize::<_, _, AgentConfig>(deserializer, |path| {
            unknown_keys.push(path.to_string());
        }) {
            Ok(config) => config,
            Err(_) => AgentConfig::default(),
        }
    }
}
