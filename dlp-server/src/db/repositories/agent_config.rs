//! Repository for the `global_agent_config` and `agent_config_overrides` tables.
//!
//! `GlobalAgentConfigRow` covers the single-row default configuration applied to
//! all agents. Per-agent overrides are stored in `agent_config_overrides`.

use rusqlite::params;

use crate::db::{Pool, UnitOfWork};

/// Plain data row for the global agent configuration.
///
/// `monitored_paths` and `excluded_paths` are stored as JSON text arrays;
/// callers deserialize them. `offline_cache_enabled` is stored as `INTEGER` (0/1).
#[derive(Debug, Clone)]
pub struct GlobalAgentConfigRow {
    /// JSON array of filesystem paths to monitor (e.g., `'["/data"]'`).
    pub monitored_paths: String,
    /// JSON array of filesystem paths to exclude from monitoring.
    pub excluded_paths: String,
    /// Interval in seconds between agent heartbeat reports.
    pub heartbeat_interval_secs: i64,
    /// Whether agents should cache events locally when offline.
    pub offline_cache_enabled: i64,
    /// ISO-8601 timestamp of last configuration update.
    pub updated_at: String,
    /// USB enforcement failure mode (USB-09): "Hard error", "Warning only", "Retry then error".
    pub usb_blocked_failure_mode: String,
    /// USB startup scan resolution strategy (USB-07): "Volume GUID resolution", "VID/PID/serial fallback".
    pub usb_startup_resolution_mode: String,
    /// Policy for USB devices without serial descriptors (USB-08): "Always Blocked",
    /// "Port-based disambiguation", "Allow unregistered".
    pub usb_none_serial_policy: String,
    /// Whether the cloud sync hook DLL is enabled (M017/S01). Stored as 0/1.
    pub cloud_hook_enabled: i64,
    /// Whether print spooler interception is enabled (M017/S04). Stored as 0/1.
    pub print_enabled: i64,
    /// Timeout in milliseconds for XPS spool file parsing (M017/S04).
    pub print_xps_timeout_ms: i64,
    /// Action when a print job cannot be classified (M017/S04): "Block" or "Allow".
    pub print_unclassifiable_action: String,
    /// Maximum pages to parse from an XPS spool file (M017/S04).
    pub print_max_pages: i64,
}

/// Plain data row for a per-agent config override.
///
/// Same column layout as `GlobalAgentConfigRow` but keyed by `agent_id`
/// instead of the single-row `global_agent_config` table.
#[derive(Debug, Clone)]
pub struct AgentConfigOverrideRow {
    /// JSON array of filesystem paths to monitor.
    pub monitored_paths: String,
    /// JSON array of filesystem paths to exclude from monitoring.
    pub excluded_paths: String,
    /// Interval in seconds between agent heartbeat reports.
    pub heartbeat_interval_secs: i64,
    /// Whether offline caching is enabled.
    pub offline_cache_enabled: i64,
    /// USB enforcement failure mode (USB-09).
    pub usb_blocked_failure_mode: String,
    /// USB startup scan resolution strategy (USB-07).
    pub usb_startup_resolution_mode: String,
    /// Policy for USB devices without serial descriptors (USB-08).
    pub usb_none_serial_policy: String,
    /// Whether the cloud sync hook DLL is enabled (M017/S01). Stored as 0/1.
    pub cloud_hook_enabled: i64,
    /// Whether print spooler interception is enabled (M017/S04). Stored as 0/1.
    pub print_enabled: i64,
    /// Timeout in milliseconds for XPS spool file parsing (M017/S04).
    pub print_xps_timeout_ms: i64,
    /// Action when a print job cannot be classified (M017/S04): "Block" or "Allow".
    pub print_unclassifiable_action: String,
    /// Maximum pages to parse from an XPS spool file (M017/S04).
    pub print_max_pages: i64,
}

/// Stateless repository for agent configuration tables.
pub struct AgentConfigRepository;

impl AgentConfigRepository {
    /// Returns the global agent configuration row.
    ///
    /// Returns `rusqlite::Error::QueryReturnedNoRows` if the seed row is
    /// missing (should not happen after `init_tables()`).
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if pool acquisition or query execution fails.
    pub fn get_global(pool: &Pool) -> rusqlite::Result<GlobalAgentConfigRow> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        conn.query_row(
            "SELECT monitored_paths, excluded_paths, heartbeat_interval_secs, \
             offline_cache_enabled, updated_at, \
             usb_blocked_failure_mode, usb_startup_resolution_mode, usb_none_serial_policy, \
             cloud_hook_enabled, print_enabled, print_xps_timeout_ms, \
             print_unclassifiable_action, print_max_pages \
             FROM global_agent_config WHERE id = 1",
            [],
            |row| {
                Ok(GlobalAgentConfigRow {
                    monitored_paths: row.get(0)?,
                    excluded_paths: row.get(1)?,
                    heartbeat_interval_secs: row.get(2)?,
                    offline_cache_enabled: row.get(3)?,
                    updated_at: row.get(4)?,
                    usb_blocked_failure_mode: row.get(5)?,
                    usb_startup_resolution_mode: row.get(6)?,
                    usb_none_serial_policy: row.get(7)?,
                    cloud_hook_enabled: row.get(8)?,
                    print_enabled: row.get(9)?,
                    print_xps_timeout_ms: row.get(10)?,
                    print_unclassifiable_action: row.get(11)?,
                    print_max_pages: row.get(12)?,
                })
            },
        )
    }

    /// Updates the global agent configuration row (always row `id = 1`).
    ///
    /// # Arguments
    ///
    /// * `uow` - Active unit of work to execute the write within.
    /// * `record` - New global configuration values to persist.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the update fails.
    pub fn update_global(
        uow: &UnitOfWork<'_>,
        record: &GlobalAgentConfigRow,
    ) -> rusqlite::Result<()> {
        uow.tx.execute(
            "UPDATE global_agent_config SET \
             monitored_paths = ?1, excluded_paths = ?2, \
             heartbeat_interval_secs = ?3, \
             offline_cache_enabled = ?4, updated_at = ?5, \
             usb_blocked_failure_mode = ?6, \
             usb_startup_resolution_mode = ?7, \
             usb_none_serial_policy = ?8, \
             cloud_hook_enabled = ?9, print_enabled = ?10, \
             print_xps_timeout_ms = ?11, print_unclassifiable_action = ?12, \
             print_max_pages = ?13 \
             WHERE id = 1",
            params![
                record.monitored_paths,
                record.excluded_paths,
                record.heartbeat_interval_secs,
                record.offline_cache_enabled,
                record.updated_at,
                record.usb_blocked_failure_mode,
                record.usb_startup_resolution_mode,
                record.usb_none_serial_policy,
                record.cloud_hook_enabled,
                record.print_enabled,
                record.print_xps_timeout_ms,
                record.print_unclassifiable_action,
                record.print_max_pages,
            ],
        )?;
        Ok(())
    }

    /// Returns the per-agent config override for the given `agent_id`, if one exists.
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    /// * `agent_id` - Unique agent identifier.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error::QueryReturnedNoRows` if no override exists.
    pub fn get_override(pool: &Pool, agent_id: &str) -> rusqlite::Result<AgentConfigOverrideRow> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        conn.query_row(
            "SELECT monitored_paths, excluded_paths, heartbeat_interval_secs, \
             offline_cache_enabled, \
             usb_blocked_failure_mode, usb_startup_resolution_mode, usb_none_serial_policy, \
             cloud_hook_enabled, print_enabled, print_xps_timeout_ms, \
             print_unclassifiable_action, print_max_pages \
             FROM agent_config_overrides WHERE agent_id = ?1",
            params![agent_id],
            |row| {
                Ok(AgentConfigOverrideRow {
                    monitored_paths: row.get(0)?,
                    excluded_paths: row.get(1)?,
                    heartbeat_interval_secs: row.get(2)?,
                    offline_cache_enabled: row.get(3)?,
                    usb_blocked_failure_mode: row.get(4)?,
                    usb_startup_resolution_mode: row.get(5)?,
                    usb_none_serial_policy: row.get(6)?,
                    cloud_hook_enabled: row.get(7)?,
                    print_enabled: row.get(8)?,
                    print_xps_timeout_ms: row.get(9)?,
                    print_unclassifiable_action: row.get(10)?,
                    print_max_pages: row.get(11)?,
                })
            },
        )
    }

    /// Inserts or replaces a per-agent config override.
    ///
    /// # Arguments
    ///
    /// * `uow` - Active unit of work to execute the write within.
    /// * `agent_id` - Unique agent identifier.
    /// * `monitored_paths` - JSON-serialized vector of paths to monitor.
    /// * `excluded_paths` - JSON-serialized vector of paths to exclude.
    /// * `heartbeat_interval_secs` - Heartbeat interval in seconds.
    /// * `offline_cache_enabled` - Whether offline caching is enabled (0 or 1).
    /// * `updated_at` - ISO-8601 timestamp of this update.
    /// * `usb_blocked_failure_mode` - USB enforcement failure mode.
    /// * `usb_startup_resolution_mode` - USB startup resolution strategy.
    /// * `usb_none_serial_policy` - Policy for devices without serial descriptors.
    /// * `cloud_hook_enabled` - Whether the cloud sync hook DLL is enabled (0 or 1).
    /// * `print_enabled` - Whether print spooler interception is enabled (0 or 1).
    /// * `print_xps_timeout_ms` - Timeout in milliseconds for XPS spool file parsing.
    /// * `print_unclassifiable_action` - Action for unclassifiable print jobs: "Block" or "Allow".
    /// * `print_max_pages` - Maximum pages to parse from an XPS spool file.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the statement fails.
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_override(
        uow: &UnitOfWork<'_>,
        agent_id: &str,
        monitored_paths: &str,
        excluded_paths: &str,
        heartbeat_interval_secs: i64,
        offline_cache_enabled: i64,
        updated_at: &str,
        usb_blocked_failure_mode: &str,
        usb_startup_resolution_mode: &str,
        usb_none_serial_policy: &str,
        cloud_hook_enabled: i64,
        print_enabled: i64,
        print_xps_timeout_ms: i64,
        print_unclassifiable_action: &str,
        print_max_pages: i64,
    ) -> rusqlite::Result<()> {
        uow.tx.execute(
            "INSERT OR REPLACE INTO agent_config_overrides \
             (agent_id, monitored_paths, excluded_paths, heartbeat_interval_secs, \
             offline_cache_enabled, updated_at, \
             usb_blocked_failure_mode, usb_startup_resolution_mode, usb_none_serial_policy, \
             cloud_hook_enabled, print_enabled, print_xps_timeout_ms, \
             print_unclassifiable_action, print_max_pages) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                agent_id,
                monitored_paths,
                excluded_paths,
                heartbeat_interval_secs,
                offline_cache_enabled,
                updated_at,
                usb_blocked_failure_mode,
                usb_startup_resolution_mode,
                usb_none_serial_policy,
                cloud_hook_enabled,
                print_enabled,
                print_xps_timeout_ms,
                print_unclassifiable_action,
                print_max_pages,
            ],
        )?;
        Ok(())
    }

    /// Deletes the per-agent config override for the given `agent_id`.
    ///
    /// # Arguments
    ///
    /// * `uow` - Active unit of work to execute the write within.
    /// * `agent_id` - Unique agent identifier.
    ///
    /// # Returns
    ///
    /// Returns the number of rows deleted (0 if no override existed).
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the statement fails.
    pub fn delete_override(uow: &UnitOfWork<'_>, agent_id: &str) -> rusqlite::Result<usize> {
        uow.tx.execute(
            "DELETE FROM agent_config_overrides WHERE agent_id = ?1",
            params![agent_id],
        )
    }
}
