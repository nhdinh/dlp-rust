//! Repository for the `global_agent_config` and `agent_config_overrides` tables.
//!
//! `GlobalAgentConfigRow` covers the single-row default configuration applied to
//! all agents. Per-agent overrides are stored in `agent_config_overrides`.

use rusqlite::params;

use crate::db::{Pool, UnitOfWork};

/// Plain data row for the global agent configuration.
///
/// `monitored_paths` is stored as a JSON text array; callers deserialize it.
/// `offline_cache_enabled` is stored as `INTEGER` (0/1).
#[derive(Debug, Clone)]
pub struct GlobalAgentConfigRow {
    /// JSON array of filesystem paths to monitor (e.g., `'["/data"]'`).
    pub monitored_paths: String,
    /// Interval in seconds between agent heartbeat reports.
    pub heartbeat_interval_secs: i64,
    /// Whether agents should cache events locally when offline.
    pub offline_cache_enabled: i64,
    /// ISO-8601 timestamp of last configuration update.
    pub updated_at: String,
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
        let conn = pool.get().map_err(|e| {
            rusqlite::Error::ToSqlConversionFailure(Box::new(e))
        })?;
        conn.query_row(
            "SELECT monitored_paths, heartbeat_interval_secs, \
             offline_cache_enabled, updated_at \
             FROM global_agent_config WHERE id = 1",
            [],
            |row| {
                Ok(GlobalAgentConfigRow {
                    monitored_paths: row.get(0)?,
                    heartbeat_interval_secs: row.get(1)?,
                    offline_cache_enabled: row.get(2)?,
                    updated_at: row.get(3)?,
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
             monitored_paths = ?1, heartbeat_interval_secs = ?2, \
             offline_cache_enabled = ?3, updated_at = ?4 \
             WHERE id = 1",
            params![
                record.monitored_paths,
                record.heartbeat_interval_secs,
                record.offline_cache_enabled,
                record.updated_at,
            ],
        )?;
        Ok(())
    }
}
