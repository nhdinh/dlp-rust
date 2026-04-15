//! Repository for the `siem_config` table.
//!
//! Single-row configuration table (enforced via `CHECK (id = 1)`).
//! Provides typed access to SIEM relay settings for Splunk and ELK.

use rusqlite::params;

use crate::db::{Pool, UnitOfWork};

/// Plain data row for the SIEM configuration.
#[derive(Debug, Clone)]
pub struct SiemConfigRow {
    /// Splunk HEC endpoint URL.
    pub splunk_url: String,
    /// Splunk HEC authentication token.
    pub splunk_token: String,
    /// Whether the Splunk relay is enabled.
    pub splunk_enabled: i64,
    /// ELK (Elasticsearch) endpoint URL.
    pub elk_url: String,
    /// ELK index name for event ingestion.
    pub elk_index: String,
    /// ELK API key for authentication.
    pub elk_api_key: String,
    /// Whether the ELK relay is enabled.
    pub elk_enabled: i64,
    /// ISO-8601 timestamp of last configuration update.
    pub updated_at: String,
}

/// Stateless repository for the `siem_config` table.
pub struct SiemConfigRepository;

impl SiemConfigRepository {
    /// Returns the current SIEM configuration row.
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
    pub fn get(pool: &Pool) -> rusqlite::Result<SiemConfigRow> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        conn.query_row(
            "SELECT splunk_url, splunk_token, splunk_enabled, \
             elk_url, elk_index, elk_api_key, elk_enabled, updated_at \
             FROM siem_config WHERE id = 1",
            [],
            |row| {
                Ok(SiemConfigRow {
                    splunk_url: row.get(0)?,
                    splunk_token: row.get(1)?,
                    splunk_enabled: row.get(2)?,
                    elk_url: row.get(3)?,
                    elk_index: row.get(4)?,
                    elk_api_key: row.get(5)?,
                    elk_enabled: row.get(6)?,
                    updated_at: row.get(7)?,
                })
            },
        )
    }

    /// Updates the SIEM configuration row (always row `id = 1`).
    ///
    /// # Arguments
    ///
    /// * `uow` - Active unit of work to execute the write within.
    /// * `record` - New SIEM configuration values to persist.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the update fails.
    pub fn update(uow: &UnitOfWork<'_>, record: &SiemConfigRow) -> rusqlite::Result<()> {
        uow.tx.execute(
            "UPDATE siem_config SET \
             splunk_url = ?1, splunk_token = ?2, splunk_enabled = ?3, \
             elk_url = ?4, elk_index = ?5, elk_api_key = ?6, \
             elk_enabled = ?7, updated_at = ?8 \
             WHERE id = 1",
            params![
                record.splunk_url,
                record.splunk_token,
                record.splunk_enabled,
                record.elk_url,
                record.elk_index,
                record.elk_api_key,
                record.elk_enabled,
                record.updated_at,
            ],
        )?;
        Ok(())
    }
}
