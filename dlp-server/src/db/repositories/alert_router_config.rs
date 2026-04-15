//! Repository for the `alert_router_config` table.
//!
//! Single-row configuration table (enforced via `CHECK (id = 1)`).
//! Provides typed access to email (SMTP) and webhook alert routing settings.

use rusqlite::params;

use crate::db::{Pool, UnitOfWork};

/// Plain data row for the alert router configuration.
#[derive(Debug, Clone)]
pub struct AlertRouterConfigRow {
    /// SMTP server hostname.
    pub smtp_host: String,
    /// SMTP server port (converted to `u16`; errors on overflow).
    pub smtp_port: u16,
    /// SMTP authentication username.
    pub smtp_username: String,
    /// SMTP authentication password.
    pub smtp_password: String,
    /// Sender email address.
    pub smtp_from: String,
    /// Recipient email address.
    pub smtp_to: String,
    /// Whether SMTP email alerts are enabled (1 = true, 0 = false).
    pub smtp_enabled: i64,
    /// Webhook endpoint URL.
    pub webhook_url: String,
    /// HMAC secret for webhook request signing.
    pub webhook_secret: String,
    /// Whether webhook alerts are enabled (1 = true, 0 = false).
    pub webhook_enabled: i64,
    /// ISO-8601 timestamp of last configuration update.
    pub updated_at: String,
}

/// Stateless repository for the `alert_router_config` table.
pub struct AlertRouterConfigRepository;

impl AlertRouterConfigRepository {
    /// Returns the current alert router configuration row.
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
    pub fn get(pool: &Pool) -> rusqlite::Result<AlertRouterConfigRow> {
        let conn = pool.get().map_err(|e| {
            rusqlite::Error::ToSqlConversionFailure(Box::new(e))
        })?;
        conn.query_row(
            "SELECT smtp_host, smtp_port, smtp_username, smtp_password, \
             smtp_from, smtp_to, smtp_enabled, webhook_url, webhook_secret, \
             webhook_enabled, updated_at \
             FROM alert_router_config WHERE id = 1",
            [],
            |row| {
                let smtp_port_i64: i64 = row.get(1)?;
                let smtp_port = u16::try_from(smtp_port_i64).map_err(|_| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Integer,
                        format!("smtp_port out of range: {smtp_port_i64}").into(),
                    )
                })?;
                Ok(AlertRouterConfigRow {
                    smtp_host: row.get(0)?,
                    smtp_port,
                    smtp_username: row.get(2)?,
                    smtp_password: row.get(3)?,
                    smtp_from: row.get(4)?,
                    smtp_to: row.get(5)?,
                    smtp_enabled: row.get(6)?,
                    webhook_url: row.get(7)?,
                    webhook_secret: row.get(8)?,
                    webhook_enabled: row.get(9)?,
                    updated_at: row.get(10)?,
                })
            },
        )
    }

    /// Updates the alert router configuration row (always row `id = 1`).
    ///
    /// # Arguments
    ///
    /// * `uow` - Active unit of work to execute the write within.
    /// * `record` - New alert router configuration values to persist.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the update fails.
    pub fn update(uow: &UnitOfWork<'_>, record: &AlertRouterConfigRow) -> rusqlite::Result<()> {
        uow.tx.execute(
            "UPDATE alert_router_config SET \
             smtp_host = ?1, smtp_port = ?2, smtp_username = ?3, smtp_password = ?4, \
             smtp_from = ?5, smtp_to = ?6, smtp_enabled = ?7, webhook_url = ?8, \
             webhook_secret = ?9, webhook_enabled = ?10, updated_at = ?11 \
             WHERE id = 1",
            params![
                record.smtp_host,
                record.smtp_port,
                record.smtp_username,
                record.smtp_password,
                record.smtp_from,
                record.smtp_to,
                record.smtp_enabled,
                record.webhook_url,
                record.webhook_secret,
                record.webhook_enabled,
                record.updated_at,
            ],
        )?;
        Ok(())
    }
}
