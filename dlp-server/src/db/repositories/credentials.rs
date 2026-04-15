//! Repository for the `agent_credentials` table.
//!
//! Stores per-key credential values used for agent authentication.
//! Values are opaque blobs (typically bcrypt hashes).

use rusqlite::params;

use crate::db::{Pool, UnitOfWork};

/// Plain data row for a credential entry.
#[derive(Debug, Clone)]
pub struct CredentialRow {
    /// Credential key identifier (e.g., `"agent_auth_hash"`).
    pub key: String,
    /// Credential value (opaque — typically a bcrypt hash).
    pub value: String,
    /// ISO-8601 timestamp of last update.
    pub updated_at: String,
}

/// Stateless repository for the `agent_credentials` table.
pub struct CredentialsRepository;

impl CredentialsRepository {
    /// Returns the credential entry for the given key.
    ///
    /// Returns `rusqlite::Error::QueryReturnedNoRows` if the key does not exist.
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    /// * `key` - Credential key to look up.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if pool acquisition or query execution fails.
    pub fn get(pool: &Pool, key: &str) -> rusqlite::Result<CredentialRow> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        conn.query_row(
            "SELECT key, value, updated_at FROM agent_credentials WHERE key = ?1",
            params![key],
            |row| {
                Ok(CredentialRow {
                    key: row.get(0)?,
                    value: row.get(1)?,
                    updated_at: row.get(2)?,
                })
            },
        )
    }

    /// Inserts or updates a credential entry by key.
    ///
    /// # Arguments
    ///
    /// * `uow` - Active unit of work to execute the write within.
    /// * `key` - Credential key identifier.
    /// * `value` - Credential value to store.
    /// * `updated_at` - ISO-8601 timestamp of this update.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the statement fails.
    pub fn upsert(
        uow: &UnitOfWork<'_>,
        key: &str,
        value: &str,
        updated_at: &str,
    ) -> rusqlite::Result<()> {
        uow.tx.execute(
            "INSERT INTO agent_credentials (key, value, updated_at) VALUES (?1, ?2, ?3) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            params![key, value, updated_at],
        )?;
        Ok(())
    }
}
