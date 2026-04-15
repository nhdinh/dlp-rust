//! Repository for the `ldap_config` table.
//!
//! Single-row configuration table (enforced via `CHECK (id = 1)`).
//! Provides typed access to Active Directory LDAP connection settings.

use rusqlite::params;

use crate::db::{Pool, UnitOfWork};

/// Plain data row for the LDAP configuration.
///
/// `require_tls` is stored as `INTEGER` (0/1) in the DB and converted to
/// `bool` on read. `cache_ttl_secs` is stored as `INTEGER` and widened to
/// `u64` on read.
#[derive(Debug, Clone)]
pub struct LdapConfigRow {
    /// LDAP server URL (e.g., `"ldaps://dc.corp.internal:636"`).
    pub ldap_url: String,
    /// LDAP base DN for searches (e.g., `"DC=corp,DC=internal"`).
    pub base_dn: String,
    /// Whether TLS is required for the LDAP connection.
    pub require_tls: bool,
    /// Duration in seconds to cache LDAP query results.
    pub cache_ttl_secs: u64,
    /// Comma-separated list of CIDR ranges considered VPN subnets.
    pub vpn_subnets: String,
    /// ISO-8601 timestamp of last configuration update.
    pub updated_at: String,
}

/// Stateless repository for the `ldap_config` table.
pub struct LdapConfigRepository;

impl LdapConfigRepository {
    /// Returns the current LDAP configuration row.
    ///
    /// Returns `rusqlite::Error::QueryReturnedNoRows` if the seed row is
    /// missing (should not happen after `init_tables()`).
    ///
    /// `require_tls` (`i64`) is converted to `bool` via `!= 0`.
    /// `cache_ttl_secs` (`i64`) is widened to `u64`.
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if pool acquisition or query execution fails.
    pub fn get(pool: &Pool) -> rusqlite::Result<LdapConfigRow> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        conn.query_row(
            "SELECT ldap_url, base_dn, require_tls, cache_ttl_secs, \
             vpn_subnets, updated_at \
             FROM ldap_config WHERE id = 1",
            [],
            |row| {
                // require_tls stored as INTEGER (0/1) — convert to bool
                let require_tls_raw: i64 = row.get(2)?;
                // cache_ttl_secs stored as INTEGER — widen to u64
                let cache_ttl_raw: i64 = row.get(3)?;
                Ok(LdapConfigRow {
                    ldap_url: row.get(0)?,
                    base_dn: row.get(1)?,
                    require_tls: require_tls_raw != 0,
                    cache_ttl_secs: cache_ttl_raw as u64,
                    vpn_subnets: row.get(4)?,
                    updated_at: row.get(5)?,
                })
            },
        )
    }

    /// Updates the LDAP configuration row (always row `id = 1`).
    ///
    /// `require_tls` is stored as `INTEGER` (0 or 1).
    /// `cache_ttl_secs` is narrowed from `u64` to `i64` for SQLite storage.
    ///
    /// # Arguments
    ///
    /// * `uow` - Active unit of work to execute the write within.
    /// * `record` - New LDAP configuration values to persist.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the update fails.
    pub fn update(uow: &UnitOfWork<'_>, record: &LdapConfigRow) -> rusqlite::Result<()> {
        // Cast u64 → i64 for SQLite INTEGER column; values fit within i64 range.
        let cache_ttl: i64 = record.cache_ttl_secs as i64;
        uow.tx.execute(
            "UPDATE ldap_config SET \
             ldap_url = ?1, base_dn = ?2, require_tls = ?3, \
             cache_ttl_secs = ?4, vpn_subnets = ?5, updated_at = ?6 \
             WHERE id = 1",
            params![
                record.ldap_url,
                record.base_dn,
                record.require_tls as i64,
                cache_ttl,
                record.vpn_subnets,
                record.updated_at,
            ],
        )?;
        Ok(())
    }
}
