//! Repository for the `ldap_config` table.
//!
//! Single-row configuration table (enforced via `CHECK (id = 1)`).
//! Provides typed access to Active Directory LDAP connection settings.
//!
//! # Phase 47 transition (Task 47-05)
//!
//! `bind_dn` and the `bind_password_{encrypted,nonce,version}` trio were added
//! in Task 47-03's migration. They enable an opt-in explicit-bind path; the
//! historical SSPI passwordless bind (machine-account TGT) remains the
//! default for deployments that leave the fields empty/NULL.
//!
//! - [`LdapConfigRepository::get`] continues to return [`LdapConfigRow`] for
//!   backward compatibility with all existing call sites (`main.rs` LDAP
//!   bootstrap, `admin_api.rs` GET handlers). It does NOT surface the bind
//!   secret — that always flows through [`get_bind_credentials`] so the
//!   plaintext stays scoped to the LDAP bind call.
//! - [`get_bind_credentials`] is the encrypted-side read: returns
//!   `Option<LdapBindCredentials>` — `None` when either `bind_dn` is empty
//!   or no encrypted password is configured (the passwordless default).
//!
//! Secret-bearing structs use `SecretString` so the derived `Debug` redacts.
//! Do not add naked-String secret fields.

use rusqlite::params;
use secrecy::SecretString;

use crate::crypto::{aad_for, Envelope, SecretCrypto};
use crate::db::{Pool, UnitOfWork};
use crate::AppError;
use dlp_common::LdapBindCredentials;

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
    /// Optional explicit-bind DN (Phase 47). `None` or empty means SSPI
    /// passwordless bind via the machine account (the default).
    pub bind_dn: Option<String>,
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
             vpn_subnets, updated_at, bind_dn \
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
                    bind_dn: row.get(6)?,
                })
            },
        )
    }

    /// Updates the LDAP configuration row (always row `id = 1`).
    ///
    /// `require_tls` is stored as `INTEGER` (0 or 1).
    /// `cache_ttl_secs` is narrowed from `u64` to `i64` for SQLite storage.
    ///
    /// **Note:** this method does NOT touch `bind_dn` or the
    /// `bind_password_*` trio. Explicit-bind credentials are managed only
    /// via [`set_bind_password`] and [`clear_bind_password`] — preserving
    /// whatever the operator configured via the encrypted-bind admin path,
    /// even when a legacy PUT `/admin/ldap-config` (which doesn't know
    /// about explicit-bind) writes a new row. This guarantees a UI flow
    /// that updates VPN subnets cannot accidentally tear down a configured
    /// explicit-bind connection. `record.bind_dn` is therefore IGNORED.
    ///
    /// # Arguments
    ///
    /// * `uow` - Active unit of work to execute the write within.
    /// * `record` - New LDAP configuration values to persist. `bind_dn` is
    ///   ignored; use [`set_bind_password`] / [`clear_bind_password`] to
    ///   change the explicit-bind credentials.
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

    /// Returns the explicit-bind credentials when both `bind_dn` and the
    /// encrypted `bind_password` triple are populated.
    ///
    /// Returns `Ok(None)` when:
    /// - `bind_dn` is NULL or empty (default SSPI passwordless deployment).
    /// - `bind_password_encrypted` is NULL (no password configured).
    ///
    /// A populated `bind_dn` paired with a populated ciphertext yields
    /// `Some(LdapBindCredentials { bind_dn, bind_password })`. The
    /// `SecretString` is constructed inside this function and never logged.
    ///
    /// # Errors
    ///
    /// - [`AppError::Database`] when the SELECT fails.
    /// - [`AppError::Internal`] when the encrypted blob cannot be decrypted
    ///   (envelope malformed, AAD/auth mismatch, unknown KEK version).
    ///   Silently falling back to SSPI in this case would mask tampering.
    pub fn get_bind_credentials(
        pool: &Pool,
        crypto: &SecretCrypto,
    ) -> Result<Option<LdapBindCredentials>, AppError> {
        let conn = pool.get().map_err(AppError::from)?;
        let raw: (Option<String>, Option<Vec<u8>>, Option<Vec<u8>>) = conn
            .query_row(
                "SELECT bind_dn, bind_password_encrypted, bind_password_nonce \
                 FROM ldap_config WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(AppError::Database)?;

        let (bind_dn_opt, ct_opt, nonce_opt) = raw;
        let bind_dn = match bind_dn_opt {
            Some(s) if !s.is_empty() => s,
            _ => return Ok(None),
        };
        let (ct, nonce) = match (ct_opt, nonce_opt) {
            (Some(c), Some(n)) => (c, n),
            _ => return Ok(None),
        };

        // Reconstitute the envelope; the on-disk wire format only stores
        // ciphertext+tag and the nonce separately. Version byte is always
        // ENVELOPE_VERSION_V1 — bumping requires a schema migration.
        if nonce.len() != crate::crypto::envelope::NONCE_LEN {
            return Err(AppError::Internal(anyhow::anyhow!(
                "decrypt failed for ldap_config.bind_password: nonce length"
            )));
        }
        let mut nonce_arr = [0u8; crate::crypto::envelope::NONCE_LEN];
        nonce_arr.copy_from_slice(&nonce);
        let envelope =
            Envelope::new(crate::crypto::ENVELOPE_VERSION_V1, nonce_arr, ct).map_err(|_| {
                AppError::Internal(anyhow::anyhow!(
                    "decrypt failed for ldap_config.bind_password: malformed envelope"
                ))
            })?;
        let aad = aad_for("ldap_config", "bind_password");
        let bind_password = crypto.decrypt(&envelope, &aad).map_err(|_| {
            AppError::Internal(anyhow::anyhow!(
                "decrypt failed for ldap_config.bind_password: auth/version error"
            ))
        })?;
        Ok(Some(LdapBindCredentials {
            bind_dn,
            bind_password,
        }))
    }

    /// Encrypts and stores the explicit-bind password.
    ///
    /// The caller has already obtained the active [`SecretCrypto`] handle and
    /// pre-validated the bind_dn. This writes all three encrypted-side
    /// columns plus updates `bind_dn` in a single UPDATE.
    ///
    /// # Errors
    ///
    /// - [`AppError::Internal`] on encryption failure.
    /// - [`AppError::Database`] on UPDATE failure.
    pub fn set_bind_password(
        uow: &UnitOfWork<'_>,
        bind_dn: &str,
        password: &SecretString,
        crypto: &SecretCrypto,
    ) -> Result<(), AppError> {
        use secrecy::ExposeSecret;
        let aad = aad_for("ldap_config", "bind_password");
        let envelope = crypto
            .encrypt(password.expose_secret().as_bytes(), &aad)
            .map_err(|_| {
                AppError::Internal(anyhow::anyhow!(
                    "encrypt failed for ldap_config.bind_password"
                ))
            })?;
        uow.tx
            .execute(
                "UPDATE ldap_config SET \
                   bind_dn = ?1, \
                   bind_password_encrypted = ?2, \
                   bind_password_nonce = ?3, \
                   bind_password_version = ?4 \
                 WHERE id = 1",
                params![
                    bind_dn,
                    envelope.ciphertext,
                    envelope.nonce.as_slice(),
                    crypto.version() as i64,
                ],
            )
            .map_err(AppError::Database)?;
        Ok(())
    }

    /// Clears the explicit-bind credentials, restoring SSPI passwordless mode.
    ///
    /// NULLs the encrypted password trio and `bind_dn`. Idempotent — applies
    /// regardless of whether credentials were configured.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` on UPDATE failure.
    pub fn clear_bind_password(uow: &UnitOfWork<'_>) -> rusqlite::Result<()> {
        uow.tx.execute(
            "UPDATE ldap_config SET \
               bind_dn = NULL, \
               bind_password_encrypted = NULL, \
               bind_password_nonce = NULL, \
               bind_password_version = NULL \
             WHERE id = 1",
            [],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ENVELOPE_VERSION_V1;
    use crate::db::new_pool;
    use secrecy::ExposeSecret;

    const TEST_KEK: [u8; 32] = [
        0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
        0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
        0x99, 0x99,
    ];

    fn fixture_crypto() -> SecretCrypto {
        SecretCrypto::from_kek(TEST_KEK, ENVELOPE_VERSION_V1)
    }

    #[test]
    fn get_bind_credentials_returns_none_on_default_passwordless_config() {
        // Fresh DB — bind_dn and bind_password_* are all NULL.
        let pool = new_pool(":memory:").expect("create pool");
        let crypto = fixture_crypto();
        let got = LdapConfigRepository::get_bind_credentials(&pool, &crypto).expect("get");
        assert!(
            got.is_none(),
            "default SSPI passwordless config must yield None"
        );
    }

    #[test]
    fn set_and_get_bind_credentials_round_trip() {
        let pool = new_pool(":memory:").expect("create pool");
        let crypto = fixture_crypto();

        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            LdapConfigRepository::set_bind_password(
                &uow,
                "CN=svc-dlp,OU=Service,DC=corp,DC=local",
                &SecretString::new("bind-secret-XYZ".to_string()),
                &crypto,
            )
            .expect("set bind password");
            uow.commit().expect("commit");
        }

        let got = LdapConfigRepository::get_bind_credentials(&pool, &crypto)
            .expect("get")
            .expect("Some");
        assert_eq!(got.bind_dn, "CN=svc-dlp,OU=Service,DC=corp,DC=local");
        assert_eq!(got.bind_password.expose_secret(), "bind-secret-XYZ");
    }

    #[test]
    fn empty_bind_dn_means_none_even_if_password_blob_present() {
        // Defensive: if a future bug seeds bind_password_* but leaves
        // bind_dn empty, we must NOT call simple_bind("", password). Treat
        // it as the SSPI default.
        let pool = new_pool(":memory:").expect("create pool");
        let crypto = fixture_crypto();
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            LdapConfigRepository::set_bind_password(
                &uow,
                "valid-dn",
                &SecretString::new("pw".to_string()),
                &crypto,
            )
            .expect("seed");
            // Now blank out bind_dn but leave the encrypted columns.
            uow.tx
                .execute("UPDATE ldap_config SET bind_dn = '' WHERE id = 1", [])
                .expect("blank bind_dn");
            uow.commit().expect("commit");
        }
        let got = LdapConfigRepository::get_bind_credentials(&pool, &crypto).expect("get");
        assert!(
            got.is_none(),
            "empty bind_dn must short-circuit even if password blob exists"
        );
    }

    #[test]
    fn clear_bind_password_restores_passwordless_mode() {
        let pool = new_pool(":memory:").expect("create pool");
        let crypto = fixture_crypto();

        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            LdapConfigRepository::set_bind_password(
                &uow,
                "CN=svc,DC=corp,DC=local",
                &SecretString::new("pw".to_string()),
                &crypto,
            )
            .expect("set");
            uow.commit().expect("commit");
        }
        // Confirm it's there.
        assert!(LdapConfigRepository::get_bind_credentials(&pool, &crypto)
            .expect("get")
            .is_some());

        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            LdapConfigRepository::clear_bind_password(&uow).expect("clear");
            uow.commit().expect("commit");
        }
        assert!(LdapConfigRepository::get_bind_credentials(&pool, &crypto)
            .expect("get post-clear")
            .is_none());
    }

    #[test]
    fn tamper_with_bind_password_nonce_yields_decrypt_error() {
        let pool = new_pool(":memory:").expect("create pool");
        let crypto = fixture_crypto();

        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            LdapConfigRepository::set_bind_password(
                &uow,
                "CN=svc,DC=corp,DC=local",
                &SecretString::new("pw-A".to_string()),
                &crypto,
            )
            .expect("set");
            uow.commit().expect("commit");
        }

        // Flip a bit in the nonce.
        {
            let conn = pool.get().expect("acquire connection");
            let mut nonce: Vec<u8> = conn
                .query_row(
                    "SELECT bind_password_nonce FROM ldap_config WHERE id = 1",
                    [],
                    |r| r.get(0),
                )
                .expect("read nonce");
            nonce[0] ^= 0xFF;
            conn.execute(
                "UPDATE ldap_config SET bind_password_nonce = ?1 WHERE id = 1",
                params![nonce],
            )
            .expect("tamper");
        }

        let err = LdapConfigRepository::get_bind_credentials(&pool, &crypto)
            .expect_err("tampered nonce must fail decrypt");
        assert!(
            err.to_string()
                .contains("decrypt failed for ldap_config.bind_password"),
            "expected typed decrypt error; got: {err}"
        );
    }

    #[test]
    fn legacy_get_still_returns_row_with_bind_dn_field() {
        // Regression guard: existing callers of LdapConfigRepository::get
        // must still compile and run after the schema/struct gained the
        // bind_dn field.
        let pool = new_pool(":memory:").expect("create pool");
        let row = LdapConfigRepository::get(&pool).expect("get");
        assert!(row.bind_dn.is_none() || row.bind_dn.as_deref() == Some(""));
    }
}
