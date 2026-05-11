//! Repository for the `siem_config` table.
//!
//! Single-row configuration table (enforced via `CHECK (id = 1)`).
//! Provides typed access to SIEM relay settings for Splunk and ELK.
//!
//! # Phase 47 (Wave 4 — Task 47-06)
//!
//! `splunk_token` and `elk_api_key` are persisted only as AES-GCM
//! envelopes wrapped under the active KEK. The legacy cleartext columns
//! were dropped in-place by [`crate::secrets_migration::migrate_secrets_to_encrypted`].
//! Every read path goes through [`SiemConfigRepository::get`], which
//! decrypts under column-binding AAD via [`crate::crypto::aad_for`].
//! Every write path goes through [`SiemConfigRepository::update`],
//! which encrypts on the way down.
//!
//! Secret-bearing structs use `SecretString` so the derived `Debug`
//! redacts them. Do not add naked-String secret fields.

use rusqlite::params;
use secrecy::{ExposeSecret, SecretString};

use crate::crypto::{aad_for, Envelope, SecretCrypto};
use crate::db::{Pool, UnitOfWork};
use crate::AppError;

/// Raw `(ciphertext, nonce, kek_version)` triple produced by
/// [`encrypt_optional`] for one secret column. `None` means "no secret
/// configured" (all three columns set to NULL).
type EncryptedTriple = (Option<Vec<u8>>, Option<Vec<u8>>, Option<i64>);

/// Raw row tuple returned by the `siem_config` SELECT inside
/// [`SiemConfigRepository::get`]. Ten columns: `(splunk_url,
/// splunk_token_encrypted, splunk_token_nonce, splunk_enabled, elk_url,
/// elk_index, elk_api_key_encrypted, elk_api_key_nonce, elk_enabled,
/// updated_at)`.
type SiemRawRow = (
    String,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    i64,
    String,
    String,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    i64,
    String,
);

/// Plain data row for the SIEM configuration.
///
/// Secret-bearing fields are [`SecretString`] so the default `Debug`
/// derive redacts them. Non-secret fields (URLs, indices, enabled
/// flags) remain `String` / `i64` for ergonomic read access.
#[derive(Debug, Clone)]
pub struct SiemConfigRow {
    /// Splunk HEC endpoint URL.
    pub splunk_url: String,
    /// Splunk HEC authentication token (decrypted) or `None` when both the
    /// encrypted column and the legacy cleartext column are empty.
    pub splunk_token: Option<SecretString>,
    /// Whether the Splunk relay is enabled.
    pub splunk_enabled: i64,
    /// ELK (Elasticsearch) endpoint URL.
    pub elk_url: String,
    /// ELK index name for event ingestion.
    pub elk_index: String,
    /// ELK API key (decrypted) or `None` when both columns are empty.
    pub elk_api_key: Option<SecretString>,
    /// Whether the ELK relay is enabled.
    pub elk_enabled: i64,
    /// ISO-8601 timestamp of last configuration update.
    pub updated_at: String,
}

/// Stateless repository for the `siem_config` table.
pub struct SiemConfigRepository;

impl SiemConfigRepository {
    /// Reads the SIEM config and decrypts the encrypted-column secrets.
    ///
    /// Behaviour per secret column (`splunk_token`, `elk_api_key`):
    ///
    /// - If the `<col>_encrypted` BLOB is **non-NULL**, deserialize the
    ///   envelope and decrypt with AAD `aad_for("siem_config", col)`.
    ///   A non-NULL ciphertext that fails to decrypt is treated as a
    ///   hard error ([`AppError::Internal`]).
    /// - If the `<col>_encrypted` BLOB is NULL, return `None` — the
    ///   secret is unset (post-migration there is no cleartext column
    ///   to fall back to).
    ///
    /// # Arguments
    ///
    /// * `pool` — connection pool (read).
    /// * `crypto` — active KEK handle. Decryption uses this KEK's version.
    ///
    /// # Errors
    ///
    /// - [`AppError::Database`] when the underlying SELECT fails.
    /// - [`AppError::Internal`] when a non-NULL `*_encrypted` blob cannot
    ///   be decrypted (envelope malformed, tag mismatch, unknown version).
    pub fn get(pool: &Pool, crypto: &SecretCrypto) -> Result<SiemConfigRow, AppError> {
        let conn = pool.get().map_err(AppError::from)?;
        let raw: SiemRawRow = conn
            .query_row(
                "SELECT splunk_url, \
                        splunk_token_encrypted, splunk_token_nonce, \
                        splunk_enabled, \
                        elk_url, elk_index, \
                        elk_api_key_encrypted, elk_api_key_nonce, \
                        elk_enabled, updated_at \
                 FROM siem_config WHERE id = 1",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                    ))
                },
            )
            .map_err(AppError::Database)?;

        let (
            splunk_url,
            splunk_token_ct,
            splunk_token_nonce,
            splunk_enabled,
            elk_url,
            elk_index,
            elk_api_key_ct,
            elk_api_key_nonce,
            elk_enabled,
            updated_at,
        ) = raw;

        let splunk_token = decrypt_optional(
            "siem_config",
            "splunk_token",
            splunk_token_ct.as_deref(),
            splunk_token_nonce.as_deref(),
            crypto,
        )?;
        let elk_api_key = decrypt_optional(
            "siem_config",
            "elk_api_key",
            elk_api_key_ct.as_deref(),
            elk_api_key_nonce.as_deref(),
            crypto,
        )?;

        Ok(SiemConfigRow {
            splunk_url,
            splunk_token,
            splunk_enabled,
            elk_url,
            elk_index,
            elk_api_key,
            elk_enabled,
            updated_at,
        })
    }

    /// Encrypts the secret-bearing fields and writes the full SIEM
    /// config row using the encrypted-column trio.
    ///
    /// For each secret column (`splunk_token`, `elk_api_key`):
    /// - `Some(value)` → encrypt with AAD `aad_for("siem_config", col)`
    ///   and write the envelope into `<col>_encrypted`, the nonce into
    ///   `<col>_nonce`, and `crypto.version()` into `<col>_version`.
    /// - `None` → set all three encrypted-side columns to NULL (clear
    ///   the secret).
    ///
    /// All updated columns are written in a single UPDATE so the change
    /// is atomic with respect to readers.
    ///
    /// # Errors
    ///
    /// - [`AppError::Internal`] if encryption fails (unreachable with
    ///   AES-GCM and well-formed inputs, but the call is fallible).
    /// - [`AppError::Database`] if the UPDATE fails.
    pub fn update(
        uow: &UnitOfWork<'_>,
        record: &SiemConfigRow,
        crypto: &SecretCrypto,
    ) -> Result<(), AppError> {
        let (splunk_ct, splunk_nonce, splunk_ver) = encrypt_optional(
            "siem_config",
            "splunk_token",
            record.splunk_token.as_ref(),
            crypto,
        )?;
        let (elk_ct, elk_nonce, elk_ver) = encrypt_optional(
            "siem_config",
            "elk_api_key",
            record.elk_api_key.as_ref(),
            crypto,
        )?;

        uow.tx
            .execute(
                "UPDATE siem_config SET \
                 splunk_url = ?1, \
                 splunk_token_encrypted = ?2, \
                 splunk_token_nonce = ?3, \
                 splunk_token_version = ?4, \
                 splunk_enabled = ?5, \
                 elk_url = ?6, elk_index = ?7, \
                 elk_api_key_encrypted = ?8, \
                 elk_api_key_nonce = ?9, \
                 elk_api_key_version = ?10, \
                 elk_enabled = ?11, \
                 updated_at = ?12 \
                 WHERE id = 1",
                params![
                    record.splunk_url,
                    splunk_ct,
                    splunk_nonce,
                    splunk_ver,
                    record.splunk_enabled,
                    record.elk_url,
                    record.elk_index,
                    elk_ct,
                    elk_nonce,
                    elk_ver,
                    record.elk_enabled,
                    record.updated_at,
                ],
            )
            .map_err(AppError::Database)?;
        Ok(())
    }
}

/// Decrypt `<col>_encrypted`/`<col>_nonce` if both are present.
///
/// Returns `None` when the encrypted-side columns are NULL (the secret
/// is unset). Decryption failure on a non-NULL ciphertext is a HARD
/// error — a silent return of `None` would mask tampering.
fn decrypt_optional(
    table: &str,
    column: &str,
    ciphertext: Option<&[u8]>,
    nonce: Option<&[u8]>,
    crypto: &SecretCrypto,
) -> Result<Option<SecretString>, AppError> {
    let (ct, n) = match (ciphertext, nonce) {
        (Some(c), Some(n)) => (c, n),
        _ => return Ok(None),
    };
    let mut nonce_arr = [0u8; crate::crypto::envelope::NONCE_LEN];
    if n.len() != nonce_arr.len() {
        return Err(AppError::Internal(anyhow::anyhow!(
            "decrypt failed for {table}.{column}: nonce length"
        )));
    }
    nonce_arr.copy_from_slice(n);
    let envelope = Envelope::new(crate::crypto::ENVELOPE_VERSION_V1, nonce_arr, ct.to_vec())
        .map_err(|_| {
            AppError::Internal(anyhow::anyhow!(
                "decrypt failed for {table}.{column}: malformed envelope"
            ))
        })?;
    let aad = aad_for(table, column);
    let plaintext = crypto.decrypt(&envelope, &aad).map_err(|_| {
        AppError::Internal(anyhow::anyhow!(
            "decrypt failed for {table}.{column}: auth/version error"
        ))
    })?;
    Ok(Some(plaintext))
}

/// Encrypt an optional secret. `None` yields the all-NULL triple,
/// `Some(s)` yields `(envelope_blob, nonce_blob, kek_version)`.
fn encrypt_optional(
    table: &str,
    column: &str,
    plaintext: Option<&SecretString>,
    crypto: &SecretCrypto,
) -> Result<EncryptedTriple, AppError> {
    match plaintext {
        Some(s) => {
            let aad = aad_for(table, column);
            // expose_secret() is sanctioned here: we are at the encrypt
            // boundary and the resulting bytes leave memory only inside
            // the AES-GCM cipher state, which zeroizes on drop.
            let env = crypto
                .encrypt(s.expose_secret().as_bytes(), &aad)
                .map_err(|_| {
                    AppError::Internal(anyhow::anyhow!("encrypt failed for {table}.{column}"))
                })?;
            // Store the GCM ciphertext+tag (not the wire-format envelope
            // with version prefix) in `_encrypted`. The KEK version goes
            // into the separate `_version` column. The wire-format version
            // byte will be reconstituted on read in `decrypt_or_fallback`.
            Ok((
                Some(env.ciphertext),
                Some(env.nonce.to_vec()),
                Some(crypto.version() as i64),
            ))
        }
        None => Ok((None, None, None)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ENVELOPE_VERSION_V1;
    use crate::db::new_pool;
    use crate::secrets_migration::migrate_secrets_to_encrypted;
    use secrecy::ExposeSecret;

    const TEST_KEK: [u8; 32] = [
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42,
    ];

    fn fixture_crypto() -> SecretCrypto {
        SecretCrypto::from_kek(TEST_KEK, ENVELOPE_VERSION_V1)
    }

    /// Builds a fresh pool and runs the Phase 47 Task 47-06 migration so
    /// the legacy cleartext `splunk_token` / `elk_api_key` columns are
    /// dropped before any repository call runs. Every test below depends
    /// on this — the repository now SELECTs only the encrypted-side
    /// columns.
    fn migrated_pool(crypto: &SecretCrypto) -> Pool {
        let pool = new_pool(":memory:").expect("create pool");
        migrate_secrets_to_encrypted(&pool, crypto, None).expect("run migration");
        pool
    }

    fn fixture_row(splunk_token: &str, elk_api_key: &str) -> SiemConfigRow {
        SiemConfigRow {
            splunk_url: "https://splunk.example.com:8088".to_string(),
            splunk_token: if splunk_token.is_empty() {
                None
            } else {
                Some(SecretString::new(splunk_token.to_string()))
            },
            splunk_enabled: 1,
            elk_url: "https://elastic.example.com:9200".to_string(),
            elk_index: "dlp-events".to_string(),
            elk_api_key: if elk_api_key.is_empty() {
                None
            } else {
                Some(SecretString::new(elk_api_key.to_string()))
            },
            elk_enabled: 1,
            updated_at: "2026-05-13T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn update_then_get_round_trips_both_secrets() {
        let crypto = fixture_crypto();
        let pool = migrated_pool(&crypto);

        let original = fixture_row("splunk-token-XYZ", "elk-api-key-ABC");
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            SiemConfigRepository::update(&uow, &original, &crypto).expect("update encrypted");
            uow.commit().expect("commit");
        }

        let got = SiemConfigRepository::get(&pool, &crypto).expect("get encrypted");
        assert_eq!(
            got.splunk_token
                .as_ref()
                .map(|s| s.expose_secret().to_string()),
            Some("splunk-token-XYZ".to_string()),
            "splunk_token must round-trip via the encrypted column"
        );
        assert_eq!(
            got.elk_api_key
                .as_ref()
                .map(|s| s.expose_secret().to_string()),
            Some("elk-api-key-ABC".to_string()),
            "elk_api_key must round-trip via the encrypted column"
        );
        assert_eq!(got.splunk_url, original.splunk_url);
        assert_eq!(got.elk_index, original.elk_index);
        assert_eq!(got.splunk_enabled, 1);
    }

    #[test]
    fn tamper_with_nonce_yields_decrypt_error() {
        let crypto = fixture_crypto();
        let pool = migrated_pool(&crypto);

        let row = fixture_row("plaintext-XYZ", "key-A");
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            SiemConfigRepository::update(&uow, &row, &crypto).expect("update");
            uow.commit().expect("commit");
        }

        // Bit-flip the first byte of splunk_token_nonce.
        {
            let conn = pool.get().expect("acquire connection");
            let mut nonce: Vec<u8> = conn
                .query_row(
                    "SELECT splunk_token_nonce FROM siem_config WHERE id = 1",
                    [],
                    |r| r.get(0),
                )
                .expect("read nonce");
            nonce[0] ^= 0xFF;
            conn.execute(
                "UPDATE siem_config SET splunk_token_nonce = ?1 WHERE id = 1",
                params![nonce],
            )
            .expect("write tampered nonce");
        }

        let err =
            SiemConfigRepository::get(&pool, &crypto).expect_err("must reject tampered nonce");
        let msg = err.to_string();
        assert!(
            msg.contains("decrypt failed for siem_config.splunk_token"),
            "expected typed decrypt error, got: {msg}"
        );
    }

    #[test]
    fn empty_secrets_round_trip_as_none() {
        let crypto = fixture_crypto();
        let pool = migrated_pool(&crypto);

        let row = fixture_row("", "");
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            SiemConfigRepository::update(&uow, &row, &crypto).expect("update");
            uow.commit().expect("commit");
        }

        let got = SiemConfigRepository::get(&pool, &crypto).expect("get");
        assert!(
            got.splunk_token.is_none(),
            "empty splunk_token must round-trip as None"
        );
        assert!(
            got.elk_api_key.is_none(),
            "empty elk_api_key must round-trip as None"
        );
    }
}
