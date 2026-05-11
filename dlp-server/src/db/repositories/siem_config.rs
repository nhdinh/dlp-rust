//! Repository for the `siem_config` table.
//!
//! Single-row configuration table (enforced via `CHECK (id = 1)`).
//! Provides typed access to SIEM relay settings for Splunk and ELK.
//!
//! # Phase 47 transition (Task 47-04)
//!
//! Two parallel read/write paths exist during the Phase 47 migration window:
//!
//! - **Cleartext path** (legacy): [`SiemConfigRepository::get`] and
//!   [`SiemConfigRepository::update`] continue to read/write the cleartext
//!   `splunk_token` / `elk_api_key` columns. These remain the only path used
//!   by `admin_api.rs` and `siem_connector.rs` until AppState gains an
//!   `Arc<SecretCrypto>` (Task 47-06 wires it).
//!
//! - **Encrypted path** (new): [`SiemConfigRepository::get_with_crypto`] and
//!   [`SiemConfigRepository::update_with_crypto`] read/write the
//!   `<col>_encrypted` / `<col>_nonce` / `<col>_version` triples added in
//!   Task 47-03. Decryption uses column-binding AAD via
//!   [`crate::crypto::aad_for`] so a ciphertext lifted from one column
//!   cannot be replayed into another.
//!
//! After Task 47-06's one-shot migration drops the cleartext columns, the
//! `get` / `update` methods will be removed and the `_with_crypto` variants
//! will be renamed to take their place. Until then, the cleartext methods
//! stay so that `admin_api.rs` and the live `siem_connector.rs` paths
//! continue to function during incremental Wave 3 deployment.

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
/// [`SiemConfigRepository::get_with_crypto`]. Twelve columns:
/// `(splunk_url, splunk_token_cleartext, splunk_token_encrypted,
///   splunk_token_nonce, splunk_enabled, elk_url, elk_index,
///   elk_api_key_cleartext, elk_api_key_encrypted, elk_api_key_nonce,
///   elk_enabled, updated_at)`.
type SiemRawRow = (
    String,
    String,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    i64,
    String,
    String,
    String,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    i64,
    String,
);

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

/// Encrypted-side row produced by [`SiemConfigRepository::get_with_crypto`].
///
/// Secret-bearing fields are [`SecretString`] so the default `Debug` derive
/// redacts them. Non-secret fields (URLs, indices, enabled flags) remain
/// `String` / `i64` for ergonomic read access.
///
/// Task 47-09 will migrate the legacy [`SiemConfigRow`] callers in
/// `admin_api.rs` and `siem_connector.rs` to consume this shape instead.
#[derive(Debug, Clone)]
pub struct SiemConfigEncrypted {
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

    /// Reads the SIEM config and decrypts the encrypted-column secrets.
    ///
    /// Behaviour per column (`splunk_token`, `elk_api_key`):
    ///
    /// - If the `<col>_encrypted` BLOB is **non-NULL**, deserialize the
    ///   envelope and decrypt with AAD `aad_for("siem_config", col)`.
    ///   A non-NULL ciphertext that fails to decrypt is treated as a hard
    ///   error ([`AppError::Internal`]); the function does NOT silently
    ///   fall back to the cleartext column — that would mask tampering.
    /// - If the `<col>_encrypted` BLOB is NULL, fall back to the legacy
    ///   cleartext column. This is the transitional path used while the
    ///   one-shot Task 47-06 migration has not yet run.
    /// - Empty (cleartext is "") in both columns yields `None` — callers
    ///   that need to differentiate "not configured" from "configured but
    ///   empty" treat `None` as "not configured".
    ///
    /// # Arguments
    ///
    /// * `pool` — connection pool (read).
    /// * `crypto` — active KEK handle. Decryption uses this KEK's version.
    ///
    /// # Errors
    ///
    /// - [`AppError::Database`] when the underlying SELECT fails.
    /// - [`AppError::Internal`] when a non-NULL `*_encrypted` blob cannot be
    ///   decrypted (envelope malformed, tag mismatch, unknown version).
    pub fn get_with_crypto(
        pool: &Pool,
        crypto: &SecretCrypto,
    ) -> Result<SiemConfigEncrypted, AppError> {
        let conn = pool.get().map_err(AppError::from)?;
        let raw: SiemRawRow = conn
            .query_row(
                "SELECT splunk_url, splunk_token, \
                        splunk_token_encrypted, splunk_token_nonce, \
                        splunk_enabled, \
                        elk_url, elk_index, elk_api_key, \
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
                        row.get(10)?,
                        row.get(11)?,
                    ))
                },
            )
            .map_err(AppError::Database)?;

        let (
            splunk_url,
            splunk_token_cleartext,
            splunk_token_ct,
            splunk_token_nonce,
            splunk_enabled,
            elk_url,
            elk_index,
            elk_api_key_cleartext,
            elk_api_key_ct,
            elk_api_key_nonce,
            elk_enabled,
            updated_at,
        ) = raw;

        let splunk_token = decrypt_or_fallback(
            "siem_config",
            "splunk_token",
            splunk_token_ct.as_deref(),
            splunk_token_nonce.as_deref(),
            &splunk_token_cleartext,
            crypto,
        )?;
        let elk_api_key = decrypt_or_fallback(
            "siem_config",
            "elk_api_key",
            elk_api_key_ct.as_deref(),
            elk_api_key_nonce.as_deref(),
            &elk_api_key_cleartext,
            crypto,
        )?;

        Ok(SiemConfigEncrypted {
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

    /// Encrypts the secret-bearing fields and writes the full SIEM config
    /// row using the encrypted-column trio.
    ///
    /// For each secret column (`splunk_token`, `elk_api_key`):
    /// - If the incoming [`SecretString`] is `Some`, encrypt with AAD
    ///   `aad_for("siem_config", col)` and write the envelope into
    ///   `<col>_encrypted`, the nonce into `<col>_nonce`, and
    ///   `crypto.version()` into `<col>_version`.
    /// - Always NULL the cleartext `<col>` in the same UPDATE — the
    ///   transitional cleartext storage is being phased out by Task 47-06.
    /// - If the incoming value is `None`, all three encrypted-side columns
    ///   are set to NULL **and** the cleartext column is NULL'd. This
    ///   represents "explicitly clear the secret".
    ///
    /// All five columns per secret (cleartext + encrypted + nonce + version)
    /// are updated in a single UPDATE statement so the write is atomic with
    /// respect to readers.
    ///
    /// # Errors
    ///
    /// - [`AppError::Internal`] if encryption fails (unreachable with AES-GCM
    ///   and well-formed inputs, but the call is fallible).
    /// - [`AppError::Database`] if the UPDATE fails.
    pub fn update_with_crypto(
        uow: &UnitOfWork<'_>,
        record: &SiemConfigEncrypted,
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

        // Cleartext columns are still NOT NULL (DDL constraint) until Task
        // 47-06 drops them. Clear them with the empty string instead of
        // NULL. The `decrypt_or_fallback` reader treats empty cleartext as
        // "no fallback" so this is semantically equivalent to NULL.
        uow.tx
            .execute(
                "UPDATE siem_config SET \
                 splunk_url = ?1, \
                 splunk_token = '', \
                 splunk_token_encrypted = ?2, \
                 splunk_token_nonce = ?3, \
                 splunk_token_version = ?4, \
                 splunk_enabled = ?5, \
                 elk_url = ?6, elk_index = ?7, \
                 elk_api_key = '', \
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

/// Decrypt `<col>_encrypted`/`<col>_nonce` if both are present; otherwise
/// fall back to the cleartext column. Returns `None` when nothing usable
/// is configured (both ciphertext and cleartext are empty/NULL).
///
/// Decryption failure on a non-NULL ciphertext is a HARD error — we do NOT
/// silently fall back to the legacy column, because that would mask
/// tampering (an attacker who can blank `*_encrypted` would otherwise
/// redirect reads to the still-present cleartext column).
fn decrypt_or_fallback(
    table: &str,
    column: &str,
    ciphertext: Option<&[u8]>,
    nonce: Option<&[u8]>,
    cleartext_fallback: &str,
    crypto: &SecretCrypto,
) -> Result<Option<SecretString>, AppError> {
    if let (Some(ct), Some(n)) = (ciphertext, nonce) {
        // Both encrypted-side columns are populated. Reconstruct the
        // envelope and decrypt under the column-binding AAD.
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
        return Ok(Some(plaintext));
    }
    // Transitional fallback: read cleartext column. Empty -> None.
    if cleartext_fallback.is_empty() {
        Ok(None)
    } else {
        Ok(Some(SecretString::new(cleartext_fallback.to_string())))
    }
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
    use secrecy::ExposeSecret;

    const TEST_KEK: [u8; 32] = [
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42,
    ];

    fn fixture_crypto() -> SecretCrypto {
        SecretCrypto::from_kek(TEST_KEK, ENVELOPE_VERSION_V1)
    }

    fn fixture_row(splunk_token: &str, elk_api_key: &str) -> SiemConfigEncrypted {
        SiemConfigEncrypted {
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
        let pool = new_pool(":memory:").expect("create pool");
        let crypto = fixture_crypto();

        let original = fixture_row("splunk-token-XYZ", "elk-api-key-ABC");
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            SiemConfigRepository::update_with_crypto(&uow, &original, &crypto)
                .expect("update encrypted");
            uow.commit().expect("commit");
        }

        let got = SiemConfigRepository::get_with_crypto(&pool, &crypto).expect("get encrypted");
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
    fn update_nulls_cleartext_columns() {
        // After update_with_crypto, the legacy cleartext columns must be
        // NULL so reads can't accidentally pick them up.
        let pool = new_pool(":memory:").expect("create pool");
        let crypto = fixture_crypto();

        let row = fixture_row("token-A", "key-A");
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            SiemConfigRepository::update_with_crypto(&uow, &row, &crypto).expect("update");
            uow.commit().expect("commit");
        }

        let conn = pool.get().expect("acquire conn");
        // Cleartext columns are NOT NULL in the legacy DDL; until Task
        // 47-06 drops them, encrypt-aware writes clear them to '' (empty
        // string), which `decrypt_or_fallback` treats as "no fallback".
        let (splunk_clear, elk_clear): (String, String) = conn
            .query_row(
                "SELECT splunk_token, elk_api_key FROM siem_config WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("read raw row");
        assert_eq!(splunk_clear, "", "cleartext splunk_token must be empty");
        assert_eq!(elk_clear, "", "cleartext elk_api_key must be empty");
    }

    #[test]
    fn tamper_with_nonce_yields_decrypt_error() {
        let pool = new_pool(":memory:").expect("create pool");
        let crypto = fixture_crypto();

        let row = fixture_row("plaintext-XYZ", "key-A");
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            SiemConfigRepository::update_with_crypto(&uow, &row, &crypto).expect("update");
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

        let err = SiemConfigRepository::get_with_crypto(&pool, &crypto)
            .expect_err("must reject tampered nonce");
        let msg = err.to_string();
        assert!(
            msg.contains("decrypt failed for siem_config.splunk_token"),
            "expected typed decrypt error, got: {msg}"
        );
    }

    #[test]
    fn empty_secrets_round_trip_as_none() {
        let pool = new_pool(":memory:").expect("create pool");
        let crypto = fixture_crypto();

        let row = fixture_row("", "");
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            SiemConfigRepository::update_with_crypto(&uow, &row, &crypto).expect("update");
            uow.commit().expect("commit");
        }

        let got = SiemConfigRepository::get_with_crypto(&pool, &crypto).expect("get");
        assert!(
            got.splunk_token.is_none(),
            "empty splunk_token must round-trip as None"
        );
        assert!(
            got.elk_api_key.is_none(),
            "empty elk_api_key must round-trip as None"
        );
    }

    #[test]
    fn cleartext_fallback_path_decrypts_through_legacy_column() {
        // Seed cleartext via the legacy update() (no encryption), then
        // read via get_with_crypto: when *_encrypted is NULL, the helper
        // must read the cleartext column. This proves the transitional
        // path still works for rows that have not yet been migrated.
        let pool = new_pool(":memory:").expect("create pool");
        let crypto = fixture_crypto();

        let legacy = SiemConfigRow {
            splunk_url: "https://splunk".to_string(),
            splunk_token: "legacy-splunk".to_string(),
            splunk_enabled: 1,
            elk_url: "https://elastic".to_string(),
            elk_index: "idx".to_string(),
            elk_api_key: "legacy-elk".to_string(),
            elk_enabled: 1,
            updated_at: "2026-05-13T00:00:00Z".to_string(),
        };
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            SiemConfigRepository::update(&uow, &legacy).expect("legacy update");
            uow.commit().expect("commit");
        }

        let got = SiemConfigRepository::get_with_crypto(&pool, &crypto).expect("get");
        assert_eq!(
            got.splunk_token
                .as_ref()
                .map(|s| s.expose_secret().to_string()),
            Some("legacy-splunk".to_string()),
            "fallback to cleartext column must succeed when *_encrypted is NULL"
        );
        assert_eq!(
            got.elk_api_key
                .as_ref()
                .map(|s| s.expose_secret().to_string()),
            Some("legacy-elk".to_string()),
        );
    }
}
