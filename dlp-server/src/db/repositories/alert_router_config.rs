//! Repository for the `alert_router_config` table.
//!
//! Single-row configuration table (enforced via `CHECK (id = 1)`).
//! Provides typed access to email (SMTP) and webhook alert routing settings.
//!
//! # Phase 47 transition (Task 47-04)
//!
//! Two parallel read/write paths exist during the migration window. See the
//! analogous explanation in `siem_config.rs`. The `_with_crypto` methods
//! here additionally provide [`AlertRouterConfigRepository::get_secrets_with_crypto`]
//! which preserves the TOCTOU-safe mask round-trip (`admin_api.rs::ALERT_SECRET_MASK`):
//! the read happens inside the caller's existing `UnitOfWork`, so the
//! subsequent write that substitutes the mask sentinel is atomic with the
//! decrypt step.
//!
//! Secret-bearing structs use `SecretString` so the derived `Debug` redacts.
//! Do not add naked-String secret fields.

use rusqlite::params;
use secrecy::{ExposeSecret, SecretString};

use crate::crypto::{aad_for, Envelope, SecretCrypto};
use crate::db::{Pool, UnitOfWork};
use crate::AppError;

/// Raw `(ciphertext, nonce, kek_version)` triple per secret column —
/// `None` indicates "no secret configured" (all three columns NULL).
type EncryptedTriple = (Option<Vec<u8>>, Option<Vec<u8>>, Option<i64>);

/// Tuple returned by the `alert_router_config` SELECT inside
/// [`AlertRouterConfigRepository::get_with_crypto`]. Fifteen columns;
/// see the SELECT statement for the exact order.
type AlertRawRow = (
    String,          // smtp_host
    u16,             // smtp_port
    String,          // smtp_username
    String,          // smtp_password (cleartext fallback)
    Option<Vec<u8>>, // smtp_password_encrypted
    Option<Vec<u8>>, // smtp_password_nonce
    String,          // smtp_from
    String,          // smtp_to
    i64,             // smtp_enabled
    String,          // webhook_url
    String,          // webhook_secret (cleartext fallback)
    Option<Vec<u8>>, // webhook_secret_encrypted
    Option<Vec<u8>>, // webhook_secret_nonce
    i64,             // webhook_enabled
    String,          // updated_at
);

/// Tuple returned by the in-transaction SELECT inside
/// [`AlertRouterConfigRepository::get_secrets_with_crypto`]. Six columns:
/// the two cleartext-fallback strings plus encrypted/nonce blobs for each.
type AlertSecretsRow = (
    String,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    String,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);

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

/// Encrypted-side row produced by [`AlertRouterConfigRepository::get_with_crypto`].
///
/// Secret fields are wrapped in [`SecretString`] so the default `Debug`
/// derive redacts them — never log this struct via `{:?}` unless you've
/// confirmed `SecretString::Debug` is in effect (it is, in `secrecy 0.8`).
#[derive(Debug, Clone)]
pub struct AlertRouterConfigEncrypted {
    /// SMTP server hostname.
    pub smtp_host: String,
    /// SMTP server port.
    pub smtp_port: u16,
    /// SMTP authentication username (non-secret in this project's threat model).
    pub smtp_username: String,
    /// SMTP authentication password (decrypted) or `None` when no password
    /// is configured.
    pub smtp_password: Option<SecretString>,
    /// Sender email address.
    pub smtp_from: String,
    /// Recipient email address(es), comma-separated.
    pub smtp_to: String,
    /// Whether SMTP delivery is enabled (1 = true, 0 = false).
    pub smtp_enabled: i64,
    /// Webhook endpoint URL.
    pub webhook_url: String,
    /// HMAC secret for webhook signing (decrypted) or `None`.
    pub webhook_secret: Option<SecretString>,
    /// Whether webhook delivery is enabled (1 = true, 0 = false).
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
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
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

    /// Returns the plaintext `smtp_password` and `webhook_secret` values
    /// from the current alert router config row (legacy cleartext path).
    ///
    /// Used by `update_alert_config_handler` to resolve masked sentinels
    /// before writing. Reads from the transaction so the read and write
    /// are atomic (no TOCTOU window).
    ///
    /// **Task 47-04 transition note:** kept unchanged so `admin_api.rs`
    /// compiles. Once Task 47-06 lands AppState's `Arc<SecretCrypto>`,
    /// `admin_api.rs` will switch to [`Self::get_secrets_with_crypto`]
    /// and this method will be deleted alongside the legacy `update()`.
    ///
    /// # Arguments
    ///
    /// * `uow` - Active unit of work to read from (provides the transaction).
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the query fails.
    pub fn get_secrets(uow: &UnitOfWork<'_>) -> rusqlite::Result<(String, String)> {
        uow.tx.query_row(
            "SELECT smtp_password, webhook_secret FROM alert_router_config WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
    }

    /// Reads the alert router config and decrypts the encrypted-column secrets.
    ///
    /// Mirrors `siem_config::SiemConfigRepository::get_with_crypto`:
    /// encrypted columns are decrypted with column-binding AAD; cleartext
    /// fallback applies only when `*_encrypted` is NULL; non-NULL ciphertext
    /// that fails to decrypt is a hard error rather than a silent fallback.
    ///
    /// # Errors
    ///
    /// - [`AppError::Database`] for SELECT or `smtp_port`-overflow failures.
    /// - [`AppError::Internal`] for decrypt errors on a non-NULL `*_encrypted`.
    pub fn get_with_crypto(
        pool: &Pool,
        crypto: &SecretCrypto,
    ) -> Result<AlertRouterConfigEncrypted, AppError> {
        let conn = pool.get().map_err(AppError::from)?;
        let raw: AlertRawRow = conn
            .query_row(
                "SELECT smtp_host, smtp_port, smtp_username, smtp_password, \
                        smtp_password_encrypted, smtp_password_nonce, \
                        smtp_from, smtp_to, smtp_enabled, \
                        webhook_url, webhook_secret, \
                        webhook_secret_encrypted, webhook_secret_nonce, \
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
                    Ok((
                        row.get::<_, String>(0)?,
                        smtp_port,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<Vec<u8>>>(4)?,
                        row.get::<_, Option<Vec<u8>>>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, i64>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, String>(10)?,
                        row.get::<_, Option<Vec<u8>>>(11)?,
                        row.get::<_, Option<Vec<u8>>>(12)?,
                        row.get::<_, i64>(13)?,
                        row.get::<_, String>(14)?,
                    ))
                },
            )
            .map_err(AppError::Database)?;
        let (
            smtp_host,
            smtp_port,
            smtp_username,
            smtp_password_clear,
            smtp_password_ct,
            smtp_password_nonce,
            smtp_from,
            smtp_to,
            smtp_enabled,
            webhook_url,
            webhook_secret_clear,
            webhook_secret_ct,
            webhook_secret_nonce,
            webhook_enabled,
            updated_at,
        ) = raw;

        let smtp_password = decrypt_or_fallback(
            "alert_router_config",
            "smtp_password",
            smtp_password_ct.as_deref(),
            smtp_password_nonce.as_deref(),
            &smtp_password_clear,
            crypto,
        )?;
        let webhook_secret = decrypt_or_fallback(
            "alert_router_config",
            "webhook_secret",
            webhook_secret_ct.as_deref(),
            webhook_secret_nonce.as_deref(),
            &webhook_secret_clear,
            crypto,
        )?;

        Ok(AlertRouterConfigEncrypted {
            smtp_host,
            smtp_port,
            smtp_username,
            smtp_password,
            smtp_from,
            smtp_to,
            smtp_enabled,
            webhook_url,
            webhook_secret,
            webhook_enabled,
            updated_at,
        })
    }

    /// Encrypts secret-bearing fields and writes the full alert router
    /// config row using the encrypted-column trio.
    ///
    /// See the analogous documentation on
    /// [`super::siem_config::SiemConfigRepository::update_with_crypto`].
    /// The cleartext `smtp_password` / `webhook_secret` columns are NULL'd
    /// in the same UPDATE — Task 47-06 will drop them entirely.
    ///
    /// # Errors
    ///
    /// - [`AppError::Internal`] on encryption failure.
    /// - [`AppError::Database`] on UPDATE failure.
    pub fn update_with_crypto(
        uow: &UnitOfWork<'_>,
        record: &AlertRouterConfigEncrypted,
        crypto: &SecretCrypto,
    ) -> Result<(), AppError> {
        let (smtp_ct, smtp_nonce, smtp_ver) = encrypt_optional(
            "alert_router_config",
            "smtp_password",
            record.smtp_password.as_ref(),
            crypto,
        )?;
        let (webhook_ct, webhook_nonce, webhook_ver) = encrypt_optional(
            "alert_router_config",
            "webhook_secret",
            record.webhook_secret.as_ref(),
            crypto,
        )?;

        // Cleartext columns are still NOT NULL (DDL constraint) until Task
        // 47-06 drops them. Clear them with '' instead of NULL — the
        // `decrypt_or_fallback` reader treats empty cleartext as "no
        // fallback", semantically equivalent to NULL.
        uow.tx
            .execute(
                "UPDATE alert_router_config SET \
                 smtp_host = ?1, smtp_port = ?2, smtp_username = ?3, \
                 smtp_password = '', \
                 smtp_password_encrypted = ?4, \
                 smtp_password_nonce = ?5, \
                 smtp_password_version = ?6, \
                 smtp_from = ?7, smtp_to = ?8, smtp_enabled = ?9, \
                 webhook_url = ?10, \
                 webhook_secret = '', \
                 webhook_secret_encrypted = ?11, \
                 webhook_secret_nonce = ?12, \
                 webhook_secret_version = ?13, \
                 webhook_enabled = ?14, \
                 updated_at = ?15 \
                 WHERE id = 1",
                params![
                    record.smtp_host,
                    record.smtp_port,
                    record.smtp_username,
                    smtp_ct,
                    smtp_nonce,
                    smtp_ver,
                    record.smtp_from,
                    record.smtp_to,
                    record.smtp_enabled,
                    record.webhook_url,
                    webhook_ct,
                    webhook_nonce,
                    webhook_ver,
                    record.webhook_enabled,
                    record.updated_at,
                ],
            )
            .map_err(AppError::Database)?;
        Ok(())
    }

    /// TOCTOU-safe encrypted-column reader for the mask round-trip.
    ///
    /// Returns the decrypted `(smtp_password, webhook_secret)` pair within
    /// the caller's active transaction. Used by future versions of
    /// `admin_api::update_alert_config_handler` once that handler is wired
    /// against `SecretCrypto` (Task 47-06+).
    ///
    /// Fallback semantics match [`Self::get_with_crypto`]: a non-NULL
    /// `*_encrypted` blob that fails to decrypt is a hard error; a NULL
    /// `*_encrypted` reads the cleartext column for the transition window.
    /// An empty cleartext column yields an empty string (preserves the
    /// existing API contract that `get_secrets()` returns `(String, String)`).
    ///
    /// # Errors
    ///
    /// - [`AppError::Database`] on SELECT failure.
    /// - [`AppError::Internal`] on decrypt failure with populated ciphertext.
    pub fn get_secrets_with_crypto(
        uow: &UnitOfWork<'_>,
        crypto: &SecretCrypto,
    ) -> Result<(SecretString, SecretString), AppError> {
        let raw: AlertSecretsRow = uow
            .tx
            .query_row(
                "SELECT smtp_password, \
                        smtp_password_encrypted, smtp_password_nonce, \
                        webhook_secret, \
                        webhook_secret_encrypted, webhook_secret_nonce \
                 FROM alert_router_config WHERE id = 1",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .map_err(AppError::Database)?;
        let (smtp_clear, smtp_ct, smtp_nonce, webhook_clear, webhook_ct, webhook_nonce) = raw;

        let smtp_password = decrypt_or_fallback(
            "alert_router_config",
            "smtp_password",
            smtp_ct.as_deref(),
            smtp_nonce.as_deref(),
            &smtp_clear,
            crypto,
        )?
        .unwrap_or_else(|| SecretString::new(String::new()));
        let webhook_secret = decrypt_or_fallback(
            "alert_router_config",
            "webhook_secret",
            webhook_ct.as_deref(),
            webhook_nonce.as_deref(),
            &webhook_clear,
            crypto,
        )?
        .unwrap_or_else(|| SecretString::new(String::new()));

        Ok((smtp_password, webhook_secret))
    }
}

/// Decrypt `<col>_encrypted`/`<col>_nonce` if both are present; otherwise
/// fall back to the cleartext column. Returns `None` when nothing usable
/// is configured. Decryption failure on a non-NULL ciphertext is a HARD
/// error — silent fallback would mask tampering.
fn decrypt_or_fallback(
    table: &str,
    column: &str,
    ciphertext: Option<&[u8]>,
    nonce: Option<&[u8]>,
    cleartext_fallback: &str,
    crypto: &SecretCrypto,
) -> Result<Option<SecretString>, AppError> {
    if let (Some(ct), Some(n)) = (ciphertext, nonce) {
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
    if cleartext_fallback.is_empty() {
        Ok(None)
    } else {
        Ok(Some(SecretString::new(cleartext_fallback.to_string())))
    }
}

/// Encrypt an optional secret. Symmetric with the helper in `siem_config.rs`.
fn encrypt_optional(
    table: &str,
    column: &str,
    plaintext: Option<&SecretString>,
    crypto: &SecretCrypto,
) -> Result<EncryptedTriple, AppError> {
    match plaintext {
        Some(s) => {
            let aad = aad_for(table, column);
            let env = crypto
                .encrypt(s.expose_secret().as_bytes(), &aad)
                .map_err(|_| {
                    AppError::Internal(anyhow::anyhow!("encrypt failed for {table}.{column}"))
                })?;
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

    /// ALERT_SECRET_MASK sentinel value duplicated locally so the test
    /// doesn't reach into `admin_api.rs` (which is a binary-side module
    /// and a much larger compile dependency). Must stay in sync with
    /// `admin_api::ALERT_SECRET_MASK`.
    const TEST_MASK: &str = "***MASKED***";

    const TEST_KEK: [u8; 32] = [
        0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17,
        0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17,
        0x17, 0x17,
    ];

    fn fixture_crypto() -> SecretCrypto {
        SecretCrypto::from_kek(TEST_KEK, ENVELOPE_VERSION_V1)
    }

    fn fixture_row(pw: &str, webhook: &str) -> AlertRouterConfigEncrypted {
        AlertRouterConfigEncrypted {
            smtp_host: "smtp.example.com".to_string(),
            smtp_port: 587,
            smtp_username: "dlp-alerts@example.com".to_string(),
            smtp_password: if pw.is_empty() {
                None
            } else {
                Some(SecretString::new(pw.to_string()))
            },
            smtp_from: "dlp-alerts@example.com".to_string(),
            smtp_to: "soc@example.com".to_string(),
            smtp_enabled: 1,
            webhook_url: "https://hooks.example.com/dlp".to_string(),
            webhook_secret: if webhook.is_empty() {
                None
            } else {
                Some(SecretString::new(webhook.to_string()))
            },
            webhook_enabled: 1,
            updated_at: "2026-05-13T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn update_then_get_round_trips_both_secrets() {
        let pool = new_pool(":memory:").expect("create pool");
        let crypto = fixture_crypto();

        let original = fixture_row("smtp-password-A", "webhook-secret-B");
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            AlertRouterConfigRepository::update_with_crypto(&uow, &original, &crypto)
                .expect("update encrypted");
            uow.commit().expect("commit");
        }

        let got =
            AlertRouterConfigRepository::get_with_crypto(&pool, &crypto).expect("get encrypted");
        assert_eq!(
            got.smtp_password
                .as_ref()
                .map(|s| s.expose_secret().to_string()),
            Some("smtp-password-A".to_string())
        );
        assert_eq!(
            got.webhook_secret
                .as_ref()
                .map(|s| s.expose_secret().to_string()),
            Some("webhook-secret-B".to_string())
        );
        assert_eq!(got.smtp_host, "smtp.example.com");
        assert_eq!(got.smtp_port, 587);
        assert_eq!(got.smtp_enabled, 1);
    }

    #[test]
    fn update_nulls_cleartext_columns() {
        let pool = new_pool(":memory:").expect("create pool");
        let crypto = fixture_crypto();

        let row = fixture_row("pw-A", "webhook-A");
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            AlertRouterConfigRepository::update_with_crypto(&uow, &row, &crypto).expect("update");
            uow.commit().expect("commit");
        }

        let conn = pool.get().expect("acquire conn");
        let (pw_clear, webhook_clear): (String, String) = conn
            .query_row(
                "SELECT smtp_password, webhook_secret \
                 FROM alert_router_config WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("read raw");
        assert_eq!(
            pw_clear, "",
            "cleartext smtp_password must be cleared to ''"
        );
        assert_eq!(
            webhook_clear, "",
            "cleartext webhook_secret must be cleared to ''"
        );
    }

    #[test]
    fn tamper_with_nonce_yields_decrypt_error() {
        let pool = new_pool(":memory:").expect("create pool");
        let crypto = fixture_crypto();

        let row = fixture_row("plain-A", "webhook-A");
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            AlertRouterConfigRepository::update_with_crypto(&uow, &row, &crypto).expect("update");
            uow.commit().expect("commit");
        }

        // Bit-flip the smtp_password_nonce.
        {
            let conn = pool.get().expect("acquire connection");
            let mut nonce: Vec<u8> = conn
                .query_row(
                    "SELECT smtp_password_nonce FROM alert_router_config WHERE id = 1",
                    [],
                    |r| r.get(0),
                )
                .expect("read nonce");
            nonce[0] ^= 0xFF;
            conn.execute(
                "UPDATE alert_router_config SET smtp_password_nonce = ?1 WHERE id = 1",
                params![nonce],
            )
            .expect("write tampered nonce");
        }

        let err = AlertRouterConfigRepository::get_with_crypto(&pool, &crypto)
            .expect_err("must reject tampered nonce");
        assert!(
            err.to_string()
                .contains("decrypt failed for alert_router_config.smtp_password"),
            "expected typed decrypt error, got: {err}"
        );
    }

    #[test]
    fn cross_column_replay_rejected_by_aad() {
        // T-47-02: ciphertext bound to (alert_router_config, smtp_password)
        // must not decrypt under (alert_router_config, webhook_secret).
        // Swap the two encrypted columns on disk and verify the read fails.
        let pool = new_pool(":memory:").expect("create pool");
        let crypto = fixture_crypto();

        let row = fixture_row("plain-PW", "plain-WH");
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            AlertRouterConfigRepository::update_with_crypto(&uow, &row, &crypto).expect("update");
            uow.commit().expect("commit");
        }

        // Swap smtp_password_{encrypted,nonce} with webhook_secret_{encrypted,nonce}.
        {
            let conn = pool.get().expect("acquire connection");
            let (pw_ct, pw_n, wh_ct, wh_n): (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = conn
                .query_row(
                    "SELECT smtp_password_encrypted, smtp_password_nonce, \
                            webhook_secret_encrypted, webhook_secret_nonce \
                     FROM alert_router_config WHERE id = 1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .expect("read raw");
            conn.execute(
                "UPDATE alert_router_config SET \
                   smtp_password_encrypted = ?1, smtp_password_nonce = ?2, \
                   webhook_secret_encrypted = ?3, webhook_secret_nonce = ?4 \
                 WHERE id = 1",
                params![wh_ct, wh_n, pw_ct, pw_n],
            )
            .expect("swap columns");
        }

        let err = AlertRouterConfigRepository::get_with_crypto(&pool, &crypto)
            .expect_err("cross-column replay must fail");
        assert!(
            err.to_string()
                .contains("decrypt failed for alert_router_config"),
            "expected AAD-mismatch decrypt error, got: {err}"
        );
    }

    #[test]
    fn mask_round_trip_preserves_existing_secret() {
        // Simulates the admin_api::ALERT_SECRET_MASK round-trip:
        //   1. Write plaintext A via update_with_crypto.
        //   2. PUT with mask sentinel: read existing via get_secrets_with_crypto
        //      (TOCTOU-safe), then write the recovered plaintext back.
        //   3. Read again — plaintext A must still be recoverable.
        let pool = new_pool(":memory:").expect("create pool");
        let crypto = fixture_crypto();

        // Step 1.
        let initial = fixture_row("plaintext-A", "webhook-A");
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            AlertRouterConfigRepository::update_with_crypto(&uow, &initial, &crypto)
                .expect("initial update");
            uow.commit().expect("commit");
        }

        // Step 2: simulate an admin PUT that echoes the mask sentinel back.
        // The handler resolves the mask within the same UoW via
        // `get_secrets_with_crypto`, then writes the recovered plaintext.
        let incoming_smtp = TEST_MASK.to_string();
        let incoming_webhook = TEST_MASK.to_string();
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            let (stored_smtp, stored_webhook) =
                AlertRouterConfigRepository::get_secrets_with_crypto(&uow, &crypto)
                    .expect("resolve secrets in-tx");

            let smtp_to_write = if incoming_smtp == TEST_MASK {
                stored_smtp
            } else {
                SecretString::new(incoming_smtp.clone())
            };
            let webhook_to_write = if incoming_webhook == TEST_MASK {
                stored_webhook
            } else {
                SecretString::new(incoming_webhook.clone())
            };

            // Re-write with the resolved plaintext (also bump updated_at).
            let record = AlertRouterConfigEncrypted {
                smtp_password: Some(smtp_to_write),
                webhook_secret: Some(webhook_to_write),
                updated_at: "2026-05-13T01:00:00Z".to_string(),
                ..initial.clone()
            };
            AlertRouterConfigRepository::update_with_crypto(&uow, &record, &crypto)
                .expect("update post-mask");
            uow.commit().expect("commit");
        }

        // Step 3: original plaintext survives the mask round-trip.
        let got = AlertRouterConfigRepository::get_with_crypto(&pool, &crypto).expect("get");
        assert_eq!(
            got.smtp_password
                .as_ref()
                .map(|s| s.expose_secret().to_string()),
            Some("plaintext-A".to_string()),
            "mask round-trip must preserve the original SMTP plaintext"
        );
        assert_eq!(
            got.webhook_secret
                .as_ref()
                .map(|s| s.expose_secret().to_string()),
            Some("webhook-A".to_string()),
        );
        assert_eq!(got.updated_at, "2026-05-13T01:00:00Z");
    }

    /// Phase 47 Task 47-09: prove `Debug` on `AlertRouterConfigEncrypted`
    /// redacts the secret fields. The fixture password's literal substring
    /// MUST NOT appear in the formatted output — `SecretString` renders as
    /// `Secret([REDACTED ...])`.
    #[test]
    fn secret_debug_redacts() {
        let row = AlertRouterConfigEncrypted {
            smtp_host: "smtp.example.com".to_string(),
            smtp_port: 587,
            smtp_username: "alerts@example.com".to_string(),
            smtp_password: Some(SecretString::new("FIXTURE-PASSWORD-XYZ".to_string())),
            smtp_from: "alerts@example.com".to_string(),
            smtp_to: "soc@example.com".to_string(),
            smtp_enabled: 1,
            webhook_url: "https://hooks.example.com".to_string(),
            webhook_secret: Some(SecretString::new("FIXTURE-WEBHOOK-ABC".to_string())),
            webhook_enabled: 1,
            updated_at: "2026-05-13T00:00:00Z".to_string(),
        };
        let dbg = format!("{row:?}");
        assert!(
            !dbg.contains("FIXTURE-PASSWORD-XYZ"),
            "smtp_password must be redacted in Debug; got: {dbg}"
        );
        assert!(
            !dbg.contains("FIXTURE-WEBHOOK-ABC"),
            "webhook_secret must be redacted in Debug; got: {dbg}"
        );
        // Sanity: non-secret fields ARE present (the redaction is targeted).
        assert!(dbg.contains("smtp.example.com"));
    }

    #[test]
    fn get_secrets_with_crypto_falls_back_to_cleartext_when_unencrypted() {
        // Pre-migration row (legacy update()) — encrypted columns NULL.
        // get_secrets_with_crypto must still resolve to plaintext via the
        // cleartext column for the transition window.
        let pool = new_pool(":memory:").expect("create pool");
        let crypto = fixture_crypto();

        let legacy = AlertRouterConfigRow {
            smtp_host: "smtp".to_string(),
            smtp_port: 25,
            smtp_username: "u".to_string(),
            smtp_password: "legacy-pw".to_string(),
            smtp_from: "f@x".to_string(),
            smtp_to: "t@x".to_string(),
            smtp_enabled: 0,
            webhook_url: String::new(),
            webhook_secret: "legacy-wh".to_string(),
            webhook_enabled: 0,
            updated_at: "2026-05-13T00:00:00Z".to_string(),
        };
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            AlertRouterConfigRepository::update(&uow, &legacy).expect("legacy update");
            uow.commit().expect("commit");
        }

        let mut conn = pool.get().expect("acquire connection");
        let uow = UnitOfWork::new(&mut conn).expect("begin uow");
        let (pw, wh) = AlertRouterConfigRepository::get_secrets_with_crypto(&uow, &crypto)
            .expect("get_secrets fallback");
        assert_eq!(pw.expose_secret(), "legacy-pw");
        assert_eq!(wh.expose_secret(), "legacy-wh");
    }
}
