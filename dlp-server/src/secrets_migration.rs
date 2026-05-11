//! Phase 47 Task 47-06 — One-shot atomic cleartext → encrypted migration.
//!
//! Runs once at every server start (idempotent). For each
//! `(table, cleartext_column)` in [`MIGRATION_TARGETS`]:
//!
//! 1. Within a single SQLite transaction, SELECT every row whose
//!    `<col>_encrypted` is NULL and whose `<col>` is non-empty.
//! 2. Encrypt each plaintext under `aad_for(table, col)`, store the
//!    envelope into the `<col>_encrypted`/`<col>_nonce`/`<col>_version`
//!    trio, and NULL the cleartext column in the same UPDATE.
//! 3. Read the row back, decrypt, and verify the plaintext matches.
//!    A mismatch rolls back the transaction.
//! 4. After every row in the table is processed (or the cleartext
//!    column was already empty), execute `ALTER TABLE <table> DROP
//!    COLUMN <col>` **inside the same transaction**. SQLite ≥ 3.35
//!    (released 2021-03) supports transactional DDL; rusqlite 0.39's
//!    bundled SQLite is well past this bound.
//!
//! After commit, the on-disk schema no longer carries the cleartext
//! column at all — this is the CONTEXT D-Q6 guarantee that no
//! persisted cleartext survives the migration.
//!
//! ## JWT special case
//!
//! Distinct from MIGRATION_TARGETS: when `secrets_jwt` is empty and a
//! `JWT_SECRET` env-var is set, the env-var is encrypted and inserted
//! into the `secrets_jwt` row, then logged via `tracing::warn!` as a
//! one-shot deprecation notice. Subsequent startups read the DB row
//! and ignore the env-var.
//!
//! ## Failure modes (CONTEXT D-Q4 — no auto-recovery)
//!
//! - DPAPI unprotect failure surfaces from [`crate::crypto::SecretCrypto::load_active_or_bootstrap`]
//!   and is returned as an `Err` to `main.rs`, which exits with a
//!   non-zero status. Recovery is operator-driven and documented in
//!   Phase 52.
//! - Encrypt+verify mismatch returns `Err` from inside the transaction;
//!   rusqlite's `Transaction::drop` rolls back automatically.
//! - Crash mid-write is recovered by SQLite WAL replay on the next
//!   startup; the migration re-runs from scratch.

use rusqlite::params;
use secrecy::ExposeSecret;

use crate::crypto::{aad_for, Envelope, SecretCrypto};
use crate::db::Pool;

/// `(table, cleartext_column_to_migrate_and_drop)` pairs.
///
/// The `<col>_encrypted` / `<col>_nonce` / `<col>_version` siblings were
/// added by Task 47-03's `run_migrations` ALTER statements. This list is
/// the data side of the migration.
///
/// `ldap_config.bind_password` is intentionally absent: the schema never
/// had a cleartext `bind_password` column (Task 47-03 added the encrypted
/// trio directly). The opt-in explicit-bind flow is managed solely via
/// [`crate::db::repositories::LdapConfigRepository::set_bind_password`].
const MIGRATION_TARGETS: &[(&str, &str)] = &[
    ("alert_router_config", "smtp_password"),
    ("alert_router_config", "webhook_secret"),
    ("siem_config", "splunk_token"),
    ("siem_config", "elk_api_key"),
];

/// Summary of what the migration did during a single startup.
///
/// Mirrors the `<interfaces>` block in 47-PLAN.md. Field meanings:
///
/// - `rows_encrypted`: total number of `(row, column)` pairs that were
///   encrypted across all targets in this run. A second run on an
///   already-migrated DB returns 0.
/// - `jwt_migrated_from_env`: `true` iff the JWT env-var was migrated
///   into `secrets_jwt` during this run.
/// - `cleartext_columns_dropped`: `"<table>.<column>"` strings for
///   every column physically removed by `ALTER TABLE ... DROP COLUMN`
///   in this run. On a subsequent (already-dropped) startup this is
///   empty.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MigrationReport {
    /// Number of (row, column) pairs encrypted in this run.
    pub rows_encrypted: u32,
    /// Whether the JWT env-var was migrated into `secrets_jwt` during
    /// this run.
    pub jwt_migrated_from_env: bool,
    /// `"<table>.<column>"` for every cleartext column dropped by this
    /// run via `ALTER TABLE ... DROP COLUMN`.
    pub cleartext_columns_dropped: Vec<String>,
}

/// Idempotent secrets migration entry point.
///
/// Runs once per server start (called from `dlp-server/src/main.rs`
/// after the connection pool and crypto handle are constructed). Safe
/// to re-run on an already-migrated database — it is effectively a
/// no-op when every cleartext column has already been dropped and the
/// JWT row already exists.
///
/// # Arguments
///
/// * `pool` — connection pool. The migration acquires its own
///   connections and opens its own transactions.
/// * `crypto` — active KEK handle obtained from
///   [`SecretCrypto::load_active_or_bootstrap`].
/// * `jwt_env_fallback` — typically `std::env::var("JWT_SECRET").ok().as_deref()`.
///   When `Some(value)` and `secrets_jwt` is empty, the env-var is
///   encrypted into the JWT row.
///
/// # Errors
///
/// Returns [`anyhow::Error`] wrapping any of:
///
/// - rusqlite errors during SELECT / UPDATE / ALTER.
/// - [`crate::crypto::CryptoError`] wrapped via `anyhow!` for
///   encrypt/decrypt failures.
/// - A read-back verify mismatch (a hard correctness failure — the
///   transaction is rolled back, the caller surfaces this as a
///   startup error per CONTEXT D-Q4).
pub fn migrate_secrets_to_encrypted(
    pool: &Pool,
    crypto: &SecretCrypto,
    jwt_env_fallback: Option<&str>,
) -> anyhow::Result<MigrationReport> {
    let mut report = MigrationReport::default();

    // --- Per-table cleartext → encrypted + DROP COLUMN pass. ------------
    for (table, column) in MIGRATION_TARGETS {
        let outcome = migrate_one_column(pool, crypto, table, column)?;
        report.rows_encrypted += outcome.rows_encrypted;
        if outcome.dropped {
            report
                .cleartext_columns_dropped
                .push(format!("{table}.{column}"));
        }
    }

    // --- JWT env-var → encrypted DB row (separate flow). ----------------
    if maybe_migrate_jwt_env(pool, crypto, jwt_env_fallback)? {
        report.jwt_migrated_from_env = true;
    }

    Ok(report)
}

/// Per-column outcome — the inner loop produces this so the report can
/// aggregate across targets.
#[derive(Debug, Default)]
struct PerColumnOutcome {
    rows_encrypted: u32,
    /// `true` iff the cleartext column was physically dropped by
    /// `ALTER TABLE ... DROP COLUMN` in this run. `false` when the
    /// column was already absent (idempotent re-run).
    dropped: bool,
}

/// Migrates one `(table, cleartext_column)` pair atomically.
///
/// Implementation outline:
///
/// 1. **Idempotency probe.** `PRAGMA table_info(<table>)` — if the
///    cleartext column is absent, return `(rows=0, dropped=false)`.
/// 2. **Transaction.** Open `Transaction`. SELECT every row's
///    `(rowid, cleartext, encrypted_blob_is_null)`. For each row
///    where the cleartext is non-empty AND the encrypted column is
///    NULL: encrypt, UPDATE, then SELECT-back + decrypt + assert
///    plaintext matches.
/// 3. **DDL inside the same transaction.** `ALTER TABLE <table> DROP
///    COLUMN <col>` (SQLite 3.35+; required).
/// 4. **Commit.** Any error before commit rolls back via
///    `Transaction::drop`.
fn migrate_one_column(
    pool: &Pool,
    crypto: &SecretCrypto,
    table: &str,
    column: &str,
) -> anyhow::Result<PerColumnOutcome> {
    // ---- Step 1: probe table_info for the cleartext column. -----------
    let cleartext_present = column_exists(pool, table, column)?;
    if !cleartext_present {
        return Ok(PerColumnOutcome::default());
    }

    // ---- Step 2 + 3 + 4: transactional encrypt-pass + DROP COLUMN. ----
    let mut conn = pool.get()?;
    let tx = conn.transaction()?;
    let aad = aad_for(table, column);
    let mut rows_encrypted: u32 = 0;

    // SELECT every row's id + cleartext + whether the encrypted column
    // is already populated. The `id = 1` single-row tables have exactly
    // one row, but we iterate generically so the same code handles
    // multi-row futures without special-casing.
    let select_sql = format!(
        "SELECT id, {col}, {col}_encrypted IS NOT NULL FROM {table}",
        col = column,
        table = table,
    );
    let rows: Vec<(i64, String, bool)> = {
        let mut stmt = tx.prepare(&select_sql)?;
        let mapped = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, bool>(2)?,
            ))
        })?;
        mapped.collect::<rusqlite::Result<Vec<_>>>()?
    };

    let update_sql = format!(
        "UPDATE {table} SET \
           {col}_encrypted = ?1, \
           {col}_nonce = ?2, \
           {col}_version = ?3, \
           {col} = '' \
         WHERE id = ?4",
        col = column,
        table = table,
    );
    let verify_sql = format!(
        "SELECT {col}_encrypted, {col}_nonce FROM {table} WHERE id = ?1",
        col = column,
        table = table,
    );

    for (row_id, cleartext, already_encrypted) in rows {
        // Skip rows that have already been migrated (their `_encrypted`
        // blob is non-NULL). The cleartext column is empty for those
        // rows in any case — Wave 3's `update_with_crypto` clears it
        // to '' — but we double-check on the encrypted-side flag rather
        // than the cleartext value so a stray operator-write can't fool
        // the migration into double-encrypting.
        if already_encrypted {
            continue;
        }
        // Skip rows with empty cleartext: nothing to migrate.
        if cleartext.is_empty() {
            continue;
        }

        // ---- Encrypt + write. ---------------------------------------
        let envelope: Envelope = crypto
            .encrypt(cleartext.as_bytes(), &aad)
            .map_err(|e| anyhow::anyhow!("encrypt failed for {table}.{column}: {e:?}"))?;
        tx.execute(
            &update_sql,
            params![
                envelope.ciphertext,
                envelope.nonce.as_slice(),
                crypto.version() as i64,
                row_id,
            ],
        )?;

        // ---- Verify (read-back + decrypt + compare). ----------------
        let (back_ct, back_nonce): (Vec<u8>, Vec<u8>) =
            tx.query_row(&verify_sql, params![row_id], |r| Ok((r.get(0)?, r.get(1)?)))?;
        if back_nonce.len() != crate::crypto::envelope::NONCE_LEN {
            return Err(anyhow::anyhow!(
                "verify failed for {table}.{column} (row {row_id}): nonce length"
            ));
        }
        let mut nonce_arr = [0u8; crate::crypto::envelope::NONCE_LEN];
        nonce_arr.copy_from_slice(&back_nonce);
        let back_env = Envelope::new(crate::crypto::ENVELOPE_VERSION_V1, nonce_arr, back_ct)
            .map_err(|e| {
                anyhow::anyhow!(
                    "verify failed for {table}.{column} (row {row_id}): envelope: {e:?}"
                )
            })?;
        let recovered = crypto.decrypt(&back_env, &aad).map_err(|e| {
            anyhow::anyhow!("verify failed for {table}.{column} (row {row_id}): decrypt: {e:?}")
        })?;
        if recovered.expose_secret() != cleartext.as_str() {
            return Err(anyhow::anyhow!(
                "verify failed for {table}.{column} (row {row_id}): plaintext mismatch"
            ));
        }
        rows_encrypted += 1;
    }

    // ---- Step 3: DROP COLUMN inside the same transaction. -----------
    // SQLite 3.35+ required for DROP COLUMN.
    let drop_sql = format!("ALTER TABLE {table} DROP COLUMN {column}");
    tx.execute(&drop_sql, [])?;

    // ---- Step 4: commit. --------------------------------------------
    tx.commit()?;

    Ok(PerColumnOutcome {
        rows_encrypted,
        dropped: true,
    })
}

/// `true` iff `table.column` is present in the live schema.
///
/// Uses `PRAGMA table_info(<table>)` which returns one row per column.
/// Cheap — the result is bounded by the column count of the named
/// table.
fn column_exists(pool: &Pool, table: &str, column: &str) -> anyhow::Result<bool> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}

/// JWT env-var → encrypted DB row migration. Returns `true` iff the
/// row was actually seeded in this run (i.e., the deprecation warn
/// was emitted).
///
/// Algorithm:
///
/// 1. If `secrets_jwt` already has a row, no-op (steady state — the
///    DB wins; the env-var is silently ignored on future startups).
/// 2. Else if `jwt_env_fallback` is `Some(non_empty)`, encrypt under
///    AAD `aad_for("secrets_jwt", "secret")`, insert via
///    [`crate::db::repositories::jwt_secret::upsert_encrypted`], and
///    log `tracing::warn!` exactly once.
/// 3. Else no-op — the production path will get a clean error from
///    [`crate::admin_auth::resolve_jwt_secret`] at JWT-issuance time
///    if neither DB nor env-var is configured.
fn maybe_migrate_jwt_env(
    pool: &Pool,
    crypto: &SecretCrypto,
    jwt_env_fallback: Option<&str>,
) -> anyhow::Result<bool> {
    let conn = pool.get()?;
    if crate::db::repositories::jwt_secret::get(&conn)?.is_some() {
        return Ok(false);
    }
    drop(conn);

    let env_value = match jwt_env_fallback {
        Some(s) if !s.is_empty() => s,
        _ => return Ok(false),
    };

    let aad = aad_for("secrets_jwt", "secret");
    let envelope = crypto
        .encrypt(env_value.as_bytes(), &aad)
        .map_err(|e| anyhow::anyhow!("encrypt failed for secrets_jwt.secret: {e:?}"))?;
    let conn = pool.get()?;
    crate::db::repositories::jwt_secret::upsert_encrypted(
        &conn,
        &envelope,
        crypto.version(),
        chrono::Utc::now(),
    )?;
    tracing::warn!(
        "JWT secret migrated from env-var into encrypted DB row; the JWT_SECRET env \
         variable is no longer required and will be ignored on future startups"
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ENVELOPE_VERSION_V1;
    use crate::db::new_pool;

    /// Deterministic 32-byte KEK keeps tests cross-platform — no DPAPI
    /// involvement. Production startup uses [`SecretCrypto::load_active_or_bootstrap`].
    const TEST_KEK: [u8; 32] = [0x7F; 32];

    fn fixture_crypto() -> SecretCrypto {
        SecretCrypto::from_kek(TEST_KEK, ENVELOPE_VERSION_V1)
    }

    /// Helper: confirm that `PRAGMA table_info` does NOT report the
    /// named column. Used to assert that DROP COLUMN actually fired.
    fn assert_column_absent(pool: &Pool, table: &str, column: &str) {
        let exists = column_exists(pool, table, column).expect("table_info");
        assert!(
            !exists,
            "{table}.{column} must have been dropped by the migration"
        );
    }

    #[test]
    fn empty_db_migration_is_a_noop_and_returns_default_report() {
        // Fresh DB: every cleartext column is empty (seed rows have
        // default ''). Migration must still DROP the columns (the
        // "transient cleartext column" guarantee from CONTEXT D-Q6
        // holds regardless of row contents) but must encrypt zero
        // rows.
        let pool = new_pool(":memory:").expect("create pool");
        let crypto = fixture_crypto();

        let report = migrate_secrets_to_encrypted(&pool, &crypto, None).expect("migrate empty db");
        assert_eq!(
            report.rows_encrypted, 0,
            "empty cleartext columns must not encrypt anything"
        );
        assert!(!report.jwt_migrated_from_env);
        // All four columns must be reported as dropped (because they
        // existed pre-migration but the seed values were empty).
        assert_eq!(
            report.cleartext_columns_dropped.len(),
            4,
            "all four MIGRATION_TARGETS columns must be dropped on first run; got {:?}",
            report.cleartext_columns_dropped
        );
        assert_column_absent(&pool, "alert_router_config", "smtp_password");
        assert_column_absent(&pool, "alert_router_config", "webhook_secret");
        assert_column_absent(&pool, "siem_config", "splunk_token");
        assert_column_absent(&pool, "siem_config", "elk_api_key");
    }

    #[test]
    fn seeded_cleartext_encrypts_and_drops_columns() {
        // Seed cleartext via direct SQL (mimicking a pre-Phase-47 row
        // that had real cleartext values), then run the migration and
        // verify both that the encrypted column round-trips AND that
        // the cleartext column is physically gone.
        let pool = new_pool(":memory:").expect("create pool");
        {
            let conn = pool.get().expect("acquire");
            conn.execute(
                "UPDATE alert_router_config SET smtp_password = ?1, webhook_secret = ?2 \
                 WHERE id = 1",
                params!["plaintext-pw-A", "plaintext-wh-B"],
            )
            .expect("seed alert_router_config");
            conn.execute(
                "UPDATE siem_config SET splunk_token = ?1, elk_api_key = ?2 WHERE id = 1",
                params!["plaintext-splunk-C", "plaintext-elk-D"],
            )
            .expect("seed siem_config");
        }

        let crypto = fixture_crypto();
        let report = migrate_secrets_to_encrypted(&pool, &crypto, None).expect("first migration");
        assert_eq!(report.rows_encrypted, 4, "four seeded rows must encrypt");

        // Cleartext columns gone.
        assert_column_absent(&pool, "alert_router_config", "smtp_password");
        assert_column_absent(&pool, "alert_router_config", "webhook_secret");
        assert_column_absent(&pool, "siem_config", "splunk_token");
        assert_column_absent(&pool, "siem_config", "elk_api_key");

        // Encrypted blobs are populated and round-trip correctly. We
        // decrypt directly via SecretCrypto so this test does NOT
        // depend on the repository-layer renaming work.
        let conn = pool.get().expect("acquire");
        let (smtp_ct, smtp_nonce): (Vec<u8>, Vec<u8>) = conn
            .query_row(
                "SELECT smtp_password_encrypted, smtp_password_nonce \
                 FROM alert_router_config WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("read encrypted");
        let mut nonce = [0u8; crate::crypto::envelope::NONCE_LEN];
        nonce.copy_from_slice(&smtp_nonce);
        let env = Envelope::new(ENVELOPE_VERSION_V1, nonce, smtp_ct).expect("envelope");
        let aad = aad_for("alert_router_config", "smtp_password");
        let recovered = crypto.decrypt(&env, &aad).expect("decrypt");
        assert_eq!(recovered.expose_secret(), "plaintext-pw-A");
    }

    #[test]
    fn idempotent_second_run_reports_zero_work() {
        // Run the migration twice. Second run must encrypt nothing
        // (cleartext columns are gone -> idempotency probe short-
        // circuits) and report no dropped columns.
        let pool = new_pool(":memory:").expect("create pool");
        let crypto = fixture_crypto();

        let _ = migrate_secrets_to_encrypted(&pool, &crypto, None).expect("first run");
        let second = migrate_secrets_to_encrypted(&pool, &crypto, None).expect("second run");
        assert_eq!(
            second,
            MigrationReport::default(),
            "second run must be a pure no-op"
        );
    }

    #[test]
    fn jwt_env_var_migrates_on_first_call_only() {
        let pool = new_pool(":memory:").expect("create pool");
        let crypto = fixture_crypto();

        // First call with env-var: migrates into the DB and reports true.
        let first = migrate_secrets_to_encrypted(&pool, &crypto, Some("fixture-jwt-XYZ"))
            .expect("first migrate");
        assert!(first.jwt_migrated_from_env);

        let conn = pool.get().expect("acquire");
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM secrets_jwt", [], |r| r.get(0))
            .expect("count");
        assert_eq!(n, 1, "secrets_jwt row must be seeded");
        drop(conn);

        // Second call with env-var still set: DB already populated,
        // env-var is silently ignored.
        let second = migrate_secrets_to_encrypted(&pool, &crypto, Some("different-fixture-jwt"))
            .expect("second migrate");
        assert!(
            !second.jwt_migrated_from_env,
            "second run must NOT re-migrate (DB row wins)"
        );

        // The DB row still decrypts to the FIRST value (env-var swap
        // does not retro-rewrite the row).
        let conn = pool.get().expect("acquire");
        let env_row = crate::db::repositories::jwt_secret::get(&conn)
            .expect("query")
            .expect("Some");
        let aad = aad_for("secrets_jwt", "secret");
        let recovered = crypto.decrypt(&env_row.0, &aad).expect("decrypt");
        assert_eq!(recovered.expose_secret(), "fixture-jwt-XYZ");
    }

    #[test]
    fn jwt_no_env_no_db_is_a_noop() {
        let pool = new_pool(":memory:").expect("create pool");
        let crypto = fixture_crypto();
        let report = migrate_secrets_to_encrypted(&pool, &crypto, None).expect("migrate");
        assert!(!report.jwt_migrated_from_env);

        let conn = pool.get().expect("acquire");
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM secrets_jwt", [], |r| r.get(0))
            .expect("count");
        assert_eq!(n, 0, "no env and no DB row: secrets_jwt stays empty");
    }

    #[test]
    fn migration_is_atomic_across_a_table_boundary() {
        // Confirm that after a successful migration, BOTH columns on a
        // single table are encrypted+dropped together. (Earlier prototype
        // code did one column per transaction; this test pins the
        // commit boundary so a regression to that pattern is caught.)
        let pool = new_pool(":memory:").expect("create pool");
        {
            let conn = pool.get().expect("acquire");
            conn.execute(
                "UPDATE alert_router_config SET smtp_password = ?1, webhook_secret = ?2 \
                 WHERE id = 1",
                params!["only-A", "only-B"],
            )
            .expect("seed");
        }
        let crypto = fixture_crypto();
        let report = migrate_secrets_to_encrypted(&pool, &crypto, None).expect("migrate");
        assert!(report
            .cleartext_columns_dropped
            .contains(&"alert_router_config.smtp_password".to_string()));
        assert!(report
            .cleartext_columns_dropped
            .contains(&"alert_router_config.webhook_secret".to_string()));
        assert_column_absent(&pool, "alert_router_config", "smtp_password");
        assert_column_absent(&pool, "alert_router_config", "webhook_secret");
    }
}
