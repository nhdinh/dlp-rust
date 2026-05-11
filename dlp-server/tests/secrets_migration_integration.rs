//! Phase 47 Task 47-11 — Migration acceptance tests (success criteria #2, #3).
//!
//! Asserts:
//!
//! * `secrets_migration::migrate_secrets_to_encrypted` upgrades pre-Phase-47
//!   cleartext rows into `*_encrypted` rows AND drops the cleartext column
//!   in the same commit (CONTEXT D-Q6: no cleartext column survives the
//!   migration).
//! * The JWT env-var → encrypted DB row migration runs exactly once
//!   (success criterion #2 special case).
//! * The migration is idempotent: a second run on an already-migrated DB
//!   produces `MigrationReport::default()`.
//!
//! Windows-only because `SecretCrypto::load_active_or_bootstrap` is used
//! by the JWT-env test; the other tests run a deterministic test KEK so
//! they could go cross-platform, but gating the whole file simplifies CI.

#![cfg(windows)]

use std::sync::Arc;

use dlp_server::crypto::{aad_for, SecretCrypto, ENVELOPE_VERSION_V1};
use dlp_server::db::{self, Pool};
use dlp_server::secrets_migration::{self, MigrationReport};
use rusqlite::params;
use secrecy::ExposeSecret;
use tempfile::NamedTempFile;

/// Deterministic KEK so migration round-trips can be verified without
/// DPAPI involvement. Production uses
/// `SecretCrypto::load_active_or_bootstrap`.
const TEST_KEK: [u8; 32] = [0xA5; 32];

fn fixture_crypto() -> SecretCrypto {
    SecretCrypto::from_kek(TEST_KEK, ENVELOPE_VERSION_V1)
}

/// Builds a fresh file-backed pool with the full Phase 47 schema.
fn fresh_pool() -> (NamedTempFile, Arc<Pool>) {
    let tmp = NamedTempFile::new().expect("create temp DB file");
    let pool =
        Arc::new(db::new_pool(tmp.path().to_str().expect("UTF-8 temp path")).expect("init pool"));
    (tmp, pool)
}

/// `PRAGMA table_info` helper — returns `true` iff `table.column` exists.
fn column_present(pool: &Pool, table: &str, column: &str) -> bool {
    let conn = pool.get().expect("acquire");
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .expect("prepare pragma");
    let mut rows = stmt.query([]).expect("query pragma");
    while let Some(row) = rows.next().expect("row iter") {
        let name: String = row.get(1).expect("name");
        if name == column {
            return true;
        }
    }
    false
}

#[test]
fn test_migration_drops_cleartext_columns_in_same_commit() {
    // Seed every MIGRATION_TARGETS column with cleartext, run migration,
    // assert: every cleartext column is GONE (not just NULL), the
    // encrypted column round-trips via crypto.decrypt.
    let (_keep, pool) = fresh_pool();

    // Pre-conditions: cleartext columns must EXIST on the fresh DB
    // (Wave 3 ALTERs created the encrypted siblings but the cleartext
    // columns are still there until the migration runs).
    assert!(
        column_present(&pool, "alert_router_config", "smtp_password"),
        "fresh DB must still have the cleartext smtp_password column \
         (migration has not run yet)"
    );
    assert!(column_present(
        &pool,
        "alert_router_config",
        "webhook_secret"
    ));
    assert!(column_present(&pool, "siem_config", "splunk_token"));
    assert!(column_present(&pool, "siem_config", "elk_api_key"));

    // Seed each cleartext column with a distinct fixture string.
    {
        let conn = pool.get().expect("acquire");
        conn.execute(
            "UPDATE alert_router_config SET smtp_password = ?1, webhook_secret = ?2 \
             WHERE id = 1",
            params!["migration-smtp", "migration-webhook"],
        )
        .expect("seed alert");
        conn.execute(
            "UPDATE siem_config SET splunk_token = ?1, elk_api_key = ?2 WHERE id = 1",
            params!["migration-splunk", "migration-elk"],
        )
        .expect("seed siem");
    }

    let crypto = fixture_crypto();
    let report = secrets_migration::migrate_secrets_to_encrypted(&pool, &crypto, None)
        .expect("migration must succeed");
    assert_eq!(report.rows_encrypted, 4);
    assert_eq!(
        report.cleartext_columns_dropped.len(),
        4,
        "all four cleartext columns must be dropped: {:?}",
        report.cleartext_columns_dropped
    );

    // ---- D-Q6 ASSERTION: cleartext columns are PHYSICALLY GONE. -----
    assert!(
        !column_present(&pool, "alert_router_config", "smtp_password"),
        "smtp_password cleartext column must be DROPPED, not just emptied"
    );
    assert!(!column_present(
        &pool,
        "alert_router_config",
        "webhook_secret"
    ));
    assert!(!column_present(&pool, "siem_config", "splunk_token"));
    assert!(!column_present(&pool, "siem_config", "elk_api_key"));

    // ---- Round-trip via the encrypted columns + crypto.decrypt. -----
    let conn = pool.get().expect("acquire");
    for (table, col, expected) in [
        ("alert_router_config", "smtp_password", "migration-smtp"),
        ("alert_router_config", "webhook_secret", "migration-webhook"),
        ("siem_config", "splunk_token", "migration-splunk"),
        ("siem_config", "elk_api_key", "migration-elk"),
    ] {
        let sql = format!("SELECT {col}_encrypted, {col}_nonce FROM {table} WHERE id = 1");
        let (ct, nonce_blob): (Vec<u8>, Vec<u8>) = conn
            .query_row(&sql, [], |r| Ok((r.get(0)?, r.get(1)?)))
            .expect("read encrypted");
        let mut nonce = [0u8; dlp_server::crypto::envelope::NONCE_LEN];
        nonce.copy_from_slice(&nonce_blob);
        let env =
            dlp_server::crypto::Envelope::new(ENVELOPE_VERSION_V1, nonce, ct).expect("envelope");
        let recovered = crypto.decrypt(&env, &aad_for(table, col)).expect("decrypt");
        assert_eq!(
            recovered.expose_secret(),
            expected,
            "{table}.{col} must round-trip to its fixture plaintext"
        );
    }
}

#[test]
fn test_migration_idempotent_on_already_migrated_db() {
    // First run migrates, second run is a pure no-op.
    let (_keep, pool) = fresh_pool();
    let crypto = fixture_crypto();

    let _first = secrets_migration::migrate_secrets_to_encrypted(&pool, &crypto, None)
        .expect("first migration");
    let second = secrets_migration::migrate_secrets_to_encrypted(&pool, &crypto, None)
        .expect("second migration");
    assert_eq!(
        second,
        MigrationReport::default(),
        "second migration must be a pure no-op (rows=0, jwt_migrated=false, drops=[])"
    );
}

#[test]
fn test_jwt_env_var_migrates_to_db_on_first_call_only() {
    // Set a magic JWT env-var, run migration once -> secrets_jwt row
    // appears, deprecation warn fires. Clear env, run migration again
    // (idempotent path): no re-migration, row still decrypts to the
    // ORIGINAL magic value.
    let (_keep, pool) = fresh_pool();
    let crypto = fixture_crypto();

    // Step 1: env-set, DB empty -> migrates.
    let first = secrets_migration::migrate_secrets_to_encrypted(
        &pool,
        &crypto,
        Some("magic-jwt-from-env-v0.9.0"),
    )
    .expect("first migrate");
    assert!(
        first.jwt_migrated_from_env,
        "first call with env-var must flip jwt_migrated_from_env=true"
    );

    // Step 2: confirm secrets_jwt row exists and decrypts.
    {
        let conn = pool.get().expect("acquire");
        let row = dlp_server::db::repositories::jwt_secret::get(&conn)
            .expect("query")
            .expect("Some row after migration");
        let recovered = crypto
            .decrypt(&row.0, &aad_for("secrets_jwt", "secret"))
            .expect("decrypt jwt");
        assert_eq!(
            recovered.expose_secret(),
            "magic-jwt-from-env-v0.9.0",
            "DB row must decrypt to the env-var's value"
        );
    }

    // Step 3: re-run migration, this time with a DIFFERENT env-var
    // value to prove the DB wins (env-var is silently ignored on
    // subsequent startups).
    let second = secrets_migration::migrate_secrets_to_encrypted(
        &pool,
        &crypto,
        Some("DIFFERENT-but-ignored-jwt"),
    )
    .expect("second migrate");
    assert!(
        !second.jwt_migrated_from_env,
        "second run must NOT re-migrate (DB row wins; env-var silently ignored)"
    );

    let conn = pool.get().expect("acquire");
    let row = dlp_server::db::repositories::jwt_secret::get(&conn)
        .expect("query")
        .expect("still Some");
    let recovered = crypto
        .decrypt(&row.0, &aad_for("secrets_jwt", "secret"))
        .expect("decrypt jwt");
    assert_eq!(
        recovered.expose_secret(),
        "magic-jwt-from-env-v0.9.0",
        "DB row stays at the FIRST-startup value; env-var swap does not retro-rewrite"
    );
}

#[test]
fn test_migration_jwt_no_env_no_db_is_a_noop() {
    let (_keep, pool) = fresh_pool();
    let crypto = fixture_crypto();
    let report =
        secrets_migration::migrate_secrets_to_encrypted(&pool, &crypto, None).expect("migrate");
    assert!(!report.jwt_migrated_from_env);

    let conn = pool.get().expect("acquire");
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM secrets_jwt", [], |r| r.get(0))
        .expect("count");
    assert_eq!(n, 0, "no env + no DB row -> secrets_jwt stays empty");
}
