//! Phase 47 Task 47-10 — Full-cycle KEK rotation integration test.
//!
//! Walks the complete rotation pipeline against a real file-backed
//! SQLite DB and a DPAPI-protected KEK:
//!
//! 1. Fresh DB -> `load_active_or_bootstrap` creates KEK v1.
//! 2. Hand-encrypt a v1 envelope (`v1_envelope_for_forensic_test`)
//!    and stash its bytes for the post-rotation forensic decrypt step.
//! 3. Seed fixture cleartext via the pre-Phase-47 SQL surface, then run
//!    `migrate_secrets_to_encrypted` so every column lands in its
//!    `*_encrypted` form under v1.
//! 4. `rotate_kek(force=true)` -> v2 active, v1 retired.
//! 5. Reload `SecretCrypto::load_active` (now v2) -> every encrypted
//!    repository `get` decrypts to the original fixture plaintext.
//! 6. Tampering check: hand-craft a row whose envelope version byte is
//!    99 -> `CryptoError::UnsupportedVersion(99)` on decrypt.
//! 7. Forensic decrypt: `SecretCrypto::load_by_version(conn, 1)`
//!    successfully decrypts the v1 envelope from step 2 (proves v1
//!    rows are retained, not deleted, by rotation).
//!
//! Windows-only: `SecretCrypto::load_active_or_bootstrap` calls into
//! DPAPI which is unavailable on non-Windows. Non-Windows CI hosts
//! skip the entire suite via the file-level `#![cfg(windows)]`.

#![cfg(windows)]

use std::sync::Arc;

use chrono::Utc;
use dlp_server::crypto::{aad_for, CryptoError, Envelope, SecretCrypto, ENVELOPE_VERSION_V1};
use dlp_server::db::repositories::secret_kek;
use dlp_server::db::{self, Pool};
use dlp_server::secrets_migration;
use rusqlite::params;
use secrecy::ExposeSecret;
use tempfile::NamedTempFile;

/// Builds a fresh file-backed pool with the Phase 47 schema in place.
///
/// `:memory:` would not work for this test because rotation acquires
/// multiple connections from the pool and `:memory:` is per-connection
/// unless `cache=shared` is configured. The file-backed path matches
/// what production runs.
fn fresh_pool() -> (NamedTempFile, Arc<Pool>) {
    let tmp = NamedTempFile::new().expect("create temp DB file");
    let pool =
        Arc::new(db::new_pool(tmp.path().to_str().expect("UTF-8 temp path")).expect("init pool"));
    (tmp, pool)
}

/// Seeds the four MIGRATION_TARGETS rows with cleartext fixtures using
/// the pre-Phase-47 column layout. Mirrors the seed pattern used in
/// `secrets_migration::tests::seeded_cleartext_encrypts_and_drops_columns`.
fn seed_fixture_cleartext(pool: &Pool) {
    let conn = pool.get().expect("acquire");
    conn.execute(
        "UPDATE alert_router_config SET smtp_password = ?1, webhook_secret = ?2 \
         WHERE id = 1",
        params!["fixture-smtp-pass", "fixture-webhook-secret"],
    )
    .expect("seed alert_router_config");
    conn.execute(
        "UPDATE siem_config SET splunk_token = ?1, elk_api_key = ?2 WHERE id = 1",
        params!["fixture-splunk-token", "fixture-elk-key"],
    )
    .expect("seed siem_config");
}

/// Reads back the four MIGRATION_TARGETS encrypted-column tuples and
/// decrypts each with `crypto`. Returns a flat vector of
/// `(label, plaintext)` pairs so assertions read top-to-bottom.
fn read_all_encrypted(pool: &Pool, crypto: &SecretCrypto) -> Vec<(&'static str, String)> {
    let conn = pool.get().expect("acquire");
    let mut out = Vec::new();
    for (label, table, col) in [
        ("smtp_password", "alert_router_config", "smtp_password"),
        ("webhook_secret", "alert_router_config", "webhook_secret"),
        ("splunk_token", "siem_config", "splunk_token"),
        ("elk_api_key", "siem_config", "elk_api_key"),
    ] {
        let sql = format!("SELECT {col}_encrypted, {col}_nonce FROM {table} WHERE id = 1");
        let (ct, nonce_blob): (Vec<u8>, Vec<u8>) = conn
            .query_row(&sql, [], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap_or_else(|e| panic!("query {table}.{col}: {e}"));
        let mut nonce = [0u8; dlp_server::crypto::envelope::NONCE_LEN];
        nonce.copy_from_slice(&nonce_blob);
        let env = Envelope::new(ENVELOPE_VERSION_V1, nonce, ct).expect("envelope");
        let recovered = crypto
            .decrypt(&env, &aad_for(table, col))
            .unwrap_or_else(|e| panic!("decrypt {table}.{col}: {e:?}"));
        out.push((label, recovered.expose_secret().to_string()));
    }
    out
}

#[test]
fn full_rotation_cycle_preserves_every_secret_and_retires_v1() {
    // ---- Step 1: fresh DB + bootstrap v1 KEK. -----------------------
    let (_keepalive, pool) = fresh_pool();
    let v1 = SecretCrypto::load_active_or_bootstrap(&pool)
        .expect("bootstrap v1 (DPAPI must be available on Windows runner)");
    assert_eq!(v1.version(), 1, "fresh DB must bootstrap as v1");

    // ---- Step 2: stash a v1 envelope for the forensic decrypt step. -
    // Encrypt against an ad-hoc (table,column) AAD so the test
    // doesn't depend on row-level state.
    let forensic_plaintext = b"forensic-test-plaintext";
    let forensic_aad = aad_for("ad-hoc-forensic", "forensic-column");
    let v1_envelope_for_forensic_test: Envelope = v1
        .encrypt(forensic_plaintext, &forensic_aad)
        .expect("encrypt forensic fixture under v1");
    // Persist nonce + ciphertext bytes (not the whole Envelope struct)
    // so the post-rotation forensic-decrypt path constructs a fresh
    // Envelope just like the production read path does.
    let forensic_nonce = v1_envelope_for_forensic_test.nonce;
    let forensic_ciphertext = v1_envelope_for_forensic_test.ciphertext.clone();

    // ---- Step 3: seed cleartext fixtures + run migration. -----------
    seed_fixture_cleartext(&pool);
    let report = secrets_migration::migrate_secrets_to_encrypted(&pool, &v1, None)
        .expect("migrate seeded cleartext");
    assert_eq!(
        report.rows_encrypted, 4,
        "migration must encrypt all four MIGRATION_TARGETS"
    );

    // Round-trip via v1 BEFORE rotation: every fixture decrypts.
    let pre_rot = read_all_encrypted(&pool, &v1);
    assert_eq!(
        pre_rot,
        vec![
            ("smtp_password", "fixture-smtp-pass".to_string()),
            ("webhook_secret", "fixture-webhook-secret".to_string()),
            ("splunk_token", "fixture-splunk-token".to_string()),
            ("elk_api_key", "fixture-elk-key".to_string()),
        ]
    );

    // ---- Step 4: rotate v1 -> v2 (force=true bypasses maintenance). -
    let rotation =
        secrets_migration::rotate_kek(&pool, &v1, /*force=*/ true).expect("rotation cycle");
    assert_eq!(rotation.old_version, 1);
    assert_eq!(rotation.new_version, 2);
    assert!(
        rotation.rows_reencrypted >= 4,
        "at least the four MIGRATION_TARGETS rows must rotate; got {}",
        rotation.rows_reencrypted
    );

    // secret_kek_history bookkeeping: v1 retired, v2 active.
    {
        let conn = pool.get().expect("acquire");
        let v1_row = secret_kek::get_by_version(&conn, 1)
            .expect("query v1 row")
            .expect("v1 must still exist (retained, not deleted)");
        assert!(v1_row.retired_at.is_some(), "v1 must be retired");
        let active = secret_kek::get_active(&conn)
            .expect("get_active")
            .expect("must have an active KEK");
        assert_eq!(active.version, 2, "v2 is now active");
    }

    // ---- Step 5: reload `SecretCrypto::load_active` (now v2). ------
    // After rotation we should be able to drop the in-memory v1
    // handle and re-derive the active KEK strictly from the DB. This
    // also exercises the load_active path against a non-bootstrap
    // (i.e. operator-rotated) row.
    let v2 = {
        let conn = pool.get().expect("acquire");
        SecretCrypto::load_active(&conn).expect("reload active KEK after rotation")
    };
    assert_eq!(v2.version(), 2);
    let post_rot = read_all_encrypted(&pool, &v2);
    assert_eq!(
        post_rot,
        vec![
            ("smtp_password", "fixture-smtp-pass".to_string()),
            ("webhook_secret", "fixture-webhook-secret".to_string()),
            ("splunk_token", "fixture-splunk-token".to_string()),
            ("elk_api_key", "fixture-elk-key".to_string()),
        ],
        "all secrets must round-trip under v2 after rotation"
    );

    // ---- Step 6: tampering check -- version byte 99. ---------------
    // Hand-craft an envelope whose version byte advertises an unknown
    // KEK generation; the decrypt path must reject with
    // CryptoError::UnsupportedVersion(99).
    let mut bogus_nonce = [0u8; dlp_server::crypto::envelope::NONCE_LEN];
    bogus_nonce.copy_from_slice(&forensic_nonce);
    // The envelope's `version` field is the wire-format version (see
    // crypto/envelope.rs: ENVELOPE_VERSION_V1 = 1, anything else is
    // rejected by decrypt). Asking for version 99 -> UnsupportedVersion.
    let bogus =
        Envelope::new(99, bogus_nonce, forensic_ciphertext.clone()).expect("envelope shell");
    let err = v2
        .decrypt(&bogus, &forensic_aad)
        .expect_err("version 99 must be rejected");
    assert!(
        matches!(err, CryptoError::UnsupportedVersion(99)),
        "expected UnsupportedVersion(99), got {err:?}"
    );

    // ---- Step 7: forensic decrypt of the pre-rotation v1 envelope. -
    // The v1 KEK row is retired but retained -- load_by_version(1)
    // must still produce a working SecretCrypto handle.
    let v1_replayed = {
        let conn = pool.get().expect("acquire");
        SecretCrypto::load_by_version(&conn, 1).expect("v1 row must be retained")
    };
    assert_eq!(v1_replayed.version(), 1);
    // Reconstruct the saved envelope and decrypt: plaintext recovers.
    let mut nonce_restored = [0u8; dlp_server::crypto::envelope::NONCE_LEN];
    nonce_restored.copy_from_slice(&forensic_nonce);
    let saved_env = Envelope::new(ENVELOPE_VERSION_V1, nonce_restored, forensic_ciphertext)
        .expect("reconstruct v1 envelope");
    let recovered_plaintext = v1_replayed
        .decrypt(&saved_env, &forensic_aad)
        .expect("v1 forensic decrypt must succeed");
    assert_eq!(
        recovered_plaintext.expose_secret().as_bytes(),
        forensic_plaintext,
        "v1 forensic decrypt must recover the exact bytes encrypted in step 2"
    );

    // Diagnostic timestamp to make CI logs easier to correlate.
    eprintln!(
        "rotation integration test completed at {} (rows_reencrypted={})",
        Utc::now().to_rfc3339(),
        rotation.rows_reencrypted
    );
}
