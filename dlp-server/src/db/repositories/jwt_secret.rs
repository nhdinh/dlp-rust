//! Repository for the `secrets_jwt` table (Phase 47 Task 47-03).
//!
//! Stores the single active JWT signing secret as an AES-GCM envelope wrapped
//! by the active KEK (see `secret_kek_history` in `secret_kek.rs`). The table
//! enforces a single-row invariant via `CHECK (id = 1)`; rotations UPDATE the
//! row in place rather than appending.
//!
//! Column layout (kept in lock-step with `init_tables()` DDL in `db/mod.rs`):
//!
//! | Column            | SQL type        | Purpose                                       |
//! | ----------------- | --------------- | --------------------------------------------- |
//! | `id`              | INTEGER PK = 1  | Single-row sentinel                           |
//! | `secret_encrypted`| BLOB NOT NULL   | AES-GCM ciphertext + 16-byte authentication tag |
//! | `secret_nonce`    | BLOB NOT NULL   | 12-byte AES-GCM nonce (`NONCE_LEN`)           |
//! | `secret_version`  | INTEGER NOT NULL| KEK version stamped at encrypt time           |
//! | `created_at`      | TEXT NOT NULL   | RFC 3339 timestamp of first write             |
//! | `rotated_at`      | TEXT (NULL ok)  | RFC 3339 timestamp of most recent rotation    |
//!
//! This module is intentionally **storage-only**: encryption and decryption
//! are performed by the caller (Task 47-05 will wire `admin_auth::resolve_jwt_secret`
//! through `SecretCrypto`). The repository accepts pre-encrypted envelopes
//! and returns raw envelope bytes — no key material is read or written here.

use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension};

use crate::crypto::envelope::NONCE_LEN;
use crate::crypto::Envelope;

/// Reads the active JWT secret envelope.
///
/// Returns `Ok(None)` on a fresh deployment (the row has not been seeded yet —
/// Task 47-05 / 47-06 will seed it during the JWT migration step). Returns
/// `Ok(Some((envelope, kek_version)))` otherwise; `kek_version` identifies the
/// row in `secret_kek_history` whose KEK was used to wrap the envelope.
///
/// # Errors
///
/// Propagates `rusqlite::Error` from the underlying query and reports
/// out-of-range `secret_version` values (anything outside `0..=u8::MAX`) as
/// `IntegralValueOutOfRange` — this is a schema invariant that should never
/// fire in production but the check keeps the caller from receiving a
/// silently-truncated version byte.
///
/// `secret_nonce` length is validated against [`NONCE_LEN`]; a non-12-byte
/// blob is rejected as `InvalidColumnType` rather than silently truncated.
pub fn get(conn: &rusqlite::Connection) -> rusqlite::Result<Option<(Envelope, u8)>> {
    conn.query_row(
        "SELECT secret_encrypted, secret_nonce, secret_version \
         FROM secrets_jwt WHERE id = 1",
        [],
        |row| {
            let ciphertext: Vec<u8> = row.get(0)?;
            let nonce_blob: Vec<u8> = row.get(1)?;
            let version_i64: i64 = row.get(2)?;

            if nonce_blob.len() != NONCE_LEN {
                return Err(rusqlite::Error::InvalidColumnType(
                    1,
                    "secret_nonce".into(),
                    rusqlite::types::Type::Blob,
                ));
            }
            if !(0..=u8::MAX as i64).contains(&version_i64) {
                return Err(rusqlite::Error::IntegralValueOutOfRange(2, version_i64));
            }

            let mut nonce = [0u8; NONCE_LEN];
            nonce.copy_from_slice(&nonce_blob);

            // Envelope::new validates ciphertext length >= TAG_LEN; we use
            // the envelope's own `version` field (the wire-format version,
            // currently always ENVELOPE_VERSION_V1) which is independent of
            // the KEK version we return separately. The on-disk row stores
            // ONLY the KEK version (in secret_version) -- the envelope's
            // wire-format version is implicit ENVELOPE_VERSION_V1 because
            // we never write any other shape from this repository.
            let envelope = Envelope::new(crate::crypto::ENVELOPE_VERSION_V1, nonce, ciphertext)
                .map_err(|_| {
                    rusqlite::Error::InvalidColumnType(
                        0,
                        "secret_encrypted".into(),
                        rusqlite::types::Type::Blob,
                    )
                })?;

            Ok((envelope, version_i64 as u8))
        },
    )
    .optional()
}

/// Writes (or rewrites) the single active JWT secret envelope.
///
/// First call on a fresh DB inserts the row with `created_at = now` and
/// `rotated_at = NULL`. Subsequent calls perform a true UPDATE that bumps
/// `secret_version`, replaces the ciphertext + nonce, and stamps
/// `rotated_at = now` — `created_at` is intentionally preserved as the
/// historical "first issued" timestamp.
///
/// `INSERT OR REPLACE` is **not** used here: it would clobber `created_at`
/// because REPLACE deletes the row before inserting the new one. Instead we
/// detect the existing-row case via `UPDATE ... WHERE id = 1` returning a
/// non-zero row count, falling back to INSERT only when no row exists.
///
/// # Arguments
///
/// * `envelope` — the AES-GCM envelope produced by `SecretCrypto::encrypt`.
///   Only the `nonce` and `ciphertext` fields are persisted; the envelope's
///   wire-format `version` byte is implicit (always [`crate::crypto::ENVELOPE_VERSION_V1`]
///   for current writes).
/// * `kek_version` — the KEK row from `secret_kek_history` that wrapped the
///   envelope. Stored verbatim in `secret_version`.
/// * `now` — RFC 3339 timestamp used for `created_at` on first insert and
///   `rotated_at` on subsequent updates. Passed as a parameter (rather than
///   read internally via `Utc::now()`) so tests can pin deterministic
///   timestamps.
///
/// # Errors
///
/// Propagates `rusqlite::Error` from either branch of the UPDATE/INSERT
/// fallback. Attempting to insert with `id != 1` is rejected by the table's
/// CHECK constraint as `SqliteFailure(CONSTRAINT_CHECK)`.
pub fn upsert_encrypted(
    conn: &rusqlite::Connection,
    envelope: &Envelope,
    kek_version: u8,
    now: DateTime<Utc>,
) -> rusqlite::Result<()> {
    let updated = conn.execute(
        "UPDATE secrets_jwt \
         SET secret_encrypted = ?1, secret_nonce = ?2, secret_version = ?3, \
             rotated_at = ?4 \
         WHERE id = 1",
        params![
            envelope.ciphertext,
            envelope.nonce.as_slice(),
            kek_version as i64,
            now.to_rfc3339(),
        ],
    )?;

    if updated == 0 {
        conn.execute(
            "INSERT INTO secrets_jwt \
                (id, secret_encrypted, secret_nonce, secret_version, created_at) \
             VALUES (1, ?1, ?2, ?3, ?4)",
            params![
                envelope.ciphertext,
                envelope.nonce.as_slice(),
                kek_version as i64,
                now.to_rfc3339(),
            ],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::envelope::TAG_LEN;
    use crate::db::new_pool;

    /// Builds a deterministic envelope. The ciphertext is plausible (>= TAG_LEN
    /// bytes so `Envelope::new` accepts it) but is NOT a valid AES-GCM
    /// ciphertext — these tests exercise the storage layer in isolation.
    fn make_envelope(seed: u8) -> Envelope {
        let nonce = [seed; NONCE_LEN];
        let ciphertext = vec![seed; TAG_LEN + 8];
        Envelope::new(crate::crypto::ENVELOPE_VERSION_V1, nonce, ciphertext)
            .expect("valid envelope")
    }

    fn fixed_ts(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s)
            .expect("static rfc3339")
            .with_timezone(&Utc)
    }

    #[test]
    fn table_exists_after_new_pool() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master \
                 WHERE type='table' AND name='secrets_jwt'",
                [],
                |r| r.get(0),
            )
            .expect("query sqlite_master");
        assert_eq!(count, 1, "secrets_jwt table must exist after new_pool()");
    }

    #[test]
    fn schema_columns_match_plan() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        // PRAGMA table_info returns (cid, name, type, notnull, dflt_value, pk).
        let columns: Vec<(String, String, i64, i64)> = conn
            .prepare("PRAGMA table_info(secrets_jwt)")
            .expect("prepare pragma")
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(5)?,
                ))
            })
            .expect("query pragma")
            .filter_map(Result::ok)
            .collect();

        assert!(
            columns
                .iter()
                .any(|(n, t, _, pk)| n == "id" && t == "INTEGER" && *pk == 1),
            "id INTEGER PRIMARY KEY missing: {columns:?}"
        );
        assert!(
            columns
                .iter()
                .any(|(n, t, nn, _)| n == "secret_encrypted" && t == "BLOB" && *nn == 1),
            "secret_encrypted BLOB NOT NULL missing: {columns:?}"
        );
        assert!(
            columns
                .iter()
                .any(|(n, t, nn, _)| n == "secret_nonce" && t == "BLOB" && *nn == 1),
            "secret_nonce BLOB NOT NULL missing: {columns:?}"
        );
        assert!(
            columns
                .iter()
                .any(|(n, t, nn, _)| n == "secret_version" && t == "INTEGER" && *nn == 1),
            "secret_version INTEGER NOT NULL missing: {columns:?}"
        );
        assert!(
            columns
                .iter()
                .any(|(n, t, nn, _)| n == "created_at" && t == "TEXT" && *nn == 1),
            "created_at TEXT NOT NULL missing: {columns:?}"
        );
        assert!(
            columns
                .iter()
                .any(|(n, t, nn, _)| n == "rotated_at" && t == "TEXT" && *nn == 0),
            "rotated_at TEXT NULL missing: {columns:?}"
        );
    }

    #[test]
    fn check_constraint_rejects_non_one_id() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        // Direct INSERT with id = 2 must hit CHECK (id = 1).
        let err = conn
            .execute(
                "INSERT INTO secrets_jwt \
                    (id, secret_encrypted, secret_nonce, secret_version, created_at) \
                 VALUES (2, X'00', X'000000000000000000000000', 1, '2026-05-11T12:00:00Z')",
                [],
            )
            .expect_err("CHECK (id = 1) must reject id = 2");
        assert!(
            err.to_string().contains("CHECK constraint failed"),
            "expected CHECK violation; got: {err}"
        );
    }

    #[test]
    fn get_on_empty_table_returns_none() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let got = get(&conn).expect("query empty");
        assert!(got.is_none(), "fresh DB must have no JWT secret row");
    }

    #[test]
    fn upsert_then_get_round_trips() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let env = make_envelope(0xAB);
        let kek_version: u8 = 1;
        let now = fixed_ts("2026-05-11T12:00:00Z");

        upsert_encrypted(&conn, &env, kek_version, now).expect("first upsert");
        let (got_env, got_version) = get(&conn).expect("get").expect("Some");

        assert_eq!(got_version, kek_version, "KEK version must round-trip");
        assert_eq!(got_env.nonce, env.nonce, "nonce must round-trip");
        assert_eq!(
            got_env.ciphertext, env.ciphertext,
            "ciphertext must round-trip"
        );
    }

    #[test]
    fn upsert_overwrites_existing_row_and_preserves_created_at() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let env1 = make_envelope(0x11);
        let env2 = make_envelope(0x22);
        let ts1 = fixed_ts("2026-05-11T12:00:00Z");
        let ts2 = fixed_ts("2026-05-12T12:00:00Z");

        upsert_encrypted(&conn, &env1, 1, ts1).expect("first upsert (INSERT path)");
        upsert_encrypted(&conn, &env2, 2, ts2).expect("second upsert (UPDATE path)");

        // The single-row invariant holds.
        let row_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM secrets_jwt", [], |r| r.get(0))
            .expect("count rows");
        assert_eq!(row_count, 1, "must remain a single-row table");

        // The newer envelope is what get() returns.
        let (got_env, got_version) = get(&conn).expect("get").expect("Some");
        assert_eq!(got_version, 2, "version must be the rotated value");
        assert_eq!(
            got_env.ciphertext, env2.ciphertext,
            "ciphertext must be the rotated value"
        );

        // created_at is preserved across the rotation; rotated_at is stamped.
        let (created_at, rotated_at): (String, Option<String>) = conn
            .query_row(
                "SELECT created_at, rotated_at FROM secrets_jwt WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("read timestamps");
        assert_eq!(
            created_at,
            ts1.to_rfc3339(),
            "created_at must survive UPDATE"
        );
        assert_eq!(
            rotated_at.as_deref(),
            Some(ts2.to_rfc3339().as_str()),
            "rotated_at must be stamped on rotation"
        );
    }

    #[test]
    fn get_rejects_corrupt_nonce_length() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        // Bypass upsert_encrypted to seed a row with an invalid nonce length.
        // Using id = 1 satisfies the CHECK constraint. This guards against
        // disk corruption / out-of-band writes producing nonce blobs that
        // would later crash the AES-GCM decryption path (NONCE_LEN is a
        // crypto invariant).
        conn.execute(
            "INSERT INTO secrets_jwt \
                (id, secret_encrypted, secret_nonce, secret_version, created_at) \
             VALUES (1, X'00010203040506070809101112131415', X'AA', 1, '2026-05-11T12:00:00Z')",
            [],
        )
        .expect("seed bad row");

        let err = get(&conn).expect_err("must reject 1-byte nonce");
        assert!(
            matches!(err, rusqlite::Error::InvalidColumnType(1, ref name, _) if name == "secret_nonce"),
            "expected InvalidColumnType on secret_nonce; got: {err:?}"
        );
    }

    #[test]
    fn get_rejects_out_of_range_kek_version() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        // secret_version is stored as INTEGER (i64-wide in SQLite); we
        // re-validate against u8::MAX in the repository so a corrupted row
        // surfaces as a typed error rather than a silently-truncated byte.
        let nonce_blob: [u8; NONCE_LEN] = [0xCC; NONCE_LEN];
        conn.execute(
            "INSERT INTO secrets_jwt \
                (id, secret_encrypted, secret_nonce, secret_version, created_at) \
             VALUES (1, X'00010203040506070809101112131415', ?1, 999, '2026-05-11T12:00:00Z')",
            params![nonce_blob.as_slice()],
        )
        .expect("seed bad row");

        let err = get(&conn).expect_err("must reject 999 > u8::MAX");
        assert!(
            matches!(err, rusqlite::Error::IntegralValueOutOfRange(2, 999)),
            "expected IntegralValueOutOfRange on secret_version; got: {err:?}"
        );
    }
}
