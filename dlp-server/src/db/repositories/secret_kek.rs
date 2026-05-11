//! Repository for the `secret_kek_history` table (Phase 47 HARD-01).
//!
//! Stores the history of Key-Encryption-Keys used to wrap every
//! `*_encrypted` column in the operator SQLite. Each row binds a
//! `version` byte (stamped into the AES-GCM envelope) to:
//!
//! * `master_seed_dpapi` — a 32-byte CSPRNG seed wrapped with DPAPI in
//!   machine scope (`CRYPTPROTECT_LOCAL_MACHINE`). DPAPI unwrap is the
//!   machine-bound trust root: the SQLite file is undecryptable on any
//!   other Windows installation.
//! * `pbkdf2_salt` + `pbkdf2_iterations` — KDF parameters fed into
//!   `pbkdf2_hmac::<Sha256>` together with the unwrapped seed to derive
//!   the actual 32-byte AES-256-GCM KEK. The KEK itself never touches
//!   disk; only the inputs needed to re-derive it do.
//!
//! `retired_at IS NULL` flags the active KEK. Retired rows are retained
//! so rows still encrypted under an older KEK can be decrypted during
//! rotation (Task 47-08) and disaster recovery.
//!
//! This module is intentionally **storage-only**: it does not call DPAPI,
//! does not run PBKDF2, and does not touch `aes-gcm`. The crypto layer
//! (`crate::crypto::SecretCrypto`) consumes the rows returned here.

use rusqlite::{params, OptionalExtension};

use chrono::{DateTime, Utc};

/// One row of `secret_kek_history`.
///
/// Field types match the `<interfaces>` block of `47-PLAN.md` exactly so
/// downstream tasks can rely on the published API:
///
/// * `version: u8` — fits SQLite `INTEGER PRIMARY KEY` (0..255 range; we
///   never expect more than a few KEK generations in a single deployment).
/// * `pbkdf2_salt: [u8; 16]` — sized array, not `Vec`, because the salt
///   length is a crypto invariant; mismatched lengths are rejected on read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretKekRecord {
    /// Stamped into every envelope produced by the KEK identified here.
    pub version: u8,
    /// DPAPI-wrapped 32-byte master seed. Opaque blob; only the
    /// originating machine can `CryptUnprotectData` it.
    pub master_seed_dpapi: Vec<u8>,
    /// PBKDF2-HMAC-SHA256 salt. Fixed 16 bytes — see
    /// [`crate::crypto::PBKDF2_SALT_LEN`].
    pub pbkdf2_salt: [u8; 16],
    /// PBKDF2 iteration count. 600 000 is the project default
    /// ([`crate::crypto::PBKDF2_DEFAULT_ITERATIONS`]); we persist the
    /// value so a future iteration-count bump can coexist with older
    /// rows during rotation.
    pub pbkdf2_iterations: u32,
    /// Row-creation timestamp; UTC, RFC 3339 on disk.
    pub created_at: DateTime<Utc>,
    /// `None` for the active KEK; `Some` for a KEK retired by a previous
    /// `rotate-secrets` invocation. Retired rows remain decryptable.
    pub retired_at: Option<DateTime<Utc>>,
}

/// Parses an RFC 3339 timestamp from the DB into a UTC `DateTime`.
///
/// SQLite stores all timestamps in this project as RFC 3339 strings (see
/// `db/mod.rs::run_migrations` default values). Any malformed value is a
/// schema invariant violation, surfaced as
/// `rusqlite::Error::FromSqlConversionFailure` to match the sibling
/// repositories' error-typing convention.
fn parse_ts(col: usize, raw: &str) -> rusqlite::Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(col, rusqlite::types::Type::Text, Box::new(e))
        })
}

/// Maps one `SELECT * FROM secret_kek_history` row into [`SecretKekRecord`].
///
/// Centralised so `get_active`, `get_by_version`, and any future list
/// helpers share identical row shape and error handling.
fn map_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecretKekRecord> {
    let version_i64: i64 = row.get(0)?;
    let master_seed_dpapi: Vec<u8> = row.get(1)?;
    let salt_blob: Vec<u8> = row.get(2)?;
    let iterations_i64: i64 = row.get(3)?;
    let created_at_raw: String = row.get(4)?;
    let retired_at_raw: Option<String> = row.get(5)?;

    // Bounds checks: the schema constraints are loose (INTEGER, BLOB) so
    // we re-validate here to prevent garbage rows propagating into the
    // crypto layer where a 17-byte salt would panic in `pbkdf2_hmac`.
    if !(0..=u8::MAX as i64).contains(&version_i64) {
        return Err(rusqlite::Error::IntegralValueOutOfRange(0, version_i64));
    }
    if !(0..=u32::MAX as i64).contains(&iterations_i64) {
        return Err(rusqlite::Error::IntegralValueOutOfRange(3, iterations_i64));
    }
    if salt_blob.len() != 16 {
        return Err(rusqlite::Error::InvalidColumnType(
            2,
            "pbkdf2_salt".into(),
            rusqlite::types::Type::Blob,
        ));
    }
    let mut pbkdf2_salt = [0u8; 16];
    pbkdf2_salt.copy_from_slice(&salt_blob);

    let created_at = parse_ts(4, &created_at_raw)?;
    let retired_at = match retired_at_raw {
        Some(s) => Some(parse_ts(5, &s)?),
        None => None,
    };

    Ok(SecretKekRecord {
        version: version_i64 as u8,
        master_seed_dpapi,
        pbkdf2_salt,
        pbkdf2_iterations: iterations_i64 as u32,
        created_at,
        retired_at,
    })
}

/// Returns the active KEK row — highest `version` with `retired_at IS NULL`.
///
/// Used by `SecretCrypto::load_active` at server start-up. Returns `None`
/// on a fresh install (before the first-run bootstrap inserts version 1).
///
/// # Errors
///
/// Propagates any `rusqlite::Error` from the underlying query, except
/// `QueryReturnedNoRows` which is mapped to `Ok(None)` per repository
/// convention.
pub fn get_active(conn: &rusqlite::Connection) -> rusqlite::Result<Option<SecretKekRecord>> {
    conn.query_row(
        "SELECT version, master_seed_dpapi, pbkdf2_salt, pbkdf2_iterations, \
                created_at, retired_at \
         FROM secret_kek_history \
         WHERE retired_at IS NULL \
         ORDER BY version DESC \
         LIMIT 1",
        [],
        map_row,
    )
    .optional()
}

/// Returns a specific KEK row by version — including retired rows.
///
/// Used by the rotation re-encrypt loop (Task 47-08) which must decrypt
/// pre-rotation ciphertexts under their original (now-retired) KEK before
/// re-encrypting under the new one.
///
/// # Errors
///
/// Same semantics as [`get_active`].
pub fn get_by_version(
    conn: &rusqlite::Connection,
    version: u8,
) -> rusqlite::Result<Option<SecretKekRecord>> {
    conn.query_row(
        "SELECT version, master_seed_dpapi, pbkdf2_salt, pbkdf2_iterations, \
                created_at, retired_at \
         FROM secret_kek_history WHERE version = ?1",
        params![version as i64],
        map_row,
    )
    .optional()
}

/// Inserts a fresh KEK row.
///
/// The caller is responsible for choosing a non-conflicting `version`
/// (typically `MAX(version) + 1` from [`get_active`] or
/// [`list_all_versions`]). A duplicate version produces a
/// `rusqlite::Error::SqliteFailure` with `SQLITE_CONSTRAINT_PRIMARYKEY`,
/// satisfying the PLAN.md `<behavior>` assertion that "insert_new rejects
/// duplicate version (UNIQUE PRIMARY KEY)".
///
/// `retired_at` is intentionally never inserted here: a new KEK is
/// active by definition. To retire a KEK, call [`retire`].
///
/// # Errors
///
/// Propagates `rusqlite::Error`.
pub fn insert_new(conn: &rusqlite::Connection, rec: &SecretKekRecord) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO secret_kek_history \
            (version, master_seed_dpapi, pbkdf2_salt, pbkdf2_iterations, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            rec.version as i64,
            rec.master_seed_dpapi,
            rec.pbkdf2_salt.as_slice(),
            rec.pbkdf2_iterations as i64,
            rec.created_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

/// Marks a KEK retired by stamping `retired_at`.
///
/// Idempotent: applying the same `retired_at` twice is a no-op
/// (`UPDATE ... WHERE retired_at IS NULL` only matches rows that have not
/// already been retired). Re-retiring with a different timestamp also
/// leaves the original `retired_at` intact — the audit history of *when*
/// the KEK was first retired must not be overwritten.
///
/// Returns the number of rows actually retired (0 if the version was
/// already retired or does not exist).
///
/// # Errors
///
/// Propagates `rusqlite::Error`.
pub fn retire(
    conn: &rusqlite::Connection,
    version: u8,
    retired_at: DateTime<Utc>,
) -> rusqlite::Result<usize> {
    conn.execute(
        "UPDATE secret_kek_history \
         SET retired_at = ?1 \
         WHERE version = ?2 AND retired_at IS NULL",
        params![retired_at.to_rfc3339(), version as i64],
    )
}

/// Lists every KEK version currently in the table, sorted ascending.
///
/// Used by the rotation flow (Task 47-08) which iterates retired versions
/// to identify which ones still have ciphertexts pointing at them. Cheap
/// — `secret_kek_history` is expected to have a single-digit row count
/// across the lifetime of a deployment.
///
/// # Errors
///
/// Propagates `rusqlite::Error`.
pub fn list_all_versions(conn: &rusqlite::Connection) -> rusqlite::Result<Vec<u8>> {
    let mut stmt = conn.prepare("SELECT version FROM secret_kek_history ORDER BY version ASC")?;
    let rows = stmt
        .query_map([], |r| r.get::<_, i64>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    // Same out-of-range guard as `map_row`: refuse to surface a u8 that
    // does not actually fit.
    rows.into_iter()
        .map(|v| {
            if !(0..=u8::MAX as i64).contains(&v) {
                Err(rusqlite::Error::IntegralValueOutOfRange(0, v))
            } else {
                Ok(v as u8)
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::new_pool;

    /// Builds a fully-populated record. Tests use deterministic blobs so
    /// equality assertions are stable; production blobs are CSPRNG output.
    fn make_rec(version: u8) -> SecretKekRecord {
        SecretKekRecord {
            version,
            master_seed_dpapi: vec![0xAA; 64],
            pbkdf2_salt: [0xBB; 16],
            pbkdf2_iterations: 600_000,
            // Fixed timestamp so round-trip comparison is exact (RFC 3339
            // round-trip is lossless at second precision).
            created_at: DateTime::parse_from_rfc3339("2026-05-11T12:00:00Z")
                .expect("static rfc3339")
                .with_timezone(&Utc),
            retired_at: None,
        }
    }

    #[test]
    fn table_exists_after_new_pool() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let tables: Vec<String> = conn
            .prepare(
                "SELECT name FROM sqlite_master \
                 WHERE type='table' AND name='secret_kek_history'",
            )
            .expect("prepare")
            .query_map([], |row| row.get(0))
            .expect("query")
            .filter_map(Result::ok)
            .collect();

        assert_eq!(
            tables,
            vec!["secret_kek_history".to_string()],
            "secret_kek_history table must exist after new_pool()"
        );
    }

    #[test]
    fn schema_columns_match_plan() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        // PRAGMA table_info returns: cid, name, type, notnull, dflt_value, pk
        let columns: Vec<(String, String, i64, i64)> = conn
            .prepare("PRAGMA table_info(secret_kek_history)")
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

        // Assert all six columns + their types + the PK shape.
        assert!(
            columns
                .iter()
                .any(|(n, t, nn, pk)| n == "version" && t == "INTEGER" && *pk == 1 && *nn == 0),
            "version INTEGER PRIMARY KEY missing: {columns:?}"
        );
        assert!(
            columns
                .iter()
                .any(|(n, t, nn, _)| n == "master_seed_dpapi" && t == "BLOB" && *nn == 1),
            "master_seed_dpapi BLOB NOT NULL missing: {columns:?}"
        );
        assert!(
            columns
                .iter()
                .any(|(n, t, nn, _)| n == "pbkdf2_salt" && t == "BLOB" && *nn == 1),
            "pbkdf2_salt BLOB NOT NULL missing: {columns:?}"
        );
        assert!(
            columns
                .iter()
                .any(|(n, t, nn, _)| n == "pbkdf2_iterations" && t == "INTEGER" && *nn == 1),
            "pbkdf2_iterations INTEGER NOT NULL missing: {columns:?}"
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
                .any(|(n, t, nn, _)| n == "retired_at" && t == "TEXT" && *nn == 0),
            "retired_at TEXT NULL missing: {columns:?}"
        );
    }

    #[test]
    fn get_active_on_empty_table_returns_none() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let active = get_active(&conn).expect("query active");
        assert!(active.is_none(), "fresh DB must have no active KEK");
    }

    #[test]
    fn insert_then_get_active_round_trips() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let rec = make_rec(1);
        insert_new(&conn, &rec).expect("insert");

        let got = get_active(&conn).expect("get_active").expect("Some");
        assert_eq!(got, rec, "round-trip must preserve every field exactly");
    }

    #[test]
    fn get_active_returns_highest_non_retired_version() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        // v1 active, v2 active -> get_active returns v2.
        insert_new(&conn, &make_rec(1)).expect("insert v1");
        insert_new(&conn, &make_rec(2)).expect("insert v2");

        let active = get_active(&conn).expect("get_active").expect("Some");
        assert_eq!(active.version, 2);
    }

    #[test]
    fn get_active_skips_retired_versions() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        insert_new(&conn, &make_rec(1)).expect("insert v1");
        insert_new(&conn, &make_rec(2)).expect("insert v2");

        let retired_ts = DateTime::parse_from_rfc3339("2026-05-11T13:00:00Z")
            .expect("static rfc3339")
            .with_timezone(&Utc);
        let updated = retire(&conn, 2, retired_ts).expect("retire v2");
        assert_eq!(updated, 1, "retire must update exactly one row");

        let active = get_active(&conn).expect("get_active").expect("Some");
        assert_eq!(active.version, 1, "v2 retired -> v1 is active");

        // get_by_version still surfaces the retired row.
        let v2 = get_by_version(&conn, 2)
            .expect("get_by_version")
            .expect("Some");
        assert_eq!(v2.version, 2);
        assert_eq!(v2.retired_at, Some(retired_ts));
    }

    #[test]
    fn retire_is_idempotent() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        insert_new(&conn, &make_rec(1)).expect("insert v1");

        let ts1 = DateTime::parse_from_rfc3339("2026-05-11T13:00:00Z")
            .expect("static rfc3339")
            .with_timezone(&Utc);
        let ts2 = DateTime::parse_from_rfc3339("2026-05-11T14:00:00Z")
            .expect("static rfc3339")
            .with_timezone(&Utc);

        assert_eq!(retire(&conn, 1, ts1).expect("first retire"), 1);
        // Second retire is a no-op (`WHERE retired_at IS NULL` excludes it).
        assert_eq!(retire(&conn, 1, ts2).expect("second retire"), 0);

        // Original retired_at preserved -- the audit timestamp is immutable.
        let row = get_by_version(&conn, 1)
            .expect("get_by_version")
            .expect("Some");
        assert_eq!(row.retired_at, Some(ts1));
    }

    #[test]
    fn retire_nonexistent_version_returns_zero() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let ts = DateTime::parse_from_rfc3339("2026-05-11T13:00:00Z")
            .expect("static rfc3339")
            .with_timezone(&Utc);
        assert_eq!(
            retire(&conn, 99, ts).expect("retire missing version"),
            0,
            "retire on absent version must be a no-op"
        );
    }

    #[test]
    fn insert_duplicate_version_fails() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        insert_new(&conn, &make_rec(1)).expect("first insert");
        let err = insert_new(&conn, &make_rec(1)).expect_err("must reject duplicate");
        // SQLite returns a primary-key constraint violation; we don't
        // pattern-match the precise variant -- the public guarantee is
        // simply "the second insert errors", and the caller (Task 47-08)
        // will surface this as `CryptoError::KdfFailed` or similar.
        assert!(
            matches!(err, rusqlite::Error::SqliteFailure(_, _)),
            "expected SqliteFailure, got {err:?}"
        );
    }

    #[test]
    fn list_all_versions_sorted_ascending() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        insert_new(&conn, &make_rec(3)).expect("insert v3");
        insert_new(&conn, &make_rec(1)).expect("insert v1");
        insert_new(&conn, &make_rec(2)).expect("insert v2");

        assert_eq!(list_all_versions(&conn).expect("list"), vec![1, 2, 3]);
    }

    #[test]
    fn migration_creates_table_on_pre_phase47_db() {
        // Simulates a v0.x → Phase 47 upgrade path: an existing DB without
        // `secret_kek_history` gets the table created by `init_tables`.
        // Modeled on `test_migration_add_mode_column` in db/mod.rs.
        let tmp = tempfile::NamedTempFile::new().expect("create temp db file");
        let path = tmp.path().to_str().expect("temp path utf8");

        // Step 1: stand up a minimal pre-Phase-47 schema that does NOT
        // contain secret_kek_history. (One unrelated table to prove the
        // DB exists before we touch it.)
        {
            let conn = rusqlite::Connection::open(path).expect("open temp db");
            conn.execute_batch(
                "CREATE TABLE agents (
                    agent_id TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    os_version TEXT NOT NULL,
                    agent_version TEXT NOT NULL,
                    last_heartbeat TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'online',
                    registered_at TEXT NOT NULL
                );",
            )
            .expect("create pre-Phase-47 schema");

            // Sanity: secret_kek_history does not exist yet.
            let n: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master \
                     WHERE type='table' AND name='secret_kek_history'",
                    [],
                    |r| r.get(0),
                )
                .expect("count");
            assert_eq!(n, 0, "precondition: table must not exist yet");
        }

        // Step 2: open via new_pool -- triggers init_tables (creates the
        // new table) and run_migrations (no-op for this table).
        let pool = new_pool(path).expect("open pool with migrations");
        let conn = pool.get().expect("acquire connection");

        // Step 3: table now exists.
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master \
                 WHERE type='table' AND name='secret_kek_history'",
                [],
                |r| r.get(0),
            )
            .expect("count");
        assert_eq!(n, 1, "table must exist after init_tables");

        // Step 4: repository operations work end-to-end on the upgraded DB.
        insert_new(&conn, &make_rec(1)).expect("insert into upgraded DB");
        let active = get_active(&conn).expect("get_active").expect("Some");
        assert_eq!(active.version, 1);

        // Step 5: idempotency -- re-opening must not error and must not
        // duplicate the table or wipe data.
        drop(conn);
        drop(pool);
        let pool2 = new_pool(path).expect("re-open must succeed");
        let conn2 = pool2.get().expect("acquire connection 2");
        let still_there = get_active(&conn2).expect("re-query").expect("Some");
        assert_eq!(
            still_there.version, 1,
            "data must survive re-open + re-init"
        );
    }
}
