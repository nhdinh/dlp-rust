//! Repository for the `system_kv` single-row-per-key flag table.
//!
//! Added in Phase 47 Task 47-08 to host the `maintenance_mode` boolean
//! that gates the KEK-rotation endpoint. Designed to be intentionally
//! generic — any future ad-hoc operator toggle can store its state here
//! rather than growing yet another single-row table.
//!
//! The on-disk encoding is `TEXT` for both key and value: booleans are
//! the single-character strings `"0"` / `"1"`. This keeps `sqlite3 .dump`
//! human-readable and avoids per-flag boolean adapters.
//!
//! This module is storage-only. The semantic meaning of any given key
//! (e.g. "maintenance_mode" means "the rotate-secrets endpoint will
//! accept calls without `force=true`") lives in the caller.

use rusqlite::{params, OptionalExtension};

/// The well-known key for the maintenance-mode boolean.
///
/// Centralised so callers cannot mis-key the flag — typos here would
/// silently bypass the rotation guard.
pub const KEY_MAINTENANCE_MODE: &str = "maintenance_mode";

/// Encoded TEXT value meaning "true" / on.
const VAL_TRUE: &str = "1";

/// Encoded TEXT value meaning "false" / off.
const VAL_FALSE: &str = "0";

/// Reads `key` from `system_kv` and returns its raw value.
///
/// Returns `Ok(None)` when the key is absent (e.g. an older DB that
/// never seeded the row — production paths always seed at init time
/// via `INSERT OR IGNORE`).
///
/// # Errors
///
/// Propagates `rusqlite::Error` from the underlying query.
pub fn get(conn: &rusqlite::Connection, key: &str) -> rusqlite::Result<Option<String>> {
    conn.query_row(
        "SELECT value FROM system_kv WHERE key = ?1",
        params![key],
        |r| r.get::<_, String>(0),
    )
    .optional()
}

/// Writes `value` for `key`, upserting via `INSERT OR REPLACE`.
///
/// `INSERT OR REPLACE` is safe here because `system_kv` has no foreign
/// keys, no triggers, and no historical-timestamp columns (unlike
/// `secrets_jwt`, where a REPLACE would clobber `created_at`).
///
/// # Errors
///
/// Propagates `rusqlite::Error`.
pub fn set(conn: &rusqlite::Connection, key: &str, value: &str) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO system_kv (key, value) VALUES (?1, ?2)",
        params![key, value],
    )?;
    Ok(())
}

/// `true` iff the `maintenance_mode` flag is set to `"1"`.
///
/// A missing row, an empty string, and any non-`"1"` value all read as
/// `false` — the guard is conservative by default so an admin must
/// explicitly opt-in to relaxed rotation rules.
///
/// # Errors
///
/// Propagates `rusqlite::Error` from the underlying query.
pub fn maintenance_is_enabled(conn: &rusqlite::Connection) -> rusqlite::Result<bool> {
    Ok(get(conn, KEY_MAINTENANCE_MODE)?
        .map(|v| v == VAL_TRUE)
        .unwrap_or(false))
}

/// Sets `maintenance_mode = "1"`.
///
/// # Errors
///
/// Propagates `rusqlite::Error`.
pub fn maintenance_enter(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    set(conn, KEY_MAINTENANCE_MODE, VAL_TRUE)
}

/// Sets `maintenance_mode = "0"`.
///
/// # Errors
///
/// Propagates `rusqlite::Error`.
pub fn maintenance_exit(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    set(conn, KEY_MAINTENANCE_MODE, VAL_FALSE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::new_pool;

    #[test]
    fn fresh_db_seeds_maintenance_mode_off() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire");
        assert_eq!(
            get(&conn, KEY_MAINTENANCE_MODE).expect("get").as_deref(),
            Some("0"),
            "init_tables must seed maintenance_mode to '0'"
        );
        assert!(!maintenance_is_enabled(&conn).expect("flag"));
    }

    #[test]
    fn enter_then_exit_toggles_the_flag() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire");

        maintenance_enter(&conn).expect("enter");
        assert!(maintenance_is_enabled(&conn).expect("after enter"));

        maintenance_exit(&conn).expect("exit");
        assert!(!maintenance_is_enabled(&conn).expect("after exit"));
    }

    #[test]
    fn set_is_upsert() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire");
        set(&conn, "custom_key", "alpha").expect("first set");
        set(&conn, "custom_key", "beta").expect("second set replaces");
        assert_eq!(
            get(&conn, "custom_key").expect("get").as_deref(),
            Some("beta")
        );
    }

    #[test]
    fn missing_key_returns_none() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire");
        assert!(get(&conn, "nope_does_not_exist").expect("get").is_none());
    }
}
