//! Agent-side offline audit event queue.
//!
//! Stores audit events locally when the dlp-server is unreachable.
//! Events are encrypted with DPAPI (Windows, LocalMachine scope) before writing to SQLite.
//! On heartbeat success, the agent drains the queue and forwards events.
//!
//! Pitfall: DPAPI data is lost on machine rebuild (expected per D-06/D-07).

use rusqlite::{params, Connection};
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(windows)]
use dlp_common::crypto::{dpapi_protect_machine, dpapi_unprotect_machine};

/// Atomic flag to prevent concurrent drain attempts (per R-62-15).
static DRAIN_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

/// Default maximum queue size (10,000 events).
pub const DEFAULT_MAX_QUEUE_SIZE: i64 = 10_000;

/// Default batch size for drain operations.
pub const DEFAULT_BATCH_SIZE: usize = 100;

/// Initialize the offline_audit_queue table on the given connection.
pub fn init_table(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS offline_audit_queue (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            event_json_dpapi BLOB NOT NULL,
            created_at     INTEGER NOT NULL,
            retry_count    INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_offline_audit_queue_created_at
            ON offline_audit_queue(created_at);",
    )
}

/// Errors that can occur during offline queue operations.
#[derive(Debug, thiserror::Error)]
pub enum OfflineQueueError {
    /// Queue is at capacity; event was dropped.
    #[error("queue at capacity ({max_size}), event dropped")]
    AtCapacity { max_size: i64 },
    /// DPAPI encryption failed.
    #[error("DPAPI encrypt error: {0}")]
    Encrypt(String),
    /// DPAPI decryption failed.
    #[error("DPAPI decrypt error: {0}")]
    Decrypt(String),
    /// Database operation failed.
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
}

/// Enqueue an event. On Windows, encrypts with DPAPI (LocalMachine) before storing.
/// On non-Windows, stores plaintext.
///
/// # Arguments
///
/// * `conn` -- SQLite connection.
/// * `event_json` -- JSON-serialized audit event.
/// * `max_size` -- maximum queue depth; returns `AtCapacity` when exceeded.
///
/// # Errors
///
/// Returns `OfflineQueueError::AtCapacity` when queue is full.
/// Returns `OfflineQueueError::Encrypt` on DPAPI failure (Windows).
/// Returns `OfflineQueueError::Database` on SQLite errors.
pub fn enqueue(
    conn: &Connection,
    event_json: &str,
    max_size: i64,
) -> Result<(), OfflineQueueError> {
    // Pre-insert tail-drop: check capacity
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM offline_audit_queue", [], |row| {
            row.get(0)
        })
        .map_err(OfflineQueueError::Database)?;
    if count >= max_size {
        return Err(OfflineQueueError::AtCapacity { max_size });
    }

    #[cfg(windows)]
    let blob = dpapi_protect_machine(event_json.as_bytes())
        .map_err(|e| OfflineQueueError::Encrypt(e.to_string()))?;
    #[cfg(not(windows))]
    let blob = event_json.as_bytes().to_vec();

    let now = chrono::Utc::now().timestamp();
    conn.execute(
        "INSERT INTO offline_audit_queue (event_json_dpapi, created_at, retry_count)
         VALUES (?1, ?2, 0)",
        params![blob, now],
    )
    .map_err(OfflineQueueError::Database)?;
    Ok(())
}

/// Drain oldest N events from the queue. Returns (id, decrypted_json) tuples.
/// Handles DPAPI corruption by logging, deleting the corrupt row, and continuing.
///
/// # Arguments
///
/// * `conn` -- SQLite connection.
/// * `batch_size` -- maximum number of events to drain.
///
/// # Errors
///
/// Returns `OfflineQueueError::Decrypt` on DPAPI failure (Windows).
/// Returns `OfflineQueueError::Database` on SQLite errors.
pub fn drain(
    conn: &Connection,
    batch_size: usize,
) -> Result<Vec<(i64, String)>, OfflineQueueError> {
    let mut stmt = conn
        .prepare(
            "SELECT id, event_json_dpapi FROM offline_audit_queue
             ORDER BY created_at LIMIT ?1",
        )
        .map_err(OfflineQueueError::Database)?;

    let rows = stmt
        .query_map([batch_size as i64], |row| {
            let id: i64 = row.get(0)?;
            let blob: Vec<u8> = row.get(1)?;

            #[cfg(windows)]
            let plaintext = match dpapi_unprotect_machine(&blob) {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!(
                        event_id = id,
                        error = %e,
                        "DPAPI unprotect failed; deleting corrupt queue entry"
                    );
                    return Ok((id, None));
                }
            };
            #[cfg(not(windows))]
            let plaintext = blob;

            let json = String::from_utf8(plaintext)
                .map_err(|e| rusqlite::Error::InvalidParameterName(format!("utf8: {e}")))?;
            Ok((id, Some(json)))
        })
        .map_err(OfflineQueueError::Database)?;

    let mut results = Vec::new();
    let mut corrupt_ids = Vec::new();
    for row in rows {
        let (id, maybe_json) = row.map_err(OfflineQueueError::Database)?;
        match maybe_json {
            Some(json) => results.push((id, json)),
            None => corrupt_ids.push(id),
        }
    }

    // Delete corrupt rows
    if !corrupt_ids.is_empty() {
        let placeholders: Vec<String> = corrupt_ids.iter().map(|_| "?".to_string()).collect();
        let sql = format!(
            "DELETE FROM offline_audit_queue WHERE id IN ({})",
            placeholders.join(",")
        );
        let mut stmt = conn.prepare(&sql).map_err(OfflineQueueError::Database)?;
        let params: Vec<&dyn rusqlite::ToSql> = corrupt_ids
            .iter()
            .map(|id| id as &dyn rusqlite::ToSql)
            .collect();
        stmt.execute(rusqlite::params_from_iter(params.iter()))
            .map_err(OfflineQueueError::Database)?;
    }

    Ok(results)
}

/// Delete rows by id after successful forwarding.
///
/// # Arguments
///
/// * `conn` -- SQLite connection.
/// * `ids` -- slice of row ids to remove.
pub fn delete(conn: &Connection, ids: &[i64]) -> Result<(), rusqlite::Error> {
    if ids.is_empty() {
        return Ok(());
    }
    let placeholders: Vec<String> = ids.iter().map(|_| "?".to_string()).collect();
    let sql = format!(
        "DELETE FROM offline_audit_queue WHERE id IN ({})",
        placeholders.join(",")
    );
    let mut stmt = conn.prepare(&sql)?;
    let params: Vec<&dyn rusqlite::ToSql> =
        ids.iter().map(|id| id as &dyn rusqlite::ToSql).collect();
    stmt.execute(rusqlite::params_from_iter(params.iter()))?;
    Ok(())
}

/// Return current queue depth.
pub fn count(conn: &Connection) -> Result<i64, rusqlite::Error> {
    conn.query_row("SELECT COUNT(*) FROM offline_audit_queue", [], |row| {
        row.get(0)
    })
}

/// Try to acquire the drain lock. Returns true if acquired, false if another drain is in progress.
pub fn try_acquire_drain_lock() -> bool {
    DRAIN_IN_PROGRESS
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
}

/// Release the drain lock.
pub fn release_drain_lock() {
    DRAIN_IN_PROGRESS.store(false, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn in_memory_conn() -> Connection {
        Connection::open_in_memory().expect("open in-memory db")
    }

    #[test]
    fn init_table_creates_schema() {
        let conn = in_memory_conn();
        init_table(&conn).expect("init_table should succeed");
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='offline_audit_queue'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn enqueue_then_drain_round_trip() {
        let conn = in_memory_conn();
        init_table(&conn).unwrap();

        let event_json = r#"{"event_id":"test-123","timestamp":"2026-05-14T00:00:00Z"}"#;
        enqueue(&conn, event_json, DEFAULT_MAX_QUEUE_SIZE).expect("enqueue should succeed");

        let drained = drain(&conn, DEFAULT_BATCH_SIZE).expect("drain should succeed");
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].1, event_json);
    }

    #[test]
    fn drain_returns_fifo_order() {
        let conn = in_memory_conn();
        init_table(&conn).unwrap();

        let events = vec![
            r#"{"event_id":"first"}"#,
            r#"{"event_id":"second"}"#,
            r#"{"event_id":"third"}"#,
        ];
        for e in &events {
            enqueue(&conn, e, DEFAULT_MAX_QUEUE_SIZE).unwrap();
        }

        let drained = drain(&conn, DEFAULT_BATCH_SIZE).unwrap();
        assert_eq!(drained.len(), 3);
        assert_eq!(drained[0].1, events[0]);
        assert_eq!(drained[1].1, events[1]);
        assert_eq!(drained[2].1, events[2]);
    }

    #[test]
    fn drain_respects_batch_size() {
        let conn = in_memory_conn();
        init_table(&conn).unwrap();

        for i in 0..5 {
            enqueue(
                &conn,
                &format!("{{\"event_id\":\"{i}\"}}"),
                DEFAULT_MAX_QUEUE_SIZE,
            )
            .unwrap();
        }

        let drained = drain(&conn, 2).unwrap();
        assert_eq!(drained.len(), 2);
    }

    #[test]
    fn delete_removes_specified_rows() {
        let conn = in_memory_conn();
        init_table(&conn).unwrap();

        for i in 0..3 {
            enqueue(
                &conn,
                &format!("{{\"event_id\":\"{i}\"}}"),
                DEFAULT_MAX_QUEUE_SIZE,
            )
            .unwrap();
        }

        let drained = drain(&conn, DEFAULT_BATCH_SIZE).unwrap();
        assert_eq!(drained.len(), 3);

        // Delete only the middle row
        delete(&conn, &[drained[1].0]).expect("delete should succeed");

        let count_after = count(&conn).expect("count should succeed");
        assert_eq!(count_after, 2);

        let remaining = drain(&conn, DEFAULT_BATCH_SIZE).unwrap();
        assert_eq!(remaining.len(), 2);
        assert_eq!(remaining[0].1, drained[0].1);
        assert_eq!(remaining[1].1, drained[2].1);
    }

    #[test]
    fn enqueue_rejects_when_queue_full() {
        let conn = in_memory_conn();
        init_table(&conn).unwrap();

        for i in 0..3 {
            enqueue(
                &conn,
                &format!("{{\"event_id\":\"{i}\"}}"),
                3, // max_size = 3
            )
            .unwrap();
        }

        // Fourth event should be rejected (pre-insert tail-drop)
        let err = enqueue(&conn, "overflow", 3).expect_err("must reject when full");
        assert!(err.to_string().contains("at capacity"));

        let count_val = count(&conn).expect("count should succeed");
        assert_eq!(count_val, 3, "queue must still have exactly 3 events");
    }

    #[test]
    fn count_returns_correct_depth() {
        let conn = in_memory_conn();
        init_table(&conn).unwrap();

        assert_eq!(count(&conn).unwrap(), 0);

        enqueue(&conn, "test1", DEFAULT_MAX_QUEUE_SIZE).unwrap();
        assert_eq!(count(&conn).unwrap(), 1);

        enqueue(&conn, "test2", DEFAULT_MAX_QUEUE_SIZE).unwrap();
        assert_eq!(count(&conn).unwrap(), 2);
    }

    #[test]
    fn drain_lock_prevents_concurrent_drains() {
        assert!(try_acquire_drain_lock(), "first acquire should succeed");
        assert!(
            !try_acquire_drain_lock(),
            "second acquire should fail while lock held"
        );
        release_drain_lock();
        assert!(
            try_acquire_drain_lock(),
            "acquire after release should succeed"
        );
        release_drain_lock();
    }

    #[test]
    fn created_at_is_integer_unix_epoch() {
        let conn = in_memory_conn();
        init_table(&conn).unwrap();

        let before = chrono::Utc::now().timestamp();
        enqueue(&conn, "test", DEFAULT_MAX_QUEUE_SIZE).unwrap();
        let after = chrono::Utc::now().timestamp();

        let created: i64 = conn
            .query_row(
                "SELECT created_at FROM offline_audit_queue LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert!(
            created >= before && created <= after,
            "created_at should be Unix epoch integer"
        );
    }

    #[test]
    #[cfg(not(windows))]
    fn non_windows_stores_plaintext() {
        let conn = in_memory_conn();
        init_table(&conn).unwrap();

        let event_json = r#"{"event_id":"plaintext-test"}"#;
        enqueue(&conn, event_json, DEFAULT_MAX_QUEUE_SIZE).unwrap();

        // On non-Windows, the blob should be identical to the input bytes
        let blob: Vec<u8> = conn
            .query_row(
                "SELECT event_json_dpapi FROM offline_audit_queue LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(blob, event_json.as_bytes());
    }
}
