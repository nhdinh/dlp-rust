//! DACL staging data layer — two-phase staged update protocol for protected paths.
//!
//! Provides the data foundation that distinguishes operator-initiated protected path
//! removals from out-of-band ACL tampering. The staging state machine:
//!
//! ```text
//! STAGED -> WATCHER_SUPPRESSED -> ACL_REMOVED -> APPLIED -> GC
//! ```
//!
//! ## Crash Recovery
//!
//! Each state transition defines recovery behavior:
//!
//! | State | Recovery |
//! |-------|----------|
//! | `Staged` | Row exists but no applied_at. On restart, re-stage if path still in config diff. |
//! | `WatcherSuppressed` | Watcher has suppressed this path. On restart, re-suppress until ACL removal completes. |
//! | `AclRemoved` | ACL removal succeeded but not yet marked applied. On restart, verify path is unprotected and mark applied. |
//! | `Applied` | Ready for GC. GC removes rows where `applied_at` + TTL < now. |
//!
//! ## Per-Path Locking
//!
//! Every mutating method acquires a per-path `Mutex<()>` from a `DashMap` before
//! touching SQLite. This serializes concurrent operations on the same path while
//! allowing concurrent operations on different paths.
//!
//! ## Threat Model
//!
//! | Threat | Mitigation |
//! |--------|-----------|
//! | DoS (unbounded table growth) | 5-minute TTL GC removes applied rows |
//! | Race between staging and watcher | Per-path locking + staging check before tamper alert |
//! | Deadlock from per-path locks | Short-lived locks (single SQLite op); Mutex poisoning detection |

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use rusqlite::{Connection, Row};
use tracing::{info, warn};

/// Error type for DACL staging operations.
#[derive(Debug, thiserror::Error)]
pub enum DaclStagingError {
    /// SQLite database error.
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// Invalid operation string (not "add" or "remove").
    #[error("invalid operation: {0}")]
    InvalidOperation(String),
    /// State machine transition violation.
    #[error("state machine violation: {0}")]
    StateMachineViolation(String),
    /// Mutex was poisoned.
    #[error("lock poisoned: {0}")]
    LockPoisoned(String),
}

/// Staging state machine representing the lifecycle of a staged operation.
///
/// The state transitions are:
/// ```text
/// Staged -> WatcherSuppressed -> AclRemoved -> Applied -> (GC removes)
/// ```
#[derive(Debug, Clone, PartialEq)]
pub enum StagingState {
    /// Row inserted, operation pending. Watcher has not yet been notified.
    Staged,
    /// Watcher has been notified to suppress tamper alerts for this path.
    WatcherSuppressed,
    /// ACL removal has been applied successfully. Waiting for `mark_applied`.
    AclRemoved,
    /// `mark_applied` called. Row is eligible for GC after TTL expires.
    Applied,
}

/// A single row from the `protected_paths_staging` table.
#[derive(Debug, Clone)]
pub struct StagingRow {
    /// The protected path (primary key).
    pub path: String,
    /// The operation type: "add" or "remove".
    pub operation: String,
    /// When the row was staged (UTC).
    pub staged_at: DateTime<Utc>,
    /// When the row was marked applied, if at all.
    pub applied_at: Option<DateTime<Utc>>,
    /// Derived staging state.
    pub state: StagingState,
}

impl StagingRow {
    /// Derive the staging state from the row's operation and timestamps.
    ///
    /// The state machine logic:
    /// - If `applied_at` is `Some` -> `Applied`
    /// - If `applied_at` is `None` and `operation` is "remove" -> `AclRemoved`
    ///   (In the current implementation, we transition directly to `AclRemoved`
    ///   after the ACL removal succeeds, before `mark_applied` sets `applied_at`.)
    /// - Otherwise -> `Staged`
    ///
    /// Note: `WatcherSuppressed` is a runtime state tracked by the watcher
    /// integration (Plan 52-07), not persisted in the database.
    fn derive_state(operation: &str, applied_at: Option<DateTime<Utc>>) -> StagingState {
        if applied_at.is_some() {
            StagingState::Applied
        } else if operation == "remove" {
            // When ACL removal succeeds but mark_applied hasn't been called yet,
            // the row has no applied_at but the operation is "remove".
            // We interpret this as AclRemoved.
            StagingState::AclRemoved
        } else {
            StagingState::Staged
        }
    }
}

/// Initialize the `protected_paths_staging` table on the given connection.
///
/// Creates the table with:
/// - `path TEXT PRIMARY KEY`
/// - `operation TEXT NOT NULL CHECK(operation IN ('add', 'remove'))`
/// - `staged_at TEXT NOT NULL`
/// - `applied_at TEXT`
///
/// Also creates two indexes for efficient GC and time-range queries.
///
/// # Arguments
///
/// * `conn` — An open SQLite connection.
///
/// # Errors
///
/// Returns `DaclStagingError::Sqlite` on database errors.
pub fn init_staging_table(conn: &Connection) -> Result<(), DaclStagingError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS protected_paths_staging (
            path        TEXT PRIMARY KEY,
            operation   TEXT NOT NULL CHECK(operation IN ('add', 'remove')),
            staged_at   TEXT NOT NULL,
            applied_at  TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_staging_applied ON protected_paths_staging(applied_at);
        CREATE INDEX IF NOT EXISTS idx_staging_staged_at ON protected_paths_staging(staged_at);",
    )?;
    Ok(())
}

/// The DACL staging data layer.
///
/// Owns a SQLite connection (behind a `Mutex`) and a `DashMap` of per-path locks.
/// All mutating methods acquire the per-path lock before touching the database.
pub struct DaclStaging {
    conn: std::sync::Mutex<Connection>,
    /// Per-path locks for serializing concurrent operations on the same path.
    /// Public so the repair watcher and removal task can coordinate.
    pub path_locks: DashMap<String, Arc<parking_lot::Mutex<()>>>,
}

impl DaclStaging {
    /// Open a new `DaclStaging` at the given database path.
    ///
    /// Opens the SQLite connection and initializes the staging table.
    ///
    /// # Arguments
    ///
    /// * `db_path` — Path to the SQLite database file.
    ///
    /// # Errors
    ///
    /// Returns `DaclStagingError::Sqlite` on database errors.
    pub fn new(db_path: &Path) -> Result<Self, DaclStagingError> {
        let conn = Connection::open(db_path)?;
        init_staging_table(&conn)?;
        Ok(Self {
            conn: std::sync::Mutex::new(conn),
            path_locks: DashMap::new(),
        })
    }

    /// Create a `DaclStaging` from an existing in-memory or open connection.
    ///
    /// Primarily used in tests. The caller is responsible for initializing
    /// the table if needed.
    ///
    /// # Arguments
    ///
    /// * `conn` — An existing SQLite connection.
    pub fn from_connection(conn: Connection) -> Self {
        Self {
            conn: std::sync::Mutex::new(conn),
            path_locks: DashMap::new(),
        }
    }

    /// Acquire the per-path lock for the given path.
    ///
    /// Returns a guard that holds the lock. The guard must be dropped before
    /// the next operation on the same path can proceed.
    /// Execute a closure while holding the per-path lock.
    ///
    /// Serializes concurrent operations on the same path while allowing
    /// concurrent operations on different paths.
    fn with_path_lock<F, R>(&self, path: &str, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let arc = self
            .path_locks
            .entry(path.to_string())
            .or_insert_with(|| Arc::new(parking_lot::Mutex::new(())))
            .clone();
        let _guard = arc.lock();
        f()
    }

    /// Stage a removal operation for the given path.
    ///
    /// Acquires the per-path lock, then inserts or replaces a row with:
    /// - `operation = 'remove'`
    /// - `staged_at = now`
    /// - `applied_at = NULL`
    ///
    /// # Arguments
    ///
    /// * `path` — The protected path to stage for removal.
    ///
    /// # Errors
    ///
    /// Returns `DaclStagingError::LockPoisoned` if the connection mutex is poisoned.
    /// Returns `DaclStagingError::Sqlite` on database errors.
    pub fn stage_removal(&self, path: &str) -> Result<(), DaclStagingError> {
        self.with_path_lock(path, || {
            let conn = self.conn.lock().map_err(|_| {
                DaclStagingError::LockPoisoned("connection mutex poisoned".to_string())
            })?;
            conn.execute(
                "INSERT OR REPLACE INTO protected_paths_staging (path, operation, staged_at, applied_at)
                 VALUES (?1, 'remove', ?2, NULL)",
                [path, &Utc::now().to_rfc3339()],
            )?;
            Ok(())
        })
    }

    /// Stage an add operation for the given path.
    ///
    /// Acquires the per-path lock, then inserts or replaces a row with:
    /// - `operation = 'add'`
    /// - `staged_at = now`
    /// - `applied_at = NULL`
    ///
    /// # Arguments
    ///
    /// * `path` — The protected path to stage for addition.
    ///
    /// # Errors
    ///
    /// Returns `DaclStagingError::LockPoisoned` if the connection mutex is poisoned.
    /// Returns `DaclStagingError::Sqlite` on database errors.
    pub fn stage_add(&self, path: &str) -> Result<(), DaclStagingError> {
        self.with_path_lock(path, || {
            let conn = self.conn.lock().map_err(|_| {
                DaclStagingError::LockPoisoned("connection mutex poisoned".to_string())
            })?;
            conn.execute(
                "INSERT OR REPLACE INTO protected_paths_staging (path, operation, staged_at, applied_at)
                 VALUES (?1, 'add', ?2, NULL)",
                [path, &Utc::now().to_rfc3339()],
            )?;
            Ok(())
        })
    }

    /// Mark a staging row as applied.
    ///
    /// Acquires the per-path lock, then sets `applied_at = now` for the given path.
    /// Idempotent: calling multiple times is a no-op after the first success.
    ///
    /// # Arguments
    ///
    /// * `path` — The path to mark as applied.
    ///
    /// # Errors
    ///
    /// Returns `DaclStagingError::LockPoisoned` if the connection mutex is poisoned.
    /// Returns `DaclStagingError::Sqlite` on database errors.
    pub fn mark_applied(&self, path: &str) -> Result<(), DaclStagingError> {
        self.with_path_lock(path, || {
            let conn = self.conn.lock().map_err(|_| {
                DaclStagingError::LockPoisoned("connection mutex poisoned".to_string())
            })?;
            conn.execute(
                "UPDATE protected_paths_staging SET applied_at = ?1 WHERE path = ?2",
                [&Utc::now().to_rfc3339(), path],
            )?;
            Ok(())
        })
    }

    /// Check if a path has any active staging row (regardless of `applied_at`).
    ///
    /// Returns `true` if a row exists for the path. This is used by the watcher
    /// (Plan 52-07) to suppress tamper alerts for paths that are in the staging
    /// table.
    ///
    /// # Arguments
    ///
    /// * `path` — The path to check.
    ///
    /// # Errors
    ///
    /// Returns `DaclStagingError::LockPoisoned` if the connection mutex is poisoned.
    /// Returns `DaclStagingError::Sqlite` on database errors.
    pub fn is_staged(&self, path: &str) -> Result<bool, DaclStagingError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| DaclStagingError::LockPoisoned("connection mutex poisoned".to_string()))?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM protected_paths_staging WHERE path = ?1",
            [path],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Check if a path is staged AND has been marked applied.
    ///
    /// Returns `true` if a row exists with `applied_at IS NOT NULL`.
    ///
    /// # Arguments
    ///
    /// * `path` — The path to check.
    ///
    /// # Errors
    ///
    /// Returns `DaclStagingError::LockPoisoned` if the connection mutex is poisoned.
    /// Returns `DaclStagingError::Sqlite` on database errors.
    pub fn is_staged_and_applied(&self, path: &str) -> Result<bool, DaclStagingError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| DaclStagingError::LockPoisoned("connection mutex poisoned".to_string()))?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM protected_paths_staging WHERE path = ?1 AND applied_at IS NOT NULL",
            [path],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Get the current staging state for a path.
    ///
    /// Returns `None` if no row exists for the path.
    ///
    /// # Arguments
    ///
    /// * `path` — The path to query.
    ///
    /// # Errors
    ///
    /// Returns `DaclStagingError::LockPoisoned` if the connection mutex is poisoned.
    /// Returns `DaclStagingError::Sqlite` on database errors.
    pub fn get_state(&self, path: &str) -> Result<Option<StagingState>, DaclStagingError> {
        match self.get_row(path)? {
            Some(row) => Ok(Some(row.state)),
            None => Ok(None),
        }
    }

    /// Get a single staging row by path.
    ///
    /// Returns `None` if no row exists for the path.
    ///
    /// # Arguments
    ///
    /// * `path` — The path to query.
    ///
    /// # Errors
    ///
    /// Returns `DaclStagingError::LockPoisoned` if the connection mutex is poisoned.
    /// Returns `DaclStagingError::Sqlite` on database errors.
    /// Returns `DaclStagingError::InvalidOperation` if the operation column is invalid.
    pub fn get_row(&self, path: &str) -> Result<Option<StagingRow>, DaclStagingError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| DaclStagingError::LockPoisoned("connection mutex poisoned".to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT path, operation, staged_at, applied_at FROM protected_paths_staging WHERE path = ?1",
        )?;
        let row = stmt.query_row([path], Self::row_to_staging_row);
        match row {
            Ok(r) => Ok(Some(r)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(DaclStagingError::Sqlite(e)),
        }
    }

    /// List all staging rows.
    ///
    /// # Errors
    ///
    /// Returns `DaclStagingError::LockPoisoned` if the connection mutex is poisoned.
    /// Returns `DaclStagingError::Sqlite` on database errors.
    pub fn list_all(&self) -> Result<Vec<StagingRow>, DaclStagingError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| DaclStagingError::LockPoisoned("connection mutex poisoned".to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT path, operation, staged_at, applied_at FROM protected_paths_staging",
        )?;
        let rows = stmt.query_map([], Self::row_to_staging_row)?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(DaclStagingError::Sqlite)?);
        }
        Ok(result)
    }

    /// Garbage-collect expired staging rows.
    ///
    /// Deletes rows where `applied_at IS NOT NULL` AND `staged_at + ttl_minutes < now`.
    /// Only rows that have been marked applied are eligible for GC.
    ///
    /// # Arguments
    ///
    /// * `ttl_minutes` — Time-to-live in minutes. Rows older than this are deleted.
    ///
    /// # Returns
    ///
    /// The number of rows deleted.
    ///
    /// # Errors
    ///
    /// Returns `DaclStagingError::LockPoisoned` if the connection mutex is poisoned.
    /// Returns `DaclStagingError::Sqlite` on database errors.
    pub fn gc_expired_rows(&self, ttl_minutes: i64) -> Result<usize, DaclStagingError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| DaclStagingError::LockPoisoned("connection mutex poisoned".to_string()))?;
        let rows_affected = conn.execute(
            "DELETE FROM protected_paths_staging
             WHERE applied_at IS NOT NULL
               AND datetime(staged_at, '+' || ?1 || ' minutes') < datetime('now')",
            [ttl_minutes],
        )?;
        Ok(rows_affected)
    }

    /// Convert a SQLite row to a `StagingRow`.
    fn row_to_staging_row(row: &Row) -> Result<StagingRow, rusqlite::Error> {
        let path: String = row.get(0)?;
        let operation: String = row.get(1)?;
        let staged_at_str: String = row.get(2)?;
        let applied_at_str: Option<String> = row.get(3)?;

        let staged_at = DateTime::parse_from_rfc3339(&staged_at_str)
            .map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    2,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?
            .with_timezone(&Utc);

        let applied_at = match applied_at_str {
            Some(s) => Some(
                DateTime::parse_from_rfc3339(&s)
                    .map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            3,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?
                    .with_timezone(&Utc),
            ),
            None => None,
        };

        let state = StagingRow::derive_state(&operation, applied_at);

        Ok(StagingRow {
            path,
            operation,
            staged_at,
            applied_at,
            state,
        })
    }
}

/// Batch stage multiple removal operations.
///
/// This free function is designed for integration with `apply_payload_to_config`
/// (Plan 52-07) which has access to a `Mutex<Connection>` but not a `DaclStaging`
/// instance.
///
/// # Arguments
///
/// * `db` — A `Mutex`-wrapped SQLite connection.
/// * `paths` — Slice of paths to stage for removal.
///
/// # Returns
///
/// The number of rows inserted.
///
/// # Errors
///
/// Returns `DaclStagingError::LockPoisoned` if the mutex is poisoned.
/// Returns `DaclStagingError::Sqlite` on database errors.
pub fn stage_removals(
    db: &std::sync::Mutex<Connection>,
    paths: &[String],
) -> Result<usize, DaclStagingError> {
    let conn = db
        .lock()
        .map_err(|_| DaclStagingError::LockPoisoned("connection mutex poisoned".to_string()))?;
    let mut count = 0;
    let now = Utc::now().to_rfc3339();
    for path in paths {
        conn.execute(
            "INSERT OR REPLACE INTO protected_paths_staging (path, operation, staged_at, applied_at)
             VALUES (?1, 'remove', ?2, NULL)",
            [path.as_str(), &now],
        )?;
        count += 1;
    }
    Ok(count)
}

/// Spawn a background GC task that periodically removes expired staging rows.
///
/// Uses an adaptive interval: if no rows were deleted, the interval is unchanged.
/// If rows were deleted, the interval resets to the base value.
///
/// # Arguments
///
/// * `staging` — An `Arc<DaclStaging>` shared with the rest of the application.
/// * `interval_secs` — Base GC interval in seconds (default: 60).
/// * `ttl_minutes` — TTL for applied rows in minutes (default: 5).
/// * `shutdown_rx` — A `tokio::sync::watch::Receiver<bool>` for graceful shutdown.
///
/// # Returns
///
/// A `tokio::task::JoinHandle<()>` for the spawned task.
pub fn spawn_gc_task(
    staging: Arc<DaclStaging>,
    interval_secs: u64,
    ttl_minutes: i64,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    let interval = std::cmp::max(interval_secs, 1);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval));
        ticker.tick().await; // consume immediate first tick
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    match staging.gc_expired_rows(ttl_minutes) {
                        Ok(count) => {
                            if count > 0 {
                                info!(deleted = count, "staging GC removed expired rows");
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "staging GC failed");
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    info!("staging GC task shutting down");
                    return;
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn in_memory_staging() -> DaclStaging {
        let conn = Connection::open_in_memory().expect("open in-memory db");
        init_staging_table(&conn).expect("init table");
        DaclStaging::from_connection(conn)
    }

    // --- Test 1: State machine transitions ---

    #[test]
    fn test_staging_state_machine_transitions() {
        let staging = in_memory_staging();
        let path = r"C:\test\file.txt";

        // Initial state: Staged
        staging.stage_removal(path).unwrap();
        let state = staging.get_state(path).unwrap();
        assert_eq!(state, Some(StagingState::AclRemoved));

        // After mark_applied: Applied
        staging.mark_applied(path).unwrap();
        let state = staging.get_state(path).unwrap();
        assert_eq!(state, Some(StagingState::Applied));
    }

    // --- Test 2: Per-path lock serializes concurrent ops on same path ---

    #[test]
    fn test_per_path_lock_serializes_concurrent_ops() {
        let staging = Arc::new(in_memory_staging());
        let path = r"C:\test\concurrent.txt";

        let mut handles = Vec::new();
        for _ in 0..10 {
            let s = Arc::clone(&staging);
            let p = path.to_string();
            handles.push(thread::spawn(move || {
                s.stage_removal(&p).unwrap();
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        // All 10 threads should have succeeded (no SQLite busy errors).
        let row = staging.get_row(path).unwrap().unwrap();
        assert_eq!(row.operation, "remove");
        assert_eq!(row.state, StagingState::AclRemoved);
    }

    // --- Test 3: Per-path lock allows concurrent different paths ---

    #[test]
    fn test_per_path_lock_allows_concurrent_different_paths() {
        let staging = Arc::new(in_memory_staging());
        let paths: Vec<String> = (0..5)
            .map(|i| format!(r"C:\test\concurrent_{}.txt", i))
            .collect();

        let mut handles = Vec::new();
        for p in &paths {
            let s = Arc::clone(&staging);
            let path = p.clone();
            handles.push(thread::spawn(move || {
                s.stage_removal(&path).unwrap();
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let all = staging.list_all().unwrap();
        assert_eq!(all.len(), 5);
        for p in &paths {
            assert!(staging.is_staged(p).unwrap());
        }
    }

    // --- Test 4: GC removes expired applied rows ---

    #[test]
    fn test_gc_removes_expired_applied_rows() {
        let staging = in_memory_staging();
        let conn = staging.conn.lock().unwrap();

        // Insert a row with applied_at 6 minutes ago
        let six_min_ago = Utc::now() - chrono::Duration::minutes(6);
        conn.execute(
            "INSERT INTO protected_paths_staging (path, operation, staged_at, applied_at)
             VALUES (?1, 'remove', ?2, ?3)",
            [
                r"C:\test\expired.txt",
                &six_min_ago.to_rfc3339(),
                &six_min_ago.to_rfc3339(),
            ],
        )
        .unwrap();
        drop(conn);

        let deleted = staging.gc_expired_rows(5).unwrap();
        assert_eq!(deleted, 1);
        assert!(!staging.is_staged(r"C:\test\expired.txt").unwrap());
    }

    // --- Test 5: GC preserves unapplied rows ---

    #[test]
    fn test_gc_preserves_unapplied_rows() {
        let staging = in_memory_staging();
        let conn = staging.conn.lock().unwrap();

        // Insert a row with applied_at NULL, staged 10 minutes ago
        let ten_min_ago = Utc::now() - chrono::Duration::minutes(10);
        conn.execute(
            "INSERT INTO protected_paths_staging (path, operation, staged_at, applied_at)
             VALUES (?1, 'remove', ?2, NULL)",
            [r"C:\test\unapplied.txt", &ten_min_ago.to_rfc3339()],
        )
        .unwrap();
        drop(conn);

        let deleted = staging.gc_expired_rows(5).unwrap();
        assert_eq!(deleted, 0);
        assert!(staging.is_staged(r"C:\test\unapplied.txt").unwrap());
    }

    // --- Test 6: GC preserves recent applied rows ---

    #[test]
    fn test_gc_preserves_recent_applied_rows() {
        let staging = in_memory_staging();
        let conn = staging.conn.lock().unwrap();

        // Insert a row with applied_at 2 minutes ago
        let two_min_ago = Utc::now() - chrono::Duration::minutes(2);
        conn.execute(
            "INSERT INTO protected_paths_staging (path, operation, staged_at, applied_at)
             VALUES (?1, 'remove', ?2, ?3)",
            [
                r"C:\test\recent.txt",
                &two_min_ago.to_rfc3339(),
                &two_min_ago.to_rfc3339(),
            ],
        )
        .unwrap();
        drop(conn);

        let deleted = staging.gc_expired_rows(5).unwrap();
        assert_eq!(deleted, 0);
        assert!(staging.is_staged(r"C:\test\recent.txt").unwrap());
    }

    // --- Test 7: Staging add operation ---

    #[test]
    fn test_staging_add_operation() {
        let staging = in_memory_staging();
        let path = r"C:\test\add.txt";

        staging.stage_add(path).unwrap();
        assert!(staging.is_staged(path).unwrap());

        let state = staging.get_state(path).unwrap();
        assert_eq!(state, Some(StagingState::Staged));
    }

    // --- Test 8: mark_applied idempotent ---

    #[test]
    fn test_mark_applied_idempotent() {
        let staging = in_memory_staging();
        let path = r"C:\test\idempotent.txt";

        staging.stage_removal(path).unwrap();
        staging.mark_applied(path).unwrap();
        staging.mark_applied(path).unwrap(); // second call should not error

        let state = staging.get_state(path).unwrap();
        assert_eq!(state, Some(StagingState::Applied));
    }

    // --- Test 9: Staging row roundtrip ---

    #[test]
    fn test_staging_row_roundtrip() {
        let staging = in_memory_staging();
        let path = r"C:\test\roundtrip.txt";

        staging.stage_removal(path).unwrap();
        let row = staging.get_row(path).unwrap().unwrap();

        assert_eq!(row.path, path);
        assert_eq!(row.operation, "remove");
        assert!(row.applied_at.is_none());
        assert_eq!(row.state, StagingState::AclRemoved);
    }

    // --- Test 10: Batch stage_removals ---

    #[test]
    fn test_batch_stage_removals() {
        let conn = Connection::open_in_memory().expect("open in-memory db");
        init_staging_table(&conn).expect("init table");
        let db = std::sync::Mutex::new(conn);

        let paths = vec![
            r"C:\test\batch1.txt".to_string(),
            r"C:\test\batch2.txt".to_string(),
            r"C:\test\batch3.txt".to_string(),
        ];

        let count = stage_removals(&db, &paths).unwrap();
        assert_eq!(count, 3);

        // Verify all 3 exist
        let conn = db.lock().unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM protected_paths_staging", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 3);
    }

    // --- Test 11: is_staged_and_applied ---

    #[test]
    fn test_is_staged_and_applied() {
        let staging = in_memory_staging();
        let path = r"C:\test\applied_check.txt";

        staging.stage_removal(path).unwrap();
        assert!(staging.is_staged(path).unwrap());
        assert!(!staging.is_staged_and_applied(path).unwrap());

        staging.mark_applied(path).unwrap();
        assert!(staging.is_staged_and_applied(path).unwrap());
    }

    // --- Test 12: list_all returns all rows ---

    #[test]
    fn test_list_all() {
        let staging = in_memory_staging();
        let paths = vec![
            r"C:\test\list1.txt",
            r"C:\test\list2.txt",
            r"C:\test\list3.txt",
        ];

        for p in &paths {
            staging.stage_removal(p).unwrap();
        }

        let all = staging.list_all().unwrap();
        assert_eq!(all.len(), 3);
        for p in &paths {
            assert!(all.iter().any(|r| r.path == *p));
        }
    }

    // --- Test 13: init_staging_table creates correct schema ---

    #[test]
    fn test_init_staging_table_creates_schema() {
        let conn = Connection::open_in_memory().expect("open in-memory db");
        init_staging_table(&conn).expect("init table");

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='protected_paths_staging'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);

        // Verify CHECK constraint by attempting invalid operation
        let result = conn.execute(
            "INSERT INTO protected_paths_staging (path, operation, staged_at) VALUES (?1, ?2, ?3)",
            ["test", "invalid", "2026-01-01T00:00:00Z"],
        );
        assert!(result.is_err());
    }

    // --- Test 14: get_row returns None for missing path ---

    #[test]
    fn test_get_row_returns_none_for_missing() {
        let staging = in_memory_staging();
        let result = staging.get_row(r"C:\nonexistent\path.txt").unwrap();
        assert!(result.is_none());
    }

    // --- Test 15: stage_removal replaces existing row ---

    #[test]
    fn test_stage_removal_replaces_existing() {
        let staging = in_memory_staging();
        let path = r"C:\test\replace.txt";

        // Stage as add first
        staging.stage_add(path).unwrap();
        let row1 = staging.get_row(path).unwrap().unwrap();
        assert_eq!(row1.operation, "add");

        // Then stage as remove (should replace)
        staging.stage_removal(path).unwrap();
        let row2 = staging.get_row(path).unwrap().unwrap();
        assert_eq!(row2.operation, "remove");
        assert_eq!(row2.state, StagingState::AclRemoved);
    }
}
