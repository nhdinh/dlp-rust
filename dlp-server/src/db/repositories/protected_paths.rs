//! Repository for the `protected_paths` and `protected_path_aces` tables.
//!
//! Encapsulates all SQL for protected-path CRUD and auto-population from
//! confirmed T3/T4 labels. The protected-paths registry is the single source
//! of truth for which paths receive DACL tripwire protection.

use rusqlite::params;

use crate::db::{Pool, UnitOfWork};

/// Plain data row returned by protected-path reads.
#[derive(Debug, Clone)]
pub struct ProtectedPathRow {
    /// Server-generated UUID string (primary key).
    pub id: String,
    /// Filesystem or SMB path of the protected object.
    pub path: String,
    /// Source of the entry: `"auto"` (populated from labels) or `"manual"`.
    pub source: String,
    /// Whether this entry overrides auto-population for the same path.
    pub is_override: bool,
    /// Data tier: `"T3"` (Confidential) or `"T4"` (Restricted).
    pub tier: String,
    /// Soft FK to `labels(id)`. `None` for manual entries.
    pub label_id: Option<String>,
    /// ISO-8601 timestamp of creation.
    pub created_at: String,
    /// ISO-8601 timestamp of last update.
    pub updated_at: String,
}

/// Plain data row returned by protected-path ACE snapshot reads.
#[derive(Debug, Clone)]
pub struct ProtectedPathAceRow {
    /// Server-generated UUID string (primary key).
    pub id: String,
    /// FK to `protected_paths(id)`.
    pub protected_path_id: String,
    /// SDDL string representing the canonical ACE snapshot.
    pub sddl: String,
    /// ISO-8601 timestamp of creation.
    pub created_at: String,
    /// ISO-8601 timestamp of last update.
    pub updated_at: String,
}

/// Stateless repository for the `protected_paths` table.
///
/// All methods are associated functions (no `&self`) -- the repository holds
/// no state. Connection pooling is handled by the caller via `Pool` for reads
/// and `UnitOfWork` for writes.
pub struct ProtectedPathsRepository;

impl ProtectedPathsRepository {
    /// Returns all protected paths ordered by `path` ascending.
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if pool acquisition or query execution fails.
    pub fn list_all(pool: &Pool) -> rusqlite::Result<Vec<ProtectedPathRow>> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

        let mut stmt = conn.prepare(
            "SELECT id, path, source, is_override, tier, label_id, created_at, updated_at \
             FROM protected_paths \
             ORDER BY path ASC",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(ProtectedPathRow {
                id: row.get(0)?,
                path: row.get(1)?,
                source: row.get(2)?,
                is_override: row.get::<_, i64>(3)? != 0,
                tier: row.get(4)?,
                label_id: row.get(5)?,
                created_at: row.get(6)?,
                updated_at: row.get(7)?,
            })
        })?;
        rows.collect()
    }

    /// Returns the protected path with the given `id`.
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    /// * `id` - UUID string of the path to retrieve.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error::QueryReturnedNoRows` if no matching row exists.
    pub fn get_by_id(pool: &Pool, id: &str) -> rusqlite::Result<ProtectedPathRow> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        conn.query_row(
            "SELECT id, path, source, is_override, tier, label_id, created_at, updated_at \
             FROM protected_paths WHERE id = ?1",
            params![id],
            |row| {
                Ok(ProtectedPathRow {
                    id: row.get(0)?,
                    path: row.get(1)?,
                    source: row.get(2)?,
                    is_override: row.get::<_, i64>(3)? != 0,
                    tier: row.get(4)?,
                    label_id: row.get(5)?,
                    created_at: row.get(6)?,
                    updated_at: row.get(7)?,
                })
            },
        )
    }

    /// Inserts a new protected path entry.
    ///
    /// # Arguments
    ///
    /// * `uow` - Active unit of work to execute the write within.
    /// * `row` - Protected path data to insert.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the statement fails (e.g., duplicate `path`
    /// rejected by the UNIQUE constraint, or invalid `source`/`tier` rejected
    /// by CHECK constraints).
    pub fn insert(uow: &UnitOfWork<'_>, row: &ProtectedPathRow) -> rusqlite::Result<()> {
        let is_override_i64: i64 = if row.is_override { 1 } else { 0 };
        uow.tx.execute(
            "INSERT INTO protected_paths \
                 (id, path, source, is_override, tier, label_id, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                row.id,
                row.path,
                row.source,
                is_override_i64,
                row.tier,
                row.label_id,
                row.created_at,
                row.updated_at,
            ],
        )?;
        Ok(())
    }

    /// Updates an existing protected path entry.
    ///
    /// # Arguments
    ///
    /// * `uow` - Active unit of work to execute the write within.
    /// * `row` - Protected path data to update. The `id` field is used as the
    ///   primary key.
    ///
    /// # Returns
    ///
    /// Returns the number of rows updated (0 if the `id` did not exist -- not an error).
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the UPDATE statement fails.
    pub fn update(uow: &UnitOfWork<'_>, row: &ProtectedPathRow) -> rusqlite::Result<usize> {
        let is_override_i64: i64 = if row.is_override { 1 } else { 0 };
        uow.tx.execute(
            "UPDATE protected_paths SET \
                 path        = ?2, \
                 source      = ?3, \
                 is_override = ?4, \
                 tier        = ?5, \
                 label_id    = ?6, \
                 updated_at  = ?7 \
             WHERE id = ?1",
            params![
                row.id,
                row.path,
                row.source,
                is_override_i64,
                row.tier,
                row.label_id,
                row.updated_at,
            ],
        )
    }

    /// Deletes the protected path with the given `id`.
    ///
    /// Because `protected_path_aces` has `ON DELETE CASCADE`, any associated
    /// ACE rows are automatically removed.
    ///
    /// # Arguments
    ///
    /// * `uow` - Active unit of work to execute the write within.
    /// * `id` - UUID string of the path to delete.
    ///
    /// # Returns
    ///
    /// Returns the number of rows deleted (0 if the `id` did not exist -- not an error).
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the DELETE statement itself fails.
    pub fn delete_by_id(uow: &UnitOfWork<'_>, id: &str) -> rusqlite::Result<usize> {
        uow.tx
            .execute("DELETE FROM protected_paths WHERE id = ?1", params![id])
    }

    /// Returns the ACE snapshot for the given protected path `id`, if any.
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    /// * `path_id` - UUID string of the protected path to query.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if pool acquisition or query execution fails.
    pub fn get_ace_by_path_id(
        pool: &Pool,
        path_id: &str,
    ) -> rusqlite::Result<Option<ProtectedPathAceRow>> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        let mut stmt = conn.prepare(
            "SELECT id, protected_path_id, sddl, created_at, updated_at \
             FROM protected_path_aces \
             WHERE protected_path_id = ?1 \
             LIMIT 1",
        )?;
        let mut rows = stmt.query_map(params![path_id], |row| {
            Ok(ProtectedPathAceRow {
                id: row.get(0)?,
                protected_path_id: row.get(1)?,
                sddl: row.get(2)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
            })
        })?;
        rows.next().transpose()
    }

    /// Inserts or updates the ACE snapshot for a protected path.
    ///
    /// If an ACE already exists for the given `protected_path_id`, updates the
    /// SDDL and `updated_at` fields. Otherwise inserts a new row.
    ///
    /// # Arguments
    ///
    /// * `uow` - Active unit of work to execute the write within.
    /// * `row` - ACE data to upsert.
    ///
    /// # Returns
    ///
    /// Returns the number of rows affected (1 for insert or update).
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the statement fails.
    pub fn upsert_ace(uow: &UnitOfWork<'_>, row: &ProtectedPathAceRow) -> rusqlite::Result<usize> {
        uow.tx.execute(
            "INSERT INTO protected_path_aces \
                 (id, protected_path_id, sddl, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5) \
             ON CONFLICT(protected_path_id) DO UPDATE SET \
                 sddl       = excluded.sddl, \
                 updated_at = excluded.updated_at",
            params![
                row.id,
                row.protected_path_id,
                row.sddl,
                row.created_at,
                row.updated_at,
            ],
        )
    }

    /// Auto-populates `protected_paths` from confirmed T3/T4 labels.
    ///
    /// Queries the `labels` table for rows where `tier IN ('T3', 'T4')` and
    /// `label_state = 'confirmed'`, then inserts or updates the corresponding
    /// `protected_paths` rows with `source = 'auto'`.
    ///
    /// # Conflict rules
    ///
    /// * If a path already exists with `source = 'manual'`: **SKIP** (never
    ///   overwrite manual entries).
    /// * If a path already exists with `source = 'auto'` and same tier: **SKIP**
    ///   (idempotent -- no change needed).
    /// * If a path already exists with `source = 'auto'` and different tier:
    ///   **UPDATE** tier to the stricter of the two (T4 > T3).
    /// * If a path does **not** exist: **INSERT** with `source = 'auto'`.
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    ///
    /// # Returns
    ///
    /// Returns the count of newly inserted rows (updates are not counted).
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if any query or statement fails.
    pub fn sync_from_labels(pool: &Pool) -> rusqlite::Result<usize> {
        let mut conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

        let labels: Vec<(String, String, Option<String>)> = {
            let mut stmt = conn.prepare(
                "SELECT path, tier, id \
                 FROM labels \
                 WHERE tier IN ('T3', 'T4') AND label_state = 'confirmed'",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get(2)?,
                ))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };

        let tx = conn.transaction()?;
        let uow = UnitOfWork { tx };

        let mut inserted_count: usize = 0;

        for (label_path, label_tier, label_id) in labels {
            // Check if a protected_path already exists for this path.
            let existing: Option<(String, String)> = uow
                .tx
                .query_row(
                    "SELECT source, tier FROM protected_paths WHERE path = ?1",
                    params![label_path],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .ok();

            match existing {
                Some((source, _existing_tier)) if source == "manual" => {
                    // Rule: manual entries are never overwritten.
                    continue;
                }
                Some((source, existing_tier)) if source == "auto" => {
                    if existing_tier == label_tier {
                        // Rule: same tier, same source -- idempotent, skip.
                        continue;
                    }
                    // Rule: different tier -- update to stricter tier.
                    // T4 is stricter than T3.
                    let stricter_tier = if existing_tier == "T4" || label_tier == "T4" {
                        "T4"
                    } else {
                        "T3"
                    };
                    let now = chrono::Utc::now().to_rfc3339();
                    uow.tx.execute(
                        "UPDATE protected_paths \
                         SET tier = ?1, updated_at = ?2 \
                         WHERE path = ?3",
                        params![stricter_tier, now, label_path],
                    )?;
                }
                _ => {
                    // No existing entry -- insert new auto-populated row.
                    let now = chrono::Utc::now().to_rfc3339();
                    let new_id = uuid::Uuid::new_v4().to_string();
                    uow.tx.execute(
                        "INSERT INTO protected_paths \
                             (id, path, source, is_override, tier, label_id, created_at, updated_at) \
                         VALUES (?1, ?2, 'auto', 0, ?3, ?4, ?5, ?5)",
                        params![new_id, label_path, label_tier, label_id, now],
                    )?;
                    inserted_count += 1;
                }
            }
        }

        uow.commit()?;
        Ok(inserted_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::new_pool;
    // LabelUpsertRow is available for future tests that construct labels via repository.
    use crate::db::unit_of_work::UnitOfWork;

    /// Helper: build an in-memory pool with the full schema initialized.
    fn make_pool() -> Pool {
        new_pool(":memory:").expect("create in-memory pool")
    }

    /// Helper: construct a test protected path row.
    fn make_row(
        id: &str,
        path: &str,
        source: &str,
        tier: &str,
        is_override: bool,
    ) -> ProtectedPathRow {
        ProtectedPathRow {
            id: id.to_string(),
            path: path.to_string(),
            source: source.to_string(),
            is_override,
            tier: tier.to_string(),
            label_id: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    /// Helper: insert a confirmed T3/T4 label directly via SQL.
    fn insert_label_direct(conn: &rusqlite::Connection, id: &str, path: &str, tier: &str) {
        conn.execute(
            "INSERT INTO labels \
                 (id, path, object_type, tier, label_state, created_at, updated_at) \
             VALUES (?1, ?2, 'folder', ?3, 'confirmed', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            params![id, path, tier],
        )
        .expect("insert label");
    }

    #[test]
    fn test_list_all_empty() {
        let pool = make_pool();
        let rows = ProtectedPathsRepository::list_all(&pool).expect("list_all on empty DB");
        assert!(
            rows.is_empty(),
            "expected empty vec from fresh DB; got {rows:?}"
        );
    }

    #[test]
    fn test_insert_and_get_by_id() {
        let pool = make_pool();

        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin transaction");
            let row = make_row("pp-1", r"C:\Data\HR", "manual", "T3", false);
            ProtectedPathsRepository::insert(&uow, &row).expect("insert new row");
            uow.commit().expect("commit");
        }

        let r = ProtectedPathsRepository::get_by_id(&pool, "pp-1").expect("get_by_id");
        assert_eq!(r.id, "pp-1");
        assert_eq!(r.path, r"C:\Data\HR");
        assert_eq!(r.source, "manual");
        assert!(!r.is_override);
        assert_eq!(r.tier, "T3");
        assert_eq!(r.label_id, None);
    }

    #[test]
    fn test_insert_duplicate_path_fails() {
        let pool = make_pool();

        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin transaction");
            let row1 = make_row("pp-1", r"C:\Data\HR", "manual", "T3", false);
            ProtectedPathsRepository::insert(&uow, &row1).expect("first insert");
            uow.commit().expect("commit");
        }

        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin transaction");
            let row2 = make_row("pp-2", r"C:\Data\HR", "manual", "T4", false);
            let result = ProtectedPathsRepository::insert(&uow, &row2);
            assert!(result.is_err(), "duplicate path must fail");
            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("UNIQUE constraint failed"),
                "error must mention UNIQUE constraint; got: {err_msg}"
            );
        }
    }

    #[test]
    fn test_update_changes_fields() {
        let pool = make_pool();

        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin transaction");
            let row = make_row("pp-1", r"C:\Data\HR", "manual", "T3", false);
            ProtectedPathsRepository::insert(&uow, &row).expect("insert");
            uow.commit().expect("commit");
        }

        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin transaction");
            let updated = ProtectedPathRow {
                tier: "T4".to_string(),
                is_override: true,
                updated_at: "2026-06-01T00:00:00Z".to_string(),
                ..make_row("pp-1", r"C:\Data\HR", "manual", "T3", false)
            };
            let affected = ProtectedPathsRepository::update(&uow, &updated).expect("update");
            assert_eq!(affected, 1, "expected 1 row updated");
            uow.commit().expect("commit");
        }

        let r = ProtectedPathsRepository::get_by_id(&pool, "pp-1").expect("get after update");
        assert_eq!(r.tier, "T4");
        assert!(r.is_override);
        assert_eq!(r.updated_at, "2026-06-01T00:00:00Z");
    }

    #[test]
    fn test_delete_by_id_cascades_to_aces() {
        let pool = make_pool();

        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin transaction");
            let row = make_row("pp-1", r"C:\Data\HR", "manual", "T3", false);
            ProtectedPathsRepository::insert(&uow, &row).expect("insert path");

            let ace = ProtectedPathAceRow {
                id: "ace-1".to_string(),
                protected_path_id: "pp-1".to_string(),
                sddl: "D:PAI(A;OICI;FA;;;BA)".to_string(),
                created_at: "2026-01-01T00:00:00Z".to_string(),
                updated_at: "2026-01-01T00:00:00Z".to_string(),
            };
            ProtectedPathsRepository::upsert_ace(&uow, &ace).expect("insert ace");
            uow.commit().expect("commit");
        }

        // Verify ACE exists before delete.
        let ace_before =
            ProtectedPathsRepository::get_ace_by_path_id(&pool, "pp-1").expect("get ace");
        assert!(ace_before.is_some(), "ACE must exist before path deletion");

        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin transaction");
            let affected =
                ProtectedPathsRepository::delete_by_id(&uow, "pp-1").expect("delete_by_id");
            assert_eq!(affected, 1, "expected 1 row deleted");
            uow.commit().expect("commit");
        }

        let rows = ProtectedPathsRepository::list_all(&pool).expect("list_all after delete");
        assert!(rows.is_empty(), "expected empty vec after delete");

        let ace_after =
            ProtectedPathsRepository::get_ace_by_path_id(&pool, "pp-1").expect("get ace after");
        assert!(
            ace_after.is_none(),
            "ACE must be cascade-deleted with parent path"
        );
    }

    #[test]
    fn test_sync_from_labels_auto_populates() {
        let pool = make_pool();
        let conn = pool.get().expect("get connection");

        // Insert two confirmed T3/T4 labels.
        insert_label_direct(&conn, "label-1", r"\\server\share\HR", "T3");
        insert_label_direct(&conn, "label-2", r"\\server\share\Finance", "T4");
        drop(conn);

        let inserted = ProtectedPathsRepository::sync_from_labels(&pool).expect("sync");
        assert_eq!(inserted, 2, "expected 2 rows inserted from labels");

        let rows = ProtectedPathsRepository::list_all(&pool).expect("list_all after sync");
        assert_eq!(rows.len(), 2);

        let hr = rows
            .iter()
            .find(|r| r.path == r"\\server\share\HR")
            .expect("HR path must exist");
        assert_eq!(hr.source, "auto");
        assert_eq!(hr.tier, "T3");

        let fin = rows
            .iter()
            .find(|r| r.path == r"\\server\share\Finance")
            .expect("Finance path must exist");
        assert_eq!(fin.source, "auto");
        assert_eq!(fin.tier, "T4");
    }

    #[test]
    fn test_sync_from_labels_idempotent() {
        let pool = make_pool();
        let conn = pool.get().expect("get connection");
        insert_label_direct(&conn, "label-1", r"\\server\share\HR", "T3");
        drop(conn);

        let first = ProtectedPathsRepository::sync_from_labels(&pool).expect("first sync");
        assert_eq!(first, 1);

        let second = ProtectedPathsRepository::sync_from_labels(&pool).expect("second sync");
        assert_eq!(second, 0, "second sync must be idempotent (0 inserts)");

        let rows = ProtectedPathsRepository::list_all(&pool).expect("list_all");
        assert_eq!(rows.len(), 1, "must still have exactly 1 row");
    }

    #[test]
    fn test_sync_preserves_manual_entries() {
        let pool = make_pool();

        // Insert a manual entry.
        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin transaction");
            let row = make_row("pp-1", r"\\server\share\HR", "manual", "T3", false);
            ProtectedPathsRepository::insert(&uow, &row).expect("insert manual");
            uow.commit().expect("commit");
        }

        // Insert a label with the same path but different tier.
        let conn = pool.get().expect("get connection");
        insert_label_direct(&conn, "label-1", r"\\server\share\HR", "T4");
        drop(conn);

        let inserted = ProtectedPathsRepository::sync_from_labels(&pool).expect("sync with manual");
        assert_eq!(inserted, 0, "must not insert over manual entry");

        let r = ProtectedPathsRepository::get_by_id(&pool, "pp-1").expect("get manual");
        assert_eq!(r.source, "manual");
        assert_eq!(r.tier, "T3", "manual tier must not change");
    }

    #[test]
    fn test_sync_updates_auto_tier_conflict() {
        let pool = make_pool();

        // Insert an auto entry at T3.
        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin transaction");
            let row = make_row("pp-1", r"\\server\share\HR", "auto", "T3", false);
            ProtectedPathsRepository::insert(&uow, &row).expect("insert auto T3");
            uow.commit().expect("commit");
        }

        // Label now says T4 for the same path.
        let conn = pool.get().expect("get connection");
        insert_label_direct(&conn, "label-1", r"\\server\share\HR", "T4");
        drop(conn);

        let inserted =
            ProtectedPathsRepository::sync_from_labels(&pool).expect("sync with tier conflict");
        assert_eq!(inserted, 0, "must not insert, but should update");

        let r = ProtectedPathsRepository::get_by_id(&pool, "pp-1").expect("get after sync");
        assert_eq!(r.tier, "T4", "auto entry tier must update to stricter T4");
    }

    #[test]
    fn test_upsert_ace_roundtrip() {
        let pool = make_pool();

        // Insert a protected path first (FK requirement).
        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin transaction");
            let row = make_row("pp-1", r"C:\Data\HR", "manual", "T3", false);
            ProtectedPathsRepository::insert(&uow, &row).expect("insert path");

            let ace = ProtectedPathAceRow {
                id: "ace-1".to_string(),
                protected_path_id: "pp-1".to_string(),
                sddl: "D:PAI(A;OICI;FA;;;BA)".to_string(),
                created_at: "2026-01-01T00:00:00Z".to_string(),
                updated_at: "2026-01-01T00:00:00Z".to_string(),
            };
            let affected = ProtectedPathsRepository::upsert_ace(&uow, &ace).expect("upsert ace");
            assert_eq!(affected, 1);
            uow.commit().expect("commit");
        }

        let ace1 = ProtectedPathsRepository::get_ace_by_path_id(&pool, "pp-1").expect("get ace");
        assert_eq!(ace1.as_ref().unwrap().sddl, "D:PAI(A;OICI;FA;;;BA)");

        // Upsert with new SDDL.
        {
            let mut conn = pool.get().expect("get connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin transaction");
            let ace = ProtectedPathAceRow {
                id: "ace-2".to_string(),
                protected_path_id: "pp-1".to_string(),
                sddl: "D:PAI(A;OICI;FA;;;BA)(A;OICI;FR;;;WD)".to_string(),
                created_at: "2026-01-01T00:00:00Z".to_string(),
                updated_at: "2026-06-01T00:00:00Z".to_string(),
            };
            let affected =
                ProtectedPathsRepository::upsert_ace(&uow, &ace).expect("upsert ace update");
            assert_eq!(affected, 1);
            uow.commit().expect("commit");
        }

        let ace2 = ProtectedPathsRepository::get_ace_by_path_id(&pool, "pp-1")
            .expect("get ace after update");
        assert_eq!(
            ace2.as_ref().unwrap().sddl,
            "D:PAI(A;OICI;FA;;;BA)(A;OICI;FR;;;WD)"
        );
    }

    #[test]
    fn test_check_constraint_rejects_invalid_source() {
        let pool = make_pool();
        let mut conn = pool.get().expect("get connection");
        let uow = UnitOfWork::new(&mut conn).expect("begin transaction");
        let bad_row = ProtectedPathRow {
            source: "invalid".to_string(),
            ..make_row("pp-bad", r"C:\Data", "invalid", "T3", false)
        };
        let result = ProtectedPathsRepository::insert(&uow, &bad_row);
        assert!(result.is_err(), "invalid source must be rejected");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("CHECK constraint failed"),
            "error must mention CHECK constraint; got: {err_msg}"
        );
    }

    #[test]
    fn test_check_constraint_rejects_invalid_tier() {
        let pool = make_pool();
        let mut conn = pool.get().expect("get connection");
        let uow = UnitOfWork::new(&mut conn).expect("begin transaction");
        let bad_row = ProtectedPathRow {
            tier: "T2".to_string(),
            ..make_row("pp-bad", r"C:\Data", "manual", "T2", false)
        };
        let result = ProtectedPathsRepository::insert(&uow, &bad_row);
        assert!(result.is_err(), "invalid tier must be rejected");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("CHECK constraint failed"),
            "error must mention CHECK constraint; got: {err_msg}"
        );
    }

    #[test]
    fn test_delete_by_id_nonexistent_returns_zero() {
        let pool = make_pool();
        let mut conn = pool.get().expect("get connection");
        let uow = UnitOfWork::new(&mut conn).expect("begin transaction");
        let affected = ProtectedPathsRepository::delete_by_id(&uow, "does-not-exist")
            .expect("delete_by_id on missing id must not error");
        uow.commit().expect("commit");
        assert_eq!(affected, 0, "expected 0 rows affected for non-existent id");
    }

    #[test]
    fn test_sync_skips_non_confirmed_labels() {
        let pool = make_pool();
        let conn = pool.get().expect("get connection");

        // Insert a temporary (not confirmed) T3 label.
        conn.execute(
            "INSERT INTO labels \
                 (id, path, object_type, tier, label_state, created_at, updated_at) \
             VALUES ('label-1', 'C:\\\\Data\\\\HR', 'folder', 'T3', 'temporary', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            [],
        )
        .expect("insert temporary label");

        // Insert a confirmed T2 label (wrong tier).
        conn.execute(
            "INSERT INTO labels \
                 (id, path, object_type, tier, label_state, created_at, updated_at) \
             VALUES ('label-2', 'C:\\\\Data\\\\IT', 'folder', 'T2', 'confirmed', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            [],
        )
        .expect("insert T2 label");
        drop(conn);

        let inserted =
            ProtectedPathsRepository::sync_from_labels(&pool).expect("sync with no valid labels");
        assert_eq!(
            inserted, 0,
            "must not insert from non-confirmed or non-T3/T4 labels"
        );

        let rows = ProtectedPathsRepository::list_all(&pool).expect("list_all");
        assert!(rows.is_empty(), "must have no protected paths");
    }
}
