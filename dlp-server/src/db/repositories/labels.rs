//! Repository for the `labels` table.
//!
//! Encapsulates all SQL for label CRUD and inheritance queries.

use rusqlite::params;

use crate::db::{Pool, UnitOfWork};

/// Plain data row returned by label reads.
#[derive(Debug, Clone)]
pub struct LabelRow {
    /// UUID string identifying the label.
    pub id: String,
    /// Filesystem or SMB path of the labeled object.
    pub path: String,
    /// Object type: `file`, `folder`, or `archive`.
    pub object_type: String,
    /// Data tier: `T1`, `T2`, `T3`, `T4`, or `Unclassified-Blocked`.
    pub tier: String,
    /// Label state: `temporary`, `confirmed`, `rejected`, or `expired`.
    pub label_state: String,
    /// SID of the Data Owner (from AD Manager attribute).
    pub owner_sid: Option<String>,
    /// FK to parent folder label for inheritance.
    pub parent_label_id: Option<String>,
    /// Reference to ACL snapshot at label time.
    pub acl_snapshot_id: Option<String>,
    /// SHA-256 hash of file content when labeled.
    pub hash: Option<String>,
    /// ISO-8601 timestamp of creation.
    pub created_at: String,
    /// ISO-8601 timestamp of last update.
    pub updated_at: String,
}

/// Row type for label insert/update operations.
#[derive(Debug, Clone)]
pub struct LabelUpsertRow<'a> {
    /// UUID string identifying the label.
    pub id: &'a str,
    /// Filesystem or SMB path.
    pub path: &'a str,
    /// Object type.
    pub object_type: &'a str,
    /// Data tier.
    pub tier: &'a str,
    /// Label state.
    pub label_state: &'a str,
    /// Data Owner SID.
    pub owner_sid: Option<&'a str>,
    /// Parent label ID for inheritance.
    pub parent_label_id: Option<&'a str>,
    /// ACL snapshot reference.
    pub acl_snapshot_id: Option<&'a str>,
    /// Content hash.
    pub hash: Option<&'a str>,
    /// ISO-8601 timestamp.
    pub created_at: &'a str,
    /// ISO-8601 timestamp.
    pub updated_at: &'a str,
}

/// Stateless repository for the `labels` table.
pub struct LabelRepository;

impl LabelRepository {
    /// Returns all labels ordered by path.
    pub fn list(pool: &Pool) -> rusqlite::Result<Vec<LabelRow>> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        let mut stmt = conn.prepare(
            "SELECT id, path, object_type, tier, label_state, owner_sid, \
             parent_label_id, acl_snapshot_id, hash, created_at, updated_at \
             FROM labels ORDER BY path ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(LabelRow {
                id: row.get(0)?,
                path: row.get(1)?,
                object_type: row.get(2)?,
                tier: row.get(3)?,
                label_state: row.get(4)?,
                owner_sid: row.get(5)?,
                parent_label_id: row.get(6)?,
                acl_snapshot_id: row.get(7)?,
                hash: row.get(8)?,
                created_at: row.get(9)?,
                updated_at: row.get(10)?,
            })
        })?;
        rows.collect()
    }

    /// Returns labels filtered by state (e.g., `temporary` for review queue).
    pub fn list_by_state(pool: &Pool, state: &str) -> rusqlite::Result<Vec<LabelRow>> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        let mut stmt = conn.prepare(
            "SELECT id, path, object_type, tier, label_state, owner_sid, \
             parent_label_id, acl_snapshot_id, hash, created_at, updated_at \
             FROM labels WHERE label_state = ?1 ORDER BY path ASC",
        )?;
        let rows = stmt.query_map(params![state], |row| {
            Ok(LabelRow {
                id: row.get(0)?,
                path: row.get(1)?,
                object_type: row.get(2)?,
                tier: row.get(3)?,
                label_state: row.get(4)?,
                owner_sid: row.get(5)?,
                parent_label_id: row.get(6)?,
                acl_snapshot_id: row.get(7)?,
                hash: row.get(8)?,
                created_at: row.get(9)?,
                updated_at: row.get(10)?,
            })
        })?;
        rows.collect()
    }

    /// Returns the single label row with the given `id`.
    pub fn get_by_id(pool: &Pool, id: &str) -> rusqlite::Result<LabelRow> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        conn.query_row(
            "SELECT id, path, object_type, tier, label_state, owner_sid, \
             parent_label_id, acl_snapshot_id, hash, created_at, updated_at \
             FROM labels WHERE id = ?1",
            params![id],
            |row| {
                Ok(LabelRow {
                    id: row.get(0)?,
                    path: row.get(1)?,
                    object_type: row.get(2)?,
                    tier: row.get(3)?,
                    label_state: row.get(4)?,
                    owner_sid: row.get(5)?,
                    parent_label_id: row.get(6)?,
                    acl_snapshot_id: row.get(7)?,
                    hash: row.get(8)?,
                    created_at: row.get(9)?,
                    updated_at: row.get(10)?,
                })
            },
        )
    }

    /// Returns the label for a given path, if any.
    pub fn get_by_path(pool: &Pool, path: &str) -> rusqlite::Result<Option<LabelRow>> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        let mut stmt = conn.prepare(
            "SELECT id, path, object_type, tier, label_state, owner_sid, \
             parent_label_id, acl_snapshot_id, hash, created_at, updated_at \
             FROM labels WHERE path = ?1 LIMIT 1",
        )?;
        let mut rows = stmt.query_map(params![path], |row| {
            Ok(LabelRow {
                id: row.get(0)?,
                path: row.get(1)?,
                object_type: row.get(2)?,
                tier: row.get(3)?,
                label_state: row.get(4)?,
                owner_sid: row.get(5)?,
                parent_label_id: row.get(6)?,
                acl_snapshot_id: row.get(7)?,
                hash: row.get(8)?,
                created_at: row.get(9)?,
                updated_at: row.get(10)?,
            })
        })?;
        rows.next().transpose()
    }

    /// Inserts a new label record.
    pub fn insert(uow: &UnitOfWork<'_>, record: &LabelUpsertRow<'_>) -> rusqlite::Result<()> {
        uow.tx.execute(
            "INSERT INTO labels (id, path, object_type, tier, label_state, \
             owner_sid, parent_label_id, acl_snapshot_id, hash, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                record.id,
                record.path,
                record.object_type,
                record.tier,
                record.label_state,
                record.owner_sid,
                record.parent_label_id,
                record.acl_snapshot_id,
                record.hash,
                record.created_at,
                record.updated_at,
            ],
        )?;
        Ok(())
    }

    /// Updates an existing label row.
    pub fn update(uow: &UnitOfWork<'_>, record: &LabelUpsertRow<'_>) -> rusqlite::Result<usize> {
        uow.tx.execute(
            "UPDATE labels SET \
                    path = ?1, object_type = ?2, tier = ?3, label_state = ?4, \
                    owner_sid = ?5, parent_label_id = ?6, acl_snapshot_id = ?7, \
                    hash = ?8, updated_at = ?9 \
             WHERE id = ?10",
            params![
                record.path,
                record.object_type,
                record.tier,
                record.label_state,
                record.owner_sid,
                record.parent_label_id,
                record.acl_snapshot_id,
                record.hash,
                record.updated_at,
                record.id,
            ],
        )
    }

    /// Updates only the label_state of a label (for confirm/reject workflow).
    pub fn update_state(
        uow: &UnitOfWork<'_>,
        id: &str,
        state: &str,
        updated_at: &str,
    ) -> rusqlite::Result<usize> {
        uow.tx.execute(
            "UPDATE labels SET label_state = ?1, updated_at = ?2 WHERE id = ?3",
            params![state, updated_at, id],
        )
    }

    /// Deletes the label row with the given `id`.
    pub fn delete(uow: &UnitOfWork<'_>, id: &str) -> rusqlite::Result<usize> {
        uow.tx.execute("DELETE FROM labels WHERE id = ?1", params![id])
    }

    /// Returns the parent folder label for a given child path.
    /// Walks up the directory tree until it finds a folder label.
    pub fn find_parent_label(pool: &Pool, child_path: &str) -> rusqlite::Result<Option<LabelRow>> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        // Walk up the path: for \\server\share\dir\file.txt, try:
        // \\server\share\dir, \\server\share, \\server
        let mut current = child_path.to_string();
        while let Some(parent_end) = current.rfind(['\\', '/']) {
            let parent = &current[..parent_end];
            if parent.is_empty() {
                break;
            }
            let result: Option<LabelRow> = conn
                .query_row(
                    "SELECT id, path, object_type, tier, label_state, owner_sid, \
                     parent_label_id, acl_snapshot_id, hash, created_at, updated_at \
                     FROM labels WHERE path = ?1 AND object_type = 'folder' LIMIT 1",
                    params![parent],
                    |row| {
                        Ok(LabelRow {
                            id: row.get(0)?,
                            path: row.get(1)?,
                            object_type: row.get(2)?,
                            tier: row.get(3)?,
                            label_state: row.get(4)?,
                            owner_sid: row.get(5)?,
                            parent_label_id: row.get(6)?,
                            acl_snapshot_id: row.get(7)?,
                            hash: row.get(8)?,
                            created_at: row.get(9)?,
                            updated_at: row.get(10)?,
                        })
                    },
                )
                .ok();
            if result.is_some() {
                return Ok(result);
            }
            current = parent.to_string();
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::new_pool;

    #[test]
    fn test_labels_table_exists() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='labels'",
                [],
                |r| r.get(0),
            )
            .expect("query sqlite_master");
        assert_eq!(count, 1, "labels table must exist after init");
    }

    #[test]
    fn test_labels_crud() {
        let pool = new_pool(":memory:").expect("create pool");

        // Insert a folder label
        let folder_id = "folder-001";
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            LabelRepository::insert(
                &uow,
                &LabelUpsertRow {
                    id: folder_id,
                    path: r"\\server\share\HR",
                    object_type: "folder",
                    tier: "T3",
                    label_state: "confirmed",
                    owner_sid: Some("S-1-5-21-1"),
                    parent_label_id: None,
                    acl_snapshot_id: None,
                    hash: None,
                    created_at: "2026-05-12T00:00:00Z",
                    updated_at: "2026-05-12T00:00:00Z",
                },
            )
            .expect("insert folder label");
            uow.commit().expect("commit");
        }

        // Insert a child file label
        let file_id = "file-001";
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            LabelRepository::insert(
                &uow,
                &LabelUpsertRow {
                    id: file_id,
                    path: r"\\server\share\HR\salary.xlsx",
                    object_type: "file",
                    tier: "T4",
                    label_state: "temporary",
                    owner_sid: Some("S-1-5-21-1"),
                    parent_label_id: Some(folder_id),
                    acl_snapshot_id: Some("acl-001"),
                    hash: Some("sha256-abc"),
                    created_at: "2026-05-12T01:00:00Z",
                    updated_at: "2026-05-12T01:00:00Z",
                },
            )
            .expect("insert file label");
            uow.commit().expect("commit");
        }

        // List all
        let all = LabelRepository::list(&pool).expect("list");
        assert_eq!(all.len(), 2);

        // List by state
        let temporary = LabelRepository::list_by_state(&pool, "temporary").expect("list temporary");
        assert_eq!(temporary.len(), 1);
        assert_eq!(temporary[0].id, file_id);

        // Get by ID
        let row = LabelRepository::get_by_id(&pool, file_id).expect("get by id");
        assert_eq!(row.tier, "T4");
        assert_eq!(row.label_state, "temporary");

        // Update state
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            let affected =
                LabelRepository::update_state(&uow, file_id, "confirmed", "2026-05-12T02:00:00Z")
                    .expect("update state");
            assert_eq!(affected, 1);
            uow.commit().expect("commit");
        }

        let confirmed = LabelRepository::list_by_state(&pool, "confirmed").expect("list confirmed");
        assert_eq!(confirmed.len(), 2); // folder + confirmed file

        // Find parent label
        let parent = LabelRepository::find_parent_label(&pool, r"\\server\share\HR\salary.xlsx")
            .expect("find parent");
        assert!(parent.is_some());
        assert_eq!(parent.unwrap().id, folder_id);

        // Delete
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            let affected = LabelRepository::delete(&uow, file_id).expect("delete");
            assert_eq!(affected, 1);
            uow.commit().expect("commit");
        }
        let remaining = LabelRepository::list(&pool).expect("list after delete");
        assert_eq!(remaining.len(), 1);
    }

    #[test]
    fn test_labels_check_constraints() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        // Invalid tier
        let result = conn.execute(
            "INSERT INTO labels (id, path, object_type, tier, label_state, created_at, updated_at) \
             VALUES ('id1', 'path', 'file', 'T5', 'temporary', '2026-01-01', '2026-01-01')",
            [],
        );
        assert!(result.is_err(), "invalid tier must fail CHECK constraint");
        assert!(
            result.unwrap_err().to_string().contains("CHECK constraint failed")
        );

        // Invalid object_type
        let result = conn.execute(
            "INSERT INTO labels (id, path, object_type, tier, label_state, created_at, updated_at) \
             VALUES ('id2', 'path', 'disk', 'T1', 'temporary', '2026-01-01', '2026-01-01')",
            [],
        );
        assert!(result.is_err(), "invalid object_type must fail CHECK constraint");

        // Invalid label_state
        let result = conn.execute(
            "INSERT INTO labels (id, path, object_type, tier, label_state, created_at, updated_at) \
             VALUES ('id3', 'path', 'file', 'T1', 'draft', '2026-01-01', '2026-01-01')",
            [],
        );
        assert!(result.is_err(), "invalid label_state must fail CHECK constraint");
    }
}
