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
    /// Scanner confidence score (0.0-1.0), nullable.
    pub scanner_confidence: Option<f32>,
    /// Department or business unit owning the data.
    pub department: Option<String>,
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
    /// Scanner confidence score (0.0-1.0), nullable.
    pub scanner_confidence: Option<f32>,
    /// Department or business unit owning the data.
    pub department: Option<&'a str>,
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
             parent_label_id, acl_snapshot_id, hash, scanner_confidence, department, \
             created_at, updated_at \
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
                scanner_confidence: row.get(9)?,
                department: row.get(10)?,
                created_at: row.get(11)?,
                updated_at: row.get(12)?,
            })
        })?;
        rows.collect()
    }

    /// Returns labels filtered by optional criteria at the DB level.
    ///
    /// Builds a parameterized query with WHERE clauses for each provided filter.
    /// This avoids in-memory filtering and supports Data Owner scoping.
    ///
    /// Pagination is supported via `limit` and `offset` parameters.
    pub fn list_by_filters(
        pool: &Pool,
        state: Option<&str>,
        tier: Option<&str>,
        owner_sid: Option<&str>,
        department: Option<&str>,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> rusqlite::Result<Vec<LabelRow>> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

        let mut sql = String::from(
            "SELECT id, path, object_type, tier, label_state, owner_sid, \
             parent_label_id, acl_snapshot_id, hash, scanner_confidence, department, \
             created_at, updated_at FROM labels WHERE 1=1",
        );
        let mut param_count = 0;
        if state.is_some() {
            param_count += 1;
            sql.push_str(&format!(" AND label_state = ?{param_count}"));
        }
        if tier.is_some() {
            param_count += 1;
            sql.push_str(&format!(" AND tier = ?{param_count}"));
        }
        if owner_sid.is_some() {
            param_count += 1;
            sql.push_str(&format!(" AND owner_sid = ?{param_count}"));
        }
        if department.is_some() {
            param_count += 1;
            sql.push_str(&format!(" AND department = ?{param_count}"));
        }

        sql.push_str(" ORDER BY path ASC");

        if let Some(lim) = limit {
            param_count += 1;
            sql.push_str(&format!(" LIMIT ?{param_count}"));
            if let Some(off) = offset {
                param_count += 1;
                sql.push_str(&format!(" OFFSET ?{param_count}"));
            }
        }

        let mut stmt = conn.prepare(&sql)?;
        // Build a Vec of &str refs first, then map to &dyn ToSql.
        let mut str_params: Vec<&str> = Vec::new();
        if let Some(s) = state {
            str_params.push(s);
        }
        if let Some(t) = tier {
            str_params.push(t);
        }
        if let Some(o) = owner_sid {
            str_params.push(o);
        }
        if let Some(d) = department {
            str_params.push(d);
        }
        let limit_i64: Option<i64> = limit.map(|v| v as i64);
        let offset_i64: Option<i64> = offset.map(|v| v as i64);
        let mut params: Vec<&dyn rusqlite::ToSql> =
            str_params.iter().map(|p| p as &dyn rusqlite::ToSql).collect();
        if let Some(ref lim) = limit_i64 {
            params.push(lim);
            if let Some(ref off) = offset_i64 {
                params.push(off);
            }
        }
        let rows = stmt.query_map(rusqlite::params_from_iter(params), |row| {
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
                scanner_confidence: row.get(9)?,
                department: row.get(10)?,
                created_at: row.get(11)?,
                updated_at: row.get(12)?,
            })
        })?;
        rows.collect()
    }

    /// Returns the count of labels matching the given filter criteria.
    ///
    /// Builds the same WHERE clause as `list_by_filters` but uses `SELECT COUNT(*)`.
    pub fn count_by_filters(
        pool: &Pool,
        state: Option<&str>,
        tier: Option<&str>,
        owner_sid: Option<&str>,
        department: Option<&str>,
    ) -> rusqlite::Result<i64> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

        let mut sql = String::from("SELECT COUNT(*) FROM labels WHERE 1=1");
        let mut param_count = 0;
        if state.is_some() {
            param_count += 1;
            sql.push_str(&format!(" AND label_state = ?{param_count}"));
        }
        if tier.is_some() {
            param_count += 1;
            sql.push_str(&format!(" AND tier = ?{param_count}"));
        }
        if owner_sid.is_some() {
            param_count += 1;
            sql.push_str(&format!(" AND owner_sid = ?{param_count}"));
        }
        if department.is_some() {
            param_count += 1;
            sql.push_str(&format!(" AND department = ?{param_count}"));
        }

        let mut str_params: Vec<&str> = Vec::new();
        if let Some(s) = state {
            str_params.push(s);
        }
        if let Some(t) = tier {
            str_params.push(t);
        }
        if let Some(o) = owner_sid {
            str_params.push(o);
        }
        if let Some(d) = department {
            str_params.push(d);
        }
        let params: Vec<&dyn rusqlite::ToSql> =
            str_params.iter().map(|p| p as &dyn rusqlite::ToSql).collect();

        conn.query_row(&sql, rusqlite::params_from_iter(params), |row| row.get(0))
    }

    /// Returns the single label row with the given `id`.
    pub fn get_by_id(pool: &Pool, id: &str) -> rusqlite::Result<LabelRow> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        conn.query_row(
            "SELECT id, path, object_type, tier, label_state, owner_sid, \
             parent_label_id, acl_snapshot_id, hash, scanner_confidence, department, \
             created_at, updated_at \
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
                    scanner_confidence: row.get(9)?,
                    department: row.get(10)?,
                    created_at: row.get(11)?,
                    updated_at: row.get(12)?,
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
             parent_label_id, acl_snapshot_id, hash, scanner_confidence, department, \
             created_at, updated_at \
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
                scanner_confidence: row.get(9)?,
                department: row.get(10)?,
                created_at: row.get(11)?,
                updated_at: row.get(12)?,
            })
        })?;
        rows.next().transpose()
    }

    /// Inserts a new label record.
    pub fn insert(uow: &UnitOfWork<'_>, record: &LabelUpsertRow<'_>) -> rusqlite::Result<()> {
        uow.tx.execute(
            "INSERT INTO labels (id, path, object_type, tier, label_state, \
             owner_sid, parent_label_id, acl_snapshot_id, hash, scanner_confidence, department, \
             created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
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
                record.scanner_confidence,
                record.department,
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
                    hash = ?8, scanner_confidence = ?9, department = ?10, updated_at = ?11 \
             WHERE id = ?12",
            params![
                record.path,
                record.object_type,
                record.tier,
                record.label_state,
                record.owner_sid,
                record.parent_label_id,
                record.acl_snapshot_id,
                record.hash,
                record.scanner_confidence,
                record.department,
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
        uow.tx
            .execute("DELETE FROM labels WHERE id = ?1", params![id])
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
                     parent_label_id, acl_snapshot_id, hash, scanner_confidence, department, \
                     created_at, updated_at \
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
                            scanner_confidence: row.get(9)?,
                            department: row.get(10)?,
                            created_at: row.get(11)?,
                            updated_at: row.get(12)?,
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
                    scanner_confidence: None,
                    department: None,
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
                    scanner_confidence: Some(0.85),
                    department: Some("HR"),
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

        // List by state using list_by_filters
        let temporary =
            LabelRepository::list_by_filters(&pool, Some("temporary"), None, None, None, None, None)
                .expect("list temporary");
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

        let confirmed =
            LabelRepository::list_by_filters(
                &pool, Some("confirmed"), None, None, None, None, None,
            )
            .expect("list confirmed");
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
    fn test_list_by_filters_department() {
        let pool = new_pool(":memory:").expect("create pool");

        // Insert labels with different departments
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            LabelRepository::insert(
                &uow,
                &LabelUpsertRow {
                    id: "label-hr",
                    path: r"\\server\share\HR\doc1.txt",
                    object_type: "file",
                    tier: "T3",
                    label_state: "temporary",
                    owner_sid: Some("S-1-5-21-1"),
                    parent_label_id: None,
                    acl_snapshot_id: None,
                    hash: None,
                    scanner_confidence: Some(0.85),
                    department: Some("HR"),
                    created_at: "2026-05-12T00:00:00Z",
                    updated_at: "2026-05-12T00:00:00Z",
                },
            )
            .expect("insert HR label");
            LabelRepository::insert(
                &uow,
                &LabelUpsertRow {
                    id: "label-it",
                    path: r"\\server\share\IT\doc2.txt",
                    object_type: "file",
                    tier: "T2",
                    label_state: "temporary",
                    owner_sid: Some("S-1-5-21-2"),
                    parent_label_id: None,
                    acl_snapshot_id: None,
                    hash: None,
                    scanner_confidence: Some(0.72),
                    department: Some("IT"),
                    created_at: "2026-05-12T00:00:00Z",
                    updated_at: "2026-05-12T00:00:00Z",
                },
            )
            .expect("insert IT label");
            LabelRepository::insert(
                &uow,
                &LabelUpsertRow {
                    id: "label-none",
                    path: r"\\server\share\doc3.txt",
                    object_type: "file",
                    tier: "T1",
                    label_state: "temporary",
                    owner_sid: None,
                    parent_label_id: None,
                    acl_snapshot_id: None,
                    hash: None,
                    scanner_confidence: None,
                    department: None,
                    created_at: "2026-05-12T00:00:00Z",
                    updated_at: "2026-05-12T00:00:00Z",
                },
            )
            .expect("insert no-dept label");
            uow.commit().expect("commit");
        }

        // Filter by department = HR
        let hr_labels =
            LabelRepository::list_by_filters(&pool, None, None, None, Some("HR"), None, None)
                .expect("list HR");
        assert_eq!(hr_labels.len(), 1);
        assert_eq!(hr_labels[0].id, "label-hr");
        assert_eq!(hr_labels[0].scanner_confidence, Some(0.85));

        // Filter by department = IT
        let it_labels =
            LabelRepository::list_by_filters(
                &pool, None, None, None, Some("IT"), None, None,
            )
            .expect("list IT");
        assert_eq!(it_labels.len(), 1);
        assert_eq!(it_labels[0].id, "label-it");

        // Filter by state = temporary AND department = HR
        let hr_temp =
            LabelRepository::list_by_filters(
                &pool, Some("temporary"), None, None, Some("HR"), None, None,
            )
            .expect("list HR temporary");
        assert_eq!(hr_temp.len(), 1);
        assert_eq!(hr_temp[0].id, "label-hr");

        // No filter returns all 3
        let all =
            LabelRepository::list_by_filters(&pool, None, None, None, None, None, None)
                .expect("list all");
        assert_eq!(all.len(), 3);
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
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("CHECK constraint failed"));

        // Invalid object_type
        let result = conn.execute(
            "INSERT INTO labels (id, path, object_type, tier, label_state, created_at, updated_at) \
             VALUES ('id2', 'path', 'disk', 'T1', 'temporary', '2026-01-01', '2026-01-01')",
            [],
        );
        assert!(
            result.is_err(),
            "invalid object_type must fail CHECK constraint"
        );

        // Invalid label_state
        let result = conn.execute(
            "INSERT INTO labels (id, path, object_type, tier, label_state, created_at, updated_at) \
             VALUES ('id3', 'path', 'file', 'T1', 'draft', '2026-01-01', '2026-01-01')",
            [],
        );
        assert!(
            result.is_err(),
            "invalid label_state must fail CHECK constraint"
        );
    }

    #[test]
    fn test_labels_indexes_exist() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let indexes: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='labels'")
            .expect("prepare")
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query")
            .filter_map(Result::ok)
            .collect();

        let expected = [
            "idx_labels_path",
            "idx_labels_tier",
            "idx_labels_state",
            "idx_labels_owner",
            "idx_labels_parent",
            "idx_labels_department",
        ];
        for idx in &expected {
            assert!(
                indexes.contains(&idx.to_string()),
                "index '{idx}' must exist on labels table; found {indexes:?}"
            );
        }
    }

    #[test]
    fn test_list_by_filters_pagination() {
        let pool = new_pool(":memory:").expect("create pool");

        // Insert 5 labels
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            for i in 1..=5 {
                LabelRepository::insert(
                    &uow,
                    &LabelUpsertRow {
                        id: &format!("label-{i}"),
                        path: &format!(r"\\server\share\doc{i}.txt"),
                        object_type: "file",
                        tier: "T2",
                        label_state: "temporary",
                        owner_sid: None,
                        parent_label_id: None,
                        acl_snapshot_id: None,
                        hash: None,
                        scanner_confidence: None,
                        department: None,
                        created_at: "2026-05-12T00:00:00Z",
                        updated_at: "2026-05-12T00:00:00Z",
                    },
                )
                .expect("insert");
            }
            uow.commit().expect("commit");
        }

        // Page 1: limit 2, offset 0
        let page1 = LabelRepository::list_by_filters(&pool, None, None, None, None, Some(2), Some(0))
            .expect("page1");
        assert_eq!(page1.len(), 2, "page1 should have 2 items");
        assert_eq!(page1[0].id, "label-1");
        assert_eq!(page1[1].id, "label-2");

        // Page 2: limit 2, offset 2
        let page2 = LabelRepository::list_by_filters(&pool, None, None, None, None, Some(2), Some(2))
            .expect("page2");
        assert_eq!(page2.len(), 2, "page2 should have 2 items");
        assert_eq!(page2[0].id, "label-3");
        assert_eq!(page2[1].id, "label-4");

        // Page 3: limit 2, offset 4
        let page3 = LabelRepository::list_by_filters(&pool, None, None, None, None, Some(2), Some(4))
            .expect("page3");
        assert_eq!(page3.len(), 1, "page3 should have 1 item");
        assert_eq!(page3[0].id, "label-5");
    }

    #[test]
    fn test_count_by_filters() {
        let pool = new_pool(":memory:").expect("create pool");

        // Insert labels with different states and tiers
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            LabelRepository::insert(
                &uow,
                &LabelUpsertRow {
                    id: "label-1",
                    path: r"\\server\share\doc1.txt",
                    object_type: "file",
                    tier: "T3",
                    label_state: "temporary",
                    owner_sid: Some("S-1-5-21-1"),
                    parent_label_id: None,
                    acl_snapshot_id: None,
                    hash: None,
                    scanner_confidence: None,
                    department: Some("HR"),
                    created_at: "2026-05-12T00:00:00Z",
                    updated_at: "2026-05-12T00:00:00Z",
                },
            )
            .expect("insert");
            LabelRepository::insert(
                &uow,
                &LabelUpsertRow {
                    id: "label-2",
                    path: r"\\server\share\doc2.txt",
                    object_type: "file",
                    tier: "T2",
                    label_state: "confirmed",
                    owner_sid: Some("S-1-5-21-2"),
                    parent_label_id: None,
                    acl_snapshot_id: None,
                    hash: None,
                    scanner_confidence: None,
                    department: Some("IT"),
                    created_at: "2026-05-12T00:00:00Z",
                    updated_at: "2026-05-12T00:00:00Z",
                },
            )
            .expect("insert");
            LabelRepository::insert(
                &uow,
                &LabelUpsertRow {
                    id: "label-3",
                    path: r"\\server\share\doc3.txt",
                    object_type: "file",
                    tier: "T3",
                    label_state: "temporary",
                    owner_sid: Some("S-1-5-21-1"),
                    parent_label_id: None,
                    acl_snapshot_id: None,
                    hash: None,
                    scanner_confidence: None,
                    department: Some("HR"),
                    created_at: "2026-05-12T00:00:00Z",
                    updated_at: "2026-05-12T00:00:00Z",
                },
            )
            .expect("insert");
            uow.commit().expect("commit");
        }

        // Count all
        let all_count = LabelRepository::count_by_filters(&pool, None, None, None, None)
            .expect("count all");
        assert_eq!(all_count, 3);

        // Count by state
        let temp_count = LabelRepository::count_by_filters(&pool, Some("temporary"), None, None, None)
            .expect("count temporary");
        assert_eq!(temp_count, 2);

        // Count by tier
        let t3_count = LabelRepository::count_by_filters(&pool, None, Some("T3"), None, None)
            .expect("count T3");
        assert_eq!(t3_count, 2);

        // Count by owner
        let owner_count =
            LabelRepository::count_by_filters(&pool, None, None, Some("S-1-5-21-1"), None)
                .expect("count owner");
        assert_eq!(owner_count, 2);

        // Count by department
        let hr_count = LabelRepository::count_by_filters(&pool, None, None, None, Some("HR"))
            .expect("count HR");
        assert_eq!(hr_count, 2);

        // Count combined filters
        let combined = LabelRepository::count_by_filters(
            &pool,
            Some("temporary"),
            Some("T3"),
            Some("S-1-5-21-1"),
            Some("HR"),
        )
        .expect("count combined");
        assert_eq!(combined, 2);
    }

    #[test]
    fn test_labels_parent_fk_constraint() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        // Verify parent_label_id has the FK constraint by checking it
        // accepts valid references and handles ON DELETE SET NULL.
        // Insert a parent folder label.
        conn.execute(
            "INSERT INTO labels (id, path, object_type, tier, label_state, created_at, updated_at) \
             VALUES ('parent-001', 'C:\\Data\\HR', 'folder', 'T3', 'confirmed', '2026-01-01', '2026-01-01')",
            [],
        )
        .expect("insert parent must succeed");

        // Insert a child with valid parent_label_id.
        conn.execute(
            "INSERT INTO labels (id, path, object_type, tier, label_state, parent_label_id, created_at, updated_at) \
             VALUES ('child-001', 'C:\\Data\\HR\\file.txt', 'file', 'T4', 'temporary', 'parent-001', '2026-01-01', '2026-01-01')",
            [],
        )
        .expect("insert child with valid FK must succeed");

        // Delete the parent — child.parent_label_id should become NULL (ON DELETE SET NULL).
        conn.execute("DELETE FROM labels WHERE id = 'parent-001'", [])
            .expect("delete parent must succeed");

        let parent_id: Option<String> = conn
            .query_row(
                "SELECT parent_label_id FROM labels WHERE id = 'child-001'",
                [],
                |r| r.get(0),
            )
            .expect("query child");
        assert!(
            parent_id.is_none(),
            "parent_label_id must be NULL after parent deletion (ON DELETE SET NULL)"
        );
    }
}
