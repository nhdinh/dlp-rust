import re

# ========================================================================
# 1. Fix dlp-server/src/db/repositories/policies.rs
# ========================================================================
with open('dlp-server/src/db/repositories/policies.rs', 'r') as f:
    content = f.read()

# Add enforcement_mode to PolicyRow (after mode)
content = content.replace(
    '''    /// Boolean composition mode for the conditions list.
    pub mode: String,
    /// Version counter incremented on each update.''',
    '''    /// Boolean composition mode for the conditions list.
    pub mode: String,
    /// Enforcement mode: "Audit", "Block", or "AuditAndBlock".
    pub enforcement_mode: String,
    /// Version counter incremented on each update.'''
)

# Add enforcement_mode to PolicyUpdateRow (after mode)
content = content.replace(
    '''    /// New boolean composition mode.
    pub mode: &'a str,
    /// New ISO-8601 timestamp.''',
    '''    /// New boolean composition mode.
    pub mode: &'a str,
    /// New enforcement mode.
    pub enforcement_mode: &'a str,
    /// New ISO-8601 timestamp.'''
)

# Update list() SELECT and mapper
content = content.replace(
    '''"SELECT id, name, description, priority, conditions, action, \\\n             enabled, mode, version, updated_at \\\n             FROM policies ORDER BY priority ASC"''',
    '''"SELECT id, name, description, priority, conditions, action, \\\n             enabled, mode, enforcement_mode, version, updated_at \\\n             FROM policies ORDER BY priority ASC"'''
)
content = content.replace(
    '''                mode: row.get(7)?,
                version: row.get(8)?,
                updated_at: row.get(9)?,''',
    '''                mode: row.get(7)?,
                enforcement_mode: row.get(8)?,
                version: row.get(9)?,
                updated_at: row.get(10)?,'''
)

# Update insert()
content = content.replace(
    '''"INSERT INTO policies (id, name, description, priority, conditions, \\\n             action, enabled, mode, version, updated_at) \\\n             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"''',
    '''"INSERT INTO policies (id, name, description, priority, conditions, \\\n             action, enabled, mode, enforcement_mode, version, updated_at) \\\n             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"'''
)
content = content.replace(
    '''                record.mode,
                record.version,
                record.updated_at,''',
    '''                record.mode,
                record.enforcement_mode,
                record.version,
                record.updated_at,'''
)

# Update get_by_id() SELECT and mapper
content = content.replace(
    '''"SELECT id, name, description, priority, conditions, action, \\\n             enabled, mode, version, updated_at \\\n             FROM policies WHERE id = ?1"''',
    '''"SELECT id, name, description, priority, conditions, action, \\\n             enabled, mode, enforcement_mode, version, updated_at \\\n             FROM policies WHERE id = ?1"'''
)
content = content.replace(
    '''                    mode: row.get(7)?,
                    version: row.get(8)?,
                    updated_at: row.get(9)?,''',
    '''                    mode: row.get(7)?,
                    enforcement_mode: row.get(8)?,
                    version: row.get(9)?,
                    updated_at: row.get(10)?,'''
)

# Update update() SQL
content = content.replace(
    '''"UPDATE policies SET \\\n                    name = ?1, description = ?2, priority = ?3, \\\n                    conditions = ?4, action = ?5, enabled = ?6, \\\n                    mode = ?7, version = version + 1, updated_at = ?8 \\\n             WHERE id = ?9"''',
    '''"UPDATE policies SET \\\n                    name = ?1, description = ?2, priority = ?3, \\\n                    conditions = ?4, action = ?5, enabled = ?6, \\\n                    mode = ?7, enforcement_mode = ?8, version = version + 1, updated_at = ?9 \\\n             WHERE id = ?10"'''
)
content = content.replace(
    '''                row.mode,
                row.updated_at,
                row.id,''',
    '''                row.mode,
                row.enforcement_mode,
                row.updated_at,
                row.id,'''
)

# Append tests at the end
old_end = '''    pub fn delete(uow: &UnitOfWork<'_>, id: &str) -> rusqlite::Result<usize> {
        uow.tx
            .execute("DELETE FROM policies WHERE id = ?1", params![id])
    }
}'''
new_end = '''    pub fn delete(uow: &UnitOfWork<'_>, id: &str) -> rusqlite::Result<usize> {
        uow.tx
            .execute("DELETE FROM policies WHERE id = ?1", params![id])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{new_pool, UnitOfWork};

    #[test]
    fn test_policy_row_enforcement_mode() {
        let row = PolicyRow {
            id: "p1".to_string(),
            name: "Test Policy".to_string(),
            description: None,
            priority: 1,
            conditions: "[]".to_string(),
            action: "DENY".to_string(),
            enabled: 1,
            mode: "ALL".to_string(),
            enforcement_mode: "Block".to_string(),
            version: 1,
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        };
        assert_eq!(row.enforcement_mode, "Block");
    }

    #[test]
    fn test_policy_repository_crud_with_enforcement_mode() {
        let pool = new_pool(":memory:").expect("create pool");

        // Insert a policy with enforcement_mode = Audit.
        let mut uow = UnitOfWork::new(&pool).expect("create uow");
        let row = PolicyRow {
            id: "p-audit".to_string(),
            name: "Audit Policy".to_string(),
            description: Some("Test".to_string()),
            priority: 10,
            conditions: "[]".to_string(),
            action: "DENY".to_string(),
            enabled: 1,
            mode: "ALL".to_string(),
            enforcement_mode: "Audit".to_string(),
            version: 1,
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        };
        PolicyRepository::insert(&uow, &row).expect("insert policy");
        uow.commit().expect("commit");

        // Read back via list.
        let policies = PolicyRepository::list(&pool).expect("list policies");
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].enforcement_mode, "Audit");

        // Read back via get_by_id.
        let fetched = PolicyRepository::get_by_id(&pool, "p-audit").expect("get by id");
        assert_eq!(fetched.enforcement_mode, "Audit");

        // Update enforcement_mode to AuditAndBlock.
        let mut uow2 = UnitOfWork::new(&pool).expect("create uow");
        let update = PolicyUpdateRow {
            name: "Audit Policy",
            description: Some("Test"),
            priority: 10,
            conditions: "[]",
            action: "DENY",
            enabled: 1,
            mode: "ALL",
            enforcement_mode: "AuditAndBlock",
            updated_at: "2026-01-02T00:00:00Z",
            id: "p-audit",
        };
        let affected = PolicyRepository::update(&uow2, &update).expect("update");
        assert_eq!(affected, 1);
        uow2.commit().expect("commit");

        // Verify update.
        let updated = PolicyRepository::get_by_id(&pool, "p-audit").expect("get updated");
        assert_eq!(updated.enforcement_mode, "AuditAndBlock");
        assert_eq!(updated.version, 2, "version must be incremented");
    }

    #[test]
    fn test_policy_repository_default_enforcement_mode() {
        // Simulate a pre-Phase-55 database where policies exist without
        // the enforcement_mode column. After migration, existing rows
        // must default to 'Block'.
        let tmp = tempfile::NamedTempFile::new().expect("create temp db file");
        let path = tmp.path().to_str().expect("temp path utf8");

        // Step 1: create a pre-Phase-55 policies table without enforcement_mode.
        {
            let conn = rusqlite::Connection::open(path).expect("open temp db");
            conn.execute_batch(
                "CREATE TABLE policies (
                    id          TEXT PRIMARY KEY,
                    name        TEXT NOT NULL,
                    description TEXT,
                    priority    INTEGER NOT NULL,
                    conditions  TEXT NOT NULL,
                    action      TEXT NOT NULL,
                    enabled     INTEGER NOT NULL DEFAULT 1,
                    mode        TEXT NOT NULL DEFAULT 'ALL',
                    version     INTEGER NOT NULL DEFAULT 1,
                    updated_at  TEXT NOT NULL
                );
                INSERT INTO policies
                    (id, name, priority, conditions, action, enabled, mode, version, updated_at)
                VALUES
                    ('legacy-policy', 'Legacy', 1, '[]', 'Allow', 1, 'ALL', 1, '2026-01-01T00:00:00Z');",
            )
            .expect("create pre-Phase-55 schema");
        }

        // Step 2: open via new_pool -- triggers run_migrations.
        let pool = new_pool(path).expect("open pool with migrations");
        let conn = pool.get().expect("acquire connection");

        // Step 3: confirm enforcement_mode column exists.
        let columns: Vec<String> = conn
            .prepare("PRAGMA table_info(policies)")
            .expect("prepare pragma")
            .query_map([], |row| row.get::<_, String>(1))
            .expect("query pragma")
            .filter_map(Result::ok)
            .collect();
        assert!(
            columns.contains(&"enforcement_mode".to_string()),
            "enforcement_mode column must exist after migration; saw {columns:?}"
        );

        // Step 4: pre-existing row picks up SQL DEFAULT 'Block'.
        let mode: String = conn
            .query_row(
                "SELECT enforcement_mode FROM policies WHERE id = 'legacy-policy'",
                [],
                |r| r.get(0),
            )
            .expect("read enforcement_mode from pre-existing row");
        assert_eq!(
            mode, "Block",
            "pre-existing rows must default to 'Block' enforcement_mode"
        );

        // Step 5: idempotency -- re-running migrations must not error.
        crate::db::run_migrations(&conn).expect("second run must not error");
    }

    #[test]
    fn test_global_enforcement_mode_system_kv_seed() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let value: String = conn
            .query_row(
                "SELECT value FROM system_kv WHERE key = 'global_enforcement_mode'",
                [],
                |r| r.get(0),
            )
            .expect("global_enforcement_mode system_kv row must exist");
        assert_eq!(value, "PerPolicy", "default global_enforcement_mode must be PerPolicy");
    }

    #[test]
    fn test_enforcement_mode_check_constraint() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        // Valid enforcement_mode values must succeed.
        for mode in ["Audit", "Block", "AuditAndBlock"] {
            let id = format!("p-{mode}");
            conn.execute(
                "INSERT INTO policies (id, name, priority, conditions, action, enabled, mode, enforcement_mode, version, updated_at) \\\n                 VALUES (?1, 'Test', 1, '[]', 'Allow', 1, 'ALL', ?2, 1, '2026-01-01T00:00:00Z')",
                rusqlite::params![id, mode],
            )
            .unwrap_or_else(|e| panic!("INSERT with enforcement_mode='{mode}' must succeed; got: {e}"));
        }

        // Invalid enforcement_mode must fail CHECK constraint.
        let result = conn.execute(
            "INSERT INTO policies (id, name, priority, conditions, action, enabled, mode, enforcement_mode, version, updated_at) \\\n             VALUES ('p-bad', 'Test', 1, '[]', 'Allow', 1, 'ALL', 'InvalidMode', 1, '2026-01-01T00:00:00Z')",
            [],
        );
        assert!(result.is_err(), "invalid enforcement_mode must fail CHECK constraint");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("CHECK constraint failed"),
            "error must mention CHECK constraint; got: {err_msg}"
        );
    }
}'''

content = content.replace(old_end, new_end)

with open('dlp-server/src/db/repositories/policies.rs', 'w') as f:
    f.write(content)
print("1. policies.rs done")

# ========================================================================
# 2. Fix dlp-server/src/db/mod.rs - add migration
# ========================================================================
with open('dlp-server/src/db/mod.rs', 'r') as f:
    content = f.read()

old_migrations = '''    // Phase 60: scanner_confidence and department columns for labels table.
    run_alter(
        conn,
        "ALTER TABLE labels ADD COLUMN scanner_confidence REAL",
        "scanner_confidence",
        "labels",
    )?;
    run_alter(
        conn,
        "ALTER TABLE labels ADD COLUMN department TEXT",
        "department",
        "labels",
    )?;

    Ok(())
}'''

new_migrations = '''    // Phase 60: scanner_confidence and department columns for labels table.
    run_alter(
        conn,
        "ALTER TABLE labels ADD COLUMN scanner_confidence REAL",
        "scanner_confidence",
        "labels",
    )?;
    run_alter(
        conn,
        "ALTER TABLE labels ADD COLUMN department TEXT",
        "department",
        "labels",
    )?;

    // Phase 55: enforcement_mode column on policies table.
    run_alter(
        conn,
        "ALTER TABLE policies ADD COLUMN enforcement_mode TEXT NOT NULL DEFAULT 'Block' CHECK(enforcement_mode IN ('Audit', 'Block', 'AuditAndBlock'))",
        "enforcement_mode",
        "policies",
    )?;

    // Phase 55: global_enforcement_mode system_kv entry (default PerPolicy).
    conn.execute(
        "INSERT OR IGNORE INTO system_kv (key, value) VALUES ('global_enforcement_mode', 'PerPolicy')",
        [],
    )
    .context("seed global_enforcement_mode system_kv")?;

    Ok(())
}'''

content = content.replace(old_migrations, new_migrations)
with open('dlp-server/src/db/mod.rs', 'w') as f:
    f.write(content)
print("2. db/mod.rs done")

# ========================================================================
# 3. Fix dlp-server/src/policy_store.rs
# ========================================================================
with open('dlp-server/src/policy_store.rs', 'r') as f:
    content = f.read()

# Add EnforcementMode to imports
content = content.replace(
    'use dlp_common::abac::{\n    AbacContext, AppField, Decision, EvaluateResponse, Policy, PolicyCondition, PolicyMode,\n};',
    'use dlp_common::abac::{\n    AbacContext, AppField, Decision, EnforcementMode, EvaluateResponse, Policy, PolicyCondition, PolicyMode,\n};'
)

# Add parse_enforcement_mode helper before deserialize_policy_row
content = content.replace(
    '/// Deserializes a `PolicyRow` into a `Policy`.',
    '''/// Parses an enforcement mode string into the `EnforcementMode` enum.
///
/// Defaults to `Block` for unrecognized values (fail-safe).
fn parse_enforcement_mode(s: &str) -> EnforcementMode {
    match s {
        "Audit" => EnforcementMode::Audit,
        "Block" => EnforcementMode::Block,
        "AuditAndBlock" => EnforcementMode::AuditAndBlock,
        _ => EnforcementMode::Block,
    }
}

/// Deserializes a `PolicyRow` into a `Policy`.'''
)

# Update deserialize_policy_row to include enforcement_mode
content = content.replace(
    '''        enabled: row.enabled != 0,
        mode,
        version: row.version as u64,''',
    '''        enabled: row.enabled != 0,
        mode,
        enforcement_mode: parse_enforcement_mode(&row.enforcement_mode),
        version: row.version as u64,'''
)

# Update EvaluateResponse match to include new fields
content = content.replace(
    '''                return EvaluateResponse {
                    decision: policy.action,
                    matched_policy_id: Some(policy.id.clone()),
                    reason: format!("matched policy '{}'", policy.name),
                };''',
    '''                return EvaluateResponse {
                    decision: policy.action,
                    matched_policy_id: Some(policy.id.clone()),
                    reason: format!("matched policy '{}'", policy.name),
                    enforcement_mode: Some(policy.enforcement_mode),
                    would_have_denied: policy.action.is_denied(),
                };'''
)

# Add enforcement_mode to all Policy struct literals in tests
# Pattern 1: let policy = Policy {
content = re.sub(
    r'let policy = Policy \{\n',
    'let policy = Policy {\n            enforcement_mode: EnforcementMode::Block,\n',
    content
)
# Pattern 2: let p1 = Policy {, let p2 = Policy {
content = re.sub(
    r'let p(\d) = Policy \{\n',
    r'let p\1 = Policy {\n            enforcement_mode: EnforcementMode::Block,\n',
    content
)
# Pattern 3: let disabled = Policy {
content = re.sub(
    r'let disabled = Policy \{\n',
    'let disabled = Policy {\n            enforcement_mode: EnforcementMode::Block,\n',
    content
)
# Pattern 4: let policy_v040 = Policy {
content = re.sub(
    r'let policy_v040 = Policy \{\n',
    'let policy_v040 = Policy {\n            enforcement_mode: EnforcementMode::Block,\n',
    content
)
# Pattern 5: let policy_explicit_all = Policy {
content = re.sub(
    r'let policy_explicit_all = Policy \{\n',
    'let policy_explicit_all = Policy {\n            enforcement_mode: EnforcementMode::Block,\n',
    content
)
# Pattern 6: cache: RwLock::new(vec![Policy {
content = re.sub(
    r'cache: RwLock::new\(vec!\[Policy \{\n',
    'cache: RwLock::new(vec![Policy {\n                enforcement_mode: EnforcementMode::Block,\n',
    content
)
# Pattern 7: helper functions that return Policy {
content = re.sub(
    r'-> Policy \{\n        Policy \{\n',
    '-> Policy {\n        Policy {\n            enforcement_mode: EnforcementMode::Block,\n',
    content
)
# Pattern 8: Policy { at start of line in test code (for make_*_policy helpers)
content = re.sub(
    r'^        Policy \{\n',
    '        Policy {\n            enforcement_mode: EnforcementMode::Block,\n',
    content,
    flags=re.MULTILINE
)

with open('dlp-server/src/policy_store.rs', 'w') as f:
    f.write(content)
print("3. policy_store.rs done")

# ========================================================================
# 4. Fix dlp-server/src/admin_api.rs
# ========================================================================
with open('dlp-server/src/admin_api.rs', 'r') as f:
    content = f.read()

# Add enforcement_mode to PolicyPayload
content = content.replace(
    '''    /// Boolean composition mode for the conditions list.
    #[serde(default)]
    pub mode: PolicyMode,
}''',
    '''    /// Boolean composition mode for the conditions list.
    #[serde(default)]
    pub mode: PolicyMode,
    /// Enforcement mode for this policy.
    #[serde(default = "default_enforcement_mode")]
    pub enforcement_mode: String,
}

fn default_enforcement_mode() -> String {
    "Block".to_string()
}'''
)

# Add enforcement_mode to PolicyResponse
content = content.replace(
    '''    /// Monotonic version number.
    pub version: i64,
    /// ISO 8601 timestamp of last update.
    pub updated_at: String,
}''',
    '''    /// Monotonic version number.
    pub version: i64,
    /// ISO 8601 timestamp of last update.
    pub updated_at: String,
    /// Enforcement mode for this policy.
    #[serde(default = "default_enforcement_mode")]
    pub enforcement_mode: String,
}'''
)

# Fix PolicyRow insert in create_policy handler
content = content.replace(
    '''            mode: mode_str(r.mode).to_string(),
            version: r.version,
            updated_at: r.updated_at.clone(),''',
    '''            mode: mode_str(r.mode).to_string(),
            enforcement_mode: r.enforcement_mode.clone(),
            version: r.version,
            updated_at: r.updated_at.clone(),'''
)

# Fix PolicyUpdateRow in update_policy handler
content = content.replace(
    '''            mode: mode_str(payload_mode),
            updated_at: &now,
            id: &id,''',
    '''            mode: mode_str(payload_mode),
            enforcement_mode: "Block",
            updated_at: &now,
            id: &id,'''
)

# Add enforcement_mode to all PolicyPayload struct literals in tests
content = re.sub(
    r'(let \w+ = )PolicyPayload \{\n',
    r'\1PolicyPayload {\n            enforcement_mode: "Block".to_string(),\n',
    content
)

# Add enforcement_mode to all PolicyResponse struct literals in tests
content = re.sub(
    r'PolicyResponse \{\n',
    'PolicyResponse {\n                enforcement_mode: "Block".to_string(),\n',
    content
)

with open('dlp-server/src/admin_api.rs', 'w') as f:
    f.write(content)
print("4. admin_api.rs done")

# ========================================================================
# 5. Fix dlp-server/src/alert_router.rs
# ========================================================================
with open('dlp-server/src/alert_router.rs', 'r') as f:
    content = f.read()

# Add policy_mode and would_have_denied to AuditEvent struct literals in tests
# Pattern: blocked_disk: None, followed by }; in test code
content = re.sub(
    r'(            blocked_disk: None,\n)(        };)',
    r'\1            policy_mode: None,\n            would_have_denied: false,\n\2',
    content
)

with open('dlp-server/src/alert_router.rs', 'w') as f:
    f.write(content)
print("5. alert_router.rs done")

# ========================================================================
# 6. Fix dlp-server/tests/mode_end_to_end.rs
# ========================================================================
try:
    with open('dlp-server/tests/mode_end_to_end.rs', 'r') as f:
        content = f.read()

    content = re.sub(
        r'(let \w+ = )PolicyPayload \{\n',
        r'\1PolicyPayload {\n        enforcement_mode: "Block".to_string(),\n',
        content
    )
    content = re.sub(
        r'^        PolicyPayload \{\n',
        '        PolicyPayload {\n            enforcement_mode: "Block".to_string(),\n',
        content,
        flags=re.MULTILINE
    )

    with open('dlp-server/tests/mode_end_to_end.rs', 'w') as f:
        f.write(content)
    print("6. mode_end_to_end.rs done")
except FileNotFoundError:
    print("6. mode_end_to_end.rs not found, skipping")

print("\nAll files updated!")
