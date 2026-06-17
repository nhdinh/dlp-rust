# Phase 18: Boolean Mode Engine + Wire Format - Pattern Map

**Mapped:** 2026-06-17
**Files analyzed:** 7
**Analogs found:** 7 / 7

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `dlp-common/src/abac.rs` - `PolicyMode` enum | model | transform | `dlp-common/src/abac.rs` - `Decision` enum (lines 170-184) | exact |
| `dlp-common/src/abac.rs` - `Policy` struct (add `mode` + `Default`) | model | transform | `dlp-common/src/abac.rs` - `Policy` struct (lines 684-708) | exact |
| `dlp-server/src/db/mod.rs` - `init_tables` policies schema | config | CRUD | `dlp-server/src/db/mod.rs` - existing `init_tables` (lines 73-540) | exact |
| `dlp-server/src/db/mod.rs` - `run_migrations` | migration | batch | `dlp-server/src/db/mod.rs` - existing `run_migrations` (lines 542-900) | exact |
| `dlp-server/src/db/repositories/policies.rs` - `PolicyRow`/`PolicyUpdateRow` | model | CRUD | `dlp-server/src/db/repositories/policies.rs` - existing rows (lines 9-63) | exact |
| `dlp-server/src/policy_store.rs` - `evaluate` mode switch | service | request-response | `dlp-server/src/policy_store.rs` - existing `evaluate` (lines 264-338) | exact |
| `dlp-server/src/policy_store.rs` - `deserialize_policy_row` | service | transform | `dlp-server/src/policy_store.rs` - existing (lines 387-420) | exact |
| `dlp-server/src/admin_api.rs` - `PolicyPayload`/`PolicyResponse` | model | request-response | `dlp-server/src/admin_api.rs` - existing types (lines 140-192) | exact |
| `dlp-server/src/admin_api.rs` - `create_policy`/`update_policy` handlers | controller | request-response | `dlp-server/src/admin_api.rs` - existing handlers (lines 1391-1614) | exact |
| `dlp-server/src/policy_store.rs` - mode evaluator tests | test | request-response | `dlp-server/src/policy_store.rs` - existing tests (lines 707-1190+) | exact |
| `dlp-server/src/db/mod.rs` - migration test | test | batch | `dlp-server/src/db/mod.rs` - existing tests (lines 902-1100+) | exact |

## Pattern Assignments

### `dlp-common/src/abac.rs` - `PolicyMode` enum (model, transform)

**Analog:** `dlp-common/src/abac.rs` - `Decision` enum (lines 170-184)

**Enum pattern** (lines 170-184):
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Decision {
    /// Permit the operation without additional logging.
    #[default]
    ALLOW,
    /// Block the operation and log the event.
    DENY,
    /// Permit the operation but emit an audit event.
    #[serde(rename = "ALLOW_WITH_LOG")]
    AllowWithLog,
    /// Block the operation, log the event, and trigger an immediate SIEM/admin alert.
    #[serde(rename = "DENY_WITH_ALERT")]
    DenyWithAlert,
}
```

**Key pattern for `PolicyMode`:**
- SCREAMING variant names (`ALL`, `ANY`, `NONE`) serialize naturally without `#[serde(rename_all)]`
- Derives: `Debug`, `Clone`, `Copy`, `PartialEq`, `Eq`, `Serialize`, `Deserialize`, `Default`
- `#[default]` on `ALL` variant for backward compatibility
- `Copy` because unit variants are cheap (1 byte on stack)

---

### `dlp-common/src/abac.rs` - `Policy` struct with `Default` (model, transform)

**Analog:** `dlp-common/src/abac.rs` - `Subject`/`Resource`/`Environment` structs (lines 237-278)

**Default derive pattern** (lines 237-278):
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Subject {
    pub user_sid: String,
    pub user_name: String,
    pub groups: Vec<String>,
    #[serde(default)]
    pub device_trust: DeviceTrust,
    #[serde(default)]
    pub network_location: NetworkLocation,
    #[serde(default)]
    pub device_health: DeviceHealthStatus,
}
```

**Key pattern for `Policy`:**
- Add `#[derive(Default)]` to `Policy` struct
- Add `#[serde(default)]` on new `mode: PolicyMode` field
- All fields get sensible defaults: `id`/`name = String::new()`, `description = None`, `priority = 0`, `conditions = vec![]`, `action = Decision::ALLOW`, `enabled = false`, `version = 0`, `mode = PolicyMode::ALL`
- Tests use `Policy { mode: PolicyMode::ANY, conditions: vec![...], ..Default::default() }` spread syntax

---

### `dlp-server/src/db/mod.rs` - `init_tables` policies schema (config, CRUD)

**Analog:** `dlp-server/src/db/mod.rs` - existing `init_tables` policies CREATE TABLE (lines 146-157)

**Schema pattern** (lines 146-157):
```sql
CREATE TABLE IF NOT EXISTS policies (
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
```

**Key pattern:**
- `mode TEXT NOT NULL DEFAULT 'ALL'` is already present in current `init_tables` (Phase 18 was partially implemented)
- Fresh installs get full schema in one shot via `CREATE TABLE IF NOT EXISTS`

---

### `dlp-server/src/db/mod.rs` - `run_migrations` (migration, batch)

**Analog:** `dlp-server/src/db/mod.rs` - existing `run_migrations` + `run_alter` helper (lines 542-900)

**Migration pattern** (lines 542-900):
```rust
/// Runs database migrations for existing installations.
///
/// Each migration is idempotent — safe to call on every startup. Duplicate-column
/// errors from `ALTER TABLE` are swallowed; all other errors are propagated.
pub fn run_migrations(conn: &SqliteConn) -> anyhow::Result<()> {
    run_alter(
        conn,
        "ALTER TABLE policies ADD COLUMN mode TEXT NOT NULL DEFAULT 'ALL'",
        "mode",
        "policies",
    )?;
    // ... more migrations ...
    Ok(())
}

/// Executes a single `ALTER TABLE` statement, ignoring duplicate-column errors.
fn run_alter(conn: &SqliteConn, sql: &str, column: &str, table: &str) -> anyhow::Result<()> {
    match conn.execute(sql, []) {
        Ok(_) => Ok(()),
        Err(e)
            if e.to_string()
                .contains(&format!("duplicate column name: {column}")) =>
        {
            Ok(())
        }
        Err(e) => Err(e).context(format!("running migration: add {column} column to {table}")),
    }
}
```

**Key pattern:**
- `run_migrations()` is called by `new_pool()` after `init_tables()` (line 64)
- Each migration is a `run_alter()` call that swallows only "duplicate column name" errors
- `run_alter` matches on `e.to_string().contains(&format!("duplicate column name: {column}"))`
- Any other error bubbles up as `anyhow::Error` with context
- The `mode` migration already exists in current codebase (line 547-552)

---

### `dlp-server/src/db/repositories/policies.rs` - `PolicyRow`/`PolicyUpdateRow` (model, CRUD)

**Analog:** `dlp-server/src/db/repositories/policies.rs` - existing row types (lines 9-63)

**Row type pattern** (lines 9-63):
```rust
/// Plain data row returned by policy reads.
#[derive(Debug, Clone)]
pub struct PolicyRow {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub priority: i64,
    pub conditions: String,
    pub action: String,
    pub enabled: i64,
    pub mode: String,
    pub enforcement_mode: String,
    pub version: i64,
    pub updated_at: String,
}

/// Row type for policy update operations.
#[derive(Debug, Clone)]
pub struct PolicyUpdateRow<'a> {
    pub name: &'a str,
    pub description: Option<&'a str>,
    pub priority: i64,
    pub conditions: &'a str,
    pub action: &'a str,
    pub enabled: i64,
    pub mode: &'a str,
    pub enforcement_mode: &'a str,
    pub updated_at: &'a str,
    pub id: &'a str,
}
```

**SQL SELECT pattern** (lines 82-86):
```rust
let mut stmt = conn.prepare(
    "SELECT id, name, description, priority, conditions, action, \
     enabled, mode, enforcement_mode, version, updated_at \
     FROM policies ORDER BY priority ASC",
)?;
```

**SQL INSERT pattern** (lines 116-133):
```rust
uow.tx.execute(
    "INSERT INTO policies (id, name, description, priority, conditions, \
     action, enabled, mode, enforcement_mode, version, updated_at) \
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
    params![
        record.id, record.name, record.description, record.priority,
        record.conditions, record.action, record.enabled, record.mode,
        record.enforcement_mode, record.version, record.updated_at,
    ],
)?;
```

**SQL UPDATE pattern** (lines 191-209):
```rust
uow.tx.execute(
    "UPDATE policies SET \
            name = ?1, description = ?2, priority = ?3, \
            conditions = ?4, action = ?5, enabled = ?6, \
            mode = ?7, enforcement_mode = ?8, version = version + 1, updated_at = ?9 \
     WHERE id = ?10",
    params![
        row.name, row.description, row.priority, row.conditions,
        row.action, row.enabled, row.mode, row.enforcement_mode,
        row.updated_at, row.id,
    ],
)
```

**Key pattern:**
- Both `PolicyRow` and `PolicyUpdateRow` already have `mode: String` / `mode: &'a str` fields
- All SQL statements already include `mode` in column lists
- The repository is already fully wired for Phase 18

---

### `dlp-server/src/policy_store.rs` - `evaluate` mode switch (service, request-response)

**Analog:** `dlp-server/src/policy_store.rs` - existing `evaluate` (lines 264-338)

**Evaluator mode switch pattern** (lines 264-338):
```rust
let conditions_match = match policy.mode {
    PolicyMode::ALL => policy
        .conditions
        .iter()
        .all(|c| condition_matches(c, ctx, &resource)),
    PolicyMode::ANY => policy
        .conditions
        .iter()
        .any(|c| condition_matches(c, ctx, &resource)),
    PolicyMode::NONE => !policy
        .conditions
        .iter()
        .any(|c| condition_matches(c, ctx, &resource)),
};
if conditions_match {
    let effective_mode = compute_effective_mode(global_mode, policy.enforcement_mode);
    // ... return EvaluateResponse ...
}
```

**Key pattern:**
- The mode switch is ALREADY implemented in current `evaluate()` (lines 271-284)
- `policy.mode` is `Copy` so matching copies the value out of the `&Policy` borrow
- Read lock scope is unchanged — entire `evaluate()` body holds the lock
- Empty-conditions behavior is natural iterator semantics:
  - `ALL + []` → `true` (vacuously all match)
  - `ANY + []` → `false` (no condition matches)
  - `NONE + []` → `true` (no condition matches, so negation is true)

---

### `dlp-server/src/policy_store.rs` - `deserialize_policy_row` (service, transform)

**Analog:** `dlp-server/src/policy_store.rs` - existing `deserialize_policy_row` (lines 387-420)

**Deserialization pattern** (lines 387-420):
```rust
fn deserialize_policy_row(
    row: &crate::db::repositories::policies::PolicyRow,
) -> Result<Policy, serde_json::Error> {
    let conditions: Vec<PolicyCondition> = serde_json::from_str(&row.conditions)?;
    let action = match row.action.to_lowercase().as_str() {
        "allow" => Decision::ALLOW,
        "deny" => Decision::DENY,
        "allow_with_log" | "allowwithlog" => Decision::AllowWithLog,
        "deny_with_alert" | "denywithalert" => Decision::DenyWithAlert,
        _ => Decision::DENY,
    };
    let mode = match row.mode.as_str() {
        "ALL" => PolicyMode::ALL,
        "ANY" => PolicyMode::ANY,
        "NONE" => PolicyMode::NONE,
        other => {
            return Err(serde::de::Error::custom(format!(
                "invalid policy mode: {other}"
            )));
        }
    };
    Ok(Policy {
        id: row.id.clone(),
        name: row.name.clone(),
        description: row.description.clone(),
        priority: row.priority as u32,
        conditions,
        action,
        enabled: row.enabled != 0,
        mode,
        enforcement_mode: parse_enforcement_mode(&row.enforcement_mode),
        version: row.version as u64,
    })
}
```

**Key pattern:**
- `mode` parsing already implemented (lines 398-407)
- Invalid mode returns `serde_json::Error` via `serde::de::Error::custom()`
- Caller (`load_from_db`) catches the error and logs warn (line 357):
  ```rust
  warn!(policy_id = %row.id, error = %e, "skipped policy with malformed conditions or mode");
  ```

---

### `dlp-server/src/admin_api.rs` - `PolicyPayload`/`PolicyResponse` (model, request-response)

**Analog:** `dlp-server/src/admin_api.rs` - existing types (lines 140-192)

**Wire type pattern** (lines 140-192):
```rust
/// Payload for creating or updating a policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPayload {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub priority: u32,
    pub conditions: serde_json::Value,
    pub action: String,
    pub enabled: bool,
    #[serde(default)]
    pub mode: PolicyMode,
    #[serde(default)]
    pub enforcement_mode: EnforcementMode,
}

/// Policy record returned by the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub priority: u32,
    pub conditions: serde_json::Value,
    pub action: String,
    pub enabled: bool,
    #[serde(default)]
    pub mode: PolicyMode,
    #[serde(default)]
    pub enforcement_mode: EnforcementMode,
    pub version: i64,
    pub updated_at: String,
}
```

**Mode string helper** (lines 51-59):
```rust
/// Parses a `PolicyMode` from its DB string representation.
fn mode_from_str(s: &str) -> PolicyMode {
    match s {
        "ALL" => PolicyMode::ALL,
        "ANY" => PolicyMode::ANY,
        "NONE" => PolicyMode::NONE,
        _ => PolicyMode::ALL,
    }
}
```

**Key pattern:**
- Both `PolicyPayload` and `PolicyResponse` already have `mode: PolicyMode` with `#[serde(default)]`
- `mode_from_str` helper already exists for DB-to-enum conversion in handlers
- `mode_str()` helper in `policy_store.rs` (lines 31-37) converts enum to DB string:
  ```rust
  pub(crate) const fn mode_str(mode: PolicyMode) -> &'static str {
      match mode {
          PolicyMode::ALL => "ALL",
          PolicyMode::ANY => "ANY",
          PolicyMode::NONE => "NONE",
      }
  }
  ```

---

### `dlp-server/src/admin_api.rs` - `create_policy`/`update_policy` handlers (controller, request-response)

**Analog:** `dlp-server/src/admin_api.rs` - existing handlers (lines 1391-1614)

**Create handler pattern** (lines 1391-1487):
```rust
async fn create_policy(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<(StatusCode, Json<PolicyResponse>), AppError> {
    // ... auth extraction ...
    let payload: Json<PolicyPayload> = Json::from_request(req, &state)
        .await
        .map_err(AppError::from)?;
    // ... validation ...
    let resp = PolicyResponse {
        id: payload.id.clone(),
        name: payload.name.clone(),
        description: payload.description.clone(),
        priority: payload.priority,
        conditions: payload.conditions.clone(),
        action: payload.action.clone(),
        enabled: payload.enabled,
        mode: payload.mode,
        enforcement_mode: payload.enforcement_mode,
        version: 1,
        updated_at: now.clone(),
    };
    // ... spawn_blocking with PolicyRow { mode: mode_str(r.mode).to_string(), ... } ...
    state.policy_store.invalidate();
    // ... audit event ...
    Ok((StatusCode::CREATED, Json(resp)))
}
```

**Update handler pattern** (lines 1489-1614):
```rust
async fn update_policy(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<Json<PolicyResponse>, AppError> {
    // ... auth + path extraction ...
    let payload: Json<PolicyPayload> = Json::from_request(req, &state)
        .await
        .map_err(AppError::from)?;
    let payload_mode = payload.mode;
    // ... spawn_blocking with PolicyUpdateRow { mode: mode_str(payload_mode), ... } ...
    state.policy_store.invalidate();
    // ... audit event ...
    Ok(Json(resp))
}
```

**Key pattern:**
- Both handlers already wire `mode` through from payload to DB row to response
- `mode_str()` from `policy_store.rs` is used for DB writes (re-exported via `crate::policy_store::mode_str`)
- `mode_from_str()` is used for DB reads in `list_policies` and `get_policy`
- Cache invalidation happens after successful DB commit

---

### `dlp-server/src/policy_store.rs` - evaluator tests (test, request-response)

**Analog:** `dlp-server/src/policy_store.rs` - existing test fixtures (lines 786-1190)

**Test fixture pattern** (lines 786-811):
```rust
#[test]
fn test_disabled_policy_skipped() {
    let disabled = Policy {
        enforcement_mode: EnforcementMode::Block,
        id: "p1".to_string(),
        name: "disabled policy".to_string(),
        description: None,
        priority: 1,
        conditions: vec![PolicyCondition::Classification {
            op: "eq".to_string(),
            value: Classification::T3,
        }],
        action: Decision::DENY,
        enabled: false,
        mode: PolicyMode::ALL,
        version: 1,
    };
    let store = PolicyStore {
        cache: RwLock::new(vec![disabled]),
        pool: Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool")),
        global_mode: RwLock::new(EnforcementMode::PerPolicy),
    };
    let resp = store.evaluate(&make_request(Classification::T3), None, false);
    assert_eq!(resp.decision, Decision::DENY);
}
```

**Key pattern for new mode tests:**
- Use `..Default::default()` spread for concise fixtures:
  ```rust
  Policy {
      mode: PolicyMode::ANY,
      conditions: vec![...],
      ..Default::default()
  }
  ```
- Existing 15+ fixtures use explicit struct literals and are NOT retrofitted
- `empty_store()` helper builds a store with empty cache (lines 749-756)
- `make_request(classification)` helper builds minimal `AbacContext` (lines 719-746)

---

### `dlp-server/src/db/mod.rs` - migration test (test, batch)

**Analog:** `dlp-server/src/db/mod.rs` - existing tests (lines 902-1100) + `tempfile::NamedTempFile` pattern

**Test pattern** (lines 907-951):
```rust
#[test]
fn test_new_pool_in_memory() {
    let pool = new_pool(":memory:");
    assert!(pool.is_ok(), "should create pool for in-memory database");
}

#[test]
fn test_tables_created() {
    let pool = new_pool(":memory:").expect("create pool");
    let conn = pool.get().expect("acquire connection");
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .expect("prepare")
        .query_map([], |row| row.get(0))
        .expect("query")
        .filter_map(|r| r.ok())
        .collect();
    assert!(tables.contains(&"policies".to_string()));
}
```

**PRAGMA table_info pattern** (from `test_device_registry_columns`, lines 1084-1094):
```rust
let columns: Vec<String> = conn
    .prepare("PRAGMA table_info(device_registry)")
    .expect("prepare pragma")
    .query_map([], |row| row.get::<_, String>(1))
    .expect("query pragma")
    .filter_map(Result::ok)
    .collect();
```

**Key pattern for migration test:**
- Use `tempfile::NamedTempFile` (not `:memory:`) for persistence across connections
- Manually create v0.4.0 schema (no `mode` column), insert row, close connection
- Re-open pool on same file, call `run_migrations()`, assert `mode` column exists via `PRAGMA table_info(policies)`
- Assert pre-existing row has `mode = 'ALL'` via SELECT
- Call `run_migrations()` again — must not error (idempotency)

---

## Shared Patterns

### Serde Default for Backward Compatibility
**Source:** `dlp-common/src/abac.rs` - `Policy` struct `#[serde(default)]`
**Apply to:** `PolicyPayload.mode`, `PolicyResponse.mode`, `Policy.mode`
```rust
#[serde(default)]
pub mode: PolicyMode,
```
- When JSON omits `mode`, `PolicyMode::default()` (which is `ALL`) is used
- Satisfies POLICY-12 backward compatibility contract with one annotation

### Mode String Conversion
**Source:** `dlp-server/src/policy_store.rs` - `mode_str()` (lines 31-37)
**Apply to:** All DB write paths (create, update handlers)
```rust
pub(crate) const fn mode_str(mode: PolicyMode) -> &'static str {
    match mode {
        PolicyMode::ALL => "ALL",
        PolicyMode::ANY => "ANY",
        PolicyMode::NONE => "NONE",
    }
}
```

### Mode String Parsing (DB read)
**Source:** `dlp-server/src/admin_api.rs` - `mode_from_str()` (lines 51-59)
**Apply to:** All DB read paths (list, get handlers)
```rust
fn mode_from_str(s: &str) -> PolicyMode {
    match s {
        "ALL" => PolicyMode::ALL,
        "ANY" => PolicyMode::ANY,
        "NONE" => PolicyMode::NONE,
        _ => PolicyMode::ALL,
    }
}
```

### Cache Invalidation After Mutation
**Source:** `dlp-server/src/admin_api.rs` - `create_policy`/`update_policy`/`delete_policy`
**Apply to:** All policy mutation handlers
```rust
state.policy_store.invalidate();
```
- Called after every successful DB commit
- Evaluator reads new mode on next request

### Skip-on-Malformed Error Handling
**Source:** `dlp-server/src/policy_store.rs` - `load_from_db` (lines 347-364)
**Apply to:** `deserialize_policy_row` extended mode parsing
```rust
for row in rows {
    match deserialize_policy_row(&row) {
        Ok(p) => policies.push(p),
        Err(e) => {
            warn!(policy_id = %row.id, error = %e, "skipped policy with malformed conditions or mode");
        }
    }
}
```

### Spawn Blocking for DB Operations
**Source:** `dlp-server/src/admin_api.rs` - all policy handlers
**Apply to:** create, update handlers
```rust
tokio::task::spawn_blocking(move || -> Result<_, AppError> {
    let mut conn = pool.get().map_err(AppError::from)?;
    let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
    // ... DB operations ...
    uow.commit().map_err(AppError::Database)?;
    Ok(result)
})
.await
.map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;
```

## No Analog Found

No files with no close match — all Phase 18 files have exact analogs in the codebase. The Phase 18 implementation is largely already present in the current codebase; the remaining work is primarily adding unit tests for the three evaluator modes and the migration path.

## Metadata

**Analog search scope:** `dlp-common/src/abac.rs`, `dlp-server/src/admin_api.rs`, `dlp-server/src/policy_store.rs`, `dlp-server/src/db/mod.rs`, `dlp-server/src/db/repositories/policies.rs`
**Files scanned:** 5
**Pattern extraction date:** 2026-06-17

**Note:** The current codebase already contains most of the Phase 18 implementation:
- `PolicyMode` enum exists in `dlp-common/src/abac.rs` (lines 667-681)
- `Policy` struct already has `mode` field + `Default` derive (lines 684-708)
- `init_tables` already has `mode` column in policies schema (line 154)
- `run_migrations` already has the `mode` ALTER TABLE (lines 547-552)
- `PolicyRow`/`PolicyUpdateRow` already have `mode` fields
- `evaluate()` already has the mode switch (lines 271-284)
- `deserialize_policy_row` already parses `mode` (lines 398-407)
- `PolicyPayload`/`PolicyResponse` already have `mode` with `#[serde(default)]`
- `create_policy`/`update_policy` already wire `mode` through

**Remaining work:** Unit tests for:
1. Three mode evaluator behavior (ALL/ANY/NONE)
2. Empty-conditions edge cases for each mode
3. Wire format serde default tests (legacy payload parity)
4. Migration test (v0.4.0 schema → add column → backfill → idempotency)
