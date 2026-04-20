---
gsd_wave: 1
depends_on: []
requirements:
  - POLICY-12
files_modified:
  - dlp-common/src/abac.rs
  - dlp-server/src/db/mod.rs
  - dlp-server/src/db/repositories/policies.rs
  - dlp-server/src/admin_api.rs
  - dlp-server/src/policy_store.rs
autonomous: true
---

# Wave 1: Types + DB Schema + Wire Format

## Overview

Wave 1 lays the foundation for Phase 18's server-side work. All tasks are parallel-safe:
no task modifies `evaluate()` logic, no task depends on another's output. Tasks modify
independent files in the dependency order (abac.rs → db/mod.rs → repositories/policies.rs → admin_api.rs → policy_store.rs).

## Task List

### T1: Add `PolicyMode` enum to `dlp-common/src/abac.rs`

**Files to read first:**
- `dlp-common/src/abac.rs` lines 1–268 (existing `Policy` struct + `Decision` enum)

**Action:**
Add the following enum directly before the `Policy` struct definition (around line 249):
```rust
/// The boolean composition mode for a policy's condition list.
///
/// - `ALL`: every condition must match (implicit v0.4.0 behavior).
/// - `ANY`: at least one condition must match.
/// - `NONE`: no condition may match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PolicyMode {
    /// Every condition must match.
    #[default]
    ALL,
    /// At least one condition must match.
    ANY,
    /// No condition may match.
    NONE,
}
```

**Acceptance Criteria:**
- `dlp-common/src/abac.rs` contains `pub enum PolicyMode` with variants `ALL`, `ANY`, `NONE`
- `PolicyMode` derives `Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default`
- `PolicyMode::default()` returns `PolicyMode::ALL` (via `#[default]` on `ALL`)
- `PolicyMode` is placed between the closing `}` of `PolicyCondition` (line ~247) and the `pub struct Policy` line (line 249)
- File compiles with `cargo build -p dlp-common` with no warnings

---

### T2: Add `mode: PolicyMode` field to `Policy` struct in `dlp-common/src/abac.rs`

**Files to read first:**
- `dlp-common/src/abac.rs` lines 249–268 (existing `Policy` struct body)
- `dlp-common/src/abac.rs` lines 48–82 (`Decision` enum — existing model for `#[derive(Default)]` behavior)

**Action:**
In the `Policy` struct at line 251, add `#[serde(default)]` to the struct and add a `mode` field:
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub priority: u32,
    pub conditions: Vec<PolicyCondition>,
    pub action: Decision,
    #[serde(default)]
    pub enabled: bool,
    pub version: u64,
    /// Boolean composition mode for the conditions list.
    #[serde(default)]
    pub mode: PolicyMode,
}
```

Notes:
- `#[serde(default)]` on the struct is already present at line 251 (confirmed from code read).
- Adding `#[serde(default)]` to the struct blanket + individual fields (`enabled`, `mode`) ensures bare JSON blobs deserialize cleanly.
- The existing blanket `#[serde(default)]` on the struct handles all fields. Adding `#[serde(default)]` explicitly to `enabled` and `mode` is harmless and documents intent.

**Acceptance Criteria:**
- `dlp-common/src/abac.rs` `Policy` struct has field `pub mode: PolicyMode` with `#[serde(default)]`
- `Policy` derives `Default` (via `#[derive(Default)]` on struct)
- `Policy::default()` produces `mode: PolicyMode::ALL` (verified by `PolicyMode::default() == ALL`)
- All existing test fixtures in `policy_store.rs` (which use explicit field literals without `mode`) continue to compile without changes
- `cargo build -p dlp-common` succeeds with no warnings

---

### T3: Add `run_migrations()` function to `dlp-server/src/db/mod.rs`

**Files to read first:**
- `dlp-server/src/db/mod.rs` lines 34–52 (`new_pool` function, calls `init_tables`)
- `dlp-server/src/db/mod.rs` lines 59–204 (`init_tables` function, full SQL schema)
- `dlp-server/src/db/mod.rs` lines 206–363 (existing `#[cfg(test)]` module — pattern for future migration tests)

**Action:**
Add `run_migrations(conn: &SqliteConn) -> anyhow::Result<()>` to `dlp-server/src/db/mod.rs` and call it from `new_pool()`:

1. In `new_pool()` (around line 50), after `init_tables(&conn)?`, add:
   ```rust
   run_migrations(&conn)?;
   ```

2. Add the new function **before** `#[cfg(test)]` (around line 205):
   ```rust
   /// Runs forward-only schema migrations on an existing database.
   ///
   /// Idempotent: `ALTER TABLE` statements that fail with "duplicate column name"
   /// are silently swallowed. Any other error propagates.
   ///
   /// # Arguments
   ///
   /// * `conn` — An open SQLite connection (pooled connection from `Pool`).
   ///
   /// # Errors
   ///
   /// Returns `anyhow::Error` if a migration statement fails for a reason
   /// other than the column already existing.
   pub fn run_migrations(conn: &SqliteConn) -> anyhow::Result<()> {
       // Migration 1: add `mode` column to `policies` table (Phase 18).
       // Wrapped in a helper that swallows "duplicate column name" only.
       let result = conn.execute(
           "ALTER TABLE policies ADD COLUMN mode TEXT NOT NULL DEFAULT 'ALL'",
           [],
       );
       if let Err(e) = result {
           let msg = e.to_string();
           // Idempotent: re-running after a prior migration is a no-op.
           if msg.contains("duplicate column name: mode") {
               // Column already exists — nothing to do.
           } else {
               return Err(e).context("running migration: add mode column to policies");
           }
       }
       Ok(())
   }
   ```

**Acceptance Criteria:**
- `dlp-server/src/db/mod.rs` exports `pub fn run_migrations(conn: &SqliteConn) -> anyhow::Result<()>`
- `new_pool()` calls `run_migrations(&conn)?` after `init_tables(&conn)?`
- The function is placed before the `#[cfg(test)]` module
- The `run_migrations()` function is called **after** `init_tables()` in `new_pool()` (column must exist before migration runs)
- `cargo build -p dlp-server` succeeds with no warnings

---

### T4: Add `mode TEXT NOT NULL DEFAULT 'ALL'` to fresh-install `policies` table in `init_tables()`

**Files to read first:**
- `dlp-server/src/db/mod.rs` lines 121–131 (existing `CREATE TABLE IF NOT EXISTS policies`)

**Action:**
In the `CREATE TABLE IF NOT EXISTS policies` block at line 121, update the final column `updated_at TEXT NOT NULL` line to add the `mode` column as the final column:

Change:
```sql
CREATE TABLE IF NOT EXISTS policies (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT,
    priority    INTEGER NOT NULL,
    conditions  TEXT NOT NULL,
    action      TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    version     INTEGER NOT NULL DEFAULT 1,
    updated_at  TEXT NOT NULL
)
```

To:
```sql
CREATE TABLE IF NOT EXISTS policies (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT,
    priority    INTEGER NOT NULL,
    conditions  TEXT NOT NULL,
    action      TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    version     INTEGER NOT NULL DEFAULT 1,
    updated_at  TEXT NOT NULL,
    mode        TEXT NOT NULL DEFAULT 'ALL'
)
```

**Acceptance Criteria:**
- `init_tables()` SQL for `policies` table includes `mode TEXT NOT NULL DEFAULT 'ALL'` as the final column
- Fresh install of the DB creates the `mode` column with the correct constraint
- `cargo build -p dlp-server` succeeds with no warnings

---

### T5: Extend `PolicyRow` and `PolicyUpdateRow` structs in `dlp-server/src/db/repositories/policies.rs`

**Files to read first:**
- `dlp-server/src/db/repositories/policies.rs` lines 9–55 (`PolicyRow` and `PolicyUpdateRow` struct definitions)
- `dlp-server/src/db/repositories/policies.rs` lines 70–158 (SQL statements for `list`, `insert`, `get_by_id`)

**Action:**
1. Add `pub mode: String` to `PolicyRow` struct (after `updated_at`):
   ```rust
   pub struct PolicyRow {
       // ... existing fields ...
       pub updated_at: String,
       /// The boolean mode string stored in the DB (always "ALL", "ANY", or "NONE").
       pub mode: String,
   }
   ```

2. Add `pub mode: &'a str` to `PolicyUpdateRow` struct (after `updated_at`):
   ```rust
   pub struct PolicyUpdateRow<'a> {
       // ... existing fields ...
       pub updated_at: &'a str,
       /// The new boolean mode.
       pub mode: &'a str,
       pub id: &'a str,
   }
   ```

3. Extend all SQL statements that read/write `policies` to include `mode`:
   - **`list()` SELECT** (line 75): Add `mode` as the 10th column
     ```sql
     SELECT id, name, description, priority, conditions, action, \
            enabled, version, updated_at, mode \
     FROM policies ORDER BY priority ASC
     ```
   - **`insert()` column list + params** (line 107): Add `mode` as the 10th column and parameter
     ```sql
     INSERT INTO policies (id, name, description, priority, conditions, \
              action, enabled, version, updated_at, mode) \
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
     ```
   - **`get_by_id()` SELECT** (line 140): Add `mode` as the 10th column
     ```sql
     SELECT id, name, description, priority, conditions, action, \
            enabled, version, updated_at, mode \
     FROM policies WHERE id = ?1
     ```
   - **`update()` SET + params** (line 178): Add `mode = ?9` in SET clause, add `row.mode` as the 9th param
     ```sql
     UPDATE policies SET \
         name = ?1, description = ?2, priority = ?3, \
         conditions = ?4, action = ?5, enabled = ?6, \
         version = version + 1, updated_at = ?7, mode = ?8 \
     WHERE id = ?9
     ```
     Note: adjust positional parameter count — the UPDATE currently has 8 params (?1..?8), adding `mode` and `id` for the WHERE clause means ?8 for mode and ?9 for id.

4. Update all `.query_map` / `query_row` / `execute` closures to read/set the `mode` field as the 10th value (index 9 for zero-indexed row.get):

   For `list` and `get_by_id` row closures — after `updated_at: row.get(8)?` add:
   ```rust
   updated_at: row.get(8)?,
   mode: row.get(9)?,
   ```

   For `insert` params — add `record.mode` as the 10th param after `record.updated_at`.

   For `update` params — add `row.mode` and adjust WHERE `row.id` to the new last param position.

**Acceptance Criteria:**
- `PolicyRow` struct has field `pub mode: String`
- `PolicyUpdateRow` struct has field `pub mode: &'a str`
- `list()` SQL query selects `mode` column as the 10th column (index 9)
- `insert()` SQL inserts `mode` as the 10th column and binds `record.mode` as the 10th param
- `get_by_id()` SQL selects `mode` as the 10th column (index 9)
- `update()` SQL SET clause includes `mode = ?N` and `row.mode` is bound as the correct param
- All `PolicyRow` closures read `mode` from index 9
- `cargo build -p dlp-server` succeeds with no warnings

---

### T6: Add `mode: PolicyMode` field to `PolicyPayload` and `PolicyResponse` in `dlp-server/src/admin_api.rs`

**Files to read first:**
- `dlp-server/src/admin_api.rs` lines 97–135 (`PolicyPayload` and `PolicyResponse` struct definitions)

**Action:**
1. Add `use dlp_common::abac::PolicyMode;` to the imports section (around line 33, after the existing `dlp_common::abac` import line).

2. Add `mode` field to `PolicyPayload`:
   ```rust
   /// Whether the policy is enabled.
   pub enabled: bool,
   /// Boolean composition mode for the condition list.
   #[serde(default)]
   pub mode: PolicyMode,
   ```

3. Add `mode` field to `PolicyResponse`:
   ```rust
   /// ISO 8601 timestamp of last update.
   pub updated_at: String,
   /// Boolean composition mode for the condition list.
   #[serde(default)]
   pub mode: PolicyMode,
   ```

**Acceptance Criteria:**
- `PolicyPayload` has field `pub mode: PolicyMode` with `#[serde(default)]`
- `PolicyResponse` has field `pub mode: PolicyMode` with `#[serde(default)]`
- `PolicyPayload` deserialization from JSON without a `mode` key produces `mode = PolicyMode::ALL` (verifiable via unit test)
- `cargo build -p dlp-server` succeeds with no warnings

---

### T7: Wire `mode` through `create_policy` and `update_policy` handlers in `dlp-server/src/admin_api.rs`

**Files to read first:**
- `dlp-server/src/admin_api.rs` lines 568–648 (`create_policy` function — full body)
- `dlp-server/src/admin_api.rs` lines 650–757 (`update_policy` function — full body)
- `dlp-server/src/db/repositories/policies.rs` lines 95–123 (insert method, column list + params)

**Action:**

**In `create_policy` (lines 584–648):**

The `PolicyResponse` construction at lines 584–594 adds `mode: payload.mode`:
```rust
let resp = PolicyResponse {
    id: payload.id.clone(),
    name: payload.name.clone(),
    description: payload.description.clone(),
    priority: payload.priority,
    conditions: payload.conditions.clone(),
    action: payload.action.clone(),
    enabled: payload.enabled,
    version: 1,
    updated_at: now.clone(),
    mode: payload.mode,  // NEW
};
```

The `PolicyRow` record built inside `spawn_blocking` at lines 602–612 adds `mode`:
```rust
let record = repositories::PolicyRow {
    id: r.id.clone(),
    name: r.name.clone(),
    description: r.description.clone(),
    priority: i64::from(r.priority),
    conditions: conditions_json.clone(),
    action: r.action.clone(),
    enabled: if r.enabled { 1 } else { 0 },
    version: r.version,
    updated_at: r.updated_at.clone(),
    mode: r.mode.as_str(),  // NEW — r.mode is PolicyMode, .as_str() helper added in T8
};
```

For the `mode` value in the DB row, a `fn mode_str(m: PolicyMode) -> &'static str` helper is added (see T8 action). Pass `mode_str(r.mode)` to `PolicyRow.mode`.

**In `update_policy` (lines 689–757):**

Clone `payload.mode` inside the spawn context (add to the clone block around line 687):
```rust
let payload_mode = payload.mode;  // PolicyMode is Copy — cheap clone
```

In the `PolicyUpdateRow` construction (lines 693–702):
```rust
let row = repositories::PolicyUpdateRow {
    name: &payload_name,
    description: payload_desc.as_deref(),
    priority: payload_priority,
    conditions: &conditions_json,
    action: &payload_action,
    enabled: payload_enabled,
    updated_at: &now,
    mode: mode_str(payload_mode),  // NEW
    id: &id,
};
```

In the `PolicyResponse` construction returned from `spawn_blocking` (lines 713–723):
```rust
Ok(PolicyResponse {
    id,
    name: payload_name,
    description: payload_desc,
    priority: u32::try_from(payload_priority).unwrap_or(payload_priority as u32),
    conditions: payload_conditions,
    action: payload_action,
    enabled: payload_enabled != 0,
    version,
    updated_at: now,
    mode: payload_mode,  // NEW
})
```

**Acceptance Criteria:**
- `create_policy` sets `mode: mode_str(payload.mode)` on the `PolicyRow` passed to `insert()`
- `create_policy` sets `mode: payload.mode` on the `PolicyResponse` returned
- `update_policy` sets `mode: mode_str(payload_mode)` on the `PolicyUpdateRow` passed to `update()`
- `update_policy` sets `mode: payload_mode` on the `PolicyResponse` returned
- Both handlers compile with no warnings

---

### T8: Add `mode_str()` helper function and `mode` parsing in `deserialize_policy_row` in `dlp-server/src/policy_store.rs`

**Files to read first:**
- `dlp-server/src/policy_store.rs` lines 153–178 (`deserialize_policy_row` function)
- `dlp-server/src/policy_store.rs` lines 1–22 (imports)
- `dlp-common/src/abac.rs` lines 249–268 (`Policy` struct — where `PolicyMode` now lives)

**Action:**

1. Add `PolicyMode` to the `use dlp_common::abac` import line (line 14):
   ```rust
   use dlp_common::abac::{Decision, EvaluateRequest, EvaluateResponse, Policy, PolicyCondition, PolicyMode};
   ```

2. Add a `mode_str()` free function before `deserialize_policy_row`:
   ```rust
   /// Converts a `PolicyMode` to its wire/DB string representation.
   ///
   /// Used exclusively for serializing `mode` to the SQLite column.
   const fn mode_str(mode: PolicyMode) -> &'static str {
       match mode {
           PolicyMode::ALL => "ALL",
           PolicyMode::ANY => "ANY",
           PolicyMode::NONE => "NONE",
       }
   }
   ```

3. Update `PolicyRow` field in `load_from_db` closure (add `mode: row.get(9)?` after `updated_at: row.get(8)?`).

4. Update `deserialize_policy_row` to parse the `mode` column:

   In the function signature, the first parameter type is:
   ```rust
   row: &crate::db::repositories::policies::PolicyRow,
   ```

   After parsing conditions and action (around line 168), add mode parsing and include `mode` in the returned `Policy`:
   ```rust
   let mode = match row.mode.as_str() {
       "ALL" => PolicyMode::ALL,
       "ANY" => PolicyMode::ANY,
       "NONE" => PolicyMode::NONE,
       other => {
           return Err(serde_json::Error::custom(format!(
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
       version: row.version as u64,
       mode,  // NEW
   })
   ```

**Acceptance Criteria:**
- `mode_str()` is a `const fn` with the three match arms returning `"ALL"`, `"ANY"`, `"NONE"`
- `deserialize_policy_row` returns `Policy` with `mode` field set from `row.mode` parsed via the match
- Unknown mode strings cause `serde_json::Error` (caught by the existing `skipped policy` warn-log path in `load_from_db`)
- `PolicyRow` closures in `policies.rs` read `mode` from index 9 (already done in T5)
- `cargo build -p dlp-server` succeeds with no warnings

---

## Verification

After Wave 1 completes, run:
```bash
cargo build --all
cargo test --lib --all
```

All builds must pass. The `mode` field should be visible in `PolicyPayload`/`PolicyResponse` JSON round-trips and persist through create/update cycles. The evaluator hot path (`evaluate()`) is unchanged — it still uses `.all()` — but is ready for the Wave 2 switch-on-mode change.

## Dependencies

- T1 → T2 (PolicyMode must exist before Policy can use it)
- T3 + T4 are independent (T3 adds `run_migrations`, T4 modifies `init_tables`)
- T5 depends on T3 (policies table must exist before repository SQL extends it) — but in practice T3/T4 run in parallel since both modify `db/mod.rs`
- T6 depends on T1 (PolicyMode must be importable)
- T7 depends on T5 (PolicyRow/PolicyUpdateRow must have `mode` field), T6 (PolicyPayload must have `mode` field), and T8 (mode_str() helper must exist)
- T8 depends on T1 + T5 (PolicyMode must exist; PolicyRow must have `mode: String`)

Wave 1 parallel groups: {T1, T2} → {T3, T4, T5} → {T6} → {T8} → {T7}
