# Phase 18: Boolean Mode Engine + Wire Format — Research

**Research date:** 2026-04-20
**Status:** Complete — ready to plan

---

## 1. SQLite ALTER TABLE ADD COLUMN Behavior

### 1.1 Adding NOT NULL + DEFAULT to a populated table

SQLite has supported `ALTER TABLE ADD COLUMN` with both `NOT NULL` and `DEFAULT` since version 3.1.0 (2005). When such a column is added to a table that already has rows, SQLite atomically applies the default value to every existing row as part of the `ALTER TABLE` statement — no `UPDATE` required. This is confirmed by SQLite's own documentation and the behavior of `CREATE TABLE IF NOT EXISTS` + subsequent `ALTER TABLE` migration path.

The `run_migrations()` pattern (D-07 of 18-CONTEXT.md) is therefore safe for pre-existing v0.4.0 databases with policies: `ALTER TABLE policies ADD COLUMN mode TEXT NOT NULL DEFAULT 'ALL'` will backfill `'ALL'` into every existing row automatically.

### 1.2 Detecting and swallowing "duplicate column name" in rusqlite

`rusqlite::Error` wraps SQLite errors via `rusqlite::Error::SqliteFailure(ru, msg)`. The `msg` is a `String` containing the human-readable message. For this specific error, rusqlite produces:

```
SqliteFailure(ErrorCode { code: SQLITE_ERROR }, "duplicate column name: mode")
```

**Pattern to use:** match on `e.to_string().contains("duplicate column name")`.

Alternative: check `e.get_sqlite_error_code()` against `ErrorCode::SqliteError`, but the message-prefix approach is more specific and explicitly documents what is being ignored. Since this is the only error swallowed (D-08 of 18-CONTEXT.md), matching the message prefix is appropriate.

**Confirmed safe:** the "duplicate column name" error is guaranteed to have that exact substring. The `.contains()` guard is not a general SQLite error suppression — it is targeted and idempotent.

### 1.3 Future migration scaffolding

Per 18-CONTEXT.md (Specifics §1), `run_migrations()` is the seed for future column-add migrations. Each future phase adds one `ALTER TABLE ADD COLUMN` wrapped in the same swallow-and-continue helper. No version table is needed at this stage per 18-CONTEXT.md (Deferred § Formal schema_version table).

---

## 2. `serde(default)` on `PolicyPayload.mode`

### 2.1 Interaction with `#[derive(Default)]` on `PolicyMode`

`PolicyMode` will be declared as:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PolicyMode {
    #[default]
    ALL,
    ANY,
    NONE,
}
```

`PolicyMode::default()` returns `PolicyMode::ALL`.

Adding `#[serde(default)]` to `PolicyPayload.mode: PolicyMode` means: when serde deserializes JSON that does not contain a `mode` key, it calls `PolicyMode::default()` and uses that value. This satisfies POLICY-12 (backward compatibility) with zero additional code.

The same applies to `PolicyResponse.mode: PolicyMode #[serde(default)]` — it handles future downgraded-server responses gracefully.

### 2.2 `#[serde(default)` on `Policy` struct itself

`Policy` already has a `#[serde(default)]` blanket on the struct in `dlp-common/src/abac.rs` (line 251). Adding `#[derive(Default)]` to `Policy` (D-04) works synergistically with this: a bare `{...}` JSON blob (future cached-policy blob format per 18-CONTEXT.md D-16) also gets `mode = ALL` from `PolicyMode::default()`. No extra work is needed; the existing blanket `#[serde(default)]` already covers the new `mode` field.

---

## 3. `parking_lot::RwLock` Read Guards with `Copy` Types

### 3.1 Mechanism

`parking_lot::RwLock` (used by `PolicyStore`) returns a `RwLockReadGuard<'a, Vec<Policy>>` from `.read()`. This guard implements `Deref<Target = Vec<Policy>>`. Calling `.iter()` on it yields `Iter<'a, Policy>`, and matching on `policy.mode` (where `PolicyMode: Copy`) copies the enum value directly. This is fully safe — the `Copy` value is copied out of the borrowed reference, not moved.

### 3.2 Borrow checker safety confirmed

Inside the `for policy in cache.iter()` loop (policy_store.rs line 102), the loop variable `policy` is of type `&Policy`. The pattern:

```rust
match policy.mode {
    PolicyMode::ALL => { /* */ }
    PolicyMode::ANY => { /* */ }
    PolicyMode::NONE => { /* */ }
}
```

copies the `PolicyMode` (which is `Copy`) and drops the `&Policy` borrow immediately after. The read lock is held for the entire `evaluate()` body (lines 100–123), which is the same scope as today. Replacing `conditions.iter().all(...)` with a `match` on mode does not change any lifetime, borrowing, or lock-behavior characteristics.

**No timing change:** `evaluate()` is already a synchronous function holding a read lock for its full duration. The `match` is a stack-allocated enum dispatch — O(1), no heap allocation.

---

## 4. Existing Migration Test Pattern

### 4.1 Pattern used in `db/mod.rs` `#[cfg(test)]` module

The existing tests in `dlp-server/src/db/mod.rs` (lines 206–363) use `new_pool(":memory:")` for pool creation. For tests requiring persistence across connections (e.g., `test_invalidate_reloads_cache` in `policy_store.rs`), `tempfile::NamedTempFile` is used:

```rust
let tmp = tempfile::NamedTempFile::new().expect("create temp db");
let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("pool from temp file"));
```

This is the correct pattern: `:memory:` pools isolate each connection to an empty DB (not useful for migration testing where we need rows to persist across the migration), so `NamedTempFile` is used instead.

### 4.2 Proposed migration test structure (per D-10)

1. Create `NamedTempFile` → acquire `rusqlite::Connection` directly.
2. Manually `CREATE TABLE policies (...)` without the `mode` column (v0.4.0 shape).
3. Insert a sample row.
4. Drop the connection.
5. Open a new pool on the same temp file path.
6. Call `run_migrations(&conn)` on a pooled connection.
7. Assert: `PRAGMA table_info(policies)` includes `mode`.
8. Assert: `SELECT mode FROM policies` on the pre-existing row returns `"ALL"`.
9. Call `run_migrations()` again → must not error (idempotency).

This exactly mirrors the `test_invalidate_reloads_cache` pattern from `policy_store.rs` for step 4 (NamedTempFile re-acquired across operations).

---

## 5. `From<PolicyResponse>` for `PolicyPayload` in dlp-admin-cli

### 5.1 Current state

The `From<PolicyResponse> for PolicyPayload` implementation in `dlp-admin-cli/src/app.rs` (lines 272–284) currently has no `mode` field on either struct.

### 5.2 Phase 19 impact (confirmed)

When Phase 19 adds `mode: PolicyMode` to both `PolicyResponse` and `PolicyPayload` in `dlp-admin-cli`, the `From` impl will need to be updated to include `mode: r.mode`. This is already noted in 18-CONTEXT.md D-22 (end of Integration Points). No structural change is needed — just add one field to the match arm.

### 5.3 Phase 18 does NOT touch dlp-admin-cli

Per 18-CONTEXT.md (Phase Boundary § Out of scope), Phase 18 does not modify the CLI. The `From` impl update is a Phase 19 task. Phase 18 only modifies `dlp-server` types (`PolicyPayload` and `PolicyResponse` in `admin_api.rs`), `dlp-common` (the new `PolicyMode` enum + `Policy.mode` field), and `dlp-server/src/db/*`.

---

## 6. `policies` Table Current Column List

From `dlp-server/src/db/mod.rs` lines 121–131:

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

**Current columns (8):** `id`, `name`, `description`, `priority`, `conditions`, `action`, `enabled`, `version`, `updated_at`.

**Phase 18 change:** `mode TEXT NOT NULL DEFAULT 'ALL'` is added as the 9th column via `run_migrations()` for existing DBs, and added directly to `init_tables()` for fresh installs.

---

## 7. `serde_json::Error` Path for Malformed Mode Values

### 7.1 Current behavior in `deserialize_policy_row`

The function in `policy_store.rs` lines 157–178 returns `Result<Policy, serde_json::Error>`. Its two current `Err` paths:

- Line 160: `serde_json::from_str(&row.conditions)?` → returns a JSON parse error if conditions JSON is corrupted.
- Line 167: `_ => Decision::DENY` → silently falls back; no error returned here (this is intentional for unknown action strings).

The `load_from_db` caller (lines 139–145) catches the conditions error via the `Err(e)` arm and logs:

```
"skipped policy with malformed conditions"
```

### 7.2 Extending for mode parsing

The `mode` column will be added to `PolicyRow`:

```rust
pub struct PolicyRow {
    // ... existing fields ...
    pub mode: String,  // NEW
}
```

In `deserialize_policy_row`, after parsing conditions, a mode parse step will be added:

```rust
let mode = match row.mode.as_str() {
    "ALL" => PolicyMode::ALL,
    "ANY" => PolicyMode::ANY,
    "NONE" => PolicyMode::NONE,
    _ => return Err(/* serde_json::Error describing corrupted mode value */),
};
```

The error message for the `_` branch should be worded to extend the existing skip log in `load_from_db` — e.g., `"skipped policy with malformed conditions or mode"`. Since the `NOT NULL DEFAULT 'ALL'` constraint guarantees the column always contains a valid string, this error path is a corruption safety net (D-18 of 18-CONTEXT.md). The exact wording is implementation detail deferred to execution.

---

## 8. `#[derive(Default)]` on `Policy` — Existing Test Fixtures

### 8.1 Current fixture pattern in `policy_store.rs`

All existing test fixtures in `policy_store.rs` use explicit struct literal syntax. Examples from lines 303–315:

```rust
Policy {
    id: "p1".to_string(),
    name: "disabled policy".to_string(),
    description: None,
    priority: 1,
    conditions: vec![...],
    action: Decision::DENY,
    enabled: false,
    version: 1,
}
```

**No fixtures use `..Default::default()` spread syntax.**

Adding `#[derive(Default)]` to `Policy` means `Policy::default()` is valid Rust syntax, but it does not change the meaning of existing explicit literals. Existing fixtures are unaffected and continue to compile unchanged.

### 8.2 New Phase 18 mode tests

New tests for the three modes will use the `..Default::default()` spread pattern (D-23 of 18-CONTEXT.md) for policy fixtures — e.g.:

```rust
Policy {
    mode: PolicyMode::ANY,
    conditions: vec![...],
    ..Default::default()
}
```

This is the cleaner idiom for new tests, consistent with D-04 guidance. The existing 15+ fixtures are not retrofitted.

---

## 9. `PolicyStore::evaluate` Hot Path — Timing and Locking

### 9.1 Current implementation (lines 99–124)

```rust
pub fn evaluate(&self, request: &EvaluateRequest) -> EvaluateResponse {
    let cache = self.cache.read();   // acquire read lock

    for policy in cache.iter() {
        if !policy.enabled {
            continue;
        }
        if policy
            .conditions
            .iter()
            .all(|c| condition_matches(c, request))
        {
            return EvaluateResponse { ... };
        }
    }

    // default-deny fallback
    ...
}
```

### 9.2 Proposed change (D-11 of 18-CONTEXT.md)

Replace lines 106–109 with:

```rust
if match policy.mode {
    PolicyMode::ALL  => policy.conditions.iter().all(|c| condition_matches(c, request)),
    PolicyMode::ANY => policy.conditions.iter().any(|c| condition_matches(c, request)),
    PolicyMode::NONE => !policy.conditions.iter().any(|c| condition_matches(c, request)),
} {
    return EvaluateResponse { ... };
}
```

### 9.3 Timing analysis

- **Read lock acquisition:** unchanged — `.read()` called once at line 100.
- **Lock scope:** unchanged — entire `evaluate()` body (lines 100–123) holds the lock.
- **Memory:** the `match` creates no heap allocation. `PolicyMode` is `Copy` (unit enum, 1 byte on the stack).
- **CPU:** the `match` is a simple jump table; no worse than the current `.all()` call. Both are O(n conditions) with early-exit on first non-match.
- **`all()` vs `match`:** `.all()` internally uses a `for` loop with early return — equivalent to what we write explicitly in the `match` arms. No behavioral difference.
- **Empty-conditions edge cases:** The natural iterator semantics already handle all three edge cases per D-13 of 18-CONTEXT.md — no extra branching needed.

**Conclusion:** Replacing `.all()` with the `match` on mode has zero observable impact on timing, lock hold duration, or cache behavior. The evaluator remains O(n conditions per policy) with first-match early exit, identical to today.

---

## Summary of Findings

| # | Research Question | Finding |
|---|-------------------|---------|
| 1 | SQLite ADD COLUMN NOT NULL + DEFAULT with existing rows | Safe — SQLite applies DEFAULT to existing rows atomically |
| 2 | rusqlite "duplicate column name" detection | Match `e.to_string().contains("duplicate column name")` — message is `"duplicate column name: {col}"` |
| 3 | `serde(default)` + `#[derive(Default)]` interaction | `PolicyMode::default() == ALL`; `#[serde(default)]` on `PolicyPayload.mode` satisfies POLICY-12 in one annotation |
| 4 | `parking_lot::RwLock` read guard with `Copy` types | Fully safe; `PolicyMode` copied out of `&Policy` borrow, lock behavior unchanged |
| 5 | Existing migration test pattern | `NamedTempFile` pool + `run_migrations()` + `PRAGMA table_info` + SELECT row — no `:memory:` |
| 6 | `From<PolicyResponse> for PolicyPayload` + mode | Phase 19 task; Phase 18 does not touch CLI; D-22 noted |
| 7 | `policies` table exact column list | 8 columns (`id` through `updated_at`); `mode` is the 9th |
| 8 | `serde_json::Error` for malformed mode | Returns from `deserialize_policy_row`; caught by existing skip-on-malformed warn log; extended message wording is implementation detail |
| 9 | `#[derive(Default)]` on `Policy` + existing test fixtures | No breakage — no fixture uses `..Default::default()` spread syntax |
| 10 | `evaluate` hot path timing | Zero observable change; lock scope, allocation, and iteration semantics unchanged |

All research questions resolved. Planning can proceed.