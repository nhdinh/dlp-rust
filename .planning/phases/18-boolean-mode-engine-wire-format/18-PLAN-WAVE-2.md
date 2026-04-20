---
gsd_wave: 2
depends_on:
  - 18-PLAN-WAVE-1
requirements:
  - POLICY-12
files_modified:
  - dlp-server/src/policy_store.rs
  - dlp-server/src/db/mod.rs
autonomous: true
---

# Wave 2: Evaluator + Tests

## Overview

Wave 2 replaces the hardcoded `.all()` call in `PolicyStore::evaluate` with a mode-aware match (D-11), extends the `load_from_db` skip-log message (D-18), and adds comprehensive unit tests covering all three modes, empty-conditions edge cases, wire format round-trips, legacy payload parity, and the migration path.

All work in Wave 2 is gated on Wave 1 completing (the types, DB schema, and wire format must be in place before the evaluator can be updated or tests written).

## Task List

### T9: Replace hardcoded `.all()` in `PolicyStore::evaluate` with mode-aware match

**Files to read first:**
- `dlp-server/src/policy_store.rs` lines 91–124 (`evaluate()` function — current `.all()` implementation)
- `dlp-server/src/policy_store.rs` lines 14–22 (imports — now includes `PolicyMode`)
- `18-CONTEXT.md` D-11 and D-12 (required semantics for ALL/ANY/NONE mapping)

**Action:**
Replace the hardcoded `if policy.conditions.iter().all(|c| condition_matches(c, request))` block (lines 106–109 in `evaluate()`) with a match on `policy.mode`:

```rust
// Replace:
if policy
    .conditions
    .iter()
    .all(|c| condition_matches(c, request))
{
// With:
let conditions_match = match policy.mode {
    PolicyMode::ALL => policy.conditions.iter().all(|c| condition_matches(c, request)),
    PolicyMode::ANY => policy.conditions.iter().any(|c| condition_matches(c, request)),
    PolicyMode::NONE => !policy.conditions.iter().any(|c| condition_matches(c, request)),
};
if conditions_match {
```

**Acceptance Criteria:**
- `evaluate()` uses `match policy.mode` with arms `PolicyMode::ALL`, `PolicyMode::ANY`, `PolicyMode::NONE`
- `ALL` arm uses `.all(...)` — matches only when every condition is satisfied
- `ANY` arm uses `.any(...)` — matches when at least one condition is satisfied
- `NONE` arm uses `!.any(...)` — matches when no condition is satisfied
- The `if conditions_match { ... }` block replaces the old `if policy.conditions.iter().all(...) { ... }`
- No new locking, no new heap allocation, no change to read-lock scope or function signature
- `cargo build -p dlp-server` succeeds with no warnings

---

### T10: Extend skip-log message in `load_from_db` for malformed mode

**Files to read first:**
- `dlp-server/src/policy_store.rs` lines 132–151 (`load_from_db` function — current `skipped policy with malformed conditions` log)

**Action:**
Update the warn message at line 143 in `load_from_db` from:
```rust
"skipped policy with malformed conditions"
```
To:
```rust
"skipped policy with malformed conditions or mode"
```

**Acceptance Criteria:**
- The warn log message in `load_from_db` uses the extended text `"skipped policy with malformed conditions or mode"`
- `cargo build -p dlp-server` succeeds with no warnings

---

### T11: Add unit tests for three-mode evaluator in `dlp-server/src/policy_store.rs`

**Files to read first:**
- `dlp-server/src/policy_store.rs` lines 235–739 (existing `#[cfg(test)]` module — all test patterns)
- `dlp-server/src/policy_store.rs` lines 387–422 (`test_first_match_wins_priority_order` — example of Policy struct literal with explicit fields)
- `dlp-common/src/abac.rs` lines 249–268 (Policy struct with `mode: PolicyMode` field — now available)
- `dlp-common/src/abac.rs` lines 249–268 (PolicyMode enum — now available)

**Action:**
Add the following tests to the `#[cfg(test)]` module in `policy_store_store.rs`. Insert them after the existing `test_access_context_match` test (around line 639, before the `test_in_op_on_classification_is_false` section):

```rust
// ---- Boolean mode tests ----

#[test]
fn test_evaluate_all_mode_all_conditions_match() {
    // Policy with mode=ALL matches only when every condition is satisfied.
    let policy = Policy {
        id: "mode-all".to_string(),
        name: "mode all".to_string(),
        description: None,
        priority: 1,
        conditions: vec![
            PolicyCondition::Classification { op: "eq".to_string(), value: Classification::T3 },
            PolicyCondition::DeviceTrust { op: "eq".to_string(), value: DeviceTrust::Managed },
        ],
        action: Decision::DENY,
        enabled: true,
        version: 1,
        mode: PolicyMode::ALL,  // all must match
    };
    let store = PolicyStore {
        cache: RwLock::new(vec![policy]),
        pool: Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool")),
    };
    // T3 + Managed → both conditions match → policy hits
    let resp = store.evaluate(&make_request(Classification::T3));
    assert_eq!(resp.decision, Decision::DENY);
    assert_eq!(resp.matched_policy_id.as_deref(), Some("mode-all"));
}

#[test]
fn test_evaluate_all_mode_one_condition_misses() {
    // Policy with mode=ALL does not match when one condition is unmet.
    let policy = Policy {
        id: "mode-all".to_string(),
        name: "mode all".to_string(),
        description: None,
        priority: 1,
        conditions: vec![
            PolicyCondition::Classification { op: "eq".to_string(), value: Classification::T3 },
            PolicyCondition::DeviceTrust { op: "eq".to_string(), value: DeviceTrust::Managed },
        ],
        action: Decision::DENY,
        enabled: true,
        version: 1,
        mode: PolicyMode::ALL,
    };
    let store = PolicyStore {
        cache: RwLock::new(vec![policy]),
        pool: Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool")),
    };
    // T1 + Managed → Classification condition misses → falls through to default-allow (T1)
    let resp = store.evaluate(&make_request(Classification::T1));
    assert_eq!(resp.decision, Decision::ALLOW);
    assert!(resp.matched_policy_id.is_none());
}

#[test]
fn test_evaluate_any_mode_one_condition_matches() {
    // Policy with mode=ANY matches when at least one condition is satisfied.
    let policy = Policy {
        id: "mode-any".to_string(),
        name: "mode any".to_string(),
        description: None,
        priority: 1,
        conditions: vec![
            PolicyCondition::Classification { op: "eq".to_string(), value: Classification::T3 },
            PolicyCondition::DeviceTrust { op: "eq".to_string(), value: DeviceTrust::Managed },
        ],
        action: Decision::DENY,
        enabled: true,
        version: 1,
        mode: PolicyMode::ANY,  // at least one must match
    };
    let store = PolicyStore {
        cache: RwLock::new(vec![policy]),
        pool: Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool")),
    };
    // T1 + Managed → Classification misses but DeviceTrust matches → policy hits
    let resp = store.evaluate(&make_request(Classification::T1));
    assert_eq!(resp.decision, Decision::DENY);
    assert_eq!(resp.matched_policy_id.as_deref(), Some("mode-any"));
}

#[test]
fn test_evaluate_any_mode_no_condition_matches() {
    // Policy with mode=ANY does not match when zero conditions are satisfied.
    let policy = Policy {
        id: "mode-any".to_string(),
        name: "mode any".to_string(),
        description: None,
        priority: 1,
        conditions: vec![
            PolicyCondition::Classification { op: "eq".to_string(), value: Classification::T3 },
            PolicyCondition::DeviceTrust { op: "eq".to_string(), value: DeviceTrust::Managed },
        ],
        action: Decision::DENY,
        enabled: true,
        version: 1,
        mode: PolicyMode::ANY,
    };
    let store = PolicyStore {
        cache: RwLock::new(vec![policy]),
        pool: Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool")),
    };
    // T1 + Unmanaged → neither condition matches → falls through to default-allow (T1)
    let resp = store.evaluate(&make_request(Classification::T1));
    assert_eq!(resp.decision, Decision::ALLOW);
    assert!(resp.matched_policy_id.is_none());
}

#[test]
fn test_evaluate_none_mode_no_condition_matches() {
    // Policy with mode=NONE matches when zero conditions are satisfied.
    let policy = Policy {
        id: "mode-none".to_string(),
        name: "mode none".to_string(),
        description: None,
        priority: 1,
        conditions: vec![
            PolicyCondition::Classification { op: "eq".to_string(), value: Classification::T3 },
            PolicyCondition::DeviceTrust { op: "eq".to_string(), value: DeviceTrust::Managed },
        ],
        action: Decision::ALLOW,
        enabled: true,
        version: 1,
        mode: PolicyMode::NONE,  // zero must match (i.e. all must NOT match)
    };
    let store = PolicyStore {
        cache: RwLock::new(vec![policy]),
        pool: Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool")),
    };
    // T1 + Unmanaged → Classification misses AND DeviceTrust misses → policy hits
    let resp = store.evaluate(&make_request(Classification::T1));
    assert_eq!(resp.decision, Decision::ALLOW);
    assert_eq!(resp.matched_policy_id.as_deref(), Some("mode-none"));
}

#[test]
fn test_evaluate_none_mode_one_condition_matches() {
    // Policy with mode=NONE does not match when any condition is satisfied.
    let policy = Policy {
        id: "mode-none".to_string(),
        name: "mode none".to_string(),
        description: None,
        priority: 1,
        conditions: vec![
            PolicyCondition::Classification { op: "eq".to_string(), value: Classification::T3 },
            PolicyCondition::DeviceTrust { op: "eq".to_string(), value: DeviceTrust::Managed },
        ],
        action: Decision::ALLOW,
        enabled: true,
        version: 1,
        mode: PolicyMode::NONE,
    };
    let store = PolicyStore {
        cache: RwLock::new(vec![policy]),
        pool: Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool")),
    };
    // T3 + Unmanaged → Classification matches → policy misses → default-deny (T3)
    let resp = store.evaluate(&make_request(Classification::T3));
    assert_eq!(resp.decision, Decision::DENY);
    assert!(resp.matched_policy_id.is_none());
}
```

**Acceptance Criteria:**
- Six new tests in `policy_store.rs` `#[cfg(test)]` module
- All six tests exercise mode-specific behavior and assert `matched_policy_id`
- `cargo test -p dlp-server --lib -- policy_store` passes all tests

---

### T12: Add empty-conditions edge case tests to `dlp-server/src/policy_store.rs`

**Files to read first:**
- `dlp-server/src/policy_store.rs` lines 235–739 (existing test module structure)
- `18-CONTEXT.md` D-13 (required edge-case semantics)

**Action:**
Add the following tests to the `#[cfg(test)]` module in `policy_store.rs`, after the boolean mode tests from T11:

```rust
// ---- Empty conditions edge cases ----

#[test]
fn test_evaluate_empty_conditions_all_mode_matches() {
    // ALL + []: vacuous truth — matches unconditionally.
    let policy = Policy {
        id: "empty-all".to_string(),
        name: "empty all".to_string(),
        description: None,
        priority: 1,
        conditions: vec![],
        action: Decision::DENY,
        enabled: true,
        version: 1,
        mode: PolicyMode::ALL,
    };
    let store = PolicyStore {
        cache: RwLock::new(vec![policy]),
        pool: Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool")),
    };
    // ANY classification request should match the empty-ALL policy
    let resp = store.evaluate(&make_request(Classification::T1));
    assert_eq!(resp.decision, Decision::DENY);
    assert_eq!(resp.matched_policy_id.as_deref(), Some("empty-all"));
}

#[test]
fn test_evaluate_empty_conditions_any_mode_does_not_match() {
    // ANY + []: no conditions exist → at least one can never be satisfied → never matches.
    let policy = Policy {
        id: "empty-any".to_string(),
        name: "empty any".to_string(),
        description: None,
        priority: 1,
        conditions: vec![],
        action: Decision::DENY,
        enabled: true,
        version: 1,
        mode: PolicyMode::ANY,
    };
    let store = PolicyStore {
        cache: RwLock::new(vec![policy]),
        pool: Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool")),
    };
    // Falls through to default-deny (T4)
    let resp = store.evaluate(&make_request(Classification::T4));
    assert_eq!(resp.decision, Decision::DENY);
    assert!(resp.matched_policy_id.is_none());
}

#[test]
fn test_evaluate_empty_conditions_none_mode_matches() {
    // NONE + []: zero conditions are satisfied (vacuously true) → matches unconditionally.
    let policy = Policy {
        id: "empty-none".to_string(),
        name: "empty none".to_string(),
        description: None,
        priority: 1,
        conditions: vec![],
        action: Decision::ALLOW,
        enabled: true,
        version: 1,
        mode: PolicyMode::NONE,
    };
    let store = PolicyStore {
        cache: RwLock::new(vec![policy]),
        pool: Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool")),
    };
    let resp = store.evaluate(&make_request(Classification::T1));
    assert_eq!(resp.decision, Decision::ALLOW);
    assert_eq!(resp.matched_policy_id.as_deref(), Some("empty-none"));
}
```

**Acceptance Criteria:**
- Three new tests covering empty-conditions edge cases
- `test_evaluate_empty_conditions_all_mode_matches`: empty ALL policy matches on any request
- `test_evaluate_empty_conditions_any_mode_does_not_match`: empty ANY policy misses on all requests
- `test_evaluate_empty_conditions_none_mode_matches`: empty NONE policy matches on any request
- `cargo test -p dlp-server --lib -- empty_conditions` passes all three tests

---

### T13: Add wire format round-trip tests to `dlp-server/src/admin_api.rs`

**Files to read first:**
- `dlp-server/src/admin_api.rs` lines 95–135 (PolicyPayload and PolicyResponse structs)
- `dlp-server/src/admin_api.rs` lines 206+ (existing test patterns in admin_api.rs test module)
- `18-CONTEXT.md` D-24 (wire format test specification)

**Action:**
Add a `#[cfg(test)]` module to `admin_api.rs` (or extend the existing one) with the following tests. Insert after the existing test code:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use dlp_common::abac::PolicyMode;

    #[test]
    fn test_policy_payload_deserializes_without_mode_as_all() {
        // POLICY-12: JSON without "mode" key defaults to PolicyMode::ALL.
        let json = r#"{
            "id": "test-1",
            "name": "test policy",
            "description": null,
            "priority": 1,
            "conditions": [],
            "action": "Allow",
            "enabled": true
        }"#;
        let payload: PolicyPayload = serde_json::from_str(json).expect("deserialize");
        assert_eq!(payload.mode, PolicyMode::ALL);
    }

    #[test]
    fn test_policy_payload_json_with_mode_any_roundtrip() {
        // PolicyPayload with mode=ANY round-trips correctly.
        let payload = PolicyPayload {
            id: "test-any".to_string(),
            name: "any mode policy".to_string(),
            description: None,
            priority: 2,
            conditions: serde_json::json!([]),
            action: "Deny".to_string(),
            enabled: true,
            mode: PolicyMode::ANY,
        };
        let json = serde_json::to_string(&payload).expect("serialize");
        let round_trip: PolicyPayload = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(round_trip.mode, PolicyMode::ANY);
        assert!(json.contains(r#""mode":"ANY""#), "JSON must contain mode field");
    }

    #[test]
    fn test_policy_response_deserializes_without_mode_as_all() {
        // PolicyResponse without "mode" key defaults to PolicyMode::ALL.
        let json = r#"{
            "id": "test-2",
            "name": "test response",
            "description": null,
            "priority": 1,
            "conditions": [],
            "action": "Allow",
            "enabled": true,
            "version": 1,
            "updated_at": "2026-04-20T00:00:00Z"
        }"#;
        let resp: PolicyResponse = serde_json::from_str(json).expect("deserialize");
        assert_eq!(resp.mode, PolicyMode::ALL);
    }

    #[test]
    fn test_policy_payload_none_mode_roundtrip() {
        let payload = PolicyPayload {
            id: "test-none".to_string(),
            name: "none mode policy".to_string(),
            description: None,
            priority: 3,
            conditions: serde_json::json!([]),
            action: "Allow".to_string(),
            enabled: true,
            mode: PolicyMode::NONE,
        };
        let json = serde_json::to_string(&payload).expect("serialize");
        assert!(json.contains(r#""mode":"NONE""#));
        let round_trip: PolicyPayload = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(round_trip.mode, PolicyMode::NONE);
    }
}
```

**Acceptance Criteria:**
- `admin_api.rs` has a `#[cfg(test)]` module with four wire format tests
- `test_policy_payload_deserializes_without_mode_as_all` asserts `PolicyMode::ALL` from mode-less JSON (POLICY-12)
- `test_policy_payload_json_with_mode_any_roundtrip` verifies `"mode":"ANY"` appears in serialized JSON
- `test_policy_response_deserializes_without_mode_as_all` asserts `PolicyMode::ALL` from mode-less response JSON
- `test_policy_payload_none_mode_roundtrip` verifies `"mode":"NONE"` in serialized JSON
- `cargo test -p dlp-server --lib -- admin_api::tests` passes all four tests

---

### T14: Add legacy payload parity test to `dlp-server/src/policy_store.rs`

**Files to read first:**
- `dlp-server/src/policy_store.rs` lines 235–739 (existing test module)
- `18-CONTEXT.md` D-25 (parity test specification: v0.4.0-shaped JSON vs explicit mode=ALL)

**Action:**
Add the following test to the `policy_store.rs` `#[cfg(test)]` module, after the empty-conditions tests from T12:

```rust
// ---- Legacy v0.4.0 payload parity test ----

#[test]
fn test_legacy_v040_policy_without_mode_behaves_like_all() {
    // POLICY-12: A v0.4.0-shaped PolicyPayload (no mode field) should produce
    // the same EvaluateResponse as an explicit PolicyMode::ALL policy.
    //
    // This test constructs two Policy structs: one without a mode field (the
    // v0.4.0 shape) and one with explicit mode=ALL (the Phase 18 shape), and
    // asserts they produce identical decisions against a 3-condition request.

    let policy_v040 = Policy {
        id: "v040-policy".to_string(),
        name: "v0.4.0 policy".to_string(),
        description: None,
        priority: 1,
        conditions: vec![
            PolicyCondition::Classification { op: "eq".to_string(), value: Classification::T3 },
            PolicyCondition::DeviceTrust { op: "eq".to_string(), value: DeviceTrust::Managed },
            PolicyCondition::NetworkLocation { op: "eq".to_string(), value: NetworkLocation::Corporate },
        ],
        action: Decision::DENY,
        enabled: true,
        version: 1,
        // mode field is NOT set here — Policy::default() gives PolicyMode::ALL
        ..Default::default()
    };

    let policy_explicit_all = Policy {
        id: "explicit-all".to_string(),
        name: "explicit all".to_string(),
        description: None,
        priority: 1,
        conditions: vec![
            PolicyCondition::Classification { op: "eq".to_string(), value: Classification::T3 },
            PolicyCondition::DeviceTrust { op: "eq".to_string(), value: DeviceTrust::Managed },
            PolicyCondition::NetworkLocation { op: "eq".to_string(), value: NetworkLocation::Corporate },
        ],
        action: Decision::DENY,
        enabled: true,
        version: 1,
        mode: PolicyMode::ALL,
    };

    // Both stores share the same :memory: pool.
    let pool = Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool"));

    let store_v040 = PolicyStore {
        cache: RwLock::new(vec![policy_v040]),
        pool: Arc::clone(&pool),
    };
    let store_explicit = PolicyStore {
        cache: RwLock::new(vec![policy_explicit_all]),
        pool: Arc::clone(&pool),
    };

    let req = make_request(Classification::T3);
    let resp_v040 = store_v040.evaluate(&req);
    let resp_explicit = store_explicit.evaluate(&req);

    assert_eq!(resp_v040.decision, resp_explicit.decision);
    assert_eq!(resp_v040.matched_policy_id, resp_explicit.matched_policy_id);
    assert_eq!(resp_v040.reason, resp_explicit.reason);
}
```

**Acceptance Criteria:**
- `test_legacy_v040_policy_without_mode_behaves_like_all` in `policy_store.rs`
- Uses `..Default::default()` on one policy fixture to simulate the v0.4.0 shape
- Uses explicit `mode: PolicyMode::ALL` on the other fixture
- Both stores assert identical `decision`, `matched_policy_id`, and `reason`
- `cargo test -p dlp-server --lib -- legacy_v040` passes

---

### T15: Add SQLite migration unit test to `dlp-server/src/db/mod.rs`

**Files to read first:**
- `dlp-server/src/db/mod.rs` lines 206–363 (existing `#[cfg(test)]` module)
- `18-CONTEXT.md` D-10 (migration test specification)
- `18-RESEARCH.md` §4 (NamedTempFile pattern for migration tests)

**Action:**
Add the following test to the `#[cfg(test)]` module in `db/mod.rs`. Insert after the existing `test_ldap_config_seed_row` test (around line 363):

```rust
#[test]
fn test_migration_add_mode_column() {
    // Test that run_migrations() safely adds the 'mode' column to an existing
    // v0.4.0-style policies table (without the mode column) and idempotently
    // re-runs without error.

    use tempfile::NamedTempFile;

    // Step 1: Create a temp DB and manually set up the v0.4.0 schema (no mode column).
    let tmp = NamedTempFile::new().expect("create temp db file");
    let path = tmp.path().to_str().unwrap();

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
                version     INTEGER NOT NULL DEFAULT 1,
                updated_at  TEXT NOT NULL
            );
            INSERT INTO policies
                (id, name, priority, conditions, action, enabled, version, updated_at)
            VALUES
                ('existing-policy', 'existing', 1, '[]', 'Allow', 1, 1, '2026-01-01T00:00:00Z');",
        )
        .expect("create v0.4.0 schema");
        // v0.4.0 rows have no mode column — confirmed.
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM policies", [], |r| r.get(0))
            .expect("count policies");
        assert_eq!(count, 1, "should have one pre-existing row");
    }

    // Step 2: Open a pool (triggers init_tables + run_migrations).
    let pool = new_pool(path).expect("open pool with migrations");
    let conn = pool.get().expect("acquire connection");

    // Step 3: Assert mode column exists in the schema.
    let columns: Vec<String> = conn
        .prepare("PRAGMA table_info(policies)")
        .expect("prepare pragma")
        .query_map([], |row| row.get(2))
        .expect("query pragma")
        .filter_map(|r| r.ok())
        .collect();
    assert!(
        columns.contains(&"mode".to_string()),
        "mode column must exist after migration"
    );

    // Step 4: Assert pre-existing row now has mode = 'ALL' (SQLite DEFAULT applies).
    let mode: String = conn
        .query_row("SELECT mode FROM policies WHERE id = 'existing-policy'", [], |r| r.get(0))
        .expect("read mode column from pre-existing row");
    assert_eq!(mode, "ALL", "pre-existing rows must default to 'ALL' mode");

    // Step 5: Assert idempotency — run_migrations again does not error.
    run_migrations(&conn).expect("second run must not error");

    // Step 6: Confirm row still has mode = 'ALL' after second migration.
    let mode2: String = conn
        .query_row("SELECT mode FROM policies WHERE id = 'existing-policy'", [], |r| r.get(0))
        .expect("re-read mode column");
    assert_eq!(mode2, "ALL", "mode must persist after re-run");
}
```

**Acceptance Criteria:**
- `test_migration_add_mode_column` in `db/mod.rs` `#[cfg(test)]` module
- Uses `NamedTempFile` (not `:memory:`) so the DB persists across pool connections
- Manually creates v0.4.0 `policies` table without `mode` column
- Inserts a pre-existing row without `mode` value
- Opens a pool via `new_pool(path)` which calls `init_tables` + `run_migrations`
- Asserts: (a) `mode` column exists in `PRAGMA table_info`, (b) pre-existing row has `mode = 'ALL'`
- Asserts idempotency by calling `run_migrations(&conn)` a second time without error
- `cargo test -p dlp-server --lib -- migration_add_mode_column` passes

---

## Verification

After Wave 2 completes, run:
```bash
cargo build --all
cargo test --lib --all
```

All tests must pass, including:
- Boolean mode tests: `test_evaluate_all_mode_all_conditions_match`, `test_evaluate_any_mode_one_condition_matches`, `test_evaluate_none_mode_no_condition_matches`, etc.
- Empty-conditions tests: three tests with `empty_conditions` in name
- Wire format tests: four tests in `admin_api::tests` module
- Legacy parity test: `test_legacy_v040_policy_without_mode_behaves_like_all`
- Migration test: `test_migration_add_mode_column`

Final check: `cargo clippy --all -- -D warnings` passes with no issues.

## Dependencies

Wave 2 is entirely gated on Wave 1 completing. All tasks in Wave 2 depend on Wave 1 output:
- T9 (evaluator) requires Wave 1 T1 (PolicyMode exists) + T2 (Policy has mode field)
- T10 (skip-log) requires Wave 1 T8 (deserialize_policy_row has mode parsing)
- T11–T14 (unit tests) require Wave 1 T1 + T2 + T6 (types + wire format exist)
- T15 (migration test) requires Wave 1 T3 + T4 (run_migrations + init_tables include mode column)

Wave 2 parallel groups: {T9, T10} → {T11, T12, T13, T14, T15}

## Must-Haves for Phase Goal Verification

| Must-Have | Verification |
|-----------|--------------|
| `PolicyMode` enum exists with `ALL`, `ANY`, `NONE` variants | `cargo build -p dlp-common` succeeds; `PolicyMode::default() == ALL` via unit test |
| `Policy` struct has `mode: PolicyMode` field with `#[serde(default)]` | Wire format tests pass |
| `policies` SQLite table has `mode TEXT NOT NULL DEFAULT 'ALL'` for both fresh and existing DBs | Migration test passes |
| `PolicyStore::evaluate` switches on policy mode | Mode-evaluator tests pass (T11) |
| Empty-conditions edge cases handled correctly | Edge case tests pass (T12) |
| Legacy v0.4.0 payloads (no `mode` key) default to `ALL` | `test_policy_payload_deserializes_without_mode_as_all` passes |
| `mode` round-trips through create/update API | Wire format tests pass |
| No regression in existing functionality | All existing tests pass (`cargo test --all --lib`) |