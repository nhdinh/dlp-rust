---
status: complete
phase: 18-boolean-mode-engine-wire-format
milestone: v0.5.0 Boolean Logic
requirements: [POLICY-12]
waves_completed: [1, 2]
---

# Phase 18: Boolean Mode Engine + Wire Format — Summary

**Phase:** 18
**Milestone:** v0.5.0 Boolean Logic
**POLICY-12:** Backward-compatible mode default (ALL)

---

## Wave 1: Types + DB Schema + Wire Format (T1–T8)

### T1 — `PolicyMode` enum (`dlp-common/src/abac.rs`)
Added `PolicyMode` enum with three variants:
- `ALL` (default): every condition must match (implicit v0.4.0 behavior)
- `ANY`: at least one condition must match
- `NONE`: no condition may match

### T2 — `mode` field on `Policy` struct (`dlp-common/src/abac.rs`)
Added `mode: PolicyMode` with `#[serde(default)]` to the `Policy` struct. Wave 2 also added `#[derive(Default)]` on `Policy` (closed Wave 1 acceptance gap), enabling the `..Default::default()` pattern in legacy parity tests.

### T3 — `run_migrations()` function (`dlp-server/src/db/mod.rs`)
Added idempotent `run_migrations(&conn)` called after `init_tables()` in `new_pool()`. Runs `ALTER TABLE policies ADD COLUMN mode TEXT NOT NULL DEFAULT 'ALL'` and silently ignores "duplicate column name" errors.

### T4 — Fresh-install `mode` column (`dlp-server/src/db/mod.rs`)
Added `mode TEXT NOT NULL DEFAULT 'ALL'` to the `CREATE TABLE IF NOT EXISTS policies` statement.

### T5 — Repository extended (`dlp-server/src/db/repositories/policies.rs`)
Extended `PolicyRow` (added `pub mode: String`) and `PolicyUpdateRow<'a>` (added `pub mode: &'a str`). Updated all SELECT/INSERT/UPDATE statements to read/write the `mode` column.

### T6 — API types (`dlp-server/src/admin_api.rs`)
Added `mode: PolicyMode` with `#[serde(default)]` to both `PolicyPayload` and `PolicyResponse` structs.

### T7 — Handler wiring (`dlp-server/src/admin_api.rs`)
Wired `mode` through `create_policy`, `update_policy`, `list_policies`, `get_policy` handlers via `mode_str()` and `mode_from_str()` helpers.

### T8 — `mode_str()` + deserialization (`dlp-server/src/policy_store.rs`)
Added `pub(crate) const fn mode_str(mode: PolicyMode) -> &'static str` helper. Updated `deserialize_policy_row` to parse `mode` from the DB column. Wave 2 hardened this to return a `serde_json::Error` for unknown mode strings (was silently defaulting to ALL).

---

## Wave 2: Evaluator + Tests (T9–T15)

### T9 — Mode-aware evaluator (`dlp-server/src/policy_store.rs`)
Replaced the hardcoded `.all(|c| condition_matches(c, request))` in `PolicyStore::evaluate` with a `match policy.mode` block:
- `ALL` → `.all(...)`
- `ANY` → `.any(...)`
- `NONE` → `!.any(...)`

No new locking, no new heap allocation, no change to read-lock scope.

### T10 — Skip-log message + malformed-mode handling (`dlp-server/src/policy_store.rs`)
Updated the warn message in `load_from_db` to `"skipped policy with malformed conditions or mode"`. Hardened `deserialize_policy_row` to return `serde::de::Error::custom(...)` for unknown mode strings instead of silently defaulting — caught by the existing skip-log path.

### T11 — Six boolean-mode tests (`dlp-server/src/policy_store.rs`)
Two tests per mode (match + miss), asserting `decision` and `matched_policy_id`.

### T12 — Three empty-conditions edge cases (`dlp-server/src/policy_store.rs`)
- `ALL + []` → vacuous truth, matches unconditionally
- `ANY + []` → never matches (no condition can be satisfied)
- `NONE + []` → vacuous truth, matches unconditionally

### T13 — Four wire format round-trip tests (`dlp-server/src/admin_api.rs`)
- `PolicyPayload` deserializes without `mode` key → `PolicyMode::ALL`
- `PolicyPayload` round-trip preserves `mode=ANY` and `mode=NONE`; serialized JSON contains `"mode":"ANY"` / `"mode":"NONE"`
- `PolicyResponse` deserializes without `mode` key → `PolicyMode::ALL`

### T14 — Legacy v0.4.0 parity test (`dlp-server/src/policy_store.rs`)
Asserts a `Policy` constructed via `..Default::default()` (no `mode` field set) produces the same `EvaluateResponse.decision` as a policy with explicit `mode: PolicyMode::ALL` against a 3-condition request.

### T15 — Migration unit test (`dlp-server/src/db/mod.rs`)
Stands up the v0.4.0 schema directly on a `NamedTempFile`, seeds one row, opens via `new_pool()` (triggers `init_tables` + `run_migrations`), then asserts:
- `mode` column appears in `PRAGMA table_info(policies)`
- The pre-existing row picks up `mode = 'ALL'` via SQL DEFAULT
- A second `run_migrations()` call is a no-op (idempotency)

---

## Migration Safety

| Path | Mechanism | Result |
|---|---|---|
| Fresh install | `CREATE TABLE` includes `mode TEXT NOT NULL DEFAULT 'ALL'` | Zero-config |
| Existing install | `run_migrations()` runs `ALTER TABLE ... ADD COLUMN` idempotently | Pre-existing rows inherit `mode = 'ALL'` |
| Deserialization | `#[serde(default)]` on `Policy.mode`, `PolicyPayload.mode`, `PolicyResponse.mode` | Mode-less JSON defaults to `PolicyMode::ALL` |
| Engine evaluation | `Policy::default().mode == PolicyMode::ALL` (via `#[default]` on `ALL`) | Defaulted policies behave identically to v0.4.0 |

---

## Verification

| Check | Result |
|---|---|
| `cargo check --all` | Clean (no warnings) |
| `cargo clippy --lib --all -- -D warnings` | Clean |
| `cargo fmt --check` | Clean (after fmt applied to long use/let lines) |
| `cargo test --lib --all` | 119 passed, 0 failed (was 104 → 15 new tests) |
| `cargo test -p dlp-server --tests` | Integration tests pass (2 fixtures updated for `mode` field) |

**Note:** 8 pre-existing `todo!()` test stubs in `dlp-agent` (`cloud_tc`, `print_tc`, `detective_tc`) panic when run — these are unimplemented-feature placeholders unrelated to Phase 18.

---

## Commits (Wave 2)

| Commit | Description |
|---|---|
| `ce32fd9` | feat(engine): switch evaluator on PolicyMode (ALL/ANY/NONE) — T9, T10, integration test fix |
| `43f0f89` | test(engine): add 10 boolean mode tests; derive Default on Policy — T11, T12, T14 |
| `2fbcf3b` | test(api): add four mode wire format round-trip tests — T13 |
| `e0c8151` | test(db): add migration unit test for mode column add — T15 |

---

## Wave 1 Acceptance Gaps Closed in Wave 2

1. **`Policy` did not derive `Default`** — Wave 1 T2 acceptance criteria required `#[derive(Default)]` on `Policy` so `Policy::default()` would produce `mode: PolicyMode::ALL`. Was missed during Wave 1 execution; closed in commit `43f0f89`.
2. **`deserialize_policy_row` silently defaulted unknown modes to `ALL`** — Wave 1 T8 acceptance required unknown mode strings to produce `serde_json::Error` so the existing `load_from_db` warn-log path catches them. Was implemented as a silent fallthrough; corrected in commit `ce32fd9`.
3. **`admin_audit_integration.rs` fixtures missed `mode`** — Wave 1 T6 added `mode` to `PolicyPayload` but two integration test fixtures were not updated. Fixed in commit `ce32fd9`.
