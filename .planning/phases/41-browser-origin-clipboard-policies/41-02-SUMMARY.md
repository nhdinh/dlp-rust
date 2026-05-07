# Plan 41-02 Summary — Origin Condition Matching in ABAC Evaluator

**Phase:** 41-browser-origin-clipboard-policies
**Plan:** 02
**Wave:** 2
**Status:** Complete

---

## Objective

Add origin condition matching to the ABAC evaluator in `dlp-server/src/policy_store.rs`, enabling the policy engine to evaluate `SourceOrigin` and `DestinationOrigin` conditions against origin fields in `AbacContext`.

---

## Tasks Executed

### Task 1: Add origin_matches helper and condition_matches arms

**Status:** Already present (delivered by Plan 41-01)

The `origin_matches()` helper function and the `SourceOrigin`/`DestinationOrigin` match arms in `condition_matches()` were already in place from the prior plan:

- `origin_matches(op, expected, origin)` — supports `eq`, `ne`, `contains` operators
- Fails closed (returns `false`) when `origin` is `None` (per D-03)
- Unknown operators return `false` (no panic)
- `condition_matches()` arms delegate to `origin_matches()` for both origin variants

### Task 2: Add unit tests for origin condition matching

**Status:** Completed — 283 lines added to `dlp-server/src/policy_store.rs`

#### origin_matches helper tests (7 tests)

| Test | Description |
|------|-------------|
| `test_origin_matches_eq_exact` | "eq" with matching origin returns true |
| `test_origin_matches_eq_no_match` | "eq" with non-matching origin returns false |
| `test_origin_matches_ne_match` | "ne" with different origin returns true |
| `test_origin_matches_contains_substring` | "contains" with substring match returns true |
| `test_origin_matches_contains_no_match` | "contains" with no substring returns false |
| `test_origin_matches_none_fails_closed` | None origin returns false for all ops (D-03) |
| `test_origin_matches_unknown_op_returns_false` | Unsupported operator returns false |

#### End-to-end evaluate() tests (7 tests)

| Test | Description |
|------|-------------|
| `test_evaluate_source_origin_eq_match` | Policy with SourceOrigin eq blocks matching origin |
| `test_evaluate_source_origin_eq_no_match` | Policy with SourceOrigin eq allows non-matching origin |
| `test_evaluate_source_origin_contains_match` | Policy with SourceOrigin contains blocks matching substring |
| `test_evaluate_destination_origin_eq_match` | Policy with DestinationOrigin eq blocks matching origin |
| `test_evaluate_source_origin_none_fails_closed` | None source_origin + SourceOrigin condition = no match |
| `test_evaluate_any_mode_source_origin_and_classification` | ANY mode: one condition hits = policy fires |
| `test_evaluate_all_mode_source_origin_and_classification` | ALL mode: both must match |
| `test_evaluate_all_mode_source_origin_misses_classification_matches` | ALL mode: one misses = policy does NOT fire |

#### Test helpers added

- `make_ctx_with_origin(classification, source_origin, destination_origin)`
- `make_source_origin_policy(op, value, action)`
- `make_dest_origin_policy(op, value, action)`

---

## Verification Results

- `cargo test -p dlp-server policy_store` — 80 passed, 0 failures
- `cargo clippy -p dlp-server -- -D warnings` — No issues found
- All existing tests pass (no regressions)

---

## Files Modified

| File | Change |
|------|--------|
| `dlp-server/src/policy_store.rs` | +283 lines: origin condition unit tests (14 tests + 3 helpers) |

---

## Threat Model Compliance

| Threat ID | Disposition | Verification |
|-----------|-------------|--------------|
| T-41-04 (Elevation of Privilege via crafted op) | Mitigated | Unknown operators return `false`; verified by `test_origin_matches_unknown_op_returns_false` |
| T-41-05 (DoS via long strings) | Accepted | Origin strings bounded by URL length; `String::contains` is O(n*m) with n < 2048 |
| T-41-06 (Information Disclosure in policy cache) | Accepted | Policy cache is in-memory only; origin values are admin-authored policy data |

---

## Key Design Decisions

1. **Fail-closed for None origin** (D-03): When `source_origin` or `destination_origin` is `None`, all origin conditions return `false`. This means a policy requiring a specific origin will NOT match if the origin is absent.
2. **Operator parity with app-identity conditions**: `eq`, `ne`, `contains` — same operator set as `SourceApplication`/`DestinationApplication` ImagePath matching.
3. **No new imports required**: Tests reuse existing `make_request()` helper and `EvaluateRequest::into()` conversion path.

---

## Commit

`2f15ab4 feat(41-02): origin condition matching unit tests for ABAC evaluator`
