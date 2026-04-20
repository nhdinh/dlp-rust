---
phase: 20-operator-expansion
reviewed: 2026-04-21T00:00:00Z
depth: standard
files_reviewed: 3
files_reviewed_list:
  - dlp-server/src/policy_store.rs
  - dlp-admin-cli/src/screens/dispatch.rs
  - dlp-admin-cli/src/screens/render.rs
findings:
  critical: 0
  warning: 3
  info: 3
  total: 6
status: issues_found
---

# Phase 20: Code Review Report

**Reviewed:** 2026-04-21
**Depth:** standard
**Files Reviewed:** 3
**Status:** issues_found

## Summary

The Phase 20 operator-expansion changes are well-structured and correctly implement `gt`/`lt` for Classification and `contains`/`neq` for MemberOf. The ABAC evaluator logic is sound, all new code paths have corresponding tests, and the TUI operator picker plumbing is consistent.

Three warnings and three info-level items were found. None are security vulnerabilities. The most important warning is a render bug in `draw_import_confirm` where the cursor is always painted on row 3 regardless of `selected`, making the [Cancel] row appear permanently unselected to the user.

---

## Warnings

### WR-01: Import confirm — cursor hardcoded to row 3, ignores `selected`

**File:** `dlp-admin-cli/src/screens/render.rs:1654-1656`
**Issue:** `draw_import_confirm` receives `selected: usize` as a parameter, but the list state is always initialized to `Some(3)` rather than `Some(selected)`. When the user presses Down to move to the [Cancel] row (index 4), the cursor visual does not follow — the [Cancel] row is never highlighted with the `> ` symbol or Cyan background. This means the user cannot see which button is active.
**Fix:**
```rust
let mut list_state = ListState::default();
list_state.select(Some(selected));   // was: Some(3)
frame.render_stateful_widget(list, area, &mut list_state);
```

---

### WR-02: `compare_op` silently returns `false` for unknown operators

**File:** `dlp-server/src/policy_store.rs:241-249`
**Issue:** The generic `compare_op` function used for `DeviceTrust`, `NetworkLocation`, and `AccessContext` conditions falls through to `_ => false` for any unrecognized operator string. A database row with a corrupted or misspelled operator (e.g. `"gte"` or `"equals"`) will silently evaluate to `false` — the condition never matches and the policy is silently skipped rather than producing a warning. This is a **silent misconfiguration** that can cause a policy to stop being enforced without any visible indicator.
**Fix:** Add a `warn!` call for unrecognized operators so the log surface captures the issue:
```rust
fn compare_op<T: PartialEq>(op: &str, actual: &T, expected: &T) -> bool {
    match op {
        "eq" => actual == expected,
        "neq" => actual != expected,
        "in" | "not_in" => false,
        other => {
            warn!(op = other, "unrecognized operator in condition; treating as no-match");
            false
        }
    }
}
```
The same pattern should be applied to `compare_op_classification` and `memberof_matches` for the `_` arms.

---

### WR-03: Conditions builder — `in`/`not_in` operators removed from picker but still exist in DB-loaded policies

**File:** `dlp-admin-cli/src/screens/dispatch.rs:2022-2031`
**Issue:** `operators_for` now returns only `["eq", "neq", "contains"]` for `MemberOf` and `["eq", "neq"]` for scalar attributes. However, the evaluator in `policy_store.rs` still handles `"in"` and `"not_in"` as valid operators for `MemberOf` (lines 283-285). A policy created via an older version of the CLI (or directly via API) may have `"in"` or `"not_in"` as the operator, but the TUI offers no way to re-create or view that operator in the conditions builder — the user editing such a policy would silently convert it away from `in`/`not_in` to the default `eq` on next save without any warning.

This is a correctness risk for policy continuity across version upgrades. The fix is either to preserve `in`/`not_in` in `operators_for` (perhaps as unenforced/legacy options), or to add a warning when `action_load_policy_for_edit` deserializes a condition whose operator is not in `operators_for(attr)`.

**Fix (minimal):** In `action_load_policy_for_edit`, after deserializing conditions, check each condition's operator against `operators_for(attr)` and emit a status warning if any operator is not in the current picker list:
```rust
// After building `conditions`:
for cond in &conditions {
    let (attr, op) = condition_attr_and_op(cond); // helper to extract
    if !operators_for(attr).iter().any(|(o, _)| *o == op) {
        app.set_status(
            format!("Warning: condition uses legacy operator '{op}'; review before saving"),
            StatusKind::Error,
        );
    }
}
```

---

## Info

### IN-01: `condition_display` has a `#[allow(dead_code)]` suppression

**File:** `dlp-admin-cli/src/screens/dispatch.rs:2123`
**Issue:** `condition_display` is marked `pub` and called from `render.rs`, but carries `#[allow(dead_code)]`. The attribute is a leftover from before the render integration was wired up. It should be removed now that the function is actively used, so that future dead-code regressions are caught by the compiler.
**Fix:** Remove `#[allow(dead_code)]` from line 2123.

---

### IN-02: `policy_mode_to_wire` duplicates `mode_str` from the server crate

**File:** `dlp-admin-cli/src/screens/dispatch.rs:1316-1322`
**Issue:** The function body and comment at line 1315 explicitly acknowledge the duplication. This is currently acceptable because `mode_str` is `pub(crate)` in the server crate and cannot be shared, but it is worth tracking. If `mode_str` (or an equivalent) is ever promoted to `dlp-common`, this duplicate should be removed to eliminate a future divergence risk.
**Fix (tracking only):** Add a `// TODO: deduplicate when dlp-common exposes PolicyMode -> &str mapping` comment, or move both into `dlp-common`.

---

### IN-03: `PolicyEngineError::PolicyNotFound` used for a non-"not found" error path

**File:** `dlp-server/src/policy_store.rs:60`
**Issue:** `PolicyStore::new` wraps the initial DB-load error with `PolicyEngineError::PolicyNotFound(e.to_string())`. A connection failure or schema error during startup is not semantically a "policy not found" condition — it is a load/initialization failure. Using the wrong error variant degrades the quality of diagnostics and could mislead anyone inspecting the error type.
**Fix:** Either add a `PolicyEngineError::LoadFailed(String)` variant in `policy_engine_error.rs`, or use a more semantically correct existing variant:
```rust
let policies = Self::load_from_db(&pool)
    .map_err(|e| PolicyEngineError::LoadFailed(e.to_string()))?;
```

---

_Reviewed: 2026-04-21_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
