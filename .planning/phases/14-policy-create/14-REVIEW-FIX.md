---
phase: 14-policy-create
fixed_at: 2026-04-17T00:00:00Z
review_path: .planning/phases/14-policy-create/14-REVIEW.md
iteration: 1
findings_in_scope: 5
fixed: 5
skipped: 0
status: all_fixed
---

# Phase 14: Code Review Fix Report

**Fixed at:** 2026-04-17T00:00:00Z
**Source review:** .planning/phases/14-policy-create/14-REVIEW.md
**Iteration:** 1

**Summary:**
- Findings in scope: 5 (all 5 warnings; 0 critical; 4 info findings out of scope)
- Fixed: 5
- Skipped: 0

## Fixed Issues

### WR-01: Debug/temporary keyboard shortcut left in production dispatch path

**Files modified:** `dlp-admin-cli/src/screens/dispatch.rs`
**Commit:** e5a801e
**Applied fix:** Removed the `KeyCode::Char('c')` branch in
`handle_policy_menu` entirely, including the accompanying
`TODO(phase-14)` comment. The normal navigation path (PolicyMenu
item 2 -> Screen::PolicyCreate) supersedes this temporary test entry
point. Removing the branch also resolves IN-03 (the TODO was tied
to this shortcut). Verified with `cargo check -p dlp-admin-cli`
(clean) and `cargo test -p dlp-admin-cli` (22 passed).

### WR-02: `action_submit_policy` overwrites `validation_error` on server error even after successful navigation

**Files modified:** `dlp-admin-cli/src/screens/dispatch.rs`
**Commit:** 5bc0560
**Applied fix:** Removed the intermediate
`app.set_status("Policy created", StatusKind::Success)` call from the
`Ok(_)` arm of `action_submit_policy`. `action_list_policies` sets
its own definitive status (`"Loaded N policies"`) after a successful
list fetch, so the earlier status was always immediately shadowed.
Added an explanatory comment describing why the status is set by the
downstream call. Verified with `cargo check` and `cargo test`.

### WR-03: `serde_json::to_value(&form.conditions).unwrap_or(...)` silently swallows serialization failures

**Files modified:** `dlp-admin-cli/src/screens/dispatch.rs`
**Commit:** 0e4204c
**Applied fix:** Replaced
`serde_json::to_value(&form.conditions).unwrap_or(serde_json::Value::Array(vec![]))`
with an explicit `match` that, on `Err`, writes a descriptive
`validation_error` (`"Failed to serialize conditions: {e}"`) to the
`Screen::PolicyCreate` screen state and returns early. This
eliminates the DLP correctness risk of submitting an allow-all policy
when the user had added conditions that failed to serialize.
Verified with `cargo check` and `cargo test`.

### WR-04: `handle_policy_create_nav` — the catch-all `_` arm enters edit mode for non-editable rows

**Files modified:** `dlp-admin-cli/src/screens/dispatch.rs`
**Commit:** faa2e55
**Applied fix:** Added an explicit `selected > POLICY_PRIORITY_ROW`
bounds guard at the start of the catch-all `_` arm in
`handle_policy_create_nav`. Rows 0..=2 are the only editable text
fields; any other index now returns immediately. The inner
`_ => String::new()` fallthrough was also tightened to `_ => return`
for defence-in-depth, even though it is unreachable given the outer
guard. This protects against future increases to `POLICY_ROW_COUNT`
that could expose the catch-all to rows above the submit row.
Verified with `cargo check` and `cargo test`.

### WR-05: `handle_conditions_step2` — operator index used without bounds check

**Files modified:** `dlp-admin-cli/src/screens/dispatch.rs`
**Commit:** 4610415
**Applied fix:** Replaced `ops[idx].0.to_string()` with a
`match ops.get(idx) { Some((name, _)) => name.to_string(), None => return }`
pattern. Today `idx` is always 0 because every attribute returns
exactly one operator, but this makes the code robust against future
`operators_for` expansions combined with a desynchronized picker
state. An out-of-range selection now silently aborts the Step 2 ->
Step 3 advance rather than panicking the TUI. Verified with
`cargo check -p dlp-admin-cli`, `cargo test -p dlp-admin-cli` (22
passed), and `cargo clippy -p dlp-admin-cli -- -D warnings` (clean).

## Skipped Issues

None — all in-scope findings were fixed.

## Out-of-Scope Findings (Info)

The four Info findings (IN-01 through IN-04) were not in the
`critical_warning` fix scope. Of note:

- **IN-03** (TODO comment tied to Phase 14) was resolved as a
  side-effect of WR-01, since the removed `KeyCode::Char('c')`
  branch carried the TODO.

---

_Fixed: 2026-04-17T00:00:00Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
