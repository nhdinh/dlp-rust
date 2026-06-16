---
phase: 16-policy-list-simulate
plan: "01a"
type: execute
wave: 1
depends_on: []
requirements:
  - POLICY-01
files_modified:
  - dlp-admin-cli/src/screens/render.rs
  - dlp-admin-cli/src/screens/dispatch.rs
autonomous: true
must_haves:
  truths:
    - "Policy list table shows 5 columns: Priority / Name / Action / Enabled / Mode"
    - "Policy list includes global_mode parameter and render_global_override_banner call"
    - "Policy list is sorted by priority ascending with name tiebreak"
    - "Malformed priorities sink to bottom (u32::MAX)"
    - "n key transitions from PolicyList to PolicyCreate"
  artifacts:
    - path: "dlp-admin-cli/src/screens/render.rs"
      provides: "draw_policy_list with 5 columns, global_mode param, override banner"
    - path: "dlp-admin-cli/src/screens/dispatch.rs"
      provides: "Char('n') branch, client-side sort"
  key_links:
    - from: "dlp-admin-cli/src/screens/dispatch.rs"
      to: "dlp-admin-cli/src/screens/dispatch.rs"
      via: "sorted.sort_by with priority+name tiebreak"
---

# Phase 16 — Wave 1a: Verify PolicyList Implementation

## Objective

Confirm that the PolicyList implementation already present in `master` matches the updated 5-column specification. The shipped code includes the 5-column table (with Mode column and global override banner), the `n` key, and client-side sort. This plan documents the current state and verifies correctness.

**Purpose:** Ensure the existing PolicyList implementation is the source of truth for future work.
**Output:** Verified state of PolicyList artifacts.

## Cross-AI Review Feedback Incorporated

- **Column spec corrected (HIGH):** The original plan specified 4 columns (Priority/Name/Action/Enabled) with widths 15/45/20/20%. The shipped code has 5 columns (Priority/Name/Action/Enabled/Mode) with widths 12/38/15/12/23%, plus a `global_mode` parameter and `render_global_override_banner` call. This plan aligns with the shipped 5-column reality.

## Context

@dlp-admin-cli/src/screens/render.rs
@dlp-admin-cli/src/screens/dispatch.rs
@dlp-admin-cli/src/app.rs
@dlp-admin-cli/Cargo.toml

## Tasks

<task type="auto">
  <name>Task 1: Verify draw_policy_list has 5 columns with Mode and global_mode</name>
  <files>dlp-admin-cli/src/screens/render.rs</files>
  <read_first>
    dlp-admin-cli/src/screens/render.rs (lines 1746-1823, draw_policy_list function)
  </read_first>
  <action>
    Verify the existing `draw_policy_list` function signature includes `global_mode: Option<&str>` and the function body contains:
    - Header row with exactly 5 columns: "Priority", "Name", "Action", "Enabled", "Mode"
    - Widths: 12%, 38%, 15%, 12%, 23% (Constraint::Percentage values)
    - Row builder that reads `p["enforcement_mode"]` and appends " (global)" when `global_active` is true
    - Call to `render_global_override_banner(frame, area, global_mode)` after the table render
    - Footer hints: "n: new | e: edit | d: delete | Enter: view | Esc: back"
    - `enabled` rendered as "Yes" / "No" (not true/false)
    - Malformed priority rendered as `u32::MAX` (sinks to bottom via sort, not "ERR" in render)
    If any of these are missing, report the deviation. Do NOT modify the function.
  </action>
  <verify>
    <automated>
      grep -n 'fn draw_policy_list' dlp-admin-cli/src/screens/render.rs
      grep -n 'global_mode: Option<&str>' dlp-admin-cli/src/screens/render.rs
      grep -n '"Priority", "Name", "Action", "Enabled", "Mode"' dlp-admin-cli/src/screens/render.rs
      grep -n 'Constraint::Percentage(12)' dlp-admin-cli/src/screens/render.rs
      grep -n 'Constraint::Percentage(38)' dlp-admin-cli/src/screens/render.rs
      grep -n 'Constraint::Percentage(15)' dlp-admin-cli/src/screens/render.rs
      grep -n 'Constraint::Percentage(23)' dlp-admin-cli/src/screens/render.rs
      grep -n 'render_global_override_banner' dlp-admin-cli/src/screens/render.rs
      grep -n '"n: new | e: edit | d: delete | Enter: view | Esc: back"' dlp-admin-cli/src/screens/render.rs
    </automated>
  </verify>
  <acceptance_criteria>
    - `grep -n 'fn draw_policy_list' dlp-admin-cli/src/screens/render.rs` returns the function definition
    - `grep -n 'global_mode: Option<&str>' dlp-admin-cli/src/screens/render.rs` returns the parameter
    - `grep -n '"Priority", "Name", "Action", "Enabled", "Mode"' dlp-admin-cli/src/screens/render.rs` returns the header row
    - `grep -n 'Constraint::Percentage(12)' dlp-admin-cli/src/screens/render.rs` returns the Priority width
    - `grep -n 'Constraint::Percentage(38)' dlp-admin-cli/src/screens/render.rs` returns the Name width
    - `grep -n 'Constraint::Percentage(23)' dlp-admin-cli/src/screens/render.rs` returns the Mode width
    - `grep -n 'render_global_override_banner' dlp-admin-cli/src/screens/render.rs` returns the banner call
    - `grep -n '"n: new | e: edit | d: delete | Enter: view | Esc: back"' dlp-admin-cli/src/screens/render.rs` returns the hints
  </acceptance_criteria>
  <done>All 5 columns, global_mode parameter, override banner, and hints are confirmed present in the shipped code.</done>
</task>

<task type="auto">
  <name>Task 2: Verify Char('n') branch and client-side sort in dispatch.rs</name>
  <files>dlp-admin-cli/src/screens/dispatch.rs</files>
  <read_first>
    dlp-admin-cli/src/screens/dispatch.rs (lines 741-791, handle_policy_list)
    dlp-admin-cli/src/screens/dispatch.rs (lines 815-850, action_list_policies)
  </read_first>
  <action>
    Verify the existing `handle_policy_list` contains:
    - `KeyCode::Char('n')` branch that transitions to `Screen::PolicyCreate` with `PolicyFormState::default()`
    - `KeyCode::Char('e')` and `KeyCode::Char('d')` branches unchanged
    Verify `action_list_policies` contains:
    - Client-side `sort_by` with primary key `priority` ascending (malformed = `u32::MAX`)
    - Secondary key `name` case-insensitive ascending via `.to_lowercase()`
    - `sorted` Vec assigned to `Screen::PolicyList { policies: sorted, selected: 0 }`
    If any are missing, report the deviation. Do NOT modify the functions.
  </action>
  <verify>
    <automated>
      grep -n "Char('n')" dlp-admin-cli/src/screens/dispatch.rs
      grep -n "sorted.sort_by" dlp-admin-cli/src/screens/dispatch.rs
      grep -n "to_lowercase()" dlp-admin-cli/src/screens/dispatch.rs
      grep -n "unwrap_or(u32::MAX)" dlp-admin-cli/src/screens/dispatch.rs
      grep -n "policies: sorted" dlp-admin-cli/src/screens/dispatch.rs
    </automated>
  </verify>
  <acceptance_criteria>
    - `grep -n "Char('n')" dlp-admin-cli/src/screens/dispatch.rs` returns the branch in `handle_policy_list`
    - `grep -n "sorted.sort_by" dlp-admin-cli/src/screens/dispatch.rs` returns the sort block
    - `grep -n "to_lowercase()" dlp-admin-cli/src/screens/dispatch.rs` returns the name tiebreak
    - `grep -n "unwrap_or(u32::MAX)" dlp-admin-cli/src/screens/dispatch.rs` returns two occurrences (priority extraction for a and b)
    - `grep -n "policies: sorted" dlp-admin-cli/src/screens/dispatch.rs` returns the assignment
  </acceptance_criteria>
  <done>Char('n') branch, client-side sort with priority+name tiebreak, and malformed-priority sinking are confirmed present.</done>
</task>

## Verification

After all tasks complete, run the build to confirm no regressions:

```bash
cargo build -p dlp-admin-cli 2>&1 | grep -i "error" | grep -v "warning:" | head -20
```

Expected: no compile errors.

Then run the test suite:

```bash
cargo test -p dlp-admin-cli 2>&1 | tail -5
```

Expected: all tests pass.

## Success Criteria

- All 5 columns in `draw_policy_list` confirmed (Priority/Name/Action/Enabled/Mode)
- `global_mode` parameter and `render_global_override_banner` confirmed
- `Char('n')` branch and client-side sort confirmed
- Build passes with no errors
- All tests pass

## Output

Create `.planning/phases/16-policy-list-simulate/16-01a-SUMMARY.md` when done.
