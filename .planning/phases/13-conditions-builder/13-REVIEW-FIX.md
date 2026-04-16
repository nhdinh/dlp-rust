---
phase: 13-conditions-builder
fixed_at: 2026-04-16T18:10:00Z
review_path: .planning/phases/13-conditions-builder/13-REVIEW.md
iteration: 1
findings_in_scope: 4
fixed: 3
skipped: 1
status: partial
---

# Phase 13: Code Review Fix Report

**Fixed at:** 2026-04-16T18:10:00Z
**Source review:** `.planning/phases/13-conditions-builder/13-REVIEW.md`
**Iteration:** 1

**Summary:**
- Findings in scope: 4 (WR-01, WR-02, WR-03, WR-04)
- Fixed: 3 (WR-01, WR-02, WR-04)
- Skipped: 1 (WR-03)

## Fixed Issues

### WR-01: Potential underflow panic in Step 2 / Step 3 up-arrow

**Files modified:** `dlp-admin-cli/src/screens/dispatch.rs`
**Commit:** c628eb6
**Applied fix:**
- `handle_conditions_step2`: added `if ops.is_empty() { return; }` guard before the `ops.len() - 1` subtraction inside the `Up | Down` branch, placed immediately after reading `current` so the guard fires before the match arm.
- `handle_conditions_step3_select`: added `if count == 0 { return; }` guard at the top of the `Up | Down` branch, before entering the `if let Screen::ConditionsBuilder` block, preventing underflow on the `count - 1` path.

---

### WR-02: Unchecked array index `ATTRIBUTES[idx]` in Step 1 Enter handler

**Files modified:** `dlp-admin-cli/src/screens/dispatch.rs`
**Commit:** c628eb6 (committed together with WR-01 — both touch dispatch.rs)
**Applied fix:** Replaced `*selected_attribute = Some(ATTRIBUTES[idx])` with a bounds-checked call to `ATTRIBUTES.get(idx).copied().unwrap_or(ConditionAttribute::Classification)`, then wrapped the result in `Some(attr)`. Falls back to `Classification` for any out-of-range index rather than panicking.

---

### WR-04: Heap allocation on every render tick for divider string

**Files modified:** `dlp-admin-cli/src/screens/render.rs`
**Commit:** 1d878f3
**Applied fix:** Replaced the `Paragraph::new(Line::styled("-".repeat(inner.width as usize), ...))` divider widget with `Block::default().borders(Borders::TOP).border_style(Style::default().fg(Color::DarkGray))`. Ratatui draws the top border line internally using its own cell-based renderer — no `String` allocation occurs on the render hot path.

## Skipped Issues

### WR-03: Unnecessary `Vec` clone in `handle_policy_list` and `handle_agent_list`

**File:** `dlp-admin-cli/src/screens/dispatch.rs:401`
**Reason:** Pre-existing code outside Phase 13 scope. The REVIEW.md finding explicitly states this is pre-existing code not introduced by Phase 13. Per the fix instructions, this finding must not be modified to keep changes scoped to Phase 13 work.
**Original issue:** `handle_policy_list` and `handle_agent_list` clone the entire `Vec<serde_json::Value>` via `policies.clone()` / `agents.clone()` on every key press to satisfy the borrow checker. The two-phase read-then-mutate pattern would eliminate the clone. Deferred to a future cleanup phase.

---

_Fixed: 2026-04-16T18:10:00Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
