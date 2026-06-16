---
phase: 16-policy-list-simulate
reviewed: 2026-06-16T00:00:00Z
depth: standard
files_reviewed: 4
files_reviewed_list:
  - dlp-admin-cli/src/app.rs
  - dlp-admin-cli/src/main.rs
  - dlp-admin-cli/src/screens/dispatch.rs
  - dlp-admin-cli/src/screens/render.rs
findings:
  critical: 0
  warning: 2
  info: 1
  total: 3
status: issues_found_resolved_critical
---

# Phase 16: Code Review Report

**Reviewed:** 2026-06-16
**Depth:** standard
**Files Reviewed:** 4
**Status:** issues_found

## Summary

Reviewed the Phase 16 (policy-list-simulate) changes across `app.rs`, `main.rs`, `dispatch.rs`, and `render.rs`. Focus areas were the `SimulateOutcome::Loading` variant, `App.terminal` ownership transfer, `action_submit_simulate` validation/redraw/loading guard, and `handle_simulate_nav` changes.

One critical correctness bug was found in `simulate_return_to_caller` routing from MainMenu. Two warnings concern the `Loading` forced-redraw pattern and a stale `SimulateOutcome::None` state after form reset. One info-level item notes a dead `#[allow(dead_code)]` on `SIMULATE_SUBMIT_ROW`.

## Critical Issues

### CR-01: `simulate_return_to_caller` routes to wrong MainMenu index

**File:** `dlp-admin-cli/src/screens/dispatch.rs:3123`
**Issue:** When returning from `PolicySimulate` opened via `SimulateCaller::MainMenu`, the function sets `Screen::MainMenu { selected: 3 }`. Index 3 in the MainMenu is "Label Management" (added in an earlier phase). The correct index for "Simulate Policy" is 5. This means pressing Esc or 'q' from the Simulate screen returns the user to the wrong menu item (Label Management instead of Simulate Policy), which is a navigation correctness bug.

**Fix:**
```rust
SimulateCaller::MainMenu => app.screen = Screen::MainMenu { selected: 5 },
```

**Resolution:** Fixed in `dlp-admin-cli/src/screens/dispatch.rs` and verified with two unit tests (`test_simulate_esc_returns_to_main_menu_simulate_policy_index`, `test_simulate_esc_returns_to_policy_menu_simulate_policy_index`). The simulate tests module was also moved out of `protected_path_tests` into its own `simulate_tests` module so the tests are discoverable by `cargo test`.

## Warnings

### WR-01: `action_submit_simulate` forced redraw is fragile and may panic on `None`

**File:** `dlp-admin-cli/src/screens/dispatch.rs:2955-2958`
**Issue:** The forced redraw to show `Loading` uses `app.terminal.take()` and unconditionally reassigns `Some(terminal)`. If `app.terminal` is `None` (e.g., if the TUI loop has already started cleanup or if a previous take failed to restore), the `if let Some(mut terminal)` silently skips the redraw. However, the bigger issue is that `terminal.draw(|frame| crate::screens::draw(&*app, frame))` borrows `app` immutably while `app.screen` is in `Loading` state. If `draw` tries to access `app.terminal` (which is `None` during this call), any downstream code that unwraps `app.terminal` will panic. The current code happens to not access `terminal` inside `draw`, but this is a latent footgun: adding a new screen that reads `app.terminal` during draw will cause a panic.

Additionally, the `let _ = terminal.draw(...)` silently discards any draw error. A terminal I/O error here means the user sees no visual feedback that submission started.

**Fix:**
1. Document the invariant that `draw` must never access `app.terminal`.
2. Or, better: pass the terminal as an explicit parameter to the draw closure instead of storing it in `App`, removing the ownership dance entirely.
3. Do not silently discard the draw result: `if let Err(e) = terminal.draw(...) { tracing::warn!("Forced redraw failed: {e}"); }`.

### WR-02: `action_open_simulate` resets `result` to `None` but does not clear a stale `SimulateOutcome::Error` from a previous session

**File:** `dlp-admin-cli/src/screens/dispatch.rs:2815-2824`
**Issue:** `action_open_simulate` correctly initializes `result: SimulateOutcome::None` when opening a fresh simulate screen. However, if the user navigates away from `PolicySimulate` via Esc (which calls `simulate_return_to_caller`) and then re-opens simulate, the screen is reconstructed from scratch, so this is fine. But if in the future the screen is reused (e.g., a "back" action that preserves form state), the `None` reset would be lost. More importantly, within the same `PolicySimulate` session, if the user submits, gets an `Error`, edits a field, and submits again, the `action_submit_simulate` function sets `result = Loading` before the blocking call, which is correct. However, there is no guard in `handle_simulate_nav` to prevent the user from pressing Enter on the `[Simulate]` row while already `Loading` — the code does check `is_loading` and skips the call, but the UX is silent (no feedback). The user might think the keypress was lost.

**Fix:** Add a brief status message when the submission is blocked due to an in-flight request:
```rust
if is_loading {
    app.set_status("Request already in flight...", StatusKind::Info);
} else {
    action_submit_simulate(app);
}
```

## Info

### IN-01: `SIMULATE_SUBMIT_ROW` is declared but never referenced outside tests

**File:** `dlp-admin-cli/src/app.rs:431-432`
**Issue:** `SIMULATE_SUBMIT_ROW` is defined as `pub const SIMULATE_SUBMIT_ROW: usize = 9;` with `#[allow(dead_code)]`. In `dispatch.rs`, `handle_simulate_nav` uses the literal `SIMULATE_SUBMIT_ROW` (line 3152), but `SIMULATE_SUBMIT_ROW` is actually imported and used. Wait — checking again: `handle_simulate_nav` at line 3152 uses `SIMULATE_SUBMIT_ROW`, which is imported at the top of `dispatch.rs`. So it IS used. The `#[allow(dead_code)]` on the declaration in `app.rs` is therefore unnecessary and misleading — it suggests the constant is unused when it is actually consumed by `dispatch.rs`.

**Fix:** Remove the `#[allow(dead_code)]` attribute from `SIMULATE_SUBMIT_ROW` in `app.rs`.

---

_Reviewed: 2026-06-16_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
