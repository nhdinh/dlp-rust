---
phase: 16
reviewers: [opencode]
reviewed_at: 2026-06-16T12:13:00Z
plans_reviewed: [16-01a-PLAN.md, 16-01b-PLAN.md, 16-02-PLAN.md]
---

# Cross-AI Plan Review — Phase 16, Cycle 3 (Final)

## Reviewers
- **OpenCode** (gpt-5.3-chat-latest via GitHub Copilot) — reviewed against actual source code with grep verification
- **Codex** — unavailable (ChatGPT account restriction — no Codex API access)

---

## OpenCode Review

### 1. Summary

The Cycle 3 revisions resolve all previous HIGH concerns. **Plan 16-01a** correctly verifies the 5-column PolicyList against actual source code via grep assertions — the Cycle 1 column spec concern is definitively closed. **Plan 16-01b** accurately documents the existing Simulate foundation. **Plan 16-02** delivers the critical architectural fix for the Loading state (terminal ownership restructuring + forced redraw before `block_on`), plus validation, normalization, granular errors, and aligned planning artifacts. The plans are substantially complete and ready for execution with only minor residual concerns.

### 2. Strengths

- **Loading state HIGH resolved (Cycle 2 → 3).** The take/draw/restore pattern (`app.terminal.take() → terminal.draw(...) → app.terminal = Some(terminal)`) avoids borrow checker conflicts and forces a synchronous redraw of the `SimulateOutcome::Loading` frame before `block_on(post)` blocks the thread. The user WILL see "Submitting..." during the HTTP request. Verified: `screens::draw` at `render.rs:44` takes `&App`, the forced redraw passes `&*app` (reborrow from `&mut App`), and the terminal is restored before `block_on`.

- **Column spec HIGH resolved (Cycle 1 → 2).** Plan 16-01a correctly specifies 5 columns (Priority/Name/Action/Enabled/Mode) with verified widths 12/38/15/12/23%, `global_mode: Option<&str>`, and `render_global_override_banner`. All grep assertions target actual shipped code.

- **Must-haves ambiguity fixed.** All future-state truths in 16-02 frontmatter now use the `"After execution:"` prefix, eliminating the confusion between current and target state identified in Cycle 2.

- **D-01 column order typo fixed.** Frontmatter truth now reads `Priority/Name/Action/Enabled/Mode` (correct order matching shipped code).

- **Re-submission guard is correct.** The `is_loading` guard in `handle_simulate_nav` prevents double-fire by checking `SimulateOutcome::Loading` before calling `action_submit_simulate`.

- **Tests for validation and normalization are solid.** 5 group normalization tests and 5 validation tests with realistic edge cases (empty input, whitespace, dedupe order preservation).

- **Planning artifact alignment is comprehensive.** All 4 context decisions, research questions, patterns, and validation strategy are updated to match shipped reality.

### 3. Concerns

| # | Concern | Severity | File | Detail |
|---|---------|----------|------|--------|
| 1 | **Error propagation in take/draw/restore can lose terminal** | **MEDIUM** | `16-02-PLAN.md` Task 1, main.rs | The event loop does: `terminal.draw(...)?; app.terminal = Some(terminal)`. If `terminal.draw()` returns `Err`, the `?` propagates before restoring the terminal to `app.terminal`. The outer recovery code then calls `app.terminal.take().unwrap()` which panics on `None`. **Fix:** swap ordering to `let r = terminal.draw(...); app.terminal = Some(terminal); r?;` — restore first, propagate second. |
| 2 | **`#[allow(dead_code)]` on `SIMULATE_SUBMIT_ROW` becomes stale** | **LOW** | `dlp-admin-cli/src/app.rs:431` | Currently `SIMULATE_SUBMIT_ROW` has `#[allow(dead_code)]`. Task 2 plans to use it in `handle_simulate_nav` (replacing magic number `9`). The annotation should be removed. Harmless but untidy. |
| 3 | **Error classification tests are compile-check only, not runtime** | **LOW** | `16-02-PLAN.md` Task 2, `simulate_tests` | `test_error_prefix_timeout` uses a closure that instantiates the function pointer but never calls it with a real `reqwest::Error`. The comment acknowledges this. The grep assertions for `"Timeout: "`, `"Connection error: "` etc. prove string existence but not that the correct code path selects each prefix. This is an honest limitation (can't easily construct `reqwest::Error` in unit tests) but should be documented in the test module. |
| 4 | **Loading flash duration depends on network latency** | **LOW** | 16-02-PLAN.md | For localhost requests (~1-5ms), the Loading state renders for exactly one forced redraw before the outcome resolves. On fast servers, the user may see a sub-100ms flash. This is expected and correct — the Loading state is most useful when the server is slow or the network is congested. Not a bug, but worth noting in the code comment. |
| 5 | **No test for re-submission guard** | **LOW** | 16-02-PLAN.md Task 2 | The `is_loading` guard has no unit test (requires constructing a `Screen::PolicySimulate` with `SimulateOutcome::Loading`). Could be added via a helper that constructs the state directly. |

### 4. Suggestions

1. **Fix the error propagation gap (Concern #1)** — Change the main.rs event loop take/draw/restore to:
   ```rust
   let mut terminal = app.terminal.take().unwrap();
   let draw_result = terminal.draw(|frame| screens::draw(&app, frame));
   app.terminal = Some(terminal);
   draw_result?;
   ```

2. **Remove `#[allow(dead_code)]` from `SIMULATE_SUBMIT_ROW`** — Trivial fix, include in Task 1 or as a note in the plan.

3. **Add a code comment explaining Loading visibility** — Add a note above the forced redraw: `// Force terminal redraw so "Submitting..." is visible to the user before block_on blocks the thread.`

4. **Document the error test limitation** — Add `// NOTE: This test verifies compile-time correctness only. Runtime error classification is tested via integration testing with a real server.` above the error classification test.

5. **Consider adding a re-submission guard test using `SimulateFormState` construction** — Trivial to construct `Screen::PolicySimulate { result: SimulateOutcome::Loading, .. }` and verify `action_submit_simulate` is not called.

### 5. Risk Assessment

**Overall risk: LOW** — Ready for execution.

#### Convergence Analysis

| Concern | Cycle 1 | Cycle 2 | Cycle 3 |
|---------|---------|---------|---------|
| Stale column spec (4 vs 5 cols) | HIGH | RESOLVED | ✅ RESOLVED |
| Advanced section not implementable | MEDIUM | RESOLVED | ✅ RESOLVED |
| No Loading state | MEDIUM | HIGH (won't render) | ✅ **RESOLVED** (forced redraw) |
| No client-side validation | LOW | ADDRESSED | ✅ ADDRESSED |
| Group normalization incomplete | LOW | ADDRESSED | ✅ ADDRESSED |
| Blocking call in TUI loop | LOW | NOT ADDRESSED | ⚠️ PARTIALLY ADDRESSED (Loading visual mitigates, but not fixed) |
| Error classification missing | LOW | ADDRESSED | ✅ ADDRESSED |
| Must-haves ambiguity | — | MEDIUM | ✅ FIXED |
| D-01 column order typo | — | LOW | ✅ FIXED |
| Missing validation tests | — | LOW | ✅ ADDRESSED |
| New: Error propagation gap | — | — | ⚠️ MEDIUM (suggestion #1 fixes) |

**The convergence loop is complete.** Two cycles of feedback have brought all HIGH/MEDIUM concerns to resolution. The remaining items are:
- 1 MEDIUM (error propagation in event loop — easy fix, suggestion #1)
- 3 LOW (stale annotation, error test limitation, no re-submission test)
- 1 LOW (blocking call — acknowledged limitation, not addressed)

**Verdict:** Accept with condition that suggestion #1 (error propagation fix) is implemented. The plans are executable and the remaining concerns do not block execution.

---

## Consensus Summary

### Agreed Strengths
- Cycle 1 HIGH concern (stale column spec) is fully resolved — 16-01a accurately documents 5-column reality
- Cycle 2 HIGH concern (Loading won't render) is fully resolved — the forced redraw approach (terminal ownership + explicit draw before block_on) correctly renders the Loading state
- 16-01b is honest about current Simulate foundation state (no Loading variant claimed in Wave 1)
- 16-02 comprehensively addresses documentation alignment and closes all cycle 1 LOW/MEDIUM concerns
- TDD annotations and re-submission guard show good engineering discipline
- Must-haves ambiguity fixed with "After execution:" prefix
- Validation and error classification tests added in Task 2

### Agreed Concerns
- **MEDIUM: Error propagation in take/draw/restore** — If `terminal.draw()` returns `Err`, the `?` propagates before restoring terminal to `app.terminal`, causing panic in outer recovery. Fix: restore first, then propagate.
- **LOW: `#[allow(dead_code)]` on `SIMULATE_SUBMIT_ROW`** becomes stale when Task 2 uses it
- **LOW: Error classification tests are compile-check only** — no runtime verification with real `reqwest::Error`
- **LOW: Loading flash duration** — fast localhost requests may show sub-100ms flash; expected behavior
- **LOW: No test for re-submission guard** — `is_loading` guard lacks unit test

### Divergent Views
- None significant. OpenCode is the sole reviewer (Codex unavailable). The review is based on direct source code inspection (grep + read) and is internally consistent.

---

## Cycle 3 vs Cycle 2 Comparison

| Concern | Cycle 2 Severity | Cycle 3 Status |
|---------|----------------|----------------|
| Stale column spec (4 vs 5 columns) | RESOLVED | ✅ RESOLVED (unchanged) |
| Advanced section not implemented | RESOLVED | ✅ RESOLVED (unchanged) |
| Loading state will never render | **HIGH** | ✅ **RESOLVED** — forced redraw approach works; user WILL see "Submitting..." |
| No client-side validation | ADDRESSED | ✅ ADDRESSED (unchanged) |
| Group normalization incomplete | ADDRESSED | ✅ ADDRESSED (unchanged) |
| Blocking call in TUI event loop | NOT ADDRESSED | ⚠️ PARTIALLY ADDRESSED (Loading visual mitigates) |
| Error classification missing | ADDRESSED | ✅ ADDRESSED (unchanged) |
| Must-haves ambiguity | MEDIUM | ✅ FIXED (unchanged) |
| D-01 column order typo | LOW | ✅ FIXED (unchanged) |
| Missing validation tests | LOW | ✅ ADDRESSED (unchanged) |
| Error propagation gap | — | ⚠️ **NEW MEDIUM** — terminal not restored if draw() fails before `?` |

**Unresolved HIGH count: 0**

---

*Review generated: 2026-06-16*
*Reviewers: OpenCode (gpt-5.3-chat-latest via GitHub Copilot)*
*Codex: unavailable (ChatGPT account restriction — no Codex API access)*
