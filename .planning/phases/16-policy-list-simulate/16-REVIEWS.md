---
phase: 16
reviewers: [opencode]
reviewed_at: 2026-06-16T11:56:00Z
plans_reviewed: [16-01a-PLAN.md, 16-01b-PLAN.md, 16-02-PLAN.md]
---

# Cross-AI Plan Review — Phase 16, Cycle 2

## Reviewers
- **OpenCode** (gpt-5.3-chat-latest via GitHub Copilot) — reviewed against actual source code with grep verification
- **Codex** — unavailable (ChatGPT account restriction — no Codex API access)

---

## OpenCode Review

### 1. Summary

The cycle 1 HIGH concern ("stale column spec") is **resolved**. Plan 16-01a accurately documents the shipped 5-column PolicyList reality and its grep-based verification commands validate against actual code. Plan 16-01b correctly documents the existing Simulate foundation (including the truthful absence of a Loading variant). Plan 16-02 addresses the remaining MEDIUM/LOW items from cycle 1 (advanced section dropped, validation, normalization, error granularity) and aligns planning artifacts. However, a **new HIGH concern** is introduced: the Loading state implementation as designed will never be rendered to the user, making it dead code. The convergence loop is making progress but a cycle 3 will be needed to fix this flaw.

### 2. Strengths

- **16-01a column spec accuracy**: Correctly identifies 5-column reality with verified widths (12/38/15/12/23%), `global_mode: Option<&str>` parameter, and `render_global_override_banner` call. All must-haves truths are verifiable via `grep` against actual source code.
- **16-01b honest about current state**: Truths state `SimulateOutcome` has `None, Success, Error` variants — notably does NOT claim a Loading variant exists. This prevents confusion between current and target state.
- **16-02 explicit removal of "Advanced section"**: The plan explicitly documents why `timestamp_override`/`session_id_override` are being dropped (server auto-generates them), closing the MEDIUM concern from cycle 1 with clear reasoning.
- **Complete artifact alignment**: Task 0 in 16-02 comprehensively updates D-01, D-02, D-20, D-24, RESEARCH.md, PATTERNS.md, and creates VALIDATION.md. The planner recognized that documentation alignment is as important as code changes in a reopened review phase.
- **TDD annotations**: Both 16-02 Task 1 and Task 2 include `tdd="true"` with behavior specs before implementation, showing awareness of test-driven discipline.
- **Re-submission guard**: `handle_simulate_nav` loading guard prevents double-submits — correct pattern even if the Loading visualization is broken.

### 3. Concerns

| # | Concern | Severity | File | Detail |
|---|---------|----------|------|--------|
| 1 | **Loading state will never render** | **HIGH** | `16-02-PLAN.md` Task 1+2 | `action_submit_simulate` sets `*result = SimulateOutcome::Loading` then immediately calls `app.rt.block_on(post(...))`, which blocks the single-threaded ratatui event loop. The TUI only re-draws on the next iteration of the `draw → handle_event` loop, which happens AFTER `action_submit_simulate` returns — at which point the result is already `Success` or `Error`. **The Loading state will never be visible to the user.** The rendered yellow "Submitting..." block plus "please wait" hints are dead code. The plan does not address this: no explicit re-draw is triggered before `block_on`, and the app's `terminal` field (if accessible) is not used. |
| 2 | **Must-haves ambiguity (present tense for future state)** | **MEDIUM** | `16-02-PLAN.md` frontmatter | The `must_haves` truths use present tense: `"SimulateOutcome::Loading variant exists"`, `"Groups are normalized..."`. In 16-01a and 16-01b, must-haves truths describe current shipped state. In 16-02, they describe target state after execution. A reviewer or automated tool reading the frontmatter without the plan body will misinterpret these as false claims about the shipped code. Recommend prefixing future-state truths with `"After execution:"` or using separate `postconditions` key. |
| 3 | **D-01 column order typo in must-haves** | **LOW** | `16-02-PLAN.md:22` | Must-haves truth says `(Priority/Name/Action/Mode/Enabled)` but actual shipped code and the plan's own Task 0 step 1 specify `Priority, Name, Action, Enabled, Mode` — Mode and Enabled are transposed. The actual CONTEXT.md revision (Task 0 action) is correct, so the final artifact will be right, but the frontmatter creates a misleading signal. |
| 4 | **Loading state re-submission guard has wrong row constant** | **MEDIUM** | `16-02-PLAN.md:499-509` | The loading guard is placed at `SIMULATE_SUBMIT_ROW` which is `9` (the Enter-to-submit row). However, pressing Enter on non-submit rows triggers text-edit (for text fields) or cycle (for select fields). The plan correctly identifies `SIMULATE_SUBMIT_ROW` as row 9, so this is fine on re-read. **No issue.** *Retracted on further analysis.* |
| 5 | **Exception: Blocking call (#6) not addressed** | **LOW** | `16-02-PLAN.md` | The Loading addition is an attempt to address concern #6 ("TUI freezes during block_on"), but since the Loading state won't render during the blocking call, this concern is not actually addressed. The plan acknowledges the pattern is "consistent with codebase conventions" but does not document that the Loading mitigation is ineffective. |
| 6 | **Missing: Granular error testing** | **LOW** | `16-02-PLAN.md Task 2` | The test module covers group normalization (5 tests) but does NOT test validation or error classification. Behaviors 1 (empty user_sid), 2 (empty path), 7-11 (error prefixes) have no automated verification beyond grep. The `grep` for prefix strings is weak — it proves the strings exist in the source file but not that they're reached at the correct code path. |
| 7 | **Potential dependency hazard: Task ordering** | **LOW** | `16-02-PLAN.md` | Task 0 (planning artifact alignment) modifies .md files. Task 1+2 modify .rs files. These are independent and could run in parallel. The plan correctly separates them by wave, but the tasks could be parallelized for efficiency. |

### 4. Suggestions

1. **Fix the Loading state rendering (HIGH severity)** — Add an explicit terminal re-draw in `action_submit_simulate` before `block_on`:
   ```rust
   *result = SimulateOutcome::Loading;
   if let Some(terminal) = app.terminal.as_mut() {
       let _ = terminal.draw(|f| app.draw(f));
   }
   ```
   This forces the Loading frame to render before the blocking call. If `terminal` is not accessible from `action_submit_simulate`, expose it via `App::force_redraw()` or restructure `action_submit_simulate` to be async.

2. **Clarify must-haves semantics** — Add a comment in the frontmatter template: `# These are POSTCONDITIONS — truths that MUST hold after plan execution, not claims about current code.`

3. **Fix D-01 column order typo** — Change `(Priority/Name/Action/Mode/Enabled)` to `(Priority/Name/Action/Enabled/Mode)` in line 22 of 16-02-PLAN.md.

4. **Add validation + error classification tests** — Extend `simulate_tests` module with:
   - A test that calls a helper function (extracted from `action_submit_simulate`) with empty `user_sid` and asserts `Validation error:` prefix
   - A test that constructs timeout-like errors and asserts correct prefix mapping
   - These require extracting validation/error logic into testable helper functions, which is good practice anyway.

5. **Document Loading limitation explicitly** — Add a note in the plan or in the code that the Loading state rendering depends on the app architecture and may be a no-op if the TUI framework doesn't re-draw synchronously. This prevents future confusion when a developer wonders why the yellow box never appears.

6. **Accept the limitation as-is** — If explicit re-draw before `block_on` is deemed too invasive for this phase, consider removing the Loading visual entirely and replacing it with a simpler approach: disable the [Simulate] button during submission (the re-submission guard already does this). Document that concern #6 is deferred to a future refactoring phase (async event loop).

### 5. Risk Assessment

**Overall risk: MEDIUM** (borderline HIGH due to the Loading rendering flaw)

#### Convergence Analysis

| Cycle | Concerns | Status |
|-------|----------|--------|
| 1 | HIGH: stale column spec | → RESOLVED in cycle 2 |
| 1 | MEDIUM: advanced section | → RESOLVED (dropped) |
| 1 | MEDIUM: no Loading state | → PARTIALLY ADDRESSED (implemented but non-functional) |
| 1 | LOW: no validation | → ADDRESSED |
| 1 | LOW: group normalization | → ADDRESSED |
| 1 | LOW: blocking call | → NOT ADDRESSED (unchanged) |
| 1 | LOW: error classification | → ADDRESSED |

**The convergence loop IS making progress** — the HIGH concern is resolved, 4 LOW items are addressed. However:

- **The new HIGH concern (Loading won't render)** means cycle 3 is likely needed to fix this.
- The Loading implementation as specified will compile, pass tests, and pass grep verification, but will have **zero visual effect**. A casual observer running the verification commands would see all checks pass. Only runtime testing would reveal the problem.
- **Net risk verdict**: If the Loading rendering flaw is fixed (suggestion #1) before execution, this drops to LOW. If executed as-is, the plan introduces effective dead code that creates maintenance debt.

**Recommended**: Accept the plan with the condition that suggestion #1 (explicit re-draw before `block_on`) is implemented, or remove the Loading variant from scope and defer to a future async-refactoring phase.

---

## Consensus Summary

### Agreed Strengths
- Cycle 1 HIGH concern (stale column spec) is fully resolved — 16-01a accurately documents 5-column reality
- 16-01b is honest about current Simulate foundation state (no Loading variant claimed)
- 16-02 comprehensively addresses documentation alignment and closes 4 of 5 cycle 1 LOW/MEDIUM concerns
- TDD annotations and re-submission guard show good engineering discipline

### Agreed Concerns
- **NEW HIGH: Loading state will never render** — `block_on` blocks the ratatui event loop before any re-draw can occur. The yellow "Submitting..." block is dead code. This is a significant architectural oversight in the 16-02 plan.
- **MEDIUM: Must-haves ambiguity** — 16-02 frontmatter uses present tense for postconditions, creating confusion between current and target state
- **LOW: D-01 column order typo** in 16-02 frontmatter (Mode/Enabled transposed)
- **LOW: Missing validation and error classification tests** — only group normalization has unit tests

### Divergent Views
- None significant. OpenCode is the sole reviewer (Codex unavailable). The review is based on direct source code inspection (grep + read) and is internally consistent.

---

## Cycle 2 vs Cycle 1 Comparison

| Concern | Cycle 1 Severity | Cycle 2 Status |
|---------|-----------------|----------------|
| Stale column spec (4 vs 5 columns) | HIGH | **RESOLVED** — 16-01a correctly documents 5-column reality |
| Advanced section not implemented | MEDIUM | **RESOLVED** — explicitly dropped from 16-02 with reasoning |
| No Loading state | MEDIUM | **PARTIALLY ADDRESSED** — plan adds Loading variant but it will never render (new HIGH) |
| No client-side validation | LOW | **ADDRESSED** — 16-02 Task 2 adds validation for empty user_sid and path |
| Group normalization incomplete | LOW | **ADDRESSED** — 16-02 Task 2 adds dedupe + lowercase |
| Blocking call in TUI event loop | LOW | **NOT ADDRESSED** — unchanged; Loading attempt is ineffective |
| Network error classification | LOW | **ADDRESSED** — 16-02 Task 2 adds timeout/connection/decode/server granularity |

**Unresolved HIGH count: 1** (new Loading rendering flaw)

---

*Review generated: 2026-06-16*
*Reviewers: OpenCode (gpt-5.3-chat-latest via GitHub Copilot)*
*Codex: unavailable (ChatGPT account restriction — no Codex API access)*
