---
phase: 16
reviewers: [codex, opencode]
reviewed_at: 2026-06-16T11:15:00Z
plans_reviewed: [16-01-PLAN.md, 16-02-PLAN.md]
---

# Cross-AI Plan Review — Phase 16

## Codex Review

Codex CLI (v0.130.0) was selected but could not be invoked. The configured default model (`gpt-5.3-codex`) and all fallback models (`gpt-5`, `gpt-5.5`, `gpt-5.4`, `gpt-5.4-mini`) returned:

```
ERROR: {"type":"error","status":400,"error":{"type":"invalid_request_error","message":"The 'gpt-5.3-codex' model is not supported when using Codex with a ChatGPT account."}}
```

This account appears to be a ChatGPT Plus/Team subscription without Codex API access. The available models in the Codex cache (`gpt-5.5`, `gpt-5.4`, `gpt-5.4-mini`, `codex-auto-review`) all require OpenAI API billing. To enable Codex reviews, upgrade to OpenAI API billing or configure a valid API key with Codex model access.

---

## OpenCode Review

### Plan 16-01 Review

#### Summary

Both plans are well-structured with clear wave separation (Wave 1 = types + PolicyList, Wave 2 = simulate implementation). However, the plans contain multiple deviations from what actually shipped — most notably the persistent **Mode column** and the **missing Advanced section** and **Loading state**. The plans are good at the architectural level but over-promise some features (advanced fields, validation, Loading state) that were dropped without documented deviations.

#### Strengths

- **Clean Wave 1 / Wave 2 split** — sharing types (`SimulateFormState`, `SimulateCaller`, `SimulateOutcome`) before render/dispatch code prevents circular dependencies.
- **`SimulateCaller` enum for Esc routing** — correct pattern (matches `CallerScreen`, `ImportCaller`, `TierPickerCaller`). Correct return indices: MainMenu `{ selected: 3 }`, PolicyMenu `{ selected: 5 }`.
- **`EDITABLE_TO_RENDER` lookup table** — correctly maps the 10 editable indices to 14 render positions with section headers interleaved. Good coupling of render and dispatch.
- **Client-side sort in `action_list_policies`** — sort-once-per-fetch pattern per D-06, malformed priority as `u32::MAX` per D-07.
- **Error classification** — distinguishing reqwest transport errors from HTTP errors is correct.
- **`'n'` key in PolicyList** — correctly navigates to PolicyCreate, which the plan correctly identified as missing.

#### Concerns

| # | Concern | Severity | Detail |
|---|---------|----------|--------|
| 1 | **Stale column spec** | **HIGH** | Plan says 4 columns (Priority/Name/Action/Enabled) with widths 15/45/20/20%. Shipped code has **5 columns** including Mode (enforcement_mode) with widths 12/38/15/12/23%. Plan did not account for the enforcement_mode column that Phase 15 added to the data model. Either the plan should drop the Mode column per D-01, or the shipped code should not have it — there's a mismatch. |
| 2 | **"Advanced section" not implemented** | **MEDIUM** | D-11 and Plan 16-02 describe `timestamp_override`, `session_id_override`, and `advanced_visible` toggle. The `Environment` struct has no such fields, `SimulateFormState` has no such fields, and `action_submit_simulate` hardcodes `chrono::Utc::now()` and `session_id: 0`. These fields do not exist on the wire. Plan over-promises or assumes server-side work that wasn't authorized (D-12 already says "no server-side work required"). |
| 3 | **No Loading state** | **MEDIUM** | Plan 16-02 says "Loading state: SimulateOutcome::Loading". The shipped `SimulateOutcome` enum only has `None`, `Success`, `Error`. No Loading rendering exists. During `block_on` the TUI freezes with no spinner — a UX gap the plan identified but didn't deliver. |
| 4 | **No client-side validation** | **LOW** | Plan 16-02 mentions "Validation: required fields, length caps, group normalization". `action_submit_simulate` does zero pre-validation — it directly builds `EvaluateRequest` and POSTs. Server-side validation per D-09 is correct, but empty `user_sid` sending an empty string to the server would be better caught client-side. |
| 5 | **Group normalization not implemented** | **LOW** | D-10 specifies: comma-separated, trim, dedupe, lowercase, preserve order. The code only does `split(',')`, `trim()`, and `filter(empty)` — no dedupe or lowercase. |
| 6 | **Blocking call in `action_submit_simulate`** | **LOW** | `app.rt.block_on(post(...))` blocks the TUI event loop for the full HTTP round-trip. Existing pattern (same as all other actions), but a 10s timeout means the TUI is unresponsive for up to 10 seconds. Not a blocker — consistent with codebase conventions. |
| 7 | **Network error classification** | **LOW** | Plan mentions "timeout, connection, decode, server" — shipped code only distinguishes `reqwest::Error` (network) from `anyhow::Error` (server). The classification is coarser than planned. |

#### Suggestions

1. **Document the Mode column as a deliberate deviation** — The shipped 5-column PolicyList (with Mode) works well and matches what admins see in PolicyCreate/PolicyEdit. Either update the plan to include Mode or update the code to remove it. Given the enforcement-mode banner feature, keeping Mode in the table is arguably correct — but the plan should reflect this.

2. **Drop the "Advanced section" from the plan** — Since `timestamp` and `session_id` are not settable via the wire API (they're endpoint-generated), the Advanced section can't work without server changes. Remove D-11 from CONTEXT.md or flag it as deferred.

3. **Add a working/loading indicator** — Even a simple `"Sending request..."` status bar message on submit would be an improvement over the silent freeze. The pattern exists: `action_submit_simulate` could set a status message before `block_on`.

4. **Implement group normalization fully** — Dedupe and lowercase are trivial (`groups.dedup()` and `.to_lowercase()`) and would make D-10 match the code.

5. **Add empty-field guard for user_sid** — A 3-line check before building the request. Not critical (server returns 400), but better UX per the plan's stated validation intent.

#### Risk Assessment

**Overall risk: MEDIUM**

The shipped code is functional and UAT-passed (11/11). The risks are about **plan accuracy and completeness** rather than implementation bugs. Two HIGH concerns exist:

1. The column spec mismatch (plan says 4 columns, code has 5) means the plan is an unreliable source of truth for PolicyList structure.
2. The Advanced section was fully planned (D-11, Plan 16-02) but completely absent from the shipped code without being marked as a deviation in SUMMARY.md. This creates confusion for future phases that might depend on it.

Both concerns are documentation/alignment issues, not runtime bugs. The plan structure (Wave 1/2 split, shared types, caller routing) was effective and well-executed.

---

## Consensus Summary

### Agreed Strengths
- Clean wave-based separation (Wave 1 types/scaffolding, Wave 2 full implementation)
- Reuses existing server endpoint (`/evaluate`) and ABAC types without backend changes
- Keyboard interaction model is consistent with prior phases (Phase 14/15 patterns)
- Inline result rendering is user-friendly
- Good separation of editing vs navigation modes
- `SimulateCaller` enum for Esc routing is clean and correct
- Client-side sort with malformed priority handling is well-designed

### Agreed Concerns
- **Plan staleness vs. shipped code (HIGH)** — The column spec in the plan (4 columns) does not match the shipped code (5 columns with Mode). This is a documentation/alignment gap.
- **Advanced section planned but not implemented (MEDIUM)** — D-11 and Plan 16-02 describe `timestamp_override`, `session_id_override`, and `advanced_visible` toggle, but these fields do not exist in the shipped code. The plan over-promised features that were not delivered.
- **No Loading state (MEDIUM)** — Plan 16-02 specifies `SimulateOutcome::Loading`, but the shipped `SimulateOutcome` enum only has `None`, `Success`, `Error`. The TUI freezes during the blocking HTTP call with no visual feedback.
- **Group normalization incomplete (LOW)** — D-10 specifies trim, dedupe, lowercase, preserve order, but the code only does `split(',')`, `trim()`, and `filter(empty)` — no dedupe or lowercase.
- **Blocking HTTP call in TUI event loop (LOW)** — `app.rt.block_on(post(...))` blocks the TUI for the full HTTP round-trip. Consistent with codebase conventions but a UX gap.

### Divergent Views
- None significant in this cycle. OpenCode reviewed against the shipped codebase and found plan/code deviations. Codex was unavailable.

---

*Review generated: 2026-06-16*
*Reviewers: OpenCode (gpt-5.3-chat-latest via GitHub Copilot)*
*Codex: unavailable (ChatGPT account restriction — no Codex API access)*
