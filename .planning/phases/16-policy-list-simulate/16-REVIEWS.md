---
phase: 16
reviewers: [opencode]
reviewed_at: 2026-06-05T08:18:23Z
plans_reviewed: [16-01-PLAN.md, 16-02-PLAN.md]
---

# Cross-AI Plan Review — Phase 16

## OpenCode Review

### Plan 16-01 Review

#### Summary
This is a clean, well-scoped Wave 1 plan that focuses on structural groundwork and UI polish without overreaching. It correctly isolates shared types, fixes known inconsistencies in the policy list UI, and prepares the simulate feature without prematurely implementing behavior. The sequencing is logical and aligns with minimizing risk while unblocking Wave 2.

#### Strengths
- Clear separation of concerns: shared types moved into `simulate.rs` instead of bloating `app.rs`
- Incremental delivery: stubbed simulate screen avoids partial/fragile implementation
- Sorting logic is explicitly defined and deterministic (priority + case-insensitive name)
- Handles malformed priority defensively (`u32::MAX` + logging + "ERR" rendering)
- Navigation fixes (menu counts) address known bugs from research
- Explicit UX decisions (column widths, Yes/No rendering) reduce ambiguity
- Selection reset after sort avoids invalid index bugs
- No unnecessary server coupling — respects existing `/evaluate`

#### Concerns
- MEDIUM: Sorting stability not explicitly guaranteed
  - Rust's `sort_by` is unstable; if equal keys exist, ordering may flicker
- LOW: Logging malformed priorities on every render could spam logs if not cached
- LOW: Adding `chrono` dependency early but only used in Wave 2 introduces minor unused dep window
- LOW: Extracting types to `simulate.rs` before full usage may lead to minor churn if Wave 2 changes shape

#### Suggestions
- Use `sort_by_key` + `then_with` or explicitly call `sort_by` with stable alternative (`sort_by` + documented acceptance, or `sort_by_stable` if available via slice API)
- Consider precomputing parsed priority once during fetch instead of parsing during render/sort repeatedly
- Gate malformed priority logging to occur only once per policy (e.g., during fetch or parse), not per draw
- If `chrono` is only used in Wave 2, consider adding it there unless it's needed for type definitions now

#### Risk Assessment
LOW — The plan is straightforward, bounded in scope, and primarily UI/state work. Risks are minor and mostly around polish rather than correctness.

---

### Plan 16-02 Review

#### Summary
This plan is comprehensive and thoughtfully incorporates prior feedback, covering validation, UX states, and error handling in detail. It delivers full functionality for policy simulation with strong attention to edge cases and user experience. However, there are a few Rust async concerns and TUI state complexities that could introduce subtle bugs if not handled carefully.

#### Strengths
- Strong validation layer (length caps, required fields, normalization)
- Thoughtful handling of groups input (dedupe, limits, normalization)
- Explicit Loading state prevents UI ambiguity during requests
- Granular error classification improves operator debugging
- Advanced mode for reproducibility is a solid design decision
- Clear separation of editing vs navigation modes
- Deterministic mapping from UI indices to ABAC enums
- Inline result rendering avoids context switching
- Reuses existing `/evaluate` endpoint cleanly

#### Concerns
- HIGH: Blocking POST in async/TUI context
  - If using a synchronous HTTP client inside the event loop, UI may freeze
  - Tokio requires either async client or `spawn_blocking`
- HIGH: State explosion in `SimulateFormState`
  - Many fields + modes (editing/nav/loading/advanced) increase risk of inconsistent transitions
- MEDIUM: Cursor/editing UX edge cases
  - No mention of handling backspace, delete, arrow keys, or multi-byte chars
- MEDIUM: Groups normalization using `HashSet` loses order
  - May confuse users if output differs from input order
- MEDIUM: Validation timing unclear
  - If validation only occurs on submit, user may repeatedly hit errors without guidance
- MEDIUM: Timestamp parsing (ISO 8601)
  - Rust chrono parsing is strict; user input errors likely frequent without format hinting
- LOW: Large input caps (4096 groups string) could impact rendering performance in TUI
- LOW: Error classification may overfit vs actual HTTP client error types

#### Suggestions
- Use an async HTTP client (`reqwest::Client`) and `await` inside an async action, or explicitly wrap in `tokio::spawn` to avoid blocking UI
- Introduce a simple state enum for form mode:
  - `enum FormMode { Navigating, Editing(field), Loading }`
  - This reduces inconsistent flag combinations
- Preserve group order while deduping:
  - Use `IndexSet` instead of `HashSet`
- Add inline validation feedback before submit:
  - e.g., mark required fields as invalid during editing
- Provide timestamp format hint in UI:
  - Example: `2026-04-20T15:04:05Z`
- Cap rendered string lengths (truncate with `...`) to avoid layout breakage
- Centralize enum mappings (DeviceTrust, NetworkLocation, etc.) into static arrays to avoid duplication bugs
- Consider debouncing or disabling submit while already in Loading state

#### Risk Assessment
MEDIUM — The feature is well-designed but has real risk around async handling and UI state complexity. If blocking calls or inconsistent state transitions slip through, the user experience could degrade (freezes, incorrect rendering, or stuck states). These are fixable with careful implementation discipline.

---

## Codex Review

Codex CLI (v0.130.0) was selected but could not be invoked. The configured default model (`gpt-5.3-codex`) and all fallback models (`o4-mini`, `gpt-4.1`, `gpt-4o`, `gpt-4o-mini`) returned:

```
ERROR: {"type":"error","status":400,"error":{"type":"invalid_request_error","message":"The 'X' model is not supported when using Codex with a ChatGPT account."}}
```

This account appears to be a ChatGPT Plus/Team subscription without Codex API access. To enable Codex reviews, upgrade to OpenAI API billing or configure a valid API key with Codex model access.

---

## Consensus Summary

### Agreed Strengths
- Clean wave-based separation (Wave 1 types/scaffolding, Wave 2 full implementation)
- Reuses existing server endpoint (`/evaluate`) and ABAC types without backend changes
- Keyboard interaction model is consistent with prior phases (Phase 14/15 patterns)
- Inline result rendering is user-friendly
- Good separation of editing vs navigation modes
- Strong validation layer with length caps and input normalization
- Explicit Loading state prevents UI ambiguity during requests

### Agreed Concerns
- **Blocking POST in TUI event loop (HIGH)** — `app.rt.block_on(...)` inside the key handler freezes the TUI until the server responds. The `ratatui` event loop runs on the same thread; blocking it prevents redraws and makes the app feel unresponsive.
- **State explosion in SimulateFormState (HIGH)** — The combination of `selected`, `editing`, `buffer`, `result`, `advanced_visible`, and per-field values creates many invalid state combinations. A dedicated form-mode enum would reduce this surface.
- **Groups normalization loses order (MEDIUM)** — `HashSet` deduplication drops the user's original input order, which may confuse operators.
- **Validation timing (MEDIUM)** — Validation only on submit means users discover errors late. Inline validation during editing would improve UX.
- **Timestamp parsing UX (MEDIUM)** — Strict ISO 8601 parsing without a format hint in the UI will cause frequent input errors.
- **Sort stability (MEDIUM)** — `slice::sort_by` is unstable; policies with identical priority+name may flicker order across refreshes.
- **Malformed priority logging spam (LOW)** — `tracing::warn!` on every render could flood logs if a policy has a persistently malformed priority.

### Divergent Views
- OpenCode suggests using `IndexSet` for group deduplication to preserve order; the plans intentionally use `HashSet` for simplicity. This is a valid UX trade-off.
- OpenCode suggests a `FormMode` enum to replace the `editing` + `result` flag combination; the plans intentionally keep flags for consistency with Phase 14/15 patterns. This is a style choice.
- OpenCode suggests adding `chrono` in Wave 2 only; the plans add it in Wave 1 because `SimulateFormState` (defined in Wave 1) includes `timestamp_override` which is conceptually a chrono-related field. This is a reasonable dependency ordering choice.

---

*Review generated: 2026-06-05*
*Reviewers: OpenCode (gpt-5.3-chat-latest)*
*Codex: unavailable (ChatGPT account restriction — no Codex API access)*
