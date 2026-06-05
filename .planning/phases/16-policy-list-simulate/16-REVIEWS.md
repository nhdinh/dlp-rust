---
phase: 16
reviewers: [opencode]
reviewed_at: 2026-06-05T14:55:00Z
plans_reviewed: [16-01-PLAN.md, 16-02-PLAN.md]
---

# Cross-AI Plan Review — Phase 16

## OpenCode Review

### Plan 16-01 Review

#### Summary
This plan is well-scoped and appropriately staged for a "Wave 1" foundation pass. It cleanly separates shared types and UI polish from the heavier simulate feature, minimizes server impact, and aligns with existing architecture. The work is mostly incremental and low-risk, though there are a few coupling and correctness concerns around sorting, enum placement, and UI state consistency.

#### Strengths
- Clear separation of concerns: shared types + UI polish vs full feature implementation
- No backend changes; leverages existing `/evaluate` endpoint correctly
- Thoughtful UX improvements (column redesign, footer hints, keyboard shortcuts)
- Client-side sort defined deterministically (priority + name)
- Forward-compatible: simulate screen scaffolding unblocks Wave 2 without rework
- Good reuse of conventions (`Default`, enum-driven navigation)

#### Concerns
- MEDIUM: Shared types placed in `app.rs` risks file bloat and poor modularity as simulate grows
- MEDIUM: Sorting malformed `priority` to `u32::MAX` silently hides data issues instead of surfacing them
- LOW: Case-insensitive sort not clearly defined (ASCII vs locale-aware); could lead to inconsistent ordering
- LOW: Adding `Screen::PolicySimulate` wiring before full implementation may create dead navigation paths if partially rendered
- LOW: No mention of preserving selection index after sort (UX jitter if list reloads)

#### Suggestions
- Extract simulate-related types into a dedicated module (`simulate.rs`) instead of `app.rs`
- Log or visually mark malformed priorities instead of silently sinking them
- Use a stable, explicit comparison (`to_ascii_lowercase`) to avoid locale surprises
- Ensure list selection is preserved post-sort (track by policy ID if available)
- Add a temporary "Not implemented" message in simulate screen stub to avoid blank UI

#### Risk Assessment
LOW — Mostly additive UI and type work with minimal system impact. Main risks are maintainability and small UX inconsistencies, not correctness or architecture.

---

### Plan 16-02 Review

#### Summary
This plan is solid and delivers the full simulate feature with a clear interaction model, consistent keyboard handling, and correct integration with ABAC evaluation. It demonstrates good alignment with existing types and avoids over-engineering. The main gaps are around validation, error handling depth, and resilience of the input model.

#### Strengths
- Clean mapping from UI → `EvaluateRequest` using existing shared types
- Reuses `Decision::is_denied()` correctly for invariant-aligned UX
- Keyboard interaction model is consistent and predictable
- Inline result rendering is user-friendly and avoids context switching
- Explicit handling of network vs server errors improves debuggability
- Good separation of editing vs navigation modes

#### Concerns
- HIGH: No client-side validation at all — malformed inputs (empty resource, invalid path, etc.) are sent directly to server
- MEDIUM: `groups_raw` parsing is naive (no deduplication, case normalization, or length limits)
- MEDIUM: Hardcoded `session_id = 0` and `agent = None` may diverge from real evaluation semantics
- MEDIUM: Timestamp always `Utc::now()` prevents reproducible simulations (no override)
- LOW: Select cycling UX may be confusing without visual indication of current option index
- LOW: No loading state during network request (UI may feel frozen)
- LOW: Error handling lumps all reqwest errors under "Network error" (timeouts vs DNS vs serialization indistinguishable)

#### Suggestions
- Add minimal validation before submit:
  - Non-empty `resource` and `user`
  - Optional: basic path format sanity check
- Normalize `groups_raw`:
  - Trim + dedupe + lowercase (or document case sensitivity explicitly)
- Consider allowing optional override fields:
  - `timestamp` (for reproducibility)
  - `session_id` (even if default remains 0)
- Add a loading indicator or disable input during submission
- Improve error granularity (timeout vs connection vs decode)
- Display current selected option explicitly (e.g., highlight or suffix)
- Cap input lengths to avoid accidental oversized payloads

#### Risk Assessment
MEDIUM — Functionally correct and aligned with architecture, but lack of validation and input normalization could lead to confusing or misleading simulation results. Risks are primarily UX correctness and data quality, not system stability.

---

## Consensus Summary

### Agreed Strengths
- Clean wave-based separation (Wave 1 types/scaffolding, Wave 2 full implementation)
- Reuses existing server endpoint (`/evaluate`) and ABAC types without backend changes
- Keyboard interaction model is consistent with prior phases (Phase 14/15 patterns)
- Inline result rendering is user-friendly
- Good separation of editing vs navigation modes

### Agreed Concerns
- **No client-side validation** (HIGH from OpenCode) — empty/invalid inputs sent to server; while the ABAC engine handles empty requests gracefully (default-deny), this could confuse operators expecting feedback
- **`groups_raw` parsing is minimal** (MEDIUM) — no deduplication, length limits, or format validation
- **Shared types in `app.rs`** (MEDIUM) — modularity concern; file bloat risk as simulate features grow
- **Hardcoded `session_id = 0` and `agent = None`** (MEDIUM) — may diverge from real evaluation semantics; documented as intentional in CONTEXT.md D-17 but worth monitoring

### Divergent Views
- OpenCode suggests extracting simulate types to `simulate.rs`; the plans intentionally keep them in `app.rs` per 16-RESEARCH.md U3 recommendation (file overhead disproportionate to size). This is a valid trade-off for a small feature.
- OpenCode suggests adding loading state and input length caps; the plans intentionally omit these for simplicity per ROADMAP scope. These are reasonable v0.5.0 polish items.

---

*Review generated: 2026-06-05*
*Reviewers: OpenCode (gpt-5.3-chat-latest)*
