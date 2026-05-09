# S04: In-Place Condition Editing (Phase 21)

**Goal:** Close delete-and-recreate gap with in-place condition editing.
**Demo:** Press 'e' on pending condition to pre-fill 3-step picker and replace at original index.

## Must-Haves

- 1. 'e' key pre-fills picker
- 2. Save replaces at original index
- 3. Cancel leaves list unchanged
- 4. No regression in delete binding

## Proof Level

- This slice proves: tested

## Integration Closure

TUI-only enhancement to conditions builder.

## Verification

- None — UI behavior.

## Tasks

- [x] **T01: In-place condition editing** `est:3h`
  Add edit_index to ConditionsBuilder state. Implement condition_to_prefill helper. Add 'e' key handler in pending-conditions list. Update step-3 commit to replace at original index when editing. Update render title/hint to show edit mode. Add unit tests for edit, save, cancel, and attribute-change reset.
  - Files: `dlp-admin-cli/src/screens/render.rs`, `dlp-admin-cli/src/screens/dispatch.rs`
  - Verify: cargo test --package dlp-admin-cli

## Files Likely Touched

- dlp-admin-cli/src/screens/render.rs
- dlp-admin-cli/src/screens/dispatch.rs
