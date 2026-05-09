# S03: Policy Edit + Delete (Phase 15)

**Goal:** Load, edit, and delete existing policies.
**Demo:** Admin edits existing policies and deletes with confirmation. Form pre-fills from loaded record.

## Must-Haves

- 1. 'e' on policy list loads full record
- 2. Submit via PUT /admin/policies/{id}
- 3. 'd' shows confirmation, fires DELETE
- 4. Edit retains enabled flag

## Proof Level

- This slice proves: tested

## Integration Closure

Consumes S02 create form. Reuses cache invalidation pattern.

## Verification

- None — UI behavior.

## Tasks

- [x] **T01: Policy edit and delete implementation** `est:4h`
  Add row constants and PolicyEdit state. Implement load, edit, and delete handlers. Add delete confirmation prompt. Implement draw_policy_edit render function. Wire into policy list navigation. Add unit tests for edit round-trip and delete confirmation.
  - Files: `dlp-admin-cli/src/screens/render.rs`, `dlp-admin-cli/src/screens/dispatch.rs`
  - Verify: cargo test --package dlp-admin-cli

## Files Likely Touched

- dlp-admin-cli/src/screens/render.rs
- dlp-admin-cli/src/screens/dispatch.rs
