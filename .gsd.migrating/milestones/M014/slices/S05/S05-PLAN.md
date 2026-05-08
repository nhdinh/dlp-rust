# S05: Import + Export (Phase 17)

**Goal:** Persist and restore policy set via JSON with conflict detection.
**Demo:** Export full policy set to JSON. Import with conflict detection and abort-on-error.

## Must-Haves

- 1. Export to user-chosen path
- 2. Import parses JSON, computes conflict diff
- 3. Abort-on-first-failure
- 4. Native file dialogs via rfd

## Proof Level

- This slice proves: tested

## Integration Closure

Consumes S04 policy list. Provides data portability.

## Verification

- None — data operation.

## Tasks

- [x] **T01: Import and export implementation** `est:5h`
  Add export action fetching live policy set and writing pretty-printed JSON. Add ImportConfirm screen. Compute conflict diff against current server state. Implement import execution with abort-on-first-failure (POST new IDs, PUT existing). Add rfd file dialogs. Add unit tests for import conflict detection and round-trip. Fix GET path bug (commit 7dda578).
  - Files: `dlp-admin-cli/src/screens/render.rs`, `dlp-admin-cli/src/screens/dispatch.rs`, `dlp-admin-cli/src/app.rs`
  - Verify: cargo test --package dlp-admin-cli

## Files Likely Touched

- dlp-admin-cli/src/screens/render.rs
- dlp-admin-cli/src/screens/dispatch.rs
- dlp-admin-cli/src/app.rs
