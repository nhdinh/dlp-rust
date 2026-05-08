# S02: Boolean Mode in TUI + Import/Export (Phase 19)

**Goal:** Surface boolean mode in admin TUI and prove end-to-end round-trip.
**Demo:** Admin can choose boolean mode in Create/Edit forms. Export/import round-trips mode field.

## Must-Haves

- 1. Mode picker in Create/Edit forms
- 2. Export includes mode
- 3. Import tolerates missing mode (defaults to ALL)
- 4. Integration test: three policies with different modes

## Proof Level

- This slice proves: tested

## Integration Closure

Consumes S01 wire format. Completes user-facing contract for POLICY-09.

## Verification

- None — UI behavior.

## Tasks

- [x] **T01: Boolean mode TUI and import/export** `est:4h`
  Add mode picker row to Policy Create and Edit forms. Implement cycle_mode helper and dispatch handlers. Update POLICY_FIELD_LABELS. Add mode to export JSON. Handle missing mode on import (default to ALL). Write integration tests creating three policies with different modes and evaluating same request.
  - Files: `dlp-admin-cli/src/screens/render.rs`, `dlp-admin-cli/src/screens/dispatch.rs`, `dlp-server/tests/mode_end_to_end.rs`
  - Verify: cargo test --package dlp-admin-cli && cargo test --package dlp-server mode_end_to_end

## Files Likely Touched

- dlp-admin-cli/src/screens/render.rs
- dlp-admin-cli/src/screens/dispatch.rs
- dlp-server/tests/mode_end_to_end.rs
