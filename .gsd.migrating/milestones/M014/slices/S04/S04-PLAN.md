# S04: Policy List + Simulate (Phase 16)

**Goal:** List policies and simulate evaluation requests.
**Demo:** Scrollable policy table with priority sort. Standalone evaluate-request simulation form renders decision and matched policy.

## Must-Haves

- 1. Policy list shows Priority/Name/Action/Enabled
- 2. Simulate form captures subject/resource/environment
- 3. Renders matched policy ID, decision, reason
- 4. Esc bug fixed (commit e1afee3)

## Proof Level

- This slice proves: tested

## Integration Closure

Consumes S03 edit/delete. Provides read-only and simulation surfaces.

## Verification

- None — UI behavior.

## Tasks

- [x] **T01: Policy list and simulate implementation** `est:4h`
  Implement PolicyList with column widths, n-key binding, inline hints. Sort ascending by priority. Add PolicySimulate screen with 10-row form. Implement submit handler posting to POST /evaluate. Render SimulateOutcome with matched policy ID, decision, reason. Fix Esc-key bug preserving edit buffer.
  - Files: `dlp-admin-cli/src/screens/render.rs`, `dlp-admin-cli/src/screens/dispatch.rs`
  - Verify: cargo test --package dlp-admin-cli

## Files Likely Touched

- dlp-admin-cli/src/screens/render.rs
- dlp-admin-cli/src/screens/dispatch.rs
