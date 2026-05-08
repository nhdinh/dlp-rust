# S01: UWP App Identity (Phase 39)

**Goal:** Agent captures UWP application identity via AUMID for ABAC enforcement.
**Demo:** UWP app identity resolved via AUMID, drag-and-drop blocked by ABAC, browser origin clipboard policies enforced, all audit events enriched with app identity.

## Must-Haves

- 1. UWP AUMID resolved via GetApplicationUserModelId
- 2. AUMID flows through ABAC evaluator
- 3. No special-casing for UWP

## Proof Level

- This slice proves: tested

## Integration Closure

Provides AUMID field for S02 drag-and-drop and S04 audit enrichment.

## Verification

- AUMID captured in audit events.

## Tasks

- [x] **T01: UWP App Identity implementation** `est:4h`
  Add AUMID resolution to AppIdentity via IShellItem::GetApplicationUserModelId. Extend ABAC evaluator and TUI conditions builder with AUMID support. Add unit tests.
  - Files: `dlp-common/src/abac.rs`, `dlp-agent/src/detection/app_identity.rs`, `dlp-admin-cli/src/screens/render.rs`
  - Verify: cargo test --package dlp-agent app_identity:: && cargo test --package dlp-common abac::

## Files Likely Touched

- dlp-common/src/abac.rs
- dlp-agent/src/detection/app_identity.rs
- dlp-admin-cli/src/screens/render.rs
