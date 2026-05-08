# S03: Browser Origin Clipboard Policies (Phase 41)

**Goal:** Extend Chrome Enterprise Connector with origin-specific clipboard policies.
**Demo:** Paste from managed origin to unmanaged origin blocked inside Chrome with origin fields in audit.

## Must-Haves

- 1. Chrome messages include tab origin
- 2. ABAC supports source_origin/destination_origin
- 3. Managed origins enforced
- 4. Block audited with origin fields

## Proof Level

- This slice proves: tested

## Integration Closure

Extends Phase 29 Chrome connector. Adds origin conditions to ABAC and TUI.

## Verification

- Audit events include source_origin and destination_origin.

## Tasks

- [x] **T01: Browser origin clipboard policies implementation** `est:6h`
  Extend Chrome Content Analysis protobuf schema with origin fields. Add SourceOrigin/DestinationOrigin to ABAC condition variants. Implement origin condition matching in evaluator. Add origin conditions builder to admin TUI. Chrome handler ABAC evaluation with thread-local test isolation.
  - Files: `dlp-agent/src/chrome/proto.rs`, `dlp-common/src/abac.rs`, `dlp-agent/src/chrome/handler.rs`, `dlp-admin-cli/src/screens/render.rs`
  - Verify: cargo test --package dlp-agent chrome:: && cargo test --package dlp-common abac::

## Files Likely Touched

- dlp-agent/src/chrome/proto.rs
- dlp-common/src/abac.rs
- dlp-agent/src/chrome/handler.rs
- dlp-admin-cli/src/screens/render.rs
