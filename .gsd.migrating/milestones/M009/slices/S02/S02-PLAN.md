# S02: Drag-and-Drop Enforcement (Phase 40)

**Goal:** Block or allow drag-and-drop operations based on source application identity and ABAC policy.
**Demo:** Drag-and-drop operations from unauthorized sources are blocked before drop completes, with toast notification and audit event.

## Must-Haves

- 1. WM_DROPFILES interception working
- 2. Source app identity resolved for Win32 and UWP
- 3. ABAC evaluated before drop completes
- 4. Toast + audit on block

## Proof Level

- This slice proves: tested

## Integration Closure

Consumes S01 AppIdentity. Integrates with service lifecycle and toast notifications.

## Verification

- Audit events for drag-and-drop blocks.

## Tasks

- [x] **T01: Drag-and-drop enforcement implementation** `est:6h`
  Implement WH_GETMESSAGE hook for WM_DROPFILES interception. Resolve source application identity (Win32 and UWP via S01). Evaluate ABAC policy before drop completes. Wire toast notification and audit event on block. Service lifecycle integration.
  - Files: `dlp-agent/src/interception/drag_drop.rs`, `dlp-agent/src/service.rs`, `dlp-common/src/audit.rs`
  - Verify: cargo test --package dlp-agent drag_drop::

## Files Likely Touched

- dlp-agent/src/interception/drag_drop.rs
- dlp-agent/src/service.rs
- dlp-common/src/audit.rs
