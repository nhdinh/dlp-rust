# S02: Per-User Device Registry (Phase 38.4)

**Goal:** Support per-user USB device registration for multi-user machines.
**Demo:** Multi-user machines support per-user USB device registration with most-restrictive tier merge.

## Must-Haves

- 1. owner_user column in device_registry
- 2. Admin API filters by owner_user
- 3. Agent evaluates against current user SID
- 4. Most-restrictive tier merge on conflict

## Proof Level

- This slice proves: tested

## Integration Closure

Extends Phase 24 device registry with owner_user column and SID-based evaluation.

## Verification

- Audit events include owner_user for per-user decisions.

## Tasks

- [x] **T01: Per-user device registry implementation** `est:4h`
  Add owner_user column to device_registry table. Update admin API to filter by owner_user. Modify agent trust tier evaluation to check current user SID first, then fall back to machine-wide entry. Implement most-restrictive tier merge when both per-user and machine-wide entries exist. Update TUI to show owner_user column.
  - Files: `dlp-server/src/db.rs`, `dlp-server/src/admin_api.rs`, `dlp-agent/src/usb_enforcer.rs`, `dlp-admin-cli/src/screens/render.rs`
  - Verify: cargo test --package dlp-agent usb_enforcer:: && cargo test --package dlp-server admin_api::

## Files Likely Touched

- dlp-server/src/db.rs
- dlp-server/src/admin_api.rs
- dlp-agent/src/usb_enforcer.rs
- dlp-admin-cli/src/screens/render.rs
