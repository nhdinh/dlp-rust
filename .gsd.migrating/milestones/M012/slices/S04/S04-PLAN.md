# S04: Notifications, Admin TUI, Chrome Connector (Phases 27-29)

**Goal:** User notifications, admin TUI screens, and Chrome Enterprise Connector.
**Demo:** Users receive toast notification on USB block with policy explanation. Admin manages devices, origins, and app-identity policies via TUI. Chrome paste blocked between managed/unmanaged origins.

## Must-Haves

- 1. Toast on USB block with 30s cooldown
- 2. Device Registry TUI screen
- 3. Managed Origins TUI screen
- 4. Chrome pipe server at \\.\pipe\brcm_chrm_cas
- 5. Paste from managed→unmanaged origin blocked

## Proof Level

- This slice proves: tested

## Integration Closure

Consumes S03 enforcement. Completes user-facing and admin-facing surfaces.

## Verification

- Toast notifications and audit events.

## Tasks

- [x] **T01: Notifications, admin TUI, and Chrome connector** `est:10h`
  Implement UsbBlockResult with per-drive cooldown and toast broadcast. Add managed_origins DDL and ManagedOriginsRepository. Add DeviceList and DeviceTierPicker TUI screens. Add ManagedOriginList TUI screen. Add ConditionAttribute app-identity variants to TUI builder. Implement Chrome pipe server with protobuf frame protocol. Register in HKLM. Handle clipboard scan requests with origin resolution and ABAC evaluation.
  - Files: `dlp-agent/src/usb_enforcer.rs`, `dlp-admin-cli/src/screens/render.rs`, `dlp-admin-cli/src/screens/dispatch.rs`, `dlp-agent/src/chrome/mod.rs`, `dlp-agent/src/chrome/handler.rs`
  - Verify: cargo test --package dlp-agent chrome:: usb_enforcer:: && cargo test --package dlp-admin-cli

## Files Likely Touched

- dlp-agent/src/usb_enforcer.rs
- dlp-admin-cli/src/screens/render.rs
- dlp-admin-cli/src/screens/dispatch.rs
- dlp-agent/src/chrome/mod.rs
- dlp-agent/src/chrome/handler.rs
