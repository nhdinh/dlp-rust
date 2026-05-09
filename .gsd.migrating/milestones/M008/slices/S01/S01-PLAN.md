# S01: USB Enforcement Fix — PnP Disable Actually Works

**Goal:** Fix DeviceController::disable_usb_device to resolve actual CM instance IDs via SetupDi. Surface hard failures. Handle (none) serial gracefully.
**Demo:** Blocked USB devices are disabled at the PnP level with real CM instance IDs. Both PnP disable and DACL deny-all return hard errors on failure. Devices with (none) serial handled gracefully.

## Must-Haves

- 1. CM_Disable_DevNode receives actual CM instance ID
- 2. (none) serial handled gracefully
- 3. Hard errors surfaced on both PnP disable and DACL deny-all failure
- 4. Precise path matching in SetupDi description lookup

## Proof Level

- This slice proves: tested

## Integration Closure

Agent-side DeviceController uses resolved CM instance IDs. Server stores enforcement config. Admin TUI exposes settings.

## Verification

- Structured USB enforcement traces; audit events include device identity.

## Tasks

- [x] **T01: SetupDi description exact path matching** `est:2h`
  Implement exact path matching in setupdi_description_for_device to avoid returning Bluetooth instead of SanDisk. Match device interface path more precisely in SetupDi enumeration. Add unit tests.
  - Files: `dlp-agent/src/detection/usb.rs`
  - Verify: cargo test --package dlp-agent usb::

- [x] **T02: Server-side config storage and admin API** `est:2h`
  Add server-side database table and admin API endpoints for USB enforcement configuration (retry count, fallback policy for none-serial devices). JWT-protected CRUD.
  - Files: `dlp-server/src/db.rs`, `dlp-server/src/admin_api.rs`
  - Verify: cargo test --package dlp-server admin_api::

- [x] **T03: Agent-side config pipeline wiring** `est:2h`
  Wire agent-side config pipeline: poll server for enforcement settings, merge into AgentConfig, propagate to DeviceController. Add TOML roundtrip tests.
  - Files: `dlp-agent/src/config.rs`, `dlp-agent/src/server_client.rs`, `dlp-agent/src/service.rs`
  - Verify: cargo test --package dlp-agent config::

- [x] **T04: Enforcement behavior: retry, failure mode, none-serial policy** `est:3h`
  Implement enforcement behavior: retry logic for CM_Disable_DevNode, hard failure mode when both PnP disable and DACL deny-all fail, (none) serial fallback policy. Update unit tests.
  - Files: `dlp-agent/src/device_controller.rs`, `dlp-agent/src/usb_enforcer.rs`
  - Verify: cargo test --package dlp-agent device_controller:: usb_enforcer::

- [x] **T05: Admin TUI USB Enforcement Settings screen** `est:2h`
  Add USB Enforcement Settings screen to dlp-admin-cli TUI. Screen shows retry count, none-serial policy, and save/cancel. Follows existing TUI patterns.
  - Files: `dlp-admin-cli/src/app.rs`, `dlp-admin-cli/src/screens/dispatch.rs`, `dlp-admin-cli/src/screens/render.rs`
  - Verify: cargo test --package dlp-admin-cli

## Files Likely Touched

- dlp-agent/src/detection/usb.rs
- dlp-server/src/db.rs
- dlp-server/src/admin_api.rs
- dlp-agent/src/config.rs
- dlp-agent/src/server_client.rs
- dlp-agent/src/service.rs
- dlp-agent/src/device_controller.rs
- dlp-agent/src/usb_enforcer.rs
- dlp-admin-cli/src/app.rs
- dlp-admin-cli/src/screens/dispatch.rs
- dlp-admin-cli/src/screens/render.rs
