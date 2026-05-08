# S02: USB Enumeration + Device Registry (Phases 23-24)

**Goal:** Agent detects USB arrival with full identity; server persists trust-tier registry.
**Demo:** USB device arrival detected with VID/PID/serial/description. Device registry DB with trust tiers.

## Must-Haves

- 1. USB arrival logs VID/PID/serial/description
- 2. None-serial devices captured as '(none)'
- 3. Server CRUD for device registry
- 4. Agent cache polls every 30s

## Proof Level

- This slice proves: tested

## Integration Closure

Provides device identity and registry for S05 enforcement.

## Verification

- USB discovery audit events.

## Tasks

- [x] **T01: USB enumeration and device registry** `est:6h`
  Implement UsbDetector with device_identities field and parse_usb_device_path helper. Add GUID_DEVINTERFACE_USB_DEVICE device notification. Wire WM_DEVICECHANGE in usb_wndproc. SetupDi description fetch. Create device_registry table and DeviceRegistryRepository. Implement admin API GET/POST/DELETE /admin/device-registry. Agent DeviceRegistryCache with 30s poll.
  - Files: `dlp-agent/src/detection/usb.rs`, `dlp-server/src/db.rs`, `dlp-server/src/admin_api.rs`, `dlp-agent/src/usb_enforcer.rs`
  - Verify: cargo test --package dlp-agent usb:: && cargo test --package dlp-server admin_api::

## Files Likely Touched

- dlp-agent/src/detection/usb.rs
- dlp-server/src/db.rs
- dlp-server/src/admin_api.rs
- dlp-agent/src/usb_enforcer.rs
