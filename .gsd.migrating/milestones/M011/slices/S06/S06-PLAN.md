# S06: USB Enforcement Fix (Phase 38.2)

**Goal:** Fix USB enforcement gap where blocked devices log DENY but writes still succeed.
**Demo:** Blocked USB devices disabled at PnP level with Volume DACL deny-all fallback.

## Must-Haves

- 1. CM_Disable_DevNode fires for blocked devices
- 2. Volume DACL deny-all as fallback
- 3. File writes fail with access denied
- 4. Startup scan catches existing devices

## Proof Level

- This slice proves: tested

## Integration Closure

PnP disable + DACL deny-all as dual real-time enforcement layers.

## Verification

- Structured USB enforcement traces.

## Tasks

- [x] **T01: USB enforcement fix — PnP disable + DACL** `est:5h`
  Add set_volume_deny_all to DeviceController for DACL defense-in-depth. Wire CM_Disable_DevNode into apply_tier_enforcement for Blocked tier. Fix race condition in usb.rs. Add startup scan for existing USB devices. Fix drive-letter mislabel in disk.rs. Normalize boot drive case.
  - Files: `dlp-agent/src/device_controller.rs`, `dlp-agent/src/detection/usb.rs`, `dlp-agent/src/service.rs`, `dlp-common/src/disk.rs`
  - Verify: cargo test --package dlp-agent device_controller:: usb::

## Files Likely Touched

- dlp-agent/src/device_controller.rs
- dlp-agent/src/detection/usb.rs
- dlp-agent/src/service.rs
- dlp-common/src/disk.rs
