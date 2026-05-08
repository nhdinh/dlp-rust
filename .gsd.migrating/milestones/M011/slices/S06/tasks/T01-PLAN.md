---
estimated_steps: 1
estimated_files: 4
skills_used: []
---

# T01: USB enforcement fix — PnP disable + DACL

Add set_volume_deny_all to DeviceController for DACL defense-in-depth. Wire CM_Disable_DevNode into apply_tier_enforcement for Blocked tier. Fix race condition in usb.rs. Add startup scan for existing USB devices. Fix drive-letter mislabel in disk.rs. Normalize boot drive case.

## Inputs

- `Existing DeviceController`
- `USB detection patterns`

## Expected Output

- `DeviceController DACL deny-all`
- `PnP disable wiring`
- `Race condition fix`
- `Startup scan`
- `Drive letter fix`

## Verification

cargo test --package dlp-agent device_controller:: usb::
