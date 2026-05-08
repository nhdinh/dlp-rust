---
id: T01
parent: S06
milestone: M011
key_files:
  - dlp-agent/src/device_controller.rs
  - dlp-agent/src/detection/usb.rs
key_decisions:
  - (none)
duration: 
verification_result: passed
completed_at: 2026-05-08T05:45:01.685Z
blocker_discovered: false
---

# T01: USB enforcement fix: PnP disable + DACL deny-all with race condition and startup scan fixes.

**USB enforcement fix: PnP disable + DACL deny-all with race condition and startup scan fixes.**

## What Happened

Added set_volume_deny_all to DeviceController for DACL defense-in-depth. Wired CM_Disable_DevNode into apply_tier_enforcement for Blocked tier. Fixed race condition in usb.rs. Added startup scan for existing USB devices. Fixed drive-letter mislabel and boot drive case normalization.

## Verification

Device controller and USB tests pass.

## Verification Evidence

| # | Command | Exit Code | Verdict | Duration |
|---|---------|-----------|---------|----------|
| 1 | `cargo test --package dlp-agent device_controller:: usb::` | 0 | ✅ pass | 15000ms |

## Deviations

None. Completed during original v0.7.0 phase execution (2026-05-06).

## Known Issues

None.

## Files Created/Modified

- `dlp-agent/src/device_controller.rs`
- `dlp-agent/src/detection/usb.rs`
