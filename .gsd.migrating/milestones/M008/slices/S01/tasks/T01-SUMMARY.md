---
id: T01
parent: S01
milestone: M008
key_files:
  - dlp-agent/src/detection/usb.rs
key_decisions:
  - (none)
duration: 
verification_result: passed
completed_at: 2026-05-08T05:33:58.639Z
blocker_discovered: false
---

# T01: SetupDi description lookup now uses precise path matching to avoid wrong-device matches.

**SetupDi description lookup now uses precise path matching to avoid wrong-device matches.**

## What Happened

Implemented exact path matching in setupdi_description_for_device to distinguish between devices with similar descriptors (e.g., Bluetooth vs SanDisk). The SetupDi enumeration now matches device interface paths precisely before returning a description. Added unit tests covering multi-device enumeration scenarios.

## Verification

Unit tests pass. Device description resolution no longer returns Bluetooth for SanDisk devices.

## Verification Evidence

| # | Command | Exit Code | Verdict | Duration |
|---|---------|-----------|---------|----------|
| 1 | `cargo test --package dlp-agent usb::` | 0 | ✅ pass | 15000ms |

## Deviations

None. Task completed during original v0.8.1 phase execution (2026-05-08).

## Known Issues

None.

## Files Created/Modified

- `dlp-agent/src/detection/usb.rs`
