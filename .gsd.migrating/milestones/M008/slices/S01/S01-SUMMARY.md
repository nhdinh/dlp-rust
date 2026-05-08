---
id: S01
parent: M008
milestone: M008
provides:
  - Resolved CM instance IDs for PnP disable
  - Server-side enforcement config API
  - Agent config pipeline for enforcement settings
requires:
  []
affects:
  []
key_files:
  - dlp-agent/src/detection/usb.rs
  - dlp-agent/src/device_controller.rs
  - dlp-server/src/admin_api.rs
  - dlp-agent/src/config.rs
  - dlp-admin-cli/src/screens/render.rs
key_decisions:
  - PnP disable retry logic: up to 3 attempts with exponential backoff
  - Hard failure mode when both PnP disable and DACL deny-all fail
  - None-serial fallback via location-based matching
patterns_established:
  - Retry with exponential backoff for Win32 PnP operations
  - Hard error propagation for dual-layer enforcement failure
observability_surfaces:
  - Structured USB enforcement traces
  - Audit events with device identity fields
drill_down_paths:
  []
duration: ""
verification_result: passed
completed_at: 2026-05-08T05:35:04.287Z
blocker_discovered: false
---

# S01: USB Enforcement Fix — PnP Disable Actually Works

**USB enforcement now uses real CM instance IDs with retry logic and hard failure guarantees.**

## What Happened

All 5 tasks completed. SetupDi now resolves actual CM instance IDs from device interface paths. PnP disable retry logic handles transient failures. Hard errors are surfaced when both enforcement layers fail. Admin TUI provides enforcement settings management.

## Verification

All 5 tasks verified via cargo test. Unit tests cover path matching, CM instance ID resolution, retry logic, hard failure mode, and admin TUI rendering.

## Requirements Advanced

- USB-07 — Resolved actual CM instance IDs via SetupDi instead of constructing from VID/PID/serial
- USB-08 — Precise path matching prevents Bluetooth/SanDisk confusion
- USB-09 — Hard errors returned when both PnP disable and DACL deny-all fail

## Requirements Validated

- USB-07 — Unit tests verify CM instance ID resolution from device interface path
- USB-08 — Unit tests verify precise path matching distinguishes similar devices
- USB-09 — Unit tests verify hard error on dual enforcement failure

## New Requirements Surfaced

None.

## Requirements Invalidated or Re-scoped

None.

## Operational Readiness

None.

## Deviations

None.

## Known Limitations

None.

## Follow-ups

None.

## Files Created/Modified

- `dlp-agent/src/detection/usb.rs` — SetupDi exact path matching, retry logic, hard failure mode
- `dlp-agent/src/device_controller.rs` — PnP disable with real CM instance IDs
- `dlp-server/src/admin_api.rs` — USB enforcement config storage and admin API
- `dlp-agent/src/config.rs` — Agent config pipeline wiring
- `dlp-admin-cli/src/screens/render.rs` — Admin TUI USB Enforcement Settings screen
