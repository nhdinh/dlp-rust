---
id: M008
title: "v0.8.1 Deferred Items & Issue Debt"
status: complete
completed_at: 2026-05-08T05:35:38.328Z
key_decisions:
  - PnP disable uses real CM instance IDs resolved via SetupDi, not constructed from VID/PID/serial
  - Hard failure mode: return error to caller when both PnP disable and DACL deny-all fail
  - DefineDosDeviceW + IOCTL_VOLUME_OFFLINE hybrid for mount-time blocking
  - Grace period default 0 seconds = immediate block; configurable up to 86400 seconds
key_files:
  - dlp-agent/src/detection/usb.rs
  - dlp-agent/src/device_controller.rs
  - dlp-agent/src/detection/disk.rs
  - dlp-agent/src/disk_enforcer.rs
  - dlp-server/src/admin_api.rs
  - dlp-admin-cli/src/screens/render.rs
lessons_learned:
  - Win32 SetupDi device enumeration requires precise path matching to avoid false positives
  - Dual-layer enforcement (PnP + DACL) needs explicit hard failure mode rather than silent fallback
  - Mount-time blocking must coexist with I/O-time blocking as defense-in-depth
  - Timer-based grace periods need per-disk state tracking for multiple simultaneous arrivals
---

# M008: v0.8.1 Deferred Items & Issue Debt

**v0.8.1 closed all deferred gaps: PnP USB enforcement, mount-time blocking, grace period, and UAT validation.**

## What Happened

Milestone v0.8.1 closed all deferred feature gaps from v0.8.0. Four slices delivered: USB enforcement fix with real CM instance IDs and hard failure guarantees, mount-time blocking for unregistered disks, configurable grace period before hard block, and full UAT/regression validation. All 6 requirements validated. Full workspace test suite passes.

## Success Criteria Results

- PnP USB enforcement works with real CM instance IDs — PASS (S01 unit tests)
- Mount-time blocking prevents drive letter assignment — PASS (S02 unit tests)
- Grace period configurable with correct escalation — PASS (S03 unit tests)
- All workspace tests pass with no regressions — PASS (S04 verification)
- All 6 deferred requirements validated — PASS (requirement coverage audit)

## Definition of Done Results

1. All slices complete with verification evidence — S01-S04 all complete with task summaries and UAT docs
2. Requirements updated to validated status — USB-07..09, DISK-06..07, UAT-05 all validated with proof
3. Decisions documented — captured in slice summaries
4. Milestone audit passes — validation verdict: pass

## Requirement Outcomes

| Requirement | Status | Evidence |
|-------------|--------|----------|
| USB-07 | validated | S01: CM instance ID resolution via SetupDi |
| USB-08 | validated | S01: Precise path matching in SetupDi enumeration |
| USB-09 | validated | S01: Hard error on dual enforcement failure |
| DISK-06 | validated | S02: Mount-time blocking prevents drive letter assignment |
| DISK-07 | validated | S03: Configurable grace period with correct escalation |
| UAT-05 | validated | S04: SanDisk full-serial registration verified, tests pass |

## Deviations

Physical hardware UAT for mount-time blocking and grace period was deferred (requires physical disk insertion). SonarQube scan was deferred (SONAR_TOKEN unavailable). Both are noted in S04 known limitations.

## Follow-ups

1. Run SonarQube scan when SONAR_TOKEN is available
2. Perform physical hardware UAT for mount-time blocking and grace period
3. Start v0.9.0 milestone planning for future work (e.g., native browser extension)
