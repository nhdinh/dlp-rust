---
phase: 56
slug: sd-optical-virtual-drive-enumeration-volume-class-abac-seed
status: complete
nyquist_compliant: true
wave_0_complete: true
created: 2026-05-29
---

# Phase 56 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Built-in `#[test]` + `cargo test` |
| **Config file** | none |
| **Quick run command** | `cargo test -p dlp-common` |
| **Full suite command** | `cargo test --all` |
| **Estimated runtime** | ~60 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p dlp-common`
- **After every plan wave:** Run `cargo test --all`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 56-01-01 | 01 | 1 | DRIVE-01 | T-56-01 | `VolumeClass` enum serializes/deserializes correctly | unit | `cargo test -p dlp-common volume_class` | Yes | green |
| 56-01-02 | 01 | 1 | DRIVE-01 | T-56-02 | `GetDriveTypeW` + WMI disambiguation produces correct class | integration | `cargo test -p dlp-agent --features integration-tests` | Yes | green |
| 56-02-01 | 02 | 1 | DRIVE-02 | T-56-03 | `SourceVolumeClass` condition matches in `PolicyStore::evaluate` | unit | `cargo test -p dlp-server policy_store` | Yes | green |
| 56-02-02 | 02 | 1 | DRIVE-02 | T-56-04 | `DestinationVolumeClass` condition matches correctly | unit | `cargo test -p dlp-server policy_store` | Yes | green |
| 56-02-03 | 02 | 1 | DRIVE-02 | T-56-05 | Admin TUI builds correct `PolicyCondition` from picker | unit | `cargo test -p dlp-admin-cli conditions_builder` | Yes | green |
| 56-03-01 | 03 | 2 | DRIVE-03 | T-56-06 | Hook DLL thread-local cache returns correct class | unit | `cargo test -p dlp-hook-dll volume_class_cache` | Yes | green |
| 56-04-01 | 04 | 2 | DRIVE-04 | T-56-07 | `VolumeArrival` event emitted on virtual mount | integration | `cargo test -p dlp-agent --features integration-tests` | Yes | green |
| 56-05-01 | 05 | 2 | DRIVE-04 | T-56-08 | `WM_DEVICECHANGE` covers SD/optical arrival with 500ms defer | integration | `cargo test -p dlp-agent --features integration-tests` | Yes | green |
| 56-06-01 | 06 | 3 | DRIVE-02 | T-56-09 | End-to-end: "DENY LocalNTFS T4 to Optical" blocks `CopyFileExW` | integration | `cargo test -p dlp-server --test volume_class_integration` | Yes | green |

*Status: pending / green / red / flaky*

---

## Wave 0 Requirements

- [x] `dlp-common/src/volume_class.rs` (or inline in `abac.rs`) — `VolumeClass` enum with serde tests
- [x] `dlp-common/src/abac.rs` — `AbacContext` field tests for `source_volume_class` / `destination_volume_class`
- [x] `dlp-server/src/policy_store.rs` — `condition_matches` tests for new volume class arms
- [x] `dlp-agent/src/detection/usb.rs` — `VolumeClass` resolution tests (mock WMI)
- [x] `dlp-hook-dll/src/volume_class_cache.rs` — thread-local cache tests
- [x] `dlp-admin-cli/src/screens/dispatch.rs` — `build_condition` tests for volume class attributes
- [x] `dlp-admin-cli/src/screens/render.rs` — `picker_items` tests for volume class values

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Physical SD card insertion produces `VolumeArrival` with `SDCard` class | DRIVE-04 | Requires physical hardware | Insert SD card into test endpoint reader; verify `VolumeArrival` event in audit log with correct `volume_class` |
| Physical optical disc insertion produces `VolumeArrival` with `Optical` class | DRIVE-04 | Requires physical hardware | Insert CD/DVD into test endpoint optical drive; verify `VolumeArrival` event in audit log |
| Daemon Tools virtual drive mount produces `VolumeArrival` with `Virtual` class | DRIVE-04 | Requires third-party software | Mount ISO via Daemon Tools on test endpoint; verify `VolumeArrival` event with `Virtual` class |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 30s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved 2026-05-29
