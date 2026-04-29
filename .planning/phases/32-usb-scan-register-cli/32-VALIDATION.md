---
phase: 32
phase-slug: usb-scan-register-cli
date: 2026-04-29
source: RESEARCH.md § Validation Architecture
---

# Phase 32 Validation Strategy

## Test Framework

| Property | Value |
|----------|-------|
| Framework | Rust built-in `#[test]` via `cargo test` |
| Config file | none (workspace default) |
| Quick run command | `cargo test -p dlp-common usb` |
| Full suite command | `cargo test --workspace` |

## Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command |
|--------|----------|-----------|-------------------|
| D-07/D-09 | `parse_usb_device_path` returns correct `DeviceIdentity` | unit | `cargo test -p dlp-common usb::tests` |
| D-07/D-09 | `enumerate_connected_usb_devices` returns `Vec` (Windows stub OK in CI) | unit | `cargo test -p dlp-common usb::tests::test_enumerate` |
| D-11 | Merge logic: registered devices show tier, unregistered show `None` | unit | `cargo test -p dlp-admin-cli` |
| D-04 | `UsbScanEntry` with `registered_tier = None` shows `"-"` in render | unit | `cargo test -p dlp-admin-cli screens` |
| D-01 | `DevicesMenu` has exactly 3 items | unit | `cargo test -p dlp-admin-cli` |
| D-05/D-12 | Enter opens `DeviceTierPicker` with pre-populated fields + correct caller | unit | `cargo test -p dlp-admin-cli` (routing tests) |
| D-03 | `TierPickerCaller::UsbScan` routes back to `Screen::UsbScan` after success | unit | `cargo test -p dlp-admin-cli` (routing tests) |

## Wave 0 Gaps (must be created by this phase)

- [ ] `dlp-common/src/usb.rs` — new file; migrate `test_parse_happy_path` and all parse tests from agent
- [ ] `dlp-common/src/usb.rs::test_enumerate` — stub test: `enumerate_connected_usb_devices()` returns `Vec<DeviceIdentity>` (empty is valid on non-Windows CI)
- [ ] `dlp-admin-cli/src/app.rs` — unit tests for `TierPickerCaller` variants, `UsbScanEntry` default construction
- [ ] Merge logic unit test: given a `Vec<DeviceIdentity>` and `Vec<serde_json::Value>` registry rows, verify `UsbScanEntry.registered_tier` is correctly populated for registered devices and `None` for unregistered ones
- [ ] Caller routing unit tests: `TierPickerCaller::DeviceList` routes to `Screen::DeviceList`, `TierPickerCaller::UsbScan` triggers `action_usb_scan` re-scan

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Control |
|---------------|---------|---------|
| V2 Authentication | yes | JWT bearer on `GET /admin/device-registry/full` and `POST /admin/device-registry` — enforced by server |
| V4 Access Control | yes | Only authenticated admin can scan/register — enforced by server auth middleware |
| V5 Input Validation | yes | VID/PID/serial/description sent to existing `upsert_device_registry_handler`; no new validation surface added |

### Threat Model

| Pattern | STRIDE | Mitigation |
|---------|--------|-----------|
| Rogue USB device enumerated and displayed | Information Disclosure | Display-only; registration requires explicit admin Enter+confirm — no auto-registration |
| Oversized SetupDi description via malicious USB | Tampering | Fixed 1024-byte buffer in `setupdi_description_for_device`; truncates silently; TUI render only — no SQL injection surface |
| VID/PID spoofing | Spoofing | Out of scope — same threat exists in current agent flow |
