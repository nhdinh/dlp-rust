---
phase: 23-usb-enumeration-in-dlp-agent
verified: 2026-04-22T08:00:00Z
status: passed
score: 13/13 must-haves verified
overrides_applied: 0
# SC-1, SC-2, SC-3 were human-verified and approved by the user during Plan 02 Task 2.
# CR-01 and CR-02 from the code review are real bugs but do not block the phase goal
# (identity capture and logging) which has been verified live by the developer.
---

# Phase 23: USB Enumeration in dlp-agent Verification Report

**Phase Goal:** USB Enumeration in dlp-agent — capture DeviceIdentity (VID, PID, serial, description) on USB device arrival and log it at INFO level; store in-memory for Phase 26 enforcement use; preserve existing file-write blocking behavior.
**Verified:** 2026-04-22T08:00:00Z
**Status:** passed
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | UsbDetector gains a device_identities field keyed by drive letter | VERIFIED | `pub device_identities: RwLock<HashMap<char, DeviceIdentity>>` at usb.rs:87 |
| 2 | A pure-Rust parser converts a USB device interface path into (vid, pid, serial) | VERIFIED | `fn parse_usb_device_path(dbcc_name: &str) -> DeviceIdentity` at usb.rs:716, no `#[cfg(windows)]` guard |
| 3 | Devices without a serial number parse to serial = "(none)" | VERIFIED | usb.rs:735 — `raw_serial.is_empty() || raw_serial.starts_with('&')` maps to `"(none)"` |
| 4 | Parser never panics and never returns Err — malformed paths yield best-effort fields | VERIFIED | No `.unwrap()` anywhere in `parse_usb_device_path`; 3 tests cover empty/malformed/unusual input |
| 5 | dlp-agent Cargo.toml declares Win32_Devices_DeviceAndDriverInstallation feature | VERIFIED | Cargo.toml:67 — `"Win32_Devices_DeviceAndDriverInstallation"` inside windows features array |
| 6 | GUID_DEVINTERFACE_USB_DEVICE defined with value {A5DCBF10-6530-11D2-901F-00C04FB951ED} | VERIFIED | usb.rs:215-220 — `from_values(0xA5DC_BF10, 0x6530, 0x11D2, [0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED])` matches SDK value |
| 7 | register_usb_notifications makes a SECOND RegisterDeviceNotificationW call for GUID_DEVINTERFACE_USB_DEVICE | VERIFIED | usb.rs:636-655 — second registration block with `GUID_DEVINTERFACE_USB_DEVICE`; 6 grep hits confirm both call sites (lines 624, 649) |
| 8 | usb_wndproc handles WM_DEVICECHANGE with correct routing by dbcc_classguid | VERIFIED | usb.rs:245-287 — WM_DEVICECHANGE arm routes VOLUME to handle_volume_event and USB_DEVICE to on_usb_device_arrival/removal |
| 9 | On USB device arrival, agent logs at INFO level with drive, vid, pid, serial, and description | VERIFIED (human-approved) | usb.rs:362-369 — `info!(drive = %letter, vid = %identity.vid, pid = %identity.pid, serial = %identity.serial, description = %identity.description, "USB device arrived — identity captured")` |
| 10 | Devices without serial log with serial = "(none)" | VERIFIED (human-approved) | Parser sentinel at usb.rs:735 confirmed by test_parse_no_serial_empty_segment and test_parse_no_serial_ampersand_synthesized; human plug test approved |
| 11 | Device description populated via SetupDiGetDeviceRegistryPropertyW with SPDRP_FRIENDLYNAME, falling back to SPDRP_DEVICEDESC | VERIFIED | usb.rs:460-463 — `read_string_property(hdev, &devinfo, SPDRP_FRIENDLYNAME).filter(|s| !s.is_empty()).or_else(|| read_string_property(hdev, &devinfo, SPDRP_DEVICEDESC))` |
| 12 | Existing file-write blocking behavior preserved | VERIFIED (human-approved) | `on_drive_arrival`, `on_drive_removal`, `should_block_write` unchanged; `handle_volume_event` rescan drives calls same `on_drive_arrival` path; human checkpoint approved SC-3 |
| 13 | device_identities keyed by drive letter, readable by Phase 26 via device_identity_for_drive | VERIFIED | `pub fn device_identity_for_drive(&self, drive_letter: char) -> Option<DeviceIdentity>` at usb.rs:165-168, case-insensitive via `to_ascii_uppercase()` |

**Score:** 13/13 truths verified

---

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `dlp-agent/src/detection/usb.rs` | UsbDetector.device_identities field, parse_usb_device_path, device_identity_for_drive, GUID_DEVINTERFACE_USB_DEVICE, WM_DEVICECHANGE arm, second RegisterDeviceNotificationW, SetupDi helpers | VERIFIED | 971 lines; all required symbols present and non-pub for private helpers |
| `dlp-agent/Cargo.toml` | Win32_Devices_DeviceAndDriverInstallation feature flag | VERIFIED | Line 67, inside `windows = { version = "0.58", features = [...] }` block |
| `dlp-common/src/endpoint.rs` | DeviceIdentity struct (vid, pid, serial, description) | VERIFIED (pre-existing) | Lines 112-123; imported correctly as `use dlp_common::{Classification, DeviceIdentity}` at usb.rs:36 |

---

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `dlp-agent/src/detection/usb.rs` | `dlp_common::DeviceIdentity` | `use dlp_common::{Classification, DeviceIdentity}` | WIRED | usb.rs:36 |
| `UsbDetector` | `device_identities RwLock map` | struct field `pub device_identities: RwLock<HashMap<char, DeviceIdentity>>` | WIRED | usb.rs:87 |
| `usb_wndproc WM_DEVICECHANGE arm` | `parse_usb_device_path + setupdi_description_for_device + DRIVE_DETECTOR` | DBT_DEVICEARRIVAL dispatch by dbcc_classguid | WIRED | usb.rs:271-276 — `on_usb_device_arrival(detector, &device_path)` called after GUID match |
| `register_usb_notifications` | `RegisterDeviceNotificationW for GUID_DEVINTERFACE_USB_DEVICE` | second DEV_BROADCAST_DEVICEINTERFACE_W on same hwnd | WIRED | usb.rs:636-655 |
| `usb arrival handler` | `UsbDetector::device_identities map` | `write().insert(letter, identity)` | WIRED | usb.rs:370 — `detector.device_identities.write().insert(letter, identity)` |

---

### Data-Flow Trace (Level 4)

`parse_usb_device_path` and `device_identities` are not UI-rendering components — they are a parser and in-memory store. Data flow verified structurally:

1. WM_DEVICECHANGE callback receives kernel-provided `lparam` pointer
2. `read_dbcc_name` extracts the device path wide string
3. `parse_usb_device_path` produces VID/PID/serial from the path string
4. `setupdi_description_for_device` fetches the friendly name via SetupDi
5. `on_usb_device_arrival` merges both and inserts into `device_identities`
6. `tracing::info!` emits the structured log with all five fields
7. `device_identity_for_drive` exposes the map entry for Phase 26

All stages are wired. No stage returns a hardcoded empty value that flows to output; `setupdi_description_for_device` returns `String::new()` on failure per D-04 (documented design decision, not a stub — the log still fires with the other fields).

---

### Behavioral Spot-Checks

Step 7b: SKIPPED for Win32 message-pump code — the WM_DEVICECHANGE path requires a live Windows message pump and a physical USB device. Behavioral verification was performed as the human checkpoint in Plan 02 Task 2 (SC-1, SC-2, SC-3 all approved by user).

Unit tests that do run without Win32 (18 total, all platform-agnostic):

| Behavior | Test | Status |
|----------|------|--------|
| Happy-path parse of VID/PID/serial | test_parse_happy_path | PASS (18 tests confirmed by Plan 02 SUMMARY) |
| Empty serial -> "(none)" sentinel | test_parse_no_serial_empty_segment | PASS |
| Synthesized &N serial -> "(none)" | test_parse_no_serial_ampersand_synthesized | PASS |
| Lowercase VID_/PID_ prefix accepted | test_parse_lowercase_vid_pid_accepted | PASS |
| Malformed segment -> best-effort | test_parse_malformed_missing_vid_pid_segment | PASS |
| Empty string input -> no panic | test_parse_empty_string | PASS |
| Two-segment path -> "(none)" | test_parse_does_not_panic_on_unusual_input | PASS |
| device_identities defaults empty | test_device_identities_default_empty | PASS |
| Case-insensitive drive lookup | test_device_identity_for_drive_present_and_absent | PASS |
| Arrival stores identity | test_on_usb_device_arrival_stores_identity_when_drive_letter_available | PASS |
| Removal matches by VID/PID/serial | test_on_usb_device_removal_logic_matches_by_vid_pid_serial | PASS |

---

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| USB-01 | 23-01, 23-02 | Agent captures VID, PID, Serial Number, and device description on DBT_DEVICEARRIVAL via SetupDiGetClassDevsW / SetupDiGetDeviceInstanceIdW | SATISFIED | `on_usb_device_arrival` parses VID/PID/serial from `dbcc_name` (REQUIREMENTS.md uses `SetupDiGetDeviceInstanceIdW`; implementation uses `SetupDiGetClassDevsW + SetupDiGetDeviceRegistryPropertyW` for description — functionally equivalent capture of all four required fields) |

No orphaned requirements — USB-01 is the only requirement mapped to Phase 23 in REQUIREMENTS.md traceability table (line 71).

---

### Anti-Patterns Found

| File | Location | Pattern | Severity | Impact |
|------|----------|---------|----------|--------|
| usb.rs | Lines 664-669 (message loop) | `GetMessageW` return -1 not handled — loop continues on OS error, potential busy-spin | Warning | Does not affect identity capture goal; only triggers if the message-only window handle becomes invalid at runtime. Documented in REVIEW.md CR-01. |
| usb.rs | Lines 623-655, 684-693 | `HDEVNOTIFY` handles from `RegisterDeviceNotificationW` are dropped immediately; `UnregisterDeviceNotification` never called | Warning | Resource leak at shutdown; does not affect identity capture or logging during normal operation. Documented in REVIEW.md CR-02. |
| usb.rs | Lines 189-193 | Redundant `unsafe impl Send + Sync` — both fields are already Send+Sync, suppresses future unsoundness detection | Info | No runtime impact. Documented in REVIEW.md WR-01. |
| usb.rs | Line 307 | Magic constant `32_768` for max device path UTF-16 length | Info | No runtime impact. Documented in REVIEW.md IN-01. |
| usb.rs | Line 485 | Magic constant `1024` for SetupDi enumeration loop cap | Info | No runtime impact. Documented in REVIEW.md IN-02. |

**Stub classification:** None of the above are stubs. `setupdi_description_for_device` returns `String::new()` on failure — this is explicitly documented behavior (D-04 in CONTEXT.md), not a placeholder. The log still fires with the other fields populated. The description field being empty in failure cases is the designed fallback, not an omission.

**CR-01 and CR-02 are real bugs.** However, they do not block the phase goal (identity capture and INFO-level logging on USB arrival). Both bugs affect resource cleanup and error recovery paths that are not exercised in normal plug-event operation. The code review documented these and they should be addressed in a maintenance phase. They are noted here as known issues.

---

### Human Verification Required

None — all three success criteria were human-verified and approved by the user during Plan 02 Task 2:

- SC-1: USB arrival logs INFO with drive, vid, pid, serial, description fields within 1 second — APPROVED
- SC-2: Devices without serial log `serial=(none)` — APPROVED
- SC-3: Existing file-write blocking unchanged — APPROVED

---

### Known Issues (Non-Blocking)

The following issues from REVIEW.md do not prevent the phase goal from being achieved but should be tracked for future resolution:

1. **CR-01** — `GetMessageW` error return (-1) creates a potential busy-loop if the message window handle becomes invalid. Fix: add a `-1` arm in the `match ret.0` block (REVIEW.md lines 47-76).
2. **CR-02** — `HDEVNOTIFY` handles leaked at shutdown; `UnregisterDeviceNotification` is never called. Fix: store and return both handles from `register_usb_notifications`, call `UnregisterDeviceNotification` in `unregister_usb_notifications` (REVIEW.md lines 80-131).
3. **WR-01** — Redundant manual `unsafe impl Send + Sync` for `UsbDetector` (REVIEW.md lines 140-157).
4. **WR-02** — Double `GetDriveTypeW` call on volume arrival (REVIEW.md lines 159-185).
5. **WR-03** — Window class not unregistered on error paths in `register_usb_notifications` (REVIEW.md lines 187-218).

---

### Gaps Summary

No gaps. All 13 must-haves are verified against the actual code. The phase goal — capture DeviceIdentity on USB arrival, log at INFO, store in-memory, preserve blocking — is fully implemented and human-approved. Two code-review bugs (CR-01 and CR-02) are real but do not invalidate goal achievement.

---

_Verified: 2026-04-22T08:00:00Z_
_Verifier: Claude (gsd-verifier)_
