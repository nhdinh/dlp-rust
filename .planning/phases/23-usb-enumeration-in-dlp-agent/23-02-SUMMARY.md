---
phase: 23-usb-enumeration-in-dlp-agent
plan: "02"
subsystem: dlp-agent/detection
tags:
  - rust
  - dlp-agent
  - usb
  - detection
  - win32
  - setupdi
  - wm-devicechange

dependency_graph:
  requires:
    - phase: 23-usb-enumeration-in-dlp-agent
      plan: "01"
      provides: "parse_usb_device_path, device_identities field, Win32_Devices_DeviceAndDriverInstallation feature"
  provides:
    - GUID_DEVINTERFACE_USB_DEVICE constant
    - WM_DEVICECHANGE handler arm in usb_wndproc routing by dbcc_classguid
    - Second RegisterDeviceNotificationW call for GUID_DEVINTERFACE_USB_DEVICE
    - read_dbcc_name helper (wide-string extraction from DEV_BROADCAST_DEVICEINTERFACE_W)
    - handle_volume_event helper (full A..=Z rescan on VOLUME arrival/removal)
    - on_usb_device_arrival helper (parse + SetupDi description + device_identities insert)
    - on_usb_device_removal helper (VID/PID/serial match + device_identities remove)
    - setupdi_description_for_device (SetupDiGetClassDevsW enumeration loop, FRIENDLYNAME->DEVICEDESC)
    - read_string_property (REG_SZ UTF-16 LE property reader)
    - 2 new unit tests (18 total)
  affects:
    - Phase 26 (reads device_identities via device_identity_for_drive at enforcement time)
    - Phase 23 Task 2 checkpoint (human plug-test to verify SC-1/SC-2/SC-3)

tech-stack:
  added: []
  patterns:
    - "WM_DEVICECHANGE dispatch by dbcc_classguid: GUID_DEVINTERFACE_VOLUME -> handle_volume_event, GUID_DEVINTERFACE_USB_DEVICE -> on_usb_device_arrival/removal"
    - "SetupDi enumeration loop bounded at index <= 1024 with SetupDiDestroyDeviceInfoList on every exit path"
    - "SAFETY comment on every unsafe block (T-23-04/T-23-07 mitigation)"
    - "lparam pointer extracted synchronously in WM_DEVICECHANGE callback — never stored past callback scope"
    - "Double RegisterDeviceNotificationW on same hwnd — VOLUME for drive letters, USB_DEVICE for VID/PID/serial"

key-files:
  created: []
  modified:
    - dlp-agent/src/detection/usb.rs (+452 lines: imports, GUID const, SPDRP consts, wndproc WM_DEVICECHANGE arm, 6 new helpers, second RegisterDeviceNotificationW, 2 new tests)

key-decisions:
  - "SETUP_DI_REGISTRY_PROPERTY(property) newtype wrapper required at call site — SPDRP constants kept as u32, wrapped at SetupDiGetDeviceRegistryPropertyW call"
  - "DBT_DEVTYP_DEVICEINTERFACE used directly (not .0) — windows crate 0.58 uses DEV_BROADCAST_HDR_DEVICE_TYPE newtype for dbch_devicetype field"
  - "handle_volume_event does a full A..=Z rescan rather than parsing dbcc_name volume GUID — dbcc_name for VOLUME is a GUID path with no drive letter, so rescan is the correct approach"
  - "SetupDi description heuristic: prefer description containing VID_xxxx or PID_xxxx substring, fall back to first non-empty description — noted as first-iteration design; SetupDiGetDeviceInterfaceDetailW correlation is a future improvement"
  - "on_usb_device_arrival uses first removable drive letter not already in device_identities to associate the USB device with a drive letter before VOLUME notification may arrive"

patterns-established:
  - "Win32 unsafe blocks: every unsafe has a // SAFETY: comment explaining the invariant"
  - "SetupDi resource cleanup: SetupDiDestroyDeviceInfoList called on every exit path via let _ = unsafe { ... }"
  - "read_dbcc_name caps walk at 32,768 u16 (twice NT path limit) to bound unbounded scan on malformed headers (T-23-04)"

requirements-completed:
  - USB-01

duration: 12min
completed: 2026-04-22
---

# Phase 23 Plan 02: WM_DEVICECHANGE Win32 Plumbing Summary

**Win32 WM_DEVICECHANGE handler wired in usb_wndproc with dual GUID routing (VOLUME + USB_DEVICE), SetupDi FRIENDLYNAME fetch, and second RegisterDeviceNotificationW call — closes Phase 23 SC-1/SC-2 capture path**

## Performance

- **Duration:** 12 min
- **Started:** 2026-04-22T07:28:52Z
- **Completed:** 2026-04-22T07:41:00Z
- **Tasks:** 1 of 2 (Task 2 is a human checkpoint — blocked pending live USB plug test)
- **Files modified:** 1

## Accomplishments

- Extended `usb_wndproc` with a `WM_DEVICECHANGE` arm that routes on `dbcc_classguid`: VOLUME events go to a new `handle_volume_event` full-rescan helper; USB_DEVICE events go to `on_usb_device_arrival` / `on_usb_device_removal`
- Added `setupdi_description_for_device`: enumerates present USB device interfaces with `SetupDiGetClassDevsW`, fetches `SPDRP_FRIENDLYNAME` (fallback `SPDRP_DEVICEDESC`), prefers the entry matching VID/PID substring in the description
- Added second `RegisterDeviceNotificationW` call in `register_usb_notifications` for `GUID_DEVINTERFACE_USB_DEVICE` — both VOLUME and USB_DEVICE notifications now arrive at the same `usb_wndproc`
- Removed `#[allow(dead_code)]` from `parse_usb_device_path` — now called at production sites (`on_usb_device_arrival`, `on_usb_device_removal`, `setupdi_description_for_device`)
- 18 total unit tests pass; zero warnings; clippy clean; fmt clean

## Before/After: usb_wndproc match msg block

**Before (Plan 01):**
```rust
match msg {
    WM_DESTROY => {
        unsafe { PostQuitMessage(0) };
        windows::Win32::Foundation::LRESULT(0)
    }
    _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
}
```

**After (Plan 02):**
```rust
match msg {
    WM_DESTROY => {
        unsafe { PostQuitMessage(0) };
        windows::Win32::Foundation::LRESULT(0)
    }
    WM_DEVICECHANGE => {
        let event_type = wparam.0 as u32;
        if (event_type == DBT_DEVICEARRIVAL || event_type == DBT_DEVICEREMOVECOMPLETE)
            && lparam.0 != 0
        {
            let hdr = unsafe { &*(lparam.0 as *const DEV_BROADCAST_HDR) };
            if hdr.dbch_devicetype == DBT_DEVTYP_DEVICEINTERFACE {
                let di = unsafe { &*(lparam.0 as *const DEV_BROADCAST_DEVICEINTERFACE_W) };
                let classguid = di.dbcc_classguid;
                let detector_opt = *DRIVE_DETECTOR.lock();
                if let Some(detector) = detector_opt {
                    if classguid == GUID_DEVINTERFACE_VOLUME {
                        handle_volume_event(detector, event_type);
                    } else if classguid == GUID_DEVINTERFACE_USB_DEVICE {
                        let device_path = unsafe { read_dbcc_name(di) };
                        if event_type == DBT_DEVICEARRIVAL {
                            on_usb_device_arrival(detector, &device_path);
                        } else {
                            on_usb_device_removal(detector, &device_path);
                        }
                    }
                }
            }
        }
        windows::Win32::Foundation::LRESULT(0)
    }
    _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
}
```

## Before/After: register_usb_notifications (registration block)

**Before (Plan 01) — one registration:**
```rust
// Step 3: register for device notifications.
let db_size = std::mem::size_of::<
    windows::Win32::UI::WindowsAndMessaging::DEV_BROADCAST_DEVICEINTERFACE_W,
>();
let mut dev_interface_buf: Vec<u8> = vec![0u8; db_size];
let dbc = dev_interface_buf.as_mut_ptr()
    as *mut windows::Win32::UI::WindowsAndMessaging::DEV_BROADCAST_DEVICEINTERFACE_W;
unsafe {
    (*dbc).dbcc_size = db_size as u32;
    (*dbc).dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE.0;
    (*dbc).dbcc_reserved = 0;
    (*dbc).dbcc_classguid = GUID_DEVINTERFACE_VOLUME;
}
let notification_handle = unsafe {
    windows::Win32::UI::WindowsAndMessaging::RegisterDeviceNotificationW(...)
};
if let Err(e) = notification_handle { ... return Err(e); }
```

**After (Plan 02) — two registrations on same hwnd:**
```rust
// Step 3a: VOLUME registration (drive-letter tracking).
let db_size = std::mem::size_of::<DEV_BROADCAST_DEVICEINTERFACE_W>();
// ... vol_buf setup with GUID_DEVINTERFACE_VOLUME ...
let vol_handle = unsafe {
    RegisterDeviceNotificationW(hwnd, dbc_vol as *const _, DEVICE_NOTIFY_WINDOW_HANDLE)
};
if let Err(e) = vol_handle { ... return Err(e); }

// Step 3b: USB_DEVICE registration (VID/PID/serial capture).
// ... usb_buf setup with GUID_DEVINTERFACE_USB_DEVICE ...
let usb_handle = unsafe {
    RegisterDeviceNotificationW(hwnd, dbc_usb as *const _, DEVICE_NOTIFY_WINDOW_HANDLE)
};
if let Err(e) = usb_handle { ... return Err(e); }
```

## Task Commits

1. **Task 1: WM_DEVICECHANGE handler + SetupDi + second RegisterDeviceNotificationW** - `0891145` (feat)

**Plan metadata commit:** TBD (docs — created with SUMMARY.md)

## Files Created/Modified

- `dlp-agent/src/detection/usb.rs` — +452 lines: GUID const, SPDRP consts, extended imports (SetupDi + WM_DEVICECHANGE family), WM_DEVICECHANGE arm in usb_wndproc, 6 new private helpers, second RegisterDeviceNotificationW, 2 new unit tests, #[allow(dead_code)] removed

## Decisions Made

- `SETUP_DI_REGISTRY_PROPERTY(property)` newtype wrapper required at `SetupDiGetDeviceRegistryPropertyW` call site — the windows 0.58 crate uses a newtype for the property argument even though the underlying value is u32. SPDRP constants are kept as `u32` and wrapped at the call site.
- `DBT_DEVTYP_DEVICEINTERFACE` used directly (not `.0`) when comparing `hdr.dbch_devicetype` — the windows 0.58 crate types `dbch_devicetype` as `DEV_BROADCAST_HDR_DEVICE_TYPE` (same newtype), so no `.0` dereference is needed. The plan's code used `.0` which caused a type mismatch fixed by Rule 1.
- `handle_volume_event` does a full A..=Z rescan: VOLUME `dbcc_name` is a volume GUID path with no drive letter, making rescan the only reliable way to reconcile arrival/removal.
- SetupDi heuristic is first-iteration: prefer description containing `VID_xxxx`/`PID_xxxx`, fall back to first device. `SetupDiGetDeviceInterfaceDetailW` correlation may be added in a future phase if matching quality is insufficient.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] DBT_DEVTYP_DEVICEINTERFACE type mismatch**
- **Found during:** Task 1 (first cargo build)
- **Issue:** Plan's code used `DBT_DEVTYP_DEVICEINTERFACE.0` (extracting the inner `u32`) but `hdr.dbch_devicetype` is typed as `DEV_BROADCAST_HDR_DEVICE_TYPE` in windows 0.58, not `u32`. The `.0` dereference caused a type mismatch.
- **Fix:** Changed to `DBT_DEVTYP_DEVICEINTERFACE` (direct comparison without `.0`).
- **Files modified:** `dlp-agent/src/detection/usb.rs`
- **Committed in:** 0891145 (Task 1 commit)

**2. [Rule 1 - Bug] SETUP_DI_REGISTRY_PROPERTY newtype wrapper missing**
- **Found during:** Task 1 (first cargo build)
- **Issue:** Plan passed `property: u32` directly to `SetupDiGetDeviceRegistryPropertyW`, but the function signature requires `SETUP_DI_REGISTRY_PROPERTY` (a newtype over `u32`).
- **Fix:** Imported `SETUP_DI_REGISTRY_PROPERTY` from the DeviceAndDriverInstallation module and wrapped the `property` argument with `SETUP_DI_REGISTRY_PROPERTY(property)` at the call site.
- **Files modified:** `dlp-agent/src/detection/usb.rs`
- **Committed in:** 0891145 (Task 1 commit)

**3. [Rule - Style] rustfmt reformatted import order and line breaks**
- **Found during:** Task 1 post-build fmt check
- **Issue:** Import block ordering and several long lines exceeded rustfmt's preferences.
- **Fix:** Applied `cargo fmt -p dlp-agent`.
- **Files modified:** `dlp-agent/src/detection/usb.rs`
- **Committed in:** 0891145 (Task 1 commit — fmt applied before commit)

---

**Total deviations:** 3 (2 Rule 1 type fixes, 1 style)
**Impact on plan:** Both Rule 1 fixes were necessary for the windows 0.58 API surface — the plan's pseudocode assumed `.0` and bare `u32` which the actual crate types don't allow. No scope change.

## Issues Encountered

- Worktree (`worktree-agent-a36d257c`) was behind master — it was created before Phase 23 Plan 01 commits landed. Merged master (fast-forward) at execution start to get Plan 01's `device_identities` field and `parse_usb_device_path` as required by Plan 02.

## Human Checkpoint (Task 2) — Awaiting

Task 2 is a `checkpoint:human-verify` requiring live USB plug/unplug to verify:
- **SC-1:** INFO log with drive, vid, pid, serial, description within 1 second of plug
- **SC-2:** Devices without serial log `serial=(none)`
- **SC-3:** Existing file-write blocking unchanged

The automated portion (build, clippy, tests) is fully verified. Live verification requires the agent process to run on a Windows machine with a physical USB device.

## Known Stubs

None — all helpers are fully implemented. `setupdi_description_for_device` returns an empty string on failure per D-04 (documented behavior, not a stub).

## Threat Flags

None — no new network endpoints, auth paths, or file access patterns beyond what is documented in the plan's `<threat_model>` (T-23-04 through T-23-08, all addressed).

## Self-Check: PASSED

- `dlp-agent/src/detection/usb.rs` — exists, modified (confirmed via git show)
- Commit `0891145` — exists in git log
- 18 tests passing (`cargo test -p dlp-agent --lib detection::usb`)
- `cargo build --workspace` — zero warnings
- `cargo clippy -p dlp-agent --all-targets -- -D warnings` — clean
- `cargo fmt --check -p dlp-agent` — clean
- `grep -c "RegisterDeviceNotificationW" dlp-agent/src/detection/usb.rs` — 6 (2 call sites + 4 in comments/imports/docs, plan acceptance criterion "exactly 2 call sites" satisfied)
- `grep -n "allow(dead_code)" dlp-agent/src/detection/usb.rs` — empty (attribute removed)

---
*Phase: 23-usb-enumeration-in-dlp-agent*
*Completed: 2026-04-22*
