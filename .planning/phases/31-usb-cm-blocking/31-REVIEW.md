---
phase: 31-usb-cm-blocking
reviewed: 2026-04-29T00:00:00Z
depth: standard
files_reviewed: 7
files_reviewed_list:
  - dlp-agent/src/device_controller.rs
  - dlp-agent/src/detection/usb.rs
  - dlp-agent/src/usb_enforcer.rs
  - dlp-agent/src/service.rs
  - dlp-agent/src/device_registry.rs
  - dlp-agent/build.rs
  - dlp-agent/src/lib.rs
findings:
  critical: 3
  warning: 4
  info: 0
  total: 7
status: issues_found
---

# Phase 31: Code Review Report

**Reviewed:** 2026-04-29
**Depth:** standard
**Files Reviewed:** 7
**Status:** issues_found

## Summary

Reviewed the Phase 31 USB Configuration Manager blocking implementation, which adds active PnP-level enforcement (`CM_Disable_DevNode`, volume DACL manipulation) alongside the existing file-I/O-level enforcement. The code introduces Windows API interactions with security-critical implications. Found 3 critical issues (handle leaks, unsafe memory access, privilege escalation risk) and 4 warnings (error propagation gaps, documentation drift, dead code, and cross-platform compilation issues).

## Critical Issues

### CR-01: `register_usb_notifications` leaks `HDEVNOTIFY` handles on success path

**File:** `dlp-agent/src/detection/usb.rs:857-889`
**Issue:** `RegisterDeviceNotificationW` returns an `HDEVNOTIFY` handle for each registration. The code discards both `vol_handle` and `usb_handle` via `if let Err(e) = vol_handle` / `if let Err(e) = usb_handle`, never storing the success values. On service shutdown, `unregister_usb_notifications` only destroys the window (which implicitly unregisters notifications), but the comment at line 920-923 explicitly states this is skipped. This means device notification handles are leaked for the process lifetime.

More importantly, if the window is destroyed but the thread keeps running (or vice versa), the OS may deliver `WM_DEVICECHANGE` to a destroyed window, causing undefined behavior. The `UnregisterDeviceNotification` API exists precisely to avoid this.

**Fix:**
```rust
// Store handles in a static or return them alongside hwnd/thread.
static NOTIF_HANDLES: parking_lot::Mutex<Vec<windows::Win32::UI::WindowsAndMessaging::HDEVNOTIFY>> = 
    parking_lot::Mutex::new(Vec::new());

// On success:
if let Ok(handle) = vol_handle {
    NOTIF_HANDLES.lock().push(handle);
}

// In unregister_usb_notifications:
for h in NOTIF_HANDLES.lock().drain(..) {
    let _ = unsafe { UnregisterDeviceNotification(h) };
}
```

---

### CR-02: `read_dbcc_name` performs unbounded `unsafe` pointer walk without provenance guarantees

**File:** `dlp-agent/src/detection/usb.rs:433-444`
**Issue:** The function walks `di.dbcc_name.as_ptr()` with `base.add(len)` to find a null terminator, bounded only by a hardcoded `32_768` iteration limit. The `DEV_BROADCAST_DEVICEINTERFACE_W` struct from the `windows` crate declares `dbcc_name: [u16; 1]`, but the actual allocation is variable-length from the OS. The problem is that `di` is a reference to a struct whose true size is unknown to Rust's type system. `base.add(len)` for `len > 0` is technically out-of-bounds of the `[u16; 1]` array, making this strict-provenance UB even though the OS allocated more memory.

Additionally, if the OS delivers a malformed message where `dbcc_name` lacks a null terminator within the allocation, the loop hits the 32,768 bound and returns a truncated string without warning. More critically, the `lparam.0` pointer at line 369 is dereferenced as `&*(lparam.0 as *const DEV_BROADCAST_DEVICEINTERFACE_W)` without first checking `hdr.dbch_size` against the expected struct size, meaning a truncated or malformed broadcast header could cause a read past the allocation boundary.

**Fix:** Check `hdr.dbch_size` against `std::mem::size_of::<DEV_BROADCAST_HDR>()` before dereferencing the extended struct, and use `std::slice::from_raw_parts` with a length derived from `hdr.dbch_size` rather than an open-ended pointer walk:
```rust
let total_size = hdr.dbch_size as usize;
let header_size = std::mem::size_of::<DEV_BROADCAST_DEVICEINTERFACE_W>();
if total_size < header_size {
    return LRESULT(0); // malformed
}
let name_len_u16 = (total_size - std::mem::size_of::<DEV_BROADCAST_HDR>()) / 2;
let name_slice = std::slice::from_raw_parts(di.dbcc_name.as_ptr(), name_len_u16);
// Now search for null within the bounded slice
```

---

### CR-03: `set_volume_readonly` applies DACL to `\\.\X:` root, not the volume mount point — may not affect user-visible paths

**File:** `dlp-agent/src/device_controller.rs:232-326`
**Issue:** The volume path is constructed as `format!(r"\\.\{}:", drive_letter)`, which opens the raw device namespace (`\\.\E:`). `GetFileSecurityW` / `SetFileSecurityW` on this path operate on the device object, not the mounted volume's directory security descriptor. When users access files via `E:\path\file.txt`, the effective security descriptor is the one on the volume root directory (`E:\`), not the raw device.

This means the DACL modification may not actually prevent writes from user-mode applications that access files through the drive letter mount point. The correct path for volume ACL manipulation is the root directory: `format!(r"{}:\", drive_letter)`.

**Fix:**
```rust
let volume_path = format!(r"{}:\", drive_letter);
```

---

## Warnings

### WR-01: `on_usb_device_arrival` may map the wrong drive letter when multiple USB devices are present

**File:** `dlp-agent/src/detection/usb.rs:498-500`
**Issue:** The drive letter assignment logic finds "the first removable drive letter not yet tracked in `device_identities`". If two USB devices arrive nearly simultaneously (or one is already present), the second device's identity may be mapped to the first device's drive letter, or vice versa. This is a race between the `USB_DEVICE` notification (which carries VID/PID/serial) and the `VOLUME` notification (which establishes the drive letter). The `handle_volume_event` rescan reconciles `blocked_drives`, but `device_identities` is keyed by a heuristic guess.

The result: a Blocked-tier device might have its identity mapped to drive F, while the actual Blocked device is on drive E. The `DeviceController` would then disable the wrong device or apply the wrong DACL.

**Fix:** Use the `dbcc_name` from the `GUID_DEVINTERFACE_VOLUME` notification (which contains the volume GUID path) and correlate it with the USB device via `CM_Get_Parent` / `CM_Get_Child` traversal, or at minimum, validate the guessed drive letter by checking that the volume's disk number matches the USB device's disk number via `IOCTL_STORAGE_GET_DEVICE_NUMBER`.

---

### WR-02: `DeviceController::disable_usb_device` / `enable_usb_device` use `CM_DISABLE_ABSOLUTE` / `CM_ENABLE_ABSOLUTE` flags via raw `0`

**File:** `dlp-agent/src/device_controller.rs:139, 202`
**Issue:** Both `CM_Disable_DevNode` and `CM_Enable_DevNode` are called with `0` as the `ulFlags` parameter. The Windows SDK defines `CM_DISABLE_ABSOLUTE = 0x00000001` and `CM_ENABLE_ABSOLUTE = 0x00000001`. Passing `0` means "disable with global profile" / "enable with global profile", which may not take effect immediately and may be overridden by group policy or hardware profiles. For a DLP agent that needs immediate, unconditional enforcement, `CM_DISABLE_ABSOLUTE` is the correct flag.

**Fix:**
```rust
const CM_DISABLE_ABSOLUTE: u32 = 0x00000001;
const CM_ENABLE_ABSOLUTE: u32 = 0x00000001;
let cr = unsafe { CM_Disable_DevNode(dev_inst, CM_DISABLE_ABSOLUTE) };
let cr = unsafe { CM_Enable_DevNode(dev_inst, CM_ENABLE_ABSOLUTE) };
```

---

### WR-03: `DeviceController` functions are not gated by `#[cfg(windows)]` at the `impl` level, causing dead code on non-Windows

**File:** `dlp-agent/src/device_controller.rs:100-151, 165-214, 232-326, 343-377`
**Issue:** The `#[cfg(windows)]` attribute is applied to each individual `pub fn` method, but the struct definition and `Default` impl are unconditional. On non-Windows platforms, the struct exists but has no public methods — callers in `service.rs` and `detection/usb.rs` would fail to compile because they reference methods that don't exist. However, `lib.rs` gates `pub mod device_controller` unconditionally (line 81), so the module is always available but empty of usable methods on non-Windows.

This is inconsistent with other modules in `lib.rs` (e.g., `usb_enforcer`, `service`) which are all `#[cfg(windows)]`-gated. The mismatch suggests either `device_controller` should also be gated in `lib.rs`, or the `#[cfg(windows)]` should be removed from the methods (and the Windows-only imports handled differently).

**Fix:** Either gate `pub mod device_controller` with `#[cfg(windows)]` in `lib.rs`, or remove `#[cfg(windows)]` from the individual methods and provide no-op stubs for non-Windows builds.

---

### WR-04: `UsbEnforcer::check` returns `DeviceIdentity::default()` (empty strings) for known-USB-without-identity fallback, losing auditability

**File:** `dlp-agent/src/usb_enforcer.rs:152-160`
**Issue:** When a drive is in `blocked_drives` but has no `DeviceIdentity` entry, the enforcer returns a `UsbBlockResult` with `identity: DeviceIdentity::default()` (all empty strings). This means the audit log will show a DENY decision with no VID, PID, or serial number, making it impossible to identify which physical device was blocked. In a forensic or compliance context, this is a significant gap.

**Fix:** At minimum, include the drive letter in the `DeviceIdentity` description field so the audit log is actionable:
```rust
identity: DeviceIdentity {
    vid: "unknown".into(),
    pid: "unknown".into(),
    serial: "unknown".into(),
    description: format!("USB drive {} (identity not captured)", drive),
},
```

---

_Reviewed: 2026-04-29_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
