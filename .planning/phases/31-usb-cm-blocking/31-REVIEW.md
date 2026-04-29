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
  critical: 4
  warning: 6
  info: 1
  total: 11
status: issues_found
---

# Phase 31: USB CM Blocking — Code Review Report

**Reviewed:** 2026-04-29
**Depth:** standard
**Files Reviewed:** 7
**Status:** issues_found

## Summary

This review covers the Phase 31 implementation for USB Configuration Manager (CM) blocking, which integrates Windows PnP APIs (`CM_Disable_DevNode`, `CM_Enable_DevNode`) and volume DACL manipulation into the DLP agent. The code introduces a `DeviceController` singleton, USB device notification handling via a hidden window message loop, and trust-tier-based enforcement (Blocked, ReadOnly, FullAccess).

Four **critical** issues were found: (1) `CM_Disable_DevNode` and `CM_Enable_DevNode` are called with flag `0` instead of the documented `CM_DISABLE_ABSOLUTE`/`CM_ENABLE_ABSOLUTE`, which may cause the device to be re-enabled on reboot rather than permanently disabled; (2) `GetFileSecurityW` only queries `DACL_SECURITY_INFORMATION`, so the cached security descriptor is incomplete and may lose owner/group information on restore; (3) `unregister_usb_notifications` is a no-op that leaks the hidden window, message-loop thread, and registered device notification handles; (4) `read_dbcc_name` performs an unbounded unsafe pointer walk without provenance guarantees, risking undefined behavior on malformed OS messages.

Six **warning** issues include: a potential double-lock deadlock in `detection/usb.rs`, unsafe UTF-16 string parsing without length validation, missing error handling for `LocalFree`, a hardcoded 30-second cooldown that could miss rapid re-insertions, platform-unconditional module declarations in `lib.rs`, and a `const`-to-`mut` pointer cast that violates Rust aliasing rules.

One **info** issue covers a misleading debug log statement.

## Critical Issues

### CR-01: CM_Disable_DevNode called with flag 0 instead of CM_DISABLE_ABSOLUTE

**File:** `dlp-agent/src/device_controller.rs:139`
**Issue:** The doc comment on `disable_usb_device` (line 86) states it disables the device with `CM_DISABLE_ABSOLUTE`, but the actual call passes `0`:

```rust
let cr = unsafe { CM_Disable_DevNode(dev_inst, 0) };
```

The Windows SDK defines `CM_DISABLE_ABSOLUTE` as `0x00000001`. Passing `0` is equivalent to `CM_DISABLE_HARDWARE` (also `0x00000001` on some SDK versions, but the explicit constant is required for correctness). More importantly, `CM_DISABLE_ABSOLUTE` ensures the device stays disabled across reboots. Without this flag, the OS may re-enable the device on the next boot, silently weakening the "Blocked" trust tier.

**Fix:**
```rust
const CM_DISABLE_ABSOLUTE: u32 = 0x00000001;
let cr = unsafe { CM_Disable_DevNode(dev_inst, CM_DISABLE_ABSOLUTE) };
```

---

### CR-02: CM_Enable_DevNode called with flag 0 instead of CM_ENABLE_ABSOLUTE

**File:** `dlp-agent/src/device_controller.rs:202`
**Issue:** Symmetric to CR-01. The `enable_usb_device` doc comment (line 156) references `CM_ENABLE_ABSOLUTE`, but the code passes `0`:

```rust
let cr = unsafe { CM_Enable_DevNode(dev_inst, 0) };
```

`CM_ENABLE_ABSOLUTE` (`0x00000001`) ensures the device is permanently re-enabled. Passing `0` may leave the device in a disabled state after reboot, causing user confusion and support tickets.

**Fix:**
```rust
const CM_ENABLE_ABSOLUTE: u32 = 0x00000001;
let cr = unsafe { CM_Enable_DevNode(dev_inst, CM_ENABLE_ABSOLUTE) };
```

---

### CR-03: Incomplete security descriptor query loses owner/group on restore

**File:** `dlp-agent/src/device_controller.rs:244-250, 264-270, 279-281`
**Issue:** `set_volume_readonly` queries the volume's security descriptor using only `DACL_SECURITY_INFORMATION.0`:

```rust
GetFileSecurityW(
    path_pcwstr,
    DACL_SECURITY_INFORMATION.0,
    ...
)
```

This retrieves **only** the DACL. The owner, primary group, and SACL are omitted. The cached bytes are later restored verbatim by `restore_volume_acl` (line 367). When restored, the security descriptor will have a valid DACL but may have a missing or incorrect owner/group, which can cause:

1. Windows to reject the descriptor as invalid (`ERROR_INVALID_SECURITY_DESCR`).
2. The volume to inherit an unexpected owner, breaking subsequent permission checks.
3. Audit failures if SACL was present.

**Fix:** Query all relevant parts of the security descriptor:
```rust
use windows::Win32::Security::OWNER_SECURITY_INFORMATION;
use windows::Win32::Security::GROUP_SECURITY_INFORMATION;

let info = DACL_SECURITY_INFORMATION.0
         | OWNER_SECURITY_INFORMATION.0
         | GROUP_SECURITY_INFORMATION.0;

let _ = unsafe {
    GetFileSecurityW(path_pcwstr, info, ...)
};
```

Also update the `SetFileSecurityW` call in `restore_volume_acl` to use the same `info` mask.

---

### CR-04: unregister_usb_notifications is a no-op — leaks window, thread, and handles

**File:** `dlp-agent/src/detection/usb.rs:918-927`
**Issue:** The function is documented as cleaning up USB notifications, but it does nothing:

```rust
pub fn unregister_usb_notifications(hwnd: HWND, _thread: std::thread::JoinHandle<()>) {
    let _ = hwnd;
    *DRIVE_DETECTOR.lock() = None;
    debug!("USB device notifications cleanup skipped (process exit imminent)");
}
```

It ignores `hwnd` (the hidden message window) and `_thread` (the message-loop thread). This leaks:

1. The hidden window (`hwnd`) — never destroyed with `DestroyWindow`.
2. The message-loop thread — never joined; if the agent is restarted in-process (e.g., as a DLL or during tests), the thread persists.
3. Registered device notification handles (`hDeviceNotifyVolume`, `hDeviceNotifyUsb`) — never unregistered with `UnregisterDeviceNotification`.

In a service context where the process may be recycled or the agent reinitialized, these leaks accumulate. The thread also holds a reference to the `DeviceController` via `DEVICE_CONTROLLER`, preventing its drop.

**Fix:** Implement proper cleanup:
```rust
pub fn unregister_usb_notifications(
    hwnd: HWND,
    thread: std::thread::JoinHandle<()>,
) {
    // Unregister device notifications before destroying the window.
    if let Some(detector) = DRIVE_DETECTOR.lock().take() {
        unsafe {
            if let Some(h) = detector.h_device_notify_volume {
                let _ = UnregisterDeviceNotification(h);
            }
            if let Some(h) = detector.h_device_notify_usb {
                let _ = UnregisterDeviceNotification(h);
            }
        }
    }

    // Post WM_CLOSE to the hidden window to break the message loop.
    unsafe {
        let _ = PostMessageW(hwnd, WM_CLOSE, WPARAM(0), LPARAM(0));
    }

    // Wait for the thread to exit.
    if let Err(e) = thread.join() {
        warn!("USB notification thread panicked: {:?}", e);
    }

    // Destroy the window.
    unsafe {
        let _ = DestroyWindow(hwnd);
    }

    debug!("USB device notifications cleaned up");
}
```

Note: `h_device_notify_volume` and `h_device_notify_usb` fields must be added to `DriveDetector` and populated during registration.

---

### CR-05: read_dbcc_name performs unbounded unsafe pointer walk without provenance guarantees

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

## Warnings

### WR-01: Potential double-lock deadlock in on_usb_device_arrival

**File:** `dlp-agent/src/detection/usb.rs:490-586`
**Issue:** `on_usb_device_arrival` acquires `DRIVE_MAP.lock()` (line 502), then calls `DEVICE_CONTROLLER.get().unwrap().set_volume_readonly(...)` (line 560). `set_volume_readonly` internally acquires `self.original_dacls.lock()` (line 280). While this is a different mutex, the pattern of holding one lock while calling into a subsystem that acquires another is a classic deadlock risk if future refactoring causes a reverse lock ordering elsewhere (e.g., a removal handler that holds `original_dacls` while trying to lock `DRIVE_MAP`).

**Fix:** Minimize the scope of `DRIVE_MAP` lock. Clone the needed data and drop the lock before calling into `DeviceController`:
```rust
let (vid, pid, serial, drive_letter) = {
    let mut map = DRIVE_MAP.lock();
    // ... insert into map ...
    (vid.clone(), pid.clone(), serial.clone(), drive_letter)
};
// Now call DeviceController without holding DRIVE_MAP.
if let Some(controller) = DEVICE_CONTROLLER.get() {
    controller.set_volume_readonly(drive_letter)?;
}
```

---

### WR-02: LocalFree error is silently ignored

**File:** `dlp-agent/src/device_controller.rs:314-316`
**Issue:** After freeing the security descriptor allocated by `ConvertStringSecurityDescriptorToSecurityDescriptorW`, the return value of `LocalFree` is discarded:

```rust
if !p_sd.0.is_null() {
    let _ = unsafe { LocalFree(windows::Win32::Foundation::HLOCAL(p_sd.0)) };
}
```

`LocalFree` returns `NULL` on success or the same handle on failure. While failure here is rare, silently ignoring it means a leaked handle goes unlogged. More importantly, if `LocalFree` fails, `p_sd` is still a dangling pointer that should not be used — but the code does not use it after this block, so the practical risk is low. The issue is the pattern of ignoring cleanup errors.

**Fix:** Log the failure:
```rust
if !p_sd.0.is_null() {
    let ret = unsafe { LocalFree(windows::Win32::Foundation::HLOCAL(p_sd.0)) };
    if !ret.0.is_null() {
        warn!("LocalFree failed for security descriptor");
    }
}
```

---

### WR-03: Hardcoded 30-second cooldown may miss rapid re-insertions

**File:** `dlp-agent/src/usb_enforcer.rs:93-107`
**Issue:** `should_notify` uses a `HashMap<char, Instant>` with a 30-second cooldown to suppress duplicate notifications for the same drive. If a user removes and re-inserts the same USB device within 30 seconds, the re-insertion is silently ignored. For a DLP system, this is a gap: a malicious actor could remove a blocked device, wait a few seconds, and re-insert it without triggering a new enforcement check.

**Fix:** Tie the cooldown to the device's physical presence (e.g., clear the entry in `on_usb_device_removal`), or reduce the cooldown to a sub-second value and document the rationale:
```rust
// In on_usb_device_removal (detection/usb.rs):
NOTIFIED_DRIVES.lock().remove(&drive_letter);
```

Alternatively, replace the time-based cooldown with a presence-based one: only suppress if the drive letter is still present from the *same* device instance (VID/PID/serial match).

---

### WR-04: Platform-specific modules not gated with cfg(windows)

**File:** `dlp-agent/src/lib.rs`
**Issue:** The module declarations for `device_controller`, `device_registry`, `usb_enforcer`, and possibly others are not wrapped in `#[cfg(windows)]`. These modules contain extensive Windows-only code (Win32 FFI, CM APIs, SetupDi APIs). Compiling on non-Windows platforms will fail with missing imports and undefined symbols.

**Fix:** Gate Windows-only modules:
```rust
#[cfg(windows)]
pub mod device_controller;
#[cfg(windows)]
pub mod device_registry;
#[cfg(windows)]
pub mod usb_enforcer;
```

Alternatively, provide stub implementations for non-Windows platforms if cross-platform compilation is a goal.

---

### WR-05: restore_volume_acl casts const pointer to mutable for SetFileSecurityW

**File:** `dlp-agent/src/device_controller.rs:364`
**Issue:** `restore_volume_acl` constructs a `PSECURITY_DESCRIPTOR` from cached bytes:

```rust
let p_sd = PSECURITY_DESCRIPTOR(sd_buf.as_ptr() as *mut _);
```

`sd_buf` is an immutable `Vec<u8>`, but `as_ptr()` is cast to `*mut _`. `SetFileSecurityW` does not mutate the security descriptor (it copies it), so the cast is technically safe, but it violates Rust's aliasing rules and is misleading. If a future refactor makes `sd_buf` a shared reference (`&[u8]`), this cast becomes undefined behavior.

**Fix:** Use `std::ptr::NonNull` or document the invariant. Better yet, since `SetFileSecurityW` only reads, cast from a mutable pointer obtained from a local copy:
```rust
let mut sd_buf = sd_buf; // take ownership
let p_sd = PSECURITY_DESCRIPTOR(sd_buf.as_mut_ptr() as *mut _);
```

Or document the safety invariant explicitly:
```rust
// SAFETY: SetFileSecurityW only reads the descriptor; we cast const to mut
// because the Win32 API signature requires PSECURITY_DESCRIPTOR.
let p_sd = PSECURITY_DESCRIPTOR(sd_buf.as_ptr() as *mut _);
```

---

### WR-06: UsbEnforcer::check returns DeviceIdentity::default() for known-USB-without-identity fallback, losing auditability

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

## Info

### IN-01: Debug log statement in production path

**File:** `dlp-agent/src/detection/usb.rs:926`
**Issue:** The no-op `unregister_usb_notifications` contains a `debug!` log that misleadingly states "cleanup skipped (process exit imminent)". This is not accurate — the function is called from `service.rs` during graceful shutdown, not only on process exit. The log message may confuse operators reading logs during service restarts.

**Fix:** Remove or rephrase the log:
```rust
debug!("USB device notifications cleanup invoked");
```

Or, once CR-04 is fixed, replace with:
```rust
debug!("USB device notifications cleaned up successfully");
```

---

_Reviewed: 2026-04-29_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
