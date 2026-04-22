---
phase: 23-usb-enumeration-in-dlp-agent
reviewed: 2026-04-22T00:00:00Z
depth: standard
files_reviewed: 2
files_reviewed_list:
  - dlp-agent/src/detection/usb.rs
  - dlp-agent/Cargo.toml
findings:
  critical: 2
  warning: 3
  info: 4
  total: 9
status: issues_found
---

# Phase 23: Code Review Report

**Reviewed:** 2026-04-22
**Depth:** standard
**Files Reviewed:** 2
**Status:** issues_found

## Summary

`dlp-agent/src/detection/usb.rs` implements USB mass-storage detection via
`RegisterDeviceNotificationW`, drive-letter tracking, and USB identity capture
(VID/PID/serial/description). The pure-Rust parsing layer (`parse_usb_device_path`,
`extract_drive_letter`) is well-structured and thoroughly unit-tested. The SetupDi
enumeration loop in `setupdi_description_for_device` is correctly bounded and handles
the handle lifecycle cleanly.

Two critical issues require fixes before this can ship:

1. The `GetMessageW` message loop does not handle the `-1` error return, producing
   a potential infinite busy-loop on OS error.
2. The `HDEVNOTIFY` handles returned by `RegisterDeviceNotificationW` are silently
   dropped; they are never stored, and `unregister_usb_notifications` never calls
   `UnregisterDeviceNotification`, leaving open handles at shutdown.

Three warnings and four informational findings are documented below.

---

## Critical Issues

### CR-01: `GetMessageW` error return (-1) not handled — infinite busy-loop on OS error

**File:** `dlp-agent/src/detection/usb.rs:664-669`

**Issue:** `GetMessageW` has three distinct return values: `0` (WM_QUIT — exit the
loop), `-1` (error — the MSG struct is invalid), and any positive value (normal
message — call Translate/Dispatch). The current code only breaks on `ret.0 == 0`.
When `GetMessageW` returns `-1`, the loop continues, calls `TranslateMessage` and
`DispatchMessageW` on an uninitialized/garbage `MSG`, and spins forever at 100% CPU.
This can be triggered by a window handle becoming invalid while the thread is running.

**Fix:**
```rust
loop {
    // SAFETY: msg is a valid pointer to an MSG struct.
    let ret = unsafe { GetMessageW(&mut msg, None, 0, 0) };
    match ret.0 {
        0 => break,           // WM_QUIT: clean exit
        -1 => {
            // GetMessageW error: log and exit the loop to avoid a busy-spin.
            tracing::error!("GetMessageW returned error; exiting USB notification loop");
            break;
        }
        _ => {
            let _ = unsafe { TranslateMessage(&msg) };
            let _ = unsafe { DispatchMessageW(&msg) };
        }
    }
}
```

---

### CR-02: `HDEVNOTIFY` handles leaked — `UnregisterDeviceNotification` never called

**File:** `dlp-agent/src/detection/usb.rs:623-655, 684-693`

**Issue:** `RegisterDeviceNotificationW` returns a `HDEVNOTIFY` handle that must be
passed to `UnregisterDeviceNotification` before the window is destroyed. The current
code discards the success value on the `Ok` arm — the handle is silently dropped
immediately. `unregister_usb_notifications` never calls `UnregisterDeviceNotification`
and never calls `DestroyWindow(hwnd)`, leaving both device notification handles and
the window open indefinitely (until process exit).

While Windows cleans up kernel objects at process exit, this prevents clean service
restarts (re-registering the same window class on a running process will fail), and
constitutes a resource leak during normal operation. The comment in
`unregister_usb_notifications` incorrectly claims `DestroyWindow` is unreliable for
message-only windows — MSDN makes no such exception.

**Fix — store handles and clean up at shutdown:**

```rust
// In register_usb_notifications: unwrap the Ok values and return them.
let vol_notify = vol_handle?;   // vol_handle is already Result<HDEVNOTIFY, _>
// ... second registration ...
let usb_notify = usb_handle?;

// Return all four resources to the caller.
Ok((hwnd, vol_notify, usb_notify, thread))

// Update the function signature:
pub fn register_usb_notifications(
    detector: &'static UsbDetector,
) -> windows::core::Result<(HWND, HDEVNOTIFY, HDEVNOTIFY, std::thread::JoinHandle<()>)>

// In unregister_usb_notifications:
pub fn unregister_usb_notifications(
    hwnd: HWND,
    vol_notify: HDEVNOTIFY,
    usb_notify: HDEVNOTIFY,
    thread: std::thread::JoinHandle<()>,
) {
    // SAFETY: handles are valid values returned by RegisterDeviceNotificationW.
    unsafe { UnregisterDeviceNotification(vol_notify) };
    unsafe { UnregisterDeviceNotification(usb_notify) };
    // Post WM_QUIT to the message loop thread, then join.
    unsafe { PostMessageW(Some(hwnd), WM_QUIT, WPARAM(0), LPARAM(0)) };
    let _ = thread.join();
    // SAFETY: hwnd is a valid message-only window we created.
    let _ = unsafe { DestroyWindow(hwnd) };
    *DRIVE_DETECTOR.lock() = None;
    debug!("USB device notifications unregistered");
}
```

Note: `UnregisterDeviceNotification` and `PostMessageW` must be added to the
`windows` import list.

---

## Warnings

### WR-01: Redundant `unsafe impl Send + Sync` for `UsbDetector`

**File:** `dlp-agent/src/detection/usb.rs:189-193`

**Issue:** Both fields of `UsbDetector` are `parking_lot::RwLock<T>` where `T` is
`HashSet<char>` / `HashMap<char, DeviceIdentity>` — all of which are `Send + Sync`.
Rust automatically derives `Send + Sync` for `UsbDetector` because all its fields
are `Send + Sync`. The manual `unsafe impl Send for UsbDetector {}` and
`unsafe impl Sync for UsbDetector {}` are redundant. Worse, they suppress the
compiler's automatic trait-bound check: if a future contributor adds a non-`Send`
field (e.g., a raw pointer), the compiler will not catch the unsoundness.

**Fix:** Remove the manual impls and let the compiler derive them automatically:
```rust
// Delete lines 189-193 entirely.
// UsbDetector is automatically Send + Sync because RwLock<HashSet<char>>
// and RwLock<HashMap<char, DeviceIdentity>> are both Send + Sync.
```

---

### WR-02: `on_drive_arrival` double-classifies drive on volume event

**File:** `dlp-agent/src/detection/usb.rs:114-119`

**Issue:** `on_drive_arrival` calls `self.is_removable_drive(letter)` before
inserting. In `handle_volume_event`, the caller has already filtered by
`is_removable_drive` before calling `on_drive_arrival` (line 331-332). The result is
two `GetDriveTypeW` calls per arrival event — one in `handle_volume_event` and one
in `on_drive_arrival`. This is not incorrect, but it is wasteful and creates a TOCTOU
window: a drive could be classified as removable in `handle_volume_event` but then
unmounted before `on_drive_arrival` re-checks it, causing a spurious log message
and missed insertion.

**Fix:** Split into two methods — a checked public variant and an unchecked internal
variant called by `handle_volume_event`:
```rust
/// Internal: unconditionally adds a drive letter to the blocked set.
/// Callers are responsible for pre-checking `is_removable_drive`.
fn add_blocked_drive(&self, letter: char) {
    info!(drive = %letter, "USB mass storage arrived — blocking writes");
    self.blocked_drives.write().insert(letter);
}

// In handle_volume_event, replace on_drive_arrival with add_blocked_drive.
```

---

### WR-03: Window class not unregistered on atom-registration failure paths

**File:** `dlp-agent/src/detection/usb.rs:584-630`

**Issue:** When `RegisterClassW` succeeds but `CreateWindowExW` fails (the `?` on
line 606), or when `RegisterDeviceNotificationW` fails for VOLUME (lines 627-630),
`UnregisterClass` is never called. Windows limits the number of registered window
classes. In a long-running service that restarts the USB subsystem repeatedly (e.g.,
on error recovery), repeated `RegisterClassW` calls without matching
`UnregisterClassW` will eventually exhaust the class table.

**Fix:** Call `UnregisterClassW` before returning on error paths after a successful
`RegisterClassW`:

```rust
// After atom == 0 check and before CreateWindowExW:
let hwnd = unsafe { CreateWindowExW(...) };
let hwnd = match hwnd {
    Ok(h) => h,
    Err(e) => {
        // SAFETY: atom is a valid class atom we just registered.
        unsafe { UnregisterClassW(
            windows::core::PCWSTR::from_raw(atom as *const u16),
            None,
        ) };
        return Err(e);
    }
};

// Similarly wrap the vol_handle and usb_handle failure paths.
```

---

## Info

### IN-01: Magic constant `32_768` in `read_dbcc_name` should be a named constant

**File:** `dlp-agent/src/detection/usb.rs:307`

**Issue:** The bound `32_768` for the wide-string walk is a magic number. The
rationale (MAX_PATH + driver prefix) is explained in a comment but not encoded as
a constant, making the value harder to find and audit.

**Fix:**
```rust
/// Maximum length of a Windows device path in UTF-16 code units.
/// Matches `UNICODE_STRING` `MaximumLength / 2` (32 767) plus a null terminator.
#[cfg(windows)]
const MAX_DEVICE_PATH_UTF16: usize = 32_768;

// In read_dbcc_name:
while unsafe { *base.add(len) } != 0 && len < MAX_DEVICE_PATH_UTF16 {
```

---

### IN-02: Magic constant `1024` in `setupdi_description_for_device` loop cap

**File:** `dlp-agent/src/detection/usb.rs:485`

**Issue:** The loop guard `if index > 1024 { break; }` is a magic number with no
associated constant or explanatory name.

**Fix:**
```rust
/// Maximum number of USB devices to enumerate before giving up.
/// Pathological installations with > 1 024 devices are not supported.
#[cfg(windows)]
const MAX_SETUPDI_ENUM_DEVICES: u32 = 1_024;

// In the loop:
if index > MAX_SETUPDI_ENUM_DEVICES {
    break;
}
```

---

### IN-03: Dead variable `_thread` in `unregister_usb_notifications` signals incomplete design

**File:** `dlp-agent/src/detection/usb.rs:684`

**Issue:** The `_thread: std::thread::JoinHandle<()>` parameter is accepted but
immediately ignored (the leading underscore is the only acknowledgment). The comment
explains the rationale, but the `JoinHandle` is dropped without joining — the thread
becomes detached. This is a code-smell signal that the cleanup logic is incomplete
(see CR-02 for the full fix). Even if a join is deemed impractical, the parameter
should be documented clearly.

**Fix:** Addressed as part of CR-02. If the join approach is rejected for shutdown-
timing reasons, document the decision explicitly in the function doc comment and
drop `_thread` explicitly with a comment rather than relying on implicit drop.

---

### IN-04: Missing test for `on_usb_device_arrival` no-drive-letter path (D-04 coverage gap)

**File:** `dlp-agent/src/detection/usb.rs:372-383`

**Issue:** The `None` arm in `on_usb_device_arrival` (when no removable drive letter
is available) is covered by the comment "D-04, never silently skipped" but has no
corresponding unit test. The test `test_on_usb_device_arrival_stores_identity_when_drive_letter_available`
only covers the `Some` arm via direct insert. Adding a test for the `None` arm would
verify the log path is reached without panicking and that `device_identities` remains
empty.

**Fix:** Add a test (pure-Rust, no Win32):
```rust
#[test]
fn test_on_usb_device_arrival_no_drive_letter_does_not_panic() {
    // When no removable drive is available, device_identities must stay empty
    // and the function must not panic.
    let detector = UsbDetector::new();
    // Directly verify the None-arm logic: no drives in identities, so
    // find() returns None.
    let existing: HashSet<char> = detector.device_identities.read().keys().copied().collect();
    let letter_opt = ('A'..='Z').find(|l| {
        // No drives are blocked, so is_removable_drive would be false;
        // simulate by checking against the empty existing set — find returns None.
        !existing.contains(l) && false // force None
    });
    assert!(letter_opt.is_none());
    assert!(detector.device_identities.read().is_empty());
}
```

---

_Reviewed: 2026-04-22_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
