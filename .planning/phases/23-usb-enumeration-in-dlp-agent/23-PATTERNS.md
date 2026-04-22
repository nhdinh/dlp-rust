# Phase 23: USB Enumeration in dlp-agent - Pattern Map

**Mapped:** 2026-04-22
**Files analyzed:** 2 (1 modified, 1 read-only reference)
**Analogs found:** 2 / 2

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `dlp-agent/src/detection/usb.rs` | detection/service | event-driven | `dlp-agent/src/detection/usb.rs` (self — extension) | exact (self-extension) |
| `dlp-common/src/endpoint.rs` | model | N/A | `dlp-common/src/endpoint.rs` (read-only reference) | exact (type consumer) |

---

## Pattern Assignments

### `dlp-agent/src/detection/usb.rs` (detection service, event-driven)

This file is being extended, not created. All new code must be consistent with what already exists in the file. The patterns below are extracted directly from the file and its closest peer (`network_share.rs`).

---

#### Imports pattern — existing block (lines 28–43)

```rust
use std::collections::HashSet;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use dlp_common::Classification;
use parking_lot::RwLock;
use tracing::{debug, info};

#[cfg(windows)]
use windows::Win32::Foundation::HWND;
#[cfg(windows)]
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW, PostQuitMessage,
    RegisterClassW, TranslateMessage, DEVICE_NOTIFY_WINDOW_HANDLE, MSG, WINDOW_STYLE, WM_DESTROY,
    WNDCLASSW, WS_EX_NOACTIVATE,
};
```

**Phase 23 additions required to this import block:**

- `use std::collections::HashMap;` — for the new `device_identities` field.
- `use dlp_common::endpoint::DeviceIdentity;` — the type being stored. The re-export path must be confirmed against `dlp-common/src/lib.rs`.
- New `windows` crate imports for `WM_DEVICECHANGE`, `DBT_DEVICEARRIVAL`, `DBT_DEVICEREMOVECOMPLETE`, `DEV_BROADCAST_HDR`, and the SetupDi family. These require new feature flags in `dlp-agent/Cargo.toml` (see Cargo pattern below).

---

#### Struct extension pattern — existing `UsbDetector` (lines 47–55)

```rust
/// Drive letters currently identified as USB mass storage (e.g., `E`, `F`).
/// Shared between the device-notification callback and the interception layer.
#[derive(Debug, Default)]
pub struct UsbDetector {
    /// Set of uppercase drive letters (e.g., `{'E', 'F'}`) for blocked USB volumes.
    ///
    /// Marked `pub` so that integration tests in `dlp-agent/tests/integration.rs`
    /// can seed drives (bypasses `GetDriveTypeW` which is unavailable in CI).
    /// Production code should use `on_drive_arrival` / `on_drive_removal` instead.
    pub blocked_drives: RwLock<HashSet<char>>,
}
```

**Phase 23 extension — add the new field after `blocked_drives`:**

```rust
    /// In-memory map from drive letter to captured USB device identity.
    ///
    /// Populated on `DBT_DEVICEARRIVAL` for `GUID_DEVINTERFACE_USB_DEVICE`.
    /// Keyed by uppercase drive letter to mirror `blocked_drives`. Phase 26
    /// reads this map at I/O enforcement time without re-querying SetupDi.
    pub device_identities: RwLock<HashMap<char, DeviceIdentity>>,
```

The `#[derive(Debug, Default)]` on the struct continues to work because both `RwLock<HashSet<char>>` and `RwLock<HashMap<char, DeviceIdentity>>` implement `Default` (empty collection). No manual `Default` impl is needed.

---

#### `new()` constructor pattern — existing (lines 57–61)

```rust
impl UsbDetector {
    /// Constructs a new detector with an empty blocked-drive set.
    pub fn new() -> Self {
        Self::default()
    }
```

The `new()` delegating to `Self::default()` means the new `device_identities` field is automatically initialized via `Default` — no change to `new()` required.

---

#### Method pattern for drive-letter–keyed RwLock — existing `on_drive_removal` (lines 89–95)

This is the closest pattern for the new `on_device_identity_removal` method (D-07) that removes from `device_identities` on `DBT_DEVICEREMOVECOMPLETE`:

```rust
    pub fn on_drive_removal(&self, drive_letter: char) {
        let letter = drive_letter.to_ascii_uppercase();
        if self.blocked_drives.write().remove(&letter) {
            info!(drive = %letter, "USB mass storage removed");
        }
    }
```

Pattern: normalize to uppercase, acquire exclusive write lock, mutate, log with structured `drive = %letter` field.

---

#### Structured logging pattern — existing in `on_drive_arrival` (line 84) and `scan_existing_drives` (line 71)

```rust
info!(drive = %letter, "USB mass storage arrived — blocking writes");
```

```rust
info!(drive = %letter, "existing USB removable drive detected");
```

```rust
debug!(
    blocked = ?*self.blocked_drives.read(),
    "initial USB drive scan complete"
);
```

Phase 23 identity-capture log should follow the same pattern with additional structured fields:

```rust
info!(
    drive = %letter,
    vid = %identity.vid,
    pid = %identity.pid,
    serial = %identity.serial,
    description = %identity.description,
    "USB device arrived — identity captured"
);
```

---

#### GUID constant pattern — existing `GUID_DEVINTERFACE_VOLUME` (lines 156–164)

```rust
/// GUID for storage volume device interface.
/// Matches the device interface registered by the Windows volume driver.
/// Windows SDK value: {0x53F5630D,0xB6BF,0x11D0,{0x94,0xF2,0x00,0xA0,0xC9,0x1E,0xFB,0x8B}}
#[cfg(windows)]
const GUID_DEVINTERFACE_VOLUME: windows::core::GUID = windows::core::GUID::from_values(
    u32::from_be_bytes([0x53, 0xF5, 0x63, 0x0D]),
    u16::from_be_bytes([0xB6, 0xBF]),
    u16::from_be_bytes([0x11, 0xD0]),
    [0x94, 0xF2, 0x00, 0xA0, 0xC9, 0x1E, 0xFB, 0x8B],
);
```

Phase 23 adds a second constant immediately below this one, using the same `from_values` constructor and `#[cfg(windows)]` guard:

```rust
/// GUID for USB device interface — fires on raw USB device plug/unplug.
/// dbcc_name carries the full device path with embedded VID/PID/serial.
/// Windows SDK value: {A5DCBF10-6530-11D2-901F-00C04FB951ED}
#[cfg(windows)]
const GUID_DEVINTERFACE_USB_DEVICE: windows::core::GUID = windows::core::GUID::from_values(
    0xA5DC_BF10,
    0x6530,
    0x11D2,
    [0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED],
);
```

Note: `from_values` takes `u32`, `u16`, `u16`, `[u8; 8]`. The first field for `GUID_DEVINTERFACE_USB_DEVICE` is `0xA5DCBF10` (straight hex literal, no byte-reversal needed when using the `from_values` direct form). Verify against GUID_DEVINTERFACE_VOLUME's byte-reversal approach to ensure consistency.

---

#### Global static pattern — existing `DRIVE_DETECTOR` (lines 168–170)

```rust
#[cfg(windows)]
static DRIVE_DETECTOR: parking_lot::Mutex<Option<&'static UsbDetector>> =
    parking_lot::Mutex::new(None);
```

No new global is added in Phase 23. The `wndproc` accesses `UsbDetector` via the same `DRIVE_DETECTOR` global.

---

#### `usb_wndproc` extension pattern — existing wndproc (lines 173–187)

Current (all non-`WM_DESTROY` falls through):

```rust
unsafe extern "system" fn usb_wndproc(
    hwnd: windows::Win32::Foundation::HWND,
    msg: u32,
    wparam: windows::Win32::Foundation::WPARAM,
    lparam: windows::Win32::Foundation::LPARAM,
) -> windows::Win32::Foundation::LRESULT {
    match msg {
        WM_DESTROY => {
            unsafe { PostQuitMessage(0) };
            windows::Win32::Foundation::LRESULT(0)
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}
```

Closest peer pattern for match-arm extension — `clipboard/listener.rs` lines 486–499:

```rust
extern "system" fn wndproc_callback(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> windows::Win32::Foundation::LRESULT {
    match msg {
        windows::Win32::UI::WindowsAndMessaging::WM_DESTROY => {
            unsafe { PostQuitMessage(0) };
            windows::Win32::Foundation::LRESULT(0)
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}
```

Phase 23 adds a `WM_DEVICECHANGE` arm before the `_` fallthrough arm. The arm skeleton:

```rust
        WM_DEVICECHANGE => {
            // wparam values: DBT_DEVICEARRIVAL = 0x8000, DBT_DEVICEREMOVECOMPLETE = 0x8004
            let event_type = wparam.0 as u32;
            if event_type == DBT_DEVICEARRIVAL || event_type == DBT_DEVICEREMOVECOMPLETE {
                // lparam is a pointer to DEV_BROADCAST_HDR — cast and read dbch_devicetype.
                // Only handle DBT_DEVTYP_DEVICEINTERFACE (0x00000005).
                // Then cast to DEV_BROADCAST_DEVICEINTERFACE_W and read dbcc_classguid.
                // Route on GUID: VOLUME → existing on_drive_* path; USB_DEVICE → new capture path.
                if let Some(detector) = *DRIVE_DETECTOR.lock() {
                    // ... dispatch
                }
            }
            windows::Win32::Foundation::LRESULT(0)
        }
```

**Safety rule:** The `lparam` pointer is only valid for the duration of the `WM_DEVICECHANGE` handler call. Do NOT store the raw pointer. Extract all needed data (drive letter, device path string, GUID) synchronously before returning `LRESULT(0)`. This matches the `WM_DESTROY` pattern of acting immediately in the arm.

---

#### `RegisterDeviceNotificationW` call pattern — existing in `register_usb_notifications` (lines 246–276)

```rust
    let db_size = std::mem::size_of::<
        windows::Win32::UI::WindowsAndMessaging::DEV_BROADCAST_DEVICEINTERFACE_W,
    >();
    let mut dev_interface_buf: Vec<u8> = vec![0u8; db_size];
    let dbc = dev_interface_buf.as_mut_ptr()
        as *mut windows::Win32::UI::WindowsAndMessaging::DEV_BROADCAST_DEVICEINTERFACE_W;

    // SAFETY: dbc points to db_size bytes that we own and are properly aligned.
    unsafe {
        (*dbc).dbcc_size = db_size as u32;
        (*dbc).dbcc_devicetype =
            windows::Win32::UI::WindowsAndMessaging::DBT_DEVTYP_DEVICEINTERFACE.0;
        (*dbc).dbcc_reserved = 0;
        (*dbc).dbcc_classguid = GUID_DEVINTERFACE_VOLUME;
    }

    let notification_handle = unsafe {
        windows::Win32::UI::WindowsAndMessaging::RegisterDeviceNotificationW(
            hwnd,
            dbc as *const _,
            DEVICE_NOTIFY_WINDOW_HANDLE,
        )
    };

    if let Err(e) = notification_handle {
        let _ = unsafe { DestroyWindow(hwnd) };
        return Err(e);
    }
```

Phase 23 adds a second registration block after this one (same `hwnd`, different `dbcc_classguid = GUID_DEVINTERFACE_USB_DEVICE`). Each `RegisterDeviceNotificationW` returns its own handle independently — two separate calls are required because the Win32 API does not support multi-GUID registration in a single call. The second handle can be tracked as a local variable alongside the first; since `unregister_usb_notifications` skips explicit cleanup (process-exit pattern, lines 305–314), storing the second handle in the return value is not required — but the call must succeed (error path mirrors existing: destroy window, return Err).

---

#### `unregister_usb_notifications` — no-op shutdown pattern (lines 305–314)

```rust
pub fn unregister_usb_notifications(hwnd: HWND, _thread: std::thread::JoinHandle<()>) {
    // The USB notification thread runs a blocking GetMessageW loop.
    // Cross-thread DestroyWindow and PostMessageW(WM_QUIT) are unreliable
    // for message-only windows.  Since this is only called during service
    // shutdown, we skip the join — the OS reclaims all resources (window,
    // device notification handle, thread) when the process exits.
    let _ = hwnd; // suppress unused warning
    *DRIVE_DETECTOR.lock() = None;
    debug!("USB device notifications cleanup skipped (process exit imminent)");
}
```

Phase 23 does not change this function signature. The second notification handle needs no explicit cleanup — process-exit reclaims it per the existing documented rationale.

---

#### Test pattern — existing `#[cfg(test)]` module (lines 328–389)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_drive_letter() {
        assert_eq!(extract_drive_letter(r"E:\Data\file.txt"), Some('E'));
        // ...
    }

    #[test]
    fn test_usb_detector_default() {
        let detector = UsbDetector::new();
        assert!(detector.blocked_drive_letters().is_empty());
    }

    #[test]
    fn test_on_drive_arrival_removal() {
        let detector = UsbDetector::new();
        detector.blocked_drives.write().insert('E');
        assert!(detector.is_path_on_blocked_drive(r"E:\secret.docx"));
        // ...
        detector.on_drive_removal('E');
        assert!(!detector.is_path_on_blocked_drive(r"E:\secret.docx"));
    }
}
```

Pattern: Arrange via `UsbDetector::new()`, Act by calling methods or directly writing to the `RwLock`, Assert on observable state. Phase 23 new tests follow the same structure — directly populate `device_identities` via `detector.device_identities.write().insert(...)` to avoid Win32 dependencies in unit tests.

---

### `dlp-common/src/endpoint.rs` — `DeviceIdentity` reference (read-only)

This file is not modified in Phase 23. It is referenced here to document the exact field names and types that `usb.rs` must use.

**`DeviceIdentity` struct (lines 112–123):**

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DeviceIdentity {
    /// USB Vendor ID as a hex string, e.g. `"0951"`.
    pub vid: String,
    /// USB Product ID as a hex string, e.g. `"1666"`.
    pub pid: String,
    /// Device serial number, or `"(none)"` for devices without one.
    pub serial: String,
    /// Human-readable device description from the USB descriptor.
    pub description: String,
}
```

All four fields are `String`. Empty-string default per `#[serde(default)]`. The `"(none)"` sentinel for `serial` is specified in the doc comment and enforced by Phase 23 SC-2.

**Import path for use in `usb.rs`:** Confirm via `dlp-common/src/lib.rs` whether `DeviceIdentity` is re-exported at the crate root (e.g., `dlp_common::DeviceIdentity`) or requires the full path (`dlp_common::endpoint::DeviceIdentity`).

---

## Shared Patterns

### `parking_lot::RwLock<T>` field pattern
**Source:** `dlp-agent/src/detection/usb.rs` lines 33, 54 and `dlp-agent/src/detection/network_share.rs` lines 42–43, 73–74
**Apply to:** New `device_identities` field in `UsbDetector`

```rust
use parking_lot::RwLock;

// Read: short-lived guard, deref to access data
let guard = self.device_identities.read();
if let Some(identity) = guard.get(&letter) { ... }

// Write: exclusive lock, mutate, guard dropped at end of scope
self.device_identities.write().insert(letter, identity);
self.device_identities.write().remove(&letter);
```

### `#[cfg(windows)]` guard on Win32 code
**Source:** `dlp-agent/src/detection/usb.rs` lines 36–43, 158, 168, 173, 206, 304
**Apply to:** All new Win32 API calls (SetupDi, WM_DEVICECHANGE dispatch, new GUID const)

Every Win32 import, constant, static, and function that uses `windows` crate types must be wrapped in `#[cfg(windows)]`. Pure-Rust code (struct fields using `parking_lot::RwLock<HashMap<char, DeviceIdentity>>`, helper functions operating on `String`, test code) does NOT need the cfg guard.

### Structured tracing fields
**Source:** `dlp-agent/src/detection/usb.rs` lines 71, 74–77, 84, 92–94 and `dlp-agent/src/detection/network_share.rs` lines 114, 126, 133
**Apply to:** All new `info!` and `debug!` calls in Phase 23

```rust
// Display format (%): for drive letter, VID, PID, serial, description
info!(drive = %letter, vid = %identity.vid, pid = %identity.pid, "USB device arrived — identity captured");

// Debug format (?): for collections or structs implementing Debug
debug!(blocked = ?*self.blocked_drives.read(), "...");
```

### Error path: fall back, never skip
**Source:** Context D-04 and `register_usb_notifications` error pattern (lines 272–276)

```rust
if let Err(e) = notification_handle {
    let _ = unsafe { DestroyWindow(hwnd) };
    return Err(e);
}
```

For parsing failures (D-04): log at INFO with best-effort fields; populate unparsed fields with empty string `""`. Never return early without logging. Never `unwrap()` on parse results.

### Cargo.toml feature flag pattern
**Source:** `dlp-agent/Cargo.toml` lines 36–65

SetupDi APIs require the `Win32_Devices_DeviceAndDriverInstallation` feature flag. The WM_DEVICECHANGE constants (`DBT_DEVICEARRIVAL`, `DBT_DEVICEREMOVECOMPLETE`, `DEV_BROADCAST_HDR`) are already available from `Win32_UI_WindowsAndMessaging` (which is already listed). Add the new feature to the existing `windows` dependency array:

```toml
windows = { version = "0.58", features = [
    # ... existing features ...
    "Win32_Devices_DeviceAndDriverInstallation",  # SetupDiGetClassDevsW, SetupDiGetDeviceRegistryPropertyW
] }
```

---

## `service.rs` — Initialization Pattern (read-only reference)

**Source:** `dlp-agent/src/service.rs` lines 136–157

```rust
use std::sync::OnceLock;
static USB_DETECTOR: OnceLock<crate::detection::UsbDetector> = OnceLock::new();
let detector = USB_DETECTOR.get_or_init(crate::detection::UsbDetector::new);
detector.scan_existing_drives();
let usb_cleanup = match crate::detection::usb::register_usb_notifications(detector) {
    Ok((hwnd, thread)) => {
        info!(thread_id = ?thread.thread().id(), "USB notifications registered");
        Some((hwnd, thread))
    }
    Err(e) => {
        warn!(error = %e, "USB detection unavailable — continuing without USB monitoring");
        None
    }
};
```

Phase 23 must NOT change this call site. The `OnceLock<UsbDetector>` pattern holds a `&'static UsbDetector` that is passed to `register_usb_notifications`. Because `UsbDetector::new()` delegates to `Default`, the new `device_identities` field will be initialized automatically. No changes to `service.rs` are required.

---

## No Analog Found

All files have close analogs within the codebase. The one area with no prior art is the SetupDi API call chain itself (`SetupDiGetClassDevsW` → `SetupDiEnumDeviceInfo` → `SetupDiGetDeviceRegistryPropertyW`). For this specific Win32 sequence, use the research notes in CONTEXT.md (D-02, D-03) and ROADMAP.md Phase 23 success criteria as the reference, since no SetupDi usage exists elsewhere in the codebase.

| File/Function | Role | Data Flow | Reason |
|---------------|------|-----------|--------|
| SetupDi call chain inside `usb.rs` | Win32 API sequence | request-response (sync) | No SetupDi usage exists anywhere in the codebase — use Windows SDK docs + CONTEXT.md D-03 |

---

## Metadata

**Analog search scope:** `dlp-agent/src/`, `dlp-common/src/`
**Files scanned:** `usb.rs` (390 lines), `endpoint.rs` (273 lines), `network_share.rs` (200 lines sampled), `listener.rs` (target lines), `service.rs` (60 lines sampled), `Cargo.toml`
**Pattern extraction date:** 2026-04-22
