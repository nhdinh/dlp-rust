# Debug Session: USB Device Notification Not Firing (Phase 31 Test 6)

## Symptom

Blocked USB device should be disabled on arrival via CM_Disable_DevNode, but:
- Device remains visible in Windows Explorer, writable
- No USB arrival logs visible in agent log file
- dlp-server offline (registry cache empty)

## Investigation

### Step 1: Code Path Analysis

Trace through `register_usb_notifications` → `usb_wndproc` → arrival handling:

1. `register_usb_notifications` registers for TWO notifications:
   - `GUID_DEVINTERFACE_VOLUME` (drive letter tracking)
   - `GUID_DEVINTERFACE_USB_DEVICE` (VID/PID/serial capture + tier enforcement)

2. On USB plug-in, `usb_wndproc` receives `WM_DEVICECHANGE`:
   - If `classguid == GUID_DEVINTERFACE_VOLUME`: calls `handle_volume_event`
   - If `classguid == GUID_DEVINTERFACE_USB_DEVICE`: calls `on_usb_device_arrival`

3. `handle_volume_event` (VOLUME path):
   - Re-scans drive letters, updates `blocked_drives` set
   - Does NOT call `apply_tier_enforcement` unless `pending_identity` exists
   - Logs via `on_drive_arrival` at INFO level

4. `on_usb_device_arrival` (USB_DEVICE path):
   - Parses VID/PID/serial from `dbcc_name`
   - Captures device identity
   - Calls `apply_tier_enforcement` → `DeviceController::disable_usb_device`
   - This is the ONLY path that triggers active PnP enforcement

### Step 2: Root Cause Identification

The `GUID_DEVINTERFACE_USB_DEVICE` notification is NOT guaranteed to fire for all USB mass storage devices. Depending on:
- Driver stack (usbstor.sys vs. vendor-specific)
- Composite device configuration
- Hub topology
- Windows version

...the device may only expose:
- `GUID_DEVINTERFACE_DISK` (disk interface)
- `GUID_DEVINTERFACE_VOLUME` (volume interface)

The USB device node exists in the PnP tree (visible in Device Manager) but does NOT register for or fire the `GUID_DEVINTERFACE_USB_DEVICE` device interface class notification that `RegisterDeviceNotificationW` subscribes to.

### Step 3: Evidence from Phase 32

Commit `5d30429` (Phase 32) fixed the SAME issue:
> "fix(32): USB enumeration now uses GUID_DEVINTERFACE_DISK + PnP tree walk"

Phase 32's `dlp-common/src/usb.rs` now uses `GUID_DEVINTERFACE_DISK` for reliable enumeration and walks the PnP tree via `CM_Get_Parent` to find USB ancestors. This confirms the `GUID_DEVINTERFACE_USB_DEVICE`-only approach is insufficient.

### Step 4: Why Server Offline Is Not the Root Cause

Even with `REGISTRY_CACHE` unset (server offline), `apply_tier_enforcement` defaults to `UsbTrustTier::Blocked` and calls `disable_usb_device`. The empty cache would cause the device to be disabled, not left accessible. The server being offline is a secondary observation, not the cause of the failure.

## Root Cause

**Event-driven USB arrival detection uses `GUID_DEVINTERFACE_USB_DEVICE` exclusively, which is unreliable for USB mass storage devices. The correct approach is `GUID_DEVINTERFACE_DISK` + PnP tree walk to find USB ancestry, matching Phase 32's fixed enumeration logic.**

## Files Involved

- `dlp-agent/src/detection/usb.rs` — notification registration and `usb_wndproc`
- `dlp-common/src/usb.rs` — contains the correct `GUID_DEVINTERFACE_DISK` approach (already fixed in Phase 32)

## Fix Direction

1. Add `GUID_DEVINTERFACE_DISK` registration alongside existing VOLUME registration
2. In `usb_wndproc`, handle `GUID_DEVINTERFACE_DISK` arrivals:
   - Use `CM_Get_Parent` to walk PnP tree upward
   - Find USB ancestor (instance ID starting with `USB\`)
   - Parse VID/PID/serial from ancestor's instance ID
   - Call `apply_tier_enforcement`
3. Keep `GUID_DEVINTERFACE_USB_DEVICE` as fallback for devices that DO fire it
4. On removal, handle both GUIDs and reconcile cleanup

This is essentially backporting the Phase 32 enumeration approach into the event-driven notification system.
