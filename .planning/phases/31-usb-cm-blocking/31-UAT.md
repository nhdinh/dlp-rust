---
status: diagnosed
phase: 31-usb-cm-blocking
source:
  - 31-01-SUMMARY.md
started: "2026-04-29T15:15:00Z"
updated: "2026-04-29T16:20:00Z"
---

## Current Test

[diagnosis complete — 1 root cause identified, ready for fix planning]

## Tests

### 1. Build Verification
expected: cargo build -p dlp-agent completes with zero warnings and zero errors
result: pass

### 2. Unit Test Suite
expected: cargo test -p dlp-agent --lib passes all 209 tests with zero failures
result: pass

### 3. Clippy Clean
expected: cargo clippy -p dlp-agent -- -D warnings reports zero issues
result: pass

### 4. Agent Service Startup
expected: |
  Starting the dlp-agent service (or run_console mode) completes without panics.
  Logs show normal initialization: registry cache loaded, device controller initialized,
  USB notifications registered. No ERROR-level logs during startup.
result: pass

### 5. UI Binary Missing Warning
expected: |
  When dlp-user-ui.exe is NOT present in the expected path, the agent logs a WARN-level
  message about the missing UI binary but continues running (does not exit).
result: pass

### 6. Blocked USB Device — Disabled on Arrival
expected: |
  With a USB device registered as "Blocked" in the device registry, plugging it in
  causes the device to be immediately disabled via CM_Disable_DevNode. The device
  does not appear in Windows Explorer. An audit event is emitted.
result: issue
reported: "Device still shown in Windows Explorer, writable. No USB arrival logs visible. dlp-server offline so registry cache is empty."
severity: major

### 7. ReadOnly USB Device — Write Denied
expected: |
  With a USB device registered as "ReadOnly" in the device registry, plugging it in
  allows reading files from the device but writing/creating/deleting files is denied.
  The volume DACL is modified on arrival and restored on removal.
result: skipped
reason: Skipped — depends on test 6 root cause resolution (USB arrival notification not firing or registry cache empty)

### 8. FullAccess USB Device — Normal Operation
expected: |
  With a USB device registered as "FullAccess" in the device registry, plugging it in
  allows normal read and write operations. No DACL modification occurs.
result: skipped
reason: Skipped — depends on test 6 root cause resolution

### 9. Unregistered USB Device — Defence-in-Depth Deny
expected: |
  With an unregistered/unknown USB device, file write operations are denied at the
  I/O level by UsbEnforcer. The audit log shows the deny decision with the drive letter
  identified (even if VID/PID/serial are unknown).
result: skipped
reason: Skipped — depends on test 6 root cause resolution

### 10. Volume DACL Restoration on Removal
expected: |
  After removing a ReadOnly-tier USB device, the original volume DACL is restored.
  A subsequent re-insertion of the same device re-applies the ReadOnly DACL correctly.
result: skipped
reason: Skipped — depends on test 6 root cause resolution

### 11. Code Review Fixes — CM Flags
expected: |
  CM_Disable_DevNode is called with CM_DISABLE_ABSOLUTE flag (0x00000001) ensuring
  the device stays disabled across reboots. CM_Enable_DevNode uses CM_ENABLE_ABSOLUTE.
result: skipped
reason: Deferred — requires agent running with working USB enforcement (blocked by test 6 root cause)

### 12. Code Review Fixes — Security Descriptor Completeness
expected: |
  GetFileSecurityW queries DACL + OWNER + GROUP security information. The cached
  security descriptor includes all three components and restores them correctly.
result: skipped
reason: Deferred — requires agent running with working USB enforcement (blocked by test 6 root cause)

### 13. Code Review Fixes — Cleanup on Shutdown
expected: |
  On agent shutdown, unregister_usb_notifications properly unregisters device
  notification handles, posts WM_CLOSE to break the message loop, joins the thread,
  and destroys the hidden window. No handle leaks.
result: skipped
reason: Deferred — requires agent running with working USB enforcement (blocked by test 6 root cause)

## Summary

total: 13
passed: 5
issues: 1
pending: 0
skipped: 7

## Gaps

- truth: Blocked USB device should be disabled on arrival via CM_Disable_DevNode
  status: failed
  reason: "User reported: Device still shown in Windows Explorer, writable. No USB arrival logs visible. dlp-server offline so registry cache is empty."
  severity: major
  test: 6
  root_cause: "GUID_DEVINTERFACE_USB_DEVICE notification is unreliable for USB mass storage devices. The code registers for GUID_DEVINTERFACE_USB_DEVICE to trigger identity capture and tier enforcement, but many USB storage devices only fire GUID_DEVINTERFACE_DISK / GUID_DEVINTERFACE_VOLUME and never fire the USB_DEVICE notification. Phase 32 fixed this same issue by switching to GUID_DEVINTERFACE_DISK + PnP tree walk."
  artifacts:
    - path: "dlp-agent/src/detection/usb.rs"
      issue: "register_usb_notifications only registers for GUID_DEVINTERFACE_VOLUME and GUID_DEVINTERFACE_USB_DEVICE; usb_wndproc only calls on_usb_device_arrival for GUID_DEVINTERFACE_USB_DEVICE"
    - path: "dlp-common/src/usb.rs"
      issue: "Phase 32 already contains the correct GUID_DEVINTERFACE_DISK + CM_Get_Parent approach but only for point-in-time enumeration, not event-driven notifications"
  missing:
    - "Add GUID_DEVINTERFACE_DISK registration alongside existing notifications"
    - "Implement disk arrival handler that walks PnP tree (CM_Get_Parent) to find USB ancestor"
    - "Parse VID/PID/serial from USB ancestor instance ID (same logic as Phase 32 enumerate_connected_usb_devices)"
    - "Call apply_tier_enforcement from the disk arrival path"
    - "Handle removal for both GUID_DEVINTERFACE_USB_DEVICE and GUID_DEVINTERFACE_DISK"
  debug_session: ".planning/debug/usb-device-notification-not-firing.md"
