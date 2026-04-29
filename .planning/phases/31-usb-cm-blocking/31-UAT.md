---
status: resolved
phase: 31-usb-cm-blocking
source:
  - 31-01-SUMMARY.md
  - 31-02-SUMMARY.md
started: "2026-04-29T15:15:00Z"
updated: "2026-04-29T16:20:00Z"
---

## Current Test

[all tests complete — 13/13 passed]

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
result: pass
notes: |
  Gap closed by Plan 02 (31-02). Added GUID_DEVINTERFACE_DISK registration + PnP tree walk.
  The DISK notification fires reliably for all USB mass storage devices, even those that
  never fire GUID_DEVINTERFACE_USB_DEVICE. The handler walks the PnP tree via CM_Get_Parent
  to find the USB ancestor, parses VID/PID/serial, and calls apply_tier_enforcement.

### 7. ReadOnly USB Device — Write Denied
expected: |
  With a USB device registered as "ReadOnly" in the device registry, plugging it in
  allows reading files from the device but writing/creating/deleting files is denied.
  The volume DACL is modified on arrival and restored on removal.
result: pass
notes: |
  The DISK arrival path (31-02) calls apply_tier_enforcement which handles ReadOnly tier
  via set_volume_readonly. Removal cleanup restores ACL via restore_volume_acl.

### 8. FullAccess USB Device — Normal Operation
expected: |
  With a USB device registered as "FullAccess" in the device registry, plugging it in
  allows normal read and write operations. No DACL modification occurs.
result: pass

### 9. Unregistered USB Device — Defence-in-Depth Deny
expected: |
  With an unregistered/unknown USB device, file write operations are denied at the
  I/O level by UsbEnforcer. The audit log shows the deny decision with the drive letter
  identified (even if VID/PID/serial are unknown).
result: pass

### 10. Volume DACL Restoration on Removal
expected: |
  After removing a ReadOnly-tier USB device, the original volume DACL is restored.
  A subsequent re-insertion of the same device re-applies the ReadOnly DACL correctly.
result: pass

### 11. Code Review Fixes — CM Flags
expected: |
  CM_Disable_DevNode is called with CM_DISABLE_ABSOLUTE flag (0x00000001) ensuring
  the device stays disabled across reboots. CM_Enable_DevNode uses CM_ENABLE_ABSOLUTE.
result: pass

### 12. Code Review Fixes — Security Descriptor Completeness
expected: |
  GetFileSecurityW queries DACL + OWNER + GROUP security information. The cached
  security descriptor includes all three components and restores them correctly.
result: pass

### 13. Code Review Fixes — Cleanup on Shutdown
expected: |
  On agent shutdown, unregister_usb_notifications properly unregisters device
  notification handles, posts WM_CLOSE to break the message loop, joins the thread,
  and destroys the hidden window. No handle leaks.
result: pass

## Summary

total: 13
passed: 13
issues: 0
pending: 0
skipped: 0

## Gaps

- truth: Blocked USB device should be disabled on arrival via CM_Disable_DevNode
  status: resolved
  resolution: "Plan 31-02 added GUID_DEVINTERFACE_DISK registration + PnP tree walk. The DISK notification fires reliably for all USB mass storage. The handler walks the PnP tree via CM_Get_Parent to find the USB ancestor, parses VID/PID/serial, and calls apply_tier_enforcement."
  resolved_by: 31-02
  test: 6
