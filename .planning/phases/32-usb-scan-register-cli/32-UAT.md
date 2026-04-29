---
status: complete
phase: 32-usb-scan-register-cli
source:
  - 32-01-SUMMARY.md
  - 32-02-SUMMARY.md
  - 32-03-SUMMARY.md
started: 2026-04-29T00:00:00Z
updated: 2026-04-29T00:00:00Z
---

## Current Test

[testing complete]

## Tests

### 1. Cold Start Smoke Test
expected: Kill any running dlp-admin-cli or dlp-server. Start the dlp-admin-cli TUI from scratch. The application boots without errors and shows the main menu.
result: pass

### 2. Devices Menu - Three Items
expected: Navigate to the Devices menu. It shows 3 options: "Device Registry", "Managed Origins", and "Scan & Register USB".
result: pass

### 3. Open USB Scan Screen
expected: Select "Scan & Register USB" from the Devices menu. The USB Scan screen opens with an empty table and a status hint like "Press 'r' to scan for connected USB devices.".
result: pass

### 4. Trigger USB Scan
expected: Press 'r' in the USB Scan screen. If the DLP server is running and USB devices are connected, a 5-column table (VID, PID, Serial, Description, Registered) populates with device rows. The "Registered" column shows "-" for unregistered devices. If no USB devices are connected, the table remains empty with an appropriate status message.
result: pass

### 5. Navigate USB Device List
expected: After the scan populates the table, press Up/Down arrows. The highlight bar moves between rows, wrapping at the top and bottom of the list.
result: pass

### 6. Register USB Device Flow
expected: With a USB device row highlighted, press Enter. The Device Tier Picker opens with the device's VID, PID, and Serial Number pre-populated. The hint shows "Select trust tier for this device.".
result: pass

### 7. Post-Registration Return
expected: After selecting a trust tier and pressing Enter to register, the app returns to the USB Scan screen. A success status message appears. The newly registered device's "Registered" column now shows the selected tier name (e.g., "Trusted" or "Blocked").
result: pass

## Summary

total: 7
passed: 7
issues: 0
pending: 0
skipped: 0
blocked: 0

## Gaps

[none]
