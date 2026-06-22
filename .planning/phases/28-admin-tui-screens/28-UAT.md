---
status: complete
phase: 28-admin-tui-screens
source:
  - 28-01-SUMMARY.md
  - 28-02-SUMMARY.md
  - 28-03-SUMMARY.md
  - 28-04-SUMMARY.md
started: "2026-06-03T00:00:00Z"
updated: "2026-06-03T00:00:00Z"
---

## Current Test

[testing complete]

## Tests

### 1. Main Menu shows Devices and Origins option
expected: Main menu displays 6 items with "Devices & Origins" at position 3
result: pass

### 2. DevicesMenu navigation
expected: From main menu, select "Devices & Origins". A submenu appears with "Registered Devices" and "Managed Origins" options. Up/Down arrows move selection. Esc returns to main menu.
result: pass

### 3. Device List view
expected: Select "Registered Devices". Screen shows list of registered USB devices in format [TIER_TAG] VID:{vid} PID:{pid} SER:{serial} "{description}". If none registered, shows empty-state message. Bottom shows hints r: Register, d: Delete, Esc: Back.
result: pass

### 4. Register device flow
expected: Press 'r' on Device List. Sequential input chain appears: Step 1 enter VID, Step 2 enter PID, Step 3 enter serial (optional - can skip with empty), Step 4 enter description (optional), then tier picker (blocked/read_only/full_access). After selecting tier, device registers and list reloads showing new device.
result: pass

### 5. Delete device with confirmation
expected: On Device List, navigate to a device and press 'd'. A confirm dialog appears asking to delete the device. Press 'y' to confirm - device is removed and list reloads. Press 'n' or Esc to cancel - returns to list without deleting.
result: pass

### 6. Managed Origins List view
expected: From DevicesMenu, select "Managed Origins". Screen shows list of origin URL patterns. If none, shows empty-state message. Bottom shows hints a: Add, d: Delete, Esc: Back.
result: pass

### 7. Add managed origin
expected: Press 'a' on Managed Origins List. Text input prompt appears for origin URL. Enter a valid URL (e.g., https://example.com) and submit. Origin appears in the list. Invalid/duplicate origins show error and stay on input screen.
result: pass

### 8. Delete managed origin with human-readable confirm
expected: On Managed Origins List, navigate to an origin and press 'd'. Confirm dialog shows "Remove origin 'https://...'?" with the actual URL pattern, NOT an opaque UUID. Press 'y' to confirm - origin is removed and list reloads.
result: pass

### 9. Conditions Builder app-identity attributes
expected: Navigate to Policies > Add/Edit Policy > Add Condition. Attribute picker shows 7 options including "Source Application" and "Destination Application". Selecting either advances to app-field sub-picker.
result: pass

### 10. AppField sub-picker
expected: After selecting SourceApplication or DestinationApplication, a sub-picker appears with three options: Publisher, Image Path, Trust Tier. Selecting one advances to operator selection.
result: pass

### 11. TrustTier picker values
expected: When Trust Tier is selected as the app-field, operator selection shows eq/ne. After selecting operator, a picker appears with three values: trusted, untrusted, unknown. Selecting one and confirming builds the condition.
result: pass

## Summary

total: 11
passed: 11
issues: 0
pending: 0
skipped: 0

## Gaps

[none]
