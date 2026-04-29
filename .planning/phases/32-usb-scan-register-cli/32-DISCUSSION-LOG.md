# Phase 32: USB Scan & Register CLI — Discussion Log

**Date:** 2026-04-29
**Areas Discussed:** UX entry point, Code location, Registered device handling, Description & multi-select

---

## Area 1: UX Entry Point

**Q1: How should the admin reach the USB scan screen?**
- Options: New 's' key on DeviceList / New DevicesMenu item / Replace manual 'r' with scan-first
- **Selected:** New DevicesMenu item ("Scan & Register USB" as 3rd entry)

**Q2: What does the Scan screen show and how does selecting a device flow into registration?**
- Options: List then Enter to register / Inline tier picker in same screen
- **Selected:** List then Enter to register — reuses existing DeviceTierPicker screen

**Q3: When should the USB scan happen?**
- Options: Auto-scan on screen open / Manual refresh with 'r'
- **Selected:** Manual refresh with 'r' — allows plugging in USB mid-session and rescanning

**Q4: After a device is registered, what happens to the scan screen?**
- Options: Return to scan list / Navigate to DeviceList
- **Selected:** Return to scan list with success status bar

---

## Area 2: Code Location

**Q1: Where should the USB enumeration logic live?**
- Options: New pub fn in dlp-agent / Extract to dlp-common / Fresh impl in dlp-admin-cli
- **Selected:** Extract to dlp-common (new `dlp-common/src/usb.rs`)

**Q2: What USB device class should enumeration cover?**
- Options: USB mass storage only / All USB devices
- **Selected:** USB mass storage only

**Q3: Is it acceptable for dlp-common to take on Windows-specific deps?**
- Options: Yes, add cfg(windows) guarded dep / No, keep dlp-common platform-neutral
- **Selected:** Yes, add `[target.'cfg(windows)'.dependencies]` for the windows crate

---

## Area 3: Registered Device Handling

**Q1: How should already-registered devices be displayed in the scan list?**
- Options: Show with tier annotation / Show only unregistered
- **Selected:** Show with tier annotation (all devices shown, registered ones get `[read_only]` etc.)

**Q2: Where does the "already registered" data come from?**
- Options: Fetch from server on scan / Cross-reference with DeviceList cache
- **Selected:** Fetch from server on scan (concurrent GET /admin/device-registry + local USB scan)

---

## Area 4: Description & Multi-select

**Q1: Should the admin be able to edit the SetupDi-captured description?**
- Options: Use as-is / Pre-fill but allow editing
- **Selected:** Use as-is — no editing step; admin can update via Device Registry if needed

**Q2: Single-select or multi-select batch?**
- Options: Single-select loop naturally / Multi-select batch
- **Selected:** Single-select, natural loop (return to scan list after each registration)

---

## Claude's Discretion Items

- `UsbScanEntry` struct shape — `{ identity: DeviceIdentity, registered_tier: Option<String> }` seems natural but researcher/planner can refine
- `TierPickerCaller` enum for routing back to UsbScan vs DeviceList — implementation detail for planner
- Exact column widths and truncation behavior for the scan list table
