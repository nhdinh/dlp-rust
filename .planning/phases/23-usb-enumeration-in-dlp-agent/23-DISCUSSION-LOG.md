# Phase 23: USB Enumeration in dlp-agent - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-22
**Phase:** 23-usb-enumeration-in-dlp-agent
**Areas discussed:** Identity capture strategy, In-memory retention

---

## Identity Capture Strategy

| Option | Description | Selected |
|--------|-------------|----------|
| Dual GUID registration | Register GUID_DEVINTERFACE_VOLUME (existing) + GUID_DEVINTERFACE_USB_DEVICE (new). Parse VID/PID/serial from dbcc_name; call SetupDi only for description. | ✓ |
| SetupDi full enumeration | On any WM_DEVICECHANGE, enumerate all present USB devices via SetupDiGetClassDevsW, diff against previous snapshot to find new arrival. | |

**User's choice:** Dual GUID registration
**Notes:** Clean separation — volume events update drive blocking, USB device events capture identity. SetupDi used only for description (SPDRP_FRIENDLYNAME), not for the identity fields themselves.

---

## Parse Failures

| Option | Description | Selected |
|--------|-------------|----------|
| Log with best-effort fields | Parse what we can; empty string for unparsed fields. Always emit a log entry. | ✓ |
| Skip and warn | WARN log and skip DeviceIdentity if parsing fails. | |

**User's choice:** Log with best-effort fields
**Notes:** A partial identity is more useful than silence — Phase 26 enforcement can still attempt a trust-tier lookup with partial VID/PID.

---

## SetupDi Threading

| Option | Description | Selected |
|--------|-------------|----------|
| Inline in message loop | Call SetupDiGetDeviceRegistryPropertyW directly inside WM_DEVICECHANGE handler. Fast (<1ms). | ✓ |
| Spawn short-lived thread | One-shot thread per SetupDi call so message loop is never delayed. | |

**User's choice:** Inline in message loop
**Notes:** SetupDi metadata queries are fast and the message loop thread is dedicated to USB events, so blocking it briefly on arrival is acceptable.

---

## In-Memory Retention

| Option | Description | Selected |
|--------|-------------|----------|
| In-memory map now, DB in Phase 24 | RwLock<HashMap<char, DeviceIdentity>> in UsbDetector keyed by drive letter. Phase 24 adds persistent device_registry DB. Phase 26 reads the in-memory map. | ✓ |
| Log only | Phase 23 just logs. Phase 26 re-queries SetupDi at enforcement time. | |
| Send to server | POST DeviceIdentity to server on arrival. Requires server changes out of scope for Phase 23. | |

**User's choice:** In-memory map now, DB in Phase 24
**Notes:** User initially said "database" — clarified to mean in-memory map now (Phase 23) with DB persistence coming in Phase 24. The in-memory map is the live identity source; the DB (Phase 24) holds admin-managed trust tiers.

---

## Claude's Discretion

- `device_identity_for_drive()` accessor method on `UsbDetector`
- Whether to register a second notification handle or reuse the same one
- Specific `windows-rs` feature flags for SetupDi

## Deferred Ideas

- Server-side DeviceIdentity persistence (Phase 24)
- Trust tier enforcement using the in-memory map (Phase 26)
- USB removal toast notification (Phase 27)
- IPC notification to dlp-user-ui on USB arrival (Phase 27)
