# Phase 23: USB Enumeration in dlp-agent - Context

**Gathered:** 2026-04-22
**Status:** Ready for planning

<domain>
## Phase Boundary

Extend `dlp-agent`'s USB detection layer to capture `DeviceIdentity` (VID, PID, serial, description) on USB device arrival and log it at INFO level. No enforcement changes — existing file-write blocking behavior is untouched. The identity is also stored in-memory for Phase 26 enforcement use.

Key fix included: the existing `usb_wndproc` does NOT handle `WM_DEVICECHANGE` — it falls through to `DefWindowProcW` unhandled. Phase 23 wires up that handler.

</domain>

<decisions>
## Implementation Decisions

### Identity Capture Strategy

- **D-01:** Register for **both** `GUID_DEVINTERFACE_VOLUME` (existing, keeps drive-letter tracking) and `GUID_DEVINTERFACE_USB_DEVICE` (new, fires on USB device arrival with the device path in `dbcc_name`). The two GUIDs serve different purposes and must coexist.
- **D-02:** VID, PID, and serial are **parsed from the `dbcc_name` device path string** — the path from `GUID_DEVINTERFACE_USB_DEVICE` embeds them directly:
  `\\?\USB#VID_0951&PID_1666#1234567890#{guid}` → VID=`0951`, PID=`1666`, serial=`1234567890`
- **D-03:** Description is retrieved via `SetupDiGetDeviceRegistryPropertyW` with `SPDRP_FRIENDLYNAME` (falls back to `SPDRP_DEVICEDESC`). This SetupDi call is made **inline in the message loop** — it is fast (<1ms for a single device) and the message loop already runs on its own dedicated thread.
- **D-04:** If `dbcc_name` parsing fails (atypical path format, built-in hub, unusual vendor), log at INFO with **best-effort fields** — parse what is available, fill unparsed fields with an empty string. Never skip the log entry silently.
- **D-05:** Devices without a serial number produce `serial = "(none)"` (matches Phase 23 SC-2 and Phase 22 `DeviceIdentity` contract).

### WM_DEVICECHANGE Handler

- **D-06:** The `usb_wndproc` window procedure is extended to handle `WM_DEVICECHANGE` with `wParam == DBT_DEVICEARRIVAL`. GUID discrimination from `dbcc_classguid` routes:
  - `GUID_DEVINTERFACE_VOLUME` arrival → existing drive-letter blocked-set logic (`on_drive_arrival`)
  - `GUID_DEVINTERFACE_USB_DEVICE` arrival → new identity capture path (D-02 → D-03 → log + store)
- **D-07:** `WM_DEVICECHANGE` with `wParam == DBT_DEVICEREMOVECOMPLETE` for `GUID_DEVINTERFACE_USB_DEVICE` removes the drive-letter entry from the in-memory identity map (D-09).

### In-Memory Retention

- **D-08:** `DeviceIdentity` is stored in memory after capture so Phase 26 can read it at I/O enforcement time without re-querying SetupDi (which is unreliable after device removal).
- **D-09:** Storage is a `RwLock<HashMap<char, DeviceIdentity>>` keyed by drive letter, added to `UsbDetector`. The `char` key matches the existing `blocked_drives: RwLock<HashSet<char>>` pattern.
- **D-10:** The in-memory map is authoritative only for the current session. Phase 24 adds the persistent `device_registry` DB table managed by the admin. Phase 26 will use both: in-memory map for live device identity, DB for admin-assigned trust tiers.

### Module Structure

- **D-11:** All new code goes into the existing `detection/usb.rs` — no new file. The `UsbDetector` struct gains the new `device_identities: RwLock<HashMap<char, DeviceIdentity>>` field. No new module needed for the amount of code added.

### Claude's Discretion

- Whether to add a `device_identity_for_drive(&self, letter: char) -> Option<DeviceIdentity>` accessor method on `UsbDetector` — Claude decides based on Phase 26 usability.
- Whether to register the second notification handle separately or combine into a single `RegisterDeviceNotificationW` call — Claude decides based on what the Win32 API supports.
- Specific `windows-rs` crate feature flags needed for `SetupDi` APIs.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase Requirements
- `.planning/REQUIREMENTS.md` — USB-01 requirement definition
- `.planning/ROADMAP.md` §Phase 23 — 3 success criteria (log within 1s, "(none)" serial, no regression)

### Existing Type Definitions (Phase 22)
- `dlp-common/src/endpoint.rs` — `DeviceIdentity` struct (`vid`, `pid`, `serial`, `description` all `String`); canonical field names and serde conventions
- `dlp-common/src/lib.rs` — re-exports to use in dlp-agent

### Existing USB Detection Code
- `dlp-agent/src/detection/usb.rs` — `UsbDetector`, `register_usb_notifications`, `GUID_DEVINTERFACE_VOLUME`, message window/thread setup; this is the file Phase 23 extends
- `dlp-agent/src/detection/mod.rs` — module re-exports
- `dlp-agent/src/service.rs` lines 136–185 — how `UsbDetector` is initialized as `&'static` and how cleanup works; Phase 23 must not break this pattern

### Phase 22 Context
- `.planning/phases/22-dlp-common-foundation/22-CONTEXT.md` — D-06 defines `DeviceIdentity` fields; D-07 defines `UsbTrustTier` (not used in Phase 23 but neighboring type)

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `UsbDetector` struct in `usb.rs`: gains `device_identities: RwLock<HashMap<char, DeviceIdentity>>` — new field alongside existing `blocked_drives`
- `GUID_DEVINTERFACE_VOLUME` const already defined — `GUID_DEVINTERFACE_USB_DEVICE` needs to be added as a new const
- `parking_lot::RwLock` already imported and used — same type for the new map
- `register_usb_notifications` already exists — needs a second `RegisterDeviceNotificationW` call for the USB device GUID, or a second notification handle tracked alongside the volume handle

### Established Patterns
- `UsbDetector` is initialized as `&'static` via `OnceLock` in `service.rs` — `Default` derive or `new()` must initialize the new field
- The message loop thread is named `"usb-notification"` and runs `GetMessageW`/`DispatchMessageW` — SetupDi calls happen synchronously inside that thread (D-03)
- `tracing::info!` with structured fields (e.g., `info!(drive = %letter, ...)`) is the existing log pattern; `DeviceIdentity` fields follow the same pattern
- `DRIVE_DETECTOR: Mutex<Option<&'static UsbDetector>>` global is how the wndproc accesses the detector — Phase 23 uses the same global, no new globals

### Integration Points
- `usb_wndproc`: add `WM_DEVICECHANGE` arm (currently falls through to `DefWindowProcW`)
- `UsbDetector::new()` / `Default`: initialize `device_identities: RwLock::new(HashMap::new())`
- `register_usb_notifications`: add second `RegisterDeviceNotificationW` call for `GUID_DEVINTERFACE_USB_DEVICE`
- `unregister_usb_notifications`: may need to release the second notification handle (or skip per existing shutdown-skip pattern)

</code_context>

<specifics>
## Specific Ideas

- The device path format `\\?\USB#VID_0951&PID_1666#1234567890#` — parse by splitting on `#`, extracting `VID_`/`PID_` prefixed segments from part[1], and treating part[2] as serial (empty or single char → `"(none)"`).
- `GUID_DEVINTERFACE_USB_DEVICE` Windows SDK value: `{A5DCBF10-6530-11D2-901F-00C04FB951ED}`.
- In-memory map keyed by drive letter (`char`) matches the `blocked_drives` key type exactly — both can be updated together in the volume-arrival handler.

</specifics>

<deferred>
## Deferred Ideas

- Sending DeviceIdentity to the server on arrival (Phase 24 adds the endpoint and DB table)
- Admin-managed trust tier lookup from in-memory map (Phase 26)
- USB removal toast notification (Phase 27)
- IPC notification to dlp-user-ui on USB arrival (not needed until Phase 27)

</deferred>

---

*Phase: 23-usb-enumeration-in-dlp-agent*
*Context gathered: 2026-04-22*
