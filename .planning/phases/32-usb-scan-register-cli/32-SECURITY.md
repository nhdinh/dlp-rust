---
phase: 32
slug: usb-scan-register-cli
status: verified
threats_open: 0
asvs_level: 1
created: 2026-04-29
updated: 2026-04-29
---

# Phase 32 — USB Scan & Register CLI Security

> Per-phase security contract: threat register, accepted risks, and audit trail.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| Admin TUI → Local Win32 SetupDi API | USB device enumeration queries the local Windows device manager. No network or external system boundary crossed. | USB device metadata (VID, PID, serial, description) — non-sensitive display data |
| Admin TUI → DLP Server (HTTP) | Device registry GET/POST calls traverse the existing authenticated admin API. | JWT bearer token, device identity + trust tier — same boundary as Device Registry screen |
| DLP Server → USB Device Registry DB | Server-side persistence of registered device identities. | DeviceIdentity + UsbTrustTier — existing Phase 23/24 boundary |

---

## Threat Register

| Threat ID | Category | Component | Disposition | Mitigation | Status |
|-----------|----------|-----------|-------------|------------|--------|
| T-32-01 | Tampering | `read_string_property` 1024-byte UTF-16 LE buffer | accept | Existing fixed-size buffer truncates oversized REG_SZ values silently; descriptions are display-only in the TUI and forwarded to the existing server upsert handler which already validates. Behavior unchanged from prior agent code. | closed |
| T-32-02 | Information Disclosure | `parse_usb_device_path` re-exposed as `pub fn` | accept | The function only parses strings already provided by the OS device-broadcast subsystem; no new disclosure surface. Pure data shape transformation. | closed |
| T-32-03 | Denial of Service | `enumerate_connected_usb_devices_windows` SetupDi loop | mitigate | Hard 1024-iteration safety valve mirrors agent pattern; cleanup via `SetupDiDestroyDeviceInfoList` on every exit path, including early returns from `Err` on `SetupDiGetClassDevsW`. | closed |
| T-32-04 | Spoofing | USB device VID/PID claims | accept | Out-of-scope for this phase — same threat exists in current agent USB identity capture path. | closed |
| T-32-05 | Information Disclosure | `UsbScanEntry.registered_tier` display | accept | Rendered to authenticated admin TUI only; admin already has full registry visibility via `/full` endpoint. | closed |
| T-32-06 | Tampering | Server returns unexpected `trust_tier` value | mitigate | Render layer treats `registered_tier` as opaque `String`; no parsing, no exec; rendered through ratatui escaping. | closed |
| T-32-07 | Information Disclosure | Long device.description from rogue USB rendered in TUI | mitigate | Description column is `Constraint::Percentage(44)` — ratatui Table truncates oversized cells to allocated width; no terminal escape sequence handling. | closed |
| T-32-08 | Tampering | Server returns malformed JSON in `/full` | mitigate | `build_registry_map` uses `unwrap_or("")` / `unwrap_or("blocked")` defaults — no panic on malformed rows. Tested by `build_registry_map_defaults_missing_tier_to_blocked`. | closed |
| T-32-09 | Denial of Service | Pathologically large USB enumeration result (1000+ devices) | accept | `enumerate_connected_usb_devices_windows` enforces a 1024-iteration safety valve (Plan 01); merge is O(n) HashMap lookup. | closed |
| T-32-10 | Spoofing | USB device claims VID/PID matching another vendor | accept | Same threat exists in current agent + manual register flow; tier registration is an admin action, audit-logged on the server. | closed |
| T-32-11 | Elevation of Privilege | Unauthenticated user crafting requests to `/admin/device-registry/full` | accept | Endpoint already enforces JWT bearer auth via existing server middleware; admin TUI is already authenticated before reaching this screen. | closed |
| T-32-12 | Information Disclosure | Status bar leaking error details with sensitive context | mitigate | `format!("Error fetching device registry: {e}")` includes only the `ClientError` Display impl, which sanitizes auth tokens and request bodies (existing client.rs convention). | closed |

*Status: open / closed*
*Disposition: mitigate (implementation required) / accept (documented risk) / transfer (third-party)*

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| R-32-01 | T-32-01, T-32-02, T-32-04, T-32-09, T-32-10, T-32-11 | Threats are either inherited from existing code paths (agent USB capture, existing auth middleware), or represent operational constraints (Win32 API buffer limits). No new attack surface introduced by this phase. | gsd-security-auditor | 2026-04-29 |
| R-32-02 | T-32-05 | Admin TUI is an authenticated context. Tier visibility to the admin is by design. | gsd-security-auditor | 2026-04-29 |

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-04-29 | 12 | 12 | 0 | gsd-secure-phase (Claude) |

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-04-29
