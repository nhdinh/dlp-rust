---
slug: usb-blocked-not-enforced
status: root_cause_found
trigger: "a USB registered as blocked would still allow read/write"
created: 2026-04-23
updated: 2026-04-23
source_phase: 28-admin-tui-screens (UAT check 1)
---

# Debug Session: USB blocked tier not enforced

## Symptoms

<!-- DATA_START -->
- expected: A USB registered via the Phase 28 TUI with trust_tier=blocked prevents all read/write/delete operations on the agent host.
- actual: The USB device is registered successfully, but after the dlp-agent re-polls the registry, the device is still usable for read, write, AND delete — as if the registration had no effect.
- error_messages: None reported. No block dialog, no agent log entry noting the blocked device.
- timeline: Surfaced during Phase 28 UAT on 2026-04-23. Phase 28 is the first release to add a TUI-driven USB registration flow (Main Menu → Devices & Origins → Device Registry → `r`).
- reproduction:
    1. Start dlp-server and dlp-admin-cli. Log in.
    2. Navigate: Main Menu → Devices & Origins → Device Registry → press `r`.
    3. Enter VID `0951`, PID `1666`, serial `TEST001`, description `Test USB Drive`.
    4. On DeviceTierPicker, select `blocked` (index 0) — Enter.
    5. Wait for dlp-agent to re-poll the registry (or restart the agent).
    6. Plug in the matching USB device and attempt read / write / delete.
    7. Observed: all three actions succeed. Expected: all three blocked.
<!-- DATA_END -->

## Current Focus

- hypothesis: ~~Phase 28 TUI sends malformed fields~~ — ELIMINATED. Real cause is that pre-existing USB drives (plugged in before agent start) never get their VID/PID/serial captured, so the Phase 26 enforcer sees an empty `device_identities` map for the drive letter and short-circuits to "not a USB drive," falling through to ABAC-allow.
- test: Traced the enforcer data path from agent startup through registry cache to `UsbEnforcer::check`.
- next_action: Apply fix to populate `device_identities` during `scan_existing_drives()`, or add fallback-to-Blocked in `UsbEnforcer::check` when a drive is present in `blocked_drives` but absent from `device_identities`.

## Evidence

- timestamp: 2026-04-23 / finding: TUI POST body construction in `dlp-admin-cli/src/screens/dispatch.rs:3697-3713` sends exactly `{vid, pid, serial, description, trust_tier}` with literal values `"blocked" | "read_only" | "full_access"` from index-to-string mapping. No casing transform applied.
- timestamp: 2026-04-23 / finding: `DeviceRegistryRequest` at `dlp-server/src/admin_api.rs:287-300` deserializes the exact TUI field shape. Allowlist check at line 1598 accepts `"blocked"`. Row is persisted verbatim — no normalisation of VID/PID/serial on the server side (`admin_api.rs:1609-1617`, `db/repositories/device_registry.rs:88-107`).
- timestamp: 2026-04-23 / finding: `DeviceRegistryCache::trust_tier_for` (`dlp-agent/src/device_registry.rs:65-73`) returns `UsbTrustTier::Blocked` on cache miss (fail-safe D-10). A casing/serial mismatch would therefore still DENY, not ALLOW. Rules out mismatch-driven ALLOW.
- timestamp: 2026-04-23 / finding: `UsbEnforcer::check` (`dlp-agent/src/usb_enforcer.rs:119-165`) at line 126-130 reads `self.detector.device_identities.read().get(&drive)` and uses `?` to early-return `None` if the drive letter has no identity. Returning `None` causes the interception event loop (`interception/mod.rs:89-163`) to skip the USB short-circuit and proceed to ABAC evaluation.
- timestamp: 2026-04-23 / finding: `UsbDetector::scan_existing_drives` (`dlp-agent/src/detection/usb.rs:100-111`) iterates A..Z, and for each removable drive it inserts the letter into `blocked_drives` (a `HashSet<char>`). It does NOT touch `device_identities`. VID/PID/serial require parsing a `dbcc_name` device path, which is only available from the `DBT_DEVICEARRIVAL` WM message.
- timestamp: 2026-04-23 / finding: `capture_device_identity_on_arrival` (`dlp-agent/src/detection/usb.rs:434-467`) is the only producer of `device_identities` entries. It fires from `usb_wndproc` only on arrival events registered by `register_usb_notifications` (`service.rs:434`).
- timestamp: 2026-04-23 / finding: `blocked_drives` is written by `scan_existing_drives`, `on_drive_arrival`, and `on_drive_removal`, but is **never read** by `UsbEnforcer::check` nor by any code under `dlp-agent/src/interception/`. Verified via repo-wide grep — only reads are in tests and one test-helper in `integration.rs:2026`. The set is a vestigial Phase 22/23 artifact.
- timestamp: 2026-04-23 / conclusion: For any USB plugged in BEFORE `dlp-agent` starts (the common UAT setup), `device_identities[letter]` is empty, `UsbEnforcer::check` returns `None`, and all file I/O falls through to ABAC. With no path-specific policy for `E:\...`, ABAC allows. Observed symptom matches exactly: no block dialog, no USB audit entry, all operations succeed.

## Eliminated

- Phase 28 TUI POST-body shape mismatch — body fields match `DeviceRegistryRequest` exactly.
- `trust_tier` casing mismatch (`"Blocked"` vs `"blocked"`) — TUI emits lowercase literal from the `match sel` arm.
- VID/PID casing mismatch in storage vs detector — irrelevant here because pure-hex-digit values (`0951`, `1666`) are case-stable; plus, any mismatch would fail-safe to Blocked, not Allow.
- Server-side allowlist rejecting the tier — server logs would show 422, and the UAT shows successful registration.
- Registry cache not refreshing — cache miss would still yield fail-safe Blocked, not Allow.
- `UsbEnforcer` not wired into the event loop — confirmed wired at `service.rs:426-430` and consulted at `interception/mod.rs:89-163`.

## Resolution

- root_cause: Pre-existing USB drives (plugged in before agent start) are marked in `UsbDetector.blocked_drives` by `scan_existing_drives()` but never have their VID/PID/serial captured into `UsbDetector.device_identities`. The Phase 26 `UsbEnforcer` only consults `device_identities`; when it's empty for the drive letter, `check()` returns `None`, bypassing USB policy and falling through to ABAC, which allows the operation.
- fix: Two-part fix. (1) Defence-in-depth in `UsbEnforcer::check`: when `device_identities[drive]` is missing but `blocked_drives.contains(&drive)` is true, treat the drive as "known USB without identity" and return `UsbBlockResult { decision: DENY, tier: Blocked, identity: DeviceIdentity::default() }` to preserve default-deny. (2) Extend `scan_existing_drives()` to resolve VID/PID/serial/description for each removable drive via `SetupDiGetClassDevs(GUID_DEVINTERFACE_DISK)` → `IOCTL_STORAGE_GET_DEVICE_NUMBER` → walk `GUID_DEVINTERFACE_USB_DEVICE` interfaces → `parse_usb_device_path` + `setupdi_description_for_device`, populating `device_identities` on startup so registry lookups work for pre-existing devices too.
- specialist_review: pending

## Specialist Review

(to be populated after user approves fix direction)

## Related Files (initial candidates)

- `dlp-admin-cli/src/screens/dispatch.rs` — new DeviceTierPicker commit handler (Plan 28-03) — VERIFIED CORRECT
- `dlp-admin-cli/src/app.rs` — DeviceRegisterState accumulator — VERIFIED CORRECT
- `dlp-server/src/admin_api.rs` — DeviceRegistryRequest, upsert_device_registry_handler — VERIFIED CORRECT
- `dlp-server/src/db/repositories/device_registry.rs` — persistence layer — VERIFIED CORRECT
- `dlp-agent/src/device_registry.rs` — agent-side cache + trust_tier lookup — VERIFIED CORRECT (fail-safe Blocked on miss)
- `dlp-agent/src/usb_enforcer.rs` — enforcement logic — **FIX TARGET (defence-in-depth fallback)**
- `dlp-agent/src/detection/usb.rs` — USB plug event → identity extraction — **FIX TARGET (scan_existing_drives must populate device_identities)**
- `dlp-agent/src/service.rs` — startup wiring — VERIFIED CORRECT
- `dlp-agent/src/interception/mod.rs` — event loop; calls enforcer — VERIFIED CORRECT
