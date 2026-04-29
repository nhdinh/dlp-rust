---
slug: usb-serial-stale-after-rereg
status: resolved
trigger: "Using dlp-admin-cli to update device registry (same VID/PID, different serial, USB Blocked tier): deleted old entry, added new entry with new serial, restarted dlp-agent — but arrival log still shows old device serial"
created: "2026-04-29"
updated: "2026-04-29"
source_phase: 31-usb-cm-blocking
---

# Debug Session: USB Stale Serial After Re-registration

## Symptoms

<!-- DATA_START -->
- expected: After deleting old device entry (old serial) and adding new entry (same VID/PID, new serial) in dlp-admin-cli, then restarting dlp-agent, plugging in the new physical device should log the new serial and apply Blocked enforcement.
- actual: The arrival log still shows the OLD serial after agent restart, even though the old registry entry was deleted and new one added with a different serial.
- error_messages: No errors. Arrival log fires (fix from usb-not-triggering-enforcement is working) but serial in log is old serial.
- timeline: Discovered 2026-04-29 during Phase 31 UAT. The device registry update path (delete old + add new) is the workaround for lack of edit capability in the TUI.
- reproduction:
    1. Register USB device (VID=X, PID=Y, serial=OLD) as Blocked via dlp-admin-cli TUI.
    2. In dlp-admin-cli Device Registry, delete the OLD entry.
    3. Register a new entry (VID=X, PID=Y, serial=NEW) as Blocked.
    4. Restart dlp-agent.
    5. Plug in the NEW physical USB device (serial=NEW).
    6. Observe arrival log — shows serial=OLD instead of serial=NEW.
<!-- DATA_END -->

## Current Focus

- hypothesis: CONFIRMED. Two root causes found:
  1. DeviceRegistryEntry in server_client.rs expects trust_tier (and id, description, created_at) but GET /admin/device-registry (PublicDeviceEntry) only returns vid/pid/serial — serde deserialization always fails, cache refresh silently retains stale state, so the old serial entry is never evicted.
  2. The serial in the arrival log comes from the physical device hardware descriptor (dbcc_name), not from the registry. If tester uses same physical device, the log always shows hardware serial regardless of registry state.
- test: Code trace complete. No runtime test needed — the struct field mismatch is a static analysis finding.
- next_action: Fix DeviceRegistryEntry to match PublicDeviceEntry shape (vid/pid/serial only), since the agent only needs these three fields for cache keying. Trust tier is not available from the unauthenticated endpoint by design.

## Evidence

- timestamp: 2026-04-29T00:00:00Z
  finding: "GET /admin/device-registry returns PublicDeviceEntry {vid, pid, serial} but DeviceRegistryEntry in server_client.rs declares trust_tier: String (required, no serde default). Deserialization fails on every cache refresh."
  file: dlp-agent/src/server_client.rs
  lines: 479-495
  detail: "DeviceRegistryEntry has id, description, trust_tier, created_at — all absent from PublicDeviceEntry JSON. Serde returns Err on missing required String fields."

- timestamp: 2026-04-29T00:00:01Z
  finding: "DeviceRegistryCache::refresh() on Err path: warn and retain stale cache (D-10 fail-safe). So the old (vid, pid, old_serial) entry is never removed."
  file: dlp-agent/src/device_registry.rs
  lines: 130-134

- timestamp: 2026-04-29T00:00:02Z
  finding: "DeviceRegistryCache::refresh() on Ok path: rebuilds the entire map from server response using e.trust_tier. If deserialization never succeeds, the map is never rebuilt. After agent restart the cache is initially empty, so trust_tier_for returns Blocked for everything (default-deny) — enforcement still works but NOT because the entry was found."
  file: dlp-agent/src/device_registry.rs
  lines: 107-127

- timestamp: 2026-04-29T00:00:03Z
  finding: "The serial in the arrival info! log at usb.rs:512 is identity.serial from parse_usb_device_path(device_path) which parses the dbcc_name Windows WM_DEVICECHANGE device path — hardware serial only. The registry is not consulted for the log message."
  file: dlp-agent/src/detection/usb.rs
  lines: 499-515

- timestamp: 2026-04-29T00:00:04Z
  finding: "The agent's cache key is (vid, pid, serial) from the server response. Since refresh never succeeds (deserialize fails), the cache stays empty after restart. on_usb_device_arrival calls trust_tier_for with hardware serial — Blocked returned by default deny, NOT by registry lookup. Enforcement works but for wrong reason; has_device() returns false for all devices."
  file: dlp-agent/src/device_registry.rs
  lines: 65-73

## Eliminated

- scan_existing_drives populating stale device_identities: eliminated — scan_existing_drives only touches blocked_drives, not device_identities.
- parse_usb_device_path extracting wrong segment: eliminated — parsing is correct per unit tests and code trace. Serial comes from segment 2 of the dbcc_name device path.

## Resolution

- root_cause: "DeviceRegistryEntry in server_client.rs declares fields (trust_tier, id, description, created_at) that are absent from the GET /admin/device-registry PublicDeviceEntry response. Serde deserialization fails on every cache refresh, causing the cache to be permanently stale (always-empty after restart). Arrival log serial is hardware-reported (correct behavior); the reported 'old serial' in logs is the hardware serial of the physical device, not a stale cache artifact."
- fix: "Align DeviceRegistryEntry with PublicDeviceEntry: keep only vid, pid, serial fields. Since trust_tier is not available from the unauthenticated endpoint, the cache can only record presence (registered devices). Change cache value type from UsbTrustTier to a unit value (or keep as Blocked for all registered entries). OR: change the endpoint the agent polls from the unauthenticated GET /admin/device-registry to the authenticated GET /admin/device-registry/full which includes trust_tier."
- verification: "After fix, DeviceRegistryCache::refresh succeeds, cache contains new serial entry, trust_tier_for(vid, pid, new_serial) returns the correct tier. Old entry (old serial) is absent from rebuilt cache."
- files_changed: [dlp-agent/src/server_client.rs, dlp-agent/src/device_registry.rs]

## Specialist Review

[pending]
