---
slug: usb-deny-logged-but-write-succeeds
status: root_cause_found
trigger: "Blocked USB still writeable — agent logs DENY but writes complete"
created: 2026-05-05
updated: 2026-05-05
related_to: usb-blocked-not-enforced (resolved 2026-04-25 — different failure mode)
---

# Debug Session: Blocked USB Writes Logged as DENY but Still Succeed

## Symptoms

<!-- DATA_START -->

- expected: A USB device registered with `trust_tier=blocked` must prevent file writes to its drive letter (F:). The user-attempted write should fail with an OS-level access-denied error and no file should be created on the device.
- actual: The dlp-agent logs four `BLOCK` events with `decision: "DENY"` and `policy_name: "USB enforcement: device blocked or read-only"` for `F:\New Bitmap image (2).bmp` and `F:\bitmap image.bmp`, but the user successfully writes the file to the USB drive. The audit decision is correct; the runtime enforcement is missing.
- error_messages: None on the user side. No OS error dialog, no access-denied prompt. Write completes silently. Audit log shows the correct DENY decisions but they have no effect on the file system.
- timeline: Reported 2026-05-05. This is a NEW failure mode distinct from the prior `usb-blocked-not-enforced` bug (resolved 2026-04-25). Previously, the USB enforcer entirely bypassed blocked-tier USBs (no block events emitted at all). Now block events ARE emitted but writes still succeed, indicating decision logic works but enforcement does not.
- reproduction: 1. Start dlp-server on port 3000 with USB registered as blocked. 2. Start dlp-agent as Windows service, connected to dlp-server. 3. Plug in SanDisk USB (mounted at F:). 4. Write any file to F:\ via Explorer or another app. 5. Observed: file appears on F:; agent emits 4 BLOCK/DENY audit events for F:\ paths. Expected: write fails, file does NOT appear, agent emits BLOCK events.

<!-- DATA_END -->

## Audit Log Evidence (verbatim, truncated)

Full timestamped events captured by the user at session start (2026-05-05T04:30:23 → 04:30:46Z):

- 04:30:23.624Z DISK_DISCOVERY — discovered SanDisk USBSTOR (drive_letter "C" — likely mislabel; user reports F:) and SanDisk Extreme 55AE at D:
- 04:30:23.930Z DISK_DISCOVERY encryption-status-change — SanDisk drives flagged "unknown" (volume not found in Win32_EncryptableVolume)
- 04:30:35.771Z BLOCK F:\New Bitmap image (2).bmp WRITE DENY — policy "USB enforcement: device blocked or read-only" — agent_id AGENT-UNKNOWN
- 04:30:35.782Z BLOCK F:\New Bitmap image (2).bmp WRITE DENY — same
- 04:30:41.973Z BLOCK F:\New Bitmap image (2).bmp WRITE DENY — same
- 04:30:41.973Z BLOCK F:\bitmap image.bmp WRITE DENY — same
- 04:30:41.977Z BLOCK F:\bitmap image.bmp WRITE DENY — same

Notable: every BLOCK has `agent_id: "AGENT-UNKNOWN"` — agent identity registration may also be broken.
Notable: discovered_disks reports SanDisk USBSTOR drive_letter as "C" but user reports plugged at F:. Drive-letter resolution may be mislabeling.

## Current Focus

- hypothesis: The `UsbEnforcer` correctly returns `decision: DENY` and audit code writes the BLOCK log entry, but the I/O interception layer (likely a Minifilter callback or user-mode hook) does not propagate the DENY back to the OS file-create call. Either (a) the interception path logs decisions out-of-band but never returns `STATUS_ACCESS_DENIED` to the IRP/IO request, or (b) the audit-log call is on a path that runs post-write, after the file has already been created.
- test: Trace the call chain from the I/O hook entry point to the audit log write. Confirm whether the hook returns a deny code synchronously to the kernel/OS, or whether enforcement is observe-only (audit-only).
- next_action: Read `dlp-agent/src/interception/mod.rs` and the USB-write code path. Confirm whether a `BLOCK` decision actually fails the underlying IRP/file-create, or whether it is logged-only.

## Evidence

- 2026-05-05T04:35:00Z — Read `dlp-agent/src/interception/mod.rs` lines 92-166. The USB enforcement path in `run_event_loop` receives a `UsbBlockResult` with `decision: DENY`, emits an audit event via `emit_audit()`, sends a `BlockNotify` to the UI via `pipe1::send_to_ui()`, and then executes `continue` to skip ABAC evaluation. There is NO code that returns an error to the OS or blocks the file operation. The file has already been written by the time the `notify` event fires.
- 2026-05-05T04:36:00Z — Read `dlp-agent/src/interception/file_monitor.rs`. The `InterceptionEngine` uses the `notify` crate with `RecommendedWatcher` and a 500ms poll interval. `notify` is a passive file system watcher — it observes changes AFTER they occur. It cannot intercept, block, or fail an I/O operation. `event_kind_to_action` maps `notify::EventKind::Create/Modify/Remove` to `FileAction` variants, all with `process_id: 0` (no PID resolution).
- 2026-05-05T04:37:00Z — Read `dlp-agent/src/usb_enforcer.rs`. `UsbEnforcer::check` returns `Some(UsbBlockResult { decision: DENY, ... })` for unregistered USB devices (defence-in-depth fallback). For registered devices (Blocked, ReadOnly, FullAccess), it returns `None` because "active enforcement is handled by DeviceController". The doc comment at lines 12-19 incorrectly states that Blocked devices "return None — device is disabled at the PnP level" and ReadOnly devices "return None — volume DACL is modified". This is the intended design, but the audit log shows BLOCK events for a device that should have been handled at the PnP level — suggesting the device is either unregistered or the PnP handler failed.
- 2026-05-05T04:38:00Z — Read `dlp-agent/src/device_controller.rs`. `DeviceController::disable_usb_device` calls `CM_Disable_DevNode` with `CM_DISABLE_ABSOLUTE`. This is the intended real enforcement for Blocked-tier devices. `set_volume_readonly` modifies the volume DACL for ReadOnly-tier devices. Both methods only fire when the arrival handler calls them for registered devices.

## Eliminated

- (none)

## Resolution

- root_cause: The file interception pipeline is purely observational (audit-only). It uses the `notify` crate — a passive file system watcher that observes changes AFTER they occur. When `UsbEnforcer::check` returns `Decision::DENY`, the `run_event_loop` only emits an audit log entry and a UI toast notification, then `continue`s to the next event. It never returns an error code to the OS or blocks the I/O operation because the file has already been written by the time the `notify` event is received. The intended real enforcement is `DeviceController::disable_usb_device` (PnP-level disable for Blocked) and `set_volume_readonly` (DACL modification for ReadOnly), but these only fire for registered devices via the arrival handler. The audit log shows the device is being blocked via the unregistered-device fallback path, which means either (a) the device is not registered in the DeviceRegistryCache, or (b) the arrival handler did not call DeviceController. In either case, the notify-based pipeline cannot block I/O — it can only observe and audit.
- fix: Two-part fix required. (1) Ensure the USB device registration and arrival handler wiring is correct so that `DeviceController::disable_usb_device` fires for Blocked-tier devices at the PnP level, preventing the device from ever being writable. (2) As a defence-in-depth measure, the file interception layer should be upgraded from a passive `notify` watcher to an actual I/O interception mechanism (Windows minifilter driver or API hooking) that can synchronously fail file-create/write operations with `STATUS_ACCESS_DENIED` before the data hits the disk. Without (2), any gap in the PnP-level enforcement (race conditions, handler failures, service restarts while device is plugged in) leaves the system exposed.
- fix_applied: no

## Related Files

- `dlp-agent/src/interception/mod.rs` — main I/O interception event loop; bridges OS hooks to enforcer (audit-only, cannot block)
- `dlp-agent/src/interception/file_monitor.rs` — `notify`-based file watcher; passive observation only
- `dlp-agent/src/usb_enforcer.rs` — produces UsbBlockResult with decision DENY/ALLOW (returns None for registered devices)
- `dlp-agent/src/device_controller.rs` — intended real enforcement via CM_Disable_DevNode and DACL modification
- `dlp-agent/src/detection/usb.rs` — USB drive-letter mapping (suspect: discovery reports "C" for plugged-at-F:)
- `dlp-agent/src/service.rs` — startup wiring; agent_id "AGENT-UNKNOWN" suggests registration not completing
- `dlp-agent/src/config.rs` — agent-id / config resolution

## Specialist Review

**Skill:** rust (engineering:debug fallback)

**Review:** LOOKS_GOOD with concerns. The root cause analysis correctly identifies that the notify-based file watcher is audit-only and cannot block I/O. The fix direction (ensure DeviceController PnP-level disable fires for registered blocked devices, or replace notify with an actual I/O filter) is correct. Key pitfall: if switching to a minifilter or API hooking approach, ensure it handles async I/O correctly and does not introduce stability issues. The current DeviceController::disable_usb_device approach is the right first fix — verify the device registration path and the arrival handler wiring.
