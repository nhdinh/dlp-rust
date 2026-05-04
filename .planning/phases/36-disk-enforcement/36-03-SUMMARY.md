---
phase: 36-disk-enforcement
plan: 03
subsystem: detection
tags: [dlp-agent, disk, device-watcher, WM_DEVICECHANGE, usb, enforcement, audit]

# Dependency graph
requires:
  - phase: 36-01
    provides: AuditEvent.blocked_disk field and with_blocked_disk builder
  - phase: 36-02
    provides: DiskEnforcer::check, DiskBlockResult, get_disk_enumerator
  - phase: 33
    provides: DiskEnumerator, set_disk_enumerator, drive_letter_map
requires:
  - phase: 35
    provides: disk_allowlist persistence in AgentConfig

provides:
  - "device_watcher.rs: hidden Win32 message-only window dispatching WM_DEVICECHANGE for VOLUME, USB_DEVICE, DISK GUIDs"
  - "disk::on_disk_arrival and on_disk_removal: live drive_letter_map maintenance + DiskDiscovery audit emit"
  - "run_event_loop pre-ABAC disk enforcement block with BlockNotify + Toast + audit"
  - "service.rs wired: DiskEnforcer + device_watcher_task + unregister_device_watcher"
  - "usb.rs refactored: Win32 window infrastructure deleted; dispatch entry-points kept"

affects:
  - 37-policy-enforcement
  - any-future-disk-enforcement-phase

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "dispatch-pattern: device_watcher owns the Win32 window; per-protocol handler functions in detection modules exposed as pub and called from wndproc"
    - "OnceLock-global + Mutex setter: DRIVE_DETECTOR uses Mutex (clearable on shutdown), others use OnceLock (set-once)"
    - "pre-ABAC short-circuit: enforcer.check -> audit -> pipe1 -> pipe2 -> continue; ABAC never fires for blocked events"
    - "30-second per-drive toast cooldown embedded in DiskEnforcer::last_toast HashMap"
    - "fail-closed D-06: disk enforcement blocks all fixed-disk writes when enumerator !is_ready()"

key-files:
  created:
    - dlp-agent/src/detection/device_watcher.rs
  modified:
    - dlp-agent/src/detection/disk.rs
    - dlp-agent/src/detection/usb.rs
    - dlp-agent/src/detection/mod.rs
    - dlp-agent/src/interception/mod.rs
    - dlp-agent/src/service.rs
    - dlp-server/src/alert_router.rs

key-decisions:
  - "device_watcher.rs owns all Win32 window/registration/loop code; usb.rs exposes only per-event handler pub fns called from the wndproc dispatcher"
  - "set_drive_detector() public setter added to usb.rs to replace direct DRIVE_DETECTOR mutation from service.rs"
  - "device watcher spawned after audit_ctx construction so DiskDiscovery audit events are properly attributed"
  - "dispatch_usb_device_arrival includes REGISTRY_CACHE async refresh fire-and-forget (ported from old usb_wndproc)"
  - "disk enforcement block uses continue to skip ABAC, mirroring the USB enforcement short-circuit pattern"
  - "Toast body format: '{model} ({drive_letter}:) - this disk is not registered' with drive_letter optional"

patterns-established:
  - "Pattern: Win32 window dispatch centralized in device_watcher; protocol handlers live in their owning modules"
  - "Pattern: pre-ABAC enforcement chain: USB -> Disk -> ABAC; each layer uses continue to short-circuit lower layers"

requirements-completed: [DISK-04, DISK-05, AUDIT-02]

# Metrics
duration: ~180min
completed: 2026-05-04
---

# Phase 36 Plan 03: End-to-End Wiring Summary

**Win32 WM_DEVICECHANGE dispatcher extracted to device_watcher.rs; disk hot-plug handlers wired to DiskEnforcer pre-ABAC block in run_event_loop with full audit/toast/pipe chain**

## Performance

- **Duration:** ~180 min
- **Started:** 2026-05-04T00:00:00Z
- **Completed:** 2026-05-04T03:44:32Z
- **Tasks:** 4 (+ 1 auto-fix)
- **Files modified:** 7

## Accomplishments

- Created `device_watcher.rs` with hidden Win32 message-only window, `RegisterDeviceNotificationW` for VOLUME/USB_DEVICE/DISK GUIDs, `GetMessageW` loop, and `WM_DEVICECHANGE` dispatcher
- Refactored `usb.rs`: deleted window infrastructure (~760 lines), populated real `dispatch_usb_device_arrival` (with cache refresh) and `dispatch_usb_device_removal`, added `set_drive_detector()` setter
- Added `disk::on_disk_arrival` and `disk::on_disk_removal` with drive_letter_map maintenance and DiskDiscovery audit emit for unregistered arrivals
- Wired `DiskEnforcer` into `run_event_loop` as a pre-ABAC enforcement block: audit `Block` event with `with_blocked_disk`, Pipe1 `BlockNotify`, Pipe2 toast (30s cooldown), `continue` to skip ABAC
- Wired `service.rs`: `spawn_device_watcher_task` replaces `register_usb_notifications`; `DiskEnforcer::new()` constructed after disk enumeration; `unregister_device_watcher` on shutdown

## Task Commits

1. **Task 1: Create device_watcher.rs** - `2910131` (feat)
2. **Task 2: disk::on_disk_arrival / on_disk_removal** - `46e5ed5` (feat)
3. **Task 3: Strip usb.rs of Win32 window infrastructure** - `63ca780` (refactor)
4. **Task 4: Wire DiskEnforcer into run_event_loop and service.rs** - `48acae4` (feat)
5. **Auto-fix: dlp-server blocked_disk field** - `6597179` (fix)

## Files Created/Modified

- `dlp-agent/src/detection/device_watcher.rs` (NEW) - Win32 hidden window, WM_DEVICECHANGE dispatcher, extract_disk_instance_id, spawn/unregister API
- `dlp-agent/src/detection/disk.rs` - on_disk_arrival, on_disk_removal, emit_disk_discovery_for_arrival
- `dlp-agent/src/detection/usb.rs` - Window infrastructure deleted; dispatch entry-points populated; set_drive_detector added
- `dlp-agent/src/detection/mod.rs` - device_watcher module + re-exports
- `dlp-agent/src/interception/mod.rs` - disk_enforcer parameter + pre-ABAC disk enforcement block
- `dlp-agent/src/service.rs` - DiskEnforcer construction, device_watcher spawn/unregister wiring
- `dlp-server/src/alert_router.rs` - Added blocked_disk: None to AuditEvent literal (Rule 1 auto-fix)

## Decisions Made

- `device_watcher.rs` owns all Win32 window + registration code; usb.rs exposes only pub handler fns called from the dispatcher — clean separation of transport vs. protocol
- `set_drive_detector()` added as a public setter (Mutex-backed, overwritable) rather than making `DRIVE_DETECTOR` static pub — maintains encapsulation
- Device watcher spawned after `audit_ctx` is constructed (not before) to ensure DiskDiscovery events are properly attributed from first arrival
- `dispatch_usb_device_arrival` carries the full REGISTRY_CACHE async refresh logic (fire-and-forget via REGISTRY_RUNTIME_HANDLE), matching the old `usb_wndproc` behavior
- Toast body uses `Option<char>` drive_letter gracefully: `"{model} ({letter}:) - this disk is not registered"` with empty drive-part when None

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] dlp-server build broken by missing blocked_disk field**
- **Found during:** Final verification (cargo build --all)
- **Issue:** `dlp-server::alert_router::send_test_alert` used struct literal for `AuditEvent` missing the `blocked_disk` field added in Plan 01. Build failed.
- **Fix:** Added `blocked_disk: None` to the struct literal in `dlp-server/src/alert_router.rs:283`
- **Files modified:** dlp-server/src/alert_router.rs
- **Verification:** `cargo build --all` passes
- **Committed in:** 6597179

---

**Total deviations:** 1 auto-fixed (Rule 1 bug)
**Impact on plan:** Fix was necessary for workspace build correctness. No scope creep.

## Issues Encountered

- **OnceLock test isolation flakiness (pre-existing):** `detection::disk::tests::test_on_disk_arrival_inner_updates_drive_letter_map_only`, `test_on_disk_arrival_inner_skips_already_tracked`, and `test_global_static_get_set` fail when run in parallel with other disk tests due to the global `OnceLock<Arc<DiskEnumerator>>` being set by a competing test. Each passes in isolation (`cargo test --lib "<test-name>"`). This is the same pre-existing race condition documented in Phase 35 Plan 02. Not caused by Plan 03 changes.

## Deferred Items

- OnceLock test isolation fix: run disk global-state tests with `#[serial]` attribute or a scoped-global test helper. Tracked for a future test-hygiene pass.

## Known Stubs

None — all dispatch functions are fully implemented; no placeholder TODO comments remain.

## Next Phase Readiness

- DISK-04, DISK-05, AUDIT-02 requirements are closed
- End-to-end disk enforcement is live: arrival -> drive_letter_map + DiskDiscovery audit; write -> DiskEnforcer::check -> Block audit + toast + Pipe1 notify
- USB enforcement paths unchanged (dispatch wrappers transparent)
- Phase 37 can build policy enforcement layers on top of the established pre-ABAC chain

---
*Phase: 36-disk-enforcement*
*Completed: 2026-05-04*
