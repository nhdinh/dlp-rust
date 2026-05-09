# Phase 44 Research: Mount-Time Blocking

## Current Disk Arrival Flow

1. `device_watcher.rs` handles `WM_DEVICECHANGE` `DBT_DEVICEARRIVAL` for `GUID_DEVINTERFACE_DISK`
2. 500ms deferral (Phase 38.2 GAP-01) allows volume manager to assign drive letter
3. `on_disk_arrival` → `on_disk_arrival_inner` in `disk.rs`
4. New disks inserted into `drive_letter_map` only
5. I/O-time blocking in `DiskEnforcer::check()` is the current enforcement

## Integration Point

Extend `on_disk_arrival_inner` to check allowlist BEFORE inserting into `drive_letter_map`. If unregistered, call mount-time blocking instead.

## Recommended Windows API Approach

1. **Primary**: `DefineDosDeviceW(DDD_REMOVE_DEFINITION, "E:", NULL)` — removes drive letter from DOS namespace
2. **Secondary**: Open volume handle, `FSCTL_DISMOUNT_VOLUME`, then `IOCTL_VOLUME_OFFLINE` — defense-in-depth
3. **Audit**: Emit `DiskMountBlocked` event

## Reusable Code Patterns

- `DeviceController::set_volume_deny_all` — `CreateFileW` + `DeviceIoControl` pattern
- `DiskEnforcer::disk_for_instance_id` — allowlist check
- `emit_disk_discovery_for_arrival` — audit emission pattern
