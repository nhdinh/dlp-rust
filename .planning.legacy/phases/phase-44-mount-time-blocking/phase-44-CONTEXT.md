# Phase 44: Mount-Time Blocking - Context

**Gathered:** 2026-05-08
**Status:** Ready for planning
**Mode:** Auto-generated (discuss skipped via workflow.skip_discuss)

<domain>
## Phase Boundary

Goal: Lock volume at mount time so unregistered disks do not appear in Explorer.

Requirement: DISK-06

Success criteria:
1. Unregistered fixed disk does not receive a drive letter on arrival
2. I/O-time blocking remains as fallback
3. Audit event emitted when mount-time block triggers

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion
All implementation choices are at Claude's discretion — discuss phase was skipped per user setting. Use ROADMAP phase goal, success criteria, and codebase conventions to guide decisions.

Key design question: How to prevent drive letter assignment at mount time?
- Option A: Volume lock via FSCTL_LOCK_VOLUME (blocks I/O but drive letter may still appear)
- Option B: Intercept DBT_DEVICEARRIVAL and call DefineDosDevice to remove drive letter
- Option C: Set volume offline via IOCTL_VOLUME_OFFLINE
- Option D: Register as volume filter driver (too complex for this phase)

Preferred approach: B + C hybrid — on DBT_DEVICEARRIVAL for unregistered disks, call IOCTL_VOLUME_OFFLINE to prevent volume from being mounted, combined with DefineDosDevice to remove any assigned letter. This is purely user-mode, requires no driver.

</decisions>

<code_context>
## Existing Code Insights

Phase 36 (Disk Enforcement) already handles WM_DEVICECHANGE DBT_DEVICEARRIVAL for GUID_DEVINTERFACE_DISK. The `on_disk_arrival` function in `dlp-agent/src/detection/disk.rs` is the existing entry point for disk arrival events.

The `DiskEnumerator` maintains an `instance_id_map` of known/allowlisted disks. The pre-ABAC check in `run_event_loop` blocks I/O for unregistered disks.

Codebase context will be gathered during plan-phase research.

</code_context>

<specifics>
## Specific Ideas

- Extend `on_disk_arrival` to call mount-time blocking BEFORE the disk gets a drive letter
- Use SetupDi to correlate the arriving device with an instance_id
- Check instance_id against `instance_id_map` (from Phase 33/37)
- If not found in allowlist: call IOCTL_VOLUME_OFFLINE on the volume
- Emit audit event with disk identity
- Keep the existing I/O-time blocking as fallback (in case mount-time block fails or is bypassed)

</specifics>

<deferred>
## Deferred Ideas

- Volume filter driver (minifilter) for kernel-level blocking — deferred to v0.9.0
- Registry-based mount-point prevention (HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies) — may be explored if IOCTL approach fails

</deferred>
