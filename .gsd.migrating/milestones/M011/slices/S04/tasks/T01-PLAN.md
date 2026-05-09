---
estimated_steps: 1
estimated_files: 3
skills_used: []
---

# T01: Disk enforcement implementation

Implement pre-ABAC volume-level I/O blocking in run_event_loop. Block FileAction::Create/Write/Move for unregistered fixed disks. Handle WM_DEVICECHANGE DBT_DEVICEARRIVAL/DBT_DEVICEREMOVECOMPLETE for GUID_DEVINTERFACE_DISK. Evaluate newly arrived disks against allowlist. Emit audit events with disk identity.

## Inputs

- `Disk allowlist from S03`
- `WM_DEVICECHANGE patterns`

## Expected Output

- `DiskEnforcer module`
- `I/O blocking in run_event_loop`
- `WM_DEVICECHANGE handling`
- `Audit event emission`

## Verification

cargo test --package dlp-agent disk_enforcer::
