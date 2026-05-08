---
estimated_steps: 1
estimated_files: 2
skills_used: []
---

# T01: Disk enumeration implementation

Implement SetupDi-based disk enumeration at install time or first startup. Capture device instance ID, bus type, model, and drive letter. Distinguish USB-bridged SATA/NVMe from genuine internal disks via IOCTL_STORAGE_QUERY_PROPERTY or PnP tree walk. Emit audit events with full disk identity.

## Inputs

- `SetupDi API`
- `IOCTL_STORAGE_QUERY_PROPERTY`

## Expected Output

- `Disk enumerator module`
- `SetupDi enumeration`
- `Bus type detection`
- `Audit event emission`

## Verification

cargo test --package dlp-agent disk::
