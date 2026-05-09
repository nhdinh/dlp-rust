---
estimated_steps: 1
estimated_files: 3
skills_used: []
---

# T01: Mount-time blocking implementation

Implement mount-time blocking using DefineDosDeviceW + IOCTL_VOLUME_OFFLINE hybrid approach. Unregistered disks blocked before drive letter assignment. I/O-time blocking preserved as fallback. Add audit event emission. Integration tests.

## Inputs

- `Existing disk enumeration`
- `S01 DeviceController patterns`

## Expected Output

- `disk.rs mount-time block functions`
- `Audit event integration`
- `Unit/integration tests`

## Verification

cargo test --package dlp-agent disk::
