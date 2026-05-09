---
estimated_steps: 1
estimated_files: 2
skills_used: []
---

# T01: BitLocker verification implementation

Query BitLocker encryption status via WMI Win32_EncryptableVolume for each enumerated fixed disk. Use CoSetProxyBlanket with PktPrivacy (or typed wmi after v0.7.1). Flag unencrypted disks in audit log with warning severity. Do not hard-block; admin decides via allowlist.

## Inputs

- `WMI Win32_EncryptableVolume`
- `Disk enumeration from S01`

## Expected Output

- `EncryptionChecker module`
- `WMI queries`
- `Audit warning for unencrypted disks`
- `Unit tests`

## Verification

cargo test --package dlp-agent encryption::
