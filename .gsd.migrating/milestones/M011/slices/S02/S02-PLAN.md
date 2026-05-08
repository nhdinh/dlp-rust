# S02: BitLocker Verification (Phase 34)

**Goal:** Agent verifies encryption status of all enumerated fixed disks.
**Demo:** BitLocker status verified via WMI for all enumerated fixed disks. Unencrypted disks flagged in audit.

## Must-Haves

- 1. BitLocker status via WMI Win32_EncryptableVolume
- 2. Unencrypted disks flagged in audit log
- 3. Status available for admin review

## Proof Level

- This slice proves: tested

## Integration Closure

Consumes disk enumeration from S01. Provides encryption status for allowlist decisions.

## Verification

- Audit warnings for unencrypted disks.

## Tasks

- [x] **T01: BitLocker verification implementation** `est:5h`
  Query BitLocker encryption status via WMI Win32_EncryptableVolume for each enumerated fixed disk. Use CoSetProxyBlanket with PktPrivacy (or typed wmi after v0.7.1). Flag unencrypted disks in audit log with warning severity. Do not hard-block; admin decides via allowlist.
  - Files: `dlp-agent/src/detection/encryption.rs`, `dlp-common/src/audit.rs`
  - Verify: cargo test --package dlp-agent encryption::

## Files Likely Touched

- dlp-agent/src/detection/encryption.rs
- dlp-common/src/audit.rs
