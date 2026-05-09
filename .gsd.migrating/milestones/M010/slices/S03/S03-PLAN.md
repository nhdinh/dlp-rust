# S03: WMI Crate Upgrade (Phase 38.5)

**Goal:** Eliminate raw CoSetProxyBlanket FFI by upgrading to wmi 0.18+.
**Demo:** BitLocker queries use typed wmi 0.18+ interface with no raw CoSetProxyBlanket FFI.

## Must-Haves

- 1. wmi 0.18+ in dependencies
- 2. Raw CoSetProxyBlanket eliminated
- 3. Typed WMI interface for Win32_EncryptableVolume
- 4. All Phase 34 tests pass

## Proof Level

- This slice proves: tested

## Integration Closure

Replaces Phase 34 WMI backend. All tests pass with no behavior change.

## Verification

- None — internal refactor.

## Tasks

- [x] **T01: WMI crate upgrade** `est:3h`
  Upgrade wmi crate to 0.18+. Replace raw CoSetProxyBlanket FFI calls with typed wmi interface. Preserve EncryptionStatus/EncryptionMethod mapping. Ensure all Phase 34 unit tests pass with no behavior change. Update Cargo.toml and lockfile.
  - Files: `dlp-agent/Cargo.toml`, `dlp-agent/src/detection/encryption.rs`, `Cargo.lock`
  - Verify: cargo test --package dlp-agent encryption::

## Files Likely Touched

- dlp-agent/Cargo.toml
- dlp-agent/src/detection/encryption.rs
- Cargo.lock
