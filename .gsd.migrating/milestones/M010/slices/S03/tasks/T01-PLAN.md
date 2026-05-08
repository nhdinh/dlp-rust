---
estimated_steps: 1
estimated_files: 3
skills_used: []
---

# T01: WMI crate upgrade

Upgrade wmi crate to 0.18+. Replace raw CoSetProxyBlanket FFI calls with typed wmi interface. Preserve EncryptionStatus/EncryptionMethod mapping. Ensure all Phase 34 unit tests pass with no behavior change. Update Cargo.toml and lockfile.

## Inputs

- `Existing CoSetProxyBlanket FFI`
- `Win32_EncryptableVolume schema`

## Expected Output

- `wmi 0.18+ dependency`
- `Typed WMI queries`
- `Removed FFI code`
- `Passing tests`

## Verification

cargo test --package dlp-agent encryption::
