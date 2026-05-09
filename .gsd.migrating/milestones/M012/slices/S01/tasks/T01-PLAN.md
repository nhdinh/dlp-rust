---
estimated_steps: 1
estimated_files: 3
skills_used: []
---

# T01: dlp-common foundation types

Create AppIdentity, DeviceIdentity, UsbTrustTier, AppTrustTier, SignatureState types in dlp-common. Extend AbacContext with source/destination application fields. Extend AuditEvent with app identity and device identity fields. Extend Pipe3UiMsg::ClipboardAlert. Verify zero workspace warnings.

## Inputs

- `Existing type system`
- `ABAC schema`

## Expected Output

- `dlp-common endpoint.rs types`
- `abac.rs extensions`
- `audit.rs extensions`
- `IPC message extensions`
- `Zero-warning build`

## Verification

cargo test --workspace && cargo build --workspace
