# S01: dlp-common Foundation (Phase 22)

**Goal:** All three enforcement tracks share stable common types.
**Demo:** Shared types (AppIdentity, DeviceIdentity, UsbTrustTier) available across all five crates.

## Must-Haves

- 1. AppIdentity in dlp-common compiles in all crates
- 2. DeviceIdentity and UsbTrustTier serializable
- 3. AbacContext carries app identity fields
- 4. Zero workspace warnings

## Proof Level

- This slice proves: tested

## Integration Closure

Gates all downstream application-aware, browser, and USB work.

## Verification

- None — foundation work.

## Tasks

- [x] **T01: dlp-common foundation types** `est:4h`
  Create AppIdentity, DeviceIdentity, UsbTrustTier, AppTrustTier, SignatureState types in dlp-common. Extend AbacContext with source/destination application fields. Extend AuditEvent with app identity and device identity fields. Extend Pipe3UiMsg::ClipboardAlert. Verify zero workspace warnings.
  - Files: `dlp-common/src/endpoint.rs`, `dlp-common/src/abac.rs`, `dlp-common/src/audit.rs`
  - Verify: cargo test --workspace && cargo build --workspace

## Files Likely Touched

- dlp-common/src/endpoint.rs
- dlp-common/src/abac.rs
- dlp-common/src/audit.rs
