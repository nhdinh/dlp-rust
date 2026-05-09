# S03: App Identity + ABAC Enforcement (Phases 25-26)

**Goal:** Clipboard and file operations blocked or allowed based on application identity and USB device trust tier.
**Demo:** Clipboard operations carry source and destination process identity with Authenticode verification. ABAC evaluator honors app-identity and USB trust-tier conditions.

## Must-Haves

- 1. App identity resolved via QueryFullProcessImageNameW + WinVerifyTrust
- 2. Authenticode cache in spawn_blocking
- 3. ABAC evaluates app-identity conditions
- 4. USB blocked/read_only/full_access enforced

## Proof Level

- This slice proves: tested

## Integration Closure

Consumes S01 types and S02 registry. Provides enforcement for S04 notifications.

## Verification

- Clipboard and USB block audit events with identity.

## Tasks

- [x] **T01: App identity capture and ABAC enforcement** `est:8h`
  Implement detection::app_identity module with AUTHENTICODE_CACHE and resolve_app_identity. Integrate into clipboard_monitor.rs with FOREGROUND_SLOT, SetWinEventHook, GetClipboardOwner. Wire through pipe3.rs. Implement agent-side gap closure. Add AppField enum and SourceApplication/DestinationApplication PolicyCondition variants. Implement app_identity_matches helper (fail-closed). Implement UsbEnforcer with check() before offline.evaluate().
  - Files: `dlp-agent/src/detection/app_identity.rs`, `dlp-user-ui/src/clipboard_monitor.rs`, `dlp-common/src/abac.rs`, `dlp-agent/src/usb_enforcer.rs`
  - Verify: cargo test --package dlp-agent app_identity:: usb_enforcer:: && cargo test --package dlp-common abac::

## Files Likely Touched

- dlp-agent/src/detection/app_identity.rs
- dlp-user-ui/src/clipboard_monitor.rs
- dlp-common/src/abac.rs
- dlp-agent/src/usb_enforcer.rs
