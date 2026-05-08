---
estimated_steps: 1
estimated_files: 4
skills_used: []
---

# T01: App identity capture and ABAC enforcement

Implement detection::app_identity module with AUTHENTICODE_CACHE and resolve_app_identity. Integrate into clipboard_monitor.rs with FOREGROUND_SLOT, SetWinEventHook, GetClipboardOwner. Wire through pipe3.rs. Implement agent-side gap closure. Add AppField enum and SourceApplication/DestinationApplication PolicyCondition variants. Implement app_identity_matches helper (fail-closed). Implement UsbEnforcer with check() before offline.evaluate().

## Inputs

- `Win32 process APIs`
- `WinVerifyTrust`
- `ABAC evaluator`

## Expected Output

- `app_identity.rs module`
- `clipboard_monitor integration`
- `pipe3 wire-up`
- `AppField enum`
- `UsbEnforcer struct`
- `Unit tests`

## Verification

cargo test --package dlp-agent app_identity:: usb_enforcer:: && cargo test --package dlp-common abac::
