---
estimated_steps: 1
estimated_files: 3
skills_used: []
---

# T01: UWP App Identity implementation

Add AUMID resolution to AppIdentity via IShellItem::GetApplicationUserModelId. Extend ABAC evaluator and TUI conditions builder with AUMID support. Add unit tests.

## Inputs

- `Existing AppIdentity struct`
- `Win32 AUMID APIs`

## Expected Output

- `AppIdentity with aumid field`
- `ABAC evaluator AUMID support`
- `TUI conditions builder update`
- `Unit tests`

## Verification

cargo test --package dlp-agent app_identity:: && cargo test --package dlp-common abac::
