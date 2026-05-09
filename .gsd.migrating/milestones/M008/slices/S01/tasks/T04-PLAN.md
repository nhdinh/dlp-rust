---
estimated_steps: 1
estimated_files: 2
skills_used: []
---

# T04: Enforcement behavior: retry, failure mode, none-serial policy

Implement enforcement behavior: retry logic for CM_Disable_DevNode, hard failure mode when both PnP disable and DACL deny-all fail, (none) serial fallback policy. Update unit tests.

## Inputs

- `T01 path matching`
- `T03 config pipeline`
- `Win32 CM API docs`

## Expected Output

- `DeviceController retry logic`
- `Hard error propagation`
- `None-serial fallback`

## Verification

cargo test --package dlp-agent device_controller:: usb_enforcer::
