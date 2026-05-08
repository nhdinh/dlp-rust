---
estimated_steps: 1
estimated_files: 3
skills_used: []
---

# T01: Drag-and-drop enforcement implementation

Implement WH_GETMESSAGE hook for WM_DROPFILES interception. Resolve source application identity (Win32 and UWP via S01). Evaluate ABAC policy before drop completes. Wire toast notification and audit event on block. Service lifecycle integration.

## Inputs

- `S01 AppIdentity with AUMID`
- `Existing toast system`
- `ABAC evaluator`

## Expected Output

- `drag_drop.rs module`
- `WH_GETMESSAGE hook`
- `ABAC evaluation`
- `Toast and audit integration`
- `Service wiring`

## Verification

cargo test --package dlp-agent drag_drop::
