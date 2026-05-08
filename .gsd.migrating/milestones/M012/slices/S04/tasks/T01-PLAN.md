---
estimated_steps: 1
estimated_files: 5
skills_used: []
---

# T01: Notifications, admin TUI, and Chrome connector

Implement UsbBlockResult with per-drive cooldown and toast broadcast. Add managed_origins DDL and ManagedOriginsRepository. Add DeviceList and DeviceTierPicker TUI screens. Add ManagedOriginList TUI screen. Add ConditionAttribute app-identity variants to TUI builder. Implement Chrome pipe server with protobuf frame protocol. Register in HKLM. Handle clipboard scan requests with origin resolution and ABAC evaluation.

## Inputs

- `Existing toast system`
- `TUI patterns`
- `Chrome Content Analysis API`

## Expected Output

- `UsbBlockResult + toast`
- `Device Registry TUI`
- `Managed Origins TUI`
- `App identity conditions builder`
- `Chrome pipe server`
- `Protobuf handling`
- `HKLM registration`

## Verification

cargo test --package dlp-agent chrome:: usb_enforcer:: && cargo test --package dlp-admin-cli
