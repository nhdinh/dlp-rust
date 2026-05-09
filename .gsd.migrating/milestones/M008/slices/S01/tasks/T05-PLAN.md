---
estimated_steps: 1
estimated_files: 3
skills_used: []
---

# T05: Admin TUI USB Enforcement Settings screen

Add USB Enforcement Settings screen to dlp-admin-cli TUI. Screen shows retry count, none-serial policy, and save/cancel. Follows existing TUI patterns.

## Inputs

- `Existing TUI screen patterns`
- `T02 admin API endpoints`

## Expected Output

- `Screen::UsbEnforcementSettings`
- `dispatch.rs handlers`
- `render.rs draw function`

## Verification

cargo test --package dlp-admin-cli
