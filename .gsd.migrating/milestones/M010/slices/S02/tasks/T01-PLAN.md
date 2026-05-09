---
estimated_steps: 1
estimated_files: 4
skills_used: []
---

# T01: Per-user device registry implementation

Add owner_user column to device_registry table. Update admin API to filter by owner_user. Modify agent trust tier evaluation to check current user SID first, then fall back to machine-wide entry. Implement most-restrictive tier merge when both per-user and machine-wide entries exist. Update TUI to show owner_user column.

## Inputs

- `Existing device registry`
- `User SID resolution`

## Expected Output

- `DB migration`
- `Admin API filtering`
- `Agent SID-based evaluation`
- `Tier merge logic`
- `TUI column update`

## Verification

cargo test --package dlp-agent usb_enforcer:: && cargo test --package dlp-server admin_api::
