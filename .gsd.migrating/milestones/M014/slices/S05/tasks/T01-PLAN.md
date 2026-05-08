---
estimated_steps: 1
estimated_files: 3
skills_used: []
---

# T01: Import and export implementation

Add export action fetching live policy set and writing pretty-printed JSON. Add ImportConfirm screen. Compute conflict diff against current server state. Implement import execution with abort-on-first-failure (POST new IDs, PUT existing). Add rfd file dialogs. Add unit tests for import conflict detection and round-trip. Fix GET path bug (commit 7dda578).

## Inputs

- `S04 policy list`
- `PolicyResponse/PolicyPayload types`
- `rfd crate`

## Expected Output

- `Export action`
- `ImportConfirm screen`
- `Conflict diff`
- `Import execution`
- `rfd dialogs`
- `Unit tests`

## Verification

cargo test --package dlp-admin-cli
