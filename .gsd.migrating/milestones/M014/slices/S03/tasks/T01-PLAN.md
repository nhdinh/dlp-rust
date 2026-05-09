---
estimated_steps: 1
estimated_files: 2
skills_used: []
---

# T01: Policy edit and delete implementation

Add row constants and PolicyEdit state. Implement load, edit, and delete handlers. Add delete confirmation prompt. Implement draw_policy_edit render function. Wire into policy list navigation. Add unit tests for edit round-trip and delete confirmation.

## Inputs

- `S02 PolicyCreate form`
- `Existing policy list screen`

## Expected Output

- `PolicyEdit screen`
- `Load handler`
- `Delete confirmation`
- `Render function`
- `Unit tests`

## Verification

cargo test --package dlp-admin-cli
