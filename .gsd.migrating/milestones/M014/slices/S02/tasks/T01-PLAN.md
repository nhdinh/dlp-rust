---
estimated_steps: 1
estimated_files: 3
skills_used: []
---

# T01: Policy create implementation

Add Screen::PolicyCreate, ACTION_OPTIONS, and form_snapshot. Implement handle_policy_create and action_submit_policy. Fix CallerScreen Esc bug. Implement draw_policy_create render function. Add unit tests for form validation and submit.

## Inputs

- `S01 conditions builder`
- `Existing TUI form patterns`

## Expected Output

- `PolicyCreate screen`
- `Submit handler`
- `Render function`
- `Unit tests`

## Verification

cargo test --package dlp-admin-cli
