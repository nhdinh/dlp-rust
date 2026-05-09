---
estimated_steps: 1
estimated_files: 3
skills_used: []
---

# T01: Conditions builder implementation

Create ConditionAttribute enum, CallerScreen, PolicyFormState, and Screen::ConditionsBuilder. Implement dispatch handler with 3-step picker: step 1 (attribute), step 2 (operator), step 3 (typed value). Implement render function with modal overlay. Add pending-conditions list with delete binding. Add unit tests.

## Inputs

- `Existing TUI patterns`
- `ABAC condition schema`

## Expected Output

- `Conditions builder types`
- `Dispatch handler`
- `Render function`
- `Unit tests`

## Verification

cargo test --package dlp-admin-cli
