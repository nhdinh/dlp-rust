---
estimated_steps: 1
estimated_files: 2
skills_used: []
---

# T01: Policy list and simulate implementation

Implement PolicyList with column widths, n-key binding, inline hints. Sort ascending by priority. Add PolicySimulate screen with 10-row form. Implement submit handler posting to POST /evaluate. Render SimulateOutcome with matched policy ID, decision, reason. Fix Esc-key bug preserving edit buffer.

## Inputs

- `Existing TUI list patterns`
- `Evaluate endpoint`

## Expected Output

- `PolicyList screen`
- `PolicySimulate screen`
- `Simulate submit handler`
- `Esc bug fix`
- `Unit tests`

## Verification

cargo test --package dlp-admin-cli
