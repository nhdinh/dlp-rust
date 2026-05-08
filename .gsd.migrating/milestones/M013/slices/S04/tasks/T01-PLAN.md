---
estimated_steps: 1
estimated_files: 2
skills_used: []
---

# T01: In-place condition editing

Add edit_index to ConditionsBuilder state. Implement condition_to_prefill helper. Add 'e' key handler in pending-conditions list. Update step-3 commit to replace at original index when editing. Update render title/hint to show edit mode. Add unit tests for edit, save, cancel, and attribute-change reset.

## Inputs

- `Existing ConditionsBuilder`
- `S03 operator filtering`

## Expected Output

- `edit_index state`
- `condition_to_prefill helper`
- `'e' key handler`
- `Index-aware commit`
- `Unit tests`

## Verification

cargo test --package dlp-admin-cli
