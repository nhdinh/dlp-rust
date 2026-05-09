---
estimated_steps: 1
estimated_files: 3
skills_used: []
---

# T01: Boolean mode TUI and import/export

Add mode picker row to Policy Create and Edit forms. Implement cycle_mode helper and dispatch handlers. Update POLICY_FIELD_LABELS. Add mode to export JSON. Handle missing mode on import (default to ALL). Write integration tests creating three policies with different modes and evaluating same request.

## Inputs

- `S01 wire format`
- `Existing TUI form patterns`

## Expected Output

- `Mode picker in TUI`
- `Export mode inclusion`
- `Import mode fallback`
- `Integration tests`

## Verification

cargo test --package dlp-admin-cli && cargo test --package dlp-server mode_end_to_end
