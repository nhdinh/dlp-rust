---
estimated_steps: 1
estimated_files: 3
skills_used: []
---

# T01: Boolean mode engine and wire format

Add policies.mode column with NOT NULL DEFAULT 'ALL' via ALTER TABLE migration. Add mode field to PolicyPayload and PolicyResponse. Implement evaluator switch on mode: ALL (every condition matches), ANY (at least one), NONE (no condition matches). Add unit tests for three modes and legacy default path.

## Inputs

- `Existing PolicyStore`
- `SQLite schema`

## Expected Output

- `DB migration`
- `Mode field on wire types`
- `Evaluator mode switch`
- `Unit tests`

## Verification

cargo test --package dlp-server policy_store:: && cargo test --package dlp-common abac::
