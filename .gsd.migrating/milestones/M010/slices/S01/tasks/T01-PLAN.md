---
estimated_steps: 1
estimated_files: 3
skills_used: []
---

# T01: AGENT-UNKNOWN remediation

Add AGENT-UNKNOWN sentinel to all audit emission paths. Guarantee non-null app identity fields in schema. Add remediation documentation. Implement metric counter per interception path. Server-side validation rejects events with missing identity fields.

## Inputs

- `Existing audit pipeline`
- `App identity fields from v0.8.0`

## Expected Output

- `AGENT-UNKNOWN sentinel`
- `Schema guarantee`
- `Remediation docs`
- `Metric counters`

## Verification

cargo test --workspace audit::
