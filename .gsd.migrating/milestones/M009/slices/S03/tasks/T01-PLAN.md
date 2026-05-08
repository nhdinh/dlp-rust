---
estimated_steps: 1
estimated_files: 4
skills_used: []
---

# T01: Browser origin clipboard policies implementation

Extend Chrome Content Analysis protobuf schema with origin fields. Add SourceOrigin/DestinationOrigin to ABAC condition variants. Implement origin condition matching in evaluator. Add origin conditions builder to admin TUI. Chrome handler ABAC evaluation with thread-local test isolation.

## Inputs

- `Existing Chrome connector`
- `Managed origins list`
- `ABAC evaluator`

## Expected Output

- `Protobuf schema extension`
- `Origin ABAC conditions`
- `Evaluator origin matching`
- `TUI origin builder`
- `Chrome handler evaluation`

## Verification

cargo test --package dlp-agent chrome:: && cargo test --package dlp-common abac::
