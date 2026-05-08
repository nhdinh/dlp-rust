---
estimated_steps: 1
estimated_files: 3
skills_used: []
---

# T03: Agent-side config pipeline wiring

Wire agent-side config pipeline: poll server for enforcement settings, merge into AgentConfig, propagate to DeviceController. Add TOML roundtrip tests.

## Inputs

- `Existing config poll loop`
- `Server API endpoints from T02`

## Expected Output

- `Agent config poll loop updated`
- `DeviceController receives config`
- `TOML tests`

## Verification

cargo test --package dlp-agent config::
