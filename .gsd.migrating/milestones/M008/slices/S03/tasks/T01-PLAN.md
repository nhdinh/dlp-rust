---
estimated_steps: 1
estimated_files: 3
skills_used: []
---

# T01: Grace period implementation

Implement configurable grace period for new disk arrivals. Add disk_grace_period_seconds to agent-config.toml with validation. During grace period: allow reads, block writes with toast notification. On expiry: escalate to S02 mount-time block. Timer state machine with per-disk tracking.

## Inputs

- `S02 mount-time blocking`
- `Existing toast notification system`
- `Agent config poll loop`

## Expected Output

- `AgentConfig grace period field`
- `Timer state machine`
- `Write-block during grace`
- `Toast notification on write attempt`

## Verification

cargo test --package dlp-agent disk_enforcer::
