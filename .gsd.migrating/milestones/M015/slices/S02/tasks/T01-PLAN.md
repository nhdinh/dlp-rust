---
estimated_steps: 1
estimated_files: 3
skills_used: []
---

# T01: Rate limiting middleware

Integrate tower-governor for rate limiting. Configure 5 rate limit configs: strict (5/min IP) for /auth/login, moderate (30/min agent-id) for heartbeat, per_agent (200/min agent-id) for audit/events, policy (60/min IP) for policy CRUD, default (100/min IP) for remaining routes. Upgrade axum 0.7→0.8 if needed. Add tests.

## Inputs

- `tower-governor crate`
- `axum routing`

## Expected Output

- `Rate limiter module`
- `5 rate configs`
- `Route-specific application`
- `Integration tests`

## Verification

cargo test --package dlp-server rate_limiter::
