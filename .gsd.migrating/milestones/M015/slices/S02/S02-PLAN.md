# S02: Rate Limiting Middleware (Phase 8)

**Goal:** Add brute-force and per-agent rate limiting.
**Demo:** Rate limiting on login, heartbeat, event ingestion, and policy CRUD with 429 responses.

## Must-Haves

- 1. 5/min for /auth/login
- 2. 30/min for heartbeat
- 3. 200/min for audit/events
- 4. 60/min for policy CRUD

## Proof Level

- This slice proves: tested

## Integration Closure

Protects all server endpoints. Required axum 0.7→0.8 upgrade.

## Verification

- 429 responses with Retry-After header.

## Tasks

- [x] **T01: Rate limiting middleware** `est:3h`
  Integrate tower-governor for rate limiting. Configure 5 rate limit configs: strict (5/min IP) for /auth/login, moderate (30/min agent-id) for heartbeat, per_agent (200/min agent-id) for audit/events, policy (60/min IP) for policy CRUD, default (100/min IP) for remaining routes. Upgrade axum 0.7→0.8 if needed. Add tests.
  - Files: `dlp-server/src/rate_limiter.rs`, `dlp-server/src/main.rs`, `dlp-server/Cargo.toml`
  - Verify: cargo test --package dlp-server rate_limiter::

## Files Likely Touched

- dlp-server/src/rate_limiter.rs
- dlp-server/src/main.rs
- dlp-server/Cargo.toml
