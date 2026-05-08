# S02: Rate Limiting Middleware (Phase 8) — UAT

**Milestone:** M015
**Written:** 2026-05-08T05:50:04.402Z

### UAT: Rate Limiting

1. Rapid-fire login attempts — verify 429 with Retry-After
2. Rapid heartbeats — verify throttled per agent-id
3. Verify policy CRUD rate limited per IP
