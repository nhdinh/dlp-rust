# S05: Policy Engine Separation (Phase 11) — UAT

**Milestone:** M015
**Written:** 2026-05-08T05:50:04.404Z

### UAT: Policy Engine

1. Create policy via admin API
2. Evaluate request immediately — verify new policy active
3. Verify cache invalidation fired
4. Wait 5 min — verify background refresh
