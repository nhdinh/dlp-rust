# Retrospective

## Cross-Milestone Trends

### Velocity

| Milestone | Phases | Plans | Days | Phase Velocity |
|-----------|--------|-------|------|---------------|
| v0.1.0 | ~6 | ~8 | ~5 | ~1.2 phases/day |
| v0.2.0 | 9 | 14 | ~4 | ~2.3 phases/day |

### Phase Completion Rate

| Milestone | Phases Done | Phases Planned | Completion |
|-----------|-------------|----------------|------------|
| v0.1.0 | ~6 | ~6 | 100% |
| v0.2.0 | 9 | 14 | 64% |

### What Slowed Us Down

- Phase 04.1 (test suite) was unplanned — inserted mid-sprint after discovering no TC coverage
- Scope creep within phases (e.g., Phase 3 → Phase 3.1 same day)
- Two human verification items for Phase 6 still open (live TOML write-back, zero-warning build)

---

## Milestone: v0.2.0 — Feature Completion

**Shipped:** 2026-04-13
**Phases:** 9 | **Plans:** 14 | **Days:** ~4

### What Was Built

- **Clipboard monitoring fixed end-to-end** — 4 compounding bugs resolved (WorkerGuard, stderr vs tracing, tracing_appender silent swallows, PIPE_NAME_DEFAULT backslash)
- **364+ workspace tests passing** — integration tests migrated to mock axum engine
- **JWT_SECRET production-hardened** — `--dev` flag required for dev-only mode
- **SIEM relay wired** — Splunk HEC + ELK with DB-backed hot-reload config (Phase 3 + 3.1)
- **Alert router wired** — SMTP + webhook with loopback URL validation, fire-and-forget (Phase 4)
- **Agent config polling** — DB-backed global + per-agent override, TOML persistence, poll loop (Phase 6)
- **41 integration tests** — comprehensive.rs 6 mod blocks (32 TCs), admin_api.rs 15 tests, E2E 6 tests
- **Phase 04.1 test suite** — wave-based TDD: unit → server → E2E

### What Worked

- **DB-backed operator config** — hot-reload + TUI-manageable + persistent; Phase 3.1 established the pattern that Phases 4 and 6 reused
- **Wave-based phase execution** — splitting Phase 04.1 into 3 waves (unit/server/E2E) allowed parallel work and clear checkpoints
- **GSD workflow** — plan → execute → verify loop kept phases from drifting
- **Independent executor agents** — parallel Phase 6 execution completed in ~45 min vs sequential estimate

### What Was Inefficient

- **Phase 04.1 was unplanned** — discovered mid-sprint that no TC coverage existed; forced insertion disrupted other work
- **Phase 3 config loading superseded** — Phase 3 delivered env-var SIEM config; Phase 3.1 reimplemented as DB-backed same day
- **Human UAT items accumulated** — Phases 4 and 6 each left 2-3 human verification items; these need live SMTP/webhook/TOML testing
- **Phase 12 had 2/3 plan summaries** — Phase 12-02 committed execution notes inline rather than separate SUMMARY.md

### Patterns Established

- Operator config always in SQLite with hot-reload (not env vars)
- JWT-protected admin endpoints; unauthenticated agent endpoints
- Fire-and-forget background tasks for SIEM relay and alerts
- TOML config files for agent-side persistent config
- Wave-based test suites: unit → integration → E2E
- Decimal phase insertion for urgent mid-sprint work (`04.1`)

### Key Lessons

1. **Establish the operator-config-in-DB pattern on Phase 3** — Phases 4 and 6 followed it without debate; saves re-architecting
2. **Audit for test coverage before planning new features** — Phase 04.1 would have been Phase 3 work if discovered earlier
3. **Human UAT items need scheduling** — leaving them as "pending" means they never get verified; assign a session to run them
4. **Axum `.route()` does not merge across calls** — all HTTP verbs for a path must be in one `.route()` call; discovered the hard way

### Cost Observations

- Model mix: mostly Opus for planning/review, Sonnet for execution
- Sessions: ~10 sessions across 4 days
- Notable: Phase 6 (config push) had a worktree branch mismatch that required manual resolution; executor agents ran cleanly once branch was corrected
