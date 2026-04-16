# Retrospective

## Cross-Milestone Trends

### Velocity

| Milestone | Phases | Plans | Days | Phase Velocity |
|-----------|--------|-------|------|---------------|
| v0.1.0 | ~6 | ~8 | ~5 | ~1.2 phases/day |
| v0.2.0 | 9 | 14 | ~4 | ~2.3 phases/day |
| v0.3.0 | 6 | 14 | ~3 | ~2.0 phases/day |

### Phase Completion Rate

| Milestone | Phases Done | Phases Planned | Completion |
|-----------|-------------|----------------|------------|
| v0.1.0 | ~6 | ~6 | 100% |
| v0.2.0 | 9 | 14 | 64% |
| v0.3.0 | 6 | 6 | 100% |

### What Slowed Us Down

- Phase 04.1 (test suite) was unplanned — inserted mid-sprint after discovering no TC coverage
- Scope creep within phases (e.g., Phase 3 → Phase 3.1 same day)
- Two human verification items for Phase 6 still open (live TOML write-back, zero-warning build)
- v0.3.0: axum 0.7 → 0.8 migration required by tower-governor (Phase 8); unplanned dependency upgrade

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

---

## Milestone: v0.3.0 — Operational Hardening

**Shipped:** 2026-04-16
**Phases:** 6 (7, 8, 9, 10, 11, 99) | **Plans:** 14 | **Days:** ~3

### What Was Built

- **AD LDAP integration** — real ABAC group membership + device trust from Active Directory; channel-based async AdClient, machine Kerberos TGT bind, fail-open (Phase 7)
- **Rate limiting** — `tower-governor` 5 configs (5/min login, 200/min events, 60/min policy CRUD); axum 0.7 → 0.8 upgrade (Phase 8)
- **Admin audit logging** — policy CRUD + password changes to `audit_events` with `EventType::AdminAction`; 4 integration tests (Phase 9)
- **SQLite connection pool** — `r2d2`/`r2d2_sqlite` replacing `Mutex<Connection>`; 220 workspace tests pass (Phase 10)
- **Policy Engine Separation** — `PolicyStore` in-memory cache, sync evaluate(), cache invalidation + 5-min background refresh, 23 unit tests (Phase 11)
- **Repository + Unit of Work** — 49 raw SQL call sites → 10 typed Repository structs; all writes via `UnitOfWork<'conn>` RAII; -109 net lines in admin_api.rs (Phase 99)

### What Worked

- **All 5 deferred requirements closed** — v0.3.0 had a clear pre-defined scope (R-03/05/07/09/10); no scope debates mid-sprint
- **Wave-based execution for Phase 11** — 4-wave plan (types → wiring → endpoint → tests) allowed incremental verification at each wave
- **Phase 99 ran concurrently** — DB refactor completed alongside the main 5 phases with no coordination overhead; clean separation from feature work
- **GSD executor agents** — parallel plan execution completed phases in hours vs days; Plan 02 (23 call sites) done in one session

### What Was Inefficient

- **axum 0.7 → 0.8 forced upgrade** — `tower-governor` required axum 0.8; discovered mid-Phase 8 execution; ~1 hour unplanned migration
- **PolicyStore `:memory:` SQLite isolation bug** — two tests used `:memory:` but pool connections are isolated; required NamedTempFile fix post-milestone (commit 492d966)
- **ROADMAP.md milestone closure incomplete** — v0.3.0 tag was created but MILESTONES.md entry, REQUIREMENTS.md deletion, and RETROSPECTIVE.md update were missed; required cleanup session

### Patterns Established

- Repository structs as the canonical DB access layer; raw SQL confined to `db/repositories/`
- `UnitOfWork<'conn>` for all writes; `&Pool` for reads — enforced at compile time via type system
- `PolicyStore` as the in-process policy cache; invalidate-on-write + background refresh as the invalidation strategy
- `parking_lot::RwLock` preferred over `std::sync::RwLock` for uncontended read performance

### Key Lessons

1. **Tag creation ≠ milestone closure** — git tag + archive commit are necessary but not sufficient; MILESTONES.md, REQUIREMENTS.md deletion, and RETROSPECTIVE.md are part of the close
2. **NamedTempFile for SQLite pool tests** — `:memory:` is per-connection; any test that initializes via one connection and reads from another must use a file-backed DB
3. **Phase 99 as concurrent refactor** — large refactors can run in parallel with feature phases without conflict if they operate on orthogonal layers (DB layer vs handler logic)
4. **Axum version pinning** — check middleware crate compatibility with axum version before planning; `tower-governor` had a hard axum 0.8 requirement

### Cost Observations

- Model mix: Sonnet for execution, Opus for planning/research
- Sessions: ~6 sessions across 3 days
- Notable: Phase 7 (AD integration) required the most planning depth (CONTEXT.md + RESEARCH.md); phases 8–10 were largely mechanical
