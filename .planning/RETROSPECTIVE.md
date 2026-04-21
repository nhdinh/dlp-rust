# Retrospective

## Cross-Milestone Trends

### Velocity

| Milestone | Phases | Plans | Days | Phase Velocity |
|-----------|--------|-------|------|---------------|
| v0.1.0 | ~6 | ~8 | ~5 | ~1.2 phases/day |
| v0.2.0 | 9 | 14 | ~4 | ~2.3 phases/day |
| v0.3.0 | 6 | 14 | ~3 | ~2.0 phases/day |
| v0.4.0 | 5 | 9 | ~4 | ~1.3 phases/day |
| v0.5.0 | 4 | 7 | ~2 | ~2.0 phases/day |

### Phase Completion Rate

| Milestone | Phases Done | Phases Planned | Completion |
|-----------|-------------|----------------|------------|
| v0.1.0 | ~6 | ~6 | 100% |
| v0.2.0 | 9 | 14 | 64% |
| v0.3.0 | 6 | 6 | 100% |
| v0.4.0 | 5 | 5 | 100% |
| v0.5.0 | 4 | 4 | 100% |

### What Slowed Us Down

- Phase 04.1 (test suite) was unplanned — inserted mid-sprint after discovering no TC coverage
- Scope creep within phases (e.g., Phase 3 → Phase 3.1 same day)
- Two human verification items for Phase 6 still open (live TOML write-back, zero-warning build)
- v0.3.0: axum 0.7 → 0.8 migration required by tower-governor (Phase 8); unplanned dependency upgrade
- v0.4.0: Phase 19 UAT deferred mid-session (TUI feature not ready); routed to Phase 20 same session

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

---

## Milestone: v0.4.0 — Policy Authoring

**Shipped:** 2026-04-20
**Phases:** 5 (13, 14, 15, 16, 17) | **Plans:** 9 | **Days:** ~4

### What Was Built

- **Conditions builder** — 3-step sequential picker (attribute → operator → value) with typed value pickers and delete for each condition (Phase 13)
- **Policy Create form** — multi-field typed form with inline validation, PolicyFormState struct to avoid borrow-split at submit (Phase 14)
- **Policy Edit + Delete** — load-for-edit via GET, PUT/DELETE with cache invalidation, `d`-key confirmation dialog (Phase 15)
- **Policy List + Simulate** — scrollable sorted table with inline `n`/`e`/`d` actions, EvaluateRequest simulate form calling POST /evaluate (Phase 16)
- **Import + Export** — native Windows file dialogs (rfd 0.14), typed PolicyResponse parsing, conflict diff, POST/PUT abort-on-error (Phase 17)
- **All 8 POLICY-01..08 requirements delivered** — admin no longer touches raw JSON for any policy operation

### What Worked

- **PolicyFormState struct pattern** — holding all form fields + conditions list in one struct eliminated borrow-split issues; established reusable pattern for Phase 15 onward
- **Typed import/export contract** — `From<PolicyResponse> for PolicyPayload` as the conversion boundary was clean; unit-tested roundtrip prevented regressions
- **Skip-nav in non-selectable rows** — `ImportConfirm` header rows excluded from Up/Down navigation; self-documenting pattern for informational-only rows

### What Was Inefficient

- **Phase 16 simulate bug found late** — `Esc` in PolicySimulate cleared the edit buffer; caught in UAT, required commit post-verification
- **Phase 17 routing asymmetry** — GET /admin/policies returned 405 (axum route merging issue from v0.3.0); required a fix commit during UAT

### Patterns Established

- `PolicyFormState` struct for all multi-field TUI forms to avoid borrow-split at submit
- `From<PolicyResponse> for PolicyPayload` as the wire conversion boundary
- Skip-nav: informational rows excluded from Up/Down navigator
- Export as typed `Vec<PolicyResponse>`; import via POST/PUT per-policy with conflict detection

### Key Lessons

1. **Detect axum route asymmetry early** — GET routes on admin paths should be smoke-tested before UAT; the 405 bug was invisible until import tried to resolve conflicts
2. **PolicyFormState is the ratatui multi-field form pattern** — any new form with 4+ fields should use it immediately
3. **UAT is required to catch TUI Esc bugs** — unit tests pass on logic, but navigation regression (Esc clearing unrelated state) only surfaces with interactive testing

### Cost Observations

- Model mix: Sonnet for execution, Opus for planning/research
- Sessions: ~8 sessions across 4 days
- Notable: Phase 13 (conditions builder) required the deepest TUI design work; Phases 14–15 reused the builder cleanly with zero rearchitecting

---

## Milestone: v0.5.0 — Boolean Logic

**Shipped:** 2026-04-21
**Phases:** 4 (18, 19, 20, 21) | **Plans:** 7 | **Days:** ~2

### What Was Built

- **Boolean mode engine** — `PolicyMode` enum (ALL/ANY/NONE), `policies.mode` column + `run_migrations()` idempotent ALTER TABLE, evaluator switch, 15 unit tests, legacy backward-compat path (Phase 18; POLICY-12)
- **Boolean mode TUI** — `POLICY_MODE_ROW` in 9-field form, `cycle_mode()` helper, Enter/Space cyclers, footer advisory for empty-conditions modes, 4 HTTP integration tests via CARGO_TARGET_DIR workaround (Phase 19; POLICY-09)
- **Operator expansion** — `operators_for()` per-attribute lists, evaluator gt/lt/contains, SC-1 stale-operator reset on attribute change, Step 2 picker auto-sizes, 6 regression tests (Phase 20; POLICY-11)
- **In-place condition editing** — `edit_index: Option<usize>`, `condition_to_prefill()` inverse of `build_condition`, `'e'` key handler, index-aware replace-vs-push commit, 4 unit tests (Phase 21; POLICY-10)

### What Worked

- **Server-before-TUI phase split (18 → 19)** — shipping the mode-aware server in Phase 18 first meant Phase 19 TUI work landed against an already-tested contract; no last-minute wire format surprises
- **`operators_for()` as single source of truth** — one function owned valid-operator lists for both the evaluator (Plan 01) and the picker (Plan 02); no duplication, no drift
- **`condition_to_prefill()` as `build_condition` inverse** — writing the inverse function upfront as part of Phase 21 planning meant the 'e' key handler was a mechanical composition; no ad-hoc state restoration needed
- **CARGO_TARGET_DIR workaround** — using `target-test` alternate build dir bypassed the Windows file lock on elevated `dlp-server.exe` without touching process management

### What Was Inefficient

- **Phase 19 UAT deferred mid-session** — UAT was attempted before Phase 19 was verified complete; session had to pivot to Phase 20 context; cost ~20 min re-orientation
- **v0.5.0-ROADMAP.md created as forward-looking doc** — the archive doc was created at milestone start rather than at close; required updating all phase checkboxes and progress table at close

### Patterns Established

- `run_migrations()` idempotent ALTER TABLE pattern for backward-compatible schema additions
- `CARGO_TARGET_DIR=target-test` for integration tests when elevated process locks target dir on Windows
- Phase split at server/TUI seam for features that have both engine and UI components
- `condition_to_prefill()` as the canonical inverse of `build_condition` for any picker pre-fill

### Key Lessons

1. **Don't attempt UAT before verification** — UAT requires a verified, code-reviewed, complete phase; starting UAT on an unverified phase wastes session time on pivot
2. **Archive doc should be written at close, not at start** — forward-looking archive docs require retroactive checkbox updates; write the archive at milestone close from SUMMARY.md files
3. **Server/TUI phase splits pay off** — Phase 18 isolating server changes let Phase 19 work against a stable contract; the pattern should be the default for any feature crossing both layers

### Cost Observations

- Model mix: Sonnet for all phases (execution + planning)
- Sessions: ~6 sessions across 2 days
- Notable: Fastest milestone to date (2 days, 100% completion); boolean mode was a pure hot-path substitution with no schema redesign needed
