---
phase: 01-fix-integration-tests
plan: PLAN
subsystem: testing
tags: [cargo, axum, integration-tests, abac, dlp-agent]

# Dependency graph
requires:
  - phase: 0
    provides: AgentConfig.server_url field (surfaced latent errors in comprehensive.rs)
provides:
  - Self-contained mock policy engine for agent integration tests
  - Workspace compiles and tests run clean (364/364 passing)
affects: [02-require-jwt-secret-in-production, 03-wire-siem-connector, 04-wire-alert-router]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Inline mock axum server for agent-side integration tests (no dlp-server dev-dep)"

key-files:
  created: []
  modified:
    - dlp-agent/tests/integration.rs
    - dlp-agent/tests/comprehensive.rs
    - dlp-agent/Cargo.toml

key-decisions:
  - "Replace start_real_engine() with start_policy_engine() mock — inline 3-policy ABAC evaluator using only axum + dlp-common types"
  - "Drop dlp-server from dlp-agent [dev-dependencies] — agent tests no longer need server crate"

patterns-established:
  - "Agent integration tests: spawn mock axum server per test instead of real dlp-server wiring"

requirements-completed: [R-06]

# Metrics
duration: ~7h (two-commit closure)
completed: 2026-04-10
---

# Phase 1: Fix Integration Tests Summary

**Workspace now compiles cleanly with 364/364 tests passing — agent integration tests use a self-contained mock axum engine instead of removed dlp_server modules.**

## Performance

- **Duration:** Two-commit closure over ~7 hours (2026-04-10 10:23 → 17:36 +0700)
- **Started:** 2026-04-10T10:23:55+07:00
- **Completed:** 2026-04-10T17:36:09+07:00
- **Tasks:** 2 commits (original fix + gap closure)
- **Files modified:** 3 source files + 2 planning files

## Accomplishments

- Replaced `start_real_engine()` with `start_policy_engine()` — a self-contained mock axum server with inline ABAC evaluation matching the 3 standard policies (T4 WRITE -> DENY, T3/T4 COPY -> DENY, T2 READ -> AllowWithLog).
- Dropped `dlp-server` from `dlp-agent/Cargo.toml [dev-dependencies]` — no longer needed.
- Closed latent Phase 0 drift: added `server_url: None` to two `AgentConfig { ... }` struct literals in `tests/comprehensive.rs` (E0063 missing field).
- Removed unused `extract::Json` import from `start_policy_engine()` in `tests/integration.rs`.

## Task Commits

1. **Original fix** — `8c62fec` (fix: replace broken integration tests with self-contained mock engine)
   - `dlp-agent/tests/integration.rs` rewritten (127 lines touched, net -10)
   - `dlp-agent/Cargo.toml` removed dlp-server dev-dep
2. **Gap closure after re-verification** — `5d60f6a` (fix(phase-1): close gap in comprehensive.rs after re-verification)
   - `dlp-agent/tests/comprehensive.rs:354,369` — added `server_url: None` to AgentConfig literals
   - `dlp-agent/tests/integration.rs:328` — removed unused `extract::Json` short-form import
   - PLAN.md + VERIFICATION.md updated with addendum

## Files Created/Modified

- `dlp-agent/tests/integration.rs` — `start_real_engine()` removed; `start_policy_engine()` inline mock added
- `dlp-agent/tests/comprehensive.rs` — `AgentConfig` literals updated to include `server_url: None`
- `dlp-agent/Cargo.toml` — `dlp-server` removed from `[dev-dependencies]`

## Decisions Made

- **Mock over real engine for agent tests.** The agent crate should not depend on the server crate in its dev tree — tests just need a policy endpoint that obeys the ABAC contract. Inline axum mock keeps the coupling one-way and makes the test surface deterministic.
- **Inline the 3-policy matrix rather than loading a file.** The standard `ABAC_POLICIES.md` rules are short enough to hardcode, and the mock stays readable.

## Deviations from Plan

The original PLAN.md scoped the work narrowly to `tests/integration.rs`. Re-running `cargo test --workspace` after commit `8c62fec` surfaced two additional compile errors Phase 0 had silently introduced in `tests/comprehensive.rs` (missing `server_url` field on `AgentConfig`) plus one dead import. The PLAN.md "Addendum — Gap closure after re-verification (2026-04-10)" documents the expansion; `5d60f6a` closed the gap. No scope creep — purely compilation unblocking to satisfy the original UAT.

## Issues Encountered

- **Phase 0 left latent drift.** `AgentConfig` gained a new field in Phase 0 but `tests/comprehensive.rs` was not updated. There was no CI to catch it, and `cargo test --workspace` was not run locally after Phase 0. Two commits were needed instead of one because the second batch of errors only surfaced during Phase 1's own re-verification. A pre-push `cargo check --workspace --tests` hook would prevent this class of drift — surfaced as an observation in VERIFICATION.md for a future phase.

## Next Phase Readiness

- Workspace compiles clean (`cargo check --workspace --tests` — verified at phase close).
- Test matrix: 364 passing across 15 binaries + doc tests (per VERIFICATION.md).
- Phase 2 (Require JWT_SECRET in production) is unblocked — no test-suite drag carried forward.

---
*Phase: 01-fix-integration-tests*
*Completed: 2026-04-10*
