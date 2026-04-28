---
phase: 30-automated-uat-infrastructure
plan: 10
subsystem: infra
tags: [github-actions, ci, nightly, release-build, smoke-test]

requires:
  - phase: 30-01
    provides: dlp-e2e test harness
  - phase: 30-05
    provides: Agent TOML write-back integration test
  - phase: 30-06
    provides: Hot-reload config tests
  - phase: 30-07
    provides: USB write-protection unit tests
provides:
  - Scheduled nightly workflow for release-mode builds
  - Release binary smoke tests (health check)
  - Separate target-release directory to avoid debug/release conflicts
affects:
  - CI pipeline
  - Release verification

tech-stack:
  added: []
  patterns:
    - "Scheduled GitHub Actions workflow (cron trigger)"
    - "CARGO_TARGET_DIR override for separate release artifact directory"

key-files:
  created:
    - .github/workflows/nightly.yml
  modified: []

key-decisions:
  - "Use target-release directory to avoid conflicting with debug builds in CI cache"
  - "Scheduled at 2 AM UTC to minimize impact on developer workflows"
  - "Include workflow_dispatch for manual trigger flexibility"

patterns-established:
  - "Nightly release build pattern: build -> clippy -> test -> binary verification -> health check"

requirements-completed: []

duration: 5min
completed: 2026-04-29
---

# Phase 30: Plan 10 — Nightly Release Build Workflow

**Scheduled GitHub Actions workflow that builds the entire workspace in release mode, runs all tests against release binaries, and performs a health-check smoke test on the release dlp-server binary.**

## Performance

- **Duration:** 5 min
- **Started:** 2026-04-29T00:05:00+07:00
- **Completed:** 2026-04-29T00:06:00+07:00
- **Tasks:** 1
- **Files modified:** 1

## Accomplishments

- Created nightly.yml with cron schedule (2 AM UTC) and workflow_dispatch
- Release build with CARGO_TARGET_DIR=target-release
- Smoke test verifies release binaries exist and dlp-server responds to health check

## Task Commits

1. **Task 1: Create nightly.yml scheduled workflow** — `b850b01` (ci)

## Files Created/Modified

- `.github/workflows/nightly.yml` — New scheduled workflow with 6 steps

## Decisions Made

- target-release directory keeps release artifacts separate from debug builds
- PowerShell smoke test for Windows-native binary verification

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered

None.

## Next Phase Readiness

- Release verification automated; no manual UAT needed for release builds

---
*Phase: 30-automated-uat-infrastructure*
*Completed: 2026-04-29*
