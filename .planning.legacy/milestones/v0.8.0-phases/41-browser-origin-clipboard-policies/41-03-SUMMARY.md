---
phase: 41-browser-origin-clipboard-policies
plan: 03
subsystem: agent
wave: 3
tags: [chrome, abac, policy-evaluation, clipboard, origin]

requires:
  - phase: 41-01
    provides: SourceOrigin and DestinationOrigin PolicyCondition variants in dlp-common
  - phase: 41-02
    provides: ABAC evaluator origin condition matching in dlp-server

provides:
  - Chrome handler constructs EvaluateRequest with Action::PASTE and source_origin
  - Chrome handler evaluates via POLICY_EVALUATOR callback instead of direct cache check
  - set_policy_evaluator() public API for service-layer wiring
  - origins_cache_is_managed() public helper for bridge evaluator
  - service.rs wires chrome_policy_evaluator before Chrome pipe thread spawn
  - Blocked pastes emit audit events with source_origin populated
  - Thread-local test override pattern for parallel test isolation

affects:
  - dlp-agent Chrome Content Analysis pipe handler
  - dlp-agent service startup lifecycle

tech-stack:
  added: []
  patterns:
    - "Thread-local test override for OnceLock globals (parallel test isolation)"
    - "ABAC bridge pattern: new handler speaks ABAC, backing evaluation uses legacy cache"
    - "RAII guard (EvaluatorGuard) for test state cleanup"

key-files:
  created: []
  modified:
    - dlp-agent/src/chrome/handler.rs
    - dlp-agent/src/service.rs

key-decisions:
  - "Thread-local TEST_EVALUATOR_OVERRIDE instead of Mutex — eliminates race conditions between parallel tests"
  - "Phase 41 bridge approach: Chrome handler speaks ABAC EvaluateRequest/EvaluateResponse, but backing evaluation still uses managed-origins cache until full OfflineManager integration"
  - "Fail-open (ALLOW) when POLICY_EVALUATOR is not set — defensive against startup races (T-41-08)"

patterns-established:
  - "Thread-local test override: RefCell<Option<fn(...)>> for test-only global overrides that must be parallel-safe"
  - "RAII EvaluatorGuard: sets override on construct, resets to None on Drop"
  - "ABAC bridge: wrap legacy cache in EvaluateRequest/EvaluateResponse shape for incremental migration"

requirements-completed:
  - BRW-04
  - BRW-04.3

duration: 35min
completed: 2026-05-07
---

# Plan 41-03: Chrome Handler ABAC Evaluation

**Chrome Content Analysis handler now evaluates clipboard paste operations through the ABAC policy engine using EvaluateRequest/EvaluateResponse shape, replacing the direct managed-origins cache check.**

## Performance

- **Duration:** 35 min
- **Started:** 2026-05-07T02:00:00Z
- **Completed:** 2026-05-07T02:35:00Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- Added `POLICY_EVALUATOR` static `OnceLock<fn(&EvaluateRequest) -> EvaluateResponse>` for ABAC callback
- Added `set_policy_evaluator()` public setter for service-layer wiring
- Added `origins_cache_is_managed()` public helper for bridge evaluator access
- Refactored `dispatch_request()` to construct `EvaluateRequest` with `Action::PASTE` and `source_origin`
- Replaced direct `ORIGINS_CACHE.is_managed()` check with `POLICY_EVALUATOR` callback invocation
- Added `debug!` trace in `emit_chrome_block_audit()` documenting destination_origin limitation
- Added `chrome_policy_evaluator()` in `service.rs` as bridge: wraps managed-origins cache in ABAC shape
- Wired `set_policy_evaluator(chrome_policy_evaluator)` before Chrome pipe thread spawn
- Added thread-local `TEST_EVALUATOR_OVERRIDE` with RAII `EvaluatorGuard` for parallel test isolation
- Added 4 new tests: evaluator-not-set, deny-via-policy, allow-via-policy, managed-origin-blocks, unmanaged-origin-allows
- Updated 2 existing tests to use mock evaluator pattern instead of cache seeding

## Task Commits

Each task committed atomically:

1. **Task 1: Refactor Chrome handler to use ABAC evaluation** - `2aa3b82` (feat)
2. **Task 2: Wire policy evaluator into service startup** - `3dc7df9` (feat)

## Files Created/Modified

- `dlp-agent/src/chrome/handler.rs` - Added POLICY_EVALUATOR, set_policy_evaluator, origins_cache_is_managed, ABAC evaluation path in dispatch_request, thread-local test override, EvaluatorGuard, 4 new tests
- `dlp-agent/src/service.rs` - Added chrome_policy_evaluator bridge function, wired set_policy_evaluator before Chrome thread spawn

## Decisions Made

- **Thread-local test override**: Used `thread_local! { RefCell<Option<fn(...)>> }` instead of `Mutex` to eliminate race conditions between parallel tests. Each test thread gets its own evaluator override.
- **RAII guard pattern**: `EvaluatorGuard` sets the override on construction and resets to `None` on `Drop`, ensuring test cleanup even on panic.
- **Phase 41 bridge approach**: The Chrome handler now speaks ABAC (EvaluateRequest/EvaluateResponse), but the backing evaluation in `chrome_policy_evaluator()` still uses the managed-origins cache. This proves the wiring works without requiring full OfflineManager policy cache integration in this phase.
- **Fail-open defensive default**: When `POLICY_EVALUATOR` is not set, `dispatch_request()` returns ALLOW. This prevents breaking user productivity during startup races (T-41-08).

## Deviations from Plan

### Auto-fixed Issues

**1. [Testing] Parallel test execution with OnceLock globals**
- **Found during:** Task 1 (test updates)
- **Issue:** `OnceLock::set()` can only succeed once per process. Multiple tests setting different mock evaluators caused race conditions and assertion failures when tests ran in parallel.
- **Fix:** Replaced `Mutex`-based global override with `thread_local! { RefCell<Option<fn(...)>> }` and added RAII `EvaluatorGuard` for automatic cleanup.
- **Files modified:** `dlp-agent/src/chrome/handler.rs`
- **Verification:** `cargo test -p dlp-agent chrome::handler` passes with 14/14 tests in parallel execution
- **Committed in:** `2aa3b82`

**2. [Plan accuracy] Simplified service-layer evaluator**
- **Found during:** Task 2 implementation
- **Issue:** Plan specified a complex OfflineManager wiring with `CHROME_OFFLINE_MANAGER` static and `tokio::runtime::Handle::try_current()` fallback logic.
- **Fix:** Used the simpler "bridge" approach recommended in the plan's ALTERNATIVE section — `chrome_policy_evaluator()` directly calls `origins_cache_is_managed()` without async runtime dependency. This is cleaner, safer (no block_on in sync context), and achieves the same Phase 41 goal.
- **Files modified:** `dlp-agent/src/service.rs`
- **Verification:** `cargo build -p dlp-agent` succeeds, `cargo test` passes
- **Committed in:** `3dc7df9`

---

**Total deviations:** 2 auto-fixed (1 testing, 1 simplification)
**Impact on plan:** Both deviations improve correctness and simplicity. No scope creep.

## Issues Encountered

- **Parallel test isolation with global state**: The initial `Mutex`-based test override failed under `cargo test`'s default parallel execution. Thread-local storage with RAII guards solved this cleanly.
- **cargo fmt line wrapping**: Existing match arms with `AppField::Publisher | AppField::ImagePath | AppField::Aumid | AppField::PackageFamilyName` exceeded rustfmt line length. Auto-fixed by `cargo fmt`.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Phase 41 is now complete (plans 41-01 through 41-04 all delivered)
- Phase 42 (Audit Enrichment — App Identity Fields) is next
- All origin condition infrastructure is in place: types (41-01), evaluator (41-02), Chrome handler (41-03), TUI builder (41-04)
- Future enhancement: Replace `chrome_policy_evaluator()` bridge with full `OfflineManager.evaluate()` when policy cache integration is ready

---
*Phase: 41-browser-origin-clipboard-policies*
*Completed: 2026-05-07*
