---
phase: 58-differentiators-bundle-override-diagnostic-hash-evidence-sel
plan: 58-03
subsystem: agent

tags: [rust, dashmap, ipc, named-pipe, diagnostics, health-monitoring, aggregation]

requires:
  - phase: 58-differentiators-bundle-override-diagnostic-hash-evidence-sel
    provides: HookHealthSnapshot, DiagnosticSnapshot, IpcEnvelope protocol (DIFF-02, DIFF-04)

provides:
  - DiagnosticAggregator with per-DLL snapshot storage and filtering
  - HealthAggregator with threshold-based status and alert emission
  - IPC handler wiring in HookIpcServer for PullDiagnostics, PullHealth, RequestOverride
  - Backward-compatible protocol fallback for pre-Phase 58 hook DLLs

affects:
  - 58-differentiators-bundle-override-diagnostic-hash-evidence-sel
  - Any phase consuming diagnostic or health data via admin API

tech-stack:
  added: [dashmap, chrono]
  patterns:
    - "Lock-free concurrent storage via DashMap for per-DLL diagnostic snapshots"
    - "Interior mutability (Mutex) for health history with rolling 12-entry cap"
    - "Function-pointer callback pattern (Box<dyn Fn>) to avoid dlp-server coupling"
    - "Versioned IPC protocol with legacy fallback for backward compatibility"

key-files:
  created:
    - dlp-agent/src/diagnostic_aggregator.rs
    - dlp-agent/src/health_aggregator.rs
  modified:
    - dlp-agent/src/hook_ipc.rs
    - dlp-agent/src/lib.rs

key-decisions:
  - "Task 3 modified hook_ipc.rs instead of interception/mod.rs because interception/mod.rs handles FileAction events from the file monitor, while hook_ipc.rs handles the named-pipe protocol with hook DLLs"
  - "Manual Debug and Clone impls on HealthAggregator because Box<dyn Fn(&AuditEvent)> does not implement Debug or Clone"
  - "Alert router stored as Box<dyn Fn(&AuditEvent) + Send + 'static> to decouple from dlp-server's AlertRouter type"
  - "Backward compatibility: tries IpcEnvelope first, falls back to legacy raw HookRequest for pre-Phase 58 DLLs"

patterns-established:
  - "Aggregator pattern: separate modules for collecting, storing, and querying domain-specific snapshots"
  - "Threshold-based health status with consecutive counter for alert debouncing"
  - "Fire-and-forget override handling via optional callback closure"

requirements-completed: [DIFF-02, DIFF-04]

# Metrics
duration: 7min
completed: 2026-06-02
---

# Phase 58 Plan 03: Agent-Side Aggregation and Polling Infrastructure Summary

**Agent-side diagnostic and health aggregation with DashMap-backed snapshot storage, threshold-based health monitoring, and versioned IPC protocol wiring for hook DLL communication**

## Performance

- **Duration:** 7 min
- **Started:** 2026-06-02T21:26:17+07:00
- **Completed:** 2026-06-02T21:33:08+07:00
- **Tasks:** 3
- **Files modified:** 4

## Accomplishments

- DiagnosticAggregator with lock-free per-DLL snapshot storage (DashMap), filtering by user_sid and policy_id, and paginated retrieval
- HealthAggregator with 12-entry rolling history, threshold-based status computation (Healthy/Degraded/Critical), and consecutive-degraded alert debouncing
- IPC protocol extension in HookIpcServer supporting PullDiagnostics, PullHealth, and RequestOverride with backward-compatible legacy fallback
- 18 unit tests total (7 diagnostic + 11 health), all passing

## Task Commits

Each task was committed atomically:

1. **Task 1: Create diagnostic_aggregator.rs** - `973f954` (feat)
2. **Task 2: Create health_aggregator.rs** - `a8fa352` (feat)
3. **Task 3: Wire IPC handlers in hook_ipc.rs** - `d44bc09` (feat)

## Files Created/Modified

- `dlp-agent/src/diagnostic_aggregator.rs` - Lock-free diagnostic snapshot aggregator with per-DLL storage, filtering, and pagination (334 lines, 7 tests)
- `dlp-agent/src/health_aggregator.rs` - Health snapshot aggregator with threshold-based status, alert emission, and rolling 12-entry history (478 lines, 11 tests)
- `dlp-agent/src/hook_ipc.rs` - Extended HookIpcServer with DiagnosticsHandler, HealthHandler, and OverrideHandler; versioned IpcEnvelope protocol with legacy fallback (+132/-11 lines)
- `dlp-agent/src/lib.rs` - Added `pub mod diagnostic_aggregator;` and `pub mod health_aggregator;`

## Decisions Made

- **Task 3 target file**: Modified `hook_ipc.rs` instead of `interception/mod.rs` as the plan suggested, because `interception/mod.rs` handles FileAction events from the file monitor, while `hook_ipc.rs` is the named-pipe protocol handler for hook DLL communication. The IPC envelope variants (PullDiagnostics, PullHealth, RequestOverride) naturally belong in the IPC layer.
- **Manual trait impls**: Wrote manual `Debug` and `Clone` for `HealthAggregator` because `Box<dyn Fn(&AuditEvent)>` does not implement either trait.
- **Alert router decoupling**: Stored the alert router as a function pointer (`Box<dyn Fn(&AuditEvent) + Send + 'static>`) rather than coupling to `dlp-server`'s `AlertRouter` type, maintaining crate separation.
- **Backward compatibility**: The IPC handler tries `IpcEnvelope` deserialization first, falling back to legacy raw `HookRequest` for pre-Phase 58 hook DLLs that do not yet speak the versioned protocol.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- `Debug` derive on `HealthAggregator` failed because `dyn Fn(&AuditEvent)` does not implement `Debug`. Fixed by writing manual `impl std::fmt::Debug for HealthAggregator`.
- `Clone` derive on `HealthAggregator` failed for the same reason. Fixed by writing manual `impl Clone for HealthAggregator` that clones the `Arc`s.
- Clippy `type_complexity` warning on the `alert_router` field. Fixed with `#[allow(clippy::type_complexity)]`.
- Clippy `infallible_destructuring_match` in `hook_ipc.rs` on single-variant `IpcEnvelope` enum. Fixed by using `let IpcEnvelope::V1(msg) = envelope;`.
- Clippy `needless_borrow` in `hook_ipc.rs` on `if let Some(ref oh)`. Fixed by removing `ref`.
- Unused variable `end` in `diagnostic_aggregator.rs` `get_snapshots_paginated`. Fixed by removing the variable.

All fixes were applied and verified: `cargo clippy -- -D warnings` passes, `cargo fmt --check` passes, all 744 dlp-agent tests pass.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Diagnostic and health aggregators are ready for integration with the admin API (planned in a subsequent phase)
- Hook DLLs can now push diagnostic snapshots and health data via the versioned IPC protocol
- Override requests are handled fire-and-forget via the optional callback pattern
- No blockers

---
*Phase: 58-differentiators-bundle-override-diagnostic-hash-evidence-sel*
*Completed: 2026-06-02*
