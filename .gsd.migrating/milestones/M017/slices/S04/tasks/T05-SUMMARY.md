---
id: T05
parent: S04
milestone: M017
key_files:
  - dlp-agent/src/print_enforcer.rs
  - dlp-agent/src/lib.rs
  - dlp-agent/src/service.rs
  - dlp-agent/tests/comprehensive.rs
key_decisions:
  - PrintEnforcer::update_enabled(false→true) at runtime emits a warning and marks enabled=true but does NOT start the watcher (no offline/audit_ctx reference stored); operator must restart service to fully activate — avoids stale-capture risk
  - PrintEnforcer stored as Option<PrintEnforcer> in RunLoopContext (always Some after init) rather than bare PrintEnforcer so shutdown can consume it with if-let without moving the whole context
duration: 
verification_result: passed
completed_at: 2026-05-09T00:07:29.607Z
blocker_discovered: false
---

# T05: Integrated PrintEnforcer into service lifecycle and implemented TC-50/51/52 print interception tests — all 3 passing, zero warnings

**Integrated PrintEnforcer into service lifecycle and implemented TC-50/51/52 print interception tests — all 3 passing, zero warnings**

## What Happened

Created `dlp-agent/src/print_enforcer.rs` with a `PrintEnforcer` struct that wraps `PrintWatcher` and gates it behind the `print_enabled` config flag. The enforcer follows the established enforcer shape (MEM018): `new()` reads `print_enabled` from config, `start()` delegates to `PrintWatcher::start()`, `stop()` delegates to `PrintWatcher::stop()`, and `update_enabled()` handles runtime flag flips. When `print_enabled=None` or `false`, the watcher is never constructed — start/stop are no-ops.

Added `#[cfg(windows)] pub mod print_enforcer;` to `lib.rs`.

In `service.rs`, added `print_enforcer: Option<PrintEnforcer>` to `RunLoopContext`. In `run_loop_init`, constructed the enforcer after the WfpManager block — reads `print_max_pages`, `print_unclassifiable_action`, and `print_enabled` from `agent_config`, calls `enforcer.start()`, and stores `Some(enforcer)` into the context. In `run_loop_shutdown`, added an explicit `if let Some(mut enforcer) = ctx.print_enforcer { enforcer.stop() }` block before the UI-process kill step.

Implemented TC-50..52 in `comprehensive.rs` replacing the `#[ignore]`/`todo!()` stubs. TC-50 verifies `ContentClassifier::classify` returns T2 for internal text and that an `EvaluateRequest` with `Action::PRINT` + T2 maps to a simulated ALLOW response. TC-51 verifies T3 confidential text produces `DenyWithAlert`, and that the resulting `AuditEvent` carries `EventType::Alert`, `Decision::DENY`, and `Action::PRINT`. TC-52 verifies T4 restricted/PII text (credit card number detected) produces `Decision::DENY`, that the job is in spooling state (status=0) enabling cancellation, and that the `AuditEvent` carries `EventType::Block` and correlation_id encoding the job ID.

## Verification

Ran `cargo build --package dlp-agent` — zero warnings, zero errors. Ran `cargo test --test comprehensive print_tc` — all 3 TC tests pass (TC-50, TC-51, TC-52). Ran `cargo test --lib --package dlp-agent print_enforcer` — all 8 enforcer unit tests pass (disabled by default, explicitly disabled, enabled constructs watcher, stop without start is noop, start when disabled is noop, update enabled true-to-false disables, update enabled false-to-true logs warning, update enabled same value is noop).

## Verification Evidence

| # | Command | Exit Code | Verdict | Duration |
|---|---------|-----------|---------|----------|
| 1 | `cargo build --package dlp-agent` | 0 | ✅ pass | 5080ms |
| 2 | `cargo test --test comprehensive print_tc` | 0 | ✅ pass — 3/3 tests passed (TC-50, TC-51, TC-52) | 6090ms |
| 3 | `cargo test --lib --package dlp-agent print_enforcer` | 0 | ✅ pass — 8/8 unit tests passed | 4670ms |

## Deviations

none — plan steps followed in order; no API mismatches encountered

## Known Issues

update_enabled(false→true) at runtime does not start the watcher — operator must restart. This is logged as a warning. The plan noted this as a known limitation of the enforcer shape.

## Files Created/Modified

- `dlp-agent/src/print_enforcer.rs`
- `dlp-agent/src/lib.rs`
- `dlp-agent/src/service.rs`
- `dlp-agent/tests/comprehensive.rs`
