---
estimated_steps: 36
estimated_files: 4
skills_used: []
---

# T05: Integrate print enforcer into service and implement UAT tests

Build the `PrintEnforcer` wrapper, wire it into the agent service lifecycle, add audit event emission, and implement the TC-50..52 print interception tests.

**Steps:**
1. Create `dlp-agent/src/print_enforcer.rs`:
   - `PrintEnforcer` struct wrapping `PrintWatcher`.
   - `new(config, offline, audit_ctx, runtime_handle) -> Self` — reads `print_enabled` from config; if disabled, watcher is not started.
   - `start(&mut self) -> Result<()>` — delegates to `PrintWatcher::start()`.
   - `stop(&mut self)` — delegates to `PrintWatcher::stop()`.
   - `update_config(&mut self, new_config: &AgentConfig)` — if `print_enabled` changes, stop/start watcher accordingly.
2. Add `#[cfg(windows)] pub mod print_enforcer;` to `dlp-agent/src/lib.rs`.
3. In `service.rs`:
   - In `run_loop_init`: construct `PrintEnforcer` when `print_enabled.unwrap_or(false)`, store in local variable.
   - Add `print_enforcer: Option<crate::print_enforcer::PrintEnforcer>` to `RunLoopContext`.
   - Call `start()` on the enforcer before returning context.
   - In `run_loop_shutdown`: if `ctx.print_enforcer` is `Some`, call `stop()`.
4. In `service.rs` `apply_payload_to_config`: if print fields changed, update config; the watcher thread reads config dynamically via `with_config` on each iteration, so no explicit restart needed.
5. Audit integration: ensure `print_watcher.rs` emits `AuditEvent` with:
   - `event_type: EventType::Block` for cancelled jobs
   - `event_type: EventType::Alert` for `SetJob` failures or `DenyWithAlert` decisions
   - `action_attempted: Action::PRINT`
   - `resource_path` = document name
   - Enrich with printer name and job ID via `AuditEvent` extension methods (or add new optional fields if needed).
6. Implement TC-50..52 in `dlp-agent/tests/comprehensive.rs`:
   - TC-50: Create mock `JobInfo` with internal document name, mock XPS text classified as T1/T2, assert `EvaluateRequest` with `Action::PRINT` returns ALLOW.
   - TC-51: Mock XPS with confidential (T3) text, assert decision is `DenyWithAlert` (require_auth), assert Alert audit event would be emitted.
   - TC-52: Mock XPS with restricted (T4) text, assert decision is `DENY`, assert Block audit event would be emitted, assert `cancel_job` would be called.
   - Remove `#[ignore = "print spooler interception not yet implemented"]` from all three tests.
7. Verify `cargo test --test comprehensive print_tc` passes.

**Skills used:** rust-engineer, test

**Failure Modes:**
- `PrintEnforcer::start()` called when `print_enabled=false` → no-op, returns Ok.
- `run_loop_shutdown` with `None` enforcer → no-op.
- TC tests fail due to missing `Action::PRINT` → ensure T01 is complete.

**Negative Tests:**
- `PrintEnforcer::new` with `print_enabled=false` → `start()` is no-op.
- `PrintEnforcer::stop()` without prior `start()` → no-op, no panic.
- Config change `print_enabled=true→false` while watcher running → watcher stops on next config read (or explicit stop in T05 integration).

## Inputs

- `dlp-agent/src/lib.rs`
- `dlp-agent/src/service.rs`
- `dlp-agent/src/print_watcher.rs`
- `dlp-agent/tests/comprehensive.rs`

## Expected Output

- ``dlp-agent/src/print_enforcer.rs` — new enforcer wrapper module`
- ``dlp-agent/src/lib.rs` — mod declaration added`
- ``dlp-agent/src/service.rs` — lifecycle wiring`
- ``dlp-agent/tests/comprehensive.rs` — TC-50..52 implemented`

## Verification

cargo test --test comprehensive print_tc passes

## Observability Impact

- Signals added: `PrintEnforcer` logs `info!` on start/stop; audit events now include `Action::PRINT` operations.
- How a future agent inspects this: grep audit JSONL for `"action_attempted":"PRINT"` to find all print blocks/alerts.
- Failure state exposed: if `PrintEnforcer::start()` fails (e.g., `OpenPrinterW` fails), error is logged and the agent continues running other subsystems.
