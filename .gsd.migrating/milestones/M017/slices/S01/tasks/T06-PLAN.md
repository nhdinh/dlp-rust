---
estimated_steps: 44
estimated_files: 5
skills_used: []
---

# T06: Cloud enforcer and service integration

Implement `CloudEnforcer` in `dlp-agent/src/cloud_enforcer.rs` following the `UsbEnforcer` pattern: `new(...) -> Self` and `check(&self, path: &str, action: &FileAction) -> Option<CloudBlockResult>`. The enforcer checks if the path is inside a sync folder (placeholder check for S01; S02 will add real path resolver) and returns a block result for T3/T4 `CLOUD_UPLOAD` actions. Wire `HookInjector` and `WfpManager` into `service.rs`: construct both in `run_loop_init`, store handles in `RunLoopContext`, and tear them down in `run_loop_shutdown`. Update `interception/mod.rs` to accept the cloud enforcer and invoke it before ABAC evaluation. Replace the TC-30 stub in `dlp-agent/tests/comprehensive.rs` with a real test that constructs a `CloudEnforcer`, passes a mock sync-folder path, and asserts the block decision and audit event shape.

## Failure Modes
| Dependency | On error | On timeout | On malformed response |
|------------|----------|-----------|----------------------|
| Hook injector init | Log error, continue without hook injection | N/A | N/A |
| WFP manager init | Log error, continue without WFP | N/A | N/A |
| Cloud enforcer | Returns `None` (fall through to ABAC) on any error | N/A | N/A |

## Negative Tests
- **Malformed inputs**: Empty path, UNC path, path outside sync folder.
- **Error paths**: Config `cloud_hook_enabled: false` — injector not started. Config `wfp_filter_enabled: false` — WFP not registered.
- **Boundary conditions**: T1 file in sync folder (ALLOW), T4 file outside sync folder (no cloud block, fall through to ABAC).

## Steps
1. Create `dlp-agent/src/cloud_enforcer.rs` with `CloudEnforcer`, `CloudBlockResult`, and `check` method.
2. Add placeholder sync-folder check (`path.starts_with("C:\\Users\\...\\OneDrive")`) — real resolver comes in S02.
3. Open `dlp-agent/src/service.rs`, add `hook_injector: Option<HookInjector>` and `wfp_manager: Option<WfpManager>` to `RunLoopContext`.
4. In `run_loop_init`: if `cloud_hook_enabled`, construct `HookInjector`; if `wfp_filter_enabled`, construct and register `WfpManager`.
5. In `run_loop_shutdown`: unregister WFP, stop injector.
6. Update `dlp-agent/src/interception/mod.rs` to pass `cloud_enforcer` into `run_event_loop`.
7. Replace TC-30 stub in `dlp-agent/tests/comprehensive.rs` with a test using `CloudEnforcer::check`.
8. Run `cargo test -p dlp-agent --test comprehensive -- test_tc_30`.

## Must-Haves
- [ ] `CloudEnforcer::check` returns `Some(CloudBlockResult)` for T3/T4 files in sync folder placeholder paths.
- [ ] `run_loop_init` constructs `HookInjector` and `WfpManager` when config enables them.
- [ ] `run_loop_shutdown` tears down both cleanly.
- [ ] TC-30 test passes with real `CloudEnforcer` logic.

## Verification
- `cargo test -p dlp-agent cloud_enforcer`
- `cargo test -p dlp-agent --test comprehensive -- test_tc_30`
- `cargo check -p dlp-agent`

## Observability Impact
- Signals added: `tracing::info!` on `CloudEnforcer::check` with path, tier, and decision.
- How a future agent inspects this: agent logs contain `cloud_enforcer` spans.
- Failure state exposed: Enforcer returns `None` on error, allowing ABAC fallback; errors are logged.

## Inputs
- `dlp-agent/src/service.rs`
- `dlp-agent/src/usb_enforcer.rs` (pattern reference)
- `dlp-agent/src/interception/mod.rs`
- `dlp-agent/tests/comprehensive.rs`

## Expected Output
- `dlp-agent/src/cloud_enforcer.rs`
- `dlp-agent/src/service.rs` (updated)
- `dlp-agent/src/interception/mod.rs` (updated)
- `dlp-agent/tests/comprehensive.rs` (updated TC-30)
- `dlp-agent/src/lib.rs` (updated with `mod cloud_enforcer`)

## Inputs

- `dlp-agent/src/service.rs`
- `dlp-agent/src/usb_enforcer.rs`
- `dlp-agent/src/interception/mod.rs`
- `dlp-agent/tests/comprehensive.rs`

## Expected Output

- `dlp-agent/src/cloud_enforcer.rs`
- `dlp-agent/src/service.rs`
- `dlp-agent/src/interception/mod.rs`
- `dlp-agent/tests/comprehensive.rs`
- `dlp-agent/src/lib.rs`

## Verification

cargo test -p dlp-agent cloud_enforcer && cargo test -p dlp-agent --test comprehensive -- test_tc_30
