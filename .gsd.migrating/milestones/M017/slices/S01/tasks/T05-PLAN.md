---
estimated_steps: 41
estimated_files: 4
skills_used: []
---

# T05: WFP FFI bindings and WFP manager

Hand-roll minimal FFI bindings to `fwpuclnt.dll` in `dlp-agent/src/wfp_ffi.rs` for `FwpmEngineOpen0`, `FwpmFilterAdd0`, `FwpmFilterDeleteById0`, `FwpmSubLayerAdd0`, and `FwpmEngineClose0`. Use `windows` crate `GUID` and `NTSTATUS` types. Implement `wfp_manager.rs` that opens the WFP engine, registers a sublayer, adds a filter blocking outbound TCP/443 from specified PIDs (using `FWPM_CONDITION_IP_LOCAL_ADDRESS`, `FWPM_CONDITION_IP_REMOTE_PORT`, `FWPM_CONDITION_IP_PROTOCOL`), and exposes `add_process_block(pid)` / `remove_process_block(pid)`. Write unit tests for registration, block, unblock, and unregistration. If `Win32_NetworkManagement_WindowsFilteringPlatform` is available in the `windows` crate, use it; otherwise rely entirely on the hand-rolled FFI module.

## Failure Modes
| Dependency | On error | On timeout | On malformed response |
|------------|----------|-----------|----------------------|
| WFP engine | Log NTSTATUS, WFP remains disabled | N/A (synchronous) | N/A |
| `FwpmFilterAdd0` | Log error, skip PID block | N/A | N/A |
| Coexistence with VPN/EDR | Other filters may have higher priority; log warning if block is bypassed | N/A | N/A |

## Load Profile
- **Shared resources**: Single WFP engine session handle.
- **Per-operation cost**: One `FwpmFilterAdd0`/`DeleteById0` call per PID (infrequent).
- **10x breakpoint**: WFP engine handle exhaustion is unlikely; filter count scales with PID count, not request rate.

## Negative Tests
- **Malformed inputs**: PID 0, PID of a system process, already-blocked PID.
- **Error paths**: WFP engine not available (e.g., Windows service disabled). Double registration of same sublayer.
- **Boundary conditions**: Unregister when no filters exist; add block when engine not open.

## Steps
1. Add `Win32_NetworkManagement_WindowsFilteringPlatform` to `dlp-agent/Cargo.toml` if available; otherwise omit.
2. Create `dlp-agent/src/wfp_ffi.rs` with `extern "system"` declarations and minimal struct definitions (`FWPM_FILTER0`, `FWPM_SUBLAYER0`, `FWP_CONDITION_VALUE0`, etc.).
3. Create `dlp-agent/src/wfp_manager.rs` with `WfpManager::new() -> Result<Self, WfpError>`, `register(&self)`, `unregister(&self)`, `add_process_block(&self, pid)`, `remove_process_block(&self, pid)`.
4. Use `FWPM_FILTER_FLAG_PERSISTENT` or transient as appropriate (transient preferred for service lifetime).
5. Write unit test: register filter, verify it exists via `FwpmFilterGetById0`, block test PID, unblock, unregister.
6. Add `pub mod wfp_ffi;` and `pub mod wfp_manager;` to `dlp-agent/src/lib.rs`.

## Must-Haves
- [ ] Hand-rolled FFI bindings compile and link against `fwpuclnt.dll`.
- [ ] `WfpManager::register()` succeeds and `unregister()` cleans up.
- [ ] `add_process_block` adds a filter for the given PID; `remove_process_block` removes it.
- [ ] Unit tests cover registration, block, unblock, and unregistration.

## Verification
- `cargo test -p dlp-agent wfp`

## Observability Impact
- Signals added: `tracing::info!` on WFP engine open/close; `tracing::info!` on each filter add/remove with PID and filter ID.
- How a future agent inspects this: agent logs contain `wfp_manager` spans.
- Failure state exposed: `WfpError::EngineUnavailable(NTSTATUS)` and `WfpError::FilterAddFailed(NTSTATUS)` carry the raw error code.

## Inputs
- `dlp-agent/Cargo.toml`
- `dlp-agent/src/lib.rs`

## Expected Output
- `dlp-agent/src/wfp_ffi.rs`
- `dlp-agent/src/wfp_manager.rs`
- `dlp-agent/Cargo.toml` (updated features/dependencies)
- `dlp-agent/src/lib.rs` (updated with `mod wfp_ffi` and `mod wfp_manager`)

## Inputs

- `dlp-agent/Cargo.toml`
- `dlp-agent/src/lib.rs`

## Expected Output

- `dlp-agent/src/wfp_ffi.rs`
- `dlp-agent/src/wfp_manager.rs`
- `dlp-agent/Cargo.toml`
- `dlp-agent/src/lib.rs`

## Verification

cargo test -p dlp-agent wfp
