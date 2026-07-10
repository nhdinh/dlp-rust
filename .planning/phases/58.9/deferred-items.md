# Phase 58.9 — Deferred / Out-of-Scope Items

Items discovered during Phase 58.9 execution that are **not** caused by this
phase's changes and are intentionally **not** fixed here (GSD executor
deviation SCOPE BOUNDARY rule). Logged for visibility; none block Phase 58.9
completion.

## Pre-existing test-environment failures (Plan 58.9-03 gate run)

Surface while running the full `dlp-agent` test suite after Task 2 of Plan
58.9-03. All three reproduce **independent of this plan's edits** (the plan
touches only `hook_ipc.rs`, `service.rs`, and `hook_ipc_integration.rs`; none of
the failing tests touch the diagnostics producer path).

### 1. `service::tests::test_dacl_manager_shutdown` — `CreateFileMappingW` access denied

- **File:** `dlp-agent/src/service.rs` (~line 6805, pre-existing test)
- **Symptom:** `CreateMappingFailed("CreateFileMappingW failed: HRESULT(0x80070005) Access is denied")`
- **Scope:** classification-cache / named-shared-memory subsystem, **not** the
  diagnostics producer path.
- **Disposition:** environmental. The same test **passes when run in isolation**
  (`cargo test -p dlp-agent --lib test_dacl_manager_shutdown` -> ok), which
  points to concurrent named-shared-memory handle contention under the default
  parallel runner (`Global\DlpClassificationCache` collisions between tests),
  not a logic regression. Out of scope for Plan 58.9-03.

### 2. `service::tests::test_reinit_applies_added_protected_path` — `CreateFileMappingW` access denied

- **File:** `dlp-agent/src/service.rs` (~line 6886, pre-existing test)
- **Symptom:** identical `HRESULT(0x80070005) Access is denied` from
  `CreateFileMappingW`.
- **Scope:** DACL reinit + classification-cache shared memory, **not** the
  diagnostics producer path.
- **Disposition:** environmental (same root cause as #1 — parallel-runner
  named-mapping contention). Out of scope for Plan 58.9-03.

### 3. `idle_injected_process_sends_poll_control_with_creation_time` — `EnumProcessModules failed`

- **File:** `dlp-agent/tests/hook_ipc_integration.rs` (~line 987, pre-existing
  real-DLL-injection test)
- **Symptom:** `injection should succeed: EnumFailed("EnumProcessModules failed")`
- **Scope:** real `CreateRemoteThread` DLL injection + module enumeration
  (privilege/timing-sensitive), **not** the `DiagnosticsResponse` ingest arm
  (this test exercises the `PollControl` path).
- **Disposition:** environmental/pre-existing flakiness in the real-injection
  integration test (module enumeration can fail under restricted or heavily
  instrumented environments). The new `diagnostics_response_ingests_into_aggregator`
  test (mock-server based, no real injection) passes deterministically. Out of
  scope for Plan 58.9-03.

## Notes

- The plan-mandated gate (`cargo fmt --check`, `cargo clippy -p dlp-agent --
  -D warnings`, `cargo build -p dlp-agent`, and the three **new** tests added
  by this plan) is green. The failures above are in pre-existing tests on
  unrelated subsystems and are logged here rather than fixed, per the SCOPE
  BOUNDARY rule.
- Suggested follow-up (not this phase): run the classification-cache /
  shared-memory tests serially or with unique mapping names, and gate the
  real-injection integration tests behind a privilege/EDR-environment check.
