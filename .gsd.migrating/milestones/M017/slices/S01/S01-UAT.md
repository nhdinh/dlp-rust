# S01: API Hook Framework + WFP Filter — UAT

**Milestone:** M017
**Written:** 2026-05-08T15:03:40.238Z

# S01 UAT: API Hook Framework + WFP Filter

## Preconditions
1. Windows development environment with Rust toolchain.
2. Agent service is installed or can be run in standalone mode.
3. `dlp_hook_dll.dll` is built and present next to `dlp-agent.exe`.

## Test Cases

### TC-S01-01: Action::CLOUD_UPLOAD serde round-trip
1. Run `cargo test -p dlp-common abac::tests::test_evaluate_request_serde`.
**Expected**: Test passes; `CLOUD_UPLOAD` serializes and deserializes correctly.

### TC-S01-02: Named pipe server latency
1. Run `cargo test -p dlp-agent hook_ipc::tests::hook_ipc_roundtrip_test`.
**Expected**: 1000 requests complete with p99 latency < 50ms.

### TC-S01-03: Hook DLL blocks on DENY
1. Run `cargo test -p dlp-hook-dll tests::hook_createfilew_fail_closed_on_deny`.
**Expected**: Hooked `CreateFileW` returns `INVALID_HANDLE_VALUE` and `GetLastError() == ERROR_ACCESS_DENIED` when the mock pipe server returns `DENY`.

### TC-S01-04: Hook DLL allows on ALLOW
1. Run `cargo test -p dlp-hook-dll tests::hook_createfilew_allow_when_allowed`.
**Expected**: Hooked `CreateFileW` succeeds when the mock pipe server returns `ALLOW`.

### TC-S01-05: Hook injector loads DLL into test process
1. Run `cargo test -p dlp-agent hook_injector::tests::test_injector_successfully_injects_dll`.
**Expected**: DLL is injected into a spawned child process; `EnumProcessModules` confirms the module is present.

### TC-S01-06: WFP manager lifecycle
1. Run `cargo test -p dlp-agent wfp_manager::tests::test_register_unregister`.
**Expected**: WFP engine opens, sublayer registers, filter adds, filter removes, engine closes — all without error.

### TC-S01-07: WFP PID block and unblock
1. Run `cargo test -p dlp-agent wfp_manager::tests::test_add_remove_block`.
**Expected**: Adding a block for PID 1234 succeeds; removing the block succeeds; double-block is idempotent.

### TC-S01-08: CloudEnforcer blocks T3/T4 in sync folder
1. Run `cargo test -p dlp-agent cloud_enforcer::tests::test_t3_file_in_sync_folder_blocked` and `test_t4_file_in_sync_folder_blocked`.
**Expected**: Both return `Some(CloudBlockResult)` with `decision == DENY` and `provider == "OneDrive"`.

### TC-S01-09: CloudEnforcer allows T1 in sync folder
1. Run `cargo test -p dlp-agent cloud_enforcer::tests::test_t1_file_in_sync_folder_returns_none`.
**Expected**: Returns `None` (falls through to ABAC).

### TC-S01-10: CloudEnforcer ignores reads and deletes
1. Run `cargo test -p dlp-agent cloud_enforcer::tests::test_read_action_returns_none` and `test_deleted_action_returns_none`.
**Expected**: Both return `None`.

### TC-S01-11: Service constructs subsystems on startup
1. Start the agent service with `cloud_hook_enabled = true` and `wfp_filter_enabled = true` in config.
2. Inspect logs for lines containing `"cloud enforcer constructed"`, `"hook injector constructed"`, and `"WFP manager registered"`.
**Expected**: All three subsystems initialize without error.

### TC-S01-12: TC-30 comprehensive test
1. Run `cargo test -p dlp-agent --test comprehensive -- test_tc_30_public_cloud_upload_allowed`.
**Expected**: Test passes; public (T1) file in sync folder is allowed.

## UAT Type
Contract + integration acceptance. Validates that the hook framework, WFP filter, named pipe protocol, and CloudEnforcer all compile, link, and pass automated tests. Does not validate live sync client behavior.

## Not Proven By This UAT
- Live OneDrive / Dropbox / Google Drive / Box process injection and blocking (deferred to S02).
- Actual HTTPS upload interception via WFP against real cloud endpoints (deferred to S02).
- Dynamic sync folder path discovery via registry / shell APIs (deferred to S02).
- Real ABAC policy evaluation in the hook path (deferred to S02).
- Print spooler interception (S04).
- Share link detection (S03).
- Admin CLI configuration of cloud/print policies (S05).
