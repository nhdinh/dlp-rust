# Deferred Items — Phase 58.10

Out-of-scope discoveries made during execution. NOT fixed in the plan that found
them (scope boundary: only auto-fix issues directly caused by that plan's changes).

## 1. Pre-existing rustfmt diff in dlp-hook-dll/src/trampolines.rs — RESOLVED in 58.10-03

- **Found during:** 58.10-02 Task 3 verification (`cargo fmt --check -p dlp-hook-dll`)
- **Location:** `dlp-hook-dll/src/trampolines.rs:400` (the `send_diagnostics`
  chunk loop — a `debug_log(&format!(...))` call rustfmt wanted to re-wrap)
- **Resolution:** Fixed in Plan 58.10-03 (commit `0999db07`, `style(58.10-03)`),
  which edits the same file. Formatting-only; no behavior change. The
  `cargo fmt --check` wave-merge gate now passes for this file.

## 2. Flaky dlp-agent lib tests under concurrent full-suite runs — OUT OF SCOPE

- **Found during:** 58.10-03 wave-merge gate (`cargo test -p dlp-agent -p dlp-hook-dll -p dlp-common --lib`)
- **Tests:** `service::tests::test_dacl_manager_shutdown` and
  `service::tests::test_reinit_applies_added_protected_path`
- **Symptom:** Both fail with `CreateFileMappingW failed: Access is denied
  (HRESULT 0x80070005)` when constructing a `ClassificationCache` during a
  CONCURRENT full-suite run. Both PASS in isolation
  (`-- --test-threads=1`, single-test filter).
- **Why out of scope:** Plan 58.10-03 touches ONLY
  `dlp-hook-dll/src/trampolines.rs` and `dlp-agent/tests/hook_ipc_integration.rs`.
  It does NOT modify `dlp-agent/src/service.rs`, the DACL manager, or
  classification-cache construction. The failure is a pre-existing
  test-isolation / shared-memory-namespace contention issue (multiple tests
  creating Global/Local mappings simultaneously), independent of this plan.
- **Evidence this plan is clean:** `dlp-hook-dll --lib` 339/339 green,
  `dlp-common --lib` 343/343 green, `dlp-agent --test hook_ipc_integration`
  20/20 green, both flaky tests green in isolation.
- **Recommendation:** Address as a test-isolation hygiene item (unique mapping
  names per test, or serialize the cache-constructing tests) in a follow-up
  quick plan, mirroring the Phase 58.5 `isolate-dlp-hook-tests` approach. Not a
  blocker for 58.10-03.
