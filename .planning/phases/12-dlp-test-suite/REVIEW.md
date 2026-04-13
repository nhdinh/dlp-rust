# Phase 12 Review: Comprehensive DLP Test Suite

**Phase:** 12 — Comprehensive DLP Test Suite
**Files changed:** 4
**New test functions:** ~65 (32 TC/unit in `comprehensive.rs`, ~6 server, 5+ integration E2E, 3 USB tests)

---

## Summary

Phase 12 adds extensive test coverage across IPC serialisation, policy mapping,
classification, cache, offline mode, audit events, USB/network detection, and
server-side TC enforcement. The test suite is thorough and well-structured.
A small number of correctness and reliability issues were identified.

---

## Critical Issues

### C-01: `test_concurrent_cache_access_stress` counts successes unconditionally

**File:** `dlp-agent/tests/comprehensive.rs`, lines 1022–1041

```rust
for j in 0..20 {
    // ...
    match cache.get(...) {
        Some(_) => {}          // cache miss is expected after TTL expiry
        None => { /* Entry may have expired or be missing; record it. */ }
    }
    successes.fetch_add(1, Ordering::Relaxed);  // ALWAYS incremented
    let _ = errors;
}
```

**Problem:** `success_count` is incremented on every loop iteration regardless of
whether the cache `get` succeeded. This makes the test unable to distinguish
between a working cache and a broken one. `errors` is cloned and dropped
immediately (`let _ = errors`) — the `fetch_add` is dead code for the errors
counter. The assertion `assert_eq!(success_count, 1000)` will always pass even
if every `get` returns `None`.

**Fix:** Increment `success_count` only on a cache hit, or on an explicitly
acceptable miss (e.g., TTL expiry), and increment `error_count` on an
unexpected miss. Remove the dead `let _ = errors` clone.

---

## High-Priority Issues

### H-01: Duplicate test names across test files cause `cargo test` ambiguity

**Files:** Multiple

`test_e2e_file_action_to_audit_log` and `test_e2e_audit_event_round_trip` in
`integration.rs` (lines 52, 283) have the same names as functions in
`comprehensive.rs` (the file was not fully read, but the patterns are present).
Additionally, `test_engine_429_is_retried` in `comprehensive.rs` is semantically
inverted — the test name says "is retried" but the assertion checks that the
*final result is an error* (i.e., retries were exhausted). The test is correct;
the name misleads.

**Fix:** Rename to disambiguate, e.g. `test_engine_429_retries_exhausted_returns_error`.
Audit all test names in both files for collisions.

---

### H-02: `test_engine_429_triggers_offline_manager_fallback` does not verify fallback

**File:** `dlp-agent/tests/integration.rs`, lines 1867–1918

The test starts an engine that returns 429, creates an `OfflineManager`,
and calls `evaluate`. It then asserts that the decision equals
`fail_closed_response(T4).decision`. However, the test does **not** assert
that `manager.is_online()` changed, nor that the 429 triggered the offline
transition rather than the decision being the default fail-closed for T4 on
any error.

The test does not verify the intended contract: that 429 causes the
`OfflineManager` to transition to offline and use its fallback table.

**Fix:** Add `assert!(!manager.is_online())` after the evaluate call, and
optionally assert that the fallback reason field is populated.

---

### H-03: `test_engine_429_is_retried` asserts final error, not retry behaviour

**File:** `dlp-agent/tests/comprehensive.rs`, line 578

```rust
async fn test_engine_429_is_retried() {
    let result = client.evaluate(&req).await;
    // 429 is retryable — client should exhaust retries.
    assert!(result.is_err());
    match result.unwrap_err() { /* ... */ }
}
```

The comment says "429 is retryable — client should exhaust retries", but the
assertion only verifies that the final result is an error. It does not verify
that retries were actually attempted, that a retry header was sent, or that the
retry count was honoured. The `is_retryable` unit tests cover the logic at the
unit level; this test conflates "the error type is retryable" with "retries
happened". The test is semantically mislabelled.

**Fix:** Rename to `test_engine_429_returns_error_after_retries` and clarify
the comment, or extend the mock engine to count retry attempts and assert
`retry_count >= 1`.

---

## Medium-Priority Issues

### M-01: `test_tc_14_copy_confidential_to_usb_blocked_log` uses `pub(crate)` field

**File:** `dlp-agent/tests/integration.rs`, line 2024

```rust
detector.blocked_drives.write().insert('F');
```

This writes to `pub(crate) blocked_drives` in `usb.rs`. While the field is
documented as `pub(crate)` for exactly this purpose (CI/test seeding), it is
a code smell: any change to the internal representation of `blocked_drives`
(e.g., changing from `HashSet<char>` to a different type) would break the
integration tests silently.

The unit tests in `usb.rs` use the same pattern (e.g., line 350:
`detector.blocked_drives.write().insert('E')`), so this is consistent with
the existing approach.

**Fix (optional):** Add a `#[cfg(test)]` constructor `UsbDetector::with_blocked_drives_for_test(drives: &[char])` that wraps the internal insertion, making the test interface explicit. This does not need to block the phase.

---

### M-02: `test_engine_400_not_retried` comment is slightly inaccurate

**File:** `dlp-agent/tests/comprehensive.rs`, line 622

```rust
// 400 is not retryable — immediate failure.
```

The client does not retry 400, but "immediate failure" implies it fails without
any retry attempt. If the client's retry loop runs up to `max_retries` times
before returning 400, the comment is misleading.

**Fix:** Update comment to: "400 is not retried — retry loop exits immediately
on 4xx response."

---

### M-03: `abac_action_to_dlp` helper is a no-op identity function

**File:** `dlp-agent/tests/integration.rs`, lines 480–482

```rust
fn abac_action_to_dlp(action: Action) -> Action {
    action
}
```

Both the input and return type are `dlp_common::Action`. The function does
nothing and adds a layer of indirection. It was likely added to allow future
divergence between ABAC actions and DLP actions, but currently it is dead code.

**Fix:** Remove the helper and call `Action::WRITE` / `Action::READ` directly, or
keep it as a documented placeholder with a comment explaining the planned
ABAC→DLP action mapping.

---

### M-04: `test_e2e_cache_hit_skips_engine` never asserts the engine was NOT called

**File:** `dlp-agent/tests/integration.rs`, lines 142–176

The test pre-populates the cache and then calls `cache.get`. It asserts the
cached response is returned but never verifies that the `EngineClient` was not
invoked. If a future bug causes the cache to be bypassed, the test would not
catch it.

**Fix:** Wrap the engine in a mock that tracks call count, or use
`start_mock_engine` and verify the handle (engine thread) was never touched.
For now, a comment documenting this gap is sufficient.

---

### M-05: `test_whitelist_share_name_partial_match` tests implementation, not contract

**File:** `dlp-agent/tests/comprehensive.rs`, lines 1415–1423

The test documents that `"files"` does not match `"files.corp.local"`. This is
an assertion about the current string-matching implementation, not about the
policy contract. If the whitelist matching logic changes (e.g., to subdomain
matching), this test would need updating even though the policy behaviour
remains correct.

**Fix:** Rename the test to `test_whitelist_server_name_requires_full_match`
to clarify it is testing the implementation detail of the whitelist matcher.

---

## Low-Priority Issues

### L-01: `test_tc_14_copy_confidential_to_usb_blocked_log` is labelled TC-14 but the
server-side `admin_api.rs` has no corresponding TC-14 server test

**File:** `dlp-agent/tests/integration.rs`, line 2017

The TC test matrix spans both agent (`integration.rs`) and server
(`admin_api.rs`). TC-14 appears only in the agent tests. TC-51 and TC-52
appear only in `admin_api.rs` as stub `#[ignore]` tests. TC-81 is split:
the agent test (`test_tc_81_bulk_download_alert`) is a full integration test,
but the server TC test (`test_tc_81_bulk_download_confidential_alert` in
`comprehensive.rs`) contains a `todo!()` that will panic if run.

**Fix:** Add TC-14 server-side test in `admin_api.rs` (seed-and-query pattern
matches TC-02/TC-03). Add TC-51 and TC-52 server-side stubs. Fix or remove
the `todo!()` in `test_tc_81_bulk_download_confidential_alert`.

---

### L-02: `test_policy_mapper_forward_slash_paths` and `test_policy_mapper_all_tiers`
have overlapping coverage

**File:** `dlp-agent/tests/comprehensive.rs`, lines 1308–1374 and
`integration.rs`, `policy_mapper_boundary` mod

`test_policy_mapper_all_tiers` tests forward-slash paths (lines 1361–1373)
and the same paths appear in `test_provisional_classification_forward_slash_paths`
in `integration.rs`. The duplication is minor but means two tests would need
to be updated if the prefix matching logic changes.

**Fix:** Consolidate forward-slash path coverage into one location (prefer the
`policy_mapper_boundary` mod in `integration.rs` as the canonical boundary
test location).

---

### L-03: `test_offline_manager_cache_hit_second_request` never asserts `is_online` after
first call

**File:** `dlp-agent/tests/comprehensive.rs`, lines 671–695

The test verifies that the first request succeeds and the cache is populated,
but does not assert `manager.is_online()` after the first request. If the
engine connection drops between the first and second request, the test would
not distinguish between "cache hit" and "engine call".

**Fix:** Add `assert!(manager.is_online())` after the first evaluate call.

---

### L-04: `spawn_admin_app` in `admin_api.rs` is repeated verbatim in multiple tests

**File:** `dlp-server/src/admin_api.rs`

Every async test in the `tests` mod that needs the app calls
`spawn_admin_app()` and then immediately calls `mint_admin_jwt()`.
These two calls appear in ~20 tests. While extracting a shared helper struct
(`TestApp`) would be a larger refactor, consolidating `spawn_admin_app` +
`mint_admin_jwt` into one `TestContext::new()` call would reduce duplication
and improve maintainability.

**Fix:** Create a `TestContext` struct in the test module with fields
`(app, token, db)` and a `new() -> Self` constructor, then replace all
`let app = spawn_admin_app(); let token = mint_admin_jwt();` call sites.

---

### L-05: `test_db_insert_select_roundtrip_via_spawn_blocking` and
`test_router_post_then_direct_db_read` test the same thing twice

**File:** `dlp-server/src/admin_api.rs`, lines 1653–1750

Both tests verify that DB writes via `spawn_blocking` are visible to
subsequent reads. `test_db_insert_select_roundtrip_via_spawn_blocking` is a
direct DB test; `test_router_post_then_direct_db_read` tests it via the HTTP
router. The first is valuable as a unit test; the second adds little beyond
the full-stack CRUD tests that follow.

**Fix:** Remove `test_db_insert_select_roundtrip_via_spawn_blocking` and keep
`test_router_post_then_direct_db_read`, or mark the former as
`#[ignore = "redundant with test_router_post_then_direct_db_read"]`.

---

### L-06: `test_tc_11_copy_confidential_to_internal_blocked_alert` re-uses TC-11 ID
for different paths

**File:** `dlp-agent/tests/integration.rs`, lines 1933–2007

The TC-11 test in `integration.rs` classifies `C:\Data\confidential_copy.xlsx`
as T3 (which is correct — `Data` is a T2 path prefix, but `confidential_copy`
contains `confident` which is NOT a full `confidential` prefix match). This
may or may not match the actual classification expected by the TC matrix.
The same path (`C:\Data\confidential_copy.xlsx`) would classify differently
from `C:\Confidential\finance.xlsx` in TC-11 tests elsewhere.

**Fix:** Verify that `C:\Data\confidential_copy.xlsx` classifies as T3 per the
test's assumption, or adjust the path to `C:\Confidential\confidential_copy.xlsx`.

---

## Security Observations (No Issues)

### S-01: No sensitive data in test fixtures

Test data uses clearly fabricated values:
- SID prefixes: `S-1-5-21-TEST`, `S-1-5-21-E2E-*`, `S-1-5-21-TC-*`
- No real SSNs, credit card numbers, or PII in test strings (test SSNs use
  `123-45-6789`, `987-65-4321`, etc., all in standard test format)
- Secrets in `admin_api.rs` tests use clearly dev-stage values
  (`t0p-secret`, `s3cret`, `hmac-key`)

No security concerns.

---

### S-02: JWT secret handling in tests is safe

`TEST_JWT_SECRET` is a hardcoded dev literal that matches the `DEV_JWT_SECRET`
in `admin_auth.rs`. Tests call `set_jwt_secret` on a `OnceLock`, which
silently ignores duplicates — safe for concurrent test execution.

---

## Documentation Observations

- `integration.rs` module doc is accurate and well-written (lines 1–15)
- `usb.rs` field comment for `blocked_drives` correctly documents the CI
  rationale (lines 51–53)
- `TC-82` test correctly marked `#[ignore]` with phase reference
- `cloud_tc` and `print_tc` mods correctly use `todo!()` stubs with phase
  references

---

## Recommendations Summary

| ID | Severity | Fix Effort | Recommendation |
|----|----------|------------|----------------|
| C-01 | Critical | Low | Fix `success_count` increment logic; remove dead `let _ = errors` |
| H-01 | High | Low | Rename duplicate/ambiguous test names |
| H-02 | High | Low | Add `assert!(!manager.is_online())` in 429 fallback test |
| H-03 | High | Low | Rename `test_engine_429_is_retried` → `test_engine_429_returns_error_after_retries` |
| M-01 | Medium | Medium | Add `#[cfg(test)]` helper ctor for `UsbDetector::with_blocked_drives` |
| M-02 | Medium | Trivial | Fix comment in `test_engine_400_not_retried` |
| M-03 | Medium | Trivial | Remove `abac_action_to_dlp` identity helper |
| M-04 | Medium | Medium | Mock engine call count or add clarifying comment |
| M-05 | Medium | Trivial | Rename test to reflect it tests implementation |
| L-01 | Low | Medium | Add missing TC-14 server test; fix `todo!()` in TC-81 |
| L-02 | Low | Trivial | Deduplicate forward-slash path coverage |
| L-03 | Low | Trivial | Add `assert!(manager.is_online())` in cache hit test |
| L-04 | Low | Medium | Consolidate `spawn_admin_app` + `mint_admin_jwt` into `TestContext` |
| L-05 | Low | Trivial | Remove or ignore `test_db_insert_select_roundtrip_via_spawn_blocking` |
| L-06 | Low | Low | Verify `C:\Data\confidential_copy.xlsx` classification assumption |

---

## Conclusion

The Phase 12 test suite is comprehensive and well-architected. The mock engine
pattern, the `start_mock_engine`-family helpers, and the seed-and-query server
tests are all excellent. The critical issue (C-01) must be fixed before
merging — the stress test's success counter is currently ineffective. All
high-priority issues are low-effort renames and one missing assertion. No
security concerns were identified.
