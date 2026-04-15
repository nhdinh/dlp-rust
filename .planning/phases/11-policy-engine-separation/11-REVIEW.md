# Phase 11 — Code Review: Policy Engine Separation (`dlp-server`)

**Review date:** 2026-04-16
**Reviewer:** Claude Sonnet 4.6
**Files reviewed:** 7
**Depth:** Standard

---

## Summary

The codebase is generally well-structured and shows high engineering standards across the board. The architecture is sound (separated concerns, DB-backed hot-reload, audit trail), security measures are thoughtful (ME-01, TM-02, JWT auth), and the test suite is thorough. Five findings are documented below: two correctness bugs, two code-quality issues, and one security gap.

---

## Findings

### CRITICAL — Bug: `test_invalidate_reloads_cache` false-positive

**File:** `dlp-server/src/policy_store.rs` (unit test, lines 669–700)

**Problem:** The test inserts a policy directly into the DB and then calls `store.invalidate()` to confirm the cache reloads. However, the `Pool` it uses is an **in-memory** SQLite database (`:memory:`). Since `PolicyStore` holds an `Arc<Pool>` pointing to that in-memory DB, any data inserted by the test connection is only visible to that same connection — the `invalidate()` call opens a **new connection** that sees an empty database.

The test passes spuriously because `PolicyStore::new()` also opens a fresh connection during construction, which also sees an empty DB (returning 0 policies), and `invalidate()` swaps in an empty `Vec`. The assertion `assert_eq!(store.list_policies().len(), 1)` passes only because the test's insert was never visible to `invalidate()` in the first place — the comparison is always `0 == 0` after both calls.

```rust
fn test_invalidate_reloads_cache() {
    let pool = Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool"));
    let store = PolicyStore::new(Arc::clone(&pool)).unwrap();
    assert_eq!(store.list_policies().len(), 0); // ← fresh connection, sees empty DB

    {   // insert via pool connection #1
        let conn = pool.get().unwrap();
        conn.execute("INSERT INTO policies ...", []).unwrap();
    }
    store.invalidate(); // opens connection #2 — does NOT see insert from #1
    assert_eq!(store.list_policies().len(), 1); // ← always passes; data was never visible
}
```

**Impact:** `invalidate()` appears to work but actually silently drops the reload on in-memory DBs. The same pattern affects `test_refresh_reloads_cache` (line 703).

**Fix:** Replace `:memory:` with a `NamedTempFile`-backed pool in both tests (matching how the integration tests do it), or use a shared in-memory connection (`mode=memory&cache=shared`).

---

### MEDIUM — Bug: `admin_api.rs` `unwrap_or_default()` hides deserialization errors

**Files:**
- `dlp-server/src/admin_api.rs` (lines 516, 549, 1093, 1095, 1101, 1102–1103, 1207, 1208, 1273, 1274)

**Problem:** Fields decoded from DB JSON strings use `unwrap_or_default()` instead of propagating errors. If the `conditions` column in the DB contains malformed JSON (e.g., due to a prior bug or manual edit), the handler silently substitutes `null` and returns a 200 response with incomplete data, making the fault invisible to the caller.

```rust
let conditions: serde_json::Value =
    serde_json::from_str(&r.conditions).unwrap_or(serde_json::Value::Null); // silently loses error
```

**Impact:** Corrupt policy data produces a successful HTTP response with `null` conditions. Admins reviewing policies via the API see no indication of the corruption. The same pattern appears in several `AgentConfigPayload` deserializations.

**Fix:** Map the `serde_json::Error` to `AppError::Internal` or `AppError::Database` (corrupt row). Alternatively, since `PolicyStore::load_from_db` already skips rows with malformed conditions, the admin API should do the same for consistency — log and return a 500 rather than silently degrading.

---

### MEDIUM — Security: `/evaluate` endpoint has no rate limiting

**File:** `dlp-server/src/admin_api.rs` (lines 44–69, router at lines 392–395)

**Problem:** `POST /evaluate` is explicitly unauthenticated and intentionally unprotected (per its docstring and the design comment). This is correct for agent-to-server calls, but there is no Governor rate-limit layer applied to it. An attacker who compromises any internal host (or finds a way to submit requests) can drive unbounded policy evaluations against the server with no throttling.

**Impact:** The hot path (`PolicyStore::evaluate`) is fast (in-memory, no DB), but uncontrolled eval rates can be used for policy fingerprinting (inferring which policies exist by timing differences), or to amplify DoS impact if the eval path is ever extended with external calls (e.g., AD lookups).

**Fix:** Add a Governor rate-limit layer to `/evaluate`, keyed by source IP. Use a permissive per-IP limit (e.g., 10,000/min) that won't affect legitimate agents but prevents abuse. Alternatively, apply `rate_limiter::moderate_config()` or a dedicated high-throughput config.

---

### LOW — Code Quality: `PolicyEngineError` is a dead-end, non-extensible error type

**File:** `dlp-server/src/policy_engine_error.rs`

**Problem:** The enum has exactly one variant (`PolicyNotFound`). The type is not a `thiserror`-derived struct containing context (e.g., a policy ID) that would make it actionable — it already just stores a `String`. Every use of `map_err(|e| PolicyEngineError::PolicyNotFound(e.to_string()))` (in `PolicyStore::new`) loses the original error's type and chain.

**Impact:** Low. The error mapping is functional, but it makes error triage harder — if `PolicyRepository::list` fails for a reason other than "policy not found," the conversion discards that signal.

**Fix:** Either expand the enum variants to cover all failure modes from the policy store, or switch to `anyhow::Error` directly for the `load_from_db` error path. If keeping the enum, add `#[from]` on the inner field.

---

### LOW — Code Quality: `get_agent_config_for_agent` handles errors inconsistently vs. other handlers

**File:** `dlp-server/src/admin_api.rs` (lines 1083–1114)

**Problem:** This handler explicitly matches `rusqlite::Error::QueryReturnedNoRows` to implement fallback logic (per-agent override → global default), but also matches and converts every other `rusqlite::Error` to `AppError::Database`. All other handlers in the file use `map_err(AppError::Database)` or `.map_err(AppError::from)` instead. This inconsistency makes the error paths harder to reason about.

Additionally, `AgentConfigRepository::get_override` already returns `rusqlite::Error` on DB failure — if the DB is truly unavailable, returning 500 is correct. The explicit match is arguably more readable here, but the inconsistency with the rest of the module is worth noting.

**Impact:** Minor. No functional bug; purely a maintainability concern.

**Fix:** Consider extracting the fallback pattern into a small helper that returns `Result<Option<Row>, AppError>` so the handler can use the standard `?` operator uniformly.

---

## Positive Observations

- **Good:** `evaluate_handler` correctly does not `.await` the synchronous `evaluate()` call (line 67).
- **Good:** `spawn_blocking` is used correctly in all async handlers — DB I/O never blocks the async thread pool.
- **Good:** ME-01 (secret masking) is well-implemented with TOCTOU protection inside a single `UnitOfWork`.
- **Good:** TM-02 (SSRF hardening) includes IPv4-mapped IPv6 protection and domain-accept (intentional, documented).
- **Good:** JWT secret is resolved before serving and stored in a `OnceLock`, preventing accidental re-initialization.
- **Good:** Graceful shutdown via `with_graceful_shutdown` in `main.rs`.
- **Good:** Background cache refresh task does not crash on DB errors (fail-safe, log-only).
- **Good:** Integration tests use `NamedTempFile` for isolated DBs; unit tests use `:memory:`.
- **Good:** All audit events are written after DB commit, not before.
- **Good:** `validate_webhook_url` is a pure function, easily unit-testable.

---

## Recommendations (Priority Order)

1. **Fix** `test_invalidate_reloads_cache` and `test_refresh_reloads_cache` with a temp file pool.
2. **Replace** `unwrap_or_default()` calls on `serde_json::from_str` with explicit error propagation in admin API handlers.
3. **Add** a rate-limit layer to `POST /evaluate` (per-IP Governor config).
4. **Expand** `PolicyEngineError` variants or switch `load_from_db` error path to `anyhow`.
5. **Audit** all other uses of `unwrap_or_default()` across the `dlp-server` crate for the same pattern.