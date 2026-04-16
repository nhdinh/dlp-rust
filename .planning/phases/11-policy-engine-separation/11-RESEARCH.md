# Phase 11: Policy Store with ABAC Evaluation — Research

**Gathered:** 2026-04-16
**Status:** Ready for planning
**Output:** `11-RESEARCH.md`

---

## 1. What This Phase Delivers

A `PolicyStore` type in `dlp-server` that:

1. Loads all policies from the `policies` table into an in-memory `Vec<Policy>` at startup.
2. Exposes a synchronous `evaluate(&self, &EvaluateRequest) -> EvaluateResponse` for the hot path — no DB call on every request.
3. Refreshes the cache on a configurable interval (background task) and invalidates immediately after admin writes.
4. Implements ABAC first-match evaluation with tiered default-deny.

The agent's existing `EngineClient::evaluate()` gets a working `/evaluate` endpoint to call.

---

## 2. Key Decisions Already Made (from 11-CONTEXT.md)

| Decision | Summary |
|---|---|
| D-01 | Tiered default-deny: T1/T2 → ALLOW, T3/T4 → DENY when no policy matches |
| D-02 | Cache: load at startup, refresh every N minutes, invalidate immediately on write |
| D-03 | First-match: lowest `priority` number wins; stop on first full match |
| D-04 | Condition matching: Classification, MemberOf, DeviceTrust, NetworkLocation, AccessContext with ops `"eq"`/`"neq"`/`"in"`/`"not_in"` |

---

## 3. What I Found in the Codebase

### 3.1 `policy_api.rs` — Dead Code to Revive

The file is orphaned (not declared in `lib.rs` `pub mod` list and not in `Cargo.toml`), but contains a complete handler template for **both** evaluation and CRUD:

```
evaluate_handler    — POST /evaluate   (needs PolicyStore)
list_policies       — GET /policies   (needs PolicyStore.list_policies())
create_policy       — POST /policies  (needs PolicyStore.add_policy())
get_policy          — GET /policies/:id
update_policy       — PUT /policies/:id
delete_policy       — DELETE /policies/:id
get_policy_versions — GET /policies/:id/versions
```

It also imports two non-existent types:
- `crate::policy_store::PolicyStore` — **must be created**
- `crate::policy_engine_error::PolicyEngineError` — **must be created** (used only for `AppError::from(PolicyEngineError::PolicyNotFound(...))` in `get_policy` and `get_policy_versions`)

The `router()` function in `policy_api.rs` builds its own `Router<()>`, but the CONTEXT says to layer `/evaluate` into the existing `admin_router`. The CRUD routes are already in `admin_api.rs`. So the cleanest approach is to **reuse only the `evaluate_handler` function** from `policy_api.rs` and delete the rest of that file.

### 3.2 `admin_api.rs` — Where Invalidation Calls Go

All five CRUD handlers already exist and follow the same pattern:

```
DB write (spawn_blocking → PolicyRepository::insert/update/delete + uow.commit())
→ emit audit event (spawn_blocking → audit_store::store_events_sync)
→ return response
```

After the DB commit block (before the `.await?` unwrap) is where `state.policy_store.invalidate()` needs to be called:

| Handler | Line | Location |
|---|---|---|
| `create_policy` | ~570 | After `uow.commit()`, before audit event |
| `update_policy` | ~677 | After `uow.commit()`, before audit event |
| `delete_policy` | ~727 | After `uow.commit()`, before audit event |

The invalidation call should be synchronous (no `spawn_blocking` needed) and placed **after** the DB commit succeeds — so the cache is only invalidated when the write has actually landed.

### 3.3 `lib.rs` — AppState

`AppState` currently holds:
```rust
pub struct AppState {
    pub pool: Arc<db::Pool>,
    pub siem: siem_connector::SiemConnector,
    pub alert: alert_router::AlertRouter,
    pub ad: Option<AdClient>,
}
```

Add `pub policy_store: Arc<PolicyStore>` here. Also need `pub mod policy_store;` in lib.rs.

### 3.4 `main.rs` — Startup Sequence

Current order:
1. Pool init
2. Admin user provisioning
3. SIEM connector
4. Alert router
5. AD client
6. Build `AppState`
7. Background heartbeat sweeper
8. `admin_router` builder
9. `TcpListener::bind` + `axum::serve`

`PolicyStore::new(&pool)` should be inserted between step 4 and step 6 — after the pool is ready, before AppState is built. The background refresh task spawns after AppState is built (step 7 area).

### 3.5 `policies.rs` Repository

`PolicyRepository::list(pool)` returns `Vec<PolicyRow>` sorted by `priority ASC`. Each `PolicyRow` contains a JSON string in the `conditions` column that must be deserialized to `Vec<PolicyCondition>`.

`action` column stores `"Allow"`, `"Deny"`, `"DenyWithAlert"` etc. — maps to `Decision` enum via `FromStr`.

### 3.6 `abac.rs` — ABAC Types (Read-Only)

`PolicyCondition` uses `#[serde(tag = "attribute", rename_all = "snake_case")]` — the JSON discriminant is `"attribute"`. Valid values in the DB JSON: `"classification"`, `"member_of"`, `"device_trust"`, `"network_location"`, `"access_context"`.

`Classification` uses `#[serde(rename_all = "UPPERCASE")]` — serialized as `"T1"`, `"T2"`, `"T3"`, `"T4"`.

`DeviceTrust` uses `#[serde(rename_all = "PascalCase")]` — serialized as `"Managed"`, `"Unmanaged"`, `"Compliant"`, `"Unknown"`.

`NetworkLocation` uses `#[serde(rename_all = "PascalCase")]` — `"Corporate"`, `"CorporateVpn"`, `"Guest"`, `"Unknown"`.

`AccessContext` uses `#[serde(rename_all = "lowercase")]` — `"local"`, `"smb"`.

### 3.7 `offline.rs` — Agent Offline Behavior (Context Only)

`OfflineManager` already has the correct fail-closed semantics: T3/T4 → DENY on cache miss, T1/T2 → ALLOW on cache miss. The agent's cache is populated by calls to `EngineClient::evaluate()`, which calls `POST /evaluate`. The endpoint just needs to exist.

### 3.8 `engine_client.rs` — Agent URL

Agents call `POST {base_url}/evaluate` where `base_url` defaults to `http://127.0.0.1:9090`. The agent handles retries and falls back to the offline cache on `EngineClientError::Unreachable`.

---

## 4. Open Questions for the Plan

### Q1: Should `/evaluate` require JWT auth?

**Arguments for auth:** Prevents unauthenticated policy probing.
**Arguments against:** The endpoint is called by agents on every file operation under high load; adding JWT validation on every request adds latency. Agents already authenticate via the heartbeat endpoint (shared-secret auth hash, not JWT). The agent's request body contains `AgentInfo` (machine name + user) which identifies the caller.

**Recommendation:** Keep `/evaluate` unauthenticated. Agent identity is established by the request body (`AgentInfo`). An attacker who can send HTTP requests to localhost:9090 already has code execution on the endpoint. If additional hardening is needed later, IP-based allowlisting via the existing rate limiter is a better fit.

### Q2: Is `PolicyStore::new` blocking or async?

The DB call in `PolicyStore::new` (loading all policies at startup) is inherently synchronous (SQLite). `spawn_blocking` is used everywhere else in this codebase for DB access. Option A (blocking `new`) matches the startup context in `main.rs` where async/sync doesn't matter. Option B (async `new`) requires the caller to be inside a tokio context.

**Recommendation:** `PolicyStore::new(pool: Arc<Pool>) -> anyhow::Result<Self>` as a **synchronous** constructor called directly in `main.rs` before the `#[tokio::main]` reactor starts (or inside it via `spawn_blocking`). Simpler and consistent with how the pool is opened.

### Q3: What is the refresh interval?

The CONTEXT says "configurable cadence (default: 5 minutes)". Options:
- **A. Hardcode in main.rs** as a constant (`REFRESH_INTERVAL_SECS = 300`)
- **B. CLI flag** (`--policy-refresh-secs <N>`)
- **C. SQLite config table** (single-row `policy_store_config`, like `siem_config`)

**Recommendation:** Start with **Option A (hardcoded constant)** in this phase. Option C can be a future enhancement if operators need to change it without restarting the server. The constant name should be visible and easily changeable (e.g., `const POLICY_REFRESH_INTERVAL: Duration = Duration::from_secs(300);` at the top of `policy_store.rs`).

### Q4: Does `policy_api.rs` stay or get deleted?

`policy_api.rs` has CRUD handlers (`list_policies`, `create_policy`, etc.) that duplicate the ones already in `admin_api.rs`. Those are dead code that should be deleted. Only `evaluate_handler` needs to survive and be moved.

**Recommendation:** Move `evaluate_handler` into `admin_api.rs` as a private helper. Delete `policy_api.rs` entirely (or keep it as a skeleton if the plan is to reuse it for a future policy-history endpoint).

### Q5: Error type for `policy_engine_error.rs`

`policy_api.rs` references `crate::policy_engine_error::PolicyEngineError` which doesn't exist. The only variant needed is `PolicyNotFound(String)`. This should be a simple `thiserror` enum.

**Recommendation:** Create `dlp-server/src/policy_engine_error.rs` with:
```rust
#[derive(Debug, thiserror::Error)]
pub enum PolicyEngineError {
    #[error("policy not found: {0}")]
    PolicyNotFound(String),
}
```

Then add `impl From<PolicyEngineError> for AppError` in `lib.rs` mapping `PolicyNotFound` → `AppError::NotFound`.

---

## 5. Condition Matching Algorithm

```
FOR each policy in cache (sorted by priority ASC):
    IF policy.enabled == false: SKIP
    FOR each condition in policy.conditions:
        IF NOT condition_matches(condition, request): BREAK (policy doesn't match)
    IF all conditions matched:
        RETURN EvaluateResponse { decision: policy.action, matched_policy_id: Some(policy.id), reason: ... }

# No policy matched — tiered default-deny
IF request.resource.classification in [T1, T2]:
    RETURN EvaluateResponse::default_allow()
ELSE:
    RETURN EvaluateResponse::default_deny()
```

### Operator semantics

| Operator | Classification | MemberOf | DeviceTrust | NetworkLocation | AccessContext |
|---|---|---|---|---|---|
| `"eq"` | `T1 == value` | groups.contains(sid) | `trust == value` | `loc == value` | `ctx == value` |
| `"neq"` | `T1 != value` | `!groups.contains(sid)` | `trust != value` | `loc != value` | `ctx != value` |
| `"in"` | error | groups contains ANY of list | error | error | error |
| `"not_in"` | error | groups contains NONE of list | error | error | error |

The CONTEXT says `"in"`/`"not_in"` apply only to `MemberOf`. For all other condition types, `"in"`/`"not_in"` should be treated as `false` (policy doesn't match) rather than an error — defensive matching.

---

## 6. Cache Invalidation Pattern

```
struct PolicyStore {
    cache: RwLock<Vec<Policy>>,
    pool: Arc<Pool>,
    refresh_interval_secs: u64,
}

fn invalidate(&self) {
    // Atomic swap: set cache to empty Vec, drop old in background
    let old = {
        let mut guard = self.cache.write();
        std::mem::swap(&mut Vec::new(), &mut *guard);
        // Re-load synchronously in this thread
        if let Ok(policies) = self.load_from_db() {
            *guard = policies;
        }
        // Vec already swapped out, dropped here
    };
}
```

This is the "flag-set-and-swap" pattern from the CONTEXT. The read path (`evaluate()`) only acquires a read lock:

```
fn evaluate(&self, request: &EvaluateRequest) -> EvaluateResponse {
    let cache = self.cache.read();
    // iterate cache, no blocking on reads
    ...
}
```

---

## 7. Background Refresh Task

```rust
// In main.rs after PolicyStore construction:
let store = Arc::clone(&state.policy_store);
let interval_secs = POLICY_STORE_REFRESH_INTERVAL_SECS;
tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
    loop {
        interval.tick().await;
        store.refresh();
    }
});
```

`PolicyStore::refresh(&self)` does a full reload from DB. It should log errors but not panic — a failed refresh means the stale cache is used for up to `interval_secs` more, which is acceptable.

---

## 8. Files to Create / Modify

| File | Action | Purpose |
|---|---|---|
| `dlp-server/src/policy_store.rs` | **Create** | `PolicyStore` struct, `evaluate()`, `refresh()`, `invalidate()`, `load_from_db()` |
| `dlp-server/src/policy_engine_error.rs` | **Create** | `PolicyEngineError` enum |
| `dlp-server/src/lib.rs` | **Modify** | Add `pub mod policy_store`, `pub mod policy_engine_error`, add `policy_store` to `AppState`, add `impl From<PolicyEngineError> for AppError` |
| `dlp-server/src/main.rs` | **Modify** | Construct `PolicyStore::new()`, spawn background refresh task |
| `dlp-server/src/admin_api.rs` | **Modify** | Add `use policy_store::PolicyStore` import, add `state.policy_store.invalidate()` to create/update/delete handlers, add `evaluate_handler` from `policy_api.rs`, add `POST /evaluate` route to `admin_router` |
| `dlp-server/src/policy_api.rs` | **Modify or delete** | Keep `evaluate_handler` (move to `admin_api.rs`), delete CRUD handlers |
| `dlp-server/src/admin_api.rs` tests | **Modify** | `spawn_admin_app()` needs to construct and inject a `PolicyStore` |

---

## 9. Risks and Mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| Serialization mismatch between DB JSON and `PolicyCondition` serde | Medium | Write unit tests that round-trip a `Policy` through `serde_json::to_string` / `from_str` before touching the DB layer |
| `evaluate_handler` accidentally exposed publicly without auth | Low | Explicit comment in code: "unauthenticated by design — AgentInfo in request body identifies caller" |
| Background refresh task panicking crashes the server | Low | `refresh()` catches errors and logs; loop continues |
| `PolicyStore::new` called twice (double-load) | Low | Construct once in `main.rs`; `Arc` is shared via `AppState` |
| Test `spawn_admin_app()` doesn't build without `PolicyStore` | High | Add `PolicyStore::new(&pool)` to test helper; use `parking_lot::RwLock` for cache |

---

## 10. Testing Strategy

### Unit tests (in `policy_store.rs`)
- `test_default_deny_t3_t4`: evaluate a T3 request with no policies → DENY
- `test_default_allow_t1_t2`: evaluate a T2 request with no policies → ALLOW
- `test_classification_eq_match`: policy with `Classification { op: "eq", value: T3 }` matches T3 request
- `test_classification_eq_no_match`: same policy doesn't match T1 request
- `test_memberof_in_match`: `MemberOf { op: "in", group_sid: ["S-1-5-21-512"] }` matches when subject.groups contains one
- `test_first_match_wins`: two policies both match — lowest priority wins
- `test_disabled_policy_skipped`: enabled=false policy never matches
- `test_cache_invalidation_reloads`: after `invalidate()`, subsequent `evaluate()` sees new policies

### Integration test (in `admin_api.rs`)
- `test_evaluate_returns_decision`: POST a valid `EvaluateRequest` to `/evaluate` → 200 with `EvaluateResponse`
- `test_evaluate_policy_matching`: create a policy via API, then POST a matching request → policy ID in response
- `test_evaluate_invalidation_on_create`: create policy, evaluate matching request, update policy, re-evaluate → new decision

---

## 11. What's Out of Scope

- Multi-replica policy sync (R-03) — deferred
- AD LDAP attribute resolution (R-05) — agent sends placeholder groups
- `PolicyStore::add_policy` / `update_policy` / `delete_policy` for in-store CRUD — admin API writes directly to DB; `PolicyStore` only reads
- Version history (`/policies/:id/versions`) — stub in `policy_api.rs` can stay as-is

---

*Research complete. Next: write `11-PLAN.md`.*
