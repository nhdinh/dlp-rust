# Phase 11: Implement /evaluate Endpoint — Context

**Gathered:** 2026-04-16
**Status:** Ready for planning
**Source:** /gsd-discuss-phase

> **NOTE:** Original roadmap goal (architectural split into separate `dlp-policy-engine` binary) is
> **not wanted**. Phase 11 implements the `/evaluate` endpoint inside `dlp-server` instead.
> R-03 (policy engine separation) remains on the roadmap but is deferred indefinitely.

<domain>
## Phase Boundary

Resurrect `dlp-server/src/policy_api.rs` (currently dead code) by:
1. Implementing `PolicyStore` with the ABAC evaluation engine
2. Wiring `POST /evaluate` into the admin_router
3. Loading policies from DB at startup and refreshing on a configurable cadence

`dlp-server` is the single policy source of truth. No architectural split.
`dlp-agent`'s `EngineClient` will have a working `/evaluate` endpoint to call.

**In scope:**
- `dlp-server/src/policy_store.rs` — new `PolicyStore` type with ABAC evaluation logic
- `dlp-server/src/policy_api.rs` — wire into `admin_router` via `Arc<PolicyStore>` in `AppState`
- `dlp-server/src/lib.rs` — add `policy_store` module, add `PolicyStore` to `AppState`
- `dlp-server/src/main.rs` — construct and seed `PolicyStore` on startup, start refresh task

**Out of scope:**
- Separate `dlp-policy-engine` binary or repository split
- Multi-replica policy sync (R-03 — deferred)
- Changes to `dlp-agent` (EngineClient already calls `/evaluate`; offline cache is adequate)
- Changes to ABAC types in `dlp-common/src/abac.rs` (already complete)

</domain>

<decisions>
## Implementation Decisions

### D-01: ABAC Evaluation Architecture — Tiered Default-Deny

**Decision:** When no policy matches an `EvaluateRequest`, the default decision is tiered:
- **T1 (Public) / T2 (Internal):** `Decision::ALLOW` — non-sensitive resources allowed by default
- **T3 (Confidential) / T4 (Restricted):** `Decision::DENY` — sensitive resources denied by default

Rationale: Balances security (fail-closed on sensitive data) with usability (no false positives on
public data). Consistent with the "Default Deny for sensitive data" principle in CLAUDE.md.

The `EvaluateResponse::default_deny()` and `default_allow()` methods in `dlp-common/src/abac.rs`
already exist — the `PolicyStore` calls the appropriate one based on resource classification.

### D-02: PolicyStore Policy Loading — Read + Cache with Refresh

**Decision:** `PolicyStore` loads all policies from `PolicyRepository` into an in-memory `Vec`
at startup, then refreshes the in-memory cache on a configurable interval (default: 5 minutes).

Startup: `PolicyStore::new(pool)` blocks briefly while loading all policies from DB.
Background: A background task re-loads policies from DB every N minutes.
Admin mutations: After a policy is created/updated/deleted via the admin API, the in-memory
cache is immediately invalidated so the next `/evaluate` request sees the new state.

**Cache invalidation on write:** The policy CRUD handlers in `admin_api.rs` call
`state.policy_store.invalidate()` after committing to the DB and before returning the HTTP response.
This is a simple flag-set-and-swap pattern — no locks needed on the read path.

Rationale: Startup-only loading means admin policy changes require a server restart to take effect.
Periodic refresh alone means changes take up to N minutes to propagate. Immediate invalidation
on write closes that gap while keeping the read path simple (no lock on every eval).

### D-03: Evaluation Ordering — First-Match Wins

**Decision:** Policies are evaluated in priority order (lowest `priority` number first). The first
policy whose conditions all match is applied and evaluation stops. This is the existing first-match
semantics already defined in `dlp-common/src/abac.rs`.

Rationale: Standard ABAC evaluation order. Priority is a u32 (lower = earlier). The agent's
`OfflineManager` caches decisions keyed by `(path, user_sid)` — the cache is invalidated when
the engine is reachable and returns a new decision.

### D-04: Policy Condition Matching

**Decision:** `PolicyCondition` variants are matched as follows:
- `Classification { op, value }` — compares `request.resource.classification` to `value` using `op`
- `MemberOf { op, group_sid }` — checks if `request.subject.groups` contains `group_sid`
- `DeviceTrust { op, value }` — compares `request.subject.device_trust` to `value`
- `NetworkLocation { op, value }` — compares `request.subject.network_location` to `value`
- `AccessContext { op, value }` — compares `request.environment.access_context` to `value`

All operators (`op` string): `"eq"`, `"neq"`, `"in"`, `"not_in"`. `"in"`/`"not_in"` apply to
`MemberOf` only (list membership). All others use `"eq"`/`"neq"`.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### ABAC types (already implemented)
- `dlp-common/src/abac.rs` — `EvaluateRequest`, `EvaluateResponse`, `Policy`, `PolicyCondition`,
  `Decision`, `Subject`, `Resource`, `Environment`, `Action`; `EvaluateResponse::default_deny()` /
  `default_allow()` methods
- `dlp-common/src/classification.rs` — `Classification` enum (T1–T4 tiers)

### Repository layer (Phase 99 — complete)
- `dlp-server/src/db/repositories/policies.rs` — `PolicyRepository::list()`, `get_by_id()`;
  `PolicyRow`, `PolicyUpdateRow` types
- `dlp-server/src/db/unit_of_work.rs` — `UnitOfWork` with RAII rollback
- Phase 99 context: `.planning/phases/99-refactor-db-layer-to-repository-unit-of-work/99-CONTEXT.md`

### Agent integration
- `dlp-agent/src/engine_client.rs` — `EngineClient::evaluate()` calls `POST /evaluate` on the server;
  already wired, just needs a working endpoint
- `dlp-agent/src/offline.rs` — `OfflineManager::evaluate()` falls back to cache on unreachable;
  fail-closed on T3/T4 cache miss, fail-open on T1/T2

### Dead code to revive
- `dlp-server/src/policy_api.rs` — currently orphaned (not in `Cargo.toml`/`lib.rs`);
  handlers exist but `PolicyStore` type doesn't; this file is the template for the evaluate handler

### Existing patterns
- `dlp-server/src/admin_api.rs` — policy CRUD handlers using `PolicyRepository::list/get_by_id/insert/update/delete`
- `dlp-server/src/lib.rs` — `AppState` struct, `AppError` variants
- `dlp-server/src/main.rs` — startup sequence (pool, SIEM, alert, AD client)

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `EvaluateResponse::default_deny()` / `default_allow()` — already implemented in `dlp-common`
- `PolicyRepository::list(pool)` — returns all `PolicyRow` sorted by priority
- `spawn_blocking` pattern — DB access already offloaded to sync thread pool
- `dlp-common/audit.rs` `AuditEvent` — event types ready to emit for evaluation logging

### Established Patterns
- `AppState` holds shared state (pool, SIEM, alert router, AD client); `PolicyStore` added here
- Background task spawning pattern: `tokio::spawn` with shutdown signal receiver
- Cache invalidation: atomic swap (set new data, drop old) without locking reads

### Integration Points
- `AppState` in `lib.rs` — add `policy_store: Arc<PolicyStore>` field
- `main.rs` — construct `PolicyStore::new(&pool)` after pool init, spawn background refresh task
- `admin_api.rs` policy CRUD handlers — call `state.policy_store.invalidate()` after DB commit
- `admin_router()` in `admin_api.rs` — merge `/evaluate` route from `policy_api.rs` into this router

### Orphaned Code
- `dlp-server/src/policy_api.rs` — file exists but not compiled; `PolicyStore` type doesn't exist
- `PolicySyncer` in `policy_sync.rs` — lives in dlp-server; push direction is wrong for current
  architecture (engine → replicas, but engine doesn't exist as separate binary); sync is deferred

</code_context>

<specifics>
## Specific Implementation Notes

### PolicyStore API (target)

```rust
// src/policy_store.rs
pub struct PolicyStore { /* interior: RwLock<Vec<Policy>> + Arc<Pool> */ }

impl PolicyStore {
    /// Blocks briefly — loads all policies from DB synchronously.
    pub fn new(pool: Arc<Pool>) -> anyhow::Result<Self>;

    /// Immediately invalidates the in-memory cache.
    /// Called by admin CRUD handlers after DB commit.
    pub fn invalidate(&self);

    /// Returns a decision for the given request.
    /// Reads in-memory cache only — no DB call on the hot path.
    pub async fn evaluate(&self, request: &EvaluateRequest) -> EvaluateResponse;

    /// Re-reads all policies from DB and replaces the cache.
    /// Called by the background refresh task.
    fn refresh(&self);
}
```

### app_state changes

Add to `AppState` in `lib.rs`:
```rust
pub struct AppState {
    pub pool: Arc<db::Pool>,
    pub policy_store: Arc<PolicyStore>,  // ← new
    pub siem: siem_connector::SiemConnector,
    pub alert: alert_router::AlertRouter,
    pub ad: Option<AdClient>,
}
```

### /evaluate handler (from policy_api.rs)

```rust
async fn evaluate_handler(
    State(store): State<Arc<PolicyStore>>,
    Json(request): Json<EvaluateRequest>,
) -> Result<Json<EvaluateResponse>, AppError> {
    let response = store.evaluate(&request).await;
    Ok(Json(response))
}
```

### Tiered default-deny logic

```rust
fn default_decision(classification: Classification) -> Decision {
    match classification {
        Classification::T1 | Classification::T2 => Decision::ALLOW,
        Classification::T3 | Classification::T4 => Decision::DENY,
    }
}
```

### Background refresh task

```rust
tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(REFRESH_INTERVAL_SECS));
    loop {
        interval.tick().await;
        store.refresh();
    }
});
```

</specifics>

<deferred>
## Deferred Ideas

- **Policy engine separation (R-03):** Original Phase 11 goal — not wanted at this time. Remains
  on roadmap as a potential future phase but is not planned.
- **Multi-replica policy sync:** `PolicySyncer` lives in dlp-server but the push model requires
  an engine → replicas architecture. Deferred until/unless a separation is revisited.
- **AD LDAP real attribute resolution (R-05):** `Subject::groups` uses empty placeholders until
  Phase 7 provides real AD data. Evaluation works with whatever groups are present.

---

*Phase: 11-policy-engine-separation*
*Context gathered: 2026-04-16 via /gsd-discuss-phase*
