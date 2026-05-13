---
phase: 61
reviewers: [codex, opencode, claude]
reviewed_at: 2026-05-13T07:45:00Z
review_cycle: 5
plans_reviewed: [61-01-PLAN.md, 61-02-PLAN.md, 61-03-PLAN.md, 61-04-PLAN.md]
---

# Cross-AI Plan Review — Phase 61

## Review Cycle History

- **Cycle 1 (2026-05-13T01:05:00Z)**: Claude CLI + OpenCode reviewed initial plans. Identified 5 HIGH, 7 MEDIUM, 7 LOW concerns.
- **Cycle 2 (2026-05-13)**: Plans revised to address all Cycle 1 concerns. OpenCode re-reviewed revised plans. Codex CLI unavailable (401 Unauthorized).
- **Cycle 3 (2026-05-13T10:30:00Z)**: OpenCode re-reviewed revised plans (Cycle 2 + additional fixes). Codex CLI still unavailable (401 Unauthorized).
- **Cycle 4 (2026-05-13T07:28:57Z)**: OpenCode re-reviewed revised plans (Cycle 3 fixes). Claude CLI reviewed Cycle 4 plans. Codex CLI still unavailable.
- **Cycle 5 (2026-05-13T07:45:00Z)**: Codex CLI + OpenCode + Claude CLI reviewed current plans. All three CLIs available and participated.

---

## Codex Review (Cycle 5)

### Summary

The phase is directionally sound and covers the core workflow: durable approval records, signed approval tokens, Data Owner and Board grant paths, agent-side validation, and operator UI. The biggest risks are cross-crate boundary mistakes, token/type placement, revocation semantics, and delivery reliability. Several details currently conflict across plans, especially around `PolicyStore`, active-approval sync endpoint ownership, and `CachedApproval` depending on server-only claims. The plans can achieve Phase 61, but they need sharper contracts between `dlp-common`, `dlp-server`, and `dlp-agent` before implementation.

### Strengths

- Establishes shared approval domain types early, which is the right first dependency for later waves.
- SQLite schema includes constraints and indexes, reducing invalid state risk.
- Repository TOCTOU guard for grant transitions is a good concurrency control pattern.
- Ed25519 compilation spike is prudent given JWT + EdDSA ecosystem friction in Rust.
- Using `PRAGMA user_version` makes migration state explicit.
- T4 grant path explicitly verifies Board signature before token issuance.
- Audit event additions are included in the API wave.
- Three-stage pipeline matches the critical invariant.
- Re-validating JWT on every cache read is conservative and appropriate for enforcement code.

### Concerns

- **HIGH:** `CachedApproval` in `dlp-common` depends on `ApprovalClaims` in `dlp-server/src/approval_token.rs`. That creates an invalid crate dependency direction. Shared token claims must live in `dlp-common`, or `CachedApproval` must move out of common.
- **HIGH:** `SCHEMA_VERSION = 2` may collide with existing migrations unless the current database version is confirmed. This needs alignment with the existing schema migration system.
- **HIGH:** `revoke_approval` reuses `update_state` with `WHERE status='pending'`, so approved approvals cannot be revoked.
- **HIGH:** Fire-and-forget token push is insufficient as the only delivery path. If the push fails, the server may mark approved while the agent never receives the token.
- **HIGH:** `PUT /admin/board-public-key` is a very sensitive endpoint. The plan does not mention authorization level, audit trail, key rotation, fingerprint confirmation, or dual-control.
- **HIGH:** `sync_active_approvals` takes `policy_store: &PolicyStore`, but the plan says `PolicyStore` is in `dlp-server`. The agent cannot depend on server internals.
- **HIGH:** `GET /agent/approvals/active` direction is ambiguous. The agent should call the server endpoint; it should not call itself.
- **HIGH:** Approval override must not bypass other deny reasons beyond ABAC. The plan says NTFS allow + ABAC deny, but implementation must preserve deny for malformed request, missing labels, unclassified object where policy requires classification, token validation failure, tamper detection, etc.
- **MEDIUM:** Hardcoding `WHERE status='pending'` inside generic `update_state` only fits approve/reject transitions. It will break revoke later if reused.
- **MEDIUM:** Cache key string format using raw colon separators is fragile if any component can contain `:`. SIDs and paths/destinations may.
- **MEDIUM:** Approval token service depending on "Phase 47 encrypted key storage" needs a concrete integration point, key ID strategy, rotation behavior, and startup failure mode.
- **MEDIUM:** Endpoint naming is confusing: `GET /agent/approvals/active` sounds like it lives on the agent, but per context the agent calls it on the server during startup.
- **MEDIUM:** T4 canonical message includes `valid_until`; the plan must guarantee exact byte-for-byte canonicalization, timezone format, and no alternate encodings.
- **MEDIUM:** Grant should validate requested scope against the original approval request. Otherwise an operator or malicious request can broaden scope at grant time.
- **MEDIUM:** Pagination and filtering need stable ordering to avoid missed/duplicated rows while approvals change.
- **MEDIUM:** Resolving `resource.path -> data_object_id` via `LabelService` before cache lookup may fail for paths without labels, renamed files, removable media, or cloud resources. Failure behavior must be explicit.
- **MEDIUM:** JWT re-verification on every cache read is secure but may be expensive under high-frequency file hooks. Need benchmark or parsed verified cache with expiry/revocation checks.
- **MEDIUM:** Revocation propagation is not fully covered. If an approved token is revoked server-side, an agent with cached token may continue allowing until expiry unless it syncs or receives revocation.
- **MEDIUM:** `chrono::DateTime<Utc>` is fine internally, but token claims usually use numeric `exp`/`nbf`/`iat`. The boundary format should be consistent.
- **LOW:** The plan mentions foreign keys but does not specify referenced tables or `ON DELETE` behavior.
- **LOW:** `POST /admin/approvals` overlaps with `POST /agent/approval-request`; the actor model should be explicit.
- **LOW:** DashMap is reasonable, but cleanup/expiry eviction needs to be specified.
- **LOW:** T4 copy-paste signing workflow is operationally fragile unless the canonical message has copy support and exact formatting guarantees.
- **LOW:** `chrono::Duration::hours(form.expiry_hours as i64)` can accept invalid or excessive values unless input is bounded.
- **LOW:** Filtering through all statuses is fine, but expired may be derived rather than stored; the UI should match backend semantics.
- **LOW:** Pagination plus changing approval states may create cursor jumps unless stable sort is defined.

### Suggestions

- Move `ApprovalClaims`, canonical token scope structs, and validation helpers into `dlp-common`.
- Split repository methods by state transition: `grant_pending`, `reject_pending`, `revoke_active`, `expire_active`, rather than one generic `update_state`.
- Use a structured cache key type or encoded tuple, not delimiter-joined strings.
- Make token delivery pull-based authoritative: server stores approved token, agent syncs active approvals on startup and periodically. Push can remain an optimization.
- Add separate revoke repository logic: allowed from `approved`, maybe also `pending`, with clear semantics.
- Require strong authorization and audit for board public key changes; include key fingerprint in T4 grant audit events.
- Define canonical T4 message as a shared function in `dlp-common` and test golden vectors.
- Define an agent-local approval cache/service type in `dlp-agent`, using shared structs from `dlp-common`.
- Treat server sync as authoritative and add periodic refresh or revocation polling, not just startup sync.
- Cache verified claims plus the original token signature metadata; revalidate signature on insert and periodically if needed, while checking expiry on each read.
- Add negative-path tests for NTFS deny, ABAC allow, expired token, wrong action, wrong destination, wrong object, wrong SID, revoked token, and invalid signature.
- Use server-provided canonical message, or a shared `dlp-common` formatter, not independently reconstructed TUI text.
- Add explicit keyboard paths for revoke and reject, including confirmation prompts.

### Risk Assessment

**Overall risk: HIGH.**

The phase touches authorization, cryptographic approval, distributed cache state, admin APIs, agent enforcement, and operator UI. The core architecture is plausible and aligned with the success criteria, but several plan details would cause either compile-time crate dependency failures or security/correctness bugs if implemented as written. The highest-priority fixes are: (1) move shared claims into `dlp-common`, (2) split approval state transitions by valid source state, (3) make server-side active approval sync authoritative and push optional, (4) define revocation propagation and cache invalidation, (5) clarify endpoint ownership between server and agent, (6) add golden tests for T4 canonical messages and token validation.

---

## OpenCode Review (Cycle 5)

### Summary

The four-plan decomposition into Foundation -> Server API -> Agent Integration -> Admin TUI is well-structured with clear wave dependencies and a sensible risk-first approach (compilation spike in Task 0). The crypto choices (Ed25519, JWT JWS, Phase 47 Envelope) are appropriate and reuse existing infrastructure. However, several agent-side architectural details are underspecified — particularly around public key distribution, offline mode behavior, and where exactly the three-stage pipeline lives — which creates rework risk when Plan 03 is executed against the actual agent codebase. The DB migration pattern (`PRAGMA user_version`) introduces an approach the project doesn't currently use, and the audit event types are not extended despite WORKFLOW-06's requirements.

### Strengths

- Compilation spike (Task 0) correctly de-risks `ed25519-dalek` v2 + `jsonwebtoken` 9.x `pkcs8` API compatibility before writing service code
- TOCTOU guard using `WHERE status='pending'` + `rows_affected` check is correct for grant/reject races
- JWT re-verification on every cache read is appropriate defense-in-depth
- T4 canonical message format with embedded `jti` prevents replay attacks on board signatures
- `scope_matches` with hierarchical wildcards (`USB:*`) is well-designed for destination scope
- Cache key design (`{sid}:{obj_id}:{action}:{dst}`) prevents scope bypass via destination inclusion
- Wave ordering is correct: Foundation (types/repo) -> API + Agent in parallel -> TUI last

### Concerns

- **HIGH: Agent has no mechanism to obtain the server's Ed25519 public key** — Plan 03 describes JWT signature re-verification on every cache read, but the agent has no way to fetch or cache the server's public key. The signing key lives in the Phase 47 encrypted `secrets_jwt` table (DPAPI-bound, machine-specific), so the public key varies per deployment. Without `GET /agent/approvals/public-key` or key distribution via agent config, every JWT verification on the agent will fail. This blocks the entire Plan 03.
- **HIGH: Approvals are unusable offline** — The agent's `OfflineManager` has no mechanism to validate approval tokens when the server is unreachable. No cached public key, no way to check JWT signature, and no fallback. Any legitimate approval granted just before a network partition becomes unenforceable. If the agent enforces fail-closed (DENY when approval can't be verified), users are blocked. If it fail-opens (ALLOW), security is defeated. The plans must specify offline behavior explicitly.
- **MEDIUM: Three-stage pipeline location is ambiguous** — Plan 03 says "Three-stage ABAC pipeline (NTFS -> ABAC -> approval override)" in "PolicyStore", but the actual evaluation flow is split: NTFS enforcement is agent-side (in `interception/mod.rs`), ABAC evaluation is server-side (`PolicyStore::evaluate()` via `POST /evaluate`), and approval tokens exist on the server. Where does the third stage live? If agent-side: modify `OfflineManager::evaluate()` to check the approval cache after a DENY response. If server-side: `PolicyStore::evaluate()` needs approval token lookup by `(sid, obj_id)` at evaluation time, which is expensive and leaks approval data into the hot path. This must be clarified before Plan 03 execution.
- **MEDIUM: EventType enum is not extended for approval events** — `WORKFLOW-06` requires approval-aware audit events (request, grant, use, expiry, revocation), but the plans do not add new `EventType` variants. The existing enum at `dlp-common/src/audit.rs:30` uses `SCREAMING_SNAKE_CASE` serde. At minimum: `APPROVAL_REQUESTED`, `APPROVAL_GRANTED`, `APPROVAL_REJECTED`, `APPROVAL_REVOKED`, `APPROVAL_EXPIRED`. These must be added to `routed_to_siem()` and `triggers_alert()`.
- **MEDIUM: DB migration pattern doesn't match existing codebase** — Plan 01 Task 4 says "Database migration with PRAGMA user_version", but the project's established pattern (in `dlp-server/src/db/mod.rs`) uses `run_alter()` inside `run_migrations()` for additive changes and `CREATE TABLE IF NOT EXISTS` in `init_tables()` for new tables. Introducing `PRAGMA user_version` as a new mechanism adds complexity and potential for drift. The `approvals` table should be added directly in `init_tables()` following existing conventions.
- **MEDIUM: Revoke race condition in TOCTOU guard** — The TOCTOU guard uses `WHERE status='pending'` for state transitions, but revocation must also match `'approved'` status. Grant: `WHERE status='pending'` -> `'approved'` (correct). Reject: `WHERE status='pending'` -> `'rejected'` (correct). Revoke: `WHERE status='pending'` OR `status='approved'` -> `'revoked'` (must handle both states, otherwise a granted approval can never be revoked before expiry).
- **MEDIUM: ApprovalRepository location unspecified** — Types go in `dlp-common` (correct), but the repository implementation location is not stated. Following existing conventions (`policies.rs`, `labels.rs`), it should be `dlp-server/src/db/repositories/approvals.rs` with `pub mod approvals;` added to `repositories/mod.rs`.
- **LOW: Agent push-token endpoint contradicts poll-based architecture** — The server endpoint `POST /agent/approval-token` implies server-to-agent push, but the agent communicates via poll (heartbeat every 30s, config poll every 60s, registry/device cache polls). There is no push mechanism. The token delivery should be folded into the agent's existing heartbeat iteration or a separate approval poll loop.
- **LOW: T4 board signature logistics unclear** — The T4 flow requires board members to compute an Ed25519 signature over the canonical message. The plan doesn't specify how the canonical message reaches the board member or how the signature is returned to the admin.
- **LOW: Phase 60 dependency is fragile** — T3 routing depends on the Data Owner concept from Phase 60. Resources classified at interception time (content-based scan, no pre-existing label) have no department and therefore no routable Data Owner. The plans don't address fallback routing for unlabeled T3 resources.
- **LOW: Cache key scope grammar is undefined** — The cache key includes `dst` (destination_scope), and `scope_matches` supports hierarchical wildcards, but no grammar is defined. Without a defined grammar, scoped approval creation in the admin UI is ambiguous.

### Suggestions

1. Add public key distribution: `GET /agent/approvals/public-key` endpoint returning the raw 32-byte Ed25519 public key (hex-encoded). The agent caches it in a new `ApprovalCache` at startup via `run_loop_init()`.
2. Specify offline behavior: When the agent is offline and a previously cached, non-expired approval token exists, the agent should honor it (the JWT's `exp` claim was already valid when cached). Only tokens that can't be signature-verified should fail closed.
3. Clarify pipeline location: State explicitly whether the three-stage pipeline is agent-side (modify `OfflineManager::evaluate()` to check approval cache post-DENY) or server-side. Recommend agent-side.
4. Extend EventType: Add `APPROVAL_REQUESTED`, `APPROVAL_GRANTED`, `APPROVAL_REJECTED`, `APPROVAL_REVOKED`, `APPROVAL_EXPIRED` variants to `dlp-common/src/audit.rs`. Wire them into `routed_to_siem()` (all true).
5. Remove `PRAGMA user_version` from plan — Use `CREATE TABLE IF NOT EXISTS approvals` in `init_tables()` and `run_alter()` in `run_migrations()`, matching existing project conventions.
6. Fix revoke TOCTOU: `UPDATE approvals SET status='revoked' WHERE id=? AND status IN ('pending','approved')`.
7. Add approval poll to agent startup — Add an `ApprovalCache` poll loop (every 60s) that calls `GET /agent/approvals/active` to sync active approvals. Remove the push endpoint concept.
8. Define scope grammar in the implementation contract (e.g., `USB:<instance_id>`, `CLIPBOARD`, `FILE:<path>`, `NET:<host>:<path>`).

### Risk Assessment

**Overall: MEDIUM.**

The crypto architecture, TOCTOU guard, cache strategy, and wave ordering are sound. The primary risk is the underspecified agent-side integration — particularly public key distribution and the three-stage pipeline location. If Plan 03 is executed without these clarifications, expect rework when the implementer discovers the agent has no way to verify JWT signatures. The DB migration approach should also be aligned with project conventions before Plan 01 execution.

---

## Claude Review (Cycle 5)

### Summary

Phase 61 plans are well-structured and follow established patterns from prior phases. The four-plan wave approach (foundation -> API -> agent integration -> TUI) is logical. However, several critical gaps persist across cycles: cross-crate type dependency issues, offline approval validation gaps, ambiguous pipeline location, and operational details around token delivery. Security concerns around board key management, token delivery reliability, and cache key fragility need addressing before execution.

### Strengths

- Wave ordering (01 -> 02/03 -> 04) correctly sequences dependencies
- Threat model included in every plan with STRIDE register
- DashMap + background sweep for agent cache is appropriate for read-heavy workload
- Cache key includes SID, preventing cross-user approval replay
- Reuse of existing patterns (PolicyList, EngineClient, repository pattern) reduces risk
- JWT (Ed25519) token format is compact and cryptographically sound
- Audit events and alert routing integrated into all state-changing operations
- Ed25519 compilation spike (Task 0) prevents mid-implementation blockers
- TOCTOU guard with rows_affected check is correctly implemented
- T4 canonical message with jti anti-replay is cryptographically sound

### Concerns

- **HIGH — Cross-crate type dependency will fail compilation:** `dlp-common/src/approval.rs` defines `CachedApproval { claims: ApprovalClaims, ... }`, but `ApprovalClaims` is defined in `dlp-server/src/approval_token.rs`. Since `dlp-server` depends on `dlp-common`, not vice versa, this creates an unresolvable circular dependency. The plan must either move `ApprovalClaims` to `dlp-common` or change `CachedApproval` to store claims fields directly.
- **HIGH — Agent cannot verify approval tokens offline:** There is no mechanism for the agent to obtain the server's Ed25519 public key. `check_approval` re-verifies JWT signatures on every cache read, but the agent has no `ApprovalTokenService` with the verifying key. If the agent is offline, cached approvals cannot be validated. A `GET /agent/approvals/public-key` endpoint and agent-side key caching is needed.
- **HIGH — Revoke TOCTOU guard is functionally broken:** Plan 01 Task 2 defines `update_state` with `WHERE status = 'pending'` hardcoded in the SQL. Plan 02 Task 2 uses this same method for `revoke_approval`, which must match `status = 'approved'`. The current plan would cause revoke to silently no-op (returning 0 rows) because the WHERE clause mismatches.
- **HIGH — Token delivery has no retry mechanism:** Plan 02 says "Server pushes token to agent via HTTP POST" — but a transient network blip or agent restart between grant and push means the token is lost. The server marks the approval as "approved" and the token is signed, but the agent never receives it. The user sees "approved" in the TUI but the agent still denies the operation.
- **MEDIUM — `/agent/approval-token` endpoint location contradicts push architecture:** Plan 02 says the server "pushes token to agent via HTTP POST to `/agent/approval-token`", but Plan 03 Task 2 defines this handler in `dlp-server/src/agent_api.rs` — a server file. If the server pushes to the agent, the handler belongs in the agent's HTTP server, not the server's API. If the agent polls the server, there is no push mechanism.
- **MEDIUM — Approval audit event types not wired into SIEM routing:** Plan 02 Task 1 adds `ApprovalEventType` variants but does not explicitly specify integration with `routed_to_siem()` or `triggers_alert()`. Without explicit wiring instructions, the implementer may miss connecting approval events to the existing audit pipeline.
- **MEDIUM — Migration mechanism may conflict with existing conventions:** Plan 01 Task 4 introduces `PRAGMA user_version` for schema versioning. The existing codebase may already use `run_alter()` inside `run_migrations()` for additive changes. Introducing a parallel migration mechanism risks drift.
- **MEDIUM — Board public key unrestricted:** `system_kv` stores board pubkey but no plan restricts who can update it. A compromised admin could swap the key and self-approve T4.
- **MEDIUM — Cache key string format is fragile:** Raw colon separators in `approval_cache_key` can break if SIDs or paths contain `:` characters. Windows SIDs contain dashes, not colons, but paths and destination scopes could.
- **MEDIUM — JWT re-verification on every cache read may be expensive:** Under high-frequency file hooks, Ed25519 verification (~50us) multiplied by thousands of operations per second could become a bottleneck. No performance target is specified.
- **LOW — `PolicyStore` type referenced from agent code:** Plan 03 Task 2's `sync_active_approvals` takes `policy_store: &PolicyStore`, but `PolicyStore` is defined in `dlp-server`. The agent crate cannot reference server types.
- **LOW — T4 board signature out-of-band channel unspecified:** The canonical message is displayed in the TUI detail screen, but there is no mechanism for a board member to receive this message, sign it, and return the hex signature.
- **LOW — `chrono::Duration::hours` may not exist:** Plan 04 Task 3 uses `chrono::Duration::hours(form.expiry_hours as i64)`. Depending on the chrono version, this may need to be `chrono::TimeDelta::try_hours()`.
- **LOW — Agent startup sync endpoint naming is confusing:** `GET /agent/approvals/active` sounds like an agent-hosted endpoint, but the agent calls the server. The naming convention should be clarified.

### Suggestions

1. Move `ApprovalClaims` to `dlp-common/src/approval.rs` (or inline its fields into `CachedApproval`) to eliminate the circular dependency.
2. Add `GET /agent/approvals/public-key` endpoint and agent-side key caching so offline JWT verification works.
3. Fix `update_state` signature to accept `expected_current_status: &str` and use it in the WHERE clause; call with `"pending"` for grant/reject and `"approved"` for revoke.
4. Clarify token delivery architecture — either define `/agent/approval-token` as an agent-side endpoint (and document the agent's HTTP server), or remove the server push and rely entirely on agent polling of `/agent/approvals/active`.
5. Explicitly document SIEM wiring — specify that `ApprovalEventType` variants map to `AuditEvent` records and are routed through `siem_connector::relay_events()` and `alert_router::send_alert()`.
6. Verify existing migration convention in `dlp-server/src/db/mod.rs` before implementing `PRAGMA user_version`; use the project's established pattern.
7. Define `ApprovalCache` in `dlp-agent` instead of reusing the server `PolicyStore` type for agent-side caching.
8. Add an operational note about how board members receive canonical messages and return signatures.
9. Consider using a structured cache key type or base64-encoded tuple instead of colon-delimited strings.
10. Add performance benchmark for JWT verification under load; consider caching verified claims with periodic re-verification if needed.

### Risk Assessment

**HIGH.**

The core architecture is well-considered and the prior review cycles have genuinely improved the plans. However, the cross-crate type dependency is a hard compilation blocker that would stall Plan 01 mid-execution, the revoke TOCTOU bug would produce a subtle functional defect (revoke silently failing), and the offline verification gap means the approval system fails during network partitions — a realistic enterprise scenario. These three issues should be fixed in the plans before execution begins. The remaining LOW concerns can be addressed during implementation without significant rework.

---

## Consensus Summary (Across All Cycles Including Cycle 5)

### Cycle 1 -> Cycle 2 -> Cycle 3 -> Cycle 4 -> Cycle 5: Resolution Status

All 5 original Cycle 1 HIGH concerns remain RESOLVED:
- Missing approval creation endpoint -- RESOLVED (Plan 02 Task 2)
- Ed25519 API incompatibility -- RESOLVED (Plan 01 Task 0 compilation spike)
- Cache key mismatch -- RESOLVED (Plan 03 Task 1: LabelService path-to-UUID resolution)
- Token delivery gap -- RESOLVED (Plan 02 Task 2: server push + Plan 03 Task 2: agent endpoint)
- Unencrypted signing key -- RESOLVED (Plan 01 Task 3: Phase 47 Envelope)

All Cycle 2/3/4 NEW concerns have been partially addressed in plan revisions.

### Cycle 5: New / Remaining Concerns

| Concern | Severity | Reviewer | Status |
|---------|----------|----------|--------|
| Cross-crate type dependency (CachedApproval references ApprovalClaims in dlp-server) | **HIGH** | Codex, Claude | **NEW** — Not previously raised by these reviewers |
| Agent cannot verify approval tokens offline (no public key distribution) | **HIGH** | Codex, OpenCode, Claude | **NEW** — All three reviewers independently identified |
| Revoke TOCTOU guard functionally broken (update_state hardcodes WHERE status=pending) | **HIGH** | Codex, Claude | **NEW** — Confirmed by two reviewers |
| Token delivery has no retry mechanism | **HIGH** | Codex, Claude | **NEW** — Delivery reliability gap |
| Board public key endpoint lacks authorization/audit | **HIGH** | Codex | **NEW** — Security gap |
| Agent push-token contradicts poll architecture | **MEDIUM** | Codex, OpenCode, Claude | **NEW** — All three reviewers agree |
| Three-stage pipeline location ambiguous | **MEDIUM** | OpenCode, Claude | **NEW** — Agent-side vs server-side unclear |
| EventType enum not extended for approval events | **MEDIUM** | OpenCode, Claude | **NEW** — WORKFLOW-06 gap |
| DB migration pattern conflicts with existing conventions | **MEDIUM** | Codex, OpenCode, Claude | **NEW** — All three reviewers agree |
| Cache key string format fragile (colon separators) | **MEDIUM** | Codex, Claude | **NEW** — SIDs/paths may contain colons |
| JWT re-verification performance concern | **MEDIUM** | Codex, Claude | **NEW** — High-frequency hooks |
| Revocation propagation not covered | **MEDIUM** | Codex | **NEW** — Cache invalidation gap |
| ApprovalRepository location unspecified | **MEDIUM** | OpenCode | **NEW** — Convention gap |
| T4 board signature out-of-band channel unspecified | **LOW** | Codex, Claude | **NEW** — Operational gap |
| PolicyStore type referenced from agent code | **LOW** | Claude | **NEW** — Circular dependency |
| chrono::Duration::hours may not exist | **LOW** | Claude | **NEW** — API compatibility |
| Phase 60 dependency fragile (unlabeled T3 resources) | **LOW** | OpenCode | **NEW** — Fallback routing gap |
| Cache key scope grammar undefined | **LOW** | OpenCode | **NEW** — Configuration ambiguity |

### Agreed Strengths (All Cycles)

- Wave ordering and dependency sequencing is correct
- Threat modeling with STRIDE register is thorough
- DashMap approval cache is appropriate for read-heavy, write-rare workload
- Cache key includes SID preventing cross-user replay
- Reuse of existing architectural patterns reduces implementation risk
- T4 Board signature adds a meaningful cryptographic boundary
- Ed25519 compilation spike (Task 0) prevents mid-implementation blockers
- TOCTOU guard with rows_affected check is correctly implemented (for grant/reject)
- JWT re-verification on cache read eliminates cache-poisoning attack vector
- Encrypted key storage (Phase 47 Envelope) is the correct security posture
- T4 canonical message with jti anti-replay is cryptographically sound

### Divergent Views

- **Offline behavior**: OpenCode and Claude raised HIGH concern about offline approval validation. Codex also flagged. All three agree this is a gap.
- **Pipeline location**: OpenCode and Claude flagged ambiguity about where the three-stage pipeline lives. Codex also noted `PolicyStore` confusion. Consensus: needs clarification.
- **Migration pattern**: OpenCode and Claude prefer existing `init_tables()` + `run_alter()` conventions over `PRAGMA user_version`. Codex also flagged collision risk. All three agree.
- **Push vs poll**: OpenCode argues token delivery should be poll-based. Claude says clarify architecture. Codex says make pull authoritative and push optional. All three converge on poll-based as primary.
- **Cache key format**: Codex and Claude flagged colon separator fragility. OpenCode did not raise this specifically.
- **Board key endpoint**: Codex specifically flagged lack of authorization/audit on `PUT /admin/board-public-key`. OpenCode and Claude did not raise this in Cycle 5.

### Recommended Actions Before Execution

1. **HIGH -- Fix cross-crate type dependency**: Move `ApprovalClaims` to `dlp-common/src/approval.rs` or inline fields into `CachedApproval`.
2. **HIGH -- Add public key distribution**: Add `GET /agent/approvals/public-key` endpoint and agent-side key caching.
3. **HIGH -- Fix revoke TOCTOU**: Change `update_state` to accept `expected_current_status` parameter; use `"approved"` for revoke.
4. **HIGH -- Add token delivery retry**: Queue failed deliveries with exponential backoff, or make agent polling the primary mechanism.
5. **HIGH -- Restrict board public key updates**: Add authorization check (dlp-admin only) and separate audit event for board key changes.
6. **MEDIUM -- Clarify pipeline location**: Document whether three-stage pipeline is agent-side (recommended) or server-side.
7. **MEDIUM -- Wire approval events to SIEM**: Explicitly document SIEM routing for all approval event types.
8. **MEDIUM -- Align migration pattern**: Use existing `init_tables()` + `run_alter()` conventions.
9. **MEDIUM -- Fix cache key format**: Use structured type or base64-encoded tuple instead of colon-delimited strings.
10. **MEDIUM -- Add revocation propagation**: Define how revoked approvals invalidate agent cache entries.
11. **LOW -- Define ApprovalCache in dlp-agent**: Create agent-local approval cache type.
12. **LOW -- Document T4 OOB channel**: Add operational note about board member workflow.
13. **LOW -- Verify chrono API**: Use `chrono::Duration::try_hours()` or `chrono::TimeDelta::try_hours()`.

---

*Review generated by cross-AI peer review (Codex CLI + OpenCode + Claude CLI).*
*Cycle 1: 2026-05-13T01:05:00Z. Cycle 2: 2026-05-13. Cycle 3: 2026-05-13T10:30:00Z. Cycle 4: 2026-05-13T07:28:57Z. Cycle 5: 2026-05-13T07:45:00Z.*
*To incorporate feedback: /gsd-plan-phase 61 --reviews*
