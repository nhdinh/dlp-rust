---
phase: 61
reviewers: [claude, opencode, codex-unavailable]
reviewed_at: 2026-05-13T01:05:00Z
review_cycle: 2
plans_reviewed: [61-01-PLAN.md, 61-02-PLAN.md, 61-03-PLAN.md, 61-04-PLAN.md]
---

# Cross-AI Plan Review — Phase 61

## Review Cycle History

- **Cycle 1 (2026-05-13T01:05:00Z)**: Claude CLI + OpenCode reviewed initial plans. Identified 5 HIGH, 7 MEDIUM, 7 LOW concerns.
- **Cycle 2 (2026-05-13)**: Plans revised to address all Cycle 1 concerns. OpenCode re-reviewed revised plans. Codex CLI unavailable (401 Unauthorized — not logged in).

---

## Claude Review (Cycle 1 — Initial Plans)

### Summary

Phase 61 plans are well-structured and follow established patterns from prior phases. The four-plan wave approach (foundation -> API -> agent integration -> TUI) is logical. However, several critical gaps exist: missing approval creation endpoints, Ed25519 API compatibility questions, cache key mismatches between path and UUID, and the T4 signature input flow in the TUI is incomplete. Security concerns around double-grant races, board key management, and token delivery to agents need addressing before execution.

### Strengths

- Wave ordering (01 -> 02/03 -> 04) correctly sequences dependencies
- Threat model included in every plan with STRIDE register
- DashMap + background sweep for agent cache is appropriate for read-heavy workload
- Cache key includes SID, preventing cross-user approval replay
- Reuse of existing patterns (PolicyList, EngineClient, repository pattern) reduces risk
- JWT (Ed25519) token format is compact and cryptographically sound
- Audit events and alert routing integrated into all state-changing operations

### Concerns

- **HIGH** — Missing approval creation endpoint: No plan implements `POST /admin/approvals` or `POST /agent/approval-request`. Without these, no approval can ever enter the `pending` state. The UI-SPEC describes the user flow but no server handler exists.
- **HIGH** — Ed25519 JWT API compatibility: `ed25519-dalek` v2 + `jsonwebtoken` 9.x interaction is untested. `to_keypair_bytes()` may not exist; `EncodingKey::from_ed_der` expects PKCS#8 DER, not raw bytes. Needs a compilation spike before execution.
- **HIGH** — Cache key mismatch: `evaluate()` builds cache key using `resource.path`, but `grant_approval` caches using `data_object_id` (UUID from DB). These will never match. Approval cache lookups will always miss.
- **HIGH** — Token delivery gap: Server generates token on grant but never delivers it to the agent. Plan 03 has the receiving endpoint but no caller. Either server must push, or agent must poll.
- **MEDIUM** — Double-grant race: `update_state` has no `WHERE status = 'pending'` guard. Two concurrent grants silently overwrite each other, generating two tokens for one approval.
- **MEDIUM** — `valid_until` not validated: `grant_approval` accepts any ISO-8601 string. No check that `valid_until > now`. Admin could grant already-expired approval.
- **MEDIUM** — Board public key unrestricted: `system_kv` stores board pubkey but no plan restricts who can update it. Compromised admin could swap key and self-approve T4.
- **MEDIUM** — `AgentTokenRequest` redundant fields: Request body includes `requester_sid`, `data_object_id`, `allowed_action` in addition to token. Claims already contain these — derive cache key purely from verified claims to prevent replay.
- **MEDIUM** — T4 signature message format undocumented: Canonical serialization for board signature is not specified. If format changes, verification breaks silently.
- **LOW** — `approval["tier"]` in TUI: `Approval` struct has no `tier` field. T4 check in grant form references non-existent field.
- **LOW** — T4 signature input missing: Grant form has `t4_signature_confirmed: bool` but actual signature hex is never collected. References "pre-form text input" that doesn't exist.
- **LOW** — Stale data on filter switch: `handle_approval_list` sets status to "Reloading..." but doesn't trigger actual reload.
- **LOW** — Empty approval list after Esc: `handle_approval_detail` returns to `ApprovalList` with `approvals: Vec::new()`, losing context.
- **LOW** — `chrono::Duration::hours` may not exist in used chrono version; may need `try_hours`.

### Suggestions

1. Add `POST /admin/approvals` and `POST /agent/approval-request` endpoints (or a separate micro-plan).
2. Add a compilation spike task for `ed25519-dalek` v2 + `jsonwebtoken` EdDSA integration before Plan 01 execution.
3. Fix cache key: resolve `resource.path` to `data_object_id` via label service before cache lookup, OR cache by path instead of UUID.
4. Add server-to-agent token push in `grant_approval` (or document agent polling strategy).
5. Add `WHERE status = 'pending'` to `update_state` with `rows_affected` check for all state transitions.
6. Validate `valid_until > now` in `grant_approval` before signing token.
7. Restrict board public key updates to dlp-admin with separate audit event.
8. Remove redundant fields from `AgentTokenRequest`; derive cache key from verified claims only.
9. Document exact canonical T4 signature message format (e.g., sorted JSON or fixed-field concatenation).
10. Add `tier` field to `Approval` struct or resolve from labels at API level before TUI receives it.

### Risk Assessment

**HIGH** — The missing approval creation endpoint and token delivery mechanism are fundamental gaps that would prevent the end-to-end flow from working. The Ed25519 API compatibility risk could block Plan 01 entirely. The cache key mismatch would silently break the agent integration. These are not edge cases; they are core functionality gaps.

---

## OpenCode Review (Cycle 1 — Initial Plans)

### Summary

Phase 61 plans demonstrate solid architectural thinking with appropriate reuse of existing patterns. However, three HIGH-severity issues must be resolved before execution: (1) `ed25519-dalek` 2.x and `jsonwebtoken` 9.x API incompatibility will cause compilation failure, (2) the approval cache key uses path in `evaluate()` but UUID in `grant_approval`, causing permanent cache misses, and (3) the Ed25519 signing key is stored as a raw env var despite Phase 47 having built secrets encryption at rest. Additionally, several security gaps (missing `iss` claim, T4 signature replay vulnerability, TOCTOU on grants) and missing edge cases (orphaned pending approvals, no rejection notification to user) need attention.

### Strengths

- T4 Board signature verification is a solid cryptographic boundary
- Threat model included in every plan with STRIDE register
- DashMap + background sweep for agent cache is appropriate
- Cache key includes SID (cross-user replay prevented)
- Wave ordering (01 -> 02/03 -> 04) is logical

### Concerns

- **HIGH** — `ed25519-dalek` 2.x + `jsonwebtoken` 9.x API incompatibility: `to_keypair_bytes()` does not exist in `ed25519-dalek` 2.x. `jsonwebtoken`'s `from_ed_der()` expects PKCS#8 v2 DER. Need `pkcs8` feature and `to_pkcs8_der()`.
- **HIGH** — Cache key mismatch: `approval_cache_key(sid, data_object_id, action)` uses UUID, but `evaluate()` constructs key with `resource.path`. Lookups always miss. Need path->UUID resolution in `evaluate()`.
- **HIGH** — Unencrypted signing key: `DLP_APPROVAL_PRIVATE_KEY` is a raw env var. Phase 47 built `Envelope` + `jwt_secret::upsert_encrypted`. This key must use the same encrypted storage path.
- **MEDIUM** — Missing `iss` claim in `ApprovalClaims`: No issuer means any JWT with matching structure could be replayed. Add `iss: "dlp-server"` and validate it.
- **MEDIUM** — T4 Board signature has no anti-replay: Board signs "canonical message from approval fields" but no `jti` in signed payload. Captured signature can be replayed for different approval. Must sign `(approval_id || requester_sid || data_object_id || allowed_action || valid_until)`.
- **MEDIUM** — No concurrent-grant protection (TOCTOU): `grant_approval` reads status, checks `== pending`, then calls `update_state`. Two concurrent grants both succeed. Need `WHERE status = 'pending'` with `rows_affected` check.
- **MEDIUM** — Agent cache has no runtime signature re-verification: `check_approval` only checks `Instant`. Memory corruption or cache poisoning could fake an entry. Verify JWT signature on cache read, or store claims hash as authority.
- **MEDIUM** — `Instant` not monotonic across sleep: `CachedApproval::expires_at: Instant` drifts across hibernation. Use `chrono::Utc::now()` vs stored `exp`.
- **LOW** — Orphaned pending approvals grow unbounded: No TTL on pending, no cleanup. User can spam override requests. Need index on `created_at` for periodic cleanup.
- **LOW** — `reject` handler doesn't notify user: No `ApprovalRejected` IPC variant. User sees indefinite "pending" state.
- **LOW** — `ApprovalRepository::delete` is dead code: No handler calls it. Either wire it or remove.
- **LOW** — No limit on justification length at API: Plan says "validated at API boundary" but no handler validates.
- **LOW** — Board public key has no admin API endpoint: `store_board_public_key` exists as static method but no route to PUT it.

### Suggestions

1. Add `pkcs8` feature to `ed25519-dalek` and use `to_pkcs8_der()` for `jsonwebtoken` compatibility.
2. Resolve `resource.path` to `data_object_id` via label service in `evaluate()` before cache lookup.
3. Store `DLP_APPROVAL_PRIVATE_KEY` through Phase 47's encrypted secrets infrastructure (`Envelope` + `jwt_secret::upsert_encrypted`).
4. Add `iss` claim to `ApprovalClaims` and enable issuer validation.
5. Include `jti` (approval ID) in the T4 board-signed payload to prevent signature replay.
6. Add `WHERE status = 'pending'` with `rows_affected` check to all state transitions.
7. Re-verify JWT signature in `check_approval` or use claims hash as cache authority.
8. Replace `Instant` with `chrono::Utc` timestamp comparison for expiry checks.
9. Add a periodic cleanup task for orphaned pending approvals (e.g., auto-reject after 7 days).
10. Add `ApprovalRejected` IPC variant so user UI can show rejection status.

### Risk Assessment

**HIGH** — Three compilation/functionality blockers (Ed25519 API mismatch, cache key mismatch, unencrypted key) plus security gaps (no `iss`, T4 replay, TOCTOU) make this phase risky to execute as-is. Recommend a pre-execution spike on the Ed25519 integration and a plan revision for the cache key and key storage before beginning implementation.

---

## OpenCode Review (Cycle 2 — Revised Plans)

### Summary

The plans are structurally sound and the prior review cycle demonstrably improved them. The TOCTOU guard, encrypted key storage, cache re-verification, and justification validation all address real attack vectors. However, three systemic gaps remain: agent-offline resilience (token delivery/startup sync), destination scope leakage in cache key design, and a T4 canonical message format inconsistency with the documented user decisions.

### Strengths

- **Ed25519 compilation spike first (Task 0)** — This prevents a class of integration failures that typically surface mid-implementation
- **TOCTOU guard with WHERE status='pending' + rows_affected check** — Correctly prevents double-grant on concurrent requests
- **Re-verification on every cache read** — Eliminates cache-poisoning as an attack vector
- **Wave dependency ordering** — Foundation->API->Agent->UI correctly isolates concerns
- **Revocation confirmation via Confirm screen** — Guards against accidental destructive actions
- **SIEM audit on all state transitions** — Covers the full lifecycle

### Concerns

- **HIGH: Agent-offline token delivery has no retry or startup sync mechanism.**
  Plan 02 says "server pushes token to agent via HTTP POST." If the agent is restarting, disconnected, or the POST fails, the token is created server-side but never reaches the agent cache. The agent never learns about it unless it explicitly syncs on startup. A user with a valid granted approval will be denied until someone notices. Fix: add a startup sync (agent queries `GET /agent/approvals/active?since=<last_known>`) and a server-side retry queue with exponential backoff for failed deliveries.

- **MEDIUM: T4 canonical message format conflicts with user decisions.**
  User decisions state: *"Signature input: JWT payload bytes (the T3 approval token) signed with board member's private key."* Plan 01 Task 3 defines: `"DLP-T4-SIGNATURE:{jti}:{sub}:{obj}:{act}:{valid_until}"` — a *different* format. If the board member signs the JWT payload (as decided) but the server verifies the canonical message, verification always fails. These must be reconciled. Recommend aligning on the canonical message format (simpler for board members to produce with external tooling) and updating the decision document to match.

- **MEDIUM: Cache key `(sub, obj, act)` omits `destination_scope`, creating a scope bypass.**
  The approval schema includes `destination_scope` (e.g. `USB:DRIVE_E` vs `USB:*`). If the cache key is only `(sub, obj, act)`, an approval scoped to one specific USB drive will match a request targeting a *different* USB drive. The `check_approval` method must verify `dst` is within the approved scope *in addition to* the cache key match. Either `destination_scope` becomes part of the cache key, or a separate scope-matching check runs after the cache hit. Either way this must be explicit.

- **MEDIUM: ABAC evaluation integration point is underspecified.**
  The plan says "approval check in agent service — hook DLL sends policy eval request to agent; agent checks approval cache as part of ABAC evaluation." But the ABAC engine currently returns a binary ALLOW/DENY. Where exactly does the approval cache hook in? The critical invariant *("NTFS ALLOW + ABAC DENY -> DENY")* needs a third path: *("NTFS ALLOW + ABAC DENY + APPROVED TOKEN -> ALLOW")*. The `evaluate()` function needs an explicit ordered pipeline: (1) NTFS check, (2) ABAC policy check, (3) approval cache override for DENY results. Without this specification, the agent integration could produce wrong results.

- **MEDIUM: No migration strategy for the approvals table.**
  The existing SQLite database presumably has a schema version. Plan 01 creates a new table but doesn't mention `PRAGMA user_version` checks, migration scripts, or how the schema upgrade integrates with the existing database initialization path. Without this, deploying Phase 61 on an existing Phase 60 database may crash at startup.

- **MEDIUM: No testing strategy mentioned across any plan.**
  No plans include test tasks — neither unit tests for `ApprovalTokenService`/`ApprovalRepository`, nor integration tests for the API handlers, nor CI checks. For a security-critical subsystem handling cryptographic signing and policy override, this is a significant gap.

- **LOW: T4 signature UX is unaddressed.**
  A board member needs to: (1) see the canonical message somehow, (2) use external tooling to produce a 128-hex-char Ed25519 signature, (3) paste it into a TUI text field. The plan doesn't mention how the board member obtains the canonical message to sign. The admin TUI should display the exact canonical message string in the approval detail screen so the board member can copy it to their signing tool.

- **LOW: No pagination in approval list.**
  An enterprise deployment may have thousands of approvals. The TUI list currently loads all records. Should add `LIMIT/OFFSET` with page-up/page-down navigation or virtual scrolling.

### Suggestions

1. **Add agent startup sync endpoint** — `GET /api/v1/agent/approvals/active` returning approved+unexpired tokens. Agent calls this on startup and on IPC reconnection. Include `last_sync_ts` to return deltas only.
2. **Add destination scope matching** — Extend `check_approval` to accept the request's `destination_scope` and validate it against the approval's scope. Use a hierarchical pattern match (e.g., `USB:*` matches `USB:DRIVE_E`).
3. **Reconcile T4 format** — Either adopt the canonical message format everywhere (preferred: simpler for offline signing) and update the user decisions document, or use raw JWT payload bytes. Pick one.
4. **Specify ABAC evaluation pipeline** — Document the three-stage flow: NTFS check -> ABAC policy -> approval override. The approval override only applies when step 1 is ALLOW and step 2 is DENY, AND the approval is for the specific `(sub, obj, act, dst)`.
5. **Add migration step** — In the server startup, check `PRAGMA user_version` and apply `CREATE TABLE IF NOT EXISTS approvals (...)` + indexes. Bump `user_version` to the next version.
6. **Add test tasks to each plan** — At minimum: (a) `ApprovalTokenService` sign/verify round-trip with valid and tampered tokens, (b) `ApprovalRepository` CRUD + TOCTOU race test, (c) API handler integration test for the full grant flow, (d) agent cache sweep expiry test.

### Risk Assessment

**MEDIUM**

The core architecture is well-considered and the prior HIGH issues are genuinely resolved. Remaining risk centers on three areas: (1) the T4 format inconsistency will produce a non-functional integration unless reconciled before coding, (2) the agent-offline gap means granted approvals can be silently lost, (3) the destination scope escape in cache key design could allow broader access than intended. All are fixable with specification clarifications and one additional plan addition (startup sync). Recommend resolving T4 format and destination scope before execution begins; agent startup sync and testing can be added as tasks during execution.

---

## Codex Review

**Status: UNAVAILABLE** — Codex CLI is installed but not authenticated (401 Unauthorized on API call). Login required to enable Codex reviews.

---

## Consensus Summary (Across Both Cycles)

### Cycle 1 -> Cycle 2 Resolution Status

| Concern | Severity (Cycle 1) | Status | How Addressed |
|---------|-------------------|--------|---------------|
| Missing approval creation endpoint | HIGH | **RESOLVED** | Plan 02 Task 2: create_approval + submit_approval_request handlers added |
| Ed25519 API incompatibility | HIGH | **RESOLVED** | Plan 01 Task 0: Compilation spike verifies pkcs8 + to_pkcs8_der() before service code |
| Cache key mismatch | HIGH | **RESOLVED** | Plan 03 Task 1: evaluate() resolves path to data_object_id via LabelService |
| Token delivery gap | HIGH | **RESOLVED** | Plan 02 Task 2: Server pushes token via HTTP POST; Plan 03 Task 2: /agent/approval-token endpoint |
| Unencrypted signing key | HIGH | **RESOLVED** | Plan 01 Task 3: Uses Phase 47 Envelope encrypted storage |
| Double-grant / TOCTOU | MEDIUM | **RESOLVED** | Plan 01 Task 2: WHERE status='pending' guard; Plan 02 Task 2: rows_affected check |
| Missing iss claim | MEDIUM | **RESOLVED** | Plan 01 Task 3: iss:"dlp-server" + validation in verify_token |
| T4 signature anti-replay | MEDIUM | **RESOLVED** | Plan 01 Task 3: t4_canonical_message includes jti |
| valid_until not validated | MEDIUM | **RESOLVED** | Plan 02 Task 2: valid_until > now check before signing |
| Board public key unrestricted | MEDIUM | **RESOLVED** | Plan 02 Task 2: PUT /admin/board-public-key restricted to dlp-admin |
| Agent cache re-verification | MEDIUM | **RESOLVED** | Plan 03 Task 1: check_approval re-verifies JWT signature on read |
| Instant vs chrono | MEDIUM | **RESOLVED** | Plan 03 Task 1: Uses chrono::DateTime<Utc> |
| Orphaned pending approvals | LOW | **RESOLVED** | Plan 01 Task 2: cleanup_orphaned + created_at index |
| ApprovalRejected IPC | LOW | **RESOLVED** | Plan 03 Task 2: Pipe1AgentMsg::ApprovalRejected variant |
| Justification length limit | LOW | **RESOLVED** | Plan 02 Task 1/2: validate() rejects > 500 chars |
| Tier field for TUI | LOW | **RESOLVED** | Plan 02 Task 2: ApprovalResponse includes tier |
| T4 signature input in TUI | LOW | **RESOLVED** | Plan 04 Task 1/2: ApprovalGrantForm.signature_hex + text input |
| Stale data on filter switch | LOW | **RESOLVED** | Plan 04 Task 3: 'f' triggers actual API reload |
| Empty approval list after Esc | LOW | **RESOLVED** | Plan 04 Task 3: Esc preserves approvals Vec |

### Cycle 2: New / Remaining Concerns

| Concern | Severity | Reviewer | Status |
|---------|----------|----------|--------|
| Agent-offline token delivery (no retry/startup sync) | **HIGH** | OpenCode (Cycle 2) | **NEW** — Not previously raised |
| T4 canonical message format conflicts with user decisions | MEDIUM | OpenCode (Cycle 2) | **NEW** — Not previously raised |
| Cache key omits destination_scope (scope bypass) | MEDIUM | OpenCode (Cycle 2) | **NEW** — Not previously raised |
| ABAC evaluation integration point underspecified | MEDIUM | OpenCode (Cycle 2) | **NEW** — Not previously raised |
| No migration strategy for approvals table | MEDIUM | OpenCode (Cycle 2) | **NEW** — Not previously raised |
| No testing strategy across plans | MEDIUM | OpenCode (Cycle 2) | **NEW** — Not previously raised |
| T4 signature UX (how board member gets canonical message) | LOW | OpenCode (Cycle 2) | **NEW** — Not previously raised |
| No pagination in approval list | LOW | OpenCode (Cycle 2) | **NEW** — Not previously raised |

### Agreed Strengths (Both Cycles)

- Wave ordering and dependency sequencing is correct
- Threat modeling with STRIDE register is thorough
- DashMap approval cache is appropriate for read-heavy, write-rare workload
- Cache key includes SID preventing cross-user replay
- Reuse of existing architectural patterns reduces implementation risk
- T4 Board signature adds a meaningful cryptographic boundary
- Ed25519 compilation spike (Task 0) prevents mid-implementation blockers
- TOCTOU guard with rows_affected check is correctly implemented
- JWT re-verification on cache read eliminates cache-poisoning attack vector

### Divergent Views

- **Key storage**: OpenCode (Cycle 1) raised HIGH concern about raw env var. Claude (Cycle 1) did not flag. **RESOLVED in Cycle 2** via Phase 47 Envelope.
- **`iss` claim**: OpenCode (Cycle 1) flagged missing `iss` as MEDIUM. Claude did not mention. **RESOLVED in Cycle 2** via ApprovalClaims.iss.
- **`Instant` vs chrono**: OpenCode (Cycle 1) noted `Instant` drifts. Claude did not. **RESOLVED in Cycle 2** via chrono::DateTime<Utc>.
- **Agent cache re-verification**: OpenCode (Cycle 1) flagged need for re-verification. Claude accepted current design. **RESOLVED in Cycle 2** via check_approval signature re-verification.
- **Orphaned pending approvals**: OpenCode (Cycle 1) noted unbounded growth. Claude did not. **RESOLVED in Cycle 2** via cleanup_orphaned.
- **Agent-offline resilience**: OpenCode (Cycle 2) raised as NEW HIGH. Not in Cycle 1.
- **Destination scope in cache key**: OpenCode (Cycle 2) raised as NEW MEDIUM. Not in Cycle 1.
- **T4 format inconsistency**: OpenCode (Cycle 2) raised as NEW MEDIUM. Not in Cycle 1 — Cycle 1 reviewers did not compare user decisions against plan implementation.

### Recommended Actions Before Execution

1. **HIGH — Agent startup sync**: Add `GET /agent/approvals/active` endpoint and agent startup sync task. Without this, granted approvals are lost when agent restarts.
2. **MEDIUM — Reconcile T4 format**: Update 61-CONTEXT.md user decisions to match the canonical message format, OR change t4_canonical_message to sign raw JWT payload bytes. Must be consistent.
3. **MEDIUM — Destination scope in cache key**: Add `dst` to cache key OR add scope-matching check in check_approval after cache hit. Prevents USB drive A approval from allowing USB drive B.
4. **MEDIUM — Specify ABAC pipeline**: Document three-stage flow: NTFS check -> ABAC policy -> approval override. Override only applies when NTFS=ALLOW and ABAC=DENY.
5. **MEDIUM — Add migration**: `CREATE TABLE IF NOT EXISTS approvals` in init_tables() handles new installs; document `PRAGMA user_version` for existing DBs.
6. **MEDIUM — Add test tasks**: Each plan needs explicit test tasks (unit + integration). Security-critical subsystem demands it.
7. **LOW — T4 signature UX**: Display canonical message in ApprovalDetail screen for board member copy-paste.
8. **LOW — Pagination**: Add LIMIT/OFFSET to list_approvals for enterprise scale.

---

*Review generated by cross-AI peer review (Claude CLI + OpenCode).*
*Cycle 1: 2026-05-13T01:05:00Z. Cycle 2: 2026-05-13.*
*To incorporate feedback: /gsd-plan-phase 61 --reviews*
