---
phase: 61
reviewers: [claude, opencode]
reviewed_at: 2026-05-13T01:05:00Z
plans_reviewed: [61-01-PLAN.md, 61-02-PLAN.md, 61-03-PLAN.md, 61-04-PLAN.md]
---

# Cross-AI Plan Review — Phase 61

## Claude Review

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

## OpenCode Review

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

## Consensus Summary

Both reviewers independently identified the same three HIGH-severity issues and several MEDIUM concerns. Agreement is strong on the critical gaps.

### Agreed Strengths

- Wave ordering and dependency sequencing is correct
- Threat modeling with STRIDE register is thorough
- DashMap approval cache is appropriate for read-heavy, write-rare workload
- Cache key includes SID preventing cross-user replay
- Reuse of existing architectural patterns reduces implementation risk
- T4 Board signature adds a meaningful cryptographic boundary

### Agreed Concerns

1. **HIGH — Ed25519 API incompatibility**: Both reviewers flagged that `ed25519-dalek` v2 + `jsonwebtoken` 9.x interaction is untested and likely broken as written. `to_keypair_bytes()` probably doesn't exist; DER encoding needs verification.
2. **HIGH — Cache key mismatch**: Both identified that `evaluate()` uses `resource.path` while `grant_approval` caches by `data_object_id` (UUID). The cache will never hit.
3. **HIGH — Missing approval creation endpoint**: Both noted that no plan implements how approvals enter the `pending` state. The user UI flow references creation but no handler exists.
4. **MEDIUM — Double-grant / TOCTOU race**: Both flagged concurrent grant vulnerability. `update_state` needs `WHERE status = 'pending'`.
5. **MEDIUM — Token delivery gap**: Both noted server generates token but never delivers it to agent. No push mechanism or polling strategy is planned.
6. **MEDIUM — T4 signature anti-replay**: OpenCode specifically noted the board-signed payload lacks `jti`, enabling signature replay across different approvals.
7. **MEDIUM — `valid_until` not validated**: Claude noted no check that expiry is in the future.
8. **LOW — T4 signature input in TUI incomplete**: Both noted the grant form references a signature input mechanism that doesn't exist.
9. **LOW — `approval["tier"]` in TUI**: References non-existent field on `Approval` struct.

### Divergent Views

- **Key storage**: OpenCode raised HIGH concern about `DLP_APPROVAL_PRIVATE_KEY` being a raw env var (vs Phase 47 encrypted storage). Claude did not flag this, treating it as consistent with existing `JWT_SECRET` pattern.
- **`iss` claim**: OpenCode flagged missing `iss` as MEDIUM. Claude did not mention it.
- **`Instant` vs chrono**: OpenCode noted `Instant` drifts across hibernation. Claude did not mention this.
- **Agent cache re-verification**: OpenCode flagged that `check_approval` should re-verify JWT signature. Claude accepted the current design.
- **Orphaned pending approvals**: OpenCode noted unbounded growth. Claude did not flag this.
- **Scope creep on `RejectRequest.reason`**: OpenCode called this scope creep. Claude did not mention it.

### Recommended Actions Before Execution

1. **Spike**: Verify `ed25519-dalek` v2 + `jsonwebtoken` 9.x EdDSA compilation. Add `pkcs8` feature if needed.
2. **Fix cache key**: Either (a) resolve path to UUID in `evaluate()` before cache lookup, or (b) cache by path instead of UUID. Document the choice.
3. **Add creation endpoint**: Add `POST /admin/approvals` and `POST /agent/approval-request` to Plan 02 (or create Plan 02b).
4. **Fix TOCTOU**: Add `WHERE status = 'pending'` guard to `update_state` with `rows_affected` check.
5. **Add token delivery**: Server `grant_approval` must push token to agent via `POST /agent/approval-token`, or agent must poll.
6. **Validate expiry**: Reject grants where `valid_until <= now`.
7. **Document T4 signature format**: Specify exact canonical serialization for board-signed payload.
8. **Fix TUI**: Add actual signature text input screen or change T4 flow to collect signature before grant form.
9. **Add `tier` to Approval**: Denormalize or resolve at API level so TUI can access it.

---

*Review generated by cross-AI peer review (Claude CLI + OpenCode).*
*To incorporate feedback: /gsd-plan-phase 61 --reviews*
