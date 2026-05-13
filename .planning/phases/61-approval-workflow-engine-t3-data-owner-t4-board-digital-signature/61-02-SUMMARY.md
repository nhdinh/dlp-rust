---
phase: 61-approval-workflow-engine-t3-data-owner-t4-board-digital-signature
plan: 02
subsystem: dlp-server
tags: [approval, workflow, api, jwt, ed25519, t4-signature, audit]
dependency_graph:
  requires: [61-01]
  provides: [61-03, 61-04]
  affects: [dlp-server/src/admin_api.rs, dlp-server/src/approval_api.rs, dlp-common/src/audit.rs]
tech-stack:
  added: []
  patterns: [axum-router, spawn_blocking-db, TOCTOU-guard, audit-event-emission, alert-fire-and-forget]
key-files:
  created:
    - dlp-server/src/approval_api.rs
  modified:
    - dlp-common/src/audit.rs
    - dlp-server/src/lib.rs
    - dlp-server/src/admin_api.rs
    - dlp-server/src/approval_token.rs
decisions:
  - Approval events use flat EventType variants (ApprovalRequest, ApprovalGrant, etc.) wired to SIEM and alerts
  - Token delivery is poll-based authoritative via GET /agent/approvals/active (no server push)
  - Agent public key distribution via GET /agent/approvals/public-key
  - T4 signature verification happens server-side at grant time; agent only validates JWT signature
  - TOCTOU guard uses WHERE status = ? with rows_affected check returning 409 on conflict
  - valid_until validated to be in the future; rejects already-expired grants
  - Board public key updates restricted to dlp-admin with key fingerprint in audit event
metrics:
  duration: "~45 minutes"
  completed_date: "2026-05-14"
---

# Phase 61 Plan 02: Approval Workflow Engine — Admin API and Agent Endpoints

**One-liner:** Admin HTTP API for approval lifecycle management (create, list, grant, reject, revoke) with T4 Board digital signature verification, agent-facing request/sync endpoints, and full audit/alert emission.

---

## What Was Built

### 1. Approval Audit Event Types (`dlp-common/src/audit.rs`)

Added six new `EventType` variants for the approval workflow lifecycle:
- `ApprovalRequest` — approval submitted
- `ApprovalGrant` — approval granted (also triggers alert)
- `ApprovalRevoke` — approval revoked
- `ApprovalUse` — token used to allow operation
- `ApprovalExpiry` — approval expired
- `ApprovalBoardKeyUpdate` — board public key changed

All variants are wired to SIEM via `routed_to_siem()` and `ApprovalGrant` triggers alerts via `triggers_alert()`.

### 2. Approval API Module (`dlp-server/src/approval_api.rs`)

New module (~1000 lines) with:

**Request/Response Types:**
- `ApprovalListQuery` — status filter + pagination (page, per_page)
- `CreateApprovalRequest` / `AgentApprovalRequest` — with validation (justification max 500 chars, destination_scope max 200)
- `GrantRequest` — valid_until + optional T4 signature
- `RejectRequest` — optional reason
- `ApprovalResponse` / `ApprovalListResponse` / `ApprovalDetailResponse` — with resolved tier and t4_canonical_message
- `GrantResponse` — approval + signed JWT token
- `AgentApprovalResponse` — id + status
- `BoardPublicKeyRequest` — hex-encoded Ed25519 pubkey
- `ActiveApprovalResponse` — token + claims for agent sync

**Handlers (11 total):**
| Handler | Route | Auth |
|---------|-------|------|
| `list_approvals` | GET /admin/approvals | JWT |
| `create_approval` | POST /admin/approvals | JWT |
| `get_approval` | GET /admin/approvals/{id} | JWT |
| `grant_approval` | POST /admin/approvals/{id}/grant | JWT |
| `reject_approval` | POST /admin/approvals/{id}/reject | JWT |
| `revoke_approval` | POST /admin/approvals/{id}/revoke | JWT |
| `update_board_public_key` | PUT /admin/board-public-key | JWT |
| `submit_approval_request` | POST /agent/approval-request | Public |
| `list_active_approvals` | GET /agent/approvals/active | Public |
| `get_public_key` | GET /agent/approvals/public-key | Public |

**Key Implementation Details:**
- `grant_approval`: Validates valid_until > now, resolves tier via LabelRepository, verifies T4 Board Ed25519 signature against stored pubkey, uses TOCTOU guard (WHERE status = 'pending'), generates signed JWT with ApprovalClaims, emits audit event + alert
- `reject_approval` / `revoke_approval`: TOCTOU guard with appropriate expected_current_status
- `list_active_approvals`: Returns approved+unexpired tokens, freshly signed on each sync
- `update_board_public_key`: Validates 64-char hex (32 bytes), stores in system_kv, emits audit event

### 3. Router Wiring (`dlp-server/src/admin_api.rs`)

- Added `use crate::approval_api;` import
- Added 6 admin approval routes to `protected_routes` (under JWT auth)
- Added 3 agent-facing approval routes to `public_routes` (no JWT)

### 4. Fixes (`dlp-server/src/approval_token.rs`)

- Moved `Signer` trait import to `#[cfg(test)]` to fix clippy unused_import warning while keeping test compilation working

---

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Action::From<&str> does not exist**
- **Found during:** Task 2 implementation
- **Issue:** The plan referenced `Action::from(approval.allowed_action.as_str())` but `Action` has no `From<&str>` implementation
- **Fix:** Added `action_from_str()` helper function that maps common action strings to `Action` enum variants
- **Files modified:** `dlp-server/src/approval_api.rs`

**2. [Rule 1 - Bug] ApprovalStatus doesn't implement FromStr**
- **Found during:** Task 2 compilation
- **Issue:** `row.status.parse().unwrap_or(...)` failed because `ApprovalStatus` has `TryFrom<&str>` not `FromStr`
- **Fix:** Changed to `row.status.as_str().try_into().unwrap_or(...)`
- **Files modified:** `dlp-server/src/approval_api.rs`

**3. [Rule 1 - Bug] spawn_blocking lifetime issues with borrowed strings**
- **Found during:** Task 2 compilation
- **Issue:** `ApprovalUpsertRow` borrows strings, but `tokio::task::spawn_blocking` requires `'static` closures
- **Fix:** Clone all strings before constructing `ApprovalUpsertRow` inside the closure
- **Files modified:** `dlp-server/src/approval_api.rs`

**4. [Rule 1 - Bug] String move issues in grant/reject/revoke handlers**
- **Found during:** Task 2 compilation
- **Issue:** `id`, `approver_sid`, `now` strings moved into spawn_blocking closures and reused afterward
- **Fix:** Clone strings before moving into closures (e.g., `id_for_fetch`, `id_for_update`)
- **Files modified:** `dlp-server/src/approval_api.rs`

**5. [Rule 2 - Missing Critical Functionality] list_active_approvals SQL query**
- **Found during:** Task 2 implementation
- **Issue:** The plan referenced `ApprovalRepository::list_by_status` but active approvals need `valid_until > now` filtering which the repository doesn't support
- **Fix:** Implemented inline SQL query in the handler with `status = 'approved' AND valid_until > ?1`
- **Files modified:** `dlp-server/src/approval_api.rs`

**6. [Rule 1 - Bug] Signer trait needed for tests but not production**
- **Found during:** clippy run
- **Issue:** Removing `Signer` import broke test compilation (board_signing.sign() needs it)
- **Fix:** Made `Signer` import conditional with `#[cfg(test)]`
- **Files modified:** `dlp-server/src/approval_token.rs`

---

## Test Results

- `cargo test -p dlp-common --lib audit::`: 23 passed
- `cargo test -p dlp-server approval_api::tests`: 12 passed
- `cargo test -p dlp-server -p dlp-common` (full suite): **592 passed, 5 ignored**
- `cargo clippy -p dlp-server -p dlp-common -- -D warnings`: **Clean**
- `cargo build --workspace`: **Success**

---

## Verification Checklist

| # | Check | Result |
|---|-------|--------|
| 1 | `approval_api` referenced in `admin_api.rs` | 10 matches |
| 2 | `/admin/approvals` routes wired | 5 route definitions |
| 3 | `approval-request` route wired | 1 match |
| 4 | `approvals/active` route wired | 1 match |
| 5 | `WHERE status` in approvals repo | 4 matches (TOCTOU guard) |
| 6 | `valid_until` in approval_api.rs | 11 matches (validation + claims) |
| 7 | `board-public-key` route wired | 1 match |
| 8 | `t4_canonical_message` in approval_api.rs | 2 matches |
| 9 | Pagination (page/per_page/limit/offset) | 21 matches |

---

## Commits

| Hash | Message |
|------|---------|
| 590f815 | feat(61-02): add approval audit event types and approval API module skeleton |
| c8be0dd | feat(61-02): implement approval handlers with T4 signature verification and audit emission |

---

## Self-Check: PASSED

- [x] `dlp-server/src/approval_api.rs` exists
- [x] `dlp-common/src/audit.rs` modified with approval event types
- [x] `dlp-server/src/lib.rs` exports approval_api module
- [x] `dlp-server/src/admin_api.rs` wires all routes
- [x] Commits 590f815 and c8be0dd exist in git log
- [x] All 592 tests pass
- [x] Clippy clean
- [x] Build succeeds
