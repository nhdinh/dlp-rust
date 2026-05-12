# Phase 61: Approval Workflow Engine - Context

**Gathered:** 2026-05-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 61 delivers the **Approval Workflow Engine** — a time-bounded approval system for blocked DLP operations. Users can request override for denied file operations; T3-classified data routes to Data Owners for approval; T4-classified data requires Board-level digital signature. Approved operations carry a cryptographically signed token that the agent validates before allowing the blocked action.

**Depends on:** Phase 60 (Data Owner review queue must exist for T3 routing)
**Requirements:** WORKFLOW-01..06

**What Phase 61 builds:**
1. `approvals` SQLite table with full approval lifecycle (pending/approved/rejected/revoked/expired)
2. T3 approval flow: user request -> agent -> server -> Data Owner approves via admin TUI -> signed token
3. T4 approval flow: same as T3 but requires Board digital signature (Ed25519)
4. Agent-side approval token validator integrated into ABAC evaluation
5. Admin TUI approval management screen (list, grant, revoke, filter)
6. Approval-aware audit events (request, grant, use, expiry, revocation)

**What Phase 61 does NOT build:**
- Bulk approve/reject (deferred to Phase 64+)
- Email-based approval links (deferred to Phase 68 — Email/Outlook)
- Real-time push notifications to Data Owners (placeholder event only)
- Automatic expiry background task (status checked on-demand at evaluation time)

</domain>

<decisions>
## Implementation Decisions

### Token Format and Signing
- **JWT (JWS)** format — reuse existing `jsonwebtoken` crate and JWT infrastructure from admin auth
- **Ed25519** signing algorithm — fast, compact 64-byte signatures; `ed25519-dalek` crate
- **Standard JWT claims**: `sub` (requester SID), `obj` (data_object_id), `act` (action), `dst` (destination), `dev` (device fingerprint), `iat`, `exp`, `jti` (token ID)
- **HTTP POST delivery** to agent loopback (`POST /agent/approval-token`) via existing agent HTTP API

### T4 Digital Signature
- **Ed25519** for T4 signatures too — single key type, simpler key management
- **Public key stored in `system_kv` table** — `board_public_key` row, hex-encoded; configurable via admin API/TUI
- **Signature input**: JWT payload bytes (the T3 approval token) signed with board member's private key
- **Board member identity**: AD SID stored in `approver_sid`; signature verification is cryptographic against stored pubkey

### Agent Integration and Hook Flow
- **Approval check in agent service** — hook DLL sends policy eval request to agent; agent checks approval cache as part of ABAC evaluation
- **In-memory `DashMap<String, CachedApproval>`** in `PolicyStore` — keyed by `(requester_sid, data_object_id, action)`; TTL-driven expiry; background sweep every 60s
- **User -> agent via named pipe** (`\\.\pipe\DlpUserPipe`) — new `UserMessage::RequestApproval` / `UserMessage::ApprovalStatus` variants
- **Deny on expiry mid-operation** — token checked at operation start; no "hold while operation runs" semantics

### Admin TUI and Management
- **Scrollable table pattern** (like `PolicyList`) — columns: requester, object, action, status, expiry
- **Actions**: `g` (grant), `r` (revoke), `v` (view detail)
- **Pre-filled expiry picker** — default 1 hour, options: 1h, 4h, 8h, 24h, custom
- **Bulk operations deferred** — single-action only in Phase 61
- **Immediate revocation** — sets status `revoked`, pushes cache delta to agent; subsequent operations denied

### Claude's Discretion
- Token cache key format: `"{sid}:{obj_id}:{action}"` — simple string join, no JSON
- Approval request from user UI carries minimal payload: justification text (max 500 chars), action, path. Server resolves data_object_id from path.
- Board signature verification happens server-side at grant time; agent only validates the JWT token signature (server's Ed25519 key, not board's).
- Expiry check is lazy (on-demand during evaluation) plus a 60s background sweep for cache cleanup. No cron/scheduler needed.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`jsonwebtoken`** crate already in dependency tree (used for admin JWT auth)
- **`LabelRepository`** (`dlp-server/src/db/repositories/labels.rs`) — lookup label by path for data_object_id resolution
- **`PolicyStore`** (`dlp-server/src/policy_store.rs`) — can host `DashMap` approval cache alongside label cache
- **`AppState { pool, policy_store, siem, alert, ad }`** — shared state pattern; add approval repository
- **`audit_log` table** — existing audit infrastructure for WORKFLOW-06
- **`system_kv` table** — existing key-value store for `board_public_key`
- **Admin API router** (`dlp-server/src/admin_api.rs`) — add `/admin/approvals` routes following existing `.route()` pattern
- **`EngineClient`** (`dlp-admin-cli/src/client.rs`) — HTTP client with GET/POST/PUT/DELETE methods
- **`Screen::PolicyList`** pattern — model ApprovalList screen after this
- **Named pipe IPC** (`dlp-agent/src/ipc/`) — existing pipe infrastructure for agent-user communication

### Established Patterns
- **Repository pattern**: Stateless struct with `pool` parameter (like `LabelRepository`)
- **Admin API CRUD**: `list` (GET, optional query filters), `get_by_id` (GET), `create` (POST), `update` (PUT), `delete` (DELETE)
- **JWT claims**: Existing `Claims` struct in auth module — reuse pattern for approval tokens
- **TUI table screen**: Scrollable list with selected index, action keys, filter cycling
- **Cache invalidation**: `policy_store.approval_cache` — clear on revoke, update on grant
- **SIEM relay**: `siem_connector::relay(audit_event)` — approval events use same path

### Integration Points
- `dlp-server/src/db/mod.rs` — add `approvals` table to `init_tables()`
- `dlp-server/src/admin_api.rs` — add `/admin/approvals` routes
- `dlp-server/src/policy_store.rs` — add `approval_cache: Arc<DashMap<...>>`
- `dlp-agent/src/ipc/` — add `UserMessage::RequestApproval` / `ApprovalStatus` variants
- `dlp-user-ui/` — toast with "Request override" button on DENY
- `dlp-admin-cli/src/app.rs` — `Screen::ApprovalList` and `Screen::ApprovalDetail`
- `dlp-common/src/` — new `approval.rs` module with `Approval`, `ApprovalStatus`, `ApprovalToken` types

</code_context>

<specifics>
## Specific Ideas

- The approval token should be a standard JWT with Ed25519 JWS. Use `ed25519-dalek` for signing/verification. The server's signing keypair is generated at first boot (or loaded from env var `DLP_APPROVAL_PRIVATE_KEY`).
- The `dlp-user-ui` toast on DENY should show: "Operation blocked by DLP policy. [Request Override]". Clicking opens a small dialog with a justification text box and Submit button.
- The admin TUI Approval screen should show a red/green/yellow status indicator for each row (pending=yellow, approved=green, rejected=red, revoked=grey, expired=grey).
- Data Owner approval grants should emit an `alert_router::send` event with `alert_type = "approval_granted"` so Phase 62 (Syslog Forwarder) can forward it.
- The approval cache in PolicyStore should use `DashMap` (not `RwLock<HashMap>`) for lock-free concurrent reads during high-volume evaluation — approvals are read-heavy, write-rare.
</specifics>

<deferred>
## Deferred Ideas

- Bulk approve/reject operations (Phase 64+)
- Email-based approval links for Data Owners (Phase 68 — Email/Outlook)
- Real-time push notifications (webhooks/Slack) to Data Owners
- Automatic background expiry task (not needed — lazy expiry on evaluation + cache sweep sufficient)
- Approval delegation (Data Owner can delegate to another user)
- Approval workflow templates (different expiry defaults per tier)
</deferred>
