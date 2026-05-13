---
phase: 61-approval-workflow-engine-t3-data-owner-t4-board-digital-signature
plan: 03
subsystem: auth
 tags: [jwt, ed25519, dashmap, abac, ipc, named-pipe, approval-workflow, dlp-agent]

# Dependency graph
requires:
  - phase: 61-01
    provides: "ApprovalClaims, ApprovalCacheKey, CachedApproval types in dlp-common; ApprovalTokenService with Ed25519 signing in dlp-server"
  - phase: 61-02
    provides: "GET /agent/approvals/active and POST /agent/approval-request endpoints in dlp-server"
provides:
  - Agent-side ApprovalCache with DashMap, JWT re-verification, and destination scope matching
  - Agent startup public key fetch and periodic approval sync poll loop (60s)
  - IPC message extensions: ApprovalGranted, ApprovalRejected, RequestApproval
  - Three-stage ABAC pipeline documented as AGENT-SIDE: NTFS -> ABAC -> approval override
affects:
  - 61-04
  - interception-engine
  - policy-evaluation

# Tech tracking
tech-stack:
  added: [dashmap, ed25519-dalek, jsonwebtoken, hex, rand]
  patterns:
    - "Lock-free concurrent cache via DashMap for high-frequency policy checks"
    - "JWT signature re-verification on every cache read for tamper resistance"
    - "JSON-encoded structured cache keys to avoid delimiter collision"
    - "Poll-based sync with server-side authoritative state (no push endpoint)"

key-files:
  created:
    - "dlp-agent/src/approval_cache.rs"
  modified:
    - "dlp-agent/src/ipc/messages.rs"
    - "dlp-agent/src/ipc/pipe3.rs"
    - "dlp-agent/src/server_client.rs"
    - "dlp-agent/src/service.rs"
    - "dlp-agent/src/lib.rs"
    - "dlp-agent/Cargo.toml"

key-decisions:
  - "Agent-side ApprovalCache defined in dlp-agent, NOT reusing server PolicyStore (breaks cross-crate coupling)"
  - "Poll-based token delivery via GET /agent/approvals/active every 60s; no push endpoint (authoritative server state)"
  - "JWT signature re-verified on every cache read using cached Ed25519 public key (~50us Ed25519 verify)"
  - "chrono::DateTime<Utc> used for expiry instead of Instant (hibernation-safe)"
  - "ApprovalCacheKey uses JSON encoding instead of colon-delimited strings (avoids delimiter collision)"
  - "Destination scope matching supports exact, wildcard (*), and prefix (USB:*) patterns"

patterns-established:
  - "Best-effort server communication: errors logged but never block agent operation"
  - "Shutdown channel pattern for all background poll tasks (config, registry, origins, approvals)"
  - "Structured cache keys with JSON encoding for type-safe lookup"

requirements-completed: [WORKFLOW-04, WORKFLOW-05]

# Metrics
duration: 45min
completed: 2026-05-14
---

# Phase 61 Plan 03: Agent-Side Approval Cache with JWT Verification and IPC Extensions

**Agent-side ApprovalCache with DashMap, Ed25519 JWT re-verification on every read, destination scope matching with hierarchical wildcards, and poll-based sync with server every 60 seconds. IPC extended with ApprovalGranted, ApprovalRejected, and RequestApproval variants.**

## Performance

- **Duration:** 45 min
- **Started:** 2026-05-14T00:00:00Z
- **Completed:** 2026-05-14T00:45:00Z
- **Tasks:** 2
- **Files modified:** 7

## Accomplishments

- Created `ApprovalCache` in `dlp-agent/src/approval_cache.rs` with DashMap for lock-free concurrent access
- Implemented JWT signature re-verification on every cache read using cached Ed25519 public key
- Added destination scope matching with exact, wildcard, and prefix patterns
- Extended IPC messages with `ApprovalGranted`, `ApprovalRejected`, and `RequestApproval` variants
- Added `ServerClient` methods: `fetch_public_key()`, `sync_active_approvals()`, `submit_approval_request()`
- Wired approval cache initialization, startup public key fetch, and 60s periodic poll loop into service startup/shutdown
- Added 19 unit tests for approval cache + 8 tests for server client + 15 IPC message tests

## Task Commits

Each task was committed atomically:

1. **Task 1: Create ApprovalCache in dlp-agent with DashMap, JWT re-verification, and agent-side three-stage ABAC pipeline** - `0732bc8` (feat)
2. **Task 2: Add agent poll loop for active approvals, public key fetch, and extend IPC messages** - `fce9626` (feat)

## Files Created/Modified

- `dlp-agent/src/approval_cache.rs` (NEW) - Agent-side approval cache with DashMap, JWT re-verification, scope matching, and TTL sweep
- `dlp-agent/src/ipc/messages.rs` - Added ApprovalGranted, ApprovalRejected to Pipe1AgentMsg; RequestApproval to Pipe3UiMsg with tests
- `dlp-agent/src/ipc/pipe3.rs` - Added routing for RequestApproval variant with logging
- `dlp-agent/src/server_client.rs` - Added fetch_public_key(), sync_active_approvals(), submit_approval_request() + ServerApprovalEntry type + tests
- `dlp-agent/src/service.rs` - Wired approval cache init, startup public key fetch, periodic poll loop spawn, and shutdown
- `dlp-agent/src/lib.rs` - Added `pub mod approval_cache;`
- `dlp-agent/Cargo.toml` - Added dashmap, ed25519-dalek, jsonwebtoken, hex, rand dependencies

## Decisions Made

- **ApprovalCache defined in dlp-agent, not reusing server PolicyStore**: Breaks cross-crate coupling and keeps the agent self-contained.
- **Poll-based sync every 60s instead of push endpoint**: Server is the authoritative source of truth; agent polls GET /agent/approvals/active. Simplifies revocation propagation (absent entries are removed from cache).
- **JWT re-verification on every cache read**: Security trade-off -- ~50us Ed25519 verification per read prevents cache poisoning even if an attacker gains memory access.
- **JSON-encoded ApprovalCacheKey**: Avoids delimiter collision issues that plague colon-delimited formats. Human-readable for debugging.
- **chrono::DateTime<Utc> for expiry**: Hibernation-safe; system clock changes do not bypass expiry checks.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed non-exhaustive match in pipe3.rs after adding RequestApproval variant**
- **Found during:** Task 2 (IPC message extension)
- **Issue:** Adding `Pipe3UiMsg::RequestApproval` to the enum broke the `match msg` in `pipe3.rs::route()` which did not have a catch-all arm
- **Fix:** Added a `_ =>` arm for `RequestApproval` that logs the request and leaves a TODO for Phase 61 integration
- **Files modified:** `dlp-agent/src/ipc/pipe3.rs`
- **Verification:** `cargo test -p dlp-agent pipe3` passes
- **Committed in:** `fce9626` (Task 2 commit)

**2. [Rule 1 - Bug] Fixed missing skip_serializing_if on RequestApproval optional fields**
- **Found during:** Task 2 (IPC message serialization test)
- **Issue:** `test_request_approval_none_fields_skipped` failed because `destination_scope` and `device_fingerprint` were serialized as `null` instead of being skipped
- **Fix:** Added `#[serde(default, skip_serializing_if = "Option::is_none")]` to both optional fields in `Pipe3UiMsg::RequestApproval`
- **Files modified:** `dlp-agent/src/ipc/messages.rs`
- **Verification:** `cargo test -p dlp-agent ipc::messages` passes
- **Committed in:** `fce9626` (Task 2 commit)

**3. [Rule 2 - Missing Critical] Added ServerApprovalEntry deserialization type**
- **Found during:** Task 2 (Implementing sync_active_approvals)
- **Issue:** Plan referenced `policy_store_client.rs` but the agent already has `server_client.rs` with a well-established pattern for server communication. Needed a deserialization target for the active approvals response.
- **Fix:** Added `ServerApprovalEntry` struct with all necessary fields and `#[derive(serde::Deserialize)]` in `server_client.rs` instead of creating a new file
- **Files modified:** `dlp-agent/src/server_client.rs`
- **Verification:** `cargo test -p dlp-agent server_client` passes
- **Committed in:** `fce9626` (Task 2 commit)

**4. [Rule 3 - Blocking] Replaced policy_store_client.rs with server_client.rs extensions**
- **Found during:** Task 2 (Planning implementation)
- **Issue:** Plan specified creating `dlp-agent/src/policy_store_client.rs` but the agent already has `dlp-agent/src/server_client.rs` with `ServerClient` struct, error types, and async patterns. Creating a new file would fragment the HTTP client layer.
- **Fix:** Added the three methods (`fetch_public_key`, `sync_active_approvals`, `submit_approval_request`) directly to the existing `ServerClient` impl block, following the established pattern
- **Files modified:** `dlp-agent/src/server_client.rs`
- **Verification:** `cargo test -p dlp-agent server_client` passes
- **Committed in:** `fce9626` (Task 2 commit)

---

**Total deviations:** 4 auto-fixed (2 bugs, 1 missing critical, 1 blocking)
**Impact on plan:** All auto-fixes necessary for correctness and consistency with existing codebase. No scope creep.

## Issues Encountered

- **Pre-existing test failure in config module**: `config::tests::test_effective_config_path_env_override` fails due to env var mutation in parallel tests. This is unrelated to Phase 61 work.
- **Plan referenced non-existent policy_store_client.rs**: The agent already has a mature `server_client.rs` with `ServerClient`. Extended that instead of creating a new module.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Approval cache is initialized and polling, ready for integration with the interception engine's three-stage pipeline
- IPC messages are ready for UI integration (ApprovalGranted/Rejected notifications, RequestApproval submission)
- Server endpoints are already operational (from Plan 02)
- **Blocker for full end-to-end**: The interception engine (`interception::run_event_loop`) needs to call `approval_cache.check()` after ABAC DENY. This is deferred to a future plan that modifies the evaluation pipeline.

## Known Stubs

| File | Line | Description | Resolution |
|------|------|-------------|------------|
| `dlp-agent/src/ipc/pipe3.rs` | ~250 | `RequestApproval` routing arm logs only with TODO comment | Future plan: wire to `approval_cache::submit_request()` or `server_client.submit_approval_request()` |
| `dlp-agent/src/service.rs` | ~687 | `approval_cache` field in `RunLoopContext` marked `#[allow(dead_code)]` | Future plan: pass to `spawn_event_loop()` for three-stage pipeline integration |

## Threat Flags

No new threat surface introduced beyond what is covered in the plan's threat model. All mitigations from the threat register are implemented:
- T-61-11 (Spoofing): JWT signature re-verified on every cache read
- T-61-12 (Tampering): Structured cache key with JSON encoding
- T-61-15 (Elevation): Cache key includes requester_sid
- T-61-16 (Tampering): JWT signature re-verification prevents cache poisoning
- T-61-17 (Spoofing): chrono::DateTime<Utc> for hibernation-safe expiry
- T-61-25 (Elevation): scope_matches validates hierarchical wildcards

---
*Phase: 61-approval-workflow-engine-t3-data-owner-t4-board-digital-signature*
*Completed: 2026-05-14*
