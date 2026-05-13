---
phase: 61-approval-workflow-engine-t3-data-owner-t4-board-digital-signature
plan: 01
subsystem: database
tags: [ed25519, jwt, sqlite, approval-workflow, tokctou, encryption-at-rest]

requires:
  - phase: 47-secrets-encryption-at-rest
    provides: SecretCrypto envelope infrastructure (PBKDF2 + DPAPI + AES-256-GCM)
  - phase: 59-label-service
    provides: labels table and LabelService for data object references
  - phase: 60-data-owner-review-queue
    provides: Data Owner scoping patterns and admin TUI screen conventions

provides:
  - ApprovalStatus enum with 5 lifecycle variants (Pending, Approved, Rejected, Revoked, Expired)
  - Approval struct with full lifecycle fields including T4 signature support
  - ApprovalClaims JWT payload struct shared across dlp-common/dlp-server boundary
  - ApprovalCacheKey structured cache key with JSON encoding (prevents scope bypass)
  - approvals SQLite table with CHECK constraint and 5 indexes
  - ApprovalRepository with CRUD, filtering, pagination, and TOCTOU-guarded state transitions
  - ApprovalTokenService with Ed25519 JWT signing/verification and iss claim validation
  - Board public key storage/retrieval in system_kv
  - T4 canonical message format with jti anti-replay
  - decrypt_bytes() on SecretCrypto for binary secret support

affects:
  - Plan 02 (admin API endpoints for approval CRUD and grant/reject)
  - Plan 03 (agent integration — token validation in ABAC pipeline)
  - Plan 04 (admin TUI approval list and detail screens)

tech-stack:
  added:
    - ed25519-dalek v2 (Ed25519 signing with pkcs8 feature)
    - rand v0.8 (CSPRNG for key generation)
    - hex v0.4 (hex encoding for key storage)
  patterns:
    - Structured cache keys via JSON encoding (replaces fragile colon-delimited strings)
    - TOCTOU guard via parameterized WHERE status = ? in state transitions
    - Binary secret storage via decrypt_bytes() on SecretCrypto envelope
    - Cross-crate type sharing: ApprovalClaims in dlp-common to break circular dependency

key-files:
  created:
    - dlp-common/src/approval.rs — Approval types, ApprovalClaims, ApprovalCacheKey
    - dlp-server/src/db/repositories/approvals.rs — ApprovalRepository with full CRUD
    - dlp-server/src/approval_token.rs — ApprovalTokenService with Ed25519 JWT
  modified:
    - dlp-common/src/lib.rs — Export approval module
    - dlp-server/src/db/mod.rs — approvals table schema in init_tables()
    - dlp-server/src/db/repositories/mod.rs — Export ApprovalRepository
    - dlp-server/src/lib.rs — Add approval_token module, extend AppState
    - dlp-server/src/main.rs — Initialize ApprovalTokenService at startup
    - dlp-server/src/crypto/mod.rs — Add decrypt_bytes() for binary secrets
    - dlp-server/Cargo.toml — Add ed25519-dalek, rand, hex dependencies
    - dlp-server/src/admin_api.rs — Update all test AppState initializers
    - dlp-e2e/src/lib.rs — Update test AppState initializer
    - dlp-server/tests/*.rs — Update test AppState initializers (6 files)

key-decisions:
  - "Moved ApprovalClaims to dlp-common to break circular dependency between server (signer) and agent (verifier)"
  - "Used JSON encoding for ApprovalCacheKey instead of colon-delimited strings to prevent delimiter collision and scope bypass"
  - "Added decrypt_bytes() to SecretCrypto rather than base64-encoding binary keys — cleaner API, no double encoding"
  - "T4 canonical message includes jti (approval ID) to prevent signature replay across different approvals"
  - "data_object_id is a soft reference (no FK) so path-based approvals work during pilot phase"

patterns-established:
  - "Structured cache keys: Use JSON-serialized structs instead of string concatenation for composite keys"
  - "TOCTOU guards: Parameterized WHERE status = ? with expected_current_status, returning rows_affected"
  - "Binary secret envelope: Use decrypt_bytes() for non-UTF-8 secrets, decrypt() for text secrets"

requirements-completed: [WORKFLOW-01]

duration: 45min
completed: 2026-05-14
---

# Phase 61 Plan 01: Approval Workflow Foundation Summary

**Ed25519 JWT approval tokens with encrypted key storage, SQLite approvals table with TOCTOU guards, and structured cache keys for T3 Data Owner / T4 Board digital-signature workflows**

## Performance

- **Duration:** 45 min
- **Started:** 2026-05-14T00:00:00Z
- **Completed:** 2026-05-14T00:00:00Z
- **Tasks:** 5 (0 spike + 4 implementation + 1 migration)
- **Files modified:** 19

## Accomplishments

- Created `dlp-common/src/approval.rs` with ApprovalStatus, Approval, ApprovalToken, ApprovalRequest, ApprovalClaims, CachedApproval, and ApprovalCacheKey types
- Added `approvals` table to `init_tables()` with CHECK constraint on status and 5 indexes
- Built `ApprovalRepository` with list, list_by_status, list_by_requester, get_by_id, insert, update_state (TOCTOU-guarded), delete, cleanup_orphaned, and count_by_status
- Implemented `ApprovalTokenService` with Ed25519 keypair generation/loading, encrypted storage via Phase 47 SecretCrypto, JWT sign/verify with iss validation
- Added `decrypt_bytes()` to `SecretCrypto` for binary secret support (Ed25519 signing keys are raw bytes, not UTF-8)
- Extended `AppState` with `approval_token_service` and updated all 20+ test initializers across the codebase

## Task Commits

Each task was committed atomically:

1. **Task 0: Ed25519 Compilation Spike** — verified via `/tmp/ed25519-spike` (not committed)
2. **Task 1: Create dlp-common approval types** — `221414c` (feat)
3. **Task 2: Create approvals table and ApprovalRepository** — `37ff114` (feat)
4. **Task 3: Create ApprovalTokenService with Ed25519 JWT signing** — `e896510` (feat)
5. **Task 4: Database migration** — included in Task 2 commit (init_tables idempotent)
6. **Fix: AppState in dlp-e2e and Signer trait** — `a62f6ab` (fix)

## Files Created/Modified

- `dlp-common/src/approval.rs` — Approval types, ApprovalClaims, ApprovalCacheKey (411 lines, 12 tests)
- `dlp-server/src/db/repositories/approvals.rs` — ApprovalRepository with full CRUD and TOCTOU guard (802 lines, 13 tests)
- `dlp-server/src/approval_token.rs` — ApprovalTokenService with Ed25519 JWT signing/verification (552 lines, 11 tests)
- `dlp-server/src/crypto/mod.rs` — Added decrypt_bytes() for binary secret support
- `dlp-server/src/db/mod.rs` — approvals table schema with CHECK constraint and indexes
- `dlp-server/src/lib.rs` — approval_token module, AppState extension
- `dlp-server/src/main.rs` — ApprovalTokenService initialization at startup
- `dlp-server/Cargo.toml` — ed25519-dalek, rand, hex dependencies
- `dlp-server/src/admin_api.rs` — All test AppState initializers updated
- `dlp-e2e/src/lib.rs` — Test AppState initializer updated
- `dlp-server/tests/*.rs` — 6 integration test files updated

## Decisions Made

- Moved `ApprovalClaims` to `dlp-common` to break circular dependency: server signs tokens, agent verifies them
- Used JSON encoding for `ApprovalCacheKey` instead of colon-delimited strings — prevents delimiter collision and makes scope bypass impossible
- Added `decrypt_bytes()` to `SecretCrypto` rather than base64-wrapping binary keys — the crypto module's comment explicitly预留了 this API for binary secrets
- T4 canonical message format: `DLP-T4-SIGNATURE:{jti}:{sub}:{obj}:{act}:{valid_until}` — jti prevents replay across approvals

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical] Added decrypt_bytes() to SecretCrypto for binary secret support**
- **Found during:** Task 3 (ApprovalTokenService implementation)
- **Issue:** Ed25519 signing keys are 32 raw bytes, not valid UTF-8. SecretCrypto::decrypt() returns SecretString which requires UTF-8, causing CryptoError::InvalidEnvelope on key reload
- **Fix:** Added decrypt_bytes() method to SecretCrypto that returns Vec<u8> without UTF-8 conversion, following the existing code comment that预留了 this API
- **Files modified:** dlp-server/src/crypto/mod.rs, dlp-server/src/approval_token.rs
- **Verification:** test_new_loads_existing_key now passes (key reload round-trips correctly)
- **Committed in:** e896510 (Task 3 commit)

**2. [Rule 3 - Blocking] Updated 20+ AppState initializers across codebase**
- **Found during:** Task 3 (compilation after adding approval_token_service to AppState)
- **Issue:** Adding a new field to AppState broke every test that constructs AppState inline (lib tests, integration tests, e2e tests)
- **Fix:** Updated all AppState initializers in dlp-server/src/admin_api.rs (16 locations), dlp-server/tests/*.rs (6 files), and dlp-e2e/src/lib.rs (1 location)
- **Files modified:** dlp-server/src/admin_api.rs, dlp-server/tests/*.rs, dlp-e2e/src/lib.rs
- **Verification:** cargo test passes (580 tests)
- **Committed in:** e896510 and a62f6ab

**3. [Rule 1 - Bug] Fixed pool move-after-use in inline AppState initializers**
- **Found during:** Task 3 (compilation after adding approval_token_service)
- **Issue:** The inline pattern `pool` moved into AppState before `pool.get()` was called for ApprovalTokenService::new(), causing E0382 borrow-after-move
- **Fix:** Restructured initializers to get connection before moving pool: `let conn = pool.get(); let state = Arc::new(AppState { pool, ..., approval_token_service: ... })`
- **Files modified:** dlp-server/src/admin_api.rs
- **Verification:** cargo build passes
- **Committed in:** e896510

---

**Total deviations:** 3 auto-fixed (1 missing critical, 2 blocking)
**Impact on plan:** All auto-fixes necessary for correctness. No scope creep.

## Issues Encountered

- Ed25519 spike needed `rand` crate addition (not in original spike Cargo.toml) — fixed immediately
- `Signer` trait import was removed as "unused" but is actually needed in test code for `board_signing.sign(message)` — restored
- `OptionalExtension` trait from rusqlite needed explicit import for `.optional()` method

## Threat Flags

| Flag | File | Description |
|------|------|-------------|
| threat_flag: new_crypto_surface | dlp-server/src/approval_token.rs | Ed25519 signing key stored encrypted in system_kv; agent will verify with public key |
| threat_flag: new_db_table | dlp-server/src/db/mod.rs | approvals table stores requester_sid, approver_sid, and justification text — PII surface |

## Known Stubs

None. All types are fully wired with no placeholder data.

## Next Phase Readiness

- Plan 02 (admin API) can now use ApprovalRepository for CRUD endpoints and ApprovalTokenService for grant/reject token generation
- Plan 03 (agent integration) can import ApprovalClaims from dlp-common for token verification
- Plan 04 (admin TUI) can use ApprovalCacheKey for structured approval lookups

---
*Phase: 61-approval-workflow-engine-t3-data-owner-t4-board-digital-signature*
*Completed: 2026-05-14*
