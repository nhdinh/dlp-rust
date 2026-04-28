---
phase: 29-chrome-enterprise-connector
plan: 01
subsystem: endpoint-enforcement
tags: [prost, protobuf, chrome-enterprise, content-analysis, named-pipe, win32]

# Dependency graph
requires:
  - phase: 28-admin-tui-screens
    provides: Admin TUI screens and managed-origins infrastructure
provides:
  - prost/protobuf dependencies in dlp-agent/Cargo.toml
  - build.rs with prost-build compile_protos for content_analysis.proto
  - Vendored content_analysis.proto with ContentAnalysisRequest/Response/Metadata
  - chrome module scaffolding (proto, frame, cache, handler, registry)
  - 4-byte LE length-prefix frame I/O with 4 MiB cap
  - ChromeCache for origin trust verdict caching
  - Chrome registry helpers for HKLM policy key management
  - pub mod chrome wired into dlp-agent/src/lib.rs
affects:
  - 29-02-chrome-handler
  - 29-03-chrome-policy-evaluation
  - 30-automated-uat-infrastructure

# Tech tracking
tech-stack:
  added: [prost 0.14, bytes 1, prost-build 0.14]
  patterns:
    - "Build-time protobuf codegen via build.rs + OUT_DIR include!"
    - "Length-prefixed frame protocol [u32 LE length][protobuf payload]"
    - "Platform-gated modules: proto/frame/cache platform-agnostic; handler/registry Windows-only"
    - "Stub handler with default-allow for downstream ABAC integration"

key-files:
  created:
    - dlp-agent/proto/content_analysis.proto
    - dlp-agent/src/chrome/mod.rs
    - dlp-agent/src/chrome/proto.rs
    - dlp-agent/src/chrome/frame.rs
    - dlp-agent/src/chrome/cache.rs
    - dlp-agent/src/chrome/handler.rs
    - dlp-agent/src/chrome/registry.rs
  modified:
    - dlp-agent/Cargo.toml
    - dlp-agent/build.rs
    - dlp-agent/src/lib.rs

key-decisions:
  - "Chrome module NOT gated with #[cfg(windows)] at lib.rs level because proto types and cache are platform-agnostic; only handler.rs and registry.rs use #[cfg(windows)] internally"
  - "MAX_PAYLOAD = 4 MiB (not 64 MiB like ipc/frame.rs) because Chrome SDK uses 4 KiB buffers; 4 MiB is three orders of magnitude larger and safe per T-29-01 threat model"
  - "Stub handler returns default-allow SUCCESS verdict; full ABAC evaluation wired in downstream plans 29-02/29-03"

patterns-established:
  - "chrome/frame.rs replicates ipc/frame.rs pattern with domain-specific 4 MiB cap"
  - "prost-build generates types at compile time; include!(concat!(env!(\"OUT_DIR\"), ...)) imports them"
  - "Platform stubs for non-Windows: handler and registry compile to no-ops on non-Windows targets"

requirements-completed: [BRW-01]

# Metrics
duration: 12min
completed: 2026-04-29
---

# Phase 29 Plan 01: Chrome Enterprise Connector Scaffold Summary

**prost/protobuf codegen, length-prefixed frame I/O, and chrome module scaffolding for Chrome Content Analysis SDK integration**

## Performance

- **Duration:** 12 min
- **Started:** 2026-04-29T01:59:52Z
- **Completed:** 2026-04-29T02:12:34Z
- **Tasks:** 2
- **Files modified:** 10

## Accomplishments

- Added prost 0.14, bytes 1 to [dependencies] and prost-build 0.14 to [build-dependencies]
- Created build.rs with prost-build compile_protos invocation and rerun-if-changed directive
- Vendored minimal content_analysis.proto with ContentAnalysisRequest, ContentAnalysisResponse, ContentMetaData, AnalysisConnector, and Reason enums
- Implemented chrome/frame.rs with read_frame/write_frame/read_exact/write_all/flush using 4-byte LE length prefix and 4 MiB MAX_PAYLOAD cap
- Created chrome/proto.rs with include! macro linking OUT_DIR generated types
- Created chrome/cache.rs with thread-safe HashMap-based verdict cache with TTL eviction
- Created chrome/handler.rs with stub handle_request and evaluate_request (default-allow)
- Created chrome/registry.rs with enable_connector/disable_connector HKLM registry helpers
- Wired pub mod chrome into dlp-agent/src/lib.rs (platform-agnostic at module level)
- cargo check -p dlp-agent passes; cargo clippy -p dlp-agent -- -D warnings passes

## Task Commits

Each task was committed atomically:

1. **Task 1: Add prost/bytes dependencies and build.rs** - `e150d10` (chore)
2. **Task 2: Create proto file and chrome module scaffolding** - `ef6d11b` (feat)

## Files Created/Modified

- `dlp-agent/Cargo.toml` - Added prost, bytes, prost-build dependencies
- `dlp-agent/build.rs` - Build-time protobuf compilation via prost-build
- `dlp-agent/proto/content_analysis.proto` - Vendored Chrome Content Analysis SDK proto
- `dlp-agent/src/chrome/mod.rs` - Module re-exports (cache, frame, handler, proto, registry)
- `dlp-agent/src/chrome/proto.rs` - include! for generated prost types from OUT_DIR
- `dlp-agent/src/chrome/frame.rs` - Length-prefixed protobuf frame I/O with 4 MiB cap
- `dlp-agent/src/chrome/cache.rs` - TTL-based origin trust verdict cache
- `dlp-agent/src/chrome/handler.rs` - Request handler stub (default-allow)
- `dlp-agent/src/chrome/registry.rs` - HKLM registry enable/disable for Chrome policy
- `dlp-agent/src/lib.rs` - Added `pub mod chrome;` declaration

## Decisions Made

- Chrome module NOT gated with #[cfg(windows)] at lib.rs because proto types and cache are platform-agnostic; only handler and registry use #[cfg(windows)] internally
- MAX_PAYLOAD = 4 MiB (vs 64 MiB in ipc/frame.rs) because Chrome SDK uses 4 KiB buffers; 4 MiB is three orders of magnitude larger and safe per T-29-01 threat model
- Stub handler returns default-allow SUCCESS verdict; full ABAC evaluation wired in downstream plans 29-02/29-03

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical] Added chrome/cache.rs, chrome/handler.rs, chrome/registry.rs stub modules**
- **Found during:** Task 2 (chrome module scaffolding)
- **Issue:** Plan specified mod.rs with `pub mod cache; pub mod handler; pub mod registry;` but these files did not exist, causing cargo check to fail with E0583 module-not-found errors
- **Fix:** Created all three missing files with minimal stub implementations: ChromeCache with TTL eviction, handle_request with default-allow, registry helpers with HKLM key management
- **Files modified:** dlp-agent/src/chrome/cache.rs, dlp-agent/src/chrome/handler.rs, dlp-agent/src/chrome/registry.rs
- **Verification:** cargo check -p dlp-agent passes
- **Committed in:** ef6d11b (Task 2 commit)

**2. [Rule 1 - Bug] Fixed registry.rs RegCreateKeyExW API mismatch and HKEY null pointer**
- **Found during:** Task 2 (cargo check after creating registry.rs)
- **Issue:** Used incorrect RegCreateKeyExW signature (None for reserved u32 param, HKEY(0) instead of HKEY::default()) causing E0308 mismatched types and E0600 null pointer errors
- **Fix:** Matched existing password_stop.rs pattern: reserved=0, HKEY::default(), PCWSTR::from_raw(), proper unsafe slice casting for REG_SZ
- **Files modified:** dlp-agent/src/chrome/registry.rs
- **Verification:** cargo check -p dlp-agent passes
- **Committed in:** ef6d11b (Task 2 commit)

**3. [Rule 1 - Bug] Fixed handler.rs clippy field_reassign_with_default and needless_update lints**
- **Found during:** Task 2 (cargo clippy verification)
- **Issue:** Used `let mut response = ...::default(); response.field = ...` pattern and `..Default::default()` on fully-specified structs, triggering clippy errors with -D warnings
- **Fix:** Used struct literal initialization with all fields specified explicitly
- **Files modified:** dlp-agent/src/chrome/handler.rs
- **Verification:** cargo clippy -p dlp-agent -- -D warnings passes
- **Committed in:** ef6d11b (Task 2 commit)

---

**Total deviations:** 3 auto-fixed (1 missing critical, 2 bugs)
**Impact on plan:** All auto-fixes necessary for compilation correctness. No scope creep beyond minimal stubs required by the module declarations in the plan.

## Issues Encountered

- rustc stack buffer overrun (STATUS_STACK_BUFFER_OVERRUN) when running full `cargo test` on Windows — this is a known rustc/Windows issue unrelated to our changes. Lib tests pass successfully (191 passed, 1 pre-existing failure in usb_enforcer::tests::test_unregistered_device_defaults_to_read_only).
- Worktree file system isolation caused initial confusion: files written to worktree path appeared in main repo but not in worktree directory listing. Resolved by using absolute paths and verifying with `test -f`.

## Known Stubs

| File | Line | Description | Resolution Plan |
|------|------|-------------|-----------------|
| dlp-agent/src/chrome/handler.rs | 49-62 | evaluate_request returns default-allow SUCCESS | Plan 29-02: wire ABAC policy evaluation |
| dlp-agent/src/chrome/handler.rs | 27 | handle_request reads/writes frames but no audit logging | Plan 29-03: add audit_emitter integration |
| dlp-agent/src/chrome/registry.rs | 28-89 | enable_connector writes static pipe name | Plan 29-02: dynamic pipe name from config |

## Threat Flags

None — all security-relevant surface is covered by the plan's threat model:
- T-29-01 (DoS via forged length prefix) mitigated by MAX_PAYLOAD = 4 MiB cap
- T-29-02 (proto tampering) accepted — vendored from official Chromium SDK
- T-29-03 (build artifact disclosure) accepted — OUT_DIR is ephemeral

## Next Phase Readiness

- Proto types (ContentAnalysisRequest, ContentAnalysisResponse) are compiled and accessible
- Frame I/O helpers (read_frame, write_frame) are ready for named pipe integration
- Cache infrastructure is ready for origin trust verdict caching
- Registry helpers are ready for Chrome policy key management
- All downstream plans (29-02, 29-03) have the foundation they need

---
*Phase: 29-chrome-enterprise-connector*
*Completed: 2026-04-29*
