---
phase: 29-chrome-enterprise-connector
plan: 03
subsystem: agent
tags: [chrome, pipe, named-pipe, protobuf, registry, hkml, service-lifecycle, audit]

requires:
  - phase: 29-01
    provides: Chrome module scaffold (proto, frame, build.rs, Cargo.toml deps)
  - phase: 29-02
    provides: ManagedOriginsCache, server_client fetch, AuditEvent origin fields
provides:
  - Chrome pipe server at \\.\pipe\brcm_chrm_cas with accept loop + protobuf dispatch
  - dispatch_request blocks CLIPBOARD_PASTE from managed origins, allows all else
  - to_origin URL normalization (scheme+host, lowercase, strip path/query/port)
  - emit_chrome_block_audit with source_origin/destination_origin on BLOCK
  - HKLM self-registration with DLP_SKIP_CHROME_REG=1 override, non-fatal on failure
  - Service lifecycle integration (run_service + run_console spawn + cache + shutdown)
affects:
  - 29-chrome-enterprise-connector (Plan 04 will add pipe-level integration tests)

tech-stack:
  added: []
  patterns:
    - "Pipe server on dedicated std::thread (not tokio task) — same as IPC P1/P2/P3"
    - "Global OnceLock<Arc<ManagedOriginsCache>> for read-only cross-thread access"
    - "HKLM registration best-effort: warn! + return Ok(()) on failure"
    - "to_origin normalization: trim, lowercase, extract scheme://host, strip port"

key-files:
  created: []
  modified:
    - dlp-agent/src/chrome/handler.rs — Full pipe server + decision logic + audit
    - dlp-agent/src/chrome/registry.rs — HKLM self-registration (replaced stub)
    - dlp-agent/src/chrome/mod.rs — Added frame, handler, proto, registry exports
    - dlp-agent/src/service.rs — Chrome thread spawn, cache setup, shutdown cleanup

key-decisions:
  - "Replaced 29-01 stub handler.rs with full implementation rather than editing in place"
  - "Replaced 29-01 stub registry.rs with simplified single-value registration (pipe_name only)"
  - "Added anyhow::Context to service.rs imports to support .context() on thread spawn"

patterns-established:
  - "Chrome pipe thread spawn mirrors IPC pipe server pattern exactly"
  - "ManagedOriginsCache lifecycle mirrors DeviceRegistryCache (create, set global, spawn poll, shutdown)"

requirements-completed:
  - BRW-01
  - BRW-03

duration: 12min
completed: 2026-04-29
---

# Phase 29 Plan 03: Chrome Pipe Server + Registry + Service Integration Summary

**Chrome Content Analysis pipe server at \\.\pipe\brcm_chrm_cas with protobuf request dispatch, managed-origin block decisions, HKLM self-registration, and full service/console lifecycle integration.**

## Performance

- **Duration:** 12 min
- **Started:** 2026-04-29T01:15:00Z
- **Completed:** 2026-04-29T01:27:00Z
- **Tasks:** 3
- **Files modified:** 4

## Accomplishments
- handler.rs: complete pipe server (serve, accept_loop, create_pipe, handle_client, cleanup_pipe)
- handler.rs: to_origin URL normalization with unit-testable doc examples
- handler.rs: dispatch_request blocks CLIPBOARD_PASTE from managed origins, allows all else
- handler.rs: emit_chrome_block_audit creates AuditEvent with source_origin/destination_origin
- registry.rs: HKLM self-registration with DLP_SKIP_CHROME_REG=1 test override
- service.rs: chrome pipe thread spawned in both service and console modes
- service.rs: managed origins cache created, set_origins_cache called, poll task spawned
- service.rs: shutdown cleanup sends origins_shutdown_tx and awaits poll handle in both modes
- cargo check -p dlp-agent compiles with zero errors

## Task Commits

1. **Task 1 + 2: Chrome pipe server, registry self-registration, and handler modules** - `d4921b0` (feat)
2. **Task 3: Wire Chrome pipe thread, registry, and origins cache into service lifecycle** - `f3c7c4d` (feat)

## Files Created/Modified
- `dlp-agent/src/chrome/handler.rs` — Full pipe server + decision logic + audit (replaced stub)
- `dlp-agent/src/chrome/registry.rs` — HKLM self-registration with non-fatal failure (replaced stub)
- `dlp-agent/src/chrome/mod.rs` — Added frame, handler, proto, registry submodule exports
- `dlp-agent/src/service.rs` — Chrome thread spawn, cache setup, shutdown cleanup in run_service/run_loop/run_console/async_run_console

## Decisions Made
- Replaced 29-01 stub files entirely rather than incremental edits — cleaner, less error-prone
- Simplified registry.rs to single pipe_name value (removed Enabled DWORD) — Chrome discovers agent via pipe name alone per SDK docs
- Added anyhow::Context import to service.rs — needed for .context() on std::thread::Builder::spawn() Result

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Missing anyhow::Context import in service.rs**
- **Found during:** Task 3 (service.rs wiring)
- **Issue:** `.context("failed to spawn Chrome pipe thread")` failed to compile because `anyhow::Context` trait was not in scope (only `anyhow::Result` was imported)
- **Fix:** Changed `use anyhow::Result;` to `use anyhow::{Context, Result};` at line 28
- **Files modified:** dlp-agent/src/service.rs
- **Verification:** `cargo check -p dlp-agent` passes
- **Committed in:** f3c7c4d (Task 3 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** Minor import fix, no scope creep.

## Issues Encountered
- None beyond the missing Context import (auto-fixed inline)

## Known Stubs

None — all functions are fully implemented. The `destination_origin` parameter in `emit_chrome_block_audit` is always `None` because the Chrome Content Analysis SDK clipboard paste request only carries a source URL, not a destination. This is correct per the protocol.

## Threat Flags

| Flag | File | Description |
|------|------|-------------|
| threat_flag: new_pipe_endpoint | dlp-agent/src/chrome/handler.rs | New named pipe `\\.\pipe\brcm_chrm_cas` — mitigated by PipeSecurity DACL (Authenticated Users read/write) |
| threat_flag: registry_write | dlp-agent/src/chrome/registry.rs | HKLM write at `SOFTWARE\Google\Chrome\3rdparty\cas_agents` — non-fatal, no privilege escalation path |

## Next Phase Readiness
- Chrome pipe server is ready for integration testing (Plan 04)
- ManagedOriginsCache is wired and polling
- No blockers

---
*Phase: 29-chrome-enterprise-connector*
*Completed: 2026-04-29*
