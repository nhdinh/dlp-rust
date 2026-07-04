# Codebase Concerns

**Analysis Date:** 2026-07-03

## Tech Debt

**Widespread `.unwrap()` Usage:**
- Issue: Approximately 958 `.unwrap()` calls across the codebase; many are in tests, but a significant number remain in production paths.
- Files: `dlp-admin-cli/src/render.rs`, `dlp-admin-cli/src/dispatch.rs`, `dlp-agent/src/*.rs`.
- Impact: Unhandled panics can crash the agent service or admin CLI, causing denial of service on protected endpoints.
- Fix approach: Audit non-test unwraps; convert production paths to `Result<T, E>` propagation. Prioritize `dlp-agent` and `dlp-server`.

**Extensive `unsafe` Surface in Hook DLL:**
- Issue: `dlp-hook-dll` contains `static mut` original function pointers, runtime ntdll patching, and inline syscall trampolines.
- Files: `dlp-hook-dll/src/lib.rs`, `dlp-hook-dll/src/trampolines.rs`, `dlp-hook-dll/src/ntdll_patcher.rs`.
- Impact: Memory safety violations can crash or compromise every protected process.
- Fix approach: Replace `static mut` with `OnceLock<Mutex<[AtomicPtr; N]>>`; add safety docs; consider external security review.

**Manual `Send`/`Sync` Implementations:**
- Issue: `unsafe impl Send for JournalReader` / `unsafe impl Sync for JournalReader` in bypass correlator.
- Files: `dlp-agent/src/bypass_correlator.rs`.
- Impact: Potential data races if invariants are not upheld.
- Fix approach: Verify and document safety invariants; add `miri` runs.

**Clippy Suppressions Masking Design Smells:**
- Issue: Multiple `#[allow(clippy::too_many_arguments)]`, `#[allow(clippy::type_complexity)]`, `#[allow(clippy::too_many_lines)]`, `#[allow(clippy::large_enum_variant)]`.
- Files: `dlp-admin-cli/src/render.rs`, `dlp-agent/src/service.rs`, `dlp-agent/src/etw_kernel_file.rs`, `dlp-agent/src/ipc/messages.rs`, `dlp-user-ui/src/ipc/messages.rs`, `dlp-hook-dll/src/trampolines.rs`.
- Impact: Structural problems remain unaddressed, increasing maintenance burden.
- Fix approach: Treat each suppression as a refactoring ticket; decompose large functions and split large enum variants into `Box<T>`.

**Dead Code Accumulation:**
- Issue: 50+ `#[allow(dead_code)]` attributes, concentrated in `dlp-admin-cli/src/app.rs` and `dlp-admin-cli/src/client.rs`.
- Files: `dlp-admin-cli/src/app.rs`, `dlp-admin-cli/src/client.rs`.
- Impact: Increased binary size, compilation time, and cognitive load.
- Fix approach: Remove genuinely dead code; use `#[expect(dead_code)]` with linked issue for intentionally reserved code.

**Library `println!` Statements:**
- Issue: `println!` used outside CLI entry points for "acceptable" errors.
- Files: `dlp-agent/src/dacl_repair_watcher.rs`, `dlp-agent/src/dacl_tripwire.rs`.
- Impact: Unstructured console output interferes with log aggregation and SIEM pipelines.
- Fix approach: Replace with `tracing::warn!` or `tracing::error!`.

## Known Bugs

**SIEM Credential Exposure on Read:**
- Symptoms: `GET /admin/siem-config` returns `splunk_token` and `elk_api_key` in plaintext.
- Files: `dlp-server/src/handlers/admin.rs`.
- Trigger: Any admin with a valid JWT calls the SIEM config read endpoint.
- Workaround: None; treat as high-priority security fix.
- Fix approach: Apply the same mask-on-GET pattern used for `smtp_password` and `webhook_secret`.

**Label Service Exact-Match Tier Comparison:**
- Symptoms: Potential mismatch between label tier and classification tier due to exact-match logic.
- Files: `dlp-agent/src/classification_cache.rs`, `dlp-server/src/label_service.rs`.
- Trigger: Policies relying on label-aware classification with tier overlap.
- Workaround: Review policy conditions manually.

## Security Considerations

**Secrets at Rest:**
- Risk: KEK seed and encrypted columns must remain protected.
- Files: `dlp-server/src/crypto/mod.rs`, `dlp-server/src/db/repositories/secret_kek.rs`.
- Current mitigation: Envelope encryption (AES-256-GCM + per-row DEKs), DPAPI on Windows, `secure_delete` PRAGMA.
- Recommendations: Rotate KEK regularly; audit access to database file and backups.

**Hook DLL Injection Target:**
- Risk: Running code inside third-party processes is high-privilege and error-prone.
- Files: `dlp-hook-dll/src/lib.rs`, `dlp-agent/src/hook_injector.rs`, `dlp-agent/src/universal_injector.rs`.
- Current mitigation: Self-allowlist, reentrancy guards, crash guards, EDR detection, optional ntdll patching gated by policy flag.
- Recommendations: Fuzz shared-memory protocol; run `miri` on bypass correlator; external security review.

**Named Pipe ACLs:**
- Risk: Misconfigured pipe security descriptors could allow unprivileged access.
- Files: `dlp-agent/src/ipc/pipe_security.rs`, `dlp-agent/src/ipc/pipe*.rs`.
- Current mitigation: SYSTEM-default DACLs on named pipes.
- Recommendations: Explicitly set least-privilege DACLs; document expected ACLs.

## Performance Bottlenecks

**Policy Evaluation under High Volume:**
- Problem: Every file operation can trigger HTTPS `/evaluate` on cache miss.
- Files: `dlp-agent/src/engine_client.rs`, `dlp-agent/src/cache.rs`.
- Cause: Cache hit rate depends on workload locality; cache misses are synchronous network round-trips.
- Improvement path: Increase cache TTL for stable policies; implement local provisional classification; batch evaluations.

**Hook DLL Path Extraction:**
- Problem: Resolving full paths from handles inside hooked functions is expensive.
- Files: `dlp-hook-dll/src/lib.rs`.
- Cause: `GetFinalPathNameByHandleW` and named-pipe classification request per operation.
- Improvement path: Cache handle-to-path mapping; classify only write/delete/move operations by default.

## Fragile Areas

**`dlp-admin-cli` `render.rs`:**
- Files: `dlp-admin-cli/src/screens/render.rs`.
- Why fragile: 8,000+ lines, 10+ functions with `too_many_arguments`, heavy `AppState` coupling.
- Safe modification: Extract widget helpers into smaller modules; add unit tests for pure layout functions.
- Test coverage: Limited pure-function tests; relies on headless TUI e2e.

**`dlp-agent` `service.rs`:**
- Files: `dlp-agent/src/service.rs`.
- Why fragile: Central coordinator for all subsystems; 4 `type_complexity` suppressions.
- Safe modification: Split subsystem initialization into a builder/launcher module.
- Test coverage: Minimal; requires Windows SCM installation.

**Cross-Platform `#[cfg]` Split:**
- Files: All `dlp-agent` and `dlp-hook-dll` source files.
- Why fragile: 245 `#[cfg(windows)]` and 60 `#[cfg(not(windows))]` annotations; non-Windows paths are stubs.
- Safe modification: Add Windows CI runners; avoid adding new `cfg` branches without tests.
- Test coverage: Windows-only paths cannot run on Linux/macOS CI.

## Scaling Limits

**SQLite Single-File Store:**
- Current capacity: Sufficient for 10k+ agents per release notes.
- Limit: Single-writer WAL contention under very high write volume.
- Scaling path: Shard by tenant or migrate to a server-grade database if agent count grows beyond SQLite limits.

**Named Pipe IPC:**
- Current capacity: One pipe server per agent; per-operation classification requests from hook DLL.
- Limit: Pipe throughput and handle limits under heavy I/O.
- Scaling path: Shared-memory classification cache; batch hook requests; reduce hook coverage to high-risk APIs.

## Dependencies at Risk

**`retour` 0.4.0-alpha.4:**
- Risk: Pre-release alpha used for runtime hooking.
- Impact: API instability and potential correctness issues in ntdll patching.
- Migration plan: Pin to a stable release when available; evaluate `detours` or custom trampolines.

**`windows` 0.58 / 0.62 Split:**
- Risk: Two different versions used across workspace crates.
- Impact: Potential ABI/feature mismatches and compile-time bloat.
- Migration plan: Align all crates on a single `windows` crate version.

## Missing Critical Features

**Approval Invalidation Method:**
- Problem: No explicit method to invalidate issued approval tokens.
- Blocks: Cannot revoke access granted by approval workflow without rotating Ed25519 key pair.

**Full Allowlist Edit Form:**
- Problem: Admin CLI lacks complete allowlist editing UI.
- Blocks: Administrators must use raw API calls for some allowlist operations.

## Test Coverage Gaps

**Windows-Only Code Paths:**
- What's not tested: SCM lifecycle, session enumeration, UI spawning, ETW Kernel-File consumer, WFP filter installation, hook DLL injection.
- Files: `dlp-agent/src/service.rs`, `dlp-agent/src/ui_spawner.rs`, `dlp-agent/src/wfp_*.rs`, `dlp-agent/src/etw_kernel_file.rs`, `dlp-agent/src/hook_injector.rs`, `dlp-hook-dll/src/lib.rs`.
- Risk: Core enforcement paths cannot be validated on non-Windows CI.
- Priority: High.

**Hook DLL:**
- What's not tested: Real-process injection and inline behavior under EDR.
- Files: `dlp-hook-dll/src/trampolines.rs`, `dlp-hook-dll/src/ntdll_patcher.rs`.
- Risk: Bypass vulnerabilities or stability issues go undetected.
- Priority: High.

**Unsafe Code:**
- What's not tested: No `miri` or sanitizer runs for `unsafe` blocks.
- Files: `dlp-agent/src/bypass_correlator.rs`, `dlp-hook-dll/src/*.rs`.
- Risk: Undefined behavior and memory safety issues.
- Priority: Medium.

---

*Concerns audit: 2026-07-03*
