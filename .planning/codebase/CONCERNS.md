# Concerns, Risks, and Technical Debt

> Last updated: 2026-06-05

## Summary

| Category | Count | Severity |
|----------|-------|----------|
| `.unwrap()` calls | ~958 | Medium |
| `unsafe` blocks | ~847 | High |
| `panic!` calls | ~117 | Medium |
| `#[allow(dead_code)]` | ~50+ | Low |
| Clippy suppressions | ~20 | Medium |
| `println!` in library code | ~15 | Low |

---

## 1. Error Handling Proliferation

### 1.1 Widespread `.unwrap()` Usage

The codebase contains approximately **958 `.unwrap()` calls** across all Rust source files. While many are in test code, a significant number exist in production paths:

- **dlp-admin-cli tests**: Heavy use of `.unwrap()` in terminal/backend test setup (`render.rs`, `dispatch.rs`)
- **dlp-admin-cli `dispatch.rs`**: Runtime `tokio::runtime::Runtime::new().unwrap()` in test-adjacent code
- **Non-test production code**: ~3850 combined `.unwrap()` and `.expect()` calls outside `#[cfg(test)]` modules

**Risk**: Unhandled panics in production can crash the agent service or admin CLI, causing denial of service on protected endpoints.

**Remediation**: Audit non-test unwraps and convert to `Result<T, E>` propagation. Prioritize `dlp-agent` and `dlp-server` crates.

---

## 2. Unsafe Code Surface

### 2.1 Extensive `unsafe` Usage (~847 blocks)

Unsafe code is heavily concentrated in Windows-specific modules:

| File | Unsafe Count | Purpose |
|------|-------------|---------|
| `dlp-agent/src/allowlist.rs` | ~20 | Certificate parsing, Win32 CryptoAPI |
| `dlp-agent/src/appinit.rs` | ~6 | Registry manipulation, AppInit_DLLs |
| `dlp-agent/src/audit_emitter.rs` | ~2 | Win32 event log writing |
| `dlp-agent/src/bypass_correlator.rs` | ~15 | Shared memory, memory-mapped files, volatile reads |
| `dlp-hook-dll/src/trampolines.rs` | ~30+ | Ntdll syscall trampolines, inline assembly |
| `dlp-hook-dll/src/ntdll_patcher.rs` | ~10 | Runtime code patching |
| `dlp-admin-cli/src/registry.rs` | ~1 | Win32 registry access |

**Risk**: Memory safety violations in `unsafe` blocks can lead to crashes, data corruption, or security vulnerabilities. The hook DLL (`dlp-hook-dll`) runs inside every protected process; a bug here compromises the entire endpoint.

**Remediation**:
- Audit all `unsafe` blocks for missing safety documentation
- Add `#[deny(clippy::missing_safety_doc)]` and fix existing violations
- Consider fuzzing the bypass correlator shared-memory protocol
- Review hook DLL with external security auditor

### 2.2 Manual `Send`/`Sync` Impls

`dlp-agent/src/bypass_correlator.rs:204-205`:

```rust
unsafe impl Send for JournalReader {}
unsafe impl Sync for JournalReader {}
```

**Risk**: If `JournalReader` contains non-thread-safe raw pointers, this creates a data race.

**Remediation**: Verify the invariant holds and document why these impls are safe.

---

## 3. Clippy Suppressions (Design Smells)

Multiple `#[allow(...)]` attributes suppress legitimate lint warnings:

| Lint | Count | Locations | Indicates |
|------|-------|-----------|-----------|
| `clippy::too_many_arguments` | 12+ | `render.rs` (10), `interception/mod.rs`, `service.rs`, `audit.rs`, `agent_config.rs`, `approvals.rs` | Functions are doing too much; violation of single-responsibility principle |
| `clippy::type_complexity` | 4 | `dlp-agent/src/service.rs` | Complex nested generic types; refactor into named types |
| `clippy::too_many_lines` | 1 | `dlp-agent/src/etw_kernel_file.rs:216` | Function exceeds recommended length; needs decomposition |
| `clippy::large_enum_variant` | 2 | `dlp-agent/src/ipc/messages.rs`, `dlp-user-ui/src/ipc/messages.rs` | Enum variants have vastly different sizes; consider `Box<T>` for large variants |
| `clippy::missing_safety_doc` | 1 | `dlp-hook-dll/src/trampolines.rs` | `unsafe` functions lack safety documentation |
| `clippy::enum_variant_names` | 2 | `dlp-admin-cli/src/app.rs`, `dlp-hook-dll/src/ntdll_patcher.rs` | Enum variants share prefixes; rename for clarity |

**Risk**: Suppressing lints masks structural problems that increase maintenance burden and bug surface.

**Remediation**: Treat each suppression as a refactoring ticket. The `too_many_arguments` suppressions in `render.rs` are particularly concerning (10 functions).

---

## 4. Dead Code

Approximately **50+ `#[allow(dead_code)]`** attributes, heavily concentrated in:

- `dlp-admin-cli/src/app.rs` (~25)
- `dlp-admin-cli/src/client.rs` (~10)

**Risk**: Dead code increases binary size, compilation time, and cognitive load. Some items may indicate incomplete features.

**Remediation**: Remove genuinely dead code. If code is reserved for future use, document with `#[expect(dead_code)]` and a linked issue.

---

## 5. Debug Output in Library Code

`println!` and `eprintln!` statements exist outside CLI entry points:

- `dlp-agent/src/dacl_repair_watcher.rs:1233` — `println!("check_acl_mismatch error (acceptable): {}", e)`
- `dlp-agent/src/dacl_tripwire.rs` (10+ lines) — `println!("Win32 error (acceptable in CI): {}", e)`

**Risk**: Unstructured console output interferes with log aggregation and SIEM pipelines. The "acceptable in CI" comments suggest these are test-only but remain in production builds.

**Remediation**: Replace all library `println!` with `tracing::warn!` or `tracing::error!`.

---

## 6. Security Concerns

### 6.1 SIEM Credential Exposure (Phase 26 Finding)

`dlp-server/src/handlers/admin.rs` — `get_siem_config_handler` returns `splunk_token` and `elk_api_key` in plaintext. The mask-on-GET pattern applied to `smtp_password` and `webhook_secret` is **not** applied here.

**Risk**: Any caller with a valid admin JWT can retrieve raw HEC tokens and API keys.

**Status**: A `TODO(followup)` comment exists but the gap remains open.

**Remediation**: Apply the same read-then-substitute pattern. Create a tracked issue and remove the TODO.

### 6.2 Silent Log Discarding (Resolved but Documented)

`tracing_appender::non_blocking` silently discards all IO errors via `Err(_) => {}` in the background writer thread. This caused zero-byte log files for both `dlp-agent` (Session 0, LocalSystem) and `dlp-user-ui` (Session 1, interactive user).

**Status**: Mitigated by replacing `non_blocking` with synchronous `RollingFileAppender`.

**Risk**: If the mitigation is reverted or `tracing_appender` is upgraded without review, the issue recurs.

---

## 7. Platform Fragility

### 7.1 Heavy `#[cfg(windows)]` / `#[cfg(not(windows))]` Split

Approximately **245 `#[cfg(windows)]`** and **60 `#[cfg(not(windows))]`** annotations.

**Risk**: Cross-platform compilation is fragile. The non-Windows paths are largely stubs or `compile_error!` macros. CI may not exercise Windows-only code paths.

**Remediation**: Add Windows-specific CI runners. Document which crates require Windows and why.

---

## 8. Incomplete / Deferred Features

### 8.1 Phase-Deferred TODOs

Multiple plan files contain deferred implementation items:

- Phase 49 (universal injection): TODOs for ETW trace error handling, SIEM emission, full allowlist edit form
- Phase 51 (ntdll trampolines): `TODO(Phase 53): Read from actual shared memory segment`
- Phase 56 (SD/optical drive): `TODO: Implement pipe round-trip or shared-memory lookup`
- Phase 59 (label service): BUG in exact-match tier comparison, cache type-loss
- Phase 61 (approval workflow): TODO for approval invalidation method

**Risk**: Deferred features accumulate without tracking. Some TODOs are in committed source code, violating coding standard `9.14`.

**Remediation**: Convert all source-code TODOs to tracked beads issues. Run `bd lint` to find violations.

---

## 9. Complexity Hotspots

### 9.1 dlp-admin-cli render.rs

- 10+ functions with `#[allow(clippy::too_many_arguments)]`
- ~8,000+ lines of terminal rendering logic
- Heavy state management in `AppState` with many `#[allow(dead_code)]` fields

### 9.2 dlp-agent service.rs

- 4 `#[allow(clippy::type_complexity)]` suppressions
- Central coordinator for all agent subsystems
- High coupling between IPC, enforcement, audit, and policy modules

### 9.3 dlp-server handlers

- Admin handler file exceeds recommended length
- Multiple responsibility areas (auth, policies, audits, config, secrets, SIEM) in one module

---

## 10. Testing Gaps

- **Windows-only code paths**: Many `#[cfg(windows)]` branches have no non-Windows test equivalents
- **Hook DLL**: `dlp-hook-dll` has minimal test coverage; requires integration tests in a real Windows environment
- **Unsafe code**: No dedicated `miri` or sanitizer runs for `unsafe` blocks

---

## Recommended Priority Order

| Priority | Item | Effort |
|----------|------|--------|
| P0 | Fix SIEM credential exposure (plaintext tokens) | Low |
| P0 | Audit `dlp-hook-dll` unsafe blocks for safety docs | Medium |
| P1 | Reduce unwrap() in production paths | Medium |
| P1 | Replace library `println!` with `tracing` | Low |
| P1 | Convert source-code TODOs to tracked issues | Low |
| P2 | Refactor `render.rs` too-many-arguments functions | High |
| P2 | Remove dead code from `app.rs` and `client.rs` | Low |
| P2 | Add Windows CI for `#[cfg(windows)]` paths | Medium |
| P3 | Run `miri` on `bypass_correlator` unsafe code | Medium |
| P3 | Reduce `type_complexity` in `service.rs` | Medium |
