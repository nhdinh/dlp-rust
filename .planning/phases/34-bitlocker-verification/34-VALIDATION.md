---
phase: 34
slug: bitlocker-verification
status: ratified
nyquist_compliant: true
wave_0_complete: true
created: 2026-05-02
---

# Phase 34 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `cargo test` (Rust built-in) |
| **Config file** | `Cargo.toml` (workspace) |
| **Quick run command** | `cargo test -p dlp-agent --lib detection::encryption -- --nocapture` |
| **Full suite command** | `cargo test --workspace --all-features` |
| **Estimated runtime** | ~60 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p dlp-agent --lib detection::encryption`
- **After every plan wave:** Run `cargo test --workspace`
- **Before `/gsd-verify-work`:** Full suite must be green; `cargo clippy --workspace -- -D warnings` clean
- **Max feedback latency:** 30 seconds for unit, 60 seconds for full

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 34-01-T1 | 34-01 | 1 | CRYPT-01 | T-34-22 (windows-crate alignment) | Workspace builds clean post-bump | unit | `cargo build --workspace` | dlp-common/Cargo.toml, dlp-agent/Cargo.toml | pending |
| 34-01-T2 | 34-01 | 1 | CRYPT-01 | T-34-01 (wire-format integrity) | Two enums + 3 fields serde-roundtrip; backward compat | unit (TDD) | `cargo test -p dlp-common --lib disk::tests` | dlp-common/src/disk.rs, dlp-common/src/lib.rs | pending |
| 34-02-T1 | 34-02 | 1 | CRYPT-02 | T-34-05 (TOML clamp) | Clamp [300, 86400], default 21600, warn! on out-of-range | unit (TDD) | `cargo test -p dlp-agent --lib config::tests` | dlp-agent/src/config.rs | pending |
| 34-03-T1 | 34-03 | 2 | CRYPT-01 | T-34-01 (no false-Encrypted) | Pure-logic: parse_drive_letter, derive_encryption_status truth table, transitions, justifications, singleton | unit (TDD) | `cargo test -p dlp-agent --lib detection::encryption::tests` | dlp-agent/src/detection/encryption.rs | pending |
| 34-03-T2 | 34-03 | 2 | CRYPT-01, CRYPT-02 | T-34-02, T-34-03, T-34-04 | WMI + Registry RAII + spawn_blocking + 5s timeout + JoinSet fan-out + D-20 in-place mutation | build/clippy + unit re-run | `cargo check --workspace && cargo test -p dlp-agent --lib detection::encryption` | dlp-agent/src/detection/encryption.rs | pending |
| 34-04-T1 | 34-04 | 3 | CRYPT-01, CRYPT-02 | T-34-06, T-34-08 | Singleton registered before spawn; cadence sourced exclusively from config | build/clippy + smoke | `cargo build -p dlp-agent && cargo clippy -p dlp-agent -- -D warnings` | dlp-agent/src/service.rs | pending |
| 34-05-T1 | 34-05 | 3 | CRYPT-01 | T-34-22 | `integration-tests` feature flag exists; `serial_test` dev-dep present | metadata grep | `cargo metadata --manifest-path dlp-agent/Cargo.toml --no-deps \| grep integration-tests` | dlp-agent/Cargo.toml | pending |
| 34-05-T2 | 34-05 | 3 | CRYPT-01, CRYPT-02 | T-34-01, T-34-02, T-34-04, Pitfall E, Pitfall D | Cross-platform end-to-end orchestration, 8 tests covering all D-XX behaviors | integration | `cargo test -p dlp-agent --test encryption_integration` | dlp-agent/tests/encryption_integration.rs | pending |
| 34-05-T3 | 34-05 | 3 | (doc) | n/a | Validation matrix + nyquist sign-off | doc | manual review | .planning/phases/34-bitlocker-verification/34-VALIDATION.md | pending |

*Status: pending · green · red · flaky*

---

## Wave 0 Requirements

- [x] `dlp-common/src/disk.rs` — `EncryptionStatus` and `EncryptionMethod` enums + tests for `serde_json` round-trip and `snake_case` rendering
- [x] `dlp-agent/src/detection/encryption.rs` — module skeleton, `EncryptionChecker` struct, `OnceLock<Arc<EncryptionChecker>>` singleton accessors
- [x] `dlp-agent/Cargo.toml` — `wmi = "0.14"` (with `chrono` feature) and `windows = "0.62"` bumped from 0.58, with feature flags re-verified
- [x] `dlp-common/Cargo.toml` — `windows = "0.62"` bumped from 0.61 to align with workspace per D-22
- [x] `dlp-agent/src/config.rs` — `EncryptionConfig { recheck_interval_secs: Option<u64> }` with `[300, 86400]` clamp
- [x] `dlp-agent/tests/encryption_integration.rs` — placeholder for integration tests (real-Windows-only, gated `#[cfg(all(windows, feature = "integration-tests"))]`)

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| `Encrypted` reading on a real BitLocker-protected boot volume | CRYPT-01 | Requires a Windows host with BitLocker enabled -- cannot run in CI | On a BitLocker-enabled machine, run the agent and verify the audit event for the boot disk shows `encryption_status: "encrypted"` and a non-null `encryption_method` |
| `Suspended` reading after `manage-bde -protectors -disable C:` | CRYPT-01 | Requires admin BitLocker manipulation on real Windows | Suspend boot volume protectors, restart agent, verify `encryption_status: "suspended"` |
| `Unencrypted` reading on a non-protected data drive | CRYPT-01 | Requires a real attached drive that is not BitLocker-provisioned | Attach a non-encrypted drive, run the agent, verify `encryption_status: "unencrypted"` |
| `Unknown` reading when WMI namespace is unavailable | CRYPT-01 | Requires an SKU/edition without `MicrosoftVolumeEncryption` namespace (e.g., Windows Home) or a manually disabled service | On a Windows Home box (no BitLocker namespace), run the agent and verify Registry fallback fires once per phase, then per-volume yields `Unknown` |
| Status-changed event on drift | CRYPT-02 | Requires waiting for or triggering a real status change | After the agent starts, run `manage-bde -protectors -disable C:`, wait for the next periodic poll (or shorten the interval to 60s for the test), verify a fresh `DiskDiscovery` event fires with `justification: "encryption status changed: ..."` |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 60s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** ratified -- wave 0 complete; ready for /gsd-execute-phase
