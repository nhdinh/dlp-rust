---
phase: 34
slug: bitlocker-verification
status: draft
nyquist_compliant: false
wave_0_complete: false
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
| _populated by planner — see RESEARCH.md §Validation Architecture for the 17-row CRYPT-01/CRYPT-02 → test map that seeds this table_ | | | | | | | | | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `dlp-common/src/disk.rs` — `EncryptionStatus` and `EncryptionMethod` enums + tests for `serde_json` round-trip and `snake_case` rendering
- [ ] `dlp-agent/src/detection/encryption.rs` — module skeleton, `EncryptionChecker` struct, `OnceLock<Arc<EncryptionChecker>>` singleton accessors
- [ ] `dlp-agent/Cargo.toml` — `wmi = "0.14"` (with `chrono` feature) and `windows = "0.62"` bumped from 0.58, with feature flags re-verified
- [ ] `dlp-common/Cargo.toml` — `windows = "0.62"` bumped from 0.61 to align with workspace per D-22
- [ ] `dlp-agent/src/config.rs` — `EncryptionConfig { recheck_interval_secs: Option<u64> }` with `[300, 86400]` clamp
- [ ] `dlp-agent/tests/encryption_integration.rs` — placeholder for integration tests (real-Windows-only, gated `#[cfg(all(windows, feature = "integration-tests"))]`)

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| `Encrypted` reading on a real BitLocker-protected boot volume | CRYPT-01 | Requires a Windows host with BitLocker enabled — cannot run in CI | On a BitLocker-enabled machine, run the agent and verify the audit event for the boot disk shows `encryption_status: "encrypted"` and a non-null `encryption_method` |
| `Suspended` reading after `manage-bde -protectors -disable C:` | CRYPT-01 | Requires admin BitLocker manipulation on real Windows | Suspend boot volume protectors, restart agent, verify `encryption_status: "suspended"` |
| `Unencrypted` reading on a non-protected data drive | CRYPT-01 | Requires a real attached drive that is not BitLocker-provisioned | Attach a non-encrypted drive, run the agent, verify `encryption_status: "unencrypted"` |
| `Unknown` reading when WMI namespace is unavailable | CRYPT-01 | Requires an SKU/edition without `MicrosoftVolumeEncryption` namespace (e.g., Windows Home) or a manually disabled service | On a Windows Home box (no BitLocker namespace), run the agent and verify Registry fallback fires once per phase, then per-volume yields `Unknown` |
| Status-changed event on drift | CRYPT-02 | Requires waiting for or triggering a real status change | After the agent starts, run `manage-bde -protectors -disable C:`, wait for the next periodic poll (or shorten the interval to 60s for the test), verify a fresh `DiskDiscovery` event fires with `justification: "encryption status changed: ..."` |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 60s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
