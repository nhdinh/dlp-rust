---
phase: 22
slug: dlp-common-foundation
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-04-22
---

# Phase 22 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust built-in (`#[test]`, `cargo test`) |
| **Config file** | `Cargo.toml` (workspace) |
| **Quick run command** | `cargo test -p dlp-common` |
| **Full suite command** | `cargo test --workspace && cargo build --workspace` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p dlp-common`
- **After every plan wave:** Run `cargo test --workspace && cargo build --workspace`
- **Before `/gsd-verify-work`:** Full suite must be green with zero warnings
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 22-T1 | 01 | 1 | SC-1 (AppIdentity) | — | Unknown trust = AppTrustTier::Unknown; no panics | unit | `cargo test -p dlp-common test_app_identity` | ❌ W0 | ⬜ pending |
| 22-T2 | 01 | 1 | SC-2 (DeviceIdentity/UsbTrustTier) | — | Default UsbTrustTier = Blocked (default deny) | unit | `cargo test -p dlp-common test_usb_trust_tier` | ❌ W0 | ⬜ pending |
| 22-T3 | 01 | 1 | SC-3 (AbacContext) | — | AbacContext compiles with optional app fields | unit | `cargo test -p dlp-common test_abac_context` | ❌ W0 | ⬜ pending |
| 22-T4 | 01 | 1 | SC-4 (AuditEvent) | — | Old AuditEvent JSON deserializes without error | unit | `cargo test -p dlp-common test_audit_event_backward_compat` | ❌ W0 | ⬜ pending |
| 22-T5 | 01 | 1 | SC-5 (IPC + compile) | — | ClipboardAlert with no app fields still deserializes | unit | `cargo build --workspace 2>&1 \| grep -c warning` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `dlp-common/src/endpoint.rs` — new module stub with `AppIdentity`, `DeviceIdentity`, `UsbTrustTier`, `AppTrustTier`, `SignatureState`
- [ ] `dlp-common/src/lib.rs` — `pub mod endpoint;` + named re-exports added
- [ ] Unit test stubs for all five success criteria in `dlp-common/src/endpoint.rs` `#[cfg(test)]` block

*Wave 0 creates the test stubs so every subsequent task has automated feedback within 30 seconds.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Zero compiler warnings across all 5 crates | SC-5 | Requires human inspection of `cargo build --workspace` output | Run `cargo build --workspace 2>&1 \| grep warning` — must return empty |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
