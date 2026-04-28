---
phase: 29
slug: chrome-enterprise-connector
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-04-29
---

# Phase 29 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Built-in `#[test]` + `cargo test` |
| **Config file** | None (built-in tests) |
| **Quick run command** | `cargo test -p dlp-agent chrome` |
| **Full suite command** | `cargo test --workspace` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p dlp-agent chrome`
- **After every plan wave:** Run `cargo test --workspace`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 29-01-01 | 01 | 1 | BRW-01 | T-29-01 | Protobuf frame parsing with 4MiB cap | unit | `cargo test -p dlp-agent chrome::frame` | No W0 | pending |
| 29-01-02 | 01 | 1 | BRW-01 | T-29-02 | `prost` decode/encode round-trip | unit | `cargo test -p dlp-agent chrome::proto` | No W0 | pending |
| 29-02-01 | 02 | 1 | BRW-03 | T-29-03 | Managed origin blocks paste from managed source | unit | `cargo test -p dlp-agent chrome::handler` | No W0 | pending |
| 29-02-02 | 02 | 1 | BRW-03 | T-29-04 | Unmanaged origin allows paste | unit | `cargo test -p dlp-agent chrome::handler` | No W0 | pending |
| 29-02-03 | 02 | 1 | BRW-03 | T-29-05 | Audit event carries source_origin/destination_origin | unit | `cargo test -p dlp-common test_audit_origin_fields` | No W0 | pending |
| 29-03-01 | 03 | 2 | BRW-01 | T-29-06 | HKLM registration writes correct key | unit | `cargo test -p dlp-agent chrome::registry` | No W0 | pending |
| 29-03-02 | 03 | 2 | BRW-01 | T-29-07 | Pipe server accepts connections | integration | `cargo test -p dlp-agent test_chrome_pipe_accept` | No W0 | pending |
| 29-04-01 | 04 | 2 | BRW-03 | T-29-08 | ManagedOriginsCache refresh from server | unit | `cargo test -p dlp-agent chrome::cache` | No W0 | pending |

*Status: pending / green / red / flaky*

---

## Wave 0 Requirements

- [ ] `dlp-agent/src/chrome/mod.rs` — module scaffolding
- [ ] `dlp-agent/src/chrome/proto.rs` — prost include
- [ ] `dlp-agent/src/chrome/frame.rs` — protobuf frame read/write
- [ ] `dlp-agent/src/chrome/handler.rs` — request dispatch + decision
- [ ] `dlp-agent/src/chrome/cache.rs` — ManagedOriginsCache
- [ ] `dlp-agent/src/chrome/registry.rs` — HKLM self-registration
- [ ] `dlp-agent/proto/content_analysis.proto` — vendored proto
- [ ] `dlp-agent/build.rs` — prost-build integration
- [ ] `dlp-agent/tests/chrome_pipe.rs` — pipe server integration test
- [ ] `dlp-common/src/audit.rs` — source_origin + destination_origin fields
- [ ] `dlp-agent/src/server_client.rs` — `fetch_managed_origins()` method

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Chrome Enterprise browser connects to pipe and sends real scan requests | BRW-01 | Requires managed Chrome Enterprise browser with Content Analysis policy enabled | 1. Enable Chrome Enterprise Content Analysis policy pointing to `brcm_chrm_cas`. 2. Copy text from managed origin. 3. Paste into unmanaged origin. 4. Verify paste is blocked and toast/audit event fires. |

---

## Validation Sign-Off

- [ ] All tasks have automated verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
