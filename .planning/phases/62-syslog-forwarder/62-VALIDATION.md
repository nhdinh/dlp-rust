---
phase: 62
slug: syslog-forwarder
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-05-14
---

# Phase 62 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | cargo test (Rust built-in) |
| **Config file** | none — existing Cargo workspace |
| **Quick run command** | `cargo test --package dlp-server syslog --no-fail-fast` |
| **Full suite command** | `cargo test --all` |
| **Estimated runtime** | ~60 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test --package dlp-server syslog --no-fail-fast`
- **After every plan wave:** Run `cargo test --all`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 60 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 62-01-01 | 01 | 1 | SYSLOG-01 | T-62-01 | TLS connection uses rustls with system CA store | unit | `cargo test --package dlp-server syslog_connector::tests::tls_connect -- --nocapture` | ❌ W0 | pending |
| 62-01-02 | 01 | 1 | SYSLOG-01 | T-62-02 | RFC 5424 message format is spec-compliant | unit | `cargo test --package dlp-server syslog_connector::tests::rfc5424_format -- --nocapture` | ❌ W0 | pending |
| 62-02-01 | 02 | 1 | SYSLOG-02 | — | JSON payload contains all AuditEvent fields | unit | `cargo test --package dlp-common syslog_payload::tests::all_fields_present -- --nocapture` | ❌ W0 | pending |
| 62-03-01 | 03 | 2 | SYSLOG-03 | T-62-03 | Agent queue encrypts with DPAPI; decrypts on drain | unit | `cargo test --package dlp-agent syslog_queue::tests::dpapi_roundtrip -- --nocapture` | ❌ W0 | pending |
| 62-04-01 | 04 | 2 | SYSLOG-04 | — | Admin TUI syslog screen renders config rows | unit | `cargo test --package dlp-admin-cli screens::syslog_config::tests::render_rows -- --nocapture` | ❌ W0 | pending |

*Status: pending · green · red · flaky*

---

## Wave 0 Requirements

- [ ] `dlp-server/src/syslog_connector.rs` — unit tests for RFC 5424 formatting and TLS transport
- [ ] `dlp-server/src/db/repositories/syslog_config.rs` — repository tests for CRUD operations
- [ ] `dlp-server/src/db/repositories/syslog_queue.rs` — queue tests for enqueue/dequeue/retry
- [ ] `dlp-agent/src/syslog_queue.rs` — agent-side queue tests for DPAPI encryption and drain
- [ ] `dlp-admin-cli/src/screens/syslog_config.rs` — TUI screen rendering tests

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| End-to-end syslog delivery to live SIEM collector | SYSLOG-01 | Requires external SIEM endpoint | Configure test syslog server (e.g., `syslog-ng` or `rsyslog` in Docker), verify message receipt and JSON parsing |
| TLS certificate validation against system CA store | SYSLOG-01 | Requires OS-level cert store | Use a certificate from a public CA; verify connection succeeds. Use self-signed cert; verify connection fails with appropriate error. |
| Agent queue drain on network reconnect | SYSLOG-03 | Requires network partition | Block agent-to-server traffic (e.g., Windows Firewall), generate audit events, restore connectivity, verify queued events are forwarded |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 60s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
