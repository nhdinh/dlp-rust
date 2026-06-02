---
phase: 58
slug: differentiators-bundle-override-diagnostic-hash-evidence-sel
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-06-02
---

# Phase 58 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Built-in `#[test]` + `cargo test` |
| **Config file** | None — per-crate test modules |
| **Quick run command** | `cargo test -p dlp-hook-dll` |
| **Full suite command** | `cargo test --workspace` |
| **Estimated runtime** | ~60 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p <affected_crate>`
- **After every plan wave:** Run `cargo test --workspace`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 58-01-01 | 01 | 1 | DIFF-03 | T-58-03 | SHA-256 hash only on DENY, capped at 100MB, offloaded to thread pool | unit | `cargo test -p dlp-hook-dll test_sha256_known_value` | No — W0 | pending |
| 58-01-02 | 01 | 1 | DIFF-03 | T-58-03 | 100MB cap truncates hash correctly, hash_skipped on pool saturation | unit | `cargo test -p dlp-hook-dll test_hash_truncation` | No — W0 | pending |
| 58-02-01 | 02 | 1 | DIFF-02 | T-58-02 | Diagnostic snapshot captures on DENY with correct ABAC context | unit | `cargo test -p dlp-hook-dll test_diagnostic_snapshot` | No — W0 | pending |
| 58-02-02 | 02 | 1 | DIFF-02 | T-58-02 | Ring buffer bounds to 1000 entries and overwrites old | unit | `cargo test -p dlp-hook-dll test_ring_buffer_capacity` | No — W0 | pending |
| 58-03-01 | 03 | 2 | DIFF-02 | T-58-02 | Agent polls and aggregates diagnostic snapshots correctly | unit | `cargo test -p dlp-agent test_diagnostic_poll` | No — W0 | pending |
| 58-03-02 | 03 | 2 | DIFF-04 | T-58-04 | Health counters increment and snapshot emission works | unit | `cargo test -p dlp-hook-dll test_health_counters` | No — W0 | pending |
| 58-04-01 | 04 | 2 | DIFF-04 | T-58-04 | Health snapshot computes cache hit rate and thresholds correctly | unit | `cargo test -p dlp-agent test_hit_rate_computation` | No — W0 | pending |
| 58-04-02 | 04 | 2 | DIFF-04 | T-58-04 | Auto-alert emits on health transition (Degraded, Critical) | integration | `cargo test -p dlp-agent test_health_alert` | No — W0 | pending |
| 58-05-01 | 05 | 3 | DIFF-01 | T-58-01 | Override request flows through pipe to agent to user UI | unit + integration | `cargo test -p dlp-hook-dll test_request_override` | No — W0 | pending |
| 58-05-02 | 05 | 3 | DIFF-01 | T-58-01 | Approval token caching and verification works end-to-end | integration | `cargo test -p dlp-agent test_approval_cache` | Yes | pending |
| 58-06-01 | 06 | 3 | DIFF-02 | T-58-02 | Admin API serves paginated diagnostics with filters | integration | `cargo test -p dlp-server test_diagnostics_api` | No — W0 | pending |
| 58-06-02 | 06 | 3 | DIFF-03 | T-58-03 | Audit event includes content_sha256 on blocked write | integration | `cargo test -p dlp-server test_audit_hash_field` | No — W0 | pending |
| 58-07-01 | 07 | 4 | DIFF-02 | T-58-02 | TUI renders diagnostic list with detail popup | unit | `cargo test -p dlp-admin-cli test_diagnostic_list_render` | No — W0 | pending |
| 58-07-02 | 07 | 4 | DIFF-04 | T-58-04 | TUI renders self-health dashboard with sparkline | unit | `cargo test -p dlp-admin-cli test_sparkline_render` | No — W0 | pending |

*Status: pending / green / red / flaky*

---

## Wave 0 Requirements

- [ ] `dlp-hook-dll/src/diagnostic_ring.rs` — unit tests for push/drain/capacity
- [ ] `dlp-hook-dll/src/hash_compute.rs` — unit tests for known hashes, truncation, null buffer
- [ ] `dlp-hook-dll/src/health_counters.rs` — unit tests for counter increment, snapshot emission
- [ ] `dlp-agent/src/diagnostic_aggregator.rs` — unit tests for poll, aggregate, filter
- [ ] `dlp-agent/src/health_aggregator.rs` — unit tests for threshold computation, alert emission
- [ ] `dlp-server/tests/diagnostics_api_integration.rs` — integration tests for GET /admin/diagnostics
- [ ] `dlp-admin-cli/src/screens/diagnostic_list.rs` — unit tests for dispatch/render
- [ ] `dlp-admin-cli/src/screens/self_health_dashboard.rs` — unit tests for sparkline render

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Override dialog appears on DENY in real Windows process | DIFF-01 | Requires actual Windows UI interaction | 1. Block a WriteFile operation 2. Verify modal dialog appears 3. Enter justification and submit 4. Verify approval request created in DB |
| Self-health dashboard shows live data from injected process | DIFF-04 | Requires actual DLL injection | 1. Inject hook DLL into notepad.exe 2. Verify counters increment 3. Verify dashboard shows green status 4. Simulate degradation and verify alert |

---

## Validation Sign-Off

- [ ] All tasks have automated verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
