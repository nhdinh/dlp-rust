---
phase: 36
slug: disk-enforcement
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-05-04
---

# Phase 36 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | cargo test (Rust built-in) |
| **Config file** | Cargo.toml |
| **Quick run command** | `cargo test -p dlp-agent disk_enforcer` |
| **Full suite command** | `cargo test --all` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p dlp-agent disk_enforcer`
- **After every plan wave:** Run `cargo test --all`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 36-01-01 | 01 | 1 | DISK-04 | — | DiskEnforcer::check() blocks Create/Write/Move on unregistered disks | unit | `cargo test -p dlp-agent disk_enforcer::tests` | ❌ W0 | ⬜ pending |
| 36-01-02 | 01 | 1 | DISK-04 | — | DiskEnforcer::check() allows Read on unregistered disks | unit | `cargo test -p dlp-agent disk_enforcer::tests::test_read_allowed` | ❌ W0 | ⬜ pending |
| 36-01-03 | 01 | 1 | DISK-04 | — | DiskEnforcer::check() returns None for allowed (registered) disk | unit | `cargo test -p dlp-agent disk_enforcer::tests::test_registered_disk_allowed` | ❌ W0 | ⬜ pending |
| 36-01-04 | 01 | 1 | DISK-04 | — | Fail-closed: blocks all writes when enumeration_complete=false | unit | `cargo test -p dlp-agent disk_enforcer::tests::test_fail_closed` | ❌ W0 | ⬜ pending |
| 36-01-05 | 01 | 1 | DISK-05 | — | Serial mismatch (physical-swap) triggers block | unit | `cargo test -p dlp-agent disk_enforcer::tests::test_serial_mismatch_blocked` | ❌ W0 | ⬜ pending |
| 36-02-01 | 02 | 1 | AUDIT-02 | — | AuditEvent::blocked_disk field present and serializes to JSON | unit | `cargo test -p dlp-common audit::tests::test_blocked_disk_serialization` | ❌ W0 | ⬜ pending |
| 36-02-02 | 02 | 1 | AUDIT-02 | — | blocked_disk absent from JSON when None (skip_serializing_if) | unit | `cargo test -p dlp-common audit::tests::test_blocked_disk_omitted` | ❌ W0 | ⬜ pending |
| 36-03-01 | 03 | 2 | DISK-05 | — | device_watcher.rs dispatches DISK arrival to disk::on_disk_arrival | manual | — | — | ⬜ pending |
| 36-03-02 | 03 | 2 | DISK-05 | — | device_watcher.rs dispatches USB arrival to usb::on_usb_device_arrival | manual | — | — | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `dlp-agent/src/disk_enforcer.rs` — unit test module stub with `#[cfg(test)]` for DiskEnforcer
- [ ] `dlp-common/src/audit.rs` — test module for blocked_disk field serialization

*Existing Rust `#[cfg(test)]` modules within each source file; no separate test runner config needed.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| device_watcher.rs dispatches WM_DEVICECHANGE to correct handlers | DISK-05 | Win32 hidden window requires physical/VM hardware event or mock | Inject DBT_DEVICEARRIVAL for GUID_DEVINTERFACE_DISK; verify on_disk_arrival called |
| DiskEnforcer toast cooldown (30s per drive letter) | DISK-04 | Requires real-time 30s wait | Trigger block twice on same drive within 30s; second should not toast |
| run_event_loop wires disk_enforcer after service.rs change | DISK-04 | Integration wiring validated by build + integration test | `cargo build` passes; integration log shows DiskEnforcer constructed |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
