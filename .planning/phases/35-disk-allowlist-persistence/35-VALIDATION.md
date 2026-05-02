---
phase: 35
slug: disk-allowlist-persistence
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-05-03
---

# Phase 35 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust built-in `#[test]` + `cargo test` |
| **Config file** | None (built-in test runner) |
| **Quick run command** | `cargo test -p dlp-agent --lib -- detection::disk config 2>&1` |
| **Full suite command** | `cargo test -p dlp-agent --lib 2>&1` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p dlp-agent --lib -- detection::disk config`
- **After every plan wave:** Run `cargo test -p dlp-agent --lib`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** ~30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 35-01-01 | 01 | 0 | DISK-03 | T-35-01 / — | `disk_allowlist` field present with `#[serde(default)]`; TOML roundtrip succeeds | unit | `cargo test -p dlp-agent --lib -- config::tests::test_disk_allowlist` | ❌ W0 | ⬜ pending |
| 35-01-02 | 01 | 0 | DISK-03 | — | Old TOML without `[[disk_allowlist]]` deserializes to empty `Vec` | unit | `cargo test -p dlp-agent --lib -- config::tests::test_disk_allowlist_backwards_compat` | ❌ W0 | ⬜ pending |
| 35-01-03 | 01 | 0 | DISK-03 | — | `drive_letter` char round-trips through TOML backend | unit | `cargo test -p dlp-agent --lib -- config::tests::test_disk_allowlist_drive_letter_toml_roundtrip` | ❌ W0 | ⬜ pending |
| 35-01-04 | 01 | 0 | DISK-03 | — | Existing `AgentConfig` struct literal tests compile with new `disk_allowlist` field | unit | `cargo test -p dlp-agent --lib -- config 2>&1` | ✅ (must update) | ⬜ pending |
| 35-02-01 | 02 | 1 | DISK-03 | — | TOML pre-load populates `instance_id_map` before enumeration | unit | `cargo test -p dlp-agent --lib -- detection::disk::tests::test_pre_load_populates_instance_map` | ❌ W0 | ⬜ pending |
| 35-02-02 | 02 | 1 | DISK-03 | — | `enumeration_complete` not set by TOML pre-load (D-12) | unit | `cargo test -p dlp-agent --lib -- detection::disk::tests::test_enumeration_complete_not_set_on_preload` | ❌ W0 | ⬜ pending |
| 35-02-03 | 02 | 1 | DISK-03 | — | Merge: live disk wins over TOML for same `instance_id` (D-07) | unit | `cargo test -p dlp-agent --lib -- detection::disk::tests::test_merge_live_wins` | ❌ W0 | ⬜ pending |
| 35-02-04 | 02 | 1 | DISK-03 | T-35-02 / — | Merge: disconnected TOML disk retained in merged list (D-06) | unit | `cargo test -p dlp-agent --lib -- detection::disk::tests::test_merge_disconnected_retained` | ❌ W0 | ⬜ pending |
| 35-02-05 | 02 | 1 | DISK-03 | — | TOML write failure is non-fatal; enumeration succeeds despite save error | unit | `cargo test -p dlp-agent --lib -- detection::disk::tests::test_toml_write_failure_non_fatal` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `dlp-agent/src/config.rs` test block — add `test_disk_allowlist_backwards_compat`, `test_disk_allowlist_toml_roundtrip`, `test_disk_allowlist_drive_letter_toml_roundtrip`
- [ ] `dlp-agent/src/detection/disk.rs` test block — add `test_pre_load_populates_instance_map`, `test_merge_live_wins`, `test_merge_disconnected_retained`, `test_enumeration_complete_not_set_on_preload`, `test_toml_write_failure_non_fatal`
- [ ] Update all existing `AgentConfig { ... }` struct literals in `config.rs` tests to add `disk_allowlist: Vec::new()` (or `..Default::default()`)

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| `agent-config.toml` contains `[[disk_allowlist]]` entries after agent restart | DISK-03 | Requires live agent process on Windows hardware | 1. Start agent; 2. Check `C:\ProgramData\DLP\agent-config.toml` for `[[disk_allowlist]]` entries; 3. Restart agent; 4. Verify entries survive restart |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
