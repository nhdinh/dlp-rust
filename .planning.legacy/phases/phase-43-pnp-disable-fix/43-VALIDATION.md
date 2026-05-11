---
phase: 43
slug: pnp-disable-fix
status: draft
nyquist_compliant: true
wave_0_complete: true
created: 2026-05-07
---

# Phase 43 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Built-in `#[test]` + `cargo test` |
| **Config file** | none — Wave 0 installs |
| **Quick run command** | `cargo test -p dlp-common usb` + `cargo test -p dlp-agent` |
| **Full suite command** | `cargo test --all` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p dlp-common usb` + `cargo test -p dlp-agent`
- **After every plan wave:** Run `cargo test --all`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 43-01-01 | 01 | 1 | USB-07 | T-43-01 | CM instance ID resolved from dbcc_name via CM_Get_Device_Interface_PropertyW | unit (Windows-only) | `cargo test -p dlp-common test_resolve_instance_id` | ✅ existing | ⬜ pending |
| 43-01-02 | 01 | 1 | USB-07 | T-43-01 | disable_usb_device calls CM_Disable_DevNode with resolved instance ID | integration (compile-time) | `cargo test -p dlp-agent test_disable_usb_device_signature` | ✅ existing | ⬜ pending |
| 43-02-01 | 02 | 1 | USB-08 | T-43-02 | setupdi_description_for_device matches exact path, not reshaped ID | unit (Windows-only) | `cargo test -p dlp-common test_setupdi_exact_path_match` | ❌ W0 | ⬜ pending |
| 43-03-01 | 03 | 2 | USB-09 | T-43-03 | apply_blocked_enforcement returns Err when both PnP and DACL fail in "Hard error" mode | unit | `cargo test -p dlp-agent test_blocked_hard_failure` | ❌ W0 | ⬜ pending |
| 43-03-02 | 03 | 2 | USB-09 | T-43-03 | Config enum serde round-trips correctly | unit | `cargo test -p dlp-agent test_usb_config_serde` | ❌ W0 | ⬜ pending |
| 43-04-01 | 04 | 2 | USB-09 | T-43-04 | Admin API GET/POST returns correct usb_* config values | unit | `cargo test -p dlp-server test_agent_config_usb_fields` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `dlp-common/src/usb.rs` — test for exact-path `setupdi_description_for_device` matching
- [ ] `dlp-agent/src/detection/usb.rs` — test for `apply_blocked_enforcement` failure mode semantics
- [ ] `dlp-agent/src/config.rs` — test for USB config field defaults and serde
- [ ] `dlp-server/src/admin_api.rs` — test for extended `AgentConfigPayload` serde with new fields

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| PnP disable actually prevents writes to a blocked USB device | USB-07 | Requires physical USB device and Windows host | 1. Register a USB device as Blocked tier. 2. Insert device. 3. Verify Explorer shows "Device is disabled" and writes fail. 4. Check audit log shows BLOCK event with PnP result. |
| "Retry then error" mode retries 3 times before hard failure | USB-09 | Requires simulated CM_Disable_DevNode failure | 1. Set failure mode to "Retry then error". 2. Temporarily block CM API (mock). 3. Insert blocked device. 4. Verify 3 retry attempts in logs, then hard error. |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
