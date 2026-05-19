---
phase: 49
slug: universal-injection-etw-process-watcher-allowlist-appinit-fa
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-05-19
---

# Phase 49 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Built-in `#[test]` + `cargo test` (Rust standard) |
| **Config file** | None — inline `#[cfg(test)]` modules |
| **Quick run command** | `cargo test -p dlp-agent` |
| **Full suite command** | `cargo test --workspace` |
| **Estimated runtime** | ~45 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p dlp-agent`
- **After every plan wave:** Run `cargo test --workspace`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 60 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 49-01-01 | 01 | 1 | BLOCK-05 | T-49-01 | ETW `KernelTrace` with `PROCESS_PROVIDER` starts without error | unit | `cargo test -p dlp-agent etw_trace_start` | No — Wave 0 | pending |
| 49-01-02 | 01 | 1 | BLOCK-05 | T-49-02 | ETW callback parses Event ID 1 correctly | integration | `cargo test -p dlp-agent etw_event_parse --features integration-tests` | No — Wave 0 | pending |
| 49-02-01 | 02 | 1 | BLOCK-06 | T-49-03 | Allowlist path prefix matching works | unit | `cargo test -p dlp-agent allowlist_path_match` | No — Wave 0 | pending |
| 49-02-02 | 02 | 1 | BLOCK-06 | T-49-04 | Allowlist cert subject matching works | unit | `cargo test -p dlp-agent allowlist_cert_match` | No — Wave 0 | pending |
| 49-02-03 | 02 | 1 | BLOCK-06 | T-49-05 | PPL detection returns true for known PPL process | integration | `cargo test -p dlp-agent ppl_detect --features integration-tests` | No — Wave 0 | pending |
| 49-02-04 | 02 | 1 | BLOCK-06 | T-49-06 | System-critical PID exclusion (PID 4) works | unit | `cargo test -p dlp-agent allowlist_system_critical` | No — Wave 0 | pending |
| 49-03-01 | 03 | 2 | BLOCK-05 | T-49-07 | `EnumProcesses` sweep completes within 5s | integration | Manual — spawn 100+ processes, measure | No — Wave 0 | pending |
| 49-03-02 | 03 | 2 | BLOCK-05 | T-49-08 | Duplicate injection guard prevents double-inject | unit | `cargo test -p dlp-agent duplicate_guard` | No — Wave 0 | pending |
| 49-03-03 | 03 | 2 | BLOCK-05 | T-49-09 | Process state transitions (Discovered->Injected->Exited) | unit | `cargo test -p dlp-agent process_state_machine` | No — Wave 0 | pending |
| 49-04-01 | 04 | 2 | BLOCK-07 | T-49-10 | Secure Boot detection returns correct value | integration | `cargo test -p dlp-agent secure_boot --features integration-tests` | No — Wave 0 | pending |
| 49-04-02 | 04 | 2 | BLOCK-07 | T-49-11 | AppInit registry read at boot works | unit | `cargo test -p dlp-agent appinit_registry_read` | No — Wave 0 | pending |
| 49-05-01 | 05 | 3 | BLOCK-05 | T-49-12 | WMI `Win32_ProcessStartTrace` subscription works | integration | `cargo test -p dlp-agent wmi_backstop --features integration-tests` | No — Wave 0 | pending |
| 49-05-02 | 05 | 3 | BLOCK-06 | T-49-13 | WoW64 dispatch routes to x86 DLL | unit | `cargo test -p dlp-agent wow64_dispatch` | Yes (existing) | pending |

*Status: pending · green · red · flaky*

---

## Wave 0 Requirements

- [ ] `dlp-agent/src/process_watcher.rs` — test stubs for ETW process creation
- [ ] `dlp-agent/src/universal_injector.rs` — test stubs for injection orchestration
- [ ] `dlp-agent/src/process_registry.rs` — test stubs for lifecycle tracking
- [ ] `dlp-agent/src/allowlist.rs` — test stubs for allowlist matching
- [ ] `dlp-agent/src/appinit.rs` — test stubs for AppInit registry reading

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| ETW 500ms latency from ProcessStart to injection | BLOCK-05 | Requires real Windows process spawning with QPC timing | Spawn notepad.exe, verify hook DLL module appears within 500ms via Process Hacker |
| Coverage telemetry >= 99% | BLOCK-05 | Requires real process fleet over time | Run for 10 min with normal workload, check `siem.injection_telemetry` events |
| AV/EDR signer-cert matching against real vendors | BLOCK-06 | Requires installed AV/EDR products | Install CrowdStrike/SentinelOne/Defender, verify processes are skipped in log |
| Secure Boot detection on real UEFI system | BLOCK-07 | Requires UEFI firmware variable access | Run on Secure Boot enabled endpoint, verify `siem.appinit_dlls_disabled` fires once |
| Startup sweep under 5s with 100+ processes | BLOCK-05 | Requires real process load | Start agent with 100+ user processes running, measure sweep completion time |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 60s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
