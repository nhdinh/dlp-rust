# Phase 30: Automated UAT Infrastructure - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-28
**Phase:** 30-automated-uat-infrastructure
**Areas discussed:** Test Harness Architecture, USB Write-Protection, TUI Test Harness, CI Integration, Deferred UAT Items (Phase 4, 6, 24)

---

## Test Harness Architecture

| Option | Description | Selected |
|--------|-------------|----------|
| Rust integration tests | Everything in cargo test | |
| PowerShell scripts | Everything outside cargo test | |
| Mixed — Rust API + PowerShell process | API tests in Rust, process tests in PowerShell | ✓ |

**User's choice:** Mixed — Rust for API tests, PowerShell for process tests
**Notes:** Aligns with existing project patterns. Rust integration tests already exist for dlp-server API. PowerShell scripts already exist for service management.

---

## USB Write-Protection Verification

| Option | Description | Selected |
|--------|-------------|----------|
| Real hardware only | PowerShell script, local only | |
| Virtual disk simulation | VHD in CI + local | |
| Mock IOCTL path | Unit test only | |
| Two-tier — unit + real hardware | Unit tests for logic, script for real hardware | ✓ |

**User's choice:** Two-tier approach

### Follow-up: Script behavior

| Question | Options | Selected |
|----------|---------|----------|
| Device registration | Full stack (admin API) vs direct DB seed | Admin API |
| Trust tiers | Blocked only vs Blocked + ReadOnly | Blocked + ReadOnly |
| Device identification | Auto-detect + interactive pick vs parameter | Auto-detect + pick |
| Cleanup | Full cleanup vs manual | Full cleanup |
| Output format | NUnit XML vs plain text | Plain text color-coded |

### Follow-up: Unit-test tier

| Question | Options | Selected |
|----------|---------|----------|
| Test scope | UsbEnforcer::check() vs mock handle vs both | Both |

**Notes:** Real-hardware script is local-only, not CI. Auto-detects removable drives via WMI. Full cleanup restores device to original state.

---

## TUI Test Harness

| Option | Description | Selected |
|--------|-------------|----------|
| API-layer only | Skip TUI navigation | |
| Headless crossterm event injection | TestBackend + KeyEvent injection | ✓ |
| Terminal emulator scripting | Windows SendKeys / expect | |

**User's choice:** Headless crossterm event injection

### Follow-up: Scope and verification

| Question | Options | Selected |
|----------|---------|----------|
| Screen coverage | Device Registry only vs all three | All three screens |
| Verification level | State only vs render only vs both | Both state + render |
| HTTP dependency | Real mock axum vs mock client | Real mock axum |
| Test location | In-crate vs dedicated dlp-e2e | Dedicated dlp-e2e crate |

**Notes:** All three Phase 28 TUI screens (Device Registry, Managed Origins, App-Identity Conditions Builder). Uses ratatui TestBackend for deterministic rendering assertions.

---

## CI Integration

| Option | Description | Selected |
|--------|-------------|----------|
| Full workspace test in CI | Every PR/push | |
| Non-Windows tests only | Skip Windows-specific | |
| SonarQube only | No cargo test in CI | |
| Full workspace on windows-latest | CI with cargo test | ✓ |

**User's choice:** Yes — full workspace test in CI

### Follow-up: CI details

| Question | Options | Selected |
|----------|---------|----------|
| Target directory | target-test vs default | Default in CI |
| Runner | windows-latest vs ubuntu-latest | windows-latest |

**Notes:** CI job runs on windows-latest with default target dir. target-test workaround is local-dev only.

---

## Phase 6 — Agent TOML Write-Back

| Option | Description | Selected |
|--------|-------------|----------|
| PowerShell script | Full stack | |
| Rust integration test | std::process::Command | ✓ |
| Unit test with mock HTTP | Fast but not full stack | |

**User's choice:** Rust integration test

### Follow-up: Test details

| Question | Options | Selected |
|----------|---------|----------|
| Test environment | Real ProgramData vs temp dir vs both | Both |
| Verification level | Full round-trip vs schema only | Full round-trip exact values |
| DB seeding | Direct SQLite vs admin API with JWT | Admin API with JWT |
| Zero-warning build | Yes vs No | Yes — fail on any warning |
| Timing | Fast-poll vs signal/notify vs wait | Fast-poll mode (1s interval) |

**Notes:** Signal/notify mechanism requested but deferred as new capability. Fast-poll (1s) used instead.

---

## Phase 24 — Release-Mode Build + Smoke

| Option | Description | Selected |
|--------|-------------|----------|
| Binary existence only | Basic sanity | |
| Runtime health check | Start + HTTP ping | |
| Full integration tests | Run all tests against release binary | ✓ |

**User's choice:** Full integration tests against release binary

### Follow-up: CI details

| Question | Options | Selected |
|----------|---------|----------|
| CI frequency | Every PR vs nightly only | Nightly only |
| Target directory | Standard vs separate | Separate target-release |

**Notes:** Release-mode verification is a nightly scheduled job, not on every PR. Uses separate target directory to avoid debug/release conflicts.

---

## Phase 4 — SMTP, Webhook, Hot-Reload

### SMTP Delivery

| Option | Description | Selected |
|--------|-------------|----------|
| Test SMTP server | Local MailHog/smtp4dev | |
| Mock SMTP client | Assert on message content | |
| Skip | Config acceptance sufficient | ✓ |

### Webhook Delivery

| Option | Description | Selected |
|--------|-------------|----------|
| Local HTTP listener | Catch real POSTs | |
| Mock HTTP client | Assert on request | |
| Skip | Config acceptance sufficient | ✓ |

### Hot-Reload

| Option | Description | Selected |
|--------|-------------|----------|
| Rust integration test | Full automation | ✓ |
| PowerShell script | Service lifecycle control | |
| Skip | Covered by other tests | |

**User's choice:** Skip SMTP and webhook (config acceptance sufficient). Automate hot-reload in Rust integration test.

### Follow-up: Hot-reload scope

| Question | Options | Selected |
|----------|---------|----------|
| Config types | Agent only vs SIEM+alerts vs all | All config types |

**Notes:** Hot-reload test covers SIEM, alerts, agent config, and operator config. SMTP and webhook delivery are external dependencies; config acceptance is sufficient.

---

## Claude's Discretion

- Exact structure of `dlp-e2e` crate (workspace member vs standalone)
- tokio::process::Command vs std::process::Command for process spawning
- Exact KeyEvent sequences for each TUI screen
- Single combined hot-reload test vs separate tests per config type
- Nightly CI workflow file format and location

---

## Deferred Ideas

- TCP notification / server-push for immediate agent polling — new capability, deferred to post-Phase 29
- Structured test report format (NUnit/JUnit XML) — deferred, plain text sufficient for now
- VHD/virtual-disk simulation for USB testing in CI — not a Phase 30 priority
- Full release-mode tests on every PR — nightly only for now, can promote later
