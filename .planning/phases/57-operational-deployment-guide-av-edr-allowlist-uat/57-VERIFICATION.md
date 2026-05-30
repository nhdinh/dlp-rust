---
phase: 57-operational-deployment-guide-av-edr-allowlist-uat
plan: verification
status: in-progress
last_updated: 2026-05-30
---

# Phase 57 Verification Report

## Phase Goal Restatement

Phase 57 is the v0.10.0 milestone ship gate. The goal is to ensure an operator can deploy v0.10.0 to a real Windows fleet alongside any of the top 6 EDRs without false-positive quarantine, and the milestone passes a UAT smoke test on a real Windows 11 host with real cloud clients, real printers, and real removable media.

---

## Success Criteria Verification

### OPS-01: Deployment Guide with Vendor Allowlist Procedures

**Status: VERIFIED**

- **Artifact:** `docs/operations/deployment-guide.md`
- **Verification:** Document exists and contains per-vendor AV/EDR allowlist procedures for all 6 required vendors:
  - Microsoft Defender for Endpoint
  - CrowdStrike Falcon
  - SentinelOne
  - Carbon Black
  - Sophos
  - Trend Micro Apex One
- **Evidence:** Each vendor section includes console navigation steps, exclusion types (file, folder, process, certificate), and specific paths to whitelist (`C:\Program Files\DLP\`, `dlp_agent.exe`, `dlp_hook_dll.dll`, `dlp_admin_cli.exe`, `dlp_user_ui.exe`, `dlp_server.exe`).
- **Completed by:** Plan 57-01 (2026-05-30)

### OPS-02: RELEASE_NOTES.md with Hashes and Provenance

**Status: VERIFIED**

- **Artifact:** `RELEASE_NOTES.md` (repo root)
- **Verification:** Document contains:
  - Release Engineer Checklist (8 mandatory items)
  - SHA-256 and SHA-512 hash generation PowerShell script
  - Hash verification PowerShell script
  - Microsoft WDSI submission flow documentation
  - Authenticode verification commands (`signtool verify /pa`)
  - Artifact Provenance table (Build ID, Commit SHA, Pipeline, Built By, Build Date)
  - Signing Certificate table (Thumbprint, Issuer, Subject, Valid From, Valid To)
  - v0.10.0 release section with all 6 binaries listed
- **Note:** Hash values and certificate details are `[TO BE FILLED AT RELEASE]` placeholders per design decision D-18/D-19. The release engineer populates these at ship time.
- **Completed by:** Plan 57-02 (2026-05-30)

### OPS-03: Deployment Reality Documentation

**Status: VERIFIED**

- **Artifact:** `docs/operations/deployment-guide.md` (Secure Boot, PPL, DACL, Privilege, Reboot sections)
- **Verification:** Document explicitly addresses:
  - Secure Boot reality: AppInit_DLLs is inert; `siem.appinit_dlls_disabled` audit event will fire
  - PPL coverage gap: lsass, MsMpEng, EDR self-processes are not injectable; DACL tripwire provides kernel-enforced backstop
  - DACL tripwire backstop: T3/T4 root paths carry explicit Deny ACE that survives hook absence
  - `SeSystemProfilePrivilege` preservation across upgrades
  - Post-install reboot requirement for hook activation
- **Completed by:** Plan 57-04 (2026-05-30)

### OPS-04: UAT Execution on Physical Windows 11 Host

**Status: PENDING**

- **Artifact:** `.planning/milestones/v0.10.0-UAT.md`
- **Verification:** UAT test plan exists with 36 scenarios across 10 categories:
  - A. Cloud Sync Clients (4 scenarios)
  - B. Printer/Print-to-PDF (4 scenarios)
  - C. USB Removable Media (4 scenarios)
  - D. SD Card (3 scenarios)
  - E. Optical Drive (3 scenarios)
  - F. Virtual Drive (3 scenarios)
  - G. Monitor-Only Mode (4 scenarios)
  - H. Active Blocking (4 scenarios)
  - I. Performance / CRIT-04 (3 scenarios)
  - J. Operational Verification (4 scenarios)
- **Pending:** Actual execution on physical Windows 11 hardware
- **Blocker:** Manual execution required; cannot be automated in CI

---

## Test Results Summary

| Category | Scenarios | Status |
|----------|-----------|--------|
| A. Cloud Sync Clients | 4 | NOT EXECUTED |
| B. Printer/Print-to-PDF | 4 | NOT EXECUTED |
| C. USB Removable Media | 4 | NOT EXECUTED |
| D. SD Card | 3 | NOT EXECUTED |
| E. Optical Drive | 3 | NOT EXECUTED |
| F. Virtual Drive | 3 | NOT EXECUTED |
| G. Monitor-Only Mode | 4 | NOT EXECUTED |
| H. Active Blocking | 4 | NOT EXECUTED |
| I. Performance / CRIT-04 | 3 | NOT EXECUTED |
| J. Operational Verification | 4 | NOT EXECUTED |
| **Total** | **36** | **PENDING** |

### CRIT-04 Benchmark Gate

| Metric | Target | Actual | Status |
|--------|--------|--------|--------|
| cargo build overhead | <= 25% | TBD | PENDING |
| Office app launch overhead | <= 25% | TBD | PENDING |
| File copy (1 GB) overhead | <= 25% | TBD | PENDING |

---

## Ship/No-Ship Decision

**Decision: PENDING**

A ship/no-ship decision cannot be made until UAT execution completes. The decision will be based on:

1. **PASS rate:** All 36 scenarios must pass for automatic SHIP
2. **Severity tiers** (per D-26):
   - **Blocking** (prevents ship): CRIT-04 >25% overhead, core blocking broken, hook injection failing, DACL tripwire not applying, monitor mode broken, any Category J operational verification failure
   - **Major** (degraded but workaround exists): Peripheral-specific issues with workaround, performance near threshold, UI cosmetic issues
   - **Minor** (cosmetic/documentation): Typos, screenshot quality, non-essential formatting
3. **Approval authority:** Engineering + QA sign-off required per D-27

### Decision Matrix

| Condition | Decision |
|-----------|----------|
| 0 Blocking failures + Engineering/QA sign-off | SHIP |
| 1+ Blocking failures | NO-SHIP, file issues, plan fix phase |
| 0 Blocking + Major failures only | Engineering discretion |

---

## Approval Authority Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Engineering Lead | [PENDING UAT COMPLETION] | | |
| QA Lead | [PENDING UAT COMPLETION] | | |

---

## Blockers

### Primary Blocker: Manual UAT Execution

- **Description:** UAT requires physical Windows 11 hardware with real peripherals (USB drives, SD cards, optical drives, printers) and real cloud client software (OneDrive, Google Drive, Dropbox, Box).
- **Impact:** OPS-04 cannot be verified without this execution.
- **Resolution:** Operator must execute UAT on physical Windows 11 host and record results in `.planning/milestones/v0.10.0-UAT.md`.
- **ETA:** TBD — dependent on operator availability and hardware access.

---

## Status

**Overall Status: `in-progress`**

- OPS-01: VERIFIED
- OPS-02: VERIFIED
- OPS-03: VERIFIED
- OPS-04: PENDING (blocked on manual UAT execution)
- Ship/No-Ship Decision: PENDING

---

## Next Steps

1. **Execute UAT** on physical Windows 11 host per `.planning/milestones/v0.10.0-UAT.md`
2. **Record results** in UAT document (PASS/FAIL/N/A per scenario)
3. **Run CRIT-04 benchmarks** and record overhead percentages
4. **Analyze results** and categorize failures by severity tier
5. **Make ship/no-ship decision** based on severity tier breakdown
6. **Complete approval sign-off** (engineering + QA)
7. **Update this VERIFICATION.md** with final status

---

*Last updated: 2026-05-30. This document will be updated when UAT execution completes.*
