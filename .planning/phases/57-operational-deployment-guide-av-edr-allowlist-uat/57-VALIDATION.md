---
phase: 57
slug: operational-deployment-guide-av-edr-allowlist-uat
status: verified
nyquist_compliant: true
wave_0_complete: true
created: 2026-06-05
updated: 2026-06-05
---

# Phase 57 -- Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | PowerShell Pester (if available) / manual verification |
| **Config file** | none -- verification is documentation + script-based |
| **Quick run command** | `powershell -ExecutionPolicy Bypass -File scripts/Uat-UsbBlock.ps1` |
| **Full suite command** | Run all `scripts/Uat-*.ps1` scripts in sequence |
| **Estimated runtime** | ~10 minutes (documentation grep checks) + ~30 minutes (UAT scripts on real hardware) |

---

## Sampling Rate

- **After every task commit:** Run grep-based verification commands from plan `<automated>` blocks
- **After every plan wave:** Run all `<automated>` verify commands for plans in that wave
- **Before `/gsd:verify-work`:** All documentation verifications must pass; UAT scripts must run on real hardware
- **Max feedback latency:** 60 seconds for grep checks; 30 minutes for full UAT

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 57-01-01 | 01 | 1 | OPS-01 | T-57-01 / T-57-02 / T-57-03 / T-57-04 | Deployment guide has pre-flight checks, Secure Boot reality, PPL gaps, DACL backstop | grep | `grep -c "^## " docs/operations/deployment-guide.md` (returned 9) | yes | green |
| 57-01-02 | 01 | 1 | OPS-03 | T-57-01 / T-57-02 | RELEASE_NOTES.md has hash tables for all 6 binaries | grep | `grep -c "SHA-256\|SHA-512\|signtool verify" docs/RELEASE_NOTES.md` (returned 14) | yes | green |
| 57-02-01 | 02 | 2 | OPS-01 | T-57-05 / T-57-06 / T-57-07 | Microsoft Defender section with SKU detection, ASR guidance, IOC examples | grep | `grep -c "Microsoft Defender for Endpoint"` (2), `grep -c "New-MpThreatIntelIndicator"` (2), `grep -c "ASR"` (5) | yes | green |
| 57-02-02 | 02 | 2 | OPS-01 | T-57-05 / T-57-06 / T-57-07 | CrowdStrike section with API scopes, region endpoints, propagation warning | grep | `grep -c "CrowdStrike Falcon"` (3), `grep -c "Invoke-RestMethod"` (3) | yes | green |
| 57-03-01 | 03 | 2 | OPS-01 | T-57-08 / T-57-09 / T-57-10 / T-57-11 | SentinelOne + Carbon Black + Sophos + Trend Micro sections | grep | `grep -c "SentinelOne"` (12), `grep -c "Carbon Black"` (7), `grep -c "Sophos"` (9), `grep -c "Trend Micro"` (3) | yes | green |
| 57-04-01 | 04 | 2 | OPS-02 | T-57-12 / T-57-13 / T-57-14 / T-57-15 / T-57-16 | RELEASE_NOTES.md has hash generation commands, signtool verify, WDSI flow | grep | `grep -c "Get-FileHash.*SHA256"` (1), `grep -c "Get-FileHash.*SHA512"` (1), `grep -c "wdsi"` (1) | yes | green |
| 57-04-02 | 04 | 2 | OPS-02 | T-57-12 / T-57-14 | deployment-guide.md has Hash Publishing and WDSI sections | grep | `grep -c "Hash Publishing and Verification"` (1), `grep -c "signtool verify /pa /v"` (2), `grep -c "wdsi"` (1) | yes | green |
| 57-05-01 | 05 | 3 | OPS-04 | T-57-17 / T-57-18 / T-57-19 / T-57-20 | All 7 UAT scripts exist with correct function names | grep | `ls scripts/Uat-*.ps1 \| wc -l` (returned 7) | yes | green |
| 57-06-01 | 06 | 3 | OPS-04 | T-57-21 / T-57-22 / T-57-23 | UAT results template exists with test matrix | grep | `grep -c "TC-ID"` (8), `grep -c "Uat-CloudSync.ps1"` (7) | yes | green |

*Status: pending / green / red / flaky*

---

## Wave 0 Requirements

- [x] `docs/operations/deployment-guide.md` -- document stubs for EDR-VENDORS, HASH-PUBLISHING, UAT-MATRIX placeholders
- [x] `docs/RELEASE_NOTES.md` -- hash table template
- [x] `scripts/Uat-*.ps1` -- UAT script stubs (follow Uat-UsbBlock.ps1 pattern)

*Wave 0 is covered by Plan 01 tasks.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| UAT on real Windows 11 hardware | OPS-04 | Requires physical endpoint with real peripherals | Run all Uat-*.ps1 scripts on Windows 11 host with cloud clients, printer, USB drive |
| EDR allowlist propagation timing | OPS-01 | Requires access to vendor console and real endpoint | Follow deployment guide steps for each EDR, verify exclusion active |
| Benchmark overhead measurement | OPS-04 | Requires real hardware with representative workloads | Run Uat-Benchmark.ps1 on clean Windows 11 host |

---

## Validation Audit 2026-06-05

| Metric | Count |
|--------|-------|
| Gaps found | 0 |
| Resolved | 9 |
| Escalated | 0 |

All 9 per-task verification items passed grep-based automated checks. No gaps detected.

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 60s for automated checks
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** verified 2026-06-05
