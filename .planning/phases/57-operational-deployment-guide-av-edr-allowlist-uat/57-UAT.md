---
status: complete
phase: 57-operational-deployment-guide-av-edr-allowlist-uat
source:
  - 57-01-SUMMARY.md
  - 57-02-SUMMARY.md
  - 57-03-SUMMARY.md
  - 57-04-SUMMARY.md
  - 57-05-SUMMARY.md
  - 57-06-SUMMARY.md
started: 2026-06-05T00:00:00Z
updated: 2026-06-05T00:15:00Z
---

## Current Test

[testing complete]

## Tests

### 1. Deployment Guide Structure and Cross-References
expected: Title "# Deployment Guide -- DLP v0.10.0", Overview cross-references DEPLOYMENT.md and OPERATIONAL.md, 9 top-level ## sections, no emojis
result: pass

### 2. Pre-Flight Checks Section
expected: Four subsections -- Secure Boot Status (with Confirm-SecureBootUEFI and AppInit_DLLs note), SeSystemProfilePrivilege (whoami /priv), Authenticode Signature Verification (signtool verify /pa /v and /all /pa, RFC-3161 timestamp), Hash Verification (Get-FileHash SHA-256 and SHA-512 for 6 binaries)
result: pass

### 3. Architecture Reality Check Section
expected: Five subsections -- Secure Boot and AppInit_DLLs (ETW primary, AppInit tertiary fallback), PPL Coverage Gap (lsass.exe, MsMpEng.exe, EDR self-processes), DACL Tripwire Backstop (NTFS Deny ACE persists when hook unloaded), SeSystemProfilePrivilege Preservation (MSI must preserve across upgrades), Post-Install Reboot Requirement (required, not optional)
result: pass

### 4. EDR Allowlist: Microsoft Defender Section
expected: Console URL, required roles, propagation time 15-30 min, Defender SKU detection via Get-MpComputerStatus, Method 1 File Hash Indicator (9 steps with Set-MpPreference -EnableFileHashComputation), Method 2 Certificate Indicator, Method 3 New-MpThreatIntelIndicator PowerShell, ASR Rules coexistence section with exclusion path C:\Program Files\DLP\*
result: pass

### 5. EDR Allowlist: CrowdStrike Section
expected: Console URL, required roles, propagation time up to 40 min, Method 1 ML Exclusion (10 steps), Method 2 Certificate Exclusion, Method 3 FalconPy API with ml_exclusions:write scope, PowerShell Invoke-RestMethod alternative with region-specific endpoints (US-1, US-2, EU-1, US-GOV-1), Quarantine recovery note
result: pass

### 6. EDR Allowlist: SentinelOne Section
expected: Console URL, required role, propagation time, Method 1 Hash Exclusion (8 steps), Method 2 Path Exclusion (C:\Program Files\DLP\*), Verification with console check + registry check (HKLM:\SOFTWARE\SentinelLabs\SentinelAgent and WOW6432Node), Agent requirement note for SHA-256 (S-25.1.1+)
result: pass

### 7. EDR Allowlist: Carbon Black Section
expected: Console URL (https://[REGION].conferdeploy.net), required role, propagation time, Method 1 Reputation Approved List (9 steps), Method 2 Policy Exclusion (path-based), Verification with console check + pilot endpoint flow for "file must be known" requirement, Note that reputation is global per tenant
result: pass

### 8. EDR Allowlist: Sophos Section
expected: Console URL (https://central.sophos.com), required role, propagation time, Explicit note "Sophos Central does NOT support hash-based allowlisting", Method 1 Path Exclusion (9 steps), Method 2 SophosLabs Reclassification (false positive submission), Verification with console check + Test-Path + log file check
result: pass

### 9. EDR Allowlist: Trend Micro Section
expected: Console URL (tenant-specific), required role, propagation time, Method 1 Application Control Hash Allow (14 steps), Method 2 Scan Exclusion (path), Verification with console check + service detection (Get-Service matching *Apex*One*) + Test-Path, Note that Application Control is PE-only (.exe, .dll, .sys) and a separately licensed feature
result: pass

### 10. Hash Publishing and Verification Section
expected: Hash Verification Steps (4-step Get-FileHash procedure with SHA-256 and SHA-512, mismatch handling), Authenticode Signature Verification (signtool verify /pa /v and /all /pa, expected output, certutil for root CA, dual-signed DLLs note), Microsoft WDSI Submission (portal URL, ZIP with password "infected", 50MB limit, 8 steps, 24-48h turnaround, troubleshooting)
result: pass

### 11. RELEASE_NOTES.md Structure
expected: Open docs/RELEASE_NOTES.md. Title "# Release Notes -- DLP v0.10.0" or similar. Sections: Release Date [YYYY-MM-DD] placeholder, Binaries table (6 binaries, architectures, paths), SHA-256 Hashes (Get-FileHash command + placeholder table), SHA-512 Hashes (Get-FileHash command + placeholder table), Authenticode Verification (signtool commands with expected RFC-3161 output), WDSI Submission (8-step flow), Known Issues placeholder, Upgrade Notes (SeSystemProfilePrivilege, reboot, EDR allowlist re-verification). No emojis.
result: pass

### 12. UAT PowerShell Scripts
expected: Six scripts exist in scripts/: Uat-CloudSync.ps1, Uat-PrintBlock.ps1, Uat-HookDll.ps1, Uat-DaclTripwire.ps1, Uat-EtwNtdll.ps1, Uat-Benchmark.ps1. Each script has #Requires -RunAsAdministrator, [CmdletBinding()], $ErrorActionPreference = 'Stop', Set-StrictMode -Version Latest, Write-Result helper with PASS/FAIL/INFO/WARN colour-coded output, helper functions with .SYNOPSIS/.DESCRIPTION, main orchestration in try/finally with cleanup, exit 0 on pass / exit 1 on fail. No emojis.
result: pass

### 13. UAT Results Template
expected: File .planning/milestones/v0.10.0-UAT.md exists. Contains: Test Environment table (Host OS, Hardware, CPU, RAM, EDR, DLP Version, Test Date, Tester), Prerequisites Checklist (8 required + 4 optional checkboxes), Test Matrix with 8 groups (v0.9.0 Cloud Sync, v0.9.0 Print, v0.10.0 Hook DLL, v0.10.0 DACL Tripwire, v0.10.0 ETW+ntdll+Monitor, v0.10.0 Volume Class OPTIONAL, USB Enforcement, CRIT-04 Benchmark), Execution Instructions (11 numbered steps), Actual Column Format Guide, UAT Pass Criteria (6 criteria), Sign-Off table (Tester, QA Lead, Release Manager). No emojis.
result: pass

### 14. UAT Test Matrix in Deployment Guide
expected: In docs/operations/deployment-guide.md, between PLACEHOLDER markers replaced with UAT Scope table (8 feature areas with scripts and hardware required), Execution Order (8 numbered steps with PowerShell commands), Manual volume class tests (conditional on hardware), USB Enforcement subsection cross-referencing scripts/Uat-ReadMe.md, CRIT-04 Benchmark Gate table with 25% threshold, UAT Pass Criteria (6 criteria), Failure escalation procedure (4 steps), Cross-reference to .planning/milestones/v0.10.0-UAT.md
result: pass

### 15. Troubleshooting Section
expected: In docs/operations/deployment-guide.md, Troubleshooting section contains at least 6 common issues with resolution steps. Each issue has a clear symptom description and step-by-step resolution. No emojis.
result: pass

## Summary

total: 15
passed: 15
issues: 0
pending: 0
skipped: 0
blocked: 0

## Gaps

[none yet]
