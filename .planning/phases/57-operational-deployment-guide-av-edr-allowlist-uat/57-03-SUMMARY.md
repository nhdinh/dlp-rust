# Plan 57-03 Summary: Append SentinelOne, Carbon Black, Sophos, and Trend Micro Apex One EDR Allowlist Sections

**Date:** 2026-06-05
**Status:** COMPLETED

## What Was Done

Appended four new vendor-specific EDR allowlist sections to `docs/operations/deployment-guide.md`, replacing the `<!-- INSERT-REMAINING-VENDORS-AFTER-HERE -->` marker. All 6 vendors (Microsoft Defender, CrowdStrike, SentinelOne, Carbon Black, Sophos, Trend Micro) are now fully documented.

## Sections Added

### Vendor: SentinelOne
- Console URL, Required Role, Propagation Time, Supported Methods
- Agent requirement note: SHA-256 requires SentinelOne agent S-25.1.1+
- Method 1: Hash Exclusion (8 steps)
- Method 2: Path Exclusion (`C:\Program Files\DLP\*`)
- Verification: console check + robust registry check (both `HKLM:\SOFTWARE\SentinelLabs\SentinelAgent` and `HKLM:\SOFTWARE\WOW6432Node\SentinelLabs\SentinelAgent`) + `Test-Path`
- Notes: exact-match hash exclusions

### Vendor: Carbon Black (VMware Carbon Black Cloud)
- Console URL (`https://[REGION].conferdeploy.net`), Required Role, Propagation Time
- Method 1: Reputation Approved List (9 steps)
- Method 2: Policy Exclusion (path-based)
- Verification: console check + pilot endpoint flow (4 steps) for "file must be known" requirement
- Notes: reputation is global per tenant

### Vendor: Sophos
- Console URL (`https://central.sophos.com`), Required Role, Propagation Time
- Explicit limitation: "Sophos Central does NOT support hash-based allowlisting"
- Method 1: Path Exclusion (9 steps)
- Method 2: SophosLabs Reclassification (false positive submission)
- Verification: console check + `Test-Path` + log file check

### Vendor: Trend Micro Apex One
- Console URL (tenant-specific), Required Role, Propagation Time
- Method 1: Application Control Hash Allow (14 steps)
- Method 2: Scan Exclusion (path)
- Verification: console check + robust service detection (`Get-Service | Where-Object { $_.Name -like "*Apex*One*" -or $_.DisplayName -like "*Apex*One*" }`) + `Test-Path`
- Notes: Application Control is PE-only (.exe, .dll, .sys); separate licensed feature

## Verification Results

| Check | Expected | Actual |
|-------|----------|--------|
| `grep -c "SentinelOne"` | > 0 | 12 |
| `grep -c "Carbon Black"` | > 0 | 7 |
| `grep -c "WOW6432Node"` | > 0 | 3 |
| `grep -c "Sophos"` | > 0 | 9 |
| `grep -c "Trend Micro"` | > 0 | 3 |
| `grep -c "Get-Service \| Where-Object"` | > 0 | 1 |
| `grep -c "does NOT support hash-based allowlisting"` | > 0 | 1 |
| No emojis | 0 | 0 |
| `INSERT-REMAINING-VENDORS-AFTER-HERE` marker removed | absent | absent |
| `PLACEHOLDER: EDR-VENDORS-END` marker preserved | present | present |

## Files Modified

- `C:\Users\nhdinh\dev\dlp-rust\docs\operations\deployment-guide.md` -- Added SentinelOne, Carbon Black, Sophos, and Trend Micro Apex One sections between the insertion marker and `<!-- PLACEHOLDER: EDR-VENDORS-END -->`.

## Files Created

- `C:\Users\nhdinh\dev\dlp-rust\.planning\phases\57-operational-deployment-guide-av-edr-allowlist-uat\57-03-SUMMARY.md` (this file)
