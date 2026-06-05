# Plan 57-02 Summary: Microsoft Defender + CrowdStrike EDR Sections

**Date:** 2026-06-05
**Plan:** 57-02
**Phase:** 57 -- Operational Deployment Guide + AV/EDR Allowlist + UAT

## What Was Done

Replaced the placeholder content between `<!-- PLACEHOLDER: EDR-VENDORS-START -->` and `<!-- PLACEHOLDER: EDR-VENDORS-END -->` in `docs/operations/deployment-guide.md` with two comprehensive vendor sections.

## Microsoft Defender for Endpoint Section

- Console URL, required roles, propagation time (15-30 min), supported methods
- Defender SKU detection via `Get-MpComputerStatus` and MDE onboarding registry check
- Method 1: File Hash Indicator (Preferred) -- 9 steps with `Set-MpPreference -EnableFileHashComputation $true`
- Method 2: Certificate Indicator
- Method 3: PowerShell `New-MpThreatIntelIndicator` with Windows Server module prerequisite note
- Verification command: `Get-MpThreatIntelIndicator`
- ASR Rules coexistence section with two known interfering rules, exclusion path `C:\Program Files\DLP\*`, and Group Policy alternative
- IOC Exclusion Example from Incidents/Alerts console flow

## CrowdStrike Falcon Section

- Console URL, required roles, propagation time (up to 40 min), supported methods
- Prominent 40-minute propagation warning
- Method 1: ML Exclusion -- 10 steps via Configuration > Detections Management > Exclusions
- Method 2: Certificate Exclusion
- Method 3: FalconPy API (Python) with `ml_exclusions:write` and `ml_exclusions:read` scope requirements
- PowerShell Alternative: `Invoke-RestMethod` with region-specific endpoints (US-1, US-2, EU-1, US-GOV-1)
- Verification: console check + `Get-ChildItem` endpoint check
- Quarantine recovery note

## Insert Marker for Plan 57-03

Added `<!-- INSERT-REMAINING-VENDORS-AFTER-HERE -->` before the closing `<!-- PLACEHOLDER: EDR-VENDORS-END -->` marker to enable deterministic appending of the remaining 4 vendor sections (SentinelOne, Carbon Black, Sophos, Trend Micro).

## Verification Results

| Check | Pattern | Count | Status |
|-------|---------|-------|--------|
| Microsoft Defender for Endpoint | grep | 2 | PASS |
| New-MpThreatIntelIndicator | grep | 2 | PASS |
| ASR | grep | 5 | PASS |
| CrowdStrike Falcon | grep | 3 | PASS |
| Invoke-RestMethod | grep | 3 | PASS |
| INSERT-REMAINING-VENDORS-AFTER-HERE | grep | 1 | PASS |
| ml_exclusions:write | grep | 1 | PASS |
| api.us-2.crowdstrike.com | grep | 1 | PASS |
| No emojis | grep unicode ranges | 0 | PASS |

## Files Modified

- `docs/operations/deployment-guide.md` -- Added Microsoft Defender for Endpoint and CrowdStrike Falcon EDR allowlist sections

## Files Created

- `.planning/phases/57-operational-deployment-guide-av-edr-allowlist-uat/57-02-SUMMARY.md` -- This file
