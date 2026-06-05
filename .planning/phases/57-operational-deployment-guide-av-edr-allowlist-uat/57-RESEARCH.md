# Phase 57: Operational Deployment Guide + AV/EDR Allowlist + UAT - Research

**Researched:** 2026-06-05
**Domain:** Windows enterprise DLP deployment, AV/EDR coexistence, Authenticode signing, UAT test planning
**Confidence:** HIGH

## Summary

Phase 57 is the v0.10.0 milestone ship gate. An operator must be able to deploy v0.10.0 to a real Windows fleet alongside any of the top 6 EDRs without false-positive quarantine, and the milestone must pass a UAT smoke test on a real Windows 11 host with real cloud clients, real printers, and real removable media.

The deployment guide must document per-vendor AV/EDR allowlist procedures for Microsoft Defender for Endpoint, CrowdStrike Falcon, SentinelOne, Carbon Black, Sophos, and Trend Micro Apex One. It must also cover Secure Boot reality (AppInit_DLLs inert), PPL coverage gaps, DACL-tripwire backstop, SeSystemProfilePrivilege preservation, and post-install reboot requirements. SHA-256/SHA-512 hashes must be published in RELEASE_NOTES.md with reproducible signtool verify commands and Microsoft WDSI file submission flow.

The UAT must exercise every v0.9.0 cloud-sync regression test plus every v0.10.0 active-blocking scenario on real hardware, capturing results in `.planning/milestones/v0.10.0-UAT.md`. The CRIT-04 benchmark gate (<= 25% wall-clock overhead) must hold.

**Primary recommendation:** Write `docs/operations/deployment-guide.md` as a comprehensive operator-facing document with per-vendor console steps (screenshot placeholders + exact navigation paths + PowerShell commands), hash verification procedures, and pre-flight checklists. Create `.planning/milestones/v0.10.0-UAT.md` as a structured test matrix with pass/fail capture. No new code dependencies -- this is a documentation and validation phase.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Deployment guide authoring | CDN / Static (docs) | -- | Pure documentation; no runtime component |
| AV/EDR allowlist procedures | CDN / Static (docs) | -- | Vendor console steps documented for operator reference |
| Hash publishing | CDN / Static (RELEASE_NOTES.md) | -- | Build artifact metadata published at release time |
| Authenticode verification | CDN / Static (docs + CI) | -- | `signtool verify /pa` commands documented; CI runs them |
| WDSI submission | CDN / Static (docs) | -- | Operator follows documented flow; no automation |
| UAT execution | Browser / Client (operator) | -- | Operator runs tests on real Windows 11 hardware |
| UAT results capture | CDN / Static (.planning/milestones/) | -- | Markdown checklist captured during UAT session |

## User Constraints (from CONTEXT.md)

> No CONTEXT.md exists for Phase 57. Decisions are derived from ROADMAP.md success criteria and cross-phase dependencies.

### Locked Decisions (from ROADMAP.md Phase 57)
- OPS-01: Per-vendor AV/EDR allowlist procedures for 6 vendors (Microsoft Defender, CrowdStrike, SentinelOne, Carbon Black, Sophos, Trend Micro)
- OPS-02: SHA-256 + SHA-512 in RELEASE_NOTES.md; WDSI submission flow; signtool verify /pa; reproducible commands
- OPS-03: Secure Boot reality, PPL gap, DACL backstop, SeSystemProfilePrivilege, post-install reboot
- OPS-04: Real Windows 11 UAT with real cloud clients, printers, USB/SD/optical/virtual drives; CRIT-04 benchmark

### Claude's Discretion
- Documentation format: follow existing `docs/operations/dpapi-recovery.md` pattern with PowerShell snippets, checklist tables, and troubleshooting sections.
- UAT format: follow existing `scripts/Uat-ReadMe.md` pattern with numbered steps, expected results, and PASS/FAIL capture.
- Vendor console steps: include both UI navigation and PowerShell/API alternatives where available.

### Deferred Ideas (OUT OF SCOPE)
- Automated EDR allowlist API integration (future: vendor APIs for programmatic exclusions)
- Automated WDSI submission via API (no public API available)
- CI-based UAT on real hardware (requires physical machine or cloud Windows Desktop)
- EV code signing migration (deferred post-v0.10.0 per Phase 48)

## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| OPS-01 | docs/operations/deployment-guide.md with per-vendor AV/EDR allowlist procedures | Verified console steps for all 6 vendors via official docs and web research |
| OPS-02 | SHA-256 + SHA-512 hashes in RELEASE_NOTES.md; WDSI flow; signtool verify; reproducible commands | Verified signtool syntax from Microsoft Learn; WDSI portal confirmed at microsoft.com/wdsi |
| OPS-03 | Secure Boot reality, PPL gap, DACL backstop, SeSystemProfilePrivilege, reboot requirement | Verified from Phase 49/51/52 research; PowerShell commands from Microsoft docs |
| OPS-04 | UAT on real Windows 11 with real hardware; all regression + active-blocking tests; CRIT-04 benchmark | Existing UAT scripts (Uat-UsbBlock.ps1) provide pattern; TESTING.md documents test framework |

## Standard Stack

### Core
| Library/Tool | Version | Purpose | Why Standard |
|--------------|---------|---------|--------------|
| `signtool` | Windows SDK [VERIFIED: Microsoft Learn] | Authenticode signing + timestamp verification | Industry standard; already used in release.yml |
| PowerShell | 5.1+ [VERIFIED: Windows built-in] | Deployment verification, privilege checks, UAT scripts | Standard Windows admin tool |
| WiX v4+ | 4.x [VERIFIED: installer/build.ps1] | MSI packaging | Already in use for DLPAgent.msi |

### Supporting
| Tool | Version | Purpose | When to Use |
|------|---------|---------|-------------|
| `Get-FileHash` | PowerShell built-in | SHA-256/SHA-512 hash generation | Documented in deployment guide for operator verification |
| `whoami /priv` | Windows built-in | Verify SeSystemProfilePrivilege | Documented in deployment guide |
| `Confirm-SecureBootUEFI` | PowerShell built-in | Verify Secure Boot status | Documented in deployment guide |
| `signtool verify /all /pa` | Windows SDK | Verify Authenticode + timestamp type | Documented for operator post-install verification |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Manual WDSI submission | Automated reputation building via EV cert | EV cert deferred post-v0.10.0; WDSI is current standard for non-EV |
| Path-based exclusions | Hash-based exclusions only | Hash-based preferred but not all vendors support it; document both |
| Single hash algorithm | SHA-256 only | SHA-512 provides stronger integrity guarantee; publish both for defense in depth |

## Package Legitimacy Audit

> No new external packages are installed in this phase. All tools are Windows built-in or already in use.

## Architecture Patterns

### System Architecture Diagram

```
Operator Workstation
|
|-- Reads docs/operations/deployment-guide.md
|   |-- Per-vendor EDR allowlist steps
|   |-- Pre-flight PowerShell checks
|   |-- Hash verification commands
|
|-- Downloads v0.10.0 release artifacts
|   |-- DLPAgent.msi
|   |-- RELEASE_NOTES.md (with SHA-256/SHA-512)
|
|-- Runs pre-flight checks on target endpoint
|   |-- Confirm-SecureBootUEFI
|   |-- whoami /priv (SeSystemProfilePrivilege)
|   |-- signtool verify /pa (signature check)
|   |-- Get-FileHash (hash verification)
|
|-- Configures EDR allowlist (per vendor)
|   |-- Microsoft Defender: Indicator > File hash > Allow
|   |-- CrowdStrike: ML Exclusion + Certificate Exclusion
|   |-- SentinelOne: Hash Exclusion
|   |-- Carbon Black: Reputation > Approved List
|   |-- Sophos: Path Exclusion (hash not available)
|   |-- Trend Micro: Application Control > Hash Allow
|
|-- Installs DLPAgent.msi
|   |-- Reboot required for hook activation
|
|-- Runs UAT test matrix
|   |-- v0.9.0 cloud-sync regression
|   |-- v0.10.0 active-blocking scenarios
|   |-- CRIT-04 benchmark (cargo build + Office launch)
|
|-- Captures results in .planning/milestones/v0.10.0-UAT.md
```

### Recommended Project Structure

```
docs/
├── operations/
│   ├── deployment-guide.md      # NEW: per-vendor allowlist + deployment steps
│   └── dpapi-recovery.md        # EXISTING: reference format
├── DEPLOYMENT.md                # EXISTING: high-level deployment overview
├── OPERATIONAL.md               # EXISTING: operational runbook
├── CHANGELOG.md                 # EXISTING: version history
└── RELEASE_NOTES.md             # NEW/UPDATE: hashes + verification commands

scripts/
├── Uat-UsbBlock.ps1             # EXISTING: USB UAT pattern
├── Uat-CloudSync.ps1            # NEW: cloud sync regression UAT
├── Uat-PrintBlock.ps1           # NEW: print enforcement UAT
├── Uat-ActiveBlocking.ps1       # NEW: v0.10.0 active blocking UAT
├── Uat-Benchmark.ps1            # NEW: CRIT-04 benchmark measurement
└── Uat-ReadMe.md                # EXISTING: UAT documentation pattern

.planning/milestones/
└── v0.10.0-UAT.md               # NEW: UAT results capture template
```

### Pattern 1: Per-Vendor EDR Allowlist Documentation
**What:** Standardized documentation format for each EDR vendor with console steps, PowerShell alternatives, and IOC/hash exclusion examples.
**When to use:** Every EDR vendor section in the deployment guide.
**Format:**
```markdown
### Vendor: [Name]

**Console URL:** [direct URL]
**Required Role:** [role name]
**Propagation Time:** [time to effect]

#### Method 1: [Primary Method]
1. Navigate to [path]
2. Click [button]
3. Enter [values]
4. Save

#### Method 2: [PowerShell/API Alternative]
```powershell
# Command
```

#### Verification
```powershell
# Command to verify exclusion is active
```
```

### Pattern 2: Pre-Flight Checklist
**What:** Standardized PowerShell-based pre-flight checks an operator runs before installation.
**When to use:** Before every deployment.
**Example:**
```powershell
# Verify Secure Boot status
$sb = Confirm-SecureBootUEFI
Write-Host "Secure Boot: $sb (expected: True on Windows 11)"

# Verify SeSystemProfilePrivilege
whoami /priv | findstr SeSystemProfilePrivilege

# Verify signature on downloaded MSI
signtool verify /pa DLPAgent.msi

# Verify hash matches RELEASE_NOTES.md
$hash = Get-FileHash DLPAgent.msi -Algorithm SHA256
Write-Host "SHA-256: $($hash.Hash)"
```

### Pattern 3: UAT Results Capture
**What:** Markdown template with test case ID, description, steps, expected result, actual result, and PASS/FAIL checkbox.
**When to use:** During UAT execution on real hardware.
**Example:**
```markdown
| TC-ID | Description | Steps | Expected | Actual | Status |
|-------|-------------|-------|----------|--------|--------|
| UAT-01 | OneDrive upload blocked for T4 file | 1. Create T4 file 2. Copy to OneDrive folder | Upload denied, audit event emitted | | [ ] |
```

### Anti-Patterns to Avoid
- **Vague vendor steps:** "Go to settings and add an exclusion" is insufficient. Document exact navigation paths and field names.
- **Missing verification steps:** Every allowlist procedure must include a verification command to confirm the exclusion is active.
- **Hash-only documentation:** Some vendors (Sophos) do not support hash-based allowlisting. Document path-based fallback explicitly.
- **Ignoring propagation delay:** CrowdStrike exclusions take up to 40 minutes. Document this so operators do not assume immediate effect.
- **Omitting Secure Boot warning:** AppInit_DLLs is inert under Secure Boot. This must be prominently documented, not buried in a footnote.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Custom hash verification tool | PowerShell `Get-FileHash` | Built-in, trusted, reproducible |
| Custom signature verification | `signtool verify /pa` | Windows SDK standard; handles timestamp validation |
| Custom UAT framework | PowerShell scripts + markdown checklists | Existing pattern from Uat-UsbBlock.ps1; no new dependencies |
| Custom EDR API client | Vendor-specific APIs | Document console steps; APIs require separate auth and change frequently |
| Custom benchmark harness | `Measure-Command` + existing cargo build | Simple, reproducible, no new tools |

**Key insight:** This phase is documentation and validation, not code. Every "solution" should be a documented procedure using existing tools, not a new tool.

## Common Pitfalls

### Pitfall 1: EDR Exclusion Propagation Delay
**What goes wrong:** Operator adds exclusion, immediately installs DLPAgent.msi, and the EDR quarantines the hook DLL because the exclusion has not propagated.
**Why it happens:** CrowdStrike takes up to 40 minutes; SentinelOne up to 15 minutes; Defender is typically 15-30 minutes.
**How to avoid:** Document propagation times per vendor. Include a verification step before installation.
**Warning signs:** Hook DLL quarantined within minutes of installation despite exclusion being configured.

### Pitfall 2: Secure Boot + AppInit_DLLs Confusion
**What goes wrong:** Operator expects AppInit_DLLs to provide universal hook coverage on Windows 11, but Secure Boot disables it. Processes started before ETW watcher initializes are uncovered.
**Why it happens:** Windows 11 enforces Secure Boot by default; AppInit_DLLs is inert when Secure Boot is enabled.
**How to avoid:** Document that ETW-driven injection is primary; AppInit is tertiary fallback only. Emphasize the `siem.appinit_dlls_disabled` audit event.
**Warning signs:** Processes started immediately after boot do not show hook DLL loaded.

### Pitfall 3: PPL Process Coverage Gap
**What goes wrong:** Operator believes all processes are covered, but lsass.exe, MsMpEng.exe, and EDR self-processes are PPL-protected and cannot be injected.
**Why it happens:** PPL (Protected Process Light) prevents injection from non-PPL processes. The agent correctly skips these, but the operator may not understand the gap.
**How to avoid:** Document the PPL coverage gap explicitly. Explain that DACL tripwire (Phase 52) provides kernel-enforced backstop for T3/T4 paths even when hooks cannot inject.
**Warning signs:** Audit events show `Skipped(PPL)` for critical processes; operator reports "incomplete coverage."

### Pitfall 4: SeSystemProfilePrivilege Loss on Upgrade
**What goes wrong:** After MSI upgrade, the agent service loses `SeSystemProfilePrivilege`, breaking ETW trace session creation.
**Why it happens:** MSI reinstall may reset service privileges to defaults if not explicitly preserved in the WiX manifest.
**How to avoid:** Document that the MSI must preserve service privileges. Include verification command in post-upgrade checklist.
**Warning signs:** ETW consumer fails to start after upgrade; agent logs show "access denied" on `StartTrace`.

### Pitfall 5: Post-Install Reboot Skipped
**What goes wrong:** Operator installs MSI but does not reboot. Hook DLL is not injected into already-running processes until they restart.
**Why it happens:** The startup `EnumProcesses` sweep injects into running processes, but some system processes (explorer, services) may require a reboot to fully reload.
**How to avoid:** Document reboot as required, not optional. Explain that the startup sweep covers most processes but a reboot ensures complete coverage.
**Warning signs:** Some processes do not show hook DLL loaded after installation without reboot.

### Pitfall 6: WDSI Submission Rejection
**What goes wrong:** Operator submits binaries to WDSI for reputation whitelisting, but submission is rejected due to incomplete information.
**Why it happens:** WDSI requires specific fields (company name, detection name, file hash) and has a 50MB file size limit.
**How to avoid:** Document exact WDSI submission steps, required fields, and file preparation (ZIP with password "infected" for suspected malware).
**Warning signs:** Submission status shows "pending" for 10+ days or returns "insufficient information."

### Pitfall 7: Benchmark Contamination
**What goes wrong:** CRIT-04 benchmark shows >25% overhead because other software (antivirus scan, Windows Update) is running concurrently.
**Why it happens:** Benchmarks on real hardware are sensitive to system load.
**How to avoid:** Document benchmark preconditions: disable Windows Update, pause AV scans, close unnecessary applications, run 3 times and take median.
**Warning signs:** Benchmark results vary significantly between runs.

## Code Examples

### Microsoft Defender for Endpoint: File Hash Indicator
```powershell
# Enable file hash computation (required for hash indicators)
Set-MpPreference -EnableFileHashComputation $true

# Console steps:
# 1. Navigate to: https://security.microsoft.com
# 2. System > Settings > Endpoints > Indicators (under Rules)
# 3. File hashes tab > Add item
# 4. Indicator: enter SHA-256 hash
# 5. Action: Allow
# 6. Scope: select device groups
# 7. Save

# Verification: Check indicator list shows "Allow" action
```
Source: [Microsoft Learn - Create indicators for files](https://learn.microsoft.com/en-us/defender-endpoint/indicator-file)

### CrowdStrike Falcon: ML Exclusion
```powershell
# Console steps:
# 1. Navigate to: https://falcon.crowdstrike.com
# 2. Configuration > Detections Management > Exclusions
# 3. Machine Learning Exclusions tab > CREATE EXCLUSION
# 4. Scope: All hosts or specific Host Groups
# 5. EXCLUDED FROM: Detections and preventions
# 6. Pattern: C:\Program Files\DLP\*
# 7. Pattern Test (optional)
# 8. Comment: "DLP v0.10.0 hook DLL exclusion"
# 9. Create Exclusion > Enable

# Note: Changes take up to 40 minutes to propagate
```
Source: [Red Canary - How to Create Exclusions in CrowdStrike](https://support.redcanary.com/hc/en-us/articles/4413344754071-How-to-Create-Exclusions-in-CrowdStrike)

### SentinelOne: Hash Exclusion
```powershell
# Console steps:
# 1. Navigate to SentinelOne Management Console
# 2. Sentinels > Exclusions (or Policy Settings > Exclusions)
# 3. New Exclusion > Create Exclusion
# 4. Exclusion Type: Hash
# 5. OS Type: Windows
# 6. Hash Value: SHA-256 of dlp_hook_dll.dll
# 7. Description: "DLP v0.10.0 hook DLL"
# 8. Save

# Note: SHA-256 supported from agent S-25.1.1+
```
Source: [Guardz - Creating a Hash Exclusion for SentinelOne](https://support.guardz.com/en/articles/10807260-creating-a-hash-exclusion-for-sentinelone)

### Carbon Black: Reputation Approved List
```powershell
# Console steps:
# 1. Navigate to [REGION].conferdeploy.net
# 2. Enforce > Reputation
# 3. Click Add
# 4. Type: Hash
# 5. List: Approved List
# 6. SHA-256: [hash value]
# 7. Name: "DLP v0.10.0 hook DLL"
# 8. Comments: "Data Loss Prevention agent hook"
# 9. Save

# Note: File must be known to Carbon Black Cloud before adding
```
Source: [Dell - How to Create Exclusions for VMware Carbon Black Cloud](https://www.dell.com/support/kbdoc/en-us/000182859/how-to-create-exclusions-or-inclusions-for-vmware-carbon-black-cloud)

### Sophos: Path Exclusion (Hash Not Available)
```powershell
# Console steps:
# 1. Navigate to Sophos Central Admin
# 2. My Products > Endpoint Protection > Policies
# 3. Click Threat Protection policy
# 4. Settings > Scanning exclusions
# 5. Add Exclusion
# 6. Type: File or folder
# 7. Path: C:\Program Files\DLP\*
# 8. Active for: Real-time, Scheduled, or Both
# 9. Add > Save

# Note: Sophos Central does NOT support hash-based allowlisting.
# Use path-based exclusions. Submit file to SophosLabs for reclassification.
```
Source: [Sophos Central - Global Exclusions](https://docs.sophos.com/central/customer/help/en-us/ManageYourProducts/GlobalSettings/ProtectionRemediation/AllowBlock/GlobalExclusions/)

### Trend Micro Apex One: Application Control Hash Allow
```powershell
# Console steps:
# 1. Navigate to Apex Central (or Apex One console)
# 2. Policies > Policy Resources > Application Control Criteria
# 3. Add Criteria > Allow
# 4. Name: "DLP v0.10.0"
# 5. Match method: Hash values
# 6. Hash type: SHA-256
# 7. Enter hash value(s)
# 8. OK
# 9. Policies > Policy Management
# 10. Select policy > Application Control
# 11. Assign criteria > Deploy

# Note: Application Control supports PE files only (.exe, .dll, .sys, etc.)
```
Source: [Trend Micro - Configuring Scan Exclusion Lists](https://docs.trendmicro.com/en-us/documentation/article/apex-central-widget-and-policy-management-guide-configuring-scan-exc_001)

### signtool Verify with Timestamp
```powershell
# Verify Authenticode signature + RFC-3161 timestamp
signtool verify /pa /v "C:\Program Files\DLP\dlp-agent.exe"

# Verify ALL signatures and identify timestamp types
signtool verify /all /pa "C:\Program Files\DLP\dlp_hook_dll.dll"

# Expected output shows:
# Index  Algorithm  Timestamp
# 0      sha256     RFC3161
```
Source: [Microsoft Learn - SignTool.exe](https://learn.microsoft.com/en-us/dotnet/framework/tools/signtool-exe)

### PowerShell Hash Generation
```powershell
# Generate SHA-256 and SHA-512 for all shipped binaries
$binaries = @(
    "dlp-agent.exe",
    "dlp-user-ui.exe",
    "dlp-admin-cli.exe",
    "dlp-server.exe",
    "dlp_hook_dll.dll",
    "dlp_hook_dll_x86.dll"
)

foreach ($bin in $binaries) {
    $path = "C:\Program Files\DLP\$bin"
    if (Test-Path $path) {
        $sha256 = Get-FileHash $path -Algorithm SHA256
        $sha512 = Get-FileHash $path -Algorithm SHA512
        Write-Host "$bin`:"
        Write-Host "  SHA-256: $($sha256.Hash)"
        Write-Host "  SHA-512: $($sha512.Hash)"
    }
}
```

### Secure Boot Verification
```powershell
# Check Secure Boot status
$sb = Confirm-SecureBootUEFI
if ($sb) {
    Write-Host "Secure Boot: ENABLED (AppInit_DLLs is INERT)"
} else {
    Write-Host "Secure Boot: DISABLED (AppInit_DLLs may function)"
}

# Check for Windows UEFI CA 2023 certificate
$db = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes)
$has2023 = $db -match 'Windows UEFI CA 2023'
Write-Host "UEFI CA 2023: $has2023"
```
Source: [Mike Robbins - Verify Windows UEFI CA 2023 Certificate](https://mikefrobbins.com/2026/02/12/verify-windows-uefi-ca-2023-certificate-with-powershell/)

### PPL Process Detection
```powershell
# List PPL-protected processes
# Requires: https://gist.github.com/jonny-jhnson/6b9e87f5a428f31d41ffc8c1ee05a999
# Or use Process Hacker / System Informer

# Quick check for known PPL processes
@("lsass", "MsMpEng", "services", "csrss") | ForEach-Object {
    $proc = Get-Process $_ -ErrorAction SilentlyContinue
    if ($proc) {
        Write-Host "$($proc.ProcessName) PID=$($proc.Id) -- PPL expected"
    }
}
```
Source: [BorderGate - Protected Process Light](https://www.bordergate.co.uk/process-protection-light/)

### SeSystemProfilePrivilege Verification
```powershell
# Verify current process has SeSystemProfilePrivilege
whoami /priv | findstr SeSystemProfilePrivilege

# Expected output:
# SeSystemProfilePrivilege        Profile system performance     Enabled

# If disabled, enable it (requires admin):
# See Lee Holmes' Set-TokenPrivilege.ps1 script
```
Source: [Lee Holmes - Adjusting Token Privileges in PowerShell](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/)

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Unsigned binaries | Authenticode + RFC-3161 timestamp | Phase 48 | Reduces AV/EDR false positives; enterprise deployment requirement |
| Cloud-sync-only hook | Universal hook DLL + ETW injection | Phases 48-49 | Broader coverage; requires broader EDR allowlist |
| No EDR coexistence documentation | Per-vendor allowlist procedures | Phase 57 (this phase) | Operator can deploy alongside any major EDR |
| Manual USB UAT only | Comprehensive v0.10.0 UAT matrix | Phase 57 (this phase) | Validates all shipped capabilities on real hardware |
| No hash publishing | SHA-256 + SHA-512 in RELEASE_NOTES.md | Phase 57 (this phase) | Supply chain integrity verification |

**Deprecated/outdated:**
- AppInit_DLLs as primary injection mechanism: replaced by ETW-driven injection (Phase 49). AppInit is tertiary fallback only.
- Path-based AV exclusions as primary: hash-based indicators preferred where supported (Defender, SentinelOne, Carbon Black).

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Microsoft Defender for Endpoint supports SHA-256 file hash indicators with Allow action | Vendor Procedures | If policy changes, operator may need to use certificate-based or path-based exclusion instead |
| A2 | CrowdStrike Falcon ML exclusions propagate within 40 minutes | Vendor Procedures | If propagation takes longer, operator must wait longer before installing |
| A3 | SentinelOne supports SHA-256 hash exclusions from agent S-25.1.1+ | Vendor Procedures | Older agents may only support SHA-1; document fallback |
| A4 | Carbon Black Cloud requires file to be "known" before adding to reputation list | Vendor Procedures | Operator may need to wait for initial detection before allowlisting |
| A5 | Sophos Central does NOT support hash-based allowlisting | Vendor Procedures | If Sophos adds hash support, documentation should be updated |
| A6 | Trend Micro Apex One Application Control supports SHA-256 for PE files | Vendor Procedures | Non-PE files (scripts, data) require path-based exclusions |
| A7 | WDSI submission portal at microsoft.com/wdsi/filesubmission is current | WDSI Flow | URL may change; verify at research time |
| A8 | Windows 11 Secure Boot cannot be disabled on most OEM systems | Secure Boot | Some enterprise systems allow Secure Boot disable; document both paths |

## Open Questions

1. **WDSI Enterprise Account Requirement**
   - What we know: WDSI supports enterprise submissions with Azure AD/work account.
   - What's unclear: Whether the DLP project has a Microsoft work account for enterprise submissions.
   - Recommendation: Document both enterprise and individual submission paths.

2. **CRIT-04 Benchmark Baseline**
   - What we know: Benchmark requires <= 25% wall-clock overhead on cargo build + Office app launch.
   - What's unclear: Exact baseline measurement methodology (warm vs cold cache, number of runs, statistical method).
   - Recommendation: Document 3-run median with warm cache, exclude outliers >2 stddev.

3. **Real Printer Requirements**
   - What we know: UAT requires "real printers."
   - What's unclear: Whether network printers, USB printers, or both are required.
   - Recommendation: Document both local USB and network printer tests.

4. **Virtual Drive Scope**
   - What we know: Phase 56 adds SD/optical/virtual drive enumeration.
   - What's unclear: Which virtual drive types (Daemon Tools, VHD, ISO mount) are available for UAT.
   - Recommendation: Document minimum viable virtual drive (Windows Explorer ISO mount).

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Windows 11 host | UAT | Required | 22H2+ | Windows 10 22H2 (partial) |
| Physical USB drive | UAT USB tests | Required | Any | None -- must be physical |
| Physical SD card | UAT SD tests | Required | Any | None -- must be physical |
| Optical drive | UAT optical tests | Optional | Any | Skip if unavailable |
| OneDrive client | UAT cloud sync | Required | Latest | None -- must be real client |
| Google Drive client | UAT cloud sync | Required | Latest | None -- must be real client |
| Dropbox client | UAT cloud sync | Required | Latest | None -- must be real client |
| Box client | UAT cloud sync | Required | Latest | None -- must be real client |
| Physical printer | UAT print tests | Required | Any | None -- must be physical |
| EDR trial/license | Allowlist verification | Required | Any | None -- must be real EDR |
| signtool | Signature verification | Yes | Windows SDK | None |
| PowerShell 5.1+ | All scripts | Yes | Built-in | None |

**Missing dependencies with no fallback:**
- Real Windows 11 hardware with real peripherals -- UAT cannot be fully validated on VMs.
- EDR licenses for all 6 vendors -- operator must have access to at least one EDR console for allowlist verification.

**Missing dependencies with fallback:**
- Optical drive -- UAT can skip optical tests if hardware unavailable; document as optional.
- Box client -- less common than other cloud clients; can be documented as "if available."

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | PowerShell scripts + manual verification |
| Config file | None -- inline parameters |
| Quick run command | `.\scripts\Uat-ActiveBlocking.ps1 -Quick` |
| Full suite command | Follow `.planning/milestones/v0.10.0-UAT.md` checklist |

### Phase Requirements -> Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| OPS-01 | Deployment guide exists with all 6 vendors | doc review | Manual read-through | No -- to be created |
| OPS-02 | RELEASE_NOTES.md has SHA-256/SHA-512 | doc review | `Get-FileHash` verification | No -- to be created |
| OPS-02 | signtool verify /pa passes | manual | `signtool verify /pa` | No -- to be run |
| OPS-03 | Secure Boot documented | doc review | `Confirm-SecureBootUEFI` | No -- to be documented |
| OPS-04 | UAT results captured | manual | `.planning/milestones/v0.10.0-UAT.md` | No -- to be created |
| OPS-04 | CRIT-04 benchmark <= 25% | manual | `Measure-Command` comparison | No -- to be run |

### Sampling Rate
- **Per task commit:** Doc review for completeness
- **Per wave merge:** Full UAT checklist review
- **Phase gate:** All UAT tests PASS on real hardware before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `docs/operations/deployment-guide.md` -- per-vendor allowlist procedures
- [ ] `docs/RELEASE_NOTES.md` -- hash publishing template
- [ ] `.planning/milestones/v0.10.0-UAT.md` -- UAT results capture template
- [ ] `scripts/Uat-CloudSync.ps1` -- cloud sync regression UAT
- [ ] `scripts/Uat-PrintBlock.ps1` -- print enforcement UAT
- [ ] `scripts/Uat-ActiveBlocking.ps1` -- v0.10.0 active blocking UAT
- [ ] `scripts/Uat-Benchmark.ps1` -- CRIT-04 benchmark measurement

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No | Not in scope |
| V3 Session Management | No | Not in scope |
| V4 Access Control | No | Not in scope |
| V5 Input Validation | Yes | UAT scripts validate file paths, hash formats |
| V6 Cryptography | Yes | SHA-256/SHA-512 hash verification; Authenticode timestamp validation |
| V10 Malicious Code | Yes | EDR allowlist prevents false-positive quarantine of legitimate hook DLL |

### Known Threat Patterns for Deployment Stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| EDR quarantine of hook DLL | Denial of Service | Per-vendor allowlist procedures (OPS-01) |
| Tampered MSI download | Tampering | SHA-256/SHA-512 hash verification (OPS-02) |
| Expired Authenticode signature | Denial of Service | RFC-3161 timestamp verification with signtool (OPS-02) |
| Secure Boot bypass expectation | Information Disclosure | Document AppInit_DLLs inert status (OPS-03) |
| PPL process coverage gap | Information Disclosure | Document DACL tripwire backstop (OPS-03) |

## Sources

### Primary (HIGH confidence)
- Microsoft Learn -- `indicator-file.md` (Create indicators for files): https://learn.microsoft.com/en-us/defender-endpoint/indicator-file
- Microsoft Learn -- `signtool-exe.md` (SignTool.exe): https://learn.microsoft.com/en-us/dotnet/framework/tools/signtool-exe
- Microsoft WDSI Portal -- https://www.microsoft.com/en-us/wdsi/filesubmission
- Phase 48 Research -- Authenticode signing pipeline, signtool commands, RFC-3161 timestamp servers
- Phase 49 Research -- AppInit_DLLs Secure Boot behavior, PPL detection, ETW injection
- Phase 51 Research -- EDR coexistence, ntdll patching, EDR detection patterns
- Phase 52 Research -- DACL tripwire, Protected Paths, repair watcher
- Phase 53 Research -- ETW Kernel-File consumer, bypass correlator, hook journal
- Phase 54 Research -- Admin TUI Protected Paths + Bypass Alerts screens
- Phase 55 Research -- Monitor-only / Audit-only enforcement mode
- `docs/operations/dpapi-recovery.md` -- Existing operations doc format reference
- `scripts/Uat-ReadMe.md` -- Existing UAT documentation pattern
- `scripts/Uat-UsbBlock.ps1` -- Existing UAT script pattern
- `.github/workflows/release.yml` -- Existing signing pipeline

### Secondary (MEDIUM confidence)
- Red Canary -- CrowdStrike Exclusions: https://support.redcanary.com/hc/en-us/articles/4413344754071-How-to-Create-Exclusions-in-CrowdStrike
- Guardz -- SentinelOne Hash Exclusion: https://support.guardz.com/en/articles/10807260-creating-a-hash-exclusion-for-sentinelone
- Dell -- Carbon Black Cloud Exclusions: https://www.dell.com/support/kbdoc/en-us/000182859/how-to-create-exclusions-or-inclusions-for-vmware-carbon-black-cloud
- Sophos Central -- Global Exclusions: https://docs.sophos.com/central/customer/help/en-us/ManageYourProducts/GlobalSettings/ProtectionRemediation/AllowBlock/GlobalExclusions/
- Trend Micro -- Scan Exclusion Lists: https://docs.trendmicro.com/en-us/documentation/article/apex-central-widget-and-policy-management-guide-configuring-scan-exc_001
- Mike Robbins -- Secure Boot 2023 CA Verification: https://mikefrobbins.com/2026/02/12/verify-windows-uefi-ca-2023-certificate-with-powershell/
- Lee Holmes -- Token Privileges in PowerShell: https://www.leeholmes.com/adjusting-token-privileges-in-powershell/
- BorderGate -- Protected Process Light: https://www.bordergate.co.uk/process-protection-light/
- Stack Overflow -- AppInit_DLLs Windows 11: https://stackoverflow.com/questions/75678722/appinit-dlls-and-loadappinit-dlls-not-working-on-windows-11-despite-disabling-se

### Tertiary (LOW confidence)
- EDR console UI evolution -- vendor UIs change frequently; exact screenshots may become outdated within 6 months
- WDSI processing time -- Microsoft does not guarantee turnaround time; typical is 24-48 hours but can be longer
- EDR propagation times -- based on community reports; vendor documentation may not specify exact times

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- all tools are Windows built-in or already in use
- Vendor procedures: MEDIUM-HIGH -- based on official docs and community guides; UIs evolve
- UAT planning: HIGH -- follows existing project patterns (Uat-UsbBlock.ps1, TESTING.md)
- Security domain: HIGH -- well-understood threats with documented mitigations

**Research date:** 2026-06-05
**Valid until:** 2026-07-05 (vendor UIs may evolve; verify console steps quarterly)
