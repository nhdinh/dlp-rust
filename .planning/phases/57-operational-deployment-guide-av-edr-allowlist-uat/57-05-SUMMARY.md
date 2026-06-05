# Plan 57-05 Summary: UAT PowerShell Scripts

**Date:** 2026-06-05
**Phase:** 57 — Operational Deployment Guide + AV/EDR Allowlist + UAT
**Plan:** 57-05 — Create six UAT PowerShell scripts following the exact pattern from `scripts/Uat-UsbBlock.ps1`

---

## Deliverables

Six UAT PowerShell scripts created in `scripts/`:

| # | Script | Synopsis | Key Tests |
|---|--------|----------|-----------|
| 1 | `Uat-CloudSync.ps1` | Cloud sync client regression UAT for DLP v0.10.0 | OneDrive, Google Drive, Dropbox, Box upload blocking for T3/T4; share-link clipboard clearing |
| 2 | `Uat-PrintBlock.ps1` | Print enforcement UAT for DLP v0.10.0 | T3/T4 print blocking via spooler; print audit event verification |
| 3 | `Uat-HookDll.ps1` | Hook DLL injection UAT for DLP v0.10.0 | New process injection (500ms), x86/WoW64, AV/EDR skip, PPL skip, startup sweep |
| 4 | `Uat-DaclTripwire.ps1` | DACL tripwire UAT for DLP v0.10.0 | T4/T3 write deny (agent stopped), SYSTEM allow, icacls tamper alert (60s), staged removal safety |
| 5 | `Uat-EtwNtdll.ps1` | ETW bypass detection, ntdll patching, and monitor mode UAT | ETW NoHookJournal alert (5s), direct-syscall block (if enabled), monitor mode (Audit + would_have_denied) |
| 6 | `Uat-Benchmark.ps1` | CRIT-04 benchmark measurement for DLP v0.10.0 | cargo build and Office launch overhead; gate <= 25% |

---

## Pattern Compliance

All six scripts follow the exact pattern established by `scripts/Uat-UsbBlock.ps1`:

- `#Requires -RunAsAdministrator`
- `[CmdletBinding()]` with typed parameters and sensible defaults
- `$ErrorActionPreference = 'Stop'` and `Set-StrictMode -Version Latest`
- `Write-Result` helper with `PASS`/`FAIL`/`INFO`/`WARN` colour-coded output
- Helper functions with `.SYNOPSIS` and `.DESCRIPTION` doc comments
- Main orchestration wrapped in `try`/`finally` for guaranteed cleanup
- `finally` blocks perform mandatory restoration:
  - `Uat-DaclTripwire.ps1`: restarts `dlp-agent` if stopped
  - `Uat-EtwNtdll.ps1`: restores original policy enforcement mode
- Exit `0` on all pass, exit `1` on any fail
- No emojis

---

## Verification Results

All grep checks passed (count > 0 for each required symbol):

```
Uat-CloudSync.ps1:   Test-CloudUploadBlocked=3, Test-ShareLinkBlocked=2, Test-CloudClientInstalled=2
Uat-PrintBlock.ps1:  Test-PrintBlocked=2, Test-PrintAuditEvent=2, Get-InstalledPrinters=3
Uat-HookDll.ps1:     Test-HookDllInjectedNewProcess=2, Test-HookDllInjectedX86=2,
                     Test-AvEdrProcessesSkipped=2, Test-PplProcessesSkipped=2, Test-StartupSweepCoverage=2
Uat-DaclTripwire.ps1: Test-T4WriteDeniedAgentStopped=2, Test-T3WriteDeniedAgentStopped=2,
                      Test-SystemWriteAllowed=2, Test-IcaclsResetTriggersAlert=2, Test-StagedRemovalSafe=2
Uat-EtwNtdll.ps1:    Test-EtwBypassDetection=2, Test-NtdllPatching=2, Test-MonitorMode=3, Restore-PolicyMode=3
Uat-Benchmark.ps1:   Measure-CargoBuild=3, Measure-OfficeLaunch=3, ThresholdPercent=5, Calculate-Overhead=2
```

---

## Script Architecture Summary

```
scripts/
|-- Uat-CloudSync.ps1
|   |-- Test-CloudClientInstalled()     Detect cloud clients and sync paths
|   |-- Test-CloudUploadBlocked()       Write T3/T4 file, verify blocked
|   |-- Test-ShareLinkBlocked()         Clipboard share-link clearing
|   |-- Get-AuditEvents()               Query admin API for audit events
|
|-- Uat-PrintBlock.ps1
|   |-- Get-InstalledPrinters()         WMI query for printers
|   |-- Show-PrinterMenu()              Interactive selection
|   |-- Test-PrintBlocked()             Send T4 file to printer, verify blocked
|   |-- Test-PrintAuditEvent()          Query PRINT audit events
|   |-- Get-PrintJobStatus()            Spooler job query
|
|-- Uat-HookDll.ps1
|   |-- Test-HookDllInjectedNewProcess()  notepad.exe + 500ms module check
|   |-- Test-HookDllInjectedX86()         SysWOW64 notepad + x86 DLL check
|   |-- Test-AvEdrProcessesSkipped()      MsMpEng, csagent, SentinelAgent
|   |-- Test-PplProcessesSkipped()        lsass, services, csrss
|   |-- Test-StartupSweepCoverage()       explorer/cmd/powershell sample
|   |-- Get-ProcessModules()              Module enumeration helper
|
|-- Uat-DaclTripwire.ps1
|   |-- Test-T4WriteDeniedAgentStopped()  Write under protected path
|   |-- Test-T3WriteDeniedAgentStopped()  Write under T3 subfolder
|   |-- Test-SystemWriteAllowed()         PsExec or scheduled task as SYSTEM
|   |-- Test-IcaclsResetTriggersAlert()   icacls /reset + 60s poll
|   |-- Test-StagedRemovalSafe()          Verify no spurious tamper alert
|   |-- Stop-DlpAgentService()            Service control
|   |-- Start-DlpAgentService()           Service control (cleanup)
|
|-- Uat-EtwNtdll.ps1
|   |-- Test-EtwBypassDetection()         Suspend/resume + NoHookJournal poll
|   |-- Test-NtdllPatching()              Config check + direct syscall test
|   |-- Test-MonitorMode()                Audit policy + would_have_denied
|   |-- Restore-PolicyMode()              Policy restoration (cleanup)
|   |-- Get-AgentConfig()                 Admin API config fetch
|   |-- Get-BypassAlerts()                Admin API bypass alert fetch
|
|-- Uat-Benchmark.ps1
|   |-- Test-Preconditions()              Windows Update, AV, memory, agent
|   |-- Test-RustAvailable()              cargo in PATH check
|   |-- Measure-CargoBuild()              cargo clean + cargo build timing
|   |-- Measure-OfficeLaunch()            winword/excel to visible window
|   |-- Calculate-Overhead()              Percentage computation
|   |-- Get-Median()                      Statistical median
|   |-- Format-Results()                  Console table output
|   |-- Stop-DlpAgentService()            Baseline phase
|   |-- Start-DlpAgentService()           Hooked phase
```

---

## Integration with Phase 57

These scripts are the executable UAT suite referenced by ROADMAP.md Phase 57
Success Criterion #4:

> "UAT executes on a real Windows 11 host with real OneDrive/Google Drive/Dropbox/Box
> clients, real printers, and real USB/SD/optical/virtual drives; every v0.9.0
> cloud-sync regression test plus every v0.10.0 active-blocking scenario passes;
> the CRIT-04 benchmark gate (<= 25% wall-clock overhead) holds; results are
> captured in `.planning/milestones/v0.10.0-UAT.md`."

The six scripts map directly to the v0.10.0 feature matrix:

| Feature | Script |
|---------|--------|
| Cloud sync blocking (v0.9.0) | `Uat-CloudSync.ps1` |
| Print blocking (v0.9.0) | `Uat-PrintBlock.ps1` |
| Universal hook DLL injection (Phase 48-49) | `Uat-HookDll.ps1` |
| DACL tripwire (Phase 52) | `Uat-DaclTripwire.ps1` |
| ETW bypass detection + ntdll patching (Phase 51, 53) | `Uat-EtwNtdll.ps1` |
| Monitor mode (Phase 55) | `Uat-EtwNtdll.ps1` |
| CRIT-04 performance gate (Phase 50) | `Uat-Benchmark.ps1` |

---

## Next Steps

1. Execute each script on a real Windows 11 endpoint with the DLP stack deployed.
2. Capture results in `.planning/milestones/v0.10.0-UAT.md`.
3. If any FAIL appears, investigate agent logs at `C:\ProgramData\DLP\logs\`.
4. Proceed to Plan 57-06 (deployment guide finalization) once all scripts pass.
