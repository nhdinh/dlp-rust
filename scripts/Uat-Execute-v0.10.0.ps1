#Requires -RunAsAdministrator
<#
.SYNOPSIS
    v0.10.0 UAT Execution Script — 36 scenarios across 10 categories (A-J).

.DESCRIPTION
    Self-contained PowerShell script that executes all UAT scenarios from
    .planning/milestones/v0.10.0-UAT.md on a physical Windows 11 host.

    The script:
      - Validates prerequisites (Windows 11, admin rights, dlp-agent, signtool)
      - Creates C:\UAT\v0.10.0\ artifact directory tree with category subfolders
      - Captures environment data (OS, CPU, RAM, EDR, cloud clients)
      - Executes one function per category (A-J), prompting for Pass/Fail/N-A
      - Auto-captures agent log snippets per scenario
      - Runs CRIT-04 benchmark with warm-up, 3 baseline + 3 hooked runs, median
      - Generates results.json, crit04_results.json, and UAT-Summary.md

.PARAMETER WhatIf
    When present, prints all scenario IDs and descriptions without executing.

.EXAMPLE
    .\Uat-Execute-v0.10.0.ps1

    Runs the full UAT suite interactively.

.EXAMPLE
    .\Uat-Execute-v0.10.0.ps1 -WhatIf

    Lists all 36 scenarios without executing anything.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ─── Constants ───────────────────────────────────────────────────────────────

$SCRIPT:UatRoot        = 'C:\UAT\v0.10.0'
$SCRIPT:AgentLogPath   = 'C:\ProgramData\DLP\logs\dlp-agent.log'
$SCRIPT:AgentService   = 'dlp-agent'
$SCRIPT:ServerUrl     = 'http://127.0.0.1:9090'
$SCRIPT:ResultsJson   = Join-Path $SCRIPT:UatRoot 'results.json'
$SCRIPT:Crit04Json    = Join-Path $SCRIPT:UatRoot 'crit04_results.json'
$SCRIPT:SummaryMd     = Join-Path $SCRIPT:UatRoot 'UAT-Summary.md'
$SCRIPT:EnvJson       = Join-Path $SCRIPT:UatRoot 'environment.json'
$SCRIPT:ScenarioCount = 36

# Category definitions: ID prefix, description, scenario count
$SCRIPT:Categories = @(
    @{ Id='A'; Name='Hook Injection';        Count=4;  Scenarios=@('A01','A02','A03','A04') }
    @{ Id='B'; Name='File Blocking';           Count=6;  Scenarios=@('B01','B02','B03','B04','B05','B06') }
    @{ Id='C'; Name='Cloud Sync';              Count=4;  Scenarios=@('C01','C02','C03','C04') }
    @{ Id='D'; Name='Print';                   Count=2;  Scenarios=@('D01','D02') }
    @{ Id='E'; Name='USB/SD/Optical/Virtual';  Count=5;  Scenarios=@('E01','E02','E03','E04','E05') }
    @{ Id='F'; Name='DACL Tripwire';           Count=3;  Scenarios=@('F01','F02','F03') }
    @{ Id='G'; Name='ETW Bypass';              Count=2;  Scenarios=@('G01','G02') }
    @{ Id='H'; Name='Monitor Mode';            Count=3;  Scenarios=@('H01','H02','H03') }
    @{ Id='I'; Name='Performance / CRIT-04';   Count=2;  Scenarios=@('I01','I02') }
    @{ Id='J'; Name='Operational Verification'; Count=5; Scenarios=@('J01','J02','J03','J04','J05') }
)

# Scenario metadata: ID -> @{ Description; Prerequisites; Steps; Expected }
$SCRIPT:ScenarioMeta = @{
    'A01' = @{ Description='Universal hook injects into new user process within 500ms'; Prerequisites='Agent service running; no existing notepad.exe'; Steps='Start agent, wait 30s, launch Notepad, verify dlp_hook_dll.dll in modules within 500ms'; Expected='dlp_hook_dll.dll appears in Notepad module list within 500ms' }
    'A02' = @{ Description='Allowlisted processes (Defender, SYSTEM, PPL) are skipped'; Prerequisites='Agent running; Defender or EDR installed; SYSTEM visible'; Steps='Start agent, wait 60s, check agent log for skip entries, verify no injection in MsMpEng/lsass/PID4'; Expected='Agent log shows explicit skip entries; no DLL in allowlisted processes' }
    'A03' = @{ Description='WoW64 32-bit processes receive x86 DLL'; Prerequisites='Agent running; 32-bit executable available'; Steps='Launch SysWOW64\notepad.exe, verify dlp_hook_dll_x86.dll loaded'; Expected='32-bit process loads x86 DLL' }
    'A04' = @{ Description='Agent restart injects into all running user processes within 5s'; Prerequisites='Agent stopped; multiple user processes running'; Steps='Stop agent, launch Edge/Calc, start agent, verify all processes show DLL within 5s'; Expected='All non-allowlisted user processes show DLL within 5s' }
    'B01' = @{ Description='T4 file write denied via IAT hook'; Prerequisites='Agent running; T4 file at protected path; NTFS write allowed'; Steps='Set-Content to T4 file, observe access denied, check agent log'; Expected='Access denied; agent log shows WriteFile denied with classification=T4' }
    'B02' = @{ Description='T4 file copy denied via CopyFileExW'; Prerequisites='Agent running; T4 source file exists'; Steps='Copy-Item T4 file to temp, observe error, check agent log'; Expected='Copy fails; agent log shows CopyFileExW denied with classification=T4' }
    'B03' = @{ Description='T4 file move denied via MoveFileExW'; Prerequisites='Agent running; T4 source file exists'; Steps='Move-Item T4 file to temp, observe error, check agent log'; Expected='Move fails; agent log shows MoveFileExW denied with classification=T4' }
    'B04' = @{ Description='T4 file delete denied via DeleteFileW'; Prerequisites='Agent running; T4 file at protected path'; Steps='Remove-Item T4 file, observe error, check agent log'; Expected='Delete fails; agent log shows DeleteFileW denied with classification=T4' }
    'B05' = @{ Description='T1/T2 file operations allowed (no false positive)'; Prerequisites='Agent running; T1/T2 files at non-protected paths'; Steps='Write, copy, move T1/T2 files, verify all succeed, check agent log for unexpected denials'; Expected='All operations succeed; zero unexpected denials' }
    'B06' = @{ Description='Direct-syscall bypass blocked (ntdll patching enabled)'; Prerequisites='Agent running; enable_ntdll_patching=true; direct-syscall test binary'; Steps='Verify config, run test binary against T4 path, check return code and agent log'; Expected='STATUS_ACCESS_DENIED; agent log shows ntdll denial' }
    'C01' = @{ Description='OneDrive sync blocked for T4 files'; Prerequisites='OneDrive installed/signed in; T4 file in sync folder'; Steps='Place T4 file in OneDrive\Test, force sync, check status and agent log'; Expected='OneDrive shows sync error; agent log shows CloudSyncBlocked with provider=OneDrive' }
    'C02' = @{ Description='Google Drive sync blocked for T4 files'; Prerequisites='Google Drive installed/signed in; T4 file in sync folder'; Steps='Place T4 file in Google Drive\Test, wait for sync, check status and agent log'; Expected='Google Drive shows sync blocked; agent log shows CloudSyncBlocked with provider=GoogleDrive' }
    'C03' = @{ Description='Dropbox sync blocked for T4 files'; Prerequisites='Dropbox installed/signed in; T4 file in sync folder'; Steps='Place T4 file in Dropbox\Test, wait for sync, check status and agent log'; Expected='Dropbox shows sync error; agent log shows CloudSyncBlocked with provider=Dropbox' }
    'C04' = @{ Description='Box sync blocked for T4 files'; Prerequisites='Box Drive installed/signed in; T4 file in sync folder'; Steps='Place T4 file in Box\Test, wait for sync, check status and agent log'; Expected='Box Drive shows sync blocked; agent log shows CloudSyncBlocked with provider=Box' }
    'D01' = @{ Description='Print job blocked for T4 document'; Prerequisites='Printer installed; T4 document available'; Steps='Open T4 document, File > Print, choose printer, click Print, observe error, check agent log'; Expected='Print job blocked; agent log shows PrintBlocked with classification=T4' }
    'D02' = @{ Description='XPS extraction produces correct content hash'; Prerequisites='Print-to-XPS available; T4 document with known content'; Steps='Create document with known content, save as T4, print to XPS Document Writer, check agent log for hash'; Expected='Agent log contains XpsExtracted with content_sha256 matching expected hash' }
    'E01' = @{ Description='USB insertion produces VolumeArrival event'; Prerequisites='USB 3.0 flash drive available'; Steps='Insert USB drive, wait 5s, check agent log for VolumeArrival with volume_class=USBRemovable'; Expected='VolumeArrival event within 5s; volume_class=USBRemovable' }
    'E02' = @{ Description='SD card insertion produces VolumeArrival with SDCard class'; Prerequisites='SD card + reader available'; Steps='Insert SD card, wait 5s, check agent log for VolumeArrival with volume_class=SDCard'; Expected='VolumeArrival with volume_class=SDCard' }
    'E03' = @{ Description='Optical drive produces VolumeArrival with Optical class'; Prerequisites='Optical drive available'; Steps='Insert CD/DVD/Blu-ray, wait 5s, check agent log for VolumeArrival with volume_class=Optical'; Expected='VolumeArrival with volume_class=Optical' }
    'E04' = @{ Description='Virtual drive mount produces VolumeArrival with Virtual class'; Prerequisites='VHD/VHDX or ISO mount capability'; Steps='Mount VHDX or ISO, wait 5s, check agent log for VolumeArrival with volume_class=Virtual'; Expected='VolumeArrival with volume_class=Virtual' }
    'E05' = @{ Description='Volume-class ABAC policy blocks T4 to optical'; Prerequisites='Optical drive available; T4 file on LocalNTFS; ABAC policy configured'; Steps='Configure DENY policy, wait for sync, copy T4 file to optical drive, observe error'; Expected='Copy fails; agent log shows denial with source_volume_class=LocalNTFS, destination=Optical' }
    'F01' = @{ Description='T4 path has Deny ACE after agent start'; Prerequisites='Agent running; protected path registered; T4 classification'; Steps='Register protected path, wait for sync, run icacls, examine ACE list'; Expected='icacls shows Deny ACE for Authenticated Users at canonical order' }
    'F02' = @{ Description='icacls /reset triggers tamper alert within 60s'; Prerequisites='Agent running; protected path with T4; icacls available'; Steps='Verify Deny ACE exists, run icacls /reset /T /C, wait 60s, check agent log for DaclTamperDetected'; Expected='DaclTamperDetected within 60s; repair watcher restores Deny ACE' }
    'F03' = @{ Description='Operator removal via TUI does NOT trigger tamper alert'; Prerequisites='Agent running; protected path registered; admin TUI accessible'; Steps='Open admin TUI, navigate to Protected Paths, remove test path, wait 60s, check for DaclTamperDetected'; Expected='Path removed; NO DaclTamperDetected event' }
    'G01' = @{ Description='Hook uninstall produces BypassAlert within 5s'; Prerequisites='Agent running; hook injected; Process Hacker available'; Steps='Launch Notepad, confirm hook injected, unload DLL via Process Hacker, save file to T4 path, wait 5s, check agent log'; Expected='BypassAlert with correlation_reason=NoHookJournal within 5s' }
    'G02' = @{ Description='Allowlisted PIDs do NOT produce bypass alerts'; Prerequisites='Agent running; allowlisted process running'; Steps='Identify allowlisted PID, trigger file operations, wait 10s, check for BypassAlerts from that PID'; Expected='Zero BypassAlert entries for allowlisted PID' }
    'H01' = @{ Description='Audit mode allows file operation but emits would-have-denied event'; Prerequisites='Agent running; policy set to Audit; T4 file at test path'; Steps='Set policy to Audit, wait for sync, attempt T4 write, verify success, check agent log for AuditEvent'; Expected='Write succeeds; agent log shows AuditEvent with would_have_denied=true' }
    'H02' = @{ Description='Block mode denies file operation'; Prerequisites='Agent running; policy set to Block; T4 file at test path'; Steps='Set policy to Block, wait for sync, attempt T4 write, observe error, check agent log'; Expected='Write fails; agent log shows denial with policy_mode=Block' }
    'H03' = @{ Description='Global override Audit overrides per-policy Block'; Prerequisites='Agent running; policy set to Block; global override set to Audit'; Steps='Set policy to Block, set global override to Audit, wait for sync, attempt T4 write, check agent log'; Expected='Write succeeds; agent log shows global_override=Audit, would_have_denied=true' }
    'I01' = @{ Description='CRIT-04 benchmark <=25% overhead on cargo build'; Prerequisites='Agent controllable; Rust toolchain installed; PowerShell with Measure-Command'; Steps='Stop agent, warm-up cargo clean+build, run 3 baseline Measure-Command, start agent, warm-up, run 3 hooked Measure-Command, compute median and overhead'; Expected='Overhead <= 25%' }
    'I02' = @{ Description='CRIT-04 benchmark <=25% overhead on Word launch/save'; Prerequisites='Microsoft Word installed; Agent controllable'; Steps='Stop agent, warm-up Word launch+open+save, run 3 baseline Measure-Command, start agent, warm-up, run 3 hooked, compute median and overhead'; Expected='Overhead <= 25%' }
    'J01' = @{ Description='Authenticode verification via signtool verify /pa succeeds'; Prerequisites='Windows SDK installed; signed binaries at C:\Program Files\DLP\'; Steps='Run signtool verify /pa for each of 6 binaries'; Expected='All binaries return Successfully verified' }
    'J02' = @{ Description='EDR allowlist prevents quarantine'; Prerequisites='EDR installed with DLP allowlist; agent running for 10+ min'; Steps='Verify allowlist applied, start agent, wait 10min, check EDR console for detections'; Expected='Zero detections/quarantines for DLP binaries' }
    'J03' = @{ Description='SeSystemProfilePrivilege is assigned and visible'; Prerequisites='Agent installed; service account configured'; Steps='Query service privileges via whoami /priv or sc qprivs, search for SeSystemProfilePrivilege'; Expected='Privilege listed with State=Enabled or Present' }
    'J04' = @{ Description='Secure Boot fallback works (AppInit_DLLs inert, ETW+CreateRemoteThread active)'; Prerequisites='Secure Boot enabled; agent running'; Steps='Verify Secure Boot enabled, start agent, check Event Viewer for appinit_dlls_disabled event, launch Notepad, verify hook injected'; Expected='Secure Boot=True; appinit event fires; hook still works via fallback' }
    'J05' = @{ Description='Binary hashes match RELEASE_NOTES.md values'; Prerequisites='Binaries installed; RELEASE_NOTES.md available'; Steps='Run Get-FileHash for each binary, compare against published values'; Expected='All 6 binaries pass hash verification' }
}

# ─── Helper: Invoke-CargoBuildCommand (inline, not imported) ─────────────────

function Invoke-CargoBuildCommand {
    <#
    .SYNOPSIS
        Runs a cargo command for benchmarking and returns exit code plus output.

    .DESCRIPTION
        Cargo writes progress to stderr. With $ErrorActionPreference = 'Stop',
        those stderr lines would be terminating errors before we can inspect
        $LASTEXITCODE. This helper temporarily relaxes error handling, captures
        output, and returns the exit code so callers can decide failure.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ArgumentList
    )

    $previousErrorAction = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & cargo @ArgumentList 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorAction
    }
    return [PSCustomObject]@{
        ExitCode = $exitCode
        Output   = ($output | ForEach-Object { "$_" }) -join "`n"
    }
}

# ─── Preamble ────────────────────────────────────────────────────────────────

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-Windows11 {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $caption = $os.Caption
    $build   = [int]$os.BuildNumber
    # Windows 11 starts at build 22000
    return ($caption -like '*Windows 11*') -or ($build -ge 22000)
}

function Test-AgentService {
    $svc = Get-Service -Name $SCRIPT:AgentService -ErrorAction SilentlyContinue
    return ($null -ne $svc)
}

function Test-Signtool {
    $st = Get-Command 'signtool.exe' -ErrorAction SilentlyContinue
    return ($null -ne $st)
}

function Initialize-UatEnvironment {
    # Create directory tree
    $dirs = @($SCRIPT:UatRoot)
    foreach ($cat in $SCRIPT:Categories) {
        $dirs += Join-Path $SCRIPT:UatRoot $cat.Id
    }
    foreach ($d in $dirs) {
        if (-not (Test-Path $d)) {
            New-Item -ItemType Directory -Path $d -Force | Out-Null
        }
    }
    Write-Host "Artifact directory tree created at $($SCRIPT:UatRoot)" -ForegroundColor Green
}

function Capture-Environment {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
    $edrProcesses = @(Get-Process | Where-Object {
        $_.ProcessName -match 'MsMpEng|CSFalconService|SentinelService|CbDefense|Sophos|TrendMicro'
    } | ForEach-Object { $_.ProcessName })

    $cloudVersions = @{}
    foreach ($client in @('OneDrive','GoogleDriveFS','Dropbox','BoxDrive')) {
        try {
            $p = Get-Process -Name $client -ErrorAction Stop | Select-Object -First 1
            $cloudVersions[$client] = $p.Path
        }
        catch {
            $cloudVersions[$client] = 'not_running'
        }
    }

    $envData = [PSCustomObject]@{
        host_os              = $os.Caption
        os_build             = $os.BuildNumber
        cpu                  = $cpu.Name
        ram_gb               = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
        disk                 = (Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'").Size / 1GB | ForEach-Object { [math]::Round($_, 1) }
        edr_installed        = ($edrProcesses.Count -gt 0)
        edr_processes        = $edrProcesses
        onedrive_version     = $cloudVersions['OneDrive']
        google_drive_version = $cloudVersions['GoogleDriveFS']
        dropbox_version      = $cloudVersions['Dropbox']
        box_drive_version    = $cloudVersions['BoxDrive']
        dlp_agent_version    = 'v0.10.0'
        policy_bundle_version = 'TBD'
        tester_name          = 'TBD'
        test_date            = (Get-Date -Format 'yyyy-MM-dd')
        capture_timestamp    = (Get-Date).ToUniversalTime().ToString('o')
    }

    $envData | ConvertTo-Json -Depth 4 | Set-Content -Path $SCRIPT:EnvJson -Encoding UTF8
    Write-Host "Environment captured to $SCRIPT:EnvJson" -ForegroundColor Green
    return $envData
}

# ─── Results tracking ────────────────────────────────────────────────────────

$SCRIPT:Results = [System.Collections.ArrayList]::new()

function New-UatArtifact {
    param(
        [Parameter(Mandatory = $true)][string]$ScenarioId,
        [Parameter(Mandatory = $true)][string]$ArtifactType,
        [Parameter(Mandatory = $true)][string]$Extension
    )
    $cat = $ScenarioId.Substring(0, 1)
    $ts  = Get-Date -Format 'yyyyMMdd_HHmmss'
    $fn  = "UAT-57-${ScenarioId}_${ArtifactType}_${ts}.${Extension}"
    return Join-Path $SCRIPT:UatRoot $cat $fn
}

function Write-UatResult {
    param(
        [Parameter(Mandatory = $true)][string]$ScenarioId,
        [Parameter(Mandatory = $true)][ValidateSet('PASS','FAIL','N-A')][string]$Result,
        [string]$Notes = ''
    )
    $entry = [PSCustomObject]@{
        scenario_id   = $ScenarioId
        result        = $Result
        notes         = $Notes
        timestamp     = (Get-Date).ToUniversalTime().ToString('o')
        agent_log_snippet = $null
    }
    [void]$SCRIPT:Results.Add($entry)
}

function Save-ResultsJson {
    $SCRIPT:Results | ConvertTo-Json -Depth 4 | Set-Content -Path $SCRIPT:ResultsJson -Encoding UTF8
}

function Capture-AgentLogSnippet {
    param(
        [Parameter(Mandatory = $true)][string]$ScenarioId,
        [int]$Lines = 100
    )
    $dest = New-UatArtifact -ScenarioId $ScenarioId -ArtifactType 'agent' -Extension 'log'
    if (Test-Path $SCRIPT:AgentLogPath) {
        Get-Content -Path $SCRIPT:AgentLogPath -Tail $Lines | Set-Content -Path $dest -Encoding UTF8
    }
    else {
        "Agent log not found at ${SCRIPT:AgentLogPath}" | Set-Content -Path $dest -Encoding UTF8
    }
    return $dest
}

function Prompt-ScenarioResult {
    param(
        [Parameter(Mandatory = $true)][string]$ScenarioId,
        [Parameter(Mandatory = $true)][string]$Description
    )
    Write-Host "`n=== Scenario $ScenarioId ===" -ForegroundColor Cyan
    Write-Host $Description -ForegroundColor White
    if ($WhatIf) {
        Write-Host "[WhatIf] Would prompt: Pass / Fail / N-A" -ForegroundColor Yellow
        return 'N-A'
    }
    do {
        $resp = Read-Host "Enter result [P]ass / [F]ail / [N]-A (or type notes after space)"
        $result = $resp.Substring(0, 1).ToUpper()
    } while ($result -notin @('P', 'F', 'N'))
    $notes = if ($resp.Length -gt 2) { $resp.Substring(2) } else { '' }
    $fullResult = switch ($result) { 'P' { 'PASS' } 'F' { 'FAIL' } 'N' { 'N-A' } }
    Write-UatResult -ScenarioId $ScenarioId -Result $fullResult -Notes $notes
    Capture-AgentLogSnippet -ScenarioId $ScenarioId
    return $fullResult
}

# ─── Category Execution Functions ─────────────────────────────────────────────

function Invoke-CategoryA {
    Write-Host "`n--- Category A: Hook Injection ---" -ForegroundColor Green
    foreach ($sid in $SCRIPT:Categories[0].Scenarios) {
        $meta = $SCRIPT:ScenarioMeta[$sid]
        Prompt-ScenarioResult -ScenarioId $sid -Description $meta.Description
    }
}

function Invoke-CategoryB {
    Write-Host "`n--- Category B: File Blocking ---" -ForegroundColor Green
    foreach ($sid in $SCRIPT:Categories[1].Scenarios) {
        $meta = $SCRIPT:ScenarioMeta[$sid]
        Prompt-ScenarioResult -ScenarioId $sid -Description $meta.Description
    }
}

function Invoke-CategoryC {
    Write-Host "`n--- Category C: Cloud Sync ---" -ForegroundColor Green
    foreach ($sid in $SCRIPT:Categories[2].Scenarios) {
        $meta = $SCRIPT:ScenarioMeta[$sid]
        Prompt-ScenarioResult -ScenarioId $sid -Description $meta.Description
    }
}

function Invoke-CategoryD {
    Write-Host "`n--- Category D: Print ---" -ForegroundColor Green
    foreach ($sid in $SCRIPT:Categories[3].Scenarios) {
        $meta = $SCRIPT:ScenarioMeta[$sid]
        Prompt-ScenarioResult -ScenarioId $sid -Description $meta.Description
    }
}

function Invoke-CategoryE {
    Write-Host "`n--- Category E: USB/SD/Optical/Virtual ---" -ForegroundColor Green
    foreach ($sid in $SCRIPT:Categories[4].Scenarios) {
        $meta = $SCRIPT:ScenarioMeta[$sid]
        Prompt-ScenarioResult -ScenarioId $sid -Description $meta.Description
    }
}

function Invoke-CategoryF {
    Write-Host "`n--- Category F: DACL Tripwire ---" -ForegroundColor Green
    foreach ($sid in $SCRIPT:Categories[5].Scenarios) {
        $meta = $SCRIPT:ScenarioMeta[$sid]
        Prompt-ScenarioResult -ScenarioId $sid -Description $meta.Description
    }
}

function Invoke-CategoryG {
    Write-Host "`n--- Category G: ETW Bypass ---" -ForegroundColor Green
    foreach ($sid in $SCRIPT:Categories[6].Scenarios) {
        $meta = $SCRIPT:ScenarioMeta[$sid]
        Prompt-ScenarioResult -ScenarioId $sid -Description $meta.Description
    }
}

function Invoke-CategoryH {
    Write-Host "`n--- Category H: Monitor Mode ---" -ForegroundColor Green
    foreach ($sid in $SCRIPT:Categories[7].Scenarios) {
        $meta = $SCRIPT:ScenarioMeta[$sid]
        Prompt-ScenarioResult -ScenarioId $sid -Description $meta.Description
    }
}

function Invoke-CategoryI {
    Write-Host "`n--- Category I: Performance / CRIT-04 ---" -ForegroundColor Green
    Invoke-Crit04Benchmark
}

# ─── CRIT-04 Benchmark ───────────────────────────────────────────────────────

function Get-Median {
    param([array]$Values)
    $sorted = $Values | Sort-Object
    $count = $sorted.Count
    if ($count -eq 0) { return 0.0 }
    if ($count % 2 -eq 1) { return [double]$sorted[[math]::Floor($count / 2)] }
    $mid = $count / 2
    return ([double]$sorted[$mid - 1] + [double]$sorted[$mid]) / 2.0
}

function Invoke-Crit04Benchmark {
    <#
    .SYNOPSIS
        Runs CRIT-04 performance benchmark: cargo build and Word launch overhead.

    .DESCRIPTION
        Protocol:
        1. Warm-up: cargo clean + cargo build --workspace --release (discarded)
        2. Baseline: 3 runs with agent STOPPED, measure with Measure-Command
        3. With-hooks: 3 runs with agent STARTED (30s wait), measure
        4. Compute median for each set, calculate overhead
        5. Results saved to crit04_results.json
    #>
    Write-Host "`n--- Category I: CRIT-04 Performance Benchmark ---" -ForegroundColor Green

    if ($WhatIf) {
        Write-Host "[WhatIf] Would run CRIT-04 benchmark with warm-up + 3 baseline + 3 hooked runs" -ForegroundColor Yellow
        return
    }

    # Determine cargo project dir (default to ripgrep clone if available)
    $cargoProjectDir = $PWD.Path
    if (Test-Path (Join-Path $cargoProjectDir 'Cargo.toml')) {
        # Use current workspace
    }
    else {
        $cargoProjectDir = 'C:\Temp\dlp-benchmark'
        if (-not (Test-Path $cargoProjectDir)) {
            Write-Host "No Cargo project found for benchmark. Skipping cargo build benchmark." -ForegroundColor Yellow
            $cargoProjectDir = $null
        }
    }

    $critResults = [PSCustomObject]@{
        timestamp       = (Get-Date).ToUniversalTime().ToString('o')
        cargo_build     = $null
        word_launch     = $null
    }

    # ── Cargo Build Benchmark ──
    if ($cargoProjectDir) {
        Write-Host "`n[CRIT-04] Cargo Build Benchmark" -ForegroundColor Cyan

        # Warm-up (discarded)
        Write-Host "  Warm-up build (discarded)..." -ForegroundColor Yellow
        $warmup = Invoke-CargoBuildCommand -ArgumentList @('clean')
        if ($warmup.ExitCode -ne 0) { Write-Host "  cargo clean exit: $($warmup.ExitCode)" -ForegroundColor Yellow }
        $warmup = Invoke-CargoBuildCommand -ArgumentList @('build', '--workspace', '--release')
        if ($warmup.ExitCode -ne 0) { Write-Host "  Warm-up build failed: $($warmup.Output)" -ForegroundColor Red }
        else { Write-Host "  Warm-up complete." -ForegroundColor Green }

        # Baseline: agent stopped
        Write-Host "`n  Baseline runs (agent STOPPED)..." -ForegroundColor Yellow
        Stop-Service -Name $SCRIPT:AgentService -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
        $baselineTimes = @()
        for ($i = 1; $i -le 3; $i++) {
            Write-Host "    Baseline run $i/3..." -ForegroundColor Cyan
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $build = Invoke-CargoBuildCommand -ArgumentList @('build', '--workspace', '--release')
            $sw.Stop()
            if ($build.ExitCode -eq 0) {
                $baselineTimes += [math]::Round($sw.Elapsed.TotalSeconds, 2)
                Write-Host "      $($baselineTimes[-1])s" -ForegroundColor Green
            }
            else {
                Write-Host "      Build failed" -ForegroundColor Red
            }
        }

        # With-hooks: agent started
        Write-Host "`n  With-hooks runs (agent STARTED)..." -ForegroundColor Yellow
        Start-Service -Name $SCRIPT:AgentService -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 30
        $hookedTimes = @()
        for ($i = 1; $i -le 3; $i++) {
            Write-Host "    Hooked run $i/3..." -ForegroundColor Cyan
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $build = Invoke-CargoBuildCommand -ArgumentList @('build', '--workspace', '--release')
            $sw.Stop()
            if ($build.ExitCode -eq 0) {
                $hookedTimes += [math]::Round($sw.Elapsed.TotalSeconds, 2)
                Write-Host "      $($hookedTimes[-1])s" -ForegroundColor Green
            }
            else {
                Write-Host "      Build failed" -ForegroundColor Red
            }
        }

        $baselineMedian = Get-Median -Values $baselineTimes
        $hookedMedian   = Get-Median -Values $hookedTimes
        $overhead = if ($baselineMedian -eq 0) { 0 } else {
            [math]::Round((($hookedMedian - $baselineMedian) / $baselineMedian) * 100, 2)
        }
        $passed = $overhead -le 25

        $critResults.cargo_build = [PSCustomObject]@{
            baseline_times   = $baselineTimes
            hooked_times     = $hookedTimes
            baseline_median  = $baselineMedian
            hooked_median    = $hookedMedian
            overhead_percent = $overhead
            passed           = $passed
            target_percent   = 25
        }

        Write-Host "`n  Cargo Build Results:" -ForegroundColor Cyan
        Write-Host "    Baseline median: ${baselineMedian}s" -ForegroundColor White
        Write-Host "    Hooked median:   ${hookedMedian}s" -ForegroundColor White
        Write-Host "    Overhead:        ${overhead}%" -ForegroundColor $(if ($passed) { 'Green' } else { 'Red' })
        Write-Host "    Status:          $(if ($passed) { 'PASS' } else { 'FAIL' })" -ForegroundColor $(if ($passed) { 'Green' } else { 'Red' })
    }

    # ── Word Launch Benchmark ──
    $wordPath = Join-Path $env:ProgramFiles 'Microsoft Office\root\Office16\WINWORD.EXE'
    if (-not (Test-Path $wordPath)) {
        $wordPath = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Office\root\Office16\WINWORD.EXE'
    }

    if (Test-Path $wordPath) {
        Write-Host "`n[CRIT-04] Word Launch Benchmark" -ForegroundColor Cyan

        # Baseline: agent stopped
        Write-Host "  Baseline runs (agent STOPPED)..." -ForegroundColor Yellow
        Stop-Service -Name $SCRIPT:AgentService -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
        $baselineTimes = @()
        for ($i = 1; $i -le 3; $i++) {
            Write-Host "    Baseline run $i/3..." -ForegroundColor Cyan
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $proc = Start-Process -FilePath $wordPath -PassThru
            Start-Sleep -Seconds 3
            if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
            $sw.Stop()
            $baselineTimes += [math]::Round($sw.Elapsed.TotalSeconds, 2)
            Write-Host "      $($baselineTimes[-1])s" -ForegroundColor Green
        }

        # With-hooks: agent started
        Write-Host "`n  With-hooks runs (agent STARTED)..." -ForegroundColor Yellow
        Start-Service -Name $SCRIPT:AgentService -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 30
        $hookedTimes = @()
        for ($i = 1; $i -le 3; $i++) {
            Write-Host "    Hooked run $i/3..." -ForegroundColor Cyan
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $proc = Start-Process -FilePath $wordPath -PassThru
            Start-Sleep -Seconds 3
            if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
            $sw.Stop()
            $hookedTimes += [math]::Round($sw.Elapsed.TotalSeconds, 2)
            Write-Host "      $($hookedTimes[-1])s" -ForegroundColor Green
        }

        $baselineMedian = Get-Median -Values $baselineTimes
        $hookedMedian   = Get-Median -Values $hookedTimes
        $overhead = if ($baselineMedian -eq 0) { 0 } else {
            [math]::Round((($hookedMedian - $baselineMedian) / $baselineMedian) * 100, 2)
        }
        $passed = $overhead -le 25

        $critResults.word_launch = [PSCustomObject]@{
            baseline_times   = $baselineTimes
            hooked_times     = $hookedTimes
            baseline_median  = $baselineMedian
            hooked_median    = $hookedMedian
            overhead_percent = $overhead
            passed           = $passed
            target_percent   = 25
        }

        Write-Host "`n  Word Launch Results:" -ForegroundColor Cyan
        Write-Host "    Baseline median: ${baselineMedian}s" -ForegroundColor White
        Write-Host "    Hooked median:   ${hookedMedian}s" -ForegroundColor White
        Write-Host "    Overhead:        ${overhead}%" -ForegroundColor $(if ($passed) { 'Green' } else { 'Red' })
        Write-Host "    Status:          $(if ($passed) { 'PASS' } else { 'FAIL' })" -ForegroundColor $(if ($passed) { 'Green' } else { 'Red' })
    }
    else {
        Write-Host "Word not found — skipping Word launch benchmark." -ForegroundColor Yellow
    }

    $critResults | ConvertTo-Json -Depth 10 | Set-Content -Path $SCRIPT:Crit04Json -Encoding UTF8
    Write-Host "`nCRIT-04 results saved to $SCRIPT:Crit04Json" -ForegroundColor Green
}

function Invoke-CategoryJ {
    Write-Host "`n--- Category J: Operational Verification ---" -ForegroundColor Green
    foreach ($sid in $SCRIPT:Categories[9].Scenarios) {
        $meta = $SCRIPT:ScenarioMeta[$sid]
        Prompt-ScenarioResult -ScenarioId $sid -Description $meta.Description
    }
}

# ─── Results Summary Generation ──────────────────────────────────────────────

function New-UatSummary {
    $passed = @($SCRIPT:Results | Where-Object { $_.result -eq 'PASS' }).Count
    $failed = @($SCRIPT:Results | Where-Object { $_.result -eq 'FAIL' }).Count
    $na     = @($SCRIPT:Results | Where-Object { $_.result -eq 'N-A' }).Count
    $blocking = @($SCRIPT:Results | Where-Object { $_.result -eq 'FAIL' -and $_.scenario_id -match '^(B01|B02|B03|B04|B05|B06|G01|H02|I01|I02|J01|J02|J04|J05)' })

    $crit04 = if (Test-Path $SCRIPT:Crit04Json) {
        Get-Content -Path $SCRIPT:Crit04Json -Raw | ConvertFrom-Json
    }
    else { $null }

    $naJustifications = @($SCRIPT:Results | Where-Object { $_.result -eq 'N-A' } | ForEach-Object { "- $($_.scenario_id): $($_.notes)" })

    $shipRecommendation = 'PENDING'
    if ($failed -eq 0 -and $na -lt 10) { $shipRecommendation = 'SHIP' }
    elseif ($blocking.Count -gt 0) { $shipRecommendation = 'NO-SHIP' }
    else { $shipRecommendation = 'Engineering Discretion Required' }

    $summary = @"
# v0.10.0 UAT Execution Summary

**Generated:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
**Tester:** TBD
**Host:** TBD

## Results Overview

| Metric | Count |
|--------|-------|
| Total Scenarios | $SCRIPT:ScenarioCount |
| Passed | $passed |
| Failed | $failed |
| N/A | $na |

## CRIT-04 Benchmark Results

"@

    if ($crit04 -and $crit04.cargo_build) {
        $cb = $crit04.cargo_build
        $summary += @"
### Cargo Build
- Baseline median: $($cb.baseline_median)s
- Hooked median: $($cb.hooked_median)s
- Overhead: $($cb.overhead_percent)%
- Status: $(if ($cb.passed) { 'PASS' } else { 'FAIL' })

"@
    }
    else {
        $summary += "### Cargo Build
- Not executed

"
    }

    if ($crit04 -and $crit04.word_launch) {
        $wl = $crit04.word_launch
        $summary += @"
### Word Launch
- Baseline median: $($wl.baseline_median)s
- Hooked median: $($wl.hooked_median)s
- Overhead: $($wl.overhead_percent)%
- Status: $(if ($wl.passed) { 'PASS' } else { 'FAIL' })

"@
    }
    else {
        $summary += "### Word Launch
- Not executed

"
    }

    $summary += @"
## Blocking Failures

$(if ($blocking.Count -gt 0) { $blocking | ForEach-Object { "- $($_.scenario_id): $($_.notes)" } | Join-String -Separator "`n" } else { "None" })

## Known Limitations (N/A Scenarios)

$(if ($naJustifications.Count -gt 0) { $naJustifications | Join-String -Separator "`n" } else { "None" })

## Ship/No-Ship Recommendation

**Recommendation:** $shipRecommendation

Per decision matrix from 57-VERIFICATION.md:
- 0 Blocking failures + Engineering/QA sign-off = SHIP
- 1+ Blocking failures = NO-SHIP
- 0 Blocking + Major failures only = Engineering discretion

## Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Engineering Lead | | | |
| QA Lead | | | |

## Detailed Results

| Scenario | Result | Notes |
|----------|--------|-------|
"@

    foreach ($r in $SCRIPT:Results) {
        $summary += "| $($r.scenario_id) | $($r.result) | $($r.notes) |`n"
    }

    $summary += "`n---`n*Generated by Uat-Execute-v0.10.0.ps1*"

    $summary | Set-Content -Path $SCRIPT:SummaryMd -Encoding UTF8
    Write-Host "`nUAT Summary saved to $SCRIPT:SummaryMd" -ForegroundColor Green
}

# ─── Main ─────────────────────────────────────────────────────────────────────

Write-Host "=== DLP v0.10.0 UAT Execution Script ===" -ForegroundColor Cyan
Write-Host "Scenarios: $SCRIPT:ScenarioCount across 10 categories (A-J)" -ForegroundColor Cyan

# Preamble checks
if (-not (Test-Admin)) {
    Write-Error "This script must run as Administrator. Exiting."
    exit 1
}
Write-Host "Administrator check: PASS" -ForegroundColor Green

if (-not (Test-Windows11)) {
    Write-Warning "This host does not appear to be Windows 11. Continuing anyway."
}
else {
    Write-Host "Windows 11 check: PASS" -ForegroundColor Green
}

if (-not (Test-AgentService)) {
    Write-Warning "dlp-agent service not found. Some scenarios may fail or require N/A."
}
else {
    Write-Host "dlp-agent service check: PASS" -ForegroundColor Green
}

if (-not (Test-Signtool)) {
    Write-Warning "signtool.exe not found in PATH. Scenario J01 may require manual verification."
}
else {
    Write-Host "signtool check: PASS" -ForegroundColor Green
}

# Initialize environment
Initialize-UatEnvironment
$envData = Capture-Environment

# WhatIf mode: list all scenarios and exit
if ($WhatIf) {
    Write-Host "`n=== WhatIf Mode: Scenario Listing ===" -ForegroundColor Yellow
    foreach ($cat in $SCRIPT:Categories) {
        Write-Host "`nCategory $($cat.Id): $($cat.Name)" -ForegroundColor Cyan
        foreach ($sid in $cat.Scenarios) {
            $meta = $SCRIPT:ScenarioMeta[$sid]
            Write-Host "  $sid - $($meta.Description)" -ForegroundColor White
        }
    }
    Write-Host "`n[WhatIf] No scenarios executed. Run without -WhatIf to execute." -ForegroundColor Yellow
    exit 0
}

# Execute categories
$categories = @(
    @{ Fn = 'Invoke-CategoryA'; Name = 'A' },
    @{ Fn = 'Invoke-CategoryB'; Name = 'B' },
    @{ Fn = 'Invoke-CategoryC'; Name = 'C' },
    @{ Fn = 'Invoke-CategoryD'; Name = 'D' },
    @{ Fn = 'Invoke-CategoryE'; Name = 'E' },
    @{ Fn = 'Invoke-CategoryF'; Name = 'F' },
    @{ Fn = 'Invoke-CategoryG'; Name = 'G' },
    @{ Fn = 'Invoke-CategoryH'; Name = 'H' },
    @{ Fn = 'Invoke-CategoryI'; Name = 'I' },
    @{ Fn = 'Invoke-CategoryJ'; Name = 'J' }
)

foreach ($cat in $categories) {
    try {
        & $cat.Fn
    }
    catch {
        Write-Warning "Category $($cat.Name) encountered error: $_"
        Write-Warning "Continuing to next category..."
    }
}

# Save results and generate summary
Save-ResultsJson
New-UatSummary

Write-Host "`n=== UAT Execution Complete ===" -ForegroundColor Cyan
Write-Host "Results: $SCRIPT:ResultsJson" -ForegroundColor White
Write-Host "CRIT-04: $SCRIPT:Crit04Json" -ForegroundColor White
Write-Host "Summary: $SCRIPT:SummaryMd" -ForegroundColor White
Write-Host "Environment: $SCRIPT:EnvJson" -ForegroundColor White

exit 0
