#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CRIT-04 performance benchmark for DLP v0.10.0.

.DESCRIPTION
    Measures wall-clock overhead introduced by the DLP hook DLL on two
    representative workloads:
      1. cargo build --release of a Rust project (default: ripgrep)
      2. Office app launch (Word or Excel to visible window)

    The default Rust project is ripgrep, cloned automatically to a temporary
    directory, because the DLP workspace's aws-lc-sys dependency fails to
    build on some Windows toolchains from a cold target directory.  You can
    override with -CargoProjectDir to benchmark any Rust project that builds
    cleanly on the host.

    Protocol:
      - One unmeasured warm-up run per workload (discarded).
      - Baseline: N measured runs with dlp-agent STOPPED.
      - Hooked:   N measured runs with dlp-agent RUNNING.
      - Overhead = ((hooked_median - baseline_median) / baseline_median) * 100
      - Gate: overhead <= 25% for both workloads.

    Results are written to:
      C:\ProgramData\DLP\logs\uat-benchmark-{timestamp}.json

    The script never stops dlp-server; it only toggles dlp-agent.  Stopping
    dlp-agent may trigger the admin password challenge UI.  When that happens,
    the script pauses and tells the operator to confirm the challenge, then
    resumes automatically once the service reaches Stopped.

.EXAMPLE
    .\Uat-Benchmark.ps1

    Runs the full CRIT-04 suite with defaults (3 measured runs, 25% gate).

.EXAMPLE
    .\Uat-Benchmark.ps1 -Runs 5 -ThresholdPercent 20.0

    Five measured runs with a stricter 20% gate.

.EXAMPLE
    .\Uat-Benchmark.ps1 -SkipOffice

    Runs only the cargo build benchmark.

.EXAMPLE
    .\Uat-Benchmark.ps1 -BaselineMode Manual

    Prompts the operator to stop/start dlp-agent manually instead of using
    the service control APIs.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('StopService', 'Manual', 'None')]
    [string]$BaselineMode = 'StopService',

    [Parameter()]
    [int]$Runs = 3,

    [Parameter()]
    [double]$ThresholdPercent = 25.0,

    [Parameter()]
    [switch]$SkipOffice,

    [Parameter()]
    [switch]$SkipPreconditionCheck,

    # Directory of the Rust project to benchmark. If omitted, ripgrep is
    # cloned automatically into a temp dir because the DLP workspace's
    # aws-lc-sys dependency fails to build from a cold target dir on some hosts.
    [Parameter()]
    [string]$CargoProjectDir,

    [Parameter()]
    [string]$CargoBenchRepoUrl = 'https://github.com/BurntSushi/ripgrep.git',

    [Parameter()]
    [string]$CargoBenchRepoTag = '14.1.1',

    # Separate target directory so cargo clean does not touch the locked
    # target/ directory where dlp-agent/dlp-server are running.
    [Parameter()]
    [string]$CargoTargetDir,

    [Parameter()]
    [string]$ResultsDir = 'C:\ProgramData\DLP\logs'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ─── Constants ───────────────────────────────────────────────────────────────

$SCRIPT:AgentServiceName = 'dlp-agent'
$SCRIPT:ServerUrl = 'http://127.0.0.1:9090'

function Get-DefaultBenchProjectDir {
    <#
    .SYNOPSIS
        Returns the path to the default benchmark project, cloning it if needed.
    #>
    $baseDir = Join-Path $env:TEMP 'dlp-benchmark-projects'
    $repoDir = Join-Path $baseDir "ripgrep-$CargoBenchRepoTag"

    if (Test-Path (Join-Path $repoDir 'Cargo.toml')) {
        return $repoDir
    }

    if (-not (Test-Path $baseDir)) {
        New-Item -ItemType Directory -Path $baseDir -Force | Out-Null
    }

    Write-Host "`n[Setup] Cloning benchmark project: $CargoBenchRepoUrl (tag $CargoBenchRepoTag)..." -ForegroundColor Yellow
    & git clone --depth 1 --branch $CargoBenchRepoTag $CargoBenchRepoUrl $repoDir 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "git clone of $CargoBenchRepoUrl failed"
    }

    return $repoDir
}

# Resolve cargo project dir: default to ripgrep clone if not provided.
if (-not $CargoProjectDir) {
    $CargoProjectDir = Get-DefaultBenchProjectDir
}

# Default to a temp target dir under the project root so it is on the same volume
# as the source and avoids locking the running agent/server binaries.
if (-not $CargoTargetDir) {
    $CargoTargetDir = Join-Path $CargoProjectDir "target-benchmark-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
}

# ─── Helpers ─────────────────────────────────────────────────────────────────

function Write-Result {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $true)]
        [ValidateSet('PASS', 'FAIL', 'INFO', 'WARN')]
        [string]$Level
    )
    switch ($Level) {
        'PASS' { Write-Host "  PASS: $Message" -ForegroundColor Green }
        'FAIL' { Write-Host "  FAIL: $Message" -ForegroundColor Red }
        'INFO' { Write-Host "  INFO: $Message" -ForegroundColor Cyan }
        'WARN' { Write-Host "  WARN: $Message" -ForegroundColor Yellow }
    }
}

function Test-Preconditions {
    $allOk = $true

    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $freeGB = [math]::Round($os.FreePhysicalMemory / 1MB, 1)
    if ($freeGB -lt 4) {
        Write-Result "Free memory is ${freeGB}GB -- recommend > 4GB" 'WARN'
        $allOk = $false
    }
    else {
        Write-Result "Free memory: ${freeGB}GB" 'INFO'
    }

    $agentSvc = Get-Service -Name $SCRIPT:AgentServiceName -ErrorAction SilentlyContinue
    if (-not $agentSvc) {
        Write-Result "dlp-agent service not found -- is the agent installed?" 'FAIL'
        $allOk = $false
    }
    else {
        Write-Result "dlp-agent service found (current state: $($agentSvc.Status))" 'INFO'
    }

    try {
        $null = Invoke-RestMethod -Uri "$($SCRIPT:ServerUrl)/health" -TimeoutSec 5 -ErrorAction Stop
        Write-Result "dlp-server health check OK ($($SCRIPT:ServerUrl))" 'INFO'
    }
    catch {
        Write-Result "dlp-server not reachable at $($SCRIPT:ServerUrl) -- start it before benchmarking" 'WARN'
        $allOk = $false
    }

    if (-not (Test-Path (Join-Path $CargoProjectDir 'Cargo.toml'))) {
        Write-Result "Cargo.toml not found in $CargoProjectDir" 'FAIL'
        $allOk = $false
    }
    else {
        Write-Result "Cargo project: $CargoProjectDir" 'INFO'
        Write-Result "Cargo target dir: $CargoTargetDir" 'INFO'
    }

    return $allOk
}

function Test-RustAvailable {
    $cargo = Get-Command 'cargo' -ErrorAction SilentlyContinue
    if ($cargo) {
        Write-Result "cargo found: $($cargo.Source)" 'INFO'
        return $true
    }
    Write-Result "cargo not found in PATH" 'WARN'
    return $false
}

function Measure-CargoBuild {
    param(
        # If true, runs cargo clean before the measured build.
        [switch]$CleanFirst
    )

    if (-not (Test-Path -LiteralPath $CargoTargetDir)) {
        New-Item -ItemType Directory -Path $CargoTargetDir -Force | Out-Null
    }

    Push-Location -LiteralPath $CargoProjectDir
    try {
        if ($CleanFirst) {
            # Clean only the dedicated benchmark target dir, never the locked
            # target/ where dlp-agent/dlp-server are running.
            $cleanOutput = & cargo clean --target-dir $CargoTargetDir 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "cargo clean failed (exit $LASTEXITCODE): $cleanOutput"
            }
        }

        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $buildOutput = & cargo build --workspace --release --target-dir $CargoTargetDir 2>&1
        $sw.Stop()

        if ($LASTEXITCODE -ne 0) {
            throw "cargo build --release failed (exit $LASTEXITCODE): $buildOutput"
        }

        return [math]::Round($sw.Elapsed.TotalSeconds, 2)
    }
    finally {
        Pop-Location
    }
}

function Invoke-CargoBuildWarmup {
    <#
    .SYNOPSIS
        Performs an unmeasured cargo build to populate the isolated target dir.

    .DESCRIPTION
        The DLP workspace contains dependencies (e.g. aws-lc-sys) whose C
        compiler feature probes can fail on a cold target directory.  This
        function builds once without timing, retries on transient failures,
        and returns only after a successful build so measured runs start from
        a warm, consistent state.
    #>
    param(
        [int]$MaxAttempts = 3
    )

    Write-Host "`n[Warm-up build] Populating isolated target dir (not measured)..." -ForegroundColor Yellow

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            Write-Host "  Warm-up attempt $attempt/$MaxAttempts..." -ForegroundColor Cyan
            $null = Measure-CargoBuild -CleanFirst
            Write-Result "Warm-up build succeeded" 'INFO'
            return
        }
        catch {
            Write-Result "Warm-up build failed: $_" 'WARN'
            if ($attempt -eq $MaxAttempts) {
                throw "Cargo warm-up build failed after $MaxAttempts attempts. Cannot benchmark."
            }
            Start-Sleep -Seconds 5
        }
    }
}

function Remove-CargoTargetDir {
    <#
    .SYNOPSIS
        Removes the dedicated benchmark target directory on exit.
    #>
    if (Test-Path -LiteralPath $CargoTargetDir) {
        try {
            Remove-Item -LiteralPath $CargoTargetDir -Recurse -Force -ErrorAction Stop
            Write-Result "Removed benchmark target dir: $CargoTargetDir" 'INFO'
        }
        catch {
            Write-Result "Could not remove benchmark target dir: $_" 'WARN'
        }
    }
}

# Compile the Win32 helper once; avoid Add-Type redefinition in a loop.
$SCRIPT:WinApiType = $null
function Get-OfficeWindowClass {
    param([string]$AppName)
    if ($AppName -eq 'WINWORD') { return 'OpusApp' }
    if ($AppName -eq 'EXCEL')  { return 'XLMAIN' }
    return $null
}

function Measure-OfficeLaunch {
    $officeApps = @(
        @{ Path = Join-Path $env:ProgramFiles 'Microsoft Office\root\Office16\WINWORD.EXE'; Name = 'WINWORD' },
        @{ Path = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Office\root\Office16\WINWORD.EXE'; Name = 'WINWORD' },
        @{ Path = Join-Path $env:ProgramFiles 'Microsoft Office\root\Office16\EXCEL.EXE'; Name = 'EXCEL' },
        @{ Path = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Office\root\Office16\EXCEL.EXE'; Name = 'EXCEL' }
    )

    $appPath = $null
    $appName = $null
    foreach ($app in $officeApps) {
        if (Test-Path -LiteralPath $app.Path) {
            $appPath = $app.Path
            $appName = $app.Name
            break
        }
    }

    if (-not $appPath) {
        Write-Result "No Office application found (WINWORD or EXCEL)" 'WARN'
        return -1
    }

    if (-not $SCRIPT:WinApiType) {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class WinApi {
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
}
"@ -ErrorAction Stop
        $SCRIPT:WinApiType = [WinApi]
    }

    $proc = $null
    try {
        $proc = Start-Process -FilePath $appPath -PassThru
        $sw = [System.Diagnostics.Stopwatch]::StartNew()

        $deadline = (Get-Date).AddSeconds(30)
        $visible = $false
        $windowClass = Get-OfficeWindowClass -AppName $appName

        while ((Get-Date) -lt $deadline -and -not $visible) {
            Start-Sleep -Milliseconds 100

            try {
                $proc.Refresh()
                if ($proc.MainWindowHandle -ne 0) {
                    $visible = $true
                    break
                }
            }
            catch { }

            if ($windowClass) {
                $hwnd = $SCRIPT:WinApiType::FindWindow($windowClass, $null)
                if ($hwnd -ne 0) {
                    $visible = $true
                    break
                }
            }
        }

        $sw.Stop()

        if ($visible) {
            return [math]::Round($sw.Elapsed.TotalSeconds, 2)
        }
        Write-Result "Office window did not become visible within 30s" 'WARN'
        return -1
    }
    catch {
        Write-Result "Office launch failed: $($_.Exception.Message)" 'WARN'
        return -1
    }
    finally {
        if ($proc -and -not $proc.HasExited) {
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        }
        Get-Process -Name $appName -ErrorAction SilentlyContinue |
            Stop-Process -Force -ErrorAction SilentlyContinue
    }
}

function Get-Median {
    param([array]$Values)

    $sorted = $Values | Sort-Object
    $count = $sorted.Count
    if ($count -eq 0) { return 0.0 }
    if ($count % 2 -eq 1) {
        return [double]$sorted[[math]::Floor($count / 2)]
    }
    $mid = $count / 2
    return ([double]$sorted[$mid - 1] + [double]$sorted[$mid]) / 2.0
}

function Calculate-Overhead {
    param(
        [Parameter(Mandatory = $true)][double]$BaselineMedian,
        [Parameter(Mandatory = $true)][double]$HookedMedian
    )
    if ($BaselineMedian -eq 0) { return 0.0 }
    return [math]::Round((($HookedMedian - $BaselineMedian) / $BaselineMedian) * 100.0, 2)
}

function Wait-ForServiceState {
    param(
        [string]$DesiredState,
        [int]$TimeoutSeconds
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $svc = Get-Service -Name $SCRIPT:AgentServiceName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq $DesiredState) {
            return $true
        }
        Start-Sleep -Seconds 1
    }
    return $false
}

function Stop-AgentForBaseline {
    if ($BaselineMode -eq 'None') {
        Write-Host "`n[Baseline] BaselineMode=None -- leaving dlp-agent in current state" -ForegroundColor Yellow
        return
    }

    if ($BaselineMode -eq 'Manual') {
        Write-Host "`n[Baseline] MANUAL MODE: stop dlp-agent now (confirm any password challenge), then press ENTER." -ForegroundColor Yellow
        $null = Read-Host
        return
    }

    # StopService mode
    $svc = Get-Service -Name $SCRIPT:AgentServiceName -ErrorAction SilentlyContinue
    if (-not $svc -or $svc.Status -eq 'Stopped') {
        Write-Result "dlp-agent already stopped" 'INFO'
        return
    }

    Write-Host "`n[Baseline] Stopping dlp-agent for baseline measurements..." -ForegroundColor Yellow
    Write-Host "  NOTE: If a password challenge UI appears, confirm it so the service can stop." -ForegroundColor Yellow

    Stop-Service -Name $SCRIPT:AgentServiceName -Force -ErrorAction Stop

    if (Wait-ForServiceState -DesiredState 'Stopped' -TimeoutSeconds 120) {
        Write-Result "dlp-agent stopped" 'INFO'
    }
    else {
        throw "dlp-agent did not stop within 120 seconds. Aborting benchmark."
    }
}

function Start-AgentForHooked {
    if ($BaselineMode -eq 'None') {
        Write-Host "`n[Hooked] BaselineMode=None -- leaving dlp-agent in current state" -ForegroundColor Yellow
        return
    }

    $svc = Get-Service -Name $SCRIPT:AgentServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') {
        Write-Result "dlp-agent already running" 'INFO'
        return
    }

    Write-Host "`n[Hooked] Starting dlp-agent for hooked measurements..." -ForegroundColor Yellow
    Start-Service -Name $SCRIPT:AgentServiceName -ErrorAction Stop

    if (Wait-ForServiceState -DesiredState 'Running' -TimeoutSeconds 60) {
        Write-Result "dlp-agent running" 'INFO'
    }
    else {
        throw "dlp-agent did not start within 60 seconds. Aborting benchmark."
    }

    # Give hooks a moment to settle into newly-started processes.
    Start-Sleep -Seconds 3
}

function Format-Results {
    param([array]$Results)

    Write-Host "`n=== Benchmark Results ===" -ForegroundColor Cyan
    Write-Host "Workload          Baseline(s)  Hooked(s)   Overhead   Status" -ForegroundColor Cyan
    Write-Host "----------------------------------------------------------------" -ForegroundColor Cyan

    foreach ($r in $Results) {
        $statusColor = if ($r.Passed) { 'Green' } else { 'Red' }
        $statusText = if ($r.Passed) { 'PASS' } else { 'FAIL' }
        $line = "{0,-17} {1,11:F2} {2,11:F2} {3,9:F1}%   {4}" -f `
            $r.Workload, $r.BaselineMedian, $r.HookedMedian, $r.OverheadPercent, $statusText
        Write-Host $line -ForegroundColor $statusColor
    }
}

# ─── Main ────────────────────────────────────────────────────────────────────

Write-Host "=== DLP CRIT-04 Benchmark UAT ===" -ForegroundColor Cyan
Write-Host "Threshold: ${ThresholdPercent}% overhead" -ForegroundColor Cyan
Write-Host "Measured runs per workload: $Runs" -ForegroundColor Cyan
Write-Host "Baseline mode: $BaselineMode" -ForegroundColor Cyan
Write-Host "Cargo project: $CargoProjectDir" -ForegroundColor Cyan

$workloads = @('cargo')
if (-not $SkipOffice) {
    $workloads += 'office'
}

if (-not $SkipPreconditionCheck) {
    Write-Host "`n[Preconditions] Checking system state..." -ForegroundColor Yellow
    $preconditionsOk = Test-Preconditions
    if (-not $preconditionsOk) {
        Write-Result "One or more preconditions failed -- continuing with caution" 'WARN'
    }
}

if (-not (Test-RustAvailable)) {
    throw "cargo is required for the cargo build benchmark"
}

if (-not (Test-Path $ResultsDir)) {
    New-Item -ItemType Directory -Path $ResultsDir -Force | Out-Null
}

$allResults = @()
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$logFile = Join-Path $ResultsDir "uat-benchmark-${timestamp}.json"

$baselineMeasurements = @{}
$hookedMeasurements = @{}

# ── Warm-up build (populate isolated target dir, discarded, with retries) ─────
if ($workloads -contains 'cargo') {
    Invoke-CargoBuildWarmup -MaxAttempts 3
}

# ── Office warm-up (discarded) ───────────────────────────────────────────────
if ($workloads -contains 'office') {
    Write-Host "`n[Warm-up] Discarded Office launch..." -ForegroundColor Yellow
    $null = Measure-OfficeLaunch
}

# ── Baseline measurements (agent STOPPED or manual) ──────────────────────────
Stop-AgentForBaseline

foreach ($workload in $workloads) {
    Write-Host "`n[Baseline] $workload ($Runs measured runs)..." -ForegroundColor Yellow
    $times = @()
    for ($i = 1; $i -le $Runs; $i++) {
        Write-Host "  Run $i/$Runs..." -ForegroundColor Cyan
        $elapsed = switch ($workload) {
            'cargo'  { Measure-CargoBuild }
            'office' { Measure-OfficeLaunch }
            default  { -1 }
        }
        if ($elapsed -ge 0) {
            $times += $elapsed
            Write-Result "Run $i`: ${elapsed}s" 'INFO'
        }
        else {
            Write-Result "Run $i`: failed" 'WARN'
        }
    }
    $baselineMeasurements[$workload] = $times
}

# ── Hooked measurements (agent RUNNING) ──────────────────────────────────────
Start-AgentForHooked

foreach ($workload in $workloads) {
    Write-Host "`n[Hooked] $workload ($Runs measured runs)..." -ForegroundColor Yellow
    $times = @()
    for ($i = 1; $i -le $Runs; $i++) {
        Write-Host "  Run $i/$Runs..." -ForegroundColor Cyan
        $elapsed = switch ($workload) {
            'cargo'  { Measure-CargoBuild }
            'office' { Measure-OfficeLaunch }
            default  { -1 }
        }
        if ($elapsed -ge 0) {
            $times += $elapsed
            Write-Result "Run $i`: ${elapsed}s" 'INFO'
        }
        else {
            Write-Result "Run $i`: failed" 'WARN'
        }
    }
    $hookedMeasurements[$workload] = $times
}

# ── Calculate results ────────────────────────────────────────────────────────
foreach ($workload in $workloads) {
    $baselineTimes = $baselineMeasurements[$workload]
    $hookedTimes = $hookedMeasurements[$workload]

    if ($baselineTimes.Count -eq 0 -or $hookedTimes.Count -eq 0) {
        Write-Result "$workload`: insufficient data" 'WARN'
        $allResults += [PSCustomObject]@{
            Workload        = $workload
            BaselineMedian  = 0.0
            HookedMedian    = 0.0
            OverheadPercent = 0.0
            Passed          = $false
        }
        continue
    }

    $baselineMedian = Get-Median -Values $baselineTimes
    $hookedMedian = Get-Median -Values $hookedTimes
    $overhead = Calculate-Overhead -BaselineMedian $baselineMedian -HookedMedian $hookedMedian
    $passed = $overhead -le $ThresholdPercent

    $allResults += [PSCustomObject]@{
        Workload        = $workload
        BaselineMedian  = $baselineMedian
        HookedMedian    = $hookedMedian
        OverheadPercent = $overhead
        Passed          = $passed
    }
}

# ── Display results ──────────────────────────────────────────────────────────
Format-Results -Results $allResults

# ── Save JSON ────────────────────────────────────────────────────────────────

# Clean up the dedicated target dir after measurements are done.
Remove-CargoTargetDir

$jsonOutput = @{
    timestamp         = (Get-Date).ToUniversalTime().ToString('o')
    threshold_percent = $ThresholdPercent
    runs              = $Runs
    baseline_mode     = $BaselineMode
    workloads         = $workloads
    baseline          = $baselineMeasurements
    hooked            = $hookedMeasurements
    results           = $allResults
} | ConvertTo-Json -Depth 10

[System.IO.File]::WriteAllText($logFile, $jsonOutput)
Write-Result "Results saved to $logFile" 'INFO'

# ── Summary ──────────────────────────────────────────────────────────────────
$totalPass = ($allResults | Where-Object { $_.Passed }).Count
$totalFail = ($allResults | Where-Object { -not $_.Passed }).Count

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Result "Total PASS: $totalPass" 'PASS'
Write-Result "Total FAIL: $totalFail" 'FAIL'

if ($totalFail -gt 0) {
    exit 1
}
exit 0
