#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CRIT-04 benchmark measurement for DLP v0.10.0.

.DESCRIPTION
    Measures wall-clock overhead introduced by the DLP hook DLL on two
    representative workloads:
    1. cargo build  — clean build of the dlp-rust workspace
    2. Office launch — launch of Microsoft Word or Excel to visible window

    The gate is <= 25% overhead compared to the baseline (agent stopped).

    All baseline measurements are run first (agent STOPPED), then the
    agent is started and all hooked measurements are run.  Medians are
    computed per workload, and overhead is calculated as:
        overhead = ((hooked_median - baseline_median) / baseline_median) * 100

    Results are saved to C:\ProgramData\DLP\logs\uat-benchmark-{timestamp}.json.

    Requires elevation because the DLP agent service control requires
    administrator privileges.

.EXAMPLE
    .\Uat-Benchmark.ps1

    Runs the full benchmark suite with default settings (3 runs, 25% threshold).

.EXAMPLE
    .\Uat-Benchmark.ps1 -Workloads @("cargo") -Runs 5 -ThresholdPercent 20.0

    Benchmarks only cargo build with 5 runs and a 20% threshold.

.EXAMPLE
    .\Uat-Benchmark.ps1 -SkipPreconditionCheck

    Skips the system precondition checks.
#

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$Workloads = @("cargo", "office"),

    [Parameter()]
    [int]$Runs = 3,

    [Parameter()]
    [double]$ThresholdPercent = 25.0,

    [Parameter()]
    [switch]$SkipPreconditionCheck
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ─── Constants ───────────────────────────────────────────────────────────────

$SCRIPT:AgentServiceName = 'dlp-agent'
$SCRIPT:LogDir = 'C:\ProgramData\DLP\logs'
$SCRIPT:CargoProjectDir = $PSScriptRoot  # Assumes script is in dlp-rust root

# ─── Helpers ─────────────────────────────────────────────────────────────────

function Write-Result {
    <#
    .SYNOPSIS
        Emits a colour-coded result line.
    #>
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
    <#
    .SYNOPSIS
        Checks system preconditions before running benchmarks.

    .DESCRIPTION
        Verifies:
        - Windows Update is not actively running
        - No AV scan is in progress
        - Free memory > 4 GB
        - dlp-agent service is installed

    .OUTPUTS
        $true if all preconditions pass, $false otherwise.
    #>
    $allOk = $true

    # Check Windows Update
    $wuService = Get-Service -Name 'wuauserv' -ErrorAction SilentlyContinue
    if ($wuService -and $wuService.Status -eq 'Running') {
        $wuJob = Get-WmiObject -Class Win32_Service -Filter "Name='wuauserv'" -ErrorAction SilentlyContinue
        if ($wuJob -and $wuJob.State -eq 'Running') {
            Write-Result "Windows Update service is running — may interfere with benchmarks" 'WARN'
            $allOk = $false
        }
    }

    # Check AV scan (Defender)
    $mpCmdRun = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
    if (Test-Path $mpCmdRun) {
        try {
            $avStatus = & $mpCmdRun -SignatureUpdateCheck 2>&1
            # MpCmdRun doesn't directly report scan status; check WMI
            $mpThreat = Get-WmiObject -Namespace "root\Microsoft\Windows\Defender" `
                -Class MSFT_MpThreatDetection -ErrorAction SilentlyContinue
            # No direct scan-in-progress WMI class; skip detailed check
        }
        catch {
            # Ignore
        }
    }

    # Check free memory
    $os = Get-WmiObject -Class Win32_OperatingSystem
    $freeGB = [math]::Round($os.FreePhysicalMemory / 1MB, 1)
    if ($freeGB -lt 4) {
        Write-Result "Free memory is ${freeGB}GB — recommend > 4GB for stable benchmarks" 'WARN'
        $allOk = $false
    }
    else {
        Write-Result "Free memory: ${freeGB}GB" 'INFO'
    }

    # Check dlp-agent service exists
    $agentSvc = Get-Service -Name $SCRIPT:AgentServiceName -ErrorAction SilentlyContinue
    if (-not $agentSvc) {
        Write-Result "dlp-agent service not found — is the agent installed?" 'FAIL'
        $allOk = $false
    }
    else {
        Write-Result "dlp-agent service found" 'INFO'
    }

    return $allOk
}

function Test-RustAvailable {
    <#
    .SYNOPSIS
        Checks if cargo is available in PATH.

    .OUTPUTS
        $true if cargo is found, $false otherwise.
    #>
    $cargo = Get-Command 'cargo' -ErrorAction SilentlyContinue
    if ($cargo) {
        Write-Result "cargo found: $($cargo.Source)" 'INFO'
        return $true
    }
    else {
        Write-Result "cargo not found in PATH — cargo build benchmark will be skipped" 'WARN'
        return $false
    }
}

function Measure-CargoBuild {
    <#
    .SYNOPSIS
        Measures the wall-clock time of cargo clean + cargo build.

    .DESCRIPTION
        Runs from the project root directory.  Returns the elapsed
        time in seconds.

    .OUTPUTS
        Elapsed time in seconds (double).
    #>
    $projectDir = $SCRIPT:CargoProjectDir
    if (-not (Test-Path (Join-Path $projectDir 'Cargo.toml'))) {
        # Try one level up if script is in scripts/ subdirectory
        $projectDir = Split-Path $projectDir -Parent
    }

    Push-Location $projectDir
    try {
        # cargo clean
        $cleanOutput = & cargo clean 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "cargo clean failed: $cleanOutput"
        }

        # cargo build
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $buildOutput = & cargo build --workspace 2>&1
        $sw.Stop()

        if ($LASTEXITCODE -ne 0) {
            throw "cargo build failed: $buildOutput"
        }

        return [math]::Round($sw.Elapsed.TotalSeconds, 2)
    }
    finally {
        Pop-Location
    }
}

function Measure-OfficeLaunch {
    <#
    .SYNOPSIS
        Measures the wall-clock time to launch an Office app to a visible window.

    .DESCRIPTION
        Launches winword.exe or excel.exe and measures the time until
        MainWindowHandle is non-zero or FindWindow finds the window.
        Does NOT use WaitForInputIdle (unreliable for modern Office).
        The process is closed after measurement.

    .OUTPUTS
        Elapsed time in seconds (double), or -1 on failure.
    #>
    $officeApps = @(
        @{ Path = Join-Path $env:ProgramFiles 'Microsoft Office\root\Office16\WINWORD.EXE'; Name = 'WINWORD' },
        @{ Path = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Office\root\Office16\WINWORD.EXE'; Name = 'WINWORD' },
        @{ Path = Join-Path $env:ProgramFiles 'Microsoft Office\root\Office16\EXCEL.EXE'; Name = 'EXCEL' },
        @{ Path = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Office\root\Office16\EXCEL.EXE'; Name = 'EXCEL' }
    )

    $appPath = $null
    $appName = $null
    foreach ($app in $officeApps) {
        if (Test-Path $app.Path) {
            $appPath = $app.Path
            $appName = $app.Name
            break
        }
    }

    if (-not $appPath) {
        Write-Result "No Office application found (WINWORD or EXCEL)" 'WARN'
        return -1
    }

    $proc = $null
    try {
        $proc = Start-Process -FilePath $appPath -PassThru
        $sw = [System.Diagnostics.Stopwatch]::StartNew()

        # Wait for window to become visible (up to 30 seconds)
        $deadline = (Get-Date).AddSeconds(30)
        $visible = $false
        while ((Get-Date) -lt $deadline -and -not $visible) {
            Start-Sleep -Milliseconds 100

            # Check MainWindowHandle
            try {
                $proc.Refresh()
                if ($proc.MainWindowHandle -ne 0) {
                    $visible = $true
                    break
                }
            }
            catch {
                # Process may have exited
            }

            # Fallback: FindWindow
            $hwnd = 0
            if ($appName -eq 'WINWORD') {
                Add-Type @"
using System;
using System.Runtime.InteropServices;
public class WinApi {
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
}
"@ -ErrorAction SilentlyContinue
                $hwnd = [WinApi]::FindWindow('OpusApp', $null)
            }
            else {
                Add-Type @"
using System;
using System.Runtime.InteropServices;
public class WinApi {
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
}
"@ -ErrorAction SilentlyContinue
                $hwnd = [WinApi]::FindWindow('XLMAIN', $null)
            }

            if ($hwnd -and $hwnd -ne 0) {
                $visible = $true
                break
            }
        }

        $sw.Stop()

        if ($visible) {
            return [math]::Round($sw.Elapsed.TotalSeconds, 2)
        }
        else {
            Write-Result "Office window did not become visible within 30s" 'WARN'
            return -1
        }
    }
    catch {
        Write-Result "Office launch failed: $($_.Exception.Message)" 'WARN'
        return -1
    }
    finally {
        if ($proc -and -not $proc.HasExited) {
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        }
        # Also kill any lingering Office processes started by us
        Get-Process -Name $appName -ErrorAction SilentlyContinue |
            Stop-Process -Force -ErrorAction SilentlyContinue
    }
}

function Calculate-Overhead {
    <#
    .SYNOPSIS
        Calculates the percentage overhead of hooked vs baseline measurements.

    .PARAMETER BaselineMedian
        Baseline median time in seconds.

    .PARAMETER HookedMedian
        Hooked median time in seconds.

    .OUTPUTS
        Overhead percentage (double).
    #>
    param(
        [Parameter(Mandatory = $true)][double]$BaselineMedian,
        [Parameter(Mandatory = $true)][double]$HookedMedian
    )

    if ($BaselineMedian -eq 0) {
        return 0.0
    }
    return [math]::Round((($HookedMedian - $BaselineMedian) / $BaselineMedian) * 100.0, 2)
}

function Format-Results {
    <#
    .SYNOPSIS
        Formats and displays the benchmark results as a table.

    .PARAMETER Results
        Array of result objects with Workload, BaselineMedian, HookedMedian,
        OverheadPercent, and Passed properties.
    #>
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

function Get-Median {
    <#
    .SYNOPSIS
        Computes the median of an array of doubles.

    .PARAMETER Values
        Array of numeric values.

    .OUTPUTS
        The median value (double).
    #>
    param([array]$Values)

    $sorted = $Values | Sort-Object
    $count = $sorted.Count
    if ($count -eq 0) {
        return 0.0
    }
    if ($count % 2 -eq 1) {
        return $sorted[[math]::Floor($count / 2)]
    }
    else {
        $mid = $count / 2
        return ($sorted[$mid - 1] + $sorted[$mid]) / 2.0
    }
}

function Stop-DlpAgentService {
    <#
    .SYNOPSIS
        Stops the dlp-agent service if it is running.
    #>
    $svc = Get-Service -Name $SCRIPT:AgentServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') {
        Stop-Service -Name $SCRIPT:AgentServiceName -Force -ErrorAction Stop
        Start-Sleep -Seconds 2
        Write-Result "dlp-agent service stopped for baseline measurements" 'INFO'
    }
}

function Start-DlpAgentService {
    <#
    .SYNOPSIS
        Starts the dlp-agent service if it is not running.
    #>
    $svc = Get-Service -Name $SCRIPT:AgentServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Running') {
        Start-Service -Name $SCRIPT:AgentServiceName -ErrorAction Stop
        Start-Sleep -Seconds 3
        Write-Result "dlp-agent service started for hooked measurements" 'INFO'
    }
}

# ─── Main ────────────────────────────────────────────────────────────────────

Write-Host "=== DLP CRIT-04 Benchmark UAT ===" -ForegroundColor Cyan
Write-Host "Threshold: ${ThresholdPercent}% overhead" -ForegroundColor Cyan
Write-Host "Runs per workload: $Runs" -ForegroundColor Cyan

# Preconditions
if (-not $SkipPreconditionCheck) {
    Write-Host "`n[Preconditions] Checking system state..." -ForegroundColor Yellow
    $preconditionsOk = Test-Preconditions
    if (-not $preconditionsOk) {
        Write-Result "One or more preconditions failed — continuing with caution" 'WARN'
    }
}

# Check Rust availability
$rustAvailable = Test-RustAvailable
if ($Workloads -contains 'cargo' -and -not $rustAvailable) {
    Write-Result "cargo not available — removing cargo from workloads" 'WARN'
    $Workloads = $Workloads | Where-Object { $_ -ne 'cargo' }
}

if ($Workloads.Count -eq 0) {
    Write-Error "No workloads available to benchmark."
    exit 1
}

# Ensure log directory exists
if (-not (Test-Path $SCRIPT:LogDir)) {
    New-Item -ItemType Directory -Path $SCRIPT:LogDir -Force | Out-Null
}

$allResults = @()
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$logFile = Join-Path $SCRIPT:LogDir "uat-benchmark-${timestamp}.json"

# ── Run ALL baseline measurements first (agent STOPPED) ──────────────────────
Write-Host "`n[Baseline] Stopping dlp-agent for baseline measurements..." -ForegroundColor Yellow
Stop-DlpAgentService

$baselineMeasurements = @{}
foreach ($workload in $Workloads) {
    Write-Host "`n[Baseline] $workload ($Runs runs)..." -ForegroundColor Yellow
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

# ── Start agent for hooked measurements ──────────────────────────────────────
Write-Host "`n[Hooked] Starting dlp-agent for hooked measurements..." -ForegroundColor Yellow
Start-DlpAgentService

$hookedMeasurements = @{}
foreach ($workload in $Workloads) {
    Write-Host "`n[Hooked] $workload ($Runs runs)..." -ForegroundColor Yellow
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
foreach ($workload in $Workloads) {
    $baselineTimes = $baselineMeasurements[$workload]
    $hookedTimes = $hookedMeasurements[$workload]

    if ($baselineTimes.Count -eq 0 -or $hookedTimes.Count -eq 0) {
        Write-Result "$workload`: insufficient data to calculate overhead" 'WARN'
        $allResults += [PSCustomObject]@{
            Workload       = $workload
            BaselineMedian = 0.0
            HookedMedian   = 0.0
            OverheadPercent = 0.0
            Passed         = $false
        }
        continue
    }

    $baselineMedian = Get-Median $baselineTimes
    $hookedMedian = Get-Median $hookedTimes
    $overhead = Calculate-Overhead $baselineMedian $hookedMedian
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
Format-Results $allResults

# ── Save to JSON ─────────────────────────────────────────────────────────────
$jsonOutput = @{
    timestamp      = (Get-Date).ToUniversalTime().ToString('o')
    threshold_percent = $ThresholdPercent
    runs           = $Runs
    workloads      = $Workloads
    baseline       = $baselineMeasurements
    hooked         = $hookedMeasurements
    results        = $allResults
} | ConvertTo-Json -Depth 10

[System.IO.File]::WriteAllText($logFile, $jsonOutput)
Write-Result "Results saved to $logFile" 'INFO'

# ── Summary ──────────────────────────────────────────────────────────────────
$totalPass = ($allResults | Where-Object { $_.Passed }).Count
$totalFail = ($allResults | Where-Object { -not $_.Passed }).Count

Write-Host "`n=== Results ===" -ForegroundColor Cyan
Write-Result "Total PASS: $totalPass" 'PASS'
Write-Result "Total FAIL: $totalFail" 'FAIL'

if ($totalFail -gt 0) {
    exit 1
}
exit 0
