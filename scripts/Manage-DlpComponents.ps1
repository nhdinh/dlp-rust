#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Unified management script for all DLP components.

.DESCRIPTION
    Starts, stops, or reports the status of dlp-server (process) and
    dlp-agent (Windows Service).  dlp-server runs as a regular foreground
    process; dlp-agent runs as a Windows Service under LocalSystem.

    -Action Start  : Start components in safe order (server first, then agent)
    -Action Stop   : Stop components in safe order (agent first, then server)
    -Action Status  : Show running state of both components

    Requires local administrator privileges (service operations need elevation).

.EXAMPLE
    .\Manage-DlpComponents.ps1 -Action Start -Component Both

    Starts dlp-server, waits for it to be ready, then starts dlp-agent.

.EXAMPLE
    .\Manage-DlpComponents.ps1 -Action Status -Component Both

    Shows whether dlp-server process and dlp-agent service are running.
#>

[CmdletBinding()]
param(
    [ValidateSet('Start', 'Stop', 'Status')]
    [Parameter(Mandatory = $true)]
    [string]$Action,

    [ValidateSet('Server', 'Agent', 'Both')]
    [Parameter(Mandatory = $true)]
    [string]$Component,

    # How many seconds to wait for dlp-server to appear as running.
    [int]$ServerStartTimeoutSeconds = 30,

    # How many seconds to wait for dlp-server to disappear after stop.
    [int]$ServerStopTimeoutSeconds = 15
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ─── Paths ────────────────────────────────────────────────────────────────────

$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot    = (Resolve-Path "$ScriptDir\..").Path
$ServerBin   = "$RepoRoot\target\release\dlp-server.exe"
$AgentSvcName = 'dlp-agent'

# ─── Helpers ────────────────────────────────────────────────────────────────────

function Write-Status {
    param([string]$Message, [string]$Level = 'OK')
    switch ($Level) {
        'OK'   { Write-Host "[OK]   $Message" -ForegroundColor Green  }
        'INFO' { Write-Host "[INFO] $Message" -ForegroundColor Cyan   }
        'WARN' { Write-Host "[WARN] $Message" -ForegroundColor Yellow }
        'FAIL' { Write-Host "[FAIL] $Message" -ForegroundColor Red    }
    }
}

# Returns $true if the dlp-server process is running.
function Test-ServerRunning {
    $proc = Get-Process -Name 'dlp-server' -ErrorAction SilentlyContinue
    return ($null -ne $proc)
}

# Returns $true if the dlp-agent service is running.
function Test-AgentRunning {
    $svc = Get-Service -Name $AgentSvcName -ErrorAction SilentlyContinue
    return ($svc -and $svc.Status -eq 'Running')
}

# Returns the process object if running, else $null.
function Get-ServerProcess {
    Get-Process -Name 'dlp-server' -ErrorAction SilentlyContinue
}

# ─── Start ─────────────────────────────────────────────────────────────────────

function Start-Server {
    if (Test-ServerRunning) {
        Write-Status "dlp-server is already running (PID $((Get-ServerProcess).Id))." -Level INFO
        return
    }
    if (-not (Test-Path $ServerBin -PathType Leaf)) {
        Write-Status "dlp-server binary not found: $ServerBin" -Level FAIL
        Write-Status 'Build with: cargo build --release -p dlp-server' -Level INFO
        throw "Server binary not found"
    }
    Write-Status "Starting dlp-server (binary: $ServerBin)..."
    # Start-Process returns immediately; use -PassThru to capture the handle.
    $proc = Start-Process $ServerBin -PassThru
    Write-Status "dlp-server started (PID $($proc.Id))."

    # Wait for the process to settle (listening on port).
    $deadline = (Get-Date).AddSeconds($ServerStartTimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if ((Test-ServerRunning) -and $proc.HasExited -eq $false) {
            Write-Status "dlp-server is ready." -Level OK
            return
        }
        if ($proc.HasExited) {
            Write-Status "dlp-server exited unexpectedly (exit code: $($proc.ExitCode))." -Level FAIL
            throw "Server process died during startup."
        }
        Start-Sleep -Milliseconds 200
    }
    Write-Status "dlp-server did not become ready within ${ServerStartTimeoutSeconds}s." -Level WARN
}

function Start-Agent {
    $svc = Get-Service -Name $AgentSvcName -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Status "dlp-agent service is not registered. Run Manage-DlpAgentService.ps1 -Action Install first." -Level FAIL
        throw "Agent service not registered."
    }
    if ($svc.Status -eq 'Running') {
        Write-Status "dlp-agent service is already running." -Level INFO
        return
    }
    Write-Status "Starting dlp-agent service..."
    Start-Service -Name $AgentSvcName -ErrorAction Stop
    Write-Status "dlp-agent service started." -Level OK
}

# ─── Stop ──────────────────────────────────────────────────────────────────────

function Stop-Agent {
    $svc = Get-Service -Name $AgentSvcName -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Status "dlp-agent service not registered — nothing to stop." -Level INFO
        return
    }
    if ($svc.Status -eq 'Stopped') {
        Write-Status "dlp-agent service is already stopped." -Level INFO
        return
    }
    Write-Status "Stopping dlp-agent service (password challenge may add delay)..."
    Stop-Service -Name $AgentSvcName -Force -ErrorAction Stop
    $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(120))
    Write-Status "dlp-agent service stopped." -Level OK
}

function Stop-Server {
    if (-not (Test-ServerRunning)) {
        Write-Status "dlp-server is not running." -Level INFO
        return
    }
    $proc = Get-ServerProcess
    Write-Status "Stopping dlp-server (PID $($proc.Id))..."
    Stop-Process -Id $proc.Id -Force -ErrorAction Stop

    $deadline = (Get-Date).AddSeconds($ServerStopTimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (-not (Test-ServerRunning)) {
            Write-Status "dlp-server stopped." -Level OK
            return
        }
        Start-Sleep -Milliseconds 200
    }
    Write-Status "dlp-server still running after ${ServerStopTimeoutSeconds}s — forcefully killed." -Level WARN
}

# ─── Status ────────────────────────────────────────────────────────────────────

function Show-ServerStatus {
    if (Test-ServerRunning) {
        $proc = Get-ServerProcess
        Write-Status "dlp-server: Running (PID $($proc.Id), started $( $proc.StartTime.ToString('yyyy-MM-dd HH:mm:ss') )" -Level OK
    } else {
        Write-Status "dlp-server: Stopped / not running" -Level WARN
    }
}

function Show-AgentStatus {
    $svc = Get-Service -Name $AgentSvcName -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Status "dlp-agent: Not registered" -Level WARN
        return
    }
    if ($svc.Status -eq 'Running') {
        Write-Status "dlp-agent: Running (service)" -Level OK
    } else {
        Write-Status "dlp-agent: $($svc.Status) (service)" -Level WARN
    }
}

# ─── Main ─────────────────────────────────────────────────────────────────────

Write-Status "DLP Component Manager" -Level INFO
Write-Status "Action    : $Action"
Write-Status "Component: $Component"
Write-Host ""

switch ($Action) {
    'Start' {
        if ($Component -in @('Server', 'Both')) {
            Start-Server
        }
        if ($Component -in @('Agent', 'Both')) {
            Start-Agent
        }
    }
    'Stop' {
        # Stop in reverse order: agent first (depends on server), then server.
        if ($Component -in @('Agent', 'Both')) {
            Stop-Agent
        }
        if ($Component -in @('Server', 'Both')) {
            Stop-Server
        }
    }
    'Status' {
        if ($Component -in @('Server', 'Both')) {
            Show-ServerStatus
        }
        if ($Component -in @('Agent', 'Both')) {
            Show-AgentStatus
        }
    }
}

Write-Status "Done." -Level INFO
