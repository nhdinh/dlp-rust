#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Manages the DLP Agent Windows Service.

.DESCRIPTION
    Registers, starts, stops, restarts, and queries the DLP Agent Windows
    Service.  The service runs under the LocalSystem (SYSTEM) account as
    required by the DLP architecture (SRS F-ADM-01).

    All operations that modify the service require local administrator
    privileges.  Running the script without elevation will exit early.

.EXAMPLE
    .\Manage-DlpAgentService.ps1 -Action Install

    Registers the service with the SCM and starts it immediately.

.EXAMPLE
    .\Manage-DlpAgentService.ps1 -Action Stop

    Stops the service (triggers the dlp-admin password challenge).

.EXAMPLE
    .\Manage-DlpAgentService.ps1 -Action Status

    Prints current service state without making changes.
#>

[CmdletBinding()]
param(
    [ValidateSet('Install', 'Uninstall', 'Register', 'Unregister', 'Start', 'Stop', 'Restart', 'Status')]
    [Parameter(Mandatory = $true)]
    [string]$Action,

    [Parameter()]
    # [string]$BinaryPath = "$env:ProgramFiles\DLP\dlp-agent.exe",
    [string]$BinaryPath = "$PSScriptRoot\..\target\debug\dlp-agent.exe",

    [Parameter()]
    [string]$ServiceName = 'dlp-agent',

    [Parameter()]
    [string]$DisplayName = 'DLP Agent',

    # DLP Server URL for agent-to-server communication.
    # Written to agent-config.toml on Install so the service can reach the server.
    [Parameter()]
    [string]$ServerUrl,

    # How long (seconds) to wait for the service to fully start after a Start.
    [int]$StartTimeoutSeconds = 30,

    # How long (seconds) to wait for the service to stop cleanly.
    # The password challenge adds up to 3 x 30 s of delay.
    [int]$StopTimeoutSeconds = 120
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ─── Helpers ─────────────────────────────────────────────────────────────────

function Write-Status {
    param([string]$Message, [string]$Level = 'OK')
    switch ($Level) {
        'OK' { Write-Host "[OK]   $Message" -ForegroundColor Green }
        'INFO' { Write-Host "[INFO] $Message" -ForegroundColor Cyan }
        'WARN' { Write-Host "[WARN] $Message" -ForegroundColor Yellow }
        'FAIL' { Write-Host "[FAIL] $Message" -ForegroundColor Red }
    }
}

function Purge-Log {
    <# Deletes all files in the log directory. #>
    if (Test-Path $LogDir) {
        Get-ChildItem -Path $LogDir -File | Remove-Item -Force
        Write-Status "Purged log directory: $LogDir" -Level INFO
    }
}

function Get-CurrentService {
    <# Returns a ServiceController or $null if not installed. #>
    Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
}

function Test-BinaryExists {
    if (-not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) {
        Write-Status "Binary not found: $BinaryPath" -Level FAIL
        Write-Status "Build the agent with: cargo build --release -p dlp-agent" -Level INFO
        return $false
    }
    return $true
}

function Wait-ForServiceState {
    param(
        [string]$DesiredState,   # 'Running' or 'Stopped'
        [int]$TimeoutSeconds
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $svc = Get-CurrentService
        if (-not $svc) {
            if ($DesiredState -eq 'Stopped') {
                Write-Status "Service removed" -Level INFO
                return $true
            }
        }
        elseif ($svc.Status -eq $DesiredState) {
            Write-Status "Service is $DesiredState" -Level INFO
            return $true
        }
        Start-Sleep -Seconds 2
    }
    Write-Status "Timeout waiting for service to reach $DesiredState (waited ${TimeoutSeconds}s)" -Level WARN
    return $false
}

# ─── Agent config file ────────────────────────────────────────────────────────

$ConfigDir = "$env:ProgramData\DLP"
$ConfigFile = "$ConfigDir\agent-config.toml"
$LogDir = "$ConfigDir\logs"

function Write-AgentConfig {
    <# Writes or updates agent-config.toml with the server URL. #>
    if (-not $ServerUrl) { return }

    if (-not (Test-Path $ConfigDir)) {
        New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
        Write-Status "Created config directory: $ConfigDir" -Level INFO
    }

    # Read existing config or start fresh.
    $content = if (Test-Path $ConfigFile) { Get-Content $ConfigFile -Raw } else { '' }

    # Normalise the URL so it always has a scheme — `from_env_with_config`
    # accepts bare hostnames (`127.0.0.1:9090`) but adding http:// explicitly
    # avoids any ambiguity and matches DEFAULT_SERVER_URL format.
    $url = if ($ServerUrl -match '^https?://') { $ServerUrl } else { "http://$ServerUrl" }

    # Update or add server_url line.
    if ($content -match '(?m)^server_url\s*=') {
        $content = $content -replace "(?m)^server_url\s*=.*$", "server_url = '$url'"
    }
    else {
        $content = "server_url = '$url'`n$content"
    }

    # Use UTF8 without BOM — the toml crate cannot parse a BOM prefix.
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($ConfigFile, $content.TrimEnd() + "`n", $utf8NoBom)
    Write-Status "Agent config written: $ConfigFile (server_url = $ServerUrl)" -Level OK
}

# ─── sc.exe wrapper helpers ────────────────────────────────────────────────────

# sc.exe create is idempotent in the sense that it fails if the service exists.
# We always delete first in Install/Register flows to make the script re-runnable.
function Remove-ServiceIfExists {
    $svc = Get-CurrentService
    if ($svc) {
        Write-Status "Removing existing service '$ServiceName'..." -Level INFO
        $null = & sc.exe delete $ServiceName 2>&1
        Start-Sleep -Seconds 2   # SCM needs a moment to clean up
    }
}

function New-DlpAgentService {
    <# Registers the service with the SCM running as LocalSystem. #>
    # Always quote the binPath — paths with spaces are common.
    $quotedPath = "`"$BinaryPath`""

    Write-Status "Registering service '$ServiceName' with SCM (obj=LocalSystem)..." -Level INFO
    $createOut = & sc.exe create $ServiceName binPath= $quotedPath DisplayName= $DisplayName obj= LocalSystem type= own start= auto error= normal 2>&1

    if ($LASTEXITCODE -ne 0) {
        Write-Status "sc.exe create failed: $createOut" -Level FAIL
        throw "sc.exe create exited $LASTEXITCODE"
    }
    Write-Status "Service registered." -Level INFO

    # Configure recovery actions so the service recovers from crashes without
    # manual intervention (F-ADM-01 requirement).
    # reset=86400 (1 day) — reset failure counter after 1 day of uptime.
    # actions=restart/60000/restart/60000/run/60000
    #   First crash  → restart after 60 s
    #   Second crash → restart after 60 s
    #   Third crash  → run a program (none configured — leave as placeholder)
    Write-Status "Configuring crash-recovery actions..." -Level INFO
    $null = & sc.exe failure $ServiceName reset= 86400 actions= "restart/60000/restart/60000/run/60000" 2>&1

    if ($LASTEXITCODE -ne 0) {
        Write-Warning "sc.exe failure configuration failed (exit $LASTEXITCODE) — non-fatal"
    }
    else {
        Write-Status "Crash-recovery actions configured." -Level INFO
    }
}

function Start-DlpAgentService {
    $svc = Get-CurrentService
    if (-not $svc) {
        Write-Status "Service '$ServiceName' is not installed." -Level FAIL
        return
    }
    if ($svc.Status -eq 'Running') {
        Write-Status "Service is already running (PID $($svc.ServiceName))." -Level INFO
        return
    }

    # delete log before starting so it's fresh for the new session — avoids confusion from old logs and ensures we have write permissions to the log dir before starting the service.
    Purge-Log

    Write-Status "Starting service '$ServiceName'..." -Level INFO
    $null = Start-Service -Name $ServiceName -ErrorAction Stop

    if (-not (Wait-ForServiceState -DesiredState 'Running' -TimeoutSeconds $StartTimeoutSeconds)) {
        Write-Status "Service did not reach Running state in ${StartTimeoutSeconds}s." -Level WARN
    }
}

function Stop-DlpAgentService {
    $svc = Get-CurrentService
    if (-not $svc) {
        Write-Status "Service '$ServiceName' is not installed." -Level INFO
        return
    }
    if ($svc.Status -eq 'Stopped') {
        Write-Status "Service is already stopped." -Level INFO
        return
    }

    Write-Status "Stopping service '$ServiceName' (password challenge may add delay)..." -Level INFO
    Write-Status "The dlp-admin must confirm the stop in the UI dialog (up to 3 attempts, 30 s each)." -Level INFO

    $null = Stop-Service -Name $ServiceName -Force -ErrorAction Stop

    if (-not (Wait-ForServiceState -DesiredState 'Stopped' -TimeoutSeconds $StopTimeoutSeconds)) {
        Write-Status "Service did not stop cleanly in ${StopTimeoutSeconds}s." -Level WARN
        Write-Status "The service may still be waiting for the dlp-admin password dialog." -Level WARN
        Write-Status "To force-terminate: sc.exe stop $ServiceName && sc.exe delete $ServiceName" -Level INFO
    }
}

function Remove-DlpAgentService {
    $svc = Get-CurrentService
    if (-not $svc) {
        Write-Status "Service '$ServiceName' is not installed." -Level INFO
        return
    }

    if ($svc.Status -ne 'Stopped') {
        Write-Status "Service is still running — stopping first..." -Level INFO
        Stop-DlpAgentService
    }

    Write-Status "Deleting service '$ServiceName' from SCM..." -Level INFO
    $null = & sc.exe delete $ServiceName 2>&1

    if ($LASTEXITCODE -ne 0) {
        Write-Status "sc.exe delete failed (exit $LASTEXITCODE)" -Level FAIL
    }
    else {
        Write-Status "Service unregistered and deleted." -Level INFO
    }
}

function Get-DlpAgentServiceStatus {
    $svc = Get-CurrentService
    if (-not $svc) {
        Write-Status "Service '$ServiceName' is NOT installed." -Level WARN
        Write-Status "Run with -Action Install to register it." -Level INFO
        return
    }

    Write-Host ""
    Write-Host "Service Name    : $($svc.ServiceName)"
    Write-Host "Display Name    : $($svc.DisplayName)"
    Write-Host "Status         : $($svc.Status)"
    Write-Host "Start Type     : $($svc.StartType)"
    Write-Host "Can Pause/Stop : $($svc.CanPauseAndContinue)"

    # Query crash/recovery configuration
    $failureOut = & sc.exe qfailure $ServiceName 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "--- Crash Recovery Configuration ---"
        foreach ($line in $failureOut) {
            if ($line -match 'RESET_PERIOD|FAILURE_ACTIONS|FAILURE_COMMAND') {
                Write-Host "  $line"
            }
        }
    }

    Write-Host ""
    Write-Host "Binary Path    : $BinaryPath"
    Write-Host ""
}

# ─── Main ─────────────────────────────────────────────────────────────────────

Write-Status "DLP Agent Service Management" -Level INFO
Write-Status "Action : $Action"
Write-Status "Service: $ServiceName"
Write-Host ""

switch ($Action) {
    'Install' {
        # Full install: write config + register + start
        if (-not (Test-BinaryExists)) { exit 1 }
        Write-AgentConfig
        Remove-ServiceIfExists
        New-DlpAgentService
        Start-DlpAgentService
    }

    'Register' {
        # Register only — do not start
        if (-not (Test-BinaryExists)) { exit 1 }
        Remove-ServiceIfExists
        New-DlpAgentService
    }

    'Start' {
        if (-not (Test-BinaryExists)) { exit 1 }
        Start-DlpAgentService
    }

    'Stop' {
        Stop-DlpAgentService
    }

    'Restart' {
        Stop-DlpAgentService
        Start-DlpAgentService
    }

    'Status' {
        Get-DlpAgentServiceStatus
    }

    'Uninstall' {
        # Stop (if running) then remove
        Remove-DlpAgentService
    }

    'Unregister' {
        # Remove without stopping (use Uninstall to stop first)
        Remove-ServiceIfExists
    }
}

Write-Status "Done." -Level INFO
