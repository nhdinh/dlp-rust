#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Print enforcement UAT for DLP v0.10.0.

.DESCRIPTION
    Tests print blocking for T3/T4 classified files.  The script detects
    installed printers, creates a temporary T4 test file, sends it to the
    selected printer, and verifies the print job is blocked by the DLP agent.

    Requires a real printer installed on the test machine.  If no printer
    is specified, an interactive menu is presented.

    Requires elevation because the DLP agent service and print spooler
    management require administrator privileges.

.EXAMPLE
    .\Uat-PrintBlock.ps1

    Detects printers, presents a menu, and runs the full print blocking test.

.EXAMPLE
    .\Uat-PrintBlock.ps1 -PrinterName "Microsoft Print to PDF"

    Uses the specified printer without showing the selection menu.

.EXAMPLE
    .\Uat-PrintBlock.ps1 -SkipBlockedTest

    Skips the blocked-tier print test and only verifies audit events.

.EXAMPLE
    .\Uat-PrintBlock.ps1 -ServerUrl "http://192.168.1.10:9090" -JwtToken "eyJhbG..."

    Targets a remote dlp-server instance with an explicit JWT token.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ServerUrl = "http://127.0.0.1:9090",

    [Parameter()]
    [string]$JwtToken = $env:DLP_ADMIN_JWT,

    [Parameter()]
    [string]$PrinterName,

    [Parameter()]
    [switch]$SkipBlockedTest,

    [Parameter()]
    [switch]$SkipAuditTest
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ─── Constants ───────────────────────────────────────────────────────────────

$SCRIPT:TestFileName = "DlpUatPrintBlockTest.txt"

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

function Get-InstalledPrinters {
    <#
    .SYNOPSIS
        Queries WMI for installed printers and returns their details.

    .OUTPUTS
        Array of PSCustomObject with properties:
        Name, PortName, DriverName, Default ($true/$false)
    #>
    $printers = Get-WmiObject -Class Win32_Printer |
        Where-Object { $_.Name -and $_.WorkOffline -eq $false }

    $results = @()
    foreach ($printer in $printers) {
        $results += [PSCustomObject]@{
            Name       = $printer.Name
            PortName   = $printer.PortName
            DriverName = $printer.DriverName
            Default    = $printer.Default
        }
    }
    return $results
}

function Show-PrinterMenu {
    <#
    .SYNOPSIS
        Displays a numbered menu of installed printers and returns the selection.

    .PARAMETER Printers
        Array of printer objects from Get-InstalledPrinters.

    .OUTPUTS
        The selected printer PSCustomObject.
    #>
    param([array]$Printers)

    Write-Host "`nDetected printers:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $Printers.Count; $i++) {
        $p = $Printers[$i]
        $defaultMarker = if ($p.Default) { " [DEFAULT]" } else { "" }
        Write-Host "  $($i + 1): $($p.Name)$defaultMarker" -ForegroundColor Cyan
    }

    while ($true) {
        $choice = Read-Host "`nSelect printer number"
        if ($choice -match '^\d+$') {
            $idx = [int]$choice - 1
            if ($idx -ge 0 -and $idx -lt $Printers.Count) {
                return $Printers[$idx]
            }
        }
        Write-Host "Invalid selection. Enter a number between 1 and $($Printers.Count)." -ForegroundColor Red
    }
}

function Test-PrintBlocked {
    <#
    .SYNOPSIS
        Sends a T4-classified test file to the printer and verifies the
        print job is blocked by the DLP agent.

    .PARAMETER PrinterName
        The name of the target printer.

    .PARAMETER TestFilePath
        The path to the test file to print.

    .OUTPUTS
        $true if the print was blocked, $false otherwise.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$PrinterName,
        [Parameter(Mandatory = $true)][string]$TestFilePath
    )

    try {
        # Use Start-Process to print the file via the default handler
        $proc = Start-Process -FilePath "notepad.exe" `
            -ArgumentList "/p `"$TestFilePath`"" `
            -PassThru `
            -WindowStyle Hidden

        # Wait for the print job to appear in the spooler
        Start-Sleep -Seconds 3

        # Check print job status
        $jobs = Get-PrintJob -PrinterName $PrinterName -ErrorAction SilentlyContinue
        if ($jobs) {
            foreach ($job in $jobs) {
                if ($job.DocumentName -like "*$SCRIPT:TestFileName*") {
                    # Job exists — check if it was cancelled (blocked)
                    if ($job.JobStatus -match 'Deleted' -or $job.JobStatus -match 'Error') {
                        return $true
                    }
                }
            }
        }

        # Alternative check: look for the job being immediately removed
        # which indicates the PrintWatcher cancelled it
        Start-Sleep -Seconds 2
        $jobsAfter = Get-PrintJob -PrinterName $PrinterName -ErrorAction SilentlyContinue |
            Where-Object { $_.DocumentName -like "*$SCRIPT:TestFileName*" }
        if (-not $jobsAfter) {
            return $true
        }

        return $false
    }
    catch {
        return $false
    }
    finally {
        # Clean up any notepad process we started
        Get-Process -Name 'notepad' -ErrorAction SilentlyContinue |
            Where-Object { $_.MainWindowTitle -like "*$SCRIPT:TestFileName*" } |
            Stop-Process -Force -ErrorAction SilentlyContinue
    }
}

function Test-PrintAuditEvent {
    <#
    .SYNOPSIS
        Queries the dlp-server admin API for recent print-related audit events.

    .PARAMETER SinceMinutes
        Number of minutes in the past to query.

    .OUTPUTS
        $true if a print audit event is found, $false otherwise.
    #>
    param([Parameter(Mandatory = $true)][int]$SinceMinutes)

    $headers = @{
        Authorization = "Bearer $JwtToken"
    }

    $since = (Get-Date).AddMinutes(-$SinceMinutes).ToUniversalTime().ToString('o')

    try {
        $response = Invoke-RestMethod `
            -Uri "$ServerUrl/audit/events?since=$since&action=PRINT" `
            -Method GET `
            -Headers $headers

        if ($response -and $response.Count -gt 0) {
            return $true
        }
        return $false
    }
    catch {
        Write-Result "Failed to fetch audit events: $($_.Exception.Message)" 'WARN'
        return $false
    }
}

function Get-PrintJobStatus {
    <#
    .SYNOPSIS
        Returns the current status of print jobs on the specified printer.

    .PARAMETER PrinterName
        The name of the printer to query.

    .OUTPUTS
        Array of print job objects.
    #>
    param([Parameter(Mandatory = $true)][string]$PrinterName)

    try {
        return Get-PrintJob -PrinterName $PrinterName -ErrorAction SilentlyContinue
    }
    catch {
        return @()
    }
}

# ─── Main ────────────────────────────────────────────────────────────────────

Write-Host "=== DLP Print Enforcement UAT ===" -ForegroundColor Cyan

# Validate JWT
if (-not $JwtToken) {
    Write-Error "DLP_ADMIN_JWT environment variable or -JwtToken parameter is required."
    exit 1
}

# Detect printers
$printers = Get-InstalledPrinters
if ($printers.Count -eq 0) {
    Write-Error "No printers detected. Install a printer and try again."
    exit 1
}

# Select printer
$selectedPrinter = $null
if ($PrinterName) {
    $selectedPrinter = $printers | Where-Object { $_.Name -eq $PrinterName } | Select-Object -First 1
    if (-not $selectedPrinter) {
        Write-Error "Printer '$PrinterName' not found. Available printers: $($printers.Name -join ', ')"
        exit 1
    }
}
else {
    $selectedPrinter = Show-PrinterMenu $printers
}

Write-Host "`nSelected printer: $($selectedPrinter.Name)" -ForegroundColor Cyan

$passCount = 0
$failCount = 0
$testFilePath = $null

try {

    # Create a T4 test file
    $testFilePath = Join-Path $env:TEMP $SCRIPT:TestFileName
    $t4Content = @"
CLASSIFICATION: T4-RESTRICTED
This document contains highly sensitive test data for DLP print blocking UAT.
Do not print, copy, or distribute.
"@
    [System.IO.File]::WriteAllText($testFilePath, $t4Content)
    Write-Result "Created T4 test file at $testFilePath" 'INFO'

    # ── Blocked tier test ────────────────────────────────────────────────────
    if (-not $SkipBlockedTest) {
        Write-Host "`n[Test] T4 print blocked..." -ForegroundColor Yellow

        $blocked = Test-PrintBlocked $selectedPrinter.Name $testFilePath
        if ($blocked) {
            Write-Result "T4 print job blocked" 'PASS'
            $passCount++
        }
        else {
            Write-Result "T4 print job was NOT blocked" 'FAIL'
            $failCount++
        }
    }

    # ── Audit event test ─────────────────────────────────────────────────────
    if (-not $SkipAuditTest) {
        Write-Host "`n[Test] Print audit event..." -ForegroundColor Yellow

        Start-Sleep -Seconds 2

        $auditFound = Test-PrintAuditEvent 2
        if ($auditFound) {
            Write-Result "Print audit event recorded" 'PASS'
            $passCount++
        }
        else {
            Write-Result "Print audit event NOT found — verify agent is connected and print watcher is active" 'FAIL'
            $failCount++
        }
    }

}
finally {
    # ── Cleanup ──────────────────────────────────────────────────────────────
    Write-Host "`n[Cleanup] Removing temporary test file and print jobs..." -ForegroundColor Yellow

    if ($testFilePath -and (Test-Path -LiteralPath $testFilePath)) {
        try {
            Remove-Item -LiteralPath $testFilePath -Force -ErrorAction Stop
            Write-Result "Removed test file $testFilePath" 'INFO'
        }
        catch {
            Write-Result "Failed to remove test file: $($_.Exception.Message)" 'WARN'
        }
    }

    # Cancel any lingering print jobs from our test
    if ($selectedPrinter) {
        $jobs = Get-PrintJobStatus $selectedPrinter.Name |
            Where-Object { $_.DocumentName -like "*$SCRIPT:TestFileName*" }
        foreach ($job in $jobs) {
            try {
                Remove-PrintJob -PrinterName $selectedPrinter.Name -ID $job.ID -ErrorAction Stop
                Write-Result "Cancelled lingering print job ID $($job.ID)" 'INFO'
            }
            catch {
                Write-Result "Failed to cancel print job ID $($job.ID): $($_.Exception.Message)" 'WARN'
            }
        }
    }

    # Clean up any notepad processes
    Get-Process -Name 'notepad' -ErrorAction SilentlyContinue |
        Where-Object { $_.MainWindowTitle -like "*$SCRIPT:TestFileName*" } |
        Stop-Process -Force -ErrorAction SilentlyContinue
}

# ── Summary ──────────────────────────────────────────────────────────────────
Write-Host "`n=== Results ===" -ForegroundColor Cyan
Write-Result "Total PASS: $passCount" 'PASS'
Write-Result "Total FAIL: $failCount" 'FAIL'

if ($failCount -gt 0) {
    exit 1
}
exit 0
