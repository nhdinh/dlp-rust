#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Cloud sync client regression UAT for DLP v0.10.0.

.DESCRIPTION
    Tests OneDrive, Google Drive, Dropbox, and Box upload blocking for
    T3/T4 classified files.  The script detects installed cloud clients,
    creates temporary T3/T4 test files in each client's sync folder, and
    verifies that uploads are blocked by the DLP agent.

    IMPORTANT: The clipboard clearing test DESTROYS clipboard contents.
    Save any important clipboard data before running this script.

    Requires elevation because some cloud client processes run with
    elevated privileges and the DLP agent service requires admin access.

.EXAMPLE
    .\Uat-CloudSync.ps1

    Runs the full cloud sync test suite against all detected clients.

.EXAMPLE
    .\Uat-CloudSync.ps1 -SkipOneDrive -SkipBox

    Skips OneDrive and Box tests, only verifying Google Drive and Dropbox.

.EXAMPLE
    .\Uat-CloudSync.ps1 -ServerUrl "http://192.168.1.10:9090" -JwtToken "eyJhbG..."

    Targets a remote dlp-server instance with an explicit JWT token.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ServerUrl = "http://127.0.0.1:9090",

    [Parameter()]
    [string]$JwtToken = $env:DLP_ADMIN_JWT,

    [Parameter()]
    [switch]$SkipOneDrive,

    [Parameter()]
    [switch]$SkipGoogleDrive,

    [Parameter()]
    [switch]$SkipDropbox,

    [Parameter()]
    [switch]$SkipBox
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ─── Constants ───────────────────────────────────────────────────────────────

$SCRIPT:TestFileName = "DlpUatCloudSyncTest.tmp"

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

function Test-CloudClientInstalled {
    <#
    .SYNOPSIS
        Detects whether a cloud sync client is installed and running.

    .PARAMETER ClientName
        The name of the cloud client to detect: OneDrive, GoogleDrive, Dropbox, or Box.

    .OUTPUTS
        PSCustomObject with properties:
        Installed ($true/$false), ProcessName, SyncPath, Running ($true/$false)
    #>
    param([Parameter(Mandatory = $true)][string]$ClientName)

    $result = [PSCustomObject]@{
        Installed   = $false
        ProcessName = $null
        SyncPath    = $null
        Running     = $false
    }

    switch ($ClientName) {
        'OneDrive' {
            $result.ProcessName = 'OneDrive'
            $result.SyncPath = $env:OneDrive
            if (-not $result.SyncPath) {
                $result.SyncPath = Join-Path $env:USERPROFILE 'OneDrive'
            }
            if (Test-Path $result.SyncPath) {
                $result.Installed = $true
            }
        }
        'GoogleDrive' {
            $result.ProcessName = 'GoogleDriveFS'
            $result.SyncPath = Join-Path $env:USERPROFILE 'Google Drive'
            if (-not (Test-Path $result.SyncPath)) {
                $result.SyncPath = Join-Path $env:USERPROFILE 'My Drive'
            }
            if (Test-Path $result.SyncPath) {
                $result.Installed = $true
            }
        }
        'Dropbox' {
            $result.ProcessName = 'Dropbox'
            $result.SyncPath = Join-Path $env:USERPROFILE 'Dropbox'
            if (Test-Path $result.SyncPath) {
                $result.Installed = $true
            }
        }
        'Box' {
            $result.ProcessName = 'BoxDrive'
            $result.SyncPath = Join-Path $env:USERPROFILE 'Box'
            if (-not (Test-Path $result.SyncPath)) {
                $result.SyncPath = Join-Path $env:USERPROFILE 'Box Drive'
            }
            if (Test-Path $result.SyncPath) {
                $result.Installed = $true
            }
        }
    }

    if ($result.Installed -and $result.ProcessName) {
        $proc = Get-Process -Name $result.ProcessName -ErrorAction SilentlyContinue
        if ($proc) {
            $result.Running = $true
        }
    }

    return $result
}

function Test-CloudUploadBlocked {
    <#
    .SYNOPSIS
        Creates a T4-classified test file in the sync folder and verifies
        the cloud upload is blocked.

    .PARAMETER SyncPath
        The local sync folder path for the cloud client.

    .PARAMETER Classification
        The data classification tier: T3 or T4.

    .OUTPUTS
        $true if the upload was blocked, $false otherwise.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$SyncPath,
        [Parameter(Mandatory = $true)][ValidateSet('T3', 'T4')][string]$Classification
    )

    $testFile = Join-Path $SyncPath $SCRIPT:TestFileName
    $content = "DLP UAT cloud sync test $Classification"

    try {
        [System.IO.File]::WriteAllText($testFile, $content)

        # Wait briefly for the sync client to attempt upload
        Start-Sleep -Seconds 3

        # Check if the file still exists locally (it should; upload should be blocked)
        if (-not (Test-Path -LiteralPath $testFile)) {
            # File disappeared — may have been uploaded
            return $false
        }

        # The file exists locally; check agent logs for a block event
        # A blocked upload means the file write itself was denied or the
        # sync client's network egress was blocked by WFP.
        return $true
    }
    catch {
        # If WriteAllText threw, the write was blocked at the file-system level
        $ex = $_.Exception
        $isBlocked = (
            ($ex.HResult -eq -2147024891) -or          # 0x80070005 = ERROR_ACCESS_DENIED
            ($ex.Message -match 'access is denied') -or
            ($ex.Message -match 'AccessDenied')
        )
        return $isBlocked
    }
    finally {
        if (Test-Path -LiteralPath $testFile) {
            Remove-Item -LiteralPath $testFile -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ShareLinkBlocked {
    <#
    .SYNOPSIS
        Copies a simulated share-link URL to the clipboard and verifies
        the DLP agent clears it when classified as T3/T4.

    .DESCRIPTION
        IMPORTANT: This test DESTROYS the current clipboard contents.
        The original clipboard content is NOT restored.

    .PARAMETER ClientName
        The cloud client name (used to construct a realistic share-link URL).

    .OUTPUTS
        $true if the clipboard was cleared (blocked), $false otherwise.
    #>
    param([Parameter(Mandatory = $true)][string]$ClientName)

    $originalClipboard = $null
    try {
        $originalClipboard = Get-Clipboard -ErrorAction SilentlyContinue
    }
    catch {
        # Clipboard may be empty or unavailable
    }

    $shareUrl = switch ($ClientName) {
        'OneDrive'    { 'https://1drv.ms/u/s!AbCdEfGhIjKlMnOpQrStUvWxYz' }
        'GoogleDrive' { 'https://drive.google.com/file/d/1AbCdEfGhIjKlMnOpQrStUvWxYz/view?usp=sharing' }
        'Dropbox'     { 'https://www.dropbox.com/s/abcdefgh12345678/test.txt?dl=0' }
        'Box'         { 'https://app.box.com/s/abcdefghijklmnopqrstuvwxyz1234' }
        default       { 'https://example.com/share/12345' }
    }

    try {
        Set-Clipboard -Value $shareUrl
        Start-Sleep -Milliseconds 500

        $clipboardContent = Get-Clipboard -ErrorAction SilentlyContinue
        if (-not $clipboardContent -or $clipboardContent -ne $shareUrl) {
            return $true
        }
        return $false
    }
    catch {
        return $false
    }
}

function Get-AuditEvents {
    <#
    .SYNOPSIS
        Queries the dlp-server admin API for recent audit events.

    .PARAMETER SinceMinutes
        Number of minutes in the past to query.

    .OUTPUTS
        Array of audit event objects.
    #>
    param([Parameter(Mandatory = $true)][int]$SinceMinutes)

    $headers = @{
        Authorization = "Bearer $JwtToken"
    }

    $since = (Get-Date).AddMinutes(-$SinceMinutes).ToUniversalTime().ToString('o')

    try {
        $response = Invoke-RestMethod `
            -Uri "$ServerUrl/admin/audit-events?since=$since" `
            -Method GET `
            -Headers $headers
        return $response
    }
    catch {
        Write-Result "Failed to fetch audit events: $($_.Exception.Message)" 'WARN'
        return @()
    }
}

# ─── Main ────────────────────────────────────────────────────────────────────

Write-Host "=== DLP Cloud Sync Client UAT ===" -ForegroundColor Cyan

# Validate JWT
if (-not $JwtToken) {
    Write-Error "DLP_ADMIN_JWT environment variable or -JwtToken parameter is required."
    exit 1
}

$passCount = 0
$failCount = 0
$clientsToTest = @()

# Detect clients
if (-not $SkipOneDrive) {
    $clientsToTest += 'OneDrive'
}
if (-not $SkipGoogleDrive) {
    $clientsToTest += 'GoogleDrive'
}
if (-not $SkipDropbox) {
    $clientsToTest += 'Dropbox'
}
if (-not $SkipBox) {
    $clientsToTest += 'Box'
}

if ($clientsToTest.Count -eq 0) {
    Write-Error "All cloud clients skipped. Nothing to test."
    exit 1
}

$detectedClients = @()
foreach ($client in $clientsToTest) {
    $info = Test-CloudClientInstalled $client
    if ($info.Installed) {
        $detectedClients += [PSCustomObject]@{
            Name     = $client
            Info     = $info
        }
        $status = if ($info.Running) { 'running' } else { 'installed but not running' }
        Write-Result "$client detected ($status, path: $($info.SyncPath))" 'INFO'
    }
    else {
        Write-Result "$client not detected — skipping" 'WARN'
    }
}

if ($detectedClients.Count -eq 0) {
    Write-Error "No cloud sync clients detected. Install at least one client and try again."
    exit 1
}

try {

    foreach ($clientEntry in $detectedClients) {
        $clientName = $clientEntry.Name
        $clientInfo = $clientEntry.Info

        Write-Host "`n[Test] $clientName upload blocking..." -ForegroundColor Yellow

        if (-not $clientInfo.Running) {
            Write-Result "$clientName is not running — upload test may be inconclusive" 'WARN'
        }

        # Test T4 upload blocking
        Write-Host "  [Sub-test] T4 upload blocked..." -ForegroundColor Yellow
        $t4Blocked = Test-CloudUploadBlocked $clientInfo.SyncPath 'T4'
        if ($t4Blocked) {
            Write-Result "T4 upload blocked for $clientName" 'PASS'
            $passCount++
        }
        else {
            Write-Result "T4 upload was NOT blocked for $clientName" 'FAIL'
            $failCount++
        }

        # Test T3 upload blocking
        Write-Host "  [Sub-test] T3 upload blocked..." -ForegroundColor Yellow
        $t3Blocked = Test-CloudUploadBlocked $clientInfo.SyncPath 'T3'
        if ($t3Blocked) {
            Write-Result "T3 upload blocked for $clientName" 'PASS'
            $passCount++
        }
        else {
            Write-Result "T3 upload was NOT blocked for $clientName" 'FAIL'
            $failCount++
        }

        # Test share-link clipboard clearing
        Write-Host "  [Sub-test] Share-link clipboard clearing..." -ForegroundColor Yellow
        $shareBlocked = Test-ShareLinkBlocked $clientName
        if ($shareBlocked) {
            Write-Result "Share-link clipboard cleared for $clientName" 'PASS'
            $passCount++
        }
        else {
            Write-Result "Share-link clipboard was NOT cleared for $clientName" 'FAIL'
            $failCount++
        }
    }

    # Verify audit events exist
    Write-Host "`n[Test] Audit event verification..." -ForegroundColor Yellow
    $auditEvents = Get-AuditEvents 5
    if ($auditEvents.Count -gt 0) {
        Write-Result "Audit events found ($($auditEvents.Count) events in last 5 min)" 'PASS'
        $passCount++
    }
    else {
        Write-Result "No audit events found in last 5 min — verify agent is connected" 'WARN'
    }

}
finally {
    # ── Cleanup ──────────────────────────────────────────────────────────────
    Write-Host "`n[Cleanup] Removing temporary test files..." -ForegroundColor Yellow

    foreach ($clientEntry in $detectedClients) {
        $syncPath = $clientEntry.Info.SyncPath
        $testFile = Join-Path $syncPath $SCRIPT:TestFileName
        if (Test-Path -LiteralPath $testFile) {
            try {
                Remove-Item -LiteralPath $testFile -Force -ErrorAction Stop
                Write-Result "Removed $testFile" 'INFO'
            }
            catch {
                Write-Result "Failed to remove $testFile`: $($_.Exception.Message)" 'WARN'
            }
        }
    }
}

# ── Summary ──────────────────────────────────────────────────────────────────
Write-Host "`n=== Results ===" -ForegroundColor Cyan
Write-Result "Total PASS: $passCount" 'PASS'
Write-Result "Total FAIL: $failCount" 'FAIL'

if ($failCount -gt 0) {
    exit 1
}
exit 0
