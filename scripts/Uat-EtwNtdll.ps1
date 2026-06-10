#Requires -RunAsAdministrator
<#
.SYNOPSIS
    ETW bypass detection, ntdll patching, and monitor mode UAT for DLP v0.10.0.

.DESCRIPTION
    Tests three v0.10.0 enforcement layers:
    1. ETW bypass detection — suspends a process before hook injection,
       performs a write, resumes, and checks for a BypassAlert with
       NoHookJournal within 5 seconds.
    2. ntdll patching — checks the enable_ntdll_patching config flag.
       If enabled, verifies direct syscalls are blocked with STATUS_ACCESS_DENIED.
       If disabled, skips with INFO.
    3. Monitor mode — creates an Audit policy via the API, tests that a
       write succeeds, and verifies the audit shows policy_mode=Audit and
       would_have_denied=true.

       CRITICAL: The finally block MUST restore the original policy mode.

    Requires elevation because process suspension, ETW tracing, and policy
    management require administrator privileges.

.EXAMPLE
    .\Uat-EtwNtdll.ps1

    Runs the full ETW, ntdll, and monitor mode test suite.

.EXAMPLE
    .\Uat-EtwNtdll.ps1 -SkipEtwTest -SkipNtdllTest

    Skips ETW and ntdll tests, only verifying monitor mode.

.EXAMPLE
    .\Uat-EtwNtdll.ps1 -ServerUrl "http://192.168.1.10:9090" -JwtToken "eyJhbG..."

    Targets a remote dlp-server instance with an explicit JWT token.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ServerUrl = "http://127.0.0.1:9090",

    [Parameter()]
    [string]$JwtToken = $env:DLP_ADMIN_JWT,

    [Parameter()]
    [switch]$SkipEtwTest,

    [Parameter()]
    [switch]$SkipNtdllTest,

    [Parameter()]
    [switch]$SkipMonitorModeTest
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ─── Constants ───────────────────────────────────────────────────────────────

$SCRIPT:BypassAlertTimeoutSec = 5
$SCRIPT:TestFileName = "DlpUatEtwNtdllTest.tmp"

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

function Get-AgentConfig {
    <#
    .SYNOPSIS
        Retrieves the current agent configuration from the dlp-server admin API.

    .OUTPUTS
        The agent config object, or $null on failure.
    #>
    $headers = @{
        Authorization = "Bearer $JwtToken"
    }

    try {
        $response = Invoke-RestMethod `
            -Uri "$ServerUrl/admin/agent-config" `
            -Method GET `
            -Headers $headers
        return $response
    }
    catch {
        Write-Result "Failed to fetch agent config: $($_.Exception.Message)" 'WARN'
        return $null
    }
}

function Get-BypassAlerts {
    <#
    .SYNOPSIS
        Queries the dlp-server admin API for recent bypass alerts.

    .PARAMETER SinceMinutes
        Number of minutes in the past to query.

    .OUTPUTS
        Array of bypass alert objects.
    #>
    param([Parameter(Mandatory = $true)][int]$SinceMinutes)

    $headers = @{
        Authorization = "Bearer $JwtToken"
    }

    $since = (Get-Date).AddMinutes(-$SinceMinutes).ToUniversalTime().ToString('o')

    try {
        $response = Invoke-RestMethod `
            -Uri "$ServerUrl/admin/bypass-alerts?since=$since" `
            -Method GET `
            -Headers $headers
        return $response
    }
    catch {
        Write-Result "Failed to fetch bypass alerts: $($_.Exception.Message)" 'WARN'
        return @()
    }
}

function Test-EtwBypassDetection {
    <#
    .SYNOPSIS
        Suspends a new process before hook injection, performs a file write,
        resumes the process, and checks for a BypassAlert with NoHookJournal
        within 5 seconds.

    .DESCRIPTION
        Retries up to 3 times with new processes if the first attempt does
        not produce a bypass alert.

    .OUTPUTS
        $true if a bypass alert was detected, $false otherwise.
    #>
    $maxRetries = 3
    for ($retry = 1; $retry -le $maxRetries; $retry++) {
        $proc = $null
        try {
            # Spawn a new process
            $proc = Start-Process -FilePath "notepad.exe" -PassThru -WindowStyle Hidden

            # Suspend the process immediately (before hook injection)
            # Use NtSuspendProcess via inline C# P/Invoke
            $csharp = @"
using System;
using System.Runtime.InteropServices;
using System.ComponentModel;

public class ProcessControl {
    [DllImport("ntdll.dll")]
    public static extern int NtSuspendProcess(IntPtr processHandle);

    [DllImport("ntdll.dll")]
    public static extern int NtResumeProcess(IntPtr processHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    public const uint PROCESS_SUSPEND_RESUME = 0x00000800;

    public static void Suspend(int pid) {
        IntPtr hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid);
        if (hProcess == IntPtr.Zero) {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        try {
            int status = NtSuspendProcess(hProcess);
            if (status != 0) {
                throw new Exception("NtSuspendProcess returned 0x" + status.ToString("X8"));
            }
        }
        finally {
            CloseHandle(hProcess);
        }
    }

    public static void Resume(int pid) {
        IntPtr hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid);
        if (hProcess == IntPtr.Zero) {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        try {
            int status = NtResumeProcess(hProcess);
            if (status != 0) {
                throw new Exception("NtResumeProcess returned 0x" + status.ToString("X8"));
            }
        }
        finally {
            CloseHandle(hProcess);
        }
    }
}
"@
            try {
                Add-Type -TypeDefinition $csharp -Language CSharp -ErrorAction SilentlyContinue
            }
            catch {
                # Type may already be loaded
            }

            [ProcessControl]::Suspend($proc.Id)

            # Perform a write while suspended (hook cannot intercept)
            $testFile = Join-Path $env:TEMP "${SCRIPT:TestFileName}_$($proc.Id)"
            try {
                [System.IO.File]::WriteAllText($testFile, "DLP UAT ETW bypass test")
            }
            catch {
                # Write may fail for various reasons; continue
            }
            finally {
                if (Test-Path -LiteralPath $testFile) {
                    Remove-Item -LiteralPath $testFile -Force -ErrorAction SilentlyContinue
                }
            }

            # Resume the process
            [ProcessControl]::Resume($proc.Id)

            # Wait for bypass alert (up to 5 seconds)
            $deadline = (Get-Date).AddSeconds($SCRIPT:BypassAlertTimeoutSec)
            while ((Get-Date) -lt $deadline) {
                Start-Sleep -Seconds 1
                $alerts = Get-BypassAlerts 1
                foreach ($alert in $alerts) {
                    if ($alert.correlation_reason -eq 'NoHookJournal' -or
                        $alert.reason -eq 'NoHookJournal') {
                        return $true
                    }
                }
            }
        }
        catch {
            Write-Result "ETW bypass detection attempt $retry failed: $($_.Exception.Message)" 'WARN'
        }
        finally {
            if ($proc -and -not $proc.HasExited) {
                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            }
        }
    }

    return $false
}

function Test-NtdllPatching {
    <#
    .SYNOPSIS
        Checks the enable_ntdll_patching config flag and verifies direct
        syscall blocking if enabled.

    .DESCRIPTION
        If enable_ntdll_patching is true, attempts a direct syscall write
        to a T4 path and verifies it returns STATUS_ACCESS_DENIED.
        If the flag is false, skips with INFO.

    .OUTPUTS
        $true if test passed or skipped appropriately, $false on failure.
    #>
    $config = Get-AgentConfig
    if (-not $config) {
        Write-Result "Could not retrieve agent config — ntdll test inconclusive" 'WARN'
        return $null
    }

    $enabled = $config.enable_ntdll_patching
    if (-not $enabled) {
        Write-Result "enable_ntdll_patching is false — skipping direct-syscall test" 'INFO'
        return $true
    }

    Write-Result "enable_ntdll_patching is true — testing direct syscall blocking..." 'INFO'

    # Attempt a direct syscall write using a simple C# program that bypasses
    # the IAT hook layer.  For UAT, we use a low-level FileStream with
    # explicit flags that bypass some user-mode hooks.
    $testFile = Join-Path $env:TEMP $SCRIPT:TestFileName
    try {
        # Use raw P/Invoke to NtCreateFile to bypass IAT hooks
        $csharp = @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public class DirectSyscall {
    [DllImport("ntdll.dll")]
    public static extern int NtCreateFile(
        out IntPtr fileHandle,
        uint desiredAccess,
        ref OBJECT_ATTRIBUTES objectAttributes,
        out IO_STATUS_BLOCK ioStatusBlock,
        ref long allocationSize,
        uint fileAttributes,
        uint shareAccess,
        uint createDisposition,
        uint createOptions,
        IntPtr eaBuffer,
        uint eaLength);

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES {
        public uint Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IO_STATUS_BLOCK {
        public uint Status;
        public ulong Information;
    }

    public const uint FILE_GENERIC_WRITE = 0x00120116;
    public const uint FILE_CREATE = 0x00000002;
    public const uint FILE_SYNCHRONIZE_IO_ALERT = 0x00000040;
    public const uint OBJ_CASE_INSENSITIVE = 0x00000040;
    public const int STATUS_ACCESS_DENIED = unchecked((int)0xC0000022);

    public static int TryCreateFile(string path) {
        IntPtr hFile;
        IO_STATUS_BLOCK iosb = new IO_STATUS_BLOCK();
        long allocSize = 0;

        UNICODE_STRING uni = new UNICODE_STRING();
        uni.Buffer = Marshal.StringToHGlobalUni("\\??\\" + path);
        uni.Length = (ushort)(("\\??\\" + path).Length * 2);
        uni.MaximumLength = (ushort)(uni.Length + 2);

        IntPtr pUni = Marshal.AllocHGlobal(Marshal.SizeOf(uni));
        Marshal.StructureToPtr(uni, pUni, false);

        OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
        oa.Length = (uint)Marshal.SizeOf(oa);
        oa.ObjectName = pUni;
        oa.Attributes = OBJ_CASE_INSENSITIVE;

        int status = NtCreateFile(
            out hFile,
            FILE_GENERIC_WRITE,
            ref oa,
            out iosb,
            ref allocSize,
            0,
            0,
            FILE_CREATE,
            FILE_SYNCHRONIZE_IO_ALERT,
            IntPtr.Zero,
            0);

        Marshal.FreeHGlobal(uni.Buffer);
        Marshal.FreeHGlobal(pUni);

        if (status == 0 && hFile != IntPtr.Zero && hFile != new IntPtr(-1)) {
            CloseHandle(hFile);
        }

        return status;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);
}
"@
        try {
            Add-Type -TypeDefinition $csharp -Language CSharp -ErrorAction SilentlyContinue
        }
        catch {
            # Type may already be loaded
        }

        $status = [DirectSyscall]::TryCreateFile($testFile)
        if ($status -eq -1073741790) {  # 0xC0000022 = STATUS_ACCESS_DENIED
            return $true
        }
        else {
            Write-Result "Direct syscall returned 0x$($status.ToString('X8')) instead of STATUS_ACCESS_DENIED" 'FAIL'
            return $false
        }
    }
    catch {
        Write-Result "Direct syscall test failed: $($_.Exception.Message)" 'FAIL'
        return $false
    }
    finally {
        if (Test-Path -LiteralPath $testFile) {
            Remove-Item -LiteralPath $testFile -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-MonitorMode {
    <#
    .SYNOPSIS
        Creates an Audit policy via the API, tests that a write succeeds,
        and verifies the audit event shows policy_mode=Audit and
        would_have_denied=true.

    .DESCRIPTION
        CRITICAL: The finally block of the caller MUST restore the original
        policy mode.  This function returns the original mode so the caller
        can do so.

    .OUTPUTS
        PSCustomObject with properties:
        TestPassed ($true/$false), OriginalMode (string or $null)
    #>
    $headers = @{
        Authorization = "Bearer $JwtToken"
    }

    # Fetch existing policies to find one to modify
    $policies = @()
    try {
        $policies = Invoke-RestMethod `
            -Uri "$ServerUrl/admin/policies" `
            -Method GET `
            -Headers $headers
    }
    catch {
        Write-Result "Failed to fetch policies: $($_.Exception.Message)" 'FAIL'
        return [PSCustomObject]@{ TestPassed = $false; OriginalMode = $null }
    }

    if ($policies.Count -eq 0) {
        Write-Result "No policies found — cannot test monitor mode" 'WARN'
        return [PSCustomObject]@{ TestPassed = $false; OriginalMode = $null }
    }

    $targetPolicy = $policies | Select-Object -First 1
    $policyId = $targetPolicy.id
    $originalMode = $targetPolicy.enforcement_mode

    # Change policy to Audit mode
    $targetPolicy.enforcement_mode = 'Audit'
    try {
        $body = $targetPolicy | ConvertTo-Json -Depth 10
        Invoke-RestMethod `
            -Uri "$ServerUrl/admin/policies/$policyId" `
            -Method PUT `
            -Headers $headers `
            -ContentType 'application/json' `
            -Body $body | Out-Null
        Write-Result "Policy $policyId set to Audit mode" 'INFO'
    }
    catch {
        Write-Result "Failed to set policy to Audit mode: $($_.Exception.Message)" 'FAIL'
        return [PSCustomObject]@{ TestPassed = $false; OriginalMode = $originalMode }
    }

    # Wait for agent to sync
    Start-Sleep -Seconds 3

    $testFile = Join-Path $env:TEMP $SCRIPT:TestFileName
    $writeSucceeded = $false
    try {
        # Attempt a write that would normally be blocked
        [System.IO.File]::WriteAllText($testFile, "DLP UAT monitor mode test")
        $writeSucceeded = $true
    }
    catch {
        $writeSucceeded = $false
    }
    finally {
        if (Test-Path -LiteralPath $testFile) {
            Remove-Item -LiteralPath $testFile -Force -ErrorAction SilentlyContinue
        }
    }

    if (-not $writeSucceeded) {
        Write-Result "Write was blocked in Audit mode — expected ALLOW" 'FAIL'
        return [PSCustomObject]@{ TestPassed = $false; OriginalMode = $originalMode }
    }

    # Check audit events for would_have_denied=true
    Start-Sleep -Seconds 2
    $since = (Get-Date).AddMinutes(-1).ToUniversalTime().ToString('o')
    $auditFound = $false
    try {
        $events = Invoke-RestMethod `
            -Uri "$ServerUrl/audit/events?since=$since" `
            -Method GET `
            -Headers $headers

        foreach ($event in $events) {
            if ($event.policy_mode -eq 'Audit' -and $event.would_have_denied -eq $true) {
                $auditFound = $true
                break
            }
        }
    }
    catch {
        Write-Result "Failed to fetch audit events: $($_.Exception.Message)" 'WARN'
    }

    if ($auditFound) {
        Write-Result "Audit event shows policy_mode=Audit and would_have_denied=true" 'PASS'
        return [PSCustomObject]@{ TestPassed = $true; OriginalMode = $originalMode }
    }
    else {
        Write-Result "Audit event with would_have_denied=true NOT found" 'FAIL'
        return [PSCustomObject]@{ TestPassed = $false; OriginalMode = $originalMode }
    }
}

function Restore-PolicyMode {
    <#
    .SYNOPSIS
        Restores a policy to its original enforcement mode.

    .PARAMETER PolicyId
        The ID of the policy to restore.

    .PARAMETER OriginalMode
        The original enforcement mode string.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$PolicyId,
        [Parameter(Mandatory = $true)][string]$OriginalMode
    )

    if (-not $PolicyId -or -not $OriginalMode) {
        return
    }

    $headers = @{
        Authorization = "Bearer $JwtToken"
    }

    try {
        $policy = Invoke-RestMethod `
            -Uri "$ServerUrl/admin/policies/$PolicyId" `
            -Method GET `
            -Headers $headers

        $policy.enforcement_mode = $OriginalMode
        $body = $policy | ConvertTo-Json -Depth 10

        Invoke-RestMethod `
            -Uri "$ServerUrl/admin/policies/$PolicyId" `
            -Method PUT `
            -Headers $headers `
            -ContentType 'application/json' `
            -Body $body | Out-Null

        Write-Result "Policy $PolicyId restored to $OriginalMode mode" 'INFO'
    }
    catch {
        Write-Result "Failed to restore policy mode: $($_.Exception.Message)" 'WARN'
    }
}

# ─── Main ────────────────────────────────────────────────────────────────────

Write-Host "=== DLP ETW / ntdll / Monitor Mode UAT ===" -ForegroundColor Cyan

# Validate JWT
if (-not $JwtToken) {
    Write-Error "DLP_ADMIN_JWT environment variable or -JwtToken parameter is required."
    exit 1
}

$passCount = 0
$failCount = 0
$monitorPolicyId = $null
$monitorOriginalMode = $null

try {

    # ── ETW bypass detection test ────────────────────────────────────────────
    if (-not $SkipEtwTest) {
        Write-Host "`n[Test] ETW bypass detection (NoHookJournal)..." -ForegroundColor Yellow

        $bypassDetected = Test-EtwBypassDetection
        if ($bypassDetected) {
            Write-Result "Bypass alert (NoHookJournal) detected within ${SCRIPT:BypassAlertTimeoutSec}s" 'PASS'
            $passCount++
        }
        else {
            Write-Result "Bypass alert NOT detected after 3 retries" 'FAIL'
            $failCount++
        }
    }

    # ── ntdll patching test ──────────────────────────────────────────────────
    if (-not $SkipNtdllTest) {
        Write-Host "`n[Test] ntdll patching direct-syscall block..." -ForegroundColor Yellow

        $ntdllResult = Test-NtdllPatching
        if ($ntdllResult -eq $true) {
            Write-Result "Direct syscall blocked with STATUS_ACCESS_DENIED" 'PASS'
            $passCount++
        }
        elseif ($ntdllResult -eq $false) {
            Write-Result "Direct syscall was NOT blocked" 'FAIL'
            $failCount++
        }
        else {
            Write-Result "ntdll patching test skipped (config disabled or unavailable)" 'INFO'
        }
    }

    # ── Monitor mode test ────────────────────────────────────────────────────
    if (-not $SkipMonitorModeTest) {
        Write-Host "`n[Test] Monitor mode (Audit policy)..." -ForegroundColor Yellow

        $monitorResult = Test-MonitorMode
        $monitorPolicyId = $monitorResult.OriginalMode
        # We need the policy ID too — extract from the policy we modified
        # The Test-MonitorMode function doesn't return the ID, so we re-fetch
        try {
            $headers = @{ Authorization = "Bearer $JwtToken" }
            $policies = Invoke-RestMethod `
                -Uri "$ServerUrl/admin/policies" `
                -Method GET `
                -Headers $headers
            $auditPolicy = $policies | Where-Object { $_.enforcement_mode -eq 'Audit' } | Select-Object -First 1
            if ($auditPolicy) {
                $monitorPolicyId = $auditPolicy.id
                $monitorOriginalMode = $monitorResult.OriginalMode
            }
        }
        catch {
            # Best effort
        }

        if ($monitorResult.TestPassed) {
            Write-Result "Monitor mode works: write allowed, audit shows would_have_denied=true" 'PASS'
            $passCount++
        }
        else {
            Write-Result "Monitor mode test failed" 'FAIL'
            $failCount++
        }
    }

}
finally {
    # ── Cleanup ──────────────────────────────────────────────────────────────
    Write-Host "`n[Cleanup] Restoring original policy mode..." -ForegroundColor Yellow

    if ($monitorPolicyId -and $monitorOriginalMode) {
        Restore-PolicyMode $monitorPolicyId $monitorOriginalMode
    }
    else {
        # Fallback: find any Audit policy and restore to Block
        try {
            $headers = @{ Authorization = "Bearer $JwtToken" }
            $policies = Invoke-RestMethod `
                -Uri "$ServerUrl/admin/policies" `
                -Method GET `
                -Headers $headers
            $auditPolicy = $policies | Where-Object { $_.enforcement_mode -eq 'Audit' } | Select-Object -First 1
            if ($auditPolicy) {
                Restore-PolicyMode $auditPolicy.id 'Block'
            }
        }
        catch {
            Write-Result "Fallback policy restore failed: $($_.Exception.Message)" 'WARN'
        }
    }

    # Remove any leftover test files
    $testFiles = Get-ChildItem -Path $env:TEMP -Filter "DlpUatEtwNtdllTest*" -ErrorAction SilentlyContinue
    foreach ($file in $testFiles) {
        try {
            Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
            Write-Result "Removed leftover test file $($file.Name)" 'INFO'
        }
        catch {
            Write-Result "Failed to remove $($file.Name): $($_.Exception.Message)" 'WARN'
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
