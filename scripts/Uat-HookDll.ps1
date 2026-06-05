#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Hook DLL injection UAT for DLP v0.10.0.

.DESCRIPTION
    Tests the universal hook DLL injection system across five dimensions:
    1. New process injection (notepad.exe spawned and injected within 500ms)
    2. x86/WoW64 process injection (SysWOW64 notepad)
    3. AV/EDR process skip (Defender, CrowdStrike, SentinelOne)
    4. PPL process skip (lsass, services, csrss)
    5. Startup sweep coverage (EnumProcesses on agent restart)

    Requires elevation because process injection and PPL querying require
    administrator privileges.

.EXAMPLE
    .\Uat-HookDll.ps1

    Runs the full hook DLL injection test suite.

.EXAMPLE
    .\Uat-HookDll.ps1 -SkipX86Test -SkipAvEdrTest

    Skips x86 and AV/EDR tests, only verifying new-process injection,
    PPL skip, and startup sweep.

.EXAMPLE
    .\Uat-HookDll.ps1 -ServerUrl "http://192.168.1.10:9090" -JwtToken "eyJhbG..."

    Targets a remote dlp-server instance with an explicit JWT token.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ServerUrl = "http://127.0.0.1:9090",

    [Parameter()]
    [string]$JwtToken = $env:DLP_ADMIN_JWT,

    [Parameter()]
    [switch]$SkipNewProcessTest,

    [Parameter()]
    [switch]$SkipX86Test,

    [Parameter()]
    [switch]$SkipAvEdrTest,

    [Parameter()]
    [switch]$SkipPplTest,

    [Parameter()]
    [switch]$SkipStartupSweepTest
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ─── Constants ───────────────────────────────────────────────────────────────

$SCRIPT:HookDllName = 'dlp_hook_dll.dll'
$SCRIPT:HookDllX86Name = 'dlp_hook_dll_x86.dll'
$SCRIPT:InjectionTimeoutMs = 500

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

function Get-ProcessModules {
    <#
    .SYNOPSIS
        Returns the list of loaded module names for a given process.

    .PARAMETER ProcessId
        The PID of the target process.

    .OUTPUTS
        Array of module name strings.
    #>
    param([Parameter(Mandatory = $true)][int]$ProcessId)

    try {
        $proc = Get-Process -Id $ProcessId -ErrorAction Stop
        return $proc.Modules | ForEach-Object { $_.ModuleName }
    }
    catch {
        return @()
    }
}

function Test-HookDllInjectedNewProcess {
    <#
    .SYNOPSIS
        Spawns a new notepad.exe process and verifies the hook DLL is
        injected within the configured timeout.

    .OUTPUTS
        $true if the hook DLL is found in the process modules, $false otherwise.
    #>
    $proc = $null
    try {
        $proc = Start-Process -FilePath "notepad.exe" -PassThru -WindowStyle Hidden

        # Wait for injection (up to 500ms per spec)
        $deadline = (Get-Date).AddMilliseconds($SCRIPT:InjectionTimeoutMs)
        $found = $false
        while ((Get-Date) -lt $deadline -and -not $found) {
            Start-Sleep -Milliseconds 50
            $modules = Get-ProcessModules $proc.Id
            if ($modules -contains $SCRIPT:HookDllName) {
                $found = $true
            }
        }

        return $found
    }
    catch {
        return $false
    }
    finally {
        if ($proc -and -not $proc.HasExited) {
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-HookDllInjectedX86 {
    <#
    .SYNOPSIS
        Spawns the 32-bit (SysWOW64) notepad.exe and verifies the x86
        hook DLL is injected.

    .OUTPUTS
        $true if the x86 hook DLL is found in the process modules, $false otherwise.
    #>
    $x86Notepad = Join-Path $env:SystemRoot 'SysWOW64\notepad.exe'
    if (-not (Test-Path $x86Notepad)) {
        Write-Result "SysWOW64 notepad.exe not found — x86 test skipped" 'WARN'
        return $false
    }

    $proc = $null
    try {
        $proc = Start-Process -FilePath $x86Notepad -PassThru -WindowStyle Hidden

        # Wait for injection (up to 500ms)
        $deadline = (Get-Date).AddMilliseconds($SCRIPT:InjectionTimeoutMs)
        $found = $false
        while ((Get-Date) -lt $deadline -and -not $found) {
            Start-Sleep -Milliseconds 50
            $modules = Get-ProcessModules $proc.Id
            if ($modules -contains $SCRIPT:HookDllX86Name) {
                $found = $true
            }
        }

        return $found
    }
    catch {
        return $false
    }
    finally {
        if ($proc -and -not $proc.HasExited) {
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-AvEdrProcessesSkipped {
    <#
    .SYNOPSIS
        Verifies that known AV/EDR processes do NOT have the hook DLL
        loaded in their module list.

    .DESCRIPTION
        Checks the running processes for common AV/EDR executables:
        MsMpEng (Defender), csagent (CrowdStrike), SentinelAgent.
        If any of these processes have the hook DLL loaded, the test fails.

    .OUTPUTS
        $true if all detected AV/EDR processes are correctly skipped, $false otherwise.
    #>
    $avEdrProcesses = @(
        @{ Name = 'MsMpEng'; Display = 'Microsoft Defender' },
        @{ Name = 'csagent'; Display = 'CrowdStrike Falcon' },
        @{ Name = 'SentinelAgent'; Display = 'SentinelOne' },
        @{ Name = 'CylanceSvc'; Display = 'Cylance' },
        @{ Name = 'bdagent'; Display = 'Bitdefender' },
        @{ Name = 'mcshield'; Display = 'McAfee' }
    )

    $allSkipped = $true
    foreach ($av in $avEdrProcesses) {
        $procs = Get-Process -Name $av.Name -ErrorAction SilentlyContinue
        if ($procs) {
            foreach ($p in $procs) {
                $modules = Get-ProcessModules $p.Id
                if ($modules -contains $SCRIPT:HookDllName) {
                    Write-Result "AV/EDR process $($av.Display) ($($av.Name)) incorrectly has hook DLL loaded" 'FAIL'
                    $allSkipped = $false
                }
            }
        }
    }

    return $allSkipped
}

function Test-PplProcessesSkipped {
    <#
    .SYNOPSIS
        Verifies that PPL (Protected Process Light) processes do NOT have
        the hook DLL loaded.

    .DESCRIPTION
        Checks lsass.exe, services.exe, and csrss.exe for the hook DLL.
        These are system-critical PPL processes that must never be injected.

    .OUTPUTS
        $true if all detected PPL processes are correctly skipped, $false otherwise.
    #>
    $pplProcesses = @(
        @{ Name = 'lsass'; Display = 'LSASS' },
        @{ Name = 'services'; Display = 'Services' },
        @{ Name = 'csrss'; Display = 'CSRSS' }
    )

    $allSkipped = $true
    foreach ($ppl in $pplProcesses) {
        $procs = Get-Process -Name $ppl.Name -ErrorAction SilentlyContinue
        if ($procs) {
            foreach ($p in $procs) {
                $modules = Get-ProcessModules $p.Id
                if ($modules -contains $SCRIPT:HookDllName) {
                    Write-Result "PPL process $($ppl.Display) ($($ppl.Name)) incorrectly has hook DLL loaded" 'FAIL'
                    $allSkipped = $false
                }
            }
        }
    }

    return $allSkipped
}

function Test-StartupSweepCoverage {
    <#
    .SYNOPSIS
        Verifies that the agent's startup EnumProcesses sweep has
        injected into already-running non-allowlisted processes.

    .DESCRIPTION
        Checks a sample of running user processes (explorer, cmd, powershell)
        for the hook DLL.  At least one must have the DLL loaded to pass.

    .OUTPUTS
        $true if at least one sample process has the hook DLL, $false otherwise.
    #>
    $sampleProcesses = @('explorer', 'cmd', 'powershell')
    $foundCount = 0

    foreach ($name in $sampleProcesses) {
        $procs = Get-Process -Name $name -ErrorAction SilentlyContinue
        if ($procs) {
            foreach ($p in $procs) {
                $modules = Get-ProcessModules $p.Id
                if ($modules -contains $SCRIPT:HookDllName) {
                    $foundCount++
                    break
                }
            }
        }
    }

    if ($foundCount -gt 0) {
        return $true
    }
    return $false
}

# ─── Main ────────────────────────────────────────────────────────────────────

Write-Host "=== DLP Hook DLL Injection UAT ===" -ForegroundColor Cyan

# Validate JWT
if (-not $JwtToken) {
    Write-Error "DLP_ADMIN_JWT environment variable or -JwtToken parameter is required."
    exit 1
}

$passCount = 0
$failCount = 0

try {

    # ── New process injection test ───────────────────────────────────────────
    if (-not $SkipNewProcessTest) {
        Write-Host "`n[Test] New process injection (notepad.exe)..." -ForegroundColor Yellow

        $injected = Test-HookDllInjectedNewProcess
        if ($injected) {
            Write-Result "Hook DLL injected into new process within ${SCRIPT:InjectionTimeoutMs}ms" 'PASS'
            $passCount++
        }
        else {
            Write-Result "Hook DLL NOT injected into new process within ${SCRIPT:InjectionTimeoutMs}ms" 'FAIL'
            $failCount++
        }
    }

    # ── x86/WoW64 injection test ─────────────────────────────────────────────
    if (-not $SkipX86Test) {
        Write-Host "`n[Test] x86/WoW64 process injection..." -ForegroundColor Yellow

        $injectedX86 = Test-HookDllInjectedX86
        if ($injectedX86) {
            Write-Result "x86 hook DLL injected into WoW64 process" 'PASS'
            $passCount++
        }
        else {
            Write-Result "x86 hook DLL NOT injected into WoW64 process" 'FAIL'
            $failCount++
        }
    }

    # ── AV/EDR skip test ─────────────────────────────────────────────────────
    if (-not $SkipAvEdrTest) {
        Write-Host "`n[Test] AV/EDR process skip..." -ForegroundColor Yellow

        $avSkipped = Test-AvEdrProcessesSkipped
        if ($avSkipped) {
            Write-Result "All detected AV/EDR processes correctly skipped" 'PASS'
            $passCount++
        }
        else {
            Write-Result "One or more AV/EDR processes incorrectly injected" 'FAIL'
            $failCount++
        }
    }

    # ── PPL skip test ────────────────────────────────────────────────────────
    if (-not $SkipPplTest) {
        Write-Host "`n[Test] PPL process skip..." -ForegroundColor Yellow

        $pplSkipped = Test-PplProcessesSkipped
        if ($pplSkipped) {
            Write-Result "All detected PPL processes correctly skipped" 'PASS'
            $passCount++
        }
        else {
            Write-Result "One or more PPL processes incorrectly injected" 'FAIL'
            $failCount++
        }
    }

    # ── Startup sweep coverage test ──────────────────────────────────────────
    if (-not $SkipStartupSweepTest) {
        Write-Host "`n[Test] Startup sweep coverage..." -ForegroundColor Yellow

        $sweepOk = Test-StartupSweepCoverage
        if ($sweepOk) {
            Write-Result "Startup sweep has injected into running user processes" 'PASS'
            $passCount++
        }
        else {
            Write-Result "Startup sweep did NOT inject into sample processes" 'FAIL'
            $failCount++
        }
    }

}
finally {
    # ── Cleanup ──────────────────────────────────────────────────────────────
    Write-Host "`n[Cleanup] Terminating leftover test processes..." -ForegroundColor Yellow

    $testProcs = @('notepad')
    foreach ($name in $testProcs) {
        Get-Process -Name $name -ErrorAction SilentlyContinue |
            Where-Object { $_.Modules.ModuleName -contains $SCRIPT:HookDllName -or
                           $_.Modules.ModuleName -contains $SCRIPT:HookDllX86Name } |
            Stop-Process -Force -ErrorAction SilentlyContinue
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
