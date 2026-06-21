#Requires -Version 5.1
<#
.SYNOPSIS
    Injects a CRIT-04 benchmark JSON result into the v0.10.0 UAT markdown file.

.DESCRIPTION
    Reads a benchmark result JSON file produced by Uat-Benchmark.ps1 and
    updates the CRIT-04 results table in .planning/milestones/v0.10.0-UAT.md.
    If no UAT file exists yet, a template is created from the embedded
    skeleton.

    The script preserves the rest of the markdown and only replaces the
    Group 8 (CRIT-04 Benchmark) section.

.EXAMPLE
    .\Uat-Benchmark-Record.ps1 -ResultJson "C:\ProgramData\DLP\logs\uat-benchmark-20260621-120000.json"

.EXAMPLE
    .\Uat-Benchmark-Record.ps1 -ResultJson .\uat-benchmark.json -UatPath .\..\..\.planning\milestones\v0.10.0-UAT.md
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ResultJson,

    [Parameter()]
    [string]$UatPath = "$PSScriptRoot\..\.planning\milestones\v0.10.0-UAT.md"
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Format-WorkloadRow {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$WorkloadResult
    )

    $name = switch ($WorkloadResult.Workload) {
        'cargo'  { '`cargo build --workspace --release`' }
        'office' { 'Office app launch' }
        default  { $WorkloadResult.Workload }
    }

    $baseline = "{0:F2}s" -f $WorkloadResult.BaselineMedian
    $hooked   = "{0:F2}s" -f $WorkloadResult.HookedMedian
    $overhead = "{0:F1}%" -f $WorkloadResult.OverheadPercent
    $status   = if ($WorkloadResult.Passed) { 'PASS' } else { 'FAIL' }
    $notes    = if ($WorkloadResult.Passed) {
        "Within $($WorkloadResult.OverheadPercent)% overhead threshold"
    }
    else {
        "Overhead $($WorkloadResult.OverheadPercent)% exceeds threshold"
    }

    return "| $name | $baseline | $hooked | $overhead | $status | $notes |"
}

# ── Load result JSON ─────────────────────────────────────────────────────────

if (-not (Test-Path -LiteralPath $ResultJson)) {
    throw "Result JSON not found: $ResultJson"
}

$data = Get-Content -LiteralPath $ResultJson -Raw | ConvertFrom-Json

$threshold = $data.threshold_percent
$runs      = $data.runs
$timestamp = $data.timestamp

# ── Build new Group 8 section ────────────────────────────────────────────────

$rows = $data.results | ForEach-Object { Format-WorkloadRow -WorkloadResult $_ }

$passCount = @($data.results | Where-Object { $_.Passed }).Count
$failCount = @($data.results | Where-Object { -not $_.Passed }).Count
$overall   = if ($failCount -eq 0) { 'PASS' } else { 'FAIL' }

$newSection = @"
### Group 8: CRIT-04 Benchmark (BM-01..BM-02)

**Recorded:** $timestamp
**Threshold:** <= $threshold% overhead
**Measured runs per workload:** $runs
**Overall:** $overall

| Workload | Baseline median | Hooked median | Overhead | Status | Notes |
| -------- | --------------- | ------------- | -------- | ------ | ----- |
$($rows -join "`n")

"@

# ── Read or create UAT file ──────────────────────────────────────────────────

$uatContent = ''
if (Test-Path -LiteralPath $UatPath) {
    $uatContent = Get-Content -LiteralPath $UatPath -Raw
}
else {
    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $uatContent = @"
# UAT Results -- DLP v0.10.0

This document captures the User Acceptance Test results for the DLP v0.10.0
milestone.  Results are populated automatically by `scripts/Uat-Benchmark.ps1`
and `scripts/Uat-Benchmark-Record.ps1`.

## Test Environment

| Field         | Value |
| ------------- | ----- |
| Host OS       |       |
| Host Hardware |       |
| CPU           |       |
| RAM           |       |
| EDR Installed |       |
| DLP Version   | v0.10.0 |
| Test Date     |       |
| Tester        |       |

## Results by Group

"@
}

# ── Replace or insert Group 8 section ────────────────────────────────────────

$pattern = '### Group 8: CRIT-04 Benchmark.*?(?=\r?\n## |\r?\n### Group |\Z)'
$singleLine = [System.Text.RegularExpressions.RegexOptions]::Singleline
if ([regex]::Match($uatContent, $pattern, $singleLine).Success) {
    $uatContent = [regex]::Replace($uatContent, $pattern, $newSection, $singleLine)
    Write-Host "Updated existing Group 8 section in $UatPath" -ForegroundColor Green
}
else {
    # Append before the first "## " that is not the title, or at the end.
    $insertPattern = '\r?\n## [^#]'
    if ([regex]::Match($uatContent, $insertPattern, $singleLine).Success) {
        $uatContent = [regex]::Replace($uatContent, $insertPattern, "`n$newSection`n`$0", $singleLine)
    }
    else {
        $uatContent += "`n$newSection`n"
    }
    Write-Host "Appended new Group 8 section to $UatPath" -ForegroundColor Green
}

# ── Write updated UAT file ───────────────────────────────────────────────────

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($UatPath, $uatContent, $utf8NoBom)

Write-Host "UAT markdown updated: $UatPath" -ForegroundColor Green
Write-Host "Overall benchmark result: $overall ($passCount PASS, $failCount FAIL)" -ForegroundColor $(if ($overall -eq 'PASS') { 'Green' } else { 'Red' })
