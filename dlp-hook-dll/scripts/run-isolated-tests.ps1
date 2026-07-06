# dlp-hook-dll/scripts/run-isolated-tests.ps1
$ErrorActionPreference = "Stop"

function Run-Test {
    param([string]$Command)
    Write-Host "Running: $Command"
    Invoke-Expression $Command
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed: $Command"
    }
}

# Library tests: serial to avoid pipe/global-state collisions.
Run-Test "cargo test -p dlp-hook-dll --lib -- --test-threads=1"

# Integration tests: each is already a separate process, but still force
# single-threaded execution inside each binary to keep global Windows state sane.
Run-Test "cargo test -p dlp-hook-dll --test pipe_client_integration -- --test-threads=1"
Run-Test "cargo test -p dlp-hook-dll --test unhook_protocol -- --test-threads=1"
Run-Test "cargo test -p dlp-hook-dll --test self_unload_safety -- --test-threads=1"
Run-Test "cargo test -p dlp-hook-dll --test control_thread_integration -- --test-threads=1"
Run-Test "cargo test -p dlp-hook-dll --test isolated_resync_recovery -- --test-threads=1"
Run-Test "cargo test -p dlp-hook-dll --test journal_integration -- --test-threads=1"
Run-Test "cargo test -p dlp-hook-dll --test journal_degraded_test -- --test-threads=1"

# ntdll_chaos_test patches ntdll .text and is #[ignore] by default.
Run-Test "cargo test -p dlp-hook-dll --test ntdll_chaos_test -- --ignored --nocapture --test-threads=1"

# journal_chaos_test will be created/moved as part of this plan.
$journalChaos = "dlp-hook-dll/tests/journal_chaos_test.rs"
if (Test-Path $journalChaos) {
    Run-Test "cargo test -p dlp-hook-dll --test journal_chaos_test -- --test-threads=1"
}

# Optional: process-level isolation via cargo nextest.
if (Get-Command cargo-nextest -ErrorAction SilentlyContinue) {
    Run-Test "cargo nextest run -p dlp-hook-dll --lib"
    Run-Test "cargo nextest run -p dlp-hook-dll --test pipe_client_integration"
    Run-Test "cargo nextest run -p dlp-hook-dll --test unhook_protocol"
    Run-Test "cargo nextest run -p dlp-hook-dll --test self_unload_safety"
    Run-Test "cargo nextest run -p dlp-hook-dll --test control_thread_integration"
    Run-Test "cargo nextest run -p dlp-hook-dll --test isolated_resync_recovery"
    Run-Test "cargo nextest run -p dlp-hook-dll --test journal_integration"
    Run-Test "cargo nextest run -p dlp-hook-dll --test journal_degraded_test"
    Run-Test "cargo nextest run -p dlp-hook-dll --test ntdll_chaos_test -- --ignored"
    if (Test-Path $journalChaos) {
        Run-Test "cargo nextest run -p dlp-hook-dll --test journal_chaos_test"
    }
} else {
    Write-Host "cargo-nextest not found; skipping nextest isolation run"
}
