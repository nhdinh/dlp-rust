# Keep refactor versions (dlp-common AD client supersedes these)
Remove-Item dlp-server/src/ad_client.rs -Force -ErrorAction SilentlyContinue
Remove-Item dlp-server/src/bind_registry.rs -Force -ErrorAction SilentlyContinue
Remove-Item dlp-server/src/engine.rs -Force -ErrorAction SilentlyContinue
Remove-Item dlp-server/src/policy_engine_error.rs -Force -ErrorAction SilentlyContinue
Remove-Item dlp-server/src/policy_store.rs -Force -ErrorAction SilentlyContinue
Remove-Item dlp-server/tests/benchmark.rs -Force -ErrorAction SilentlyContinue
Remove-Item dlp-server/tests/integration.rs -Force -ErrorAction SilentlyContinue

# Keep master versions (Phase 07) and remove left-behind conflict markers for delete conflicts
Remove-Item docs/plans/user-stories.md -Force -ErrorAction SilentlyContinue
Remove-Item docs/task-tracker.md -Force -ErrorAction SilentlyContinue
Remove-Item docs/THREAT_MODEL.md -Force -ErrorAction SilentlyContinue

# Accept master (Phase 07) versions for all content conflicts
foreach ($f in @(
    'README.md',
    'docs/ARCHITECTURE.md',
    'docs/IMPLEMENTATION_GUIDE.md',
    'docs/MANUAL_TESTING.md',
    'docs/OPERATIONAL.md',
    'docs/SECURITY_ARCHITECTURE.md',
    'docs/SECURITY_AUDIT.md',
    'docs/SRS.md',
    'dlp-admin-cli/src/engine.rs',
    'dlp-admin-cli/src/main.rs',
    'dlp-agent/Cargo.toml',
    'dlp-agent/src/engine_client.rs',
    'dlp-agent/tests/integration.rs',
    'dlp-server/Cargo.toml',
    'dlp-server/src/admin_api.rs',
    'dlp-server/src/lib.rs',
    'dlp-server/src/main.rs'
)) {
    & git -C 'C:\Users\nhdinh\dev\DLP\dlp-rust' checkout --ours $f 2>&1 | Out-Null
}

# Stage all resolved files
& git -C 'C:\Users\nhdinh\dev\DLP\dlp-rust' add -A 2>&1 | Out-Null

Write-Output "done"