#!/usr/bin/env bash
set -euo pipefail

cargo test -p dlp-hook-dll --lib -- --test-threads=1
cargo test -p dlp-hook-dll --test pipe_client_integration -- --test-threads=1
cargo test -p dlp-hook-dll --test unhook_protocol -- --test-threads=1
cargo test -p dlp-hook-dll --test self_unload_safety -- --test-threads=1
cargo test -p dlp-hook-dll --test control_thread_integration -- --test-threads=1
cargo test -p dlp-hook-dll --test isolated_resync_recovery -- --test-threads=1
cargo test -p dlp-hook-dll --test journal_integration -- --test-threads=1
cargo test -p dlp-hook-dll --test journal_degraded_test -- --test-threads=1
cargo test -p dlp-hook-dll --test ntdll_chaos_test -- --ignored --nocapture --test-threads=1

if [ -f dlp-hook-dll/tests/journal_chaos_test.rs ]; then
    cargo test -p dlp-hook-dll --test journal_chaos_test -- --test-threads=1
fi

if command -v cargo-nextest >/dev/null 2>&1; then
    cargo nextest run -p dlp-hook-dll --lib
    cargo nextest run -p dlp-hook-dll --test pipe_client_integration
    cargo nextest run -p dlp-hook-dll --test unhook_protocol
    cargo nextest run -p dlp-hook-dll --test self_unload_safety
    cargo nextest run -p dlp-hook-dll --test control_thread_integration
    cargo nextest run -p dlp-hook-dll --test isolated_resync_recovery
    cargo nextest run -p dlp-hook-dll --test journal_integration
    cargo nextest run -p dlp-hook-dll --test journal_degraded_test
    cargo nextest run -p dlp-hook-dll --test ntdll_chaos_test -- --ignored
    if [ -f dlp-hook-dll/tests/journal_chaos_test.rs ]; then
        cargo nextest run -p dlp-hook-dll --test journal_chaos_test
    fi
fi
