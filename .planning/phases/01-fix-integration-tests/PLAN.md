# Phase 1 Plan: Fix Integration Tests

## Problem

`dlp-agent/tests/integration.rs` references removed `dlp_server` modules:
- `dlp_server::engine::AbacEngine` (removed)
- `dlp_server::policy_store::PolicyStore` (removed)
- `dlp_server::policy_api::router` (removed)

This causes `cargo test --workspace` to fail with compilation errors.

## Approach

Replace `start_real_engine()` with a lightweight mock axum server that:
1. Serves `POST /evaluate` — matches policies by classification and returns a decision
2. Serves `GET /health` — returns 200 OK
3. Uses inline policy rules (no file-based policy store needed)

The mock uses only `axum` and `dlp-common` types (already in dev-dependencies).

## Files to Modify

- `dlp-agent/tests/integration.rs` — rewrite `start_real_engine()` to use a self-contained mock server

## Implementation Steps

### Step 1: Rewrite `start_real_engine()`

Replace the function that references removed modules with a mock:

```rust
async fn start_mock_engine() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    // Inline policy evaluation: 
    //   T4 WRITE -> DENY (pol-001)
    //   T3/T4 COPY -> DENY (pol-002)  
    //   T2 READ -> AllowWithLog (pol-003)
    //   else -> ALLOW
    let app = Router::new()
        .route("/evaluate", post(mock_evaluate))
        .route("/health", get(|| async { "ok" }));
    // ...
}
```

### Step 2: Update test references

Replace `start_real_engine()` calls with `start_mock_engine()`.

### Step 3: Remove unused dlp-server dev-dependency

If `dlp-server` is no longer used in any test file, remove it from `[dev-dependencies]`.

## Verification

- `cargo test --workspace` compiles with zero errors
- `cargo test --package dlp-agent --test integration` passes
- `cargo clippy --workspace -- -D warnings` clean

## UAT Criteria

- [x] `cargo test --workspace` passes with no compilation errors
- [x] Integration test `test_agent_to_real_engine_e2e` still validates T4 WRITE -> DENY and T2 READ -> AllowWithLog
- [x] No references to removed dlp_server modules remain

## Addendum — Gap closure after re-verification (2026-04-10)

Re-running `cargo test --workspace` after the original commit `8c62fec`
surfaced two additional compile errors in `dlp-agent/tests/comprehensive.rs`
that the original plan did not cover: the `AgentConfig` struct literal at
lines 354 and 369 were missing the `server_url: Option<String>` field that
Phase 0 added. `tests/integration.rs` also had an unused `extract::Json`
import in `start_policy_engine` (the body uses the fully-qualified
`axum::extract::Json` and `axum::Json` instead).

Closure actions:
1. Added `server_url: None` to both `AgentConfig { ... }` initializers in
   `dlp-agent/tests/comprehensive.rs`.
2. Removed the unused `extract::Json` from the import list inside
   `start_policy_engine()` in `dlp-agent/tests/integration.rs`.

Post-closure state: `cargo test` from the workspace root returns 364/364
passing across all 15 test binaries — see VERIFICATION.md for the full
breakdown.
