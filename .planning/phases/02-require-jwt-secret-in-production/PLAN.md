# Phase 2 Plan: Require JWT_SECRET in Production

## Problem

`admin_auth.rs` falls back to a hardcoded dev secret (`"dlp-server-dev-secret-change-me"`) when `JWT_SECRET` is not set. This is a security risk — if an operator forgets to set the env var, the server runs with a known secret and any attacker can forge JWT tokens.

## Approach

1. Add a `--dev` CLI flag to `dlp-server` that enables the insecure fallback.
2. Without `--dev`, require `JWT_SECRET` env var — fail on startup if unset.
3. When `--dev` is active, log a prominent warning at startup.

## Files to Modify

- `dlp-server/src/admin_auth.rs` — change `jwt_secret()` to accept a `dev_mode` parameter
- `dlp-server/src/main.rs` — add `--dev` flag, validate JWT_SECRET before serving, pass dev_mode to auth

## Implementation Steps

### Step 1: Update `jwt_secret()` in `admin_auth.rs`

Change from:
```rust
fn jwt_secret() -> String {
    std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "dlp-server-dev-secret-change-me".to_string())
}
```

To:
```rust
pub fn jwt_secret(dev_mode: bool) -> Result<String, String> {
    match std::env::var("JWT_SECRET") {
        Ok(s) if !s.is_empty() => Ok(s),
        _ if dev_mode => {
            tracing::warn!("using insecure dev JWT secret (--dev mode)");
            Ok("dlp-server-dev-secret-change-me".to_string())
        }
        _ => Err("JWT_SECRET env var is required. Set it or use --dev for development.".to_string()),
    }
}
```

Store the resolved secret in server state so it doesn't re-read env on every request.

### Step 2: Add `--dev` flag to `main.rs`

Add `dev_mode: bool` to `Config`. Parse `--dev` from args. Update help text.

### Step 3: Validate JWT_SECRET at startup

After parsing config, call `jwt_secret(config.dev_mode)`. If it returns Err, print the error and exit.

### Step 4: Pass the secret through server state

Store the JWT secret string in the axum Router state so `login()`, `verify_jwt()`, and `require_auth()` use it instead of calling `jwt_secret()` on every request.

## Verification

- `cargo test --package dlp-server --lib` passes
- Server refuses to start without JWT_SECRET (no --dev)
- Server starts with --dev and warns
- Server starts with JWT_SECRET set

## UAT Criteria

- [ ] Server refuses to start without JWT_SECRET and without --dev
- [ ] Server starts with --dev flag and logs a warning
- [ ] Server starts normally when JWT_SECRET is set
- [ ] Existing auth tests pass
