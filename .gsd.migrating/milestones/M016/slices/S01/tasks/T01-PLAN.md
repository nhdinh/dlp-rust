---
estimated_steps: 1
estimated_files: 6
skills_used: []
---

# T01: Core features and infrastructure

Fix clipboard monitoring runtime pipeline (WorkerGuard lifetime, UI subscriber stderr, tracing_appender IO errors, pipe name backslashes). Fix integration tests. Require JWT_SECRET in production with --dev flag. Wire SIEM connector into server startup with AppState { db, siem }. Move SIEM config to DB with admin TUI. Wire alert router with DB-backed config and email/webhook. Wire agent config distribution via polling with TOML persistence.

## Inputs

- `Existing server infrastructure`
- `Win32 pipe APIs`

## Expected Output

- `Clipboard fix`
- `Integration tests passing`
- `JWT auth hardening`
- `SIEM connector`
- `Alert router`
- `Agent config poll loop`

## Verification

cargo test --workspace
