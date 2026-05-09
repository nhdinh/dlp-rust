# S01: Core Features and Infrastructure (Phases 0.1-6)

**Goal:** Fix critical runtime issues, harden auth, and wire core server infrastructure.
**Demo:** Clipboard monitoring runtime pipeline fixed. Integration tests compile and pass. JWT_SECRET required in production. SIEM connector wired. Alert router wired. Agent config distribution via polling.

## Must-Haves

- 1. Clipboard monitoring produces runtime alerts
- 2. cargo test --workspace passes
- 3. JWT_SECRET required in prod (--dev flag)
- 4. SIEM relay hot-reloads from DB
- 5. Alert router sends email/webhook
- 6. Agent config polls and persists to TOML

## Proof Level

- This slice proves: tested

## Integration Closure

Foundation for all v0.3.0+ operational hardening.

## Verification

- Audit events relayed to SIEM. Alerts sent via email/webhook.

## Tasks

- [x] **T01: Core features and infrastructure** `est:12h`
  Fix clipboard monitoring runtime pipeline (WorkerGuard lifetime, UI subscriber stderr, tracing_appender IO errors, pipe name backslashes). Fix integration tests. Require JWT_SECRET in production with --dev flag. Wire SIEM connector into server startup with AppState { db, siem }. Move SIEM config to DB with admin TUI. Wire alert router with DB-backed config and email/webhook. Wire agent config distribution via polling with TOML persistence.
  - Files: `dlp-agent/src/service.rs`, `dlp-user-ui/src/app.rs`, `dlp-server/src/lib.rs`, `dlp-server/src/siem_connector.rs`, `dlp-server/src/alert_router.rs`, `dlp-agent/src/config.rs`
  - Verify: cargo test --workspace

## Files Likely Touched

- dlp-agent/src/service.rs
- dlp-user-ui/src/app.rs
- dlp-server/src/lib.rs
- dlp-server/src/siem_connector.rs
- dlp-server/src/alert_router.rs
- dlp-agent/src/config.rs
