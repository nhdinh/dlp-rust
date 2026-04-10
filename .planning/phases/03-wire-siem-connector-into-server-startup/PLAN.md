# Phase 3 Plan: Wire SIEM Connector into Server Startup

## Problem

`siem_connector.rs` is fully implemented (Splunk HEC + ELK relay) but never instantiated or called. Audit events are stored in SQLite but never forwarded to external SIEM platforms.

## Approach

1. Create a shared `AppState` struct that holds both the `Database` and `SiemConnector`.
2. Initialize `SiemConnector::from_env()` at server startup.
3. After audit events are ingested into SQLite, relay them to configured SIEM backends (best-effort, non-blocking).
4. Use the existing `admin_router` pattern — just change the state type from `Arc<Database>` to `Arc<AppState>`.

## Files to Modify

- `dlp-server/src/main.rs` — create AppState, initialize SiemConnector
- `dlp-server/src/lib.rs` — define AppState struct
- `dlp-server/src/admin_api.rs` — update State extractor from `Arc<Database>` to `Arc<AppState>`
- `dlp-server/src/audit_store.rs` — after DB insert, spawn SIEM relay task
- `dlp-server/src/agent_registry.rs` — update State extractor
- `dlp-server/src/exception_store.rs` — update State extractor
- `dlp-server/src/admin_auth.rs` — update State extractor

## Implementation Steps

### Step 1: Define AppState in lib.rs

```rust
pub struct AppState {
    pub db: Database,
    pub siem: SiemConnector,
}
```

### Step 2: Initialize in main.rs

```rust
let siem = SiemConnector::from_env();
let state = Arc::new(AppState { db, siem });
```

### Step 3: Update all handlers

Replace `State(db): State<Arc<Database>>` with `State(state): State<Arc<AppState>>` and use `state.db` where `db` was used.

### Step 4: Add SIEM relay in audit_store::ingest_events

After the DB insert succeeds, spawn a background task:
```rust
let siem = state.siem.clone();
tokio::spawn(async move {
    if let Err(e) = siem.relay_events(&events).await {
        tracing::warn!(error = %e, "SIEM relay failed (best-effort)");
    }
});
```

## Verification

- `cargo test --package dlp-server --lib` passes
- `cargo clippy --workspace -- -D warnings` clean
- Server starts with no SIEM env vars (inert connector, no errors)
- Server starts with SIEM env vars and logs "Splunk HEC relay enabled" / "ELK relay enabled"

## UAT Criteria

- [x] Server starts without SIEM env vars — no errors, connector is inert
- [ ] ~~With SPLUNK_HEC_URL + SPLUNK_HEC_TOKEN set, startup logs show relay enabled~~ — **SUPERSEDED** by Phase 3.1 (see addendum)
- [x] Audit events ingested via POST /audit/events are relayed to configured backends — verified via `audit_store.rs:145-150`
- [x] SIEM relay failures are logged but don't fail the ingest request — `tracing::warn!` + fire-and-forget `tokio::spawn`

## Addendum — Superseded by Phase 3.1 (2026-04-10)

This plan was executed as commit `30ccaaf` (feat: wire SIEM connector into server startup, Phase 3, R-01), but the env-var configuration mechanism it prescribed was **superseded the same day** by Phase 3.1 (`.planning/phases/03.1-siem-config-in-db/`). The user's explicit decision during Phase 3.1 discuss: SIEM (and similar operator-tunable) configuration must live in the SQLite database and be managed via admin REST endpoints + dlp-admin-cli TUI — **not** env vars. Rationale captured in `.planning/phases/03.1-siem-config-in-db/CONTEXT.md`.

**What was kept from Phase 3 (still in the codebase):**

- `AppState { db, siem }` struct in `dlp-server/src/lib.rs` — shared axum state
- Handler refactor from `State<Arc<Database>>` to `State<Arc<AppState>>` across `admin_api.rs`, `admin_auth.rs`, `agent_registry.rs`, `exception_store.rs`
- Best-effort background SIEM relay in `audit_store::ingest_events` — `tokio::spawn` fire-and-forget after the DB insert, with `tracing::warn!` on failure
- End-to-end wiring: audit event → DB insert → spawn relay task

**What Phase 3.1 replaced:**

- `SiemConnector::from_env()` → `SiemConnector::new(db: Arc<Database>)`
- Env-var loading (`SPLUNK_HEC_URL`, `SPLUNK_HEC_TOKEN`, `ELK_URL`, `ELK_INDEX`, `ELK_API_KEY`) → `siem_config` SQLite table with hot-reload on every relay
- No admin interface → `GET/PUT /admin/siem-config` + dlp-admin-cli TUI screen under System menu

Phase 3 is therefore marked complete on its **foundation contributions** (AppState + relay plumbing), and the config-loading half of its UAT is marked superseded. The actual "SIEM is wired and usable in production" deliverable is tracked in Phase 3.1's SUMMARY.md and VERIFICATION.md.
