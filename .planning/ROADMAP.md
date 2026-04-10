# ROADMAP.md — v0.2.0 Feature Completion

## Milestone: v0.2.0

### Phase 1: Fix integration tests
**Requirement:** R-06
**Files:** `dlp-agent/tests/integration.rs`
**Description:** Update broken integration tests that reference removed dlp_server modules. Make `cargo test --workspace` compile cleanly.
**UAT:** `cargo test --workspace` passes with zero compilation errors.

### Phase 2: Require JWT_SECRET in production
**Requirement:** R-08
**Files:** `dlp-server/src/admin_auth.rs`, `dlp-server/src/main.rs`
**Description:** Remove hardcoded dev fallback. Add `--dev` flag to allow insecure secret in development only. Fail on startup otherwise.
**UAT:** Server refuses to start without JWT_SECRET (no --dev flag). Server starts with --dev flag and warns.

### Phase 3: Wire SIEM connector into server startup
**Requirement:** R-01
**Files:** `dlp-server/src/main.rs`, `dlp-server/src/siem_connector.rs`, `dlp-server/src/audit_store.rs`
**Description:** Initialize SiemConnector from env vars at startup. After audit events are ingested, relay them to configured SIEM endpoints.
**UAT:** With SIEM env vars set, audit events are forwarded to Splunk/ELK endpoints.

### Phase 4: Wire alert router into server
**Requirement:** R-02
**Files:** `dlp-server/src/main.rs`, `dlp-server/src/alert_router.rs`, `dlp-server/src/audit_store.rs`
**Description:** Initialize AlertRouter from env vars at startup. Route DenyWithAlert audit events to configured email/webhook destinations.
**UAT:** DenyWithAlert events trigger email/webhook notifications when configured.

### Phase 5: Wire policy sync for multi-replica
**Requirement:** R-03
**Files:** `dlp-server/src/main.rs`, `dlp-server/src/policy_sync.rs`, `dlp-server/src/admin_api.rs`
**Description:** Initialize PolicySyncer from env vars. Call sync on policy create/update/delete.
**UAT:** Policy changes propagate to peer servers listed in DLP_REPLICA_URLS.

### Phase 6: Wire config push for agent config distribution
**Requirement:** R-04
**Files:** `dlp-server/src/main.rs`, `dlp-server/src/config_push.rs`, `dlp-server/src/admin_api.rs`
**Description:** Add admin API endpoint for pushing config updates. Agents poll for config changes on heartbeat.
**UAT:** Admin can push updated monitored_paths via API; agent picks up changes.

### Phase 7: Active Directory LDAP integration
**Requirement:** R-05
**Depends on:** Phase 2
**Files:** `dlp-agent/src/identity.rs`, `dlp-common/src/abac.rs`, new `dlp-agent/src/ad_client.rs`
**Description:** Implement LDAP client using `ldap3` crate. Query AD for user group membership, device trust level, and network location. Replace placeholder values in ABAC evaluation requests.
**UAT:** ABAC evaluation uses real AD group membership for policy decisions.

### Phase 8: Rate limiting middleware
**Requirement:** R-07
**Files:** `dlp-server/src/main.rs`, `dlp-server/Cargo.toml`
**Description:** Add tower-governor or custom rate limiting middleware. Apply to /auth/login (strict), heartbeat (moderate), event ingestion (per-agent).
**UAT:** Rapid-fire login attempts are throttled with 429 responses.

### Phase 9: Admin operation audit logging
**Requirement:** R-09
**Files:** `dlp-server/src/admin_api.rs`, `dlp-server/src/audit_store.rs`
**Description:** Emit audit events for policy CRUD and admin password changes. Store in audit_events table with EventType::AdminAction.
**UAT:** Policy create/update/delete appear as audit events queryable via GET /audit/events.

### Phase 10: SQLite connection pool
**Requirement:** R-10
**Files:** `dlp-server/src/db.rs`, `dlp-server/Cargo.toml`
**Description:** Replace Mutex<Connection> with r2d2-sqlite connection pool. Update all handlers to use pool.get() instead of conn().lock().
**UAT:** Concurrent API requests execute without serializing on a single mutex. Existing tests pass.
