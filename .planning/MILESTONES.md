# Milestones

## v0.2.0 Feature Completion (Shipped: 2026-04-13)

**Phases completed:** 9 | **Plans:** 14 | **Days:** ~4

**Key accomplishments:**

- **Clipboard monitoring fixed end-to-end** — 4 compounding root causes resolved (WorkerGuard lifetime, stderr vs tracing, tracing_appender silent swallows, PIPE_NAME_DEFAULT backslash count)
- **364+ workspace tests passing** — integration tests migrated to self-contained mock axum engine; no removed `dlp_server` module references
- **JWT_SECRET production-hardened** — server refuses to start without `JWT_SECRET`; `--dev` flag enables dev mode with prominent warning
- **SIEM relay wired + DB-backed** — Splunk HEC + ELK, hot-reload on every relay, `GET/PUT /admin/siem-config`, dlp-admin-cli TUI screen (Phase 3 + 3.1)
- **Alert router wired + DB-backed** — SMTP + webhook, loopback URL validation at PUT time, fire-and-forget, dlp-admin-cli TUI screen (Phase 4)
- **Agent config polling wired** — DB-backed global + per-agent override, `GET /agent-config/{id}` unauthenticated resolution, TOML write-back, poll loop in service.rs (Phase 6)
- **32 agent TCs + 15 server TCs + 6 E2E pipeline tests** — Phase 04.1 wave-based TDD: unit → server → E2E

**Deferred to v0.3.0:** AD LDAP (R-05), rate limiting (R-07), admin audit logging (R-09), SQLite pool (R-10), Policy Engine Separation (R-03)

**Human UAT items still open:**
- Live SMTP email delivery (Phase 4)
- Live webhook POST (Phase 4)
- Hot-reload through HTTP + TUI (Phase 4)
- Live agent TOML write-back (Phase 6)
- Zero-warning workspace build (Phase 6)

---

## v0.3.0 Operational Hardening (Shipped: 2026-04-16)

**Phases completed:** 6 | **Plans:** 14 | **Days:** ~3

**Key accomplishments:**

- **Active Directory LDAP integration** — real ABAC attribute resolution via `ldap3`; channel-based async AdClient with machine-account Kerberos TGT bind, transitive group membership via `tokenGroups`, device trust via `NetGetJoinInformation`, fail-open on AD unavailability (Phase 7)
- **Rate limiting middleware** — `tower-governor` with 5 per-route configs (5/min login, 200/min event ingestion, 60/min policy CRUD); required axum 0.7 → 0.8 upgrade (Phase 8)
- **Admin operation audit logging** — policy CRUD + password changes persisted as `EventType::AdminAction` audit events; 4 integration tests verifying exact SQLite contents (Phase 9)
- **SQLite connection pool** — `r2d2`/`r2d2_sqlite` replacing single `Mutex<Connection>`; `AppState` derives `Clone`; 220 workspace tests pass (Phase 10)
- **Policy Engine Separation** — `PolicyStore` with `parking_lot::RwLock`, sync hot-path `evaluate()`, 23 unit tests, cache invalidation on every policy CRUD, 5-min background refresh (Phase 11)
- **Repository + Unit of Work refactor** — 49 `pool.get()` + raw SQL call sites migrated into 10 typed Repository structs; all writes via `UnitOfWork<'conn>` RAII transaction; net -109 lines in admin_api.rs (Phase 99)

**All 5 deferred v0.2.0 requirements validated:** R-03, R-05, R-07, R-09, R-10

---
