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
