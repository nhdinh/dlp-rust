# M015: v0.3.0 Operational Hardening

**Vision:** Harden the v0.2.0 foundation with Active Directory integration, rate limiting, admin audit logging, SQLite connection pooling, and policy engine separation with cache invalidation.

## Success Criteria

- All 10 requirements validated (R-03, R-05, R-07, R-09, R-10 plus v0.2.0 requirements)
- AD LDAP integration working
- Rate limiting working
- Admin audit logging working
- SQLite connection pool working
- Policy engine separation working
- Repository refactor complete

## Slices

- [x] **S01: S01** `risk:Low — shipped 2026-04-16.` `depends:[]`
  > After this: AD group membership, device trust, and network location resolved via LDAP with configurable TTL cache.

- [x] **S02: S02** `risk:Low — shipped 2026-04-16.` `depends:[]`
  > After this: Rate limiting on login, heartbeat, event ingestion, and policy CRUD with 429 responses.

- [x] **S03: S03** `risk:Low — shipped 2026-04-16.` `depends:[]`
  > After this: Policy CRUD and password changes emit AuditEvent with EventType::AdminAction. Queryable via API.

- [x] **S04: S04** `risk:Low — shipped 2026-04-16.` `depends:[]`
  > After this: r2d2 SQLite connection pool replaces single Mutex<Connection>. Concurrent requests execute in parallel.

- [x] **S05: S05** `risk:Low — shipped 2026-04-16.` `depends:[]`
  > After this: PolicyStore with in-memory cache, sync evaluate(), tiered default-deny, cache invalidation on CRUD, background refresh every 5 min.

- [x] **S06: S06** `risk:Low — shipped 2026-04-16.` `depends:[]`
  > After this: 49 raw SQL call sites migrated to typed Repository structs. All writes go through UnitOfWork RAII transaction.

## Boundary Map

Not provided.
