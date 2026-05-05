# M003: Operational Hardening (v0.3.0)

**Vision:** Establish production-grade operational foundations — AD identity, rate limiting, audit pipeline, connection pooling, and policy engine isolation.

## Success Criteria

- Agents authenticate via AD LDAP with group resolution
- Server APIs are rate-limited per agent
- Audit events are structured, persisted, and queryable
- SQLite pool handles concurrent agent connections without contention
- Policy engine is a standalone testable module

## Slices

- [x] **S01: AD LDAP client** `risk:high` `depends:[]`
  > After this: Server resolves AD user/group identity for policy evaluation
- [x] **S02: Rate limiting middleware** `risk:medium` `depends:[]`
  > After this: Server APIs reject excess requests per agent with proper 429 responses
- [x] **S03: Audit logging pipeline** `risk:medium` `depends:[]`
  > After this: All DLP events flow through structured audit with persistence
- [x] **S04: SQLite connection pool** `risk:low` `depends:[]`
  > After this: Database handles concurrent agent load without lock contention
- [x] **S05: Policy engine separation** `risk:medium` `depends:[S01]`
  > After this: Policy engine is a standalone module with clean API boundaries
