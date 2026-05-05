# M003: Operational Hardening (v0.3.0)

**Gathered:** 2026-04-13
**Status:** Closed (shipped 2026-04-16)

## Project Description

Operational hardening of the DLP infrastructure — AD LDAP integration, rate limiting, audit logging pipeline, SQLite connection pooling, and policy engine separation.

## Why This Milestone

The system needed production-grade operational foundations: real AD integration for identity resolution, rate limiting to prevent abuse, structured audit logging for compliance, connection pooling for database performance, and clean separation of the policy engine for testability.

## User-Visible Outcome

### When this milestone is complete, the user can:

- Authenticate agents via AD LDAP
- See structured audit events flowing to the audit store
- Rely on rate limiting protecting the server APIs
- Benefit from SQLite pool performance under concurrent agent load

### Entry point / environment

- Entry point: DLP Server APIs + Agent registration
- Environment: Windows Server with AD
- Live dependencies involved: Active Directory (LDAP), SQLite database

## Scope

### In Scope

- AD LDAP client integration
- Rate limiting middleware
- Structured audit logging pipeline
- SQLite connection pool
- Policy engine extraction from monolith

### Out of Scope / Non-Goals

- Multi-tenant support
- Cloud-hosted server deployment
- SAML/OAuth federation
