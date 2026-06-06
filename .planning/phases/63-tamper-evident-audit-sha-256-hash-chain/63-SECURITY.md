---
phase: 63
slug: tamper-evident-audit-sha-256-hash-chain
status: verified
threats_open: 0
asvs_level: 1
created: 2026-06-06
---

# Phase 63 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| SQLite audit_events table | Persistent tamper-evident storage boundary | Audit events with SHA-256 hash chain |
| Repository layer | SQL injection boundary (parameterized queries) | Pre-serialized AuditEventRow |
| Agent JSONL file | Local tamper-evident log boundary — protected by NTFS ACLs | JSONL lines with prev_hash/chain_hash |
| Agent memory (last_chain_hash) | Runtime chain head boundary | SHA-256 hex string |
| Ingestion handler | Validates chain before DB commit | AuditEvent batch |
| Alert router | Distributes tamper alerts to configured channels | ChainBreakDetected events |
| Admin API | Requires JWT authentication; only admins can request integrity reports | Integrity report JSON |
| Integrity handler | Read-only re-verification of stored events | Chain break list, per-agent status |

---

## Threat Register

| Threat ID | Category | Component | Disposition | Mitigation | Status |
|-----------|----------|-----------|-------------|------------|--------|
| T-63-01 | Tampering | audit_events table | mitigate | Hash chain verification in Plan 03 detects unauthorized modification at ingestion time | closed |
| T-63-02 | Information Disclosure | chain_hash column | accept | Hash values are not sensitive; derived from non-secret event data | closed |
| T-63-03 | Denial of Service | Migration failure on startup | mitigate | `run_alter` is idempotent and swallows duplicate-column errors | closed |
| T-63-03b | Denial of Service | get_chain_breaks full-table scan on large DB | mitigate | Window-function query with `since_id` + `limit` pagination; partial index on `chain_hash IS NOT NULL` | closed |
| T-63-04 | Tampering | JSONL file modification | mitigate | Server-side verification in Plan 03 detects breaks on ingestion | closed |
| T-63-05 | Denial of Service | compute_chain_hash failure | mitigate | Errors are propagated as AuditError and logged without blocking enforcement | closed |
| T-63-06 | Information Disclosure | chain_hash in JSONL | accept | Hash is derived from non-secret event metadata | closed |
| T-63-07 | Tampering | Modified event payload | mitigate | compute_chain_hash verifies event integrity | closed |
| T-63-08 | Tampering | Reordered/deleted events | mitigate | prev_hash continuity check detects gaps | closed |
| T-63-09 | Denial of Service | Verification panics on malformed JSON | mitigate | compute_chain_hash returns Result; events that fail hash computation are flagged as chain breaks and rejected | closed |
| T-63-09b | Denial of Service | Alert storm from repeated chain breaks | mitigate | Deduplicate alerts per (agent_id, expected_prev_hash) per batch | closed |
| T-63-10 | Elevation of Privilege | Alert router spoofing | accept | AlertRouter is an internal trusted service; no external caller can inject alerts | closed |
| T-63-11 | Information Disclosure | Integrity report to unauthorized caller | mitigate | Route is registered under JWT-protected admin router | closed |
| T-63-12 | Denial of Service | Large audit table causes slow report | mitigate | Default limit=10_000, max limit=100_000, optional `since` param for time-bounded queries; spawn_blocking keeps async reactor responsive | closed |
| T-63-13 | Tampering | Report itself is not signed | accept | Report is an API view derived from the tamper-evident DB; the underlying hashes are protected | closed |

*Status: open · closed*
*Disposition: mitigate (implementation required) · accept (documented risk) · transfer (third-party)*

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| R-63-01 | T-63-02 | Hash values are not sensitive; they are derived from non-secret event data. No encryption or access control beyond standard DB permissions is required. | Plan 63-01 | 2026-06-06 |
| R-63-02 | T-63-06 | Hash in JSONL is derived from non-secret event metadata. The JSONL file is protected by NTFS ACLs. | Plan 63-02 | 2026-06-06 |
| R-63-03 | T-63-10 | AlertRouter is an internal trusted service; no external caller can inject alerts. All alert events originate from within the server's own chain verification logic. | Plan 63-03 | 2026-06-06 |
| R-63-04 | T-63-13 | Report is an API view derived from the tamper-evident DB; the underlying hashes are protected by the chain itself. Signing the report would add complexity without meaningful security gain since the report can be re-generated at any time from the protected source data. | Plan 63-04 | 2026-06-06 |

*Accepted risks do not resurface in future audit runs.*

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-06-06 | 14 | 14 | 0 | gsd-security-auditor |

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-06-06
