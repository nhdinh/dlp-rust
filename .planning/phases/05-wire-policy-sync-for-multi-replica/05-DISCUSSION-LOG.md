# Phase 5: Wire Policy Sync for Multi-Replica — Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-11
**Phase:** 05-wire-policy-sync-for-multi-replica
**Areas discussed:** Replica config source

---

## Replica Config Source

| Option | Description | Selected |
|--------|-------------|----------|
| Env var (`DLP_SERVER_REPLICAS`) | As described in current ROADMAP.md | |
| DB-backed (single-row table, hot-reload) | Phase 3.1 / Phase 4 pattern — operator config in SQLite | ✓ |

**User's choice:** DB-backed (single-row table, hot-reload) — explicit directive: "Update ROADMAP to remove env vars. Use DB instead."

**Notes:** User explicitly rejected the env var approach and directed alignment with the established DB-backed pattern from Phases 3.1 and 4. Single decision captured; no further gray areas needed discussion.

---

## Other Gray Areas — Skipped

| Area | Reason |
|------|--------|
| Partial failure handling | User's single directive covers it implicitly — follow existing Phase 4 pattern (fire-and-forget, warn on failure) |
| Manual sync trigger | Skip for Phase 5 |

---

## Deferred Ideas

- PolicySyncConfig TUI screen in dlp-admin-cli — future phase
- Manual sync trigger (`POST /admin/policy-sync`) — future phase
- Encryption of replica_urls at rest — deferred key-management phase
