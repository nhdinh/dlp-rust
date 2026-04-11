# Phase 5: Policy Engine Separation — Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-11
**Phase:** 05-wire-policy-sync-for-multi-replica
**Areas discussed:** Architecture model, Role split, Sync direction, Database, Admin scope, Push protocol, Engine discovery

---

## Architecture Model

| Option | Description | Selected |
|--------|-------------|----------|
| Policy Engine as primary | One dlp-server as designated primary, rest as read-only replicas | |
| Separate binary | Policy engine as a completely separate Rust binary | ✓ |
| Keep symmetric peer model | All dlp-server instances equal, symmetric peer sync | |

**User's choice:** Separate binary — "In case there many replicas of dlp-server, I think we need to separate the policy-engine again. So the policy-engine will be single-source-of-truth that manage all the policies."

---

## Role Split

| Option | Description | Selected |
|--------|-------------|----------|
| Evaluation replicas only | dlp-server has no admin API, only agent comms + eval | ✓ |
| Split admin vs eval concerns | dlp-server keeps some admin capabilities (SIEM, alerts) | |

**User's choice:** Evaluation replicas only

---

## Sync Direction

| Option | Description | Selected |
|--------|-------------|----------|
| Push from engine | Engine pushes policy changes to replicas on CRUD | ✓ |
| Pull by replicas | Replicas poll engine periodically | |

**User's choice:** Push from engine

---

## Database

| Option | Description | Selected |
|--------|-------------|----------|
| Separate DB files | Engine and replicas each have their own SQLite | ✓ |
| Same DB file (dual-process) | Shared SQLite file, only engine writes policies | |

**User's choice:** Separate DB files

---

## Admin Scope

| Option | Description | Selected |
|--------|-------------|----------|
| Policies only | Engine handles policy CRUD + replica push only | ✓ |
| All admin config in engine | Engine also owns SIEM, alert, config_push DB tables | |

**User's choice:** Policies only

---

## Push Protocol

| Option | Description | Selected |
|--------|-------------|----------|
| Replica has writable policies table | Engine POSTs full policy JSON to replica's /policies endpoint | ✓ |
| Replica has read-only cache | Engine sends invalidation signal only | |

**User's choice:** Replica has writable policies table

---

## Engine Discovery

| Option | Description | Selected |
|--------|-------------|----------|
| Env var at startup | DLP_POLICY_ENGINE_URL env var for replicas | |
| DB-backed | Replicas read engine_url from policy_cache_config DB table | ✓ |

**User's choice:** DB-backed — "DB table in replica"

---

## Deferred Ideas

- HA / leader election for policy engine — future phase
- Replica-to-replica failover — future phase
- dlp-admin-cli changes — deferred (TUI needs to distinguish engine vs replica)
- Config push on replicas — deferred to Phase 6 or Phase 5.x
- Encryption of replica_urls / engine_url at rest — deferred key-management phase
