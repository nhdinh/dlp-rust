# Phase 24: Device Registry DB + Admin API - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-22
**Phase:** 24-device-registry-db-admin-api
**Areas discussed:** Agent endpoint auth, Registry uniqueness, Delete route ID, Agent cache refresh

---

## Agent Endpoint Auth

| Option | Description | Selected |
|--------|-------------|----------|
| Unauthenticated GET | Agents poll without credentials — matches config poll endpoint pattern. POST/DELETE still require JWT. | ✓ |
| JWT-gated GET | Agents hold admin JWT or separate credential. More secure but adds credential management complexity. | |

**User's choice:** Recommended default — unauthenticated GET
**Notes:** Agent has no stored secrets; server is localhost-only; aligns with existing unauthenticated config poll pattern.

---

## Registry Uniqueness

| Option | Description | Selected |
|--------|-------------|----------|
| Unique + upsert | UNIQUE(vid, pid, serial); POST on duplicate updates trust tier. One row per physical device. | ✓ |
| Allow duplicates | Multiple entries per device; POST always INSERTs. Complicates enforcement lookup. | |
| Unique + 409 | UNIQUE(vid, pid, serial); POST on duplicate returns conflict error. Admin must DELETE first. | |

**User's choice:** Recommended default — unique constraint with upsert
**Notes:** Most ergonomic for admin workflow; no 409 noise when re-registering a device with a new trust tier.

---

## Delete Route Identifier

| Option | Description | Selected |
|--------|-------------|----------|
| UUID | Consistent with policy table pattern. Returned in GET list. No URL-encoding issues. | ✓ |
| Auto-increment integer | Simpler but not consistent with existing patterns. | |
| Composite vid+pid+serial | Natural key but requires encoding in URL path. | |

**User's choice:** Recommended default — UUID
**Notes:** Matches `policies` table pattern; the GET list response returns the UUID for TUI reference.

---

## Agent Cache Refresh

| Option | Description | Selected |
|--------|-------------|----------|
| 30-second timer | Background task polls every 30s. Simple, matches audit flush loop pattern. | ✓ |
| USB-arrival trigger only | Refresh only when a device is plugged in. Misses admin changes between events. | |
| Version-gated | Server embeds registry_version in heartbeat; agent polls only when version changes. Efficient but complex. | |

**User's choice:** Recommended default — 30-second timer + immediate refresh on USB arrival
**Notes:** Timer is the baseline guarantee; immediate refresh on arrival reduces enforcement latency. Version-gated deferred as future optimization.

---

## Claude's Discretion

- `description` field in POST body: optional, defaults to empty string
- Polling interval: hardcoded 30s constant (no env var config)
- Upsert SQL: `INSERT OR REPLACE` vs `INSERT ... ON CONFLICT DO UPDATE` — Claude decides based on rusqlite compat

## Deferred Ideas

- Per-user registry (USB-06) — explicitly out of scope for v0.6.0
- USB-05 audit events with device identity — post-USB-03
- Admin TUI screen — Phase 28
- Configurable polling interval — unnecessary complexity now
