# Phase 7: Active Directory LDAP Integration — Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-14
**Phase:** 07-active-directory-ldap-integration
**Areas discussed:** LDAP connection strategy, ABAC attribute mapping, Configuration management, Crate placement & Phase 9 link

---

## Area 1: LDAP Connection Strategy

| Option | Description | Selected |
|--------|-------------|----------|
| Persistent connection + reconnect | Bind once at startup, keep connection alive with reconnect on failure. Lower latency. More complex connection management. | |
| Per-request bind | Bind, query, unbind per request. Higher latency (~5-10ms). Simpler, stateless, no connection lifecycle to manage. | |
| Async connection pool | Pool of reusable async connections. Best latency, most complex to implement. | ✓ |

**User's choice:** Async connection pool
**Notes:** Want the best latency with ldap3 async connections, accepting the complexity tradeoff.

---

| Option | Description | Selected |
|--------|-------------|----------|
| Required (LDAPS) | Enforce LDAPS (port 636) or STARTTLS (port 389). No plaintext LDAP. Safer for production. | |
| Preferred but optional | Try LDAPS first, fall back to plaintext LDAP on 389. Easier for lab/test environments. | ✓ |

**User's choice:** Preferred but optional
**Notes:** Prefer TLS but accept plaintext in non-production environments.

---

| Option | Description | Selected |
|--------|-------------|----------|
| Fail-open (ALLOW) | Allow operation when AD unreachable, log warning. Operations continue; audit trail shows 'AD unreachable' state. | ✓ |
| Fail-closed (DENY) | Deny when AD unreachable. Maximum protection; may block legitimate work when AD is down. Matches offline cache pattern. | |

**User's choice:** Fail-open (ALLOW)
**Notes:** Consistent with existing offline-cache-first pattern. Blocking legitimate work when AD is temporarily down is worse than allowing with reduced enforcement.

---

## Area 2: ABAC Attribute Mapping

| Option | Description | Selected |
|--------|-------------|----------|
| Primary + all nested groups | Query tokenGroups on user object. Returns all groups including nested. Most complete, higher latency. | ✓ |
| Direct membership only | Query memberOf on user object. Direct group membership only. Faster, less complete. | |
| Cached (with TTL) | Cached results with configurable TTL. Reduce AD load. Stale group data risk. | |

**User's choice:** Primary + all nested groups via tokenGroups
**Notes:** Full transitive closure needed for accurate ABAC evaluation.

---

| Option | Description | Selected |
|--------|-------------|----------|
| TTL-based cache | Cache group membership for N minutes. Reduces AD load significantly. Stale group data risk. | ✓ |
| No caching (always fresh) | No caching. Always fresh data from AD. Higher AD load, no stale risk. | |
| Cache permanently + refresh on server signal | Cache forever; invalidate only on startup or explicit refresh signal from server. | |

**User's choice:** TTL-based cache
**Notes:** With fail-open, stale group data is acceptable.

---

| Option | Description | Selected |
|--------|-------------|----------|
| 5 minutes | Group membership refreshed every 5 minutes. Good balance of freshness and AD load reduction. | |
| 15 minutes | Refresh every 15 minutes. Lower AD load. Slightly higher risk of stale group data. | |
| 1 hour | Refresh every hour. Minimal AD load. Higher risk of stale group data during group membership changes. | |
| Configurable (with default 5 min) | Custom value specified in agent config (default 5 min). | ✓ |

**User's choice:** Configurable with default 5 minutes
**Notes:** Allow admins to tune based on their environment's group change frequency.

---

| Option | Description | Selected |
|--------|-------------|----------|
| Query AD for managed device attributes | Query ms-DS-Machine-Account-Quota or check for computer object in AD to determine trust. | |
| Domain join status from Windows API | Use existing IdentityResolver (already checks if machine is domain-joined). No extra LDAP query. | ✓ |
| Leave as Unknown | No device trust from AD. Leave as Unknown. May be refined in a future phase. | |

**User's choice:** Domain join status from Windows API (NetIsPartOfDomain)
**Notes:** No extra LDAP query needed; fast Windows API call is authoritative enough.

---

| Option | Description | Selected |
|--------|-------------|----------|
| IP address ranges from config | Infer from IP address ranges. Corporate = RFC1918 private ranges. VPN = known VPN subnets. Guest = public IP or non-corp ranges. | |
| AD site and subnet lookup | Query AD site/subnet info (nltest /dssitequery). Authoritative but complex. | ✓ |

**User's choice:** AD site and subnet lookup
**Notes:** AD site/subnet is the authoritative source for network location in an AD environment. VPN subnet list as fallback.

---

## Area 3: Configuration Management

| Option | Description | Selected |
|--------|-------------|----------|
| agent-config.toml (existing pattern) | ldap_url, bind_dn, bind_password, base_dn, cache_ttl_secs in agent-config.toml. Agent reads AD config at startup. No circular dependency since agent doesn't need AD to fetch config. | |
| SQLite DB + server-push (Phase 3.1/4 pattern) | LDAP config stored in DB, managed via dlp-admin-cli. Pushed to agent via existing config push mechanism (Phase 6). Requires server knows LDAP URL before agent can fetch it. | ✓ |

**User's choice:** SQLite DB + server-push (Phase 3.1/4 pattern)
**Notes:** Consistent with Phase 3.1/4 pattern. Single source of truth in DB. Admins manage via TUI. Agents get pushed config.

---

| Option | Description | Selected |
|--------|-------------|----------|
| Read-only service account in TOML | Read-only service account DN + password in agent-config.toml. Simple, no special tooling needed. | |
| Current Windows user (SSPI/NTLM) | Bind using current user's credentials (already authenticated to AD via Windows). No separate AD password needed. Requires gMSA or current user has AD rights. | |
| Machine account (domain-joined) | Bind using machine account (WORKSTATION$@DOMAIN). No separate credentials. Standard domain join behavior. | ✓ |

**User's choice:** Machine account (domain-joined)
**Notes:** Standard Kerberos auth using machine account. No separate service account credentials to manage.

---

## Area 4: Crate Placement & Phase 9 Link

| Option | Description | Selected |
|--------|-------------|----------|
| dlp-common (shared crate) | Shared between agent and server. Like classify_text. Server can use it to resolve admin SIDs for Phase 9's user_sid population. | ✓ |
| dlp-agent only | dlp-agent only. Server uses a separate HTTP endpoint on dlp-server instead. More decoupled. | |
| dlp-agent + re-export via dlp-common | dlp-agent as primary, re-exported from dlp-common as a convenience for the server side. Hybrid approach. | |

**User's choice:** dlp-common (shared crate)
**Notes:** Shared client avoids duplication. Server needs it for Phase 9 admin SID resolution.

---

| Option | Description | Selected |
|--------|-------------|----------|
| Phase 7 covers agent + server side | Phase 7 adds a shared function that both the agent (for ABAC) and server (for admin_users.user_sid population on login) can call. | ✓ |
| Phase 7 shared client, Phase 9 server use | Phase 7 adds the shared LDAP client in dlp-common. Phase 9's server-side SID resolution is a separate Phase 9 task using that client. | |

**User's choice:** Phase 7 covers agent + server side
**Notes:** Phase 7 delivers complete integration end-to-end: ABAC attribute resolution on the agent AND admin SID population on the server.

---

## Deferred Ideas

None — all discussion stayed within phase scope.

---

*Discussion log complete. Decisions captured in 07-CONTEXT.md.*
