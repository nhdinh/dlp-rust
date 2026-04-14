# Phase 7: Active Directory LDAP Integration — Context

**Gathered:** 2026-04-14
**Status:** Ready for planning
**Source:** /gsd-discuss-phase

<domain>
## Phase Boundary

Implement LDAP client using the `ldap3` crate to query Active Directory for real ABAC attribute resolution. The agent currently uses placeholder values (empty `groups`, `Unknown` device trust and network location). This phase replaces those placeholders with live AD data.

**In scope:**
- New `dlp-common/src/ad_client.rs` — shared LDAP client crate
- Async connection pool (ldap3) for efficient connection reuse
- Group membership resolution via `tokenGroups` (primary + all nested groups)
- TTL-based in-memory cache for group membership (configurable, default 5 minutes)
- `device_trust` resolution via Windows domain-join API (`NetIsPartOfDomain`)
- `network_location` resolution via AD site/subnet lookup (`nltest /dssitequery`)
- AD connection config in SQLite DB (Phase 3.1/4 pattern) + server-push to agents
- Machine account (Kerberos) authentication — no separate AD credentials
- Fallback fail-open on AD unavailability
- Server-side admin SID resolution for `admin_users.user_sid` population (Phase 9 linkage)
- Replace `identity.rs`-derived placeholder groups with live AD group SIDs in `Subject::groups`

**Out of scope:**
- LDAPS-only enforcement (prefer TLS, accept plaintext in non-production)
- Admin CLI TUI screen for AD config (handled in Phase 3.1/4 pattern via dlp-admin-cli extensions)
- Real-time group change notifications (LDAP persistent search / AD change notifications)
- Nested group expansion beyond tokenGroups recursion depth

</domain>

<decisions>
## Implementation Decisions

### A — LDAP Client Crate Location

**Decision:** `dlp-common/src/ad_client.rs` — shared between `dlp-agent` and `dlp-server`.

Rationale: Like `classify_text` (shared between agent and UI), the AD client needs to be in a shared crate so both sides can use it. The server side needs it for Phase 9's `admin_users.user_sid` population when admins log in. Keeping it in `dlp-common` avoids duplication and maintains consistency.

Both `dlp-common` and `dlp-agent` Cargo.tomls gain `ldap3` and `tokio` as dependencies.

### B — Connection Model: Async Connection Pool

**Decision:** Use `ldap3` with `ldap3::Conn` managed in an async connection pool. Multiple connections kept alive, borrowed/reused per request.

Rationale: Lower latency than per-request bind (~5-10ms saved). ldap3 supports async connections. Pool size configurable (default: 4 connections). On connection failure, pool auto-reconnects.

### C — TLS Preference

**Decision:** Prefer LDAPS (port 636) or STARTTLS (port 389); accept plaintext LDAP only when explicitly configured for non-production environments.

Rationale: Production security. Plaintext LDAP is a security risk. The LDAP config in the DB includes a `require_tls` boolean field (default: `true`).

### D — Fail-Open on AD Unavailability

**Decision:** When AD is unreachable, the agent proceeds with operations using best-effort ABAC attributes. `device_trust` falls back to `Unknown`, `network_location` falls back to `Unknown`, `groups` uses cached values if available (stale OK under fail-open), or empty vector.

Rationale: Fail-open is consistent with the existing offline-cache-first pattern in `dlp-agent`. Blocking legitimate work when AD is temporarily down is worse than allowing it with reduced policy enforcement. The audit trail notes when attributes are unresolved.

### E — Group Membership: tokenGroups (Primary + All Nested)

**Decision:** Query `tokenGroups` attribute on the user object (DN from SMB identity). This returns ALL group SIDs including nested group memberships (transitive closure), not just direct `memberOf` entries.

Rationale: Full transitive closure is needed for accurate ABAC evaluation. `memberOf` only returns direct groups and requires separate resolution for nested groups. `tokenGroups` is the authoritative AD-computed token group set.

Implementation: `ldap3::Scope::Base` query on user DN, requesting `tokenGroups` attribute. Parse the returned byte arrays into SID strings.

### F — TTL-Based Group Cache

**Decision:** Group membership cached in-memory with a configurable TTL. Default: 5 minutes. Minimum: 1 minute. Maximum: 1 hour. Cache key: user's SID.

Rationale: Reduces AD query load significantly (same user making multiple file ops in a short window). 5-minute TTL means group membership changes take up to 5 minutes to take effect — acceptable given fail-open behavior. TTL is configurable via the LDAP config in the DB (server-pushed to agent).

Cache is in-memory only (no persistence). Invalidated on TTL expiry. No explicit invalidation signal from server needed.

### G — device_trust: Domain-Join Status via Windows API

**Decision:** `device_trust` is resolved via `NetIsPartOfDomain()` Windows API (from `Win32_System_NetworkManagement_Miscellaneous` feature), not via LDAP query.

- Returns `Managed` if machine is part of a domain (`NetIsPartOfDomain` returns TRUE)
- Returns `Unmanaged` otherwise

Rationale: No extra LDAP query needed — the Windows API is authoritative and fast. The LDAP session is not needed for this check.

No additional `windows` crate features required for `NetIsPartOfDomain` — check if it's in `Win32_System_NetworkManagement_Miscellaneous` or similar.

### H — network_location: AD Site/Subnet Lookup

**Decision:** `network_location` is resolved via `nltest /dssitequery` (parsed stdout) or via `DsGetSiteName` + `DsAddressToSiteNames` Windows API.

- If the machine is in a known AD site → `NetworkLocation::Corporate`
- If connected via known VPN subnet (configurable list) → `NetworkLocation::CorporateVpn`
- Otherwise → `NetworkLocation::Corporate` (default, since machine is domain-joined)

Rationale: AD site/subnet membership is the authoritative source for network location in an AD environment. VPN subnet list is a fallback for VPN detection that AD site lookup doesn't cover.

VPN subnet list: configurable in LDAP config (default: none). When a VPN subnet is configured and the current IP falls in the range, use `CorporateVpn`.

### I — LDAP Config Storage: SQLite DB + Server Push

**Decision:** LDAP connection configuration lives in the SQLite database (same pattern as Phase 3.1 SIEM config, Phase 4 alert config), managed via `dlp-admin-cli` TUI. The server pushes LDAP config to agents via the existing Phase 6 agent config push mechanism.

New `ldap_config` table in `dlp-server.db`:

```sql
CREATE TABLE IF NOT EXISTS ldap_config (
    id                    INTEGER PRIMARY KEY CHECK (id = 1),
    ldap_url              TEXT NOT NULL DEFAULT 'ldaps://dc.corp.internal:636',
    base_dn               TEXT NOT NULL DEFAULT '',
    require_tls           INTEGER NOT NULL DEFAULT 1,
    cache_ttl_secs        INTEGER NOT NULL DEFAULT 300,
    vpn_subnets           TEXT NOT NULL DEFAULT '',  -- comma-separated CIDRs, e.g. "10.10.0.0/16,172.16.0.0/12"
    updated_at            TEXT NOT NULL DEFAULT ''
);
INSERT OR IGNORE INTO ldap_config (id) VALUES (1);
```

Admin API: `GET /admin/ldap-config`, `PUT /admin/ldap-config`.

Agent side: LDAP config embedded in `AgentConfigPayload` (Phase 6 pattern), sent via `GET /agent-config/{id}`. The agent reads it from the pushed config, not from its local TOML.

Rationale: LDAP URL and base DN are site-specific (different per forest/domain). Storing in DB makes them admin-manageable via the TUI. Server-push ensures agents get updated config without manual TOML editing.

### J — AD Authentication: Machine Account (Kerberos)

**Decision:** Agent binds to AD using its machine account (`WORKSTATION$@DOMAIN`) via Kerberos/GSSAPI. No separate AD service account credentials needed.

Rationale: Domain-joined machines already have a machine account in AD. The agent can authenticate using SPNEGO/Kerberos via `ldap3` `Simple` auth mechanism (SASL with GSSAPI). This avoids managing a separate service account password in the config.

Implementation: `ldap3::Simple::Kerberos` or `ldap3::Simple::GssApi` if available in `ldap3`. Fallback: bind with `WORKSTATION$` DN from `COMPUTERNAME` env var.

### K — Phase 9 Linkage: Admin SID Resolution

**Decision:** Phase 7's `dlp-common/src/ad_client.rs` is used by `dlp-server` to populate `admin_users.user_sid` on admin login (Phase 9 context: R-09 admin audit logging, SID field left empty pending AD integration).

When an admin successfully authenticates via `POST /auth/login`, the server resolves their username → SID via LDAP (using machine account auth) and stores/updates `user_sid` in `admin_users`. This is done once per login (cache in `admin_users` table), not on every request.

Rationale: Admin login is infrequent enough that an LDAP query per login is acceptable. The SID is stored in the DB so subsequent admin operations (policy CRUD, audit queries) don't need LDAP lookups.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase requirement
- `.planning/ROADMAP.md` — Phase 7 section (R-05, UAT criteria, file list)
- `.planning/REQUIREMENTS.md` — R-05 full text

### ABAC types to populate
- `dlp-common/src/abac.rs` — `Subject` struct (groups, device_trust, network_location fields), `DeviceTrust` enum, `NetworkLocation` enum
- `dlp-agent/src/identity.rs` — existing `WindowsIdentity` → `Subject::to_subject()` (replace placeholder groups)
- `dlp-agent/src/engine_client.rs` — where `EvaluateRequest` is built with `Subject`

### Phase 9 linkage
- `.planning/phases/09-admin-operation-audit-logging/09-CONTEXT.md` — Decision C: admin_users schema change, user_sid population
- `dlp-server/src/db.rs` — `admin_users` table schema (where to add user_sid update logic)

### DB config pattern (mirror Phase 3.1 / Phase 4)
- `.planning/phases/03.1-siem-config-in-db/CONTEXT.md` — SIEM config in DB pattern
- `.planning/phases/04-wire-alert-router-into-server/04-CONTEXT.md` — alert config in DB pattern

### Agent config push (Phase 6)
- `.planning/phases/06-wire-config-push-for-agent-config-distribution/06-CONTEXT.md` — agent config push pattern

### Windows API for device trust
- `dlp-agent/src/session_identity.rs` — existing Windows API usage patterns (Net* APIs, etc.)

### Established patterns
- `CLAUDE.md` §9 — Rust Coding Standards (no `.unwrap()`, `thiserror`, `tracing`, 4-space indent, 100-char lines)
- `dlp-server/src/main.rs` — how `AppState` is constructed and shared
- `dlp-server/src/admin_api.rs` — admin API handler patterns, JWT auth extractor

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `identity.rs WindowsIdentity::to_subject()` — replace `groups: Vec::new()` with AD-resolved groups
- `ldap3` crate — async LDAP client (add to Cargo.toml deps)
- `session_identity.rs` — Windows API usage for domain-join check

### Established Patterns
- DB-backed config: single-row table with CHECK (id=1), seeded via INSERT OR IGNORE
- Server push: AgentConfigPayload extended with new fields, agent reads from pushed config
- Shared crate: dlp-common has classify_text; ad_client follows same pattern
- Audit event: EventType::AdminAction from Phase 09 CONTEXT.md

### Integration Points
- `dlp-common/src/lib.rs` — add `pub mod ad_client`
- `dlp-agent/src/lib.rs` — add `use dlp_common::ad_client`
- `dlp-agent/src/identity.rs` — inject AD group lookup before building `Subject`
- `dlp-agent/src/engine_client.rs` — pass AD-resolved `Subject` to `EvaluateRequest`
- `dlp-server/src/main.rs` — construct `AdClient` and share via `AppState` (for Phase 9 admin SID resolution)
- `dlp-server/src/admin_api.rs` — `login` handler → resolve user SID → update `admin_users.user_sid`
- `dlp-server/src/db.rs` — add `ldap_config` table
- `dlp-admin-cli/src/client.rs` — add `get_ldap_config()` / `update_ldap_config()` API calls
- `dlp-admin-cli/src/app.rs` — add `Screen::LdapConfig` variant
- `dlp-admin-cli/src/screens/render.rs` — add `draw_ldap_config` function

</code_context>

<specifics>
## Specific Implementation Notes

### Shared AD client API (dlp-common/src/ad_client.rs)

```rust
/// Resolves a user's AD group memberships (primary + all nested via tokenGroups).
pub async fn resolve_user_groups(&self, user_dn: &str) -> Result<Vec<String>, AdClientError>;

/// Resolves machine's domain join status.
pub fn get_device_trust(&self) -> DeviceTrust;

/// Resolves machine's AD site and network location.
pub async fn get_network_location(&self, vpn_subnets: &[CidrRange]) -> NetworkLocation;

/// Resolves a username → SID via LDAP (for server-side Phase 9 use).
pub async fn resolve_username_to_sid(&self, username: &str) -> Result<String, AdClientError>;
```

### Machine account bind

The LDAP client binds with the machine account DN:
`CN=WORKSTATION$,OU=Computers,DC=corp,DC=internal` (constructed from `COMPUTERNAME` + configured `base_dn`).

Implementation: `ldap3::Simple::Bind(&machine_account_dn, "")` — empty password uses Kerberos credential cache.

### Group cache structure

```rust
struct GroupCache {
    entries: HashMap<String, (Vec<String>, Instant)>,  // sid → (groups, cached_at)
    ttl: Duration,
}
```

### VPN subnet parsing

`vpn_subnets` column is comma-separated CIDR notation:
`10.10.0.0/16,172.16.0.0/12` → parsed into `Vec<CidrRange>` for IP matching.

</specifics>

<deferred>
## Deferred Ideas

- LDAPS-only enforcement (strict) — currently "preferred but optional"; future hardening
- Real-time group change notifications (AD change notifications / LDAP persistent search)
- Admin CLI TUI screen for LDAP config — Phase 7 adds DB table + admin API; dlp-admin-cli screen deferred until Phase 7.1 or follow-on
- LDAP config in dlp-admin-cli TUI — handled by Phase 7's DB + admin API; the TUI screen is a follow-on task
- Nested group expansion beyond tokenGroups depth — tokenGroups already returns transitive closure
- Encryption of LDAP bind password at rest in DB — machine account auth eliminates need for stored password

</deferred>

---

*Phase: 07-active-directory-ldap-integration*
*Context gathered: 2026-04-14 via /gsd-discuss-phase*
