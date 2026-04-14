# Phase 7: Active Directory LDAP Integration — Research

**Phase:** 07-active-directory-ldap-integration
**Status:** Research
**Requirement:** R-05
**Output:** Plan prerequisites, open questions, technical decision points, and implementation shape

---

## 1. What Is Being Built

An AD integration layer that replaces the placeholder ABAC attributes in `Subject`
(`groups: []`, `device_trust: Unknown`, `network_location: Unknown`) with live
Active Directory data resolved at runtime on the endpoint.

The three attributes are sourced differently:

| Attribute | Source | Mechanism |
|-----------|--------|-----------|
| `groups` | LDAP `tokenGroups` | Query user DN, parse binary SID → `Vec<String>` |
| `device_trust` | Windows API | `NetIsPartOfDomain()` — no LDAP needed |
| `network_location` | Windows API + VPN config | `DsGetSiteName` / `DsAddressToSiteNames` |

The LDAP client lives in `dlp-common` so both `dlp-server` (Phase 9 admin SID
resolution) and `dlp-agent` (group lookup per operation) share it.

---

## 2. Module Layout

```
dlp-common/src/
    ad_client.rs        NEW — shared AD/LDAP client
    lib.rs              add: pub mod ad_client

dlp-server/src/
    ad_client.rs        RE-EXPORT — server-side AdClient wrapper (Arc pool)
    admin_api.rs        add: GET/PUT /admin/ldap-config
    db.rs               add: ldap_config table
    lib.rs              add: pub mod ad_client (server-side)
    main.rs             construct AdClient, add to AppState

dlp-agent/src/
    identity.rs         replace placeholders → AdClient calls
    lib.rs              add: use dlp_common::ad_client
```

`dlp-admin-cli` gets a LDAP config screen in a follow-on task (deferred to Phase 7.x).

---

## 3. DB Schema

Mirrors the Phase 3.1 / Phase 4 pattern exactly: single-row table, `CHECK (id = 1)`,
seeded via `INSERT OR IGNORE`.

```sql
CREATE TABLE IF NOT EXISTS ldap_config (
    id               INTEGER PRIMARY KEY CHECK (id = 1),
    ldap_url         TEXT NOT NULL DEFAULT 'ldaps://dc.corp.internal:636',
    base_dn          TEXT NOT NULL DEFAULT '',
    require_tls      INTEGER NOT NULL DEFAULT 1,
    cache_ttl_secs   INTEGER NOT NULL DEFAULT 300,
    vpn_subnets      TEXT NOT NULL DEFAULT '',
    updated_at       TEXT NOT NULL DEFAULT ''
);
INSERT OR IGNORE INTO ldap_config (id) VALUES (1);
```

`vpn_subnets` is a comma-separated list of CIDR ranges (e.g. `"10.10.0.0/16,172.16.0.0/12"`).

The `GET /admin/ldap-config` / `PUT /admin/ldap-config` admin API follows the
identical pattern as `siem_config` and `alert_router_config`.

**Question 1:** Should `ldap_config.base_dn` default to the machine's domain DN
discovered at startup, or should admins always set it explicitly?
- Pro-auto: zero-config on standard domain-joined machines
- Con-auto: wrong DN causes cryptic LDAP failures; explicit is safer
- **Decision needed before planning.** Context suggests explicit (Decision I:
  "LDAP URL and base DN are site-specific").

---

## 4. `dlp-common/src/ad_client.rs` — Core API Surface

### 4.1 Public API

```rust
/// LDAP / AD client for resolving ABAC subject attributes.
#[derive(Clone)]
pub struct AdClient {
    pool: ldap3::LdapPool,
    config: LdapConfig,
    cache: GroupCache,
}

impl AdClient {
    /// Constructs a client from a config struct.
    pub fn new(config: LdapConfig) -> Result<Self, AdClientError>;

    /// Resolves the user's AD group SIDs (primary + transitive nested).
    ///
    /// Uses `tokenGroups` for full transitive closure. Results are cached
    /// by the caller's SID for `cache_ttl_secs`.
    pub async fn resolve_user_groups(
        &self,
        user_dn: &str,
        caller_sid: &str,
    ) -> Result<Vec<String>, AdClientError>;

    /// Resolves username → SID for server-side Phase 9 use.
    ///
    /// Performs a `ldap3` search on `base_dn` with `(sAMAccountName={username})`.
    pub async fn resolve_username_to_sid(
        &self,
        username: &str,
    ) -> Result<String, AdClientError>;
}

/// The resolved device trust level for the local machine.
pub fn get_device_trust() -> DeviceTrust;

/// Network location resolved from AD site membership and VPN subnet config.
pub async fn get_network_location(
    vpn_subnets: &[CidrNet],
) -> NetworkLocation;
```

### 4.2 `LdapConfig` struct

```rust
#[derive(Debug, Clone)]
pub struct LdapConfig {
    pub ldap_url: String,        // e.g. "ldaps://dc.corp.internal:636"
    pub base_dn: String,         // e.g. "DC=corp,DC=internal"
    pub require_tls: bool,
    pub cache_ttl_secs: u64,     // min 60, max 3600, default 300
}
```

### 4.3 Group cache

```rust
struct GroupCache {
    entries: HashMap<String, (Vec<String>, Instant)>,
    ttl: Duration,
}

impl GroupCache {
    fn get(&self, sid: &str) -> Option<Vec<String>>;
    fn insert(&mut self, sid: String, groups: Vec<String>);
    fn evict_expired(&mut self);
}
```

**Key question 2:** The cache is keyed by `caller_sid` (the user making the file request),
not by `user_dn`. This is because the DN may not be readily available at all call
sites (only the SID is available from the token). Confirm this is the right key.

**Key question 3:** `resolve_user_groups` takes both `user_dn` (for the LDAP query)
and `caller_sid` (for the cache key). The DN is available from `identity.rs`'s
`WindowsIdentity` by constructing it from the SID and `LookupAccountSidW` to get
the user's domain component — OR by passing it through from the session identity
resolution pipeline. Need to trace: where is the DN actually available today?
The `identity.rs` `WindowsIdentity` only carries `sid` and `username`. To get the
DN for the LDAP query, we need either:
- (a) Store DN alongside SID in `WindowsIdentity` — requires Win32 API call to
  `GetUserNameEx` with `NameFullyQualifiedDN` or `LookupAccountSid` to get the
  domain portion, then construct DN from `sAMAccountName`.
- (b) Use `sAMAccountName` (the `username` field) as the LDAP search filter
  instead of DN. This avoids needing the DN at all — just search `base_dn` with
  `(sAMAccountName=jsmith)` to find the user object and read `tokenGroups`.

Option (b) is simpler and avoids changing `WindowsIdentity`. The LDAP search
with `sAMAccountName` filter is the right approach.

---

## 5. `tokenGroups` — Parsing Binary SID Data

`tokenGroups` returns a multi-valued attribute where each value is the binary
representation of a SID (not the string form). The format is a byte array
with a `SID` structure starting with revision byte, authority size, and then
the subauthorities.

The `ldap3` crate returns raw bytes. We need to parse them into strings.

**SidBytes → String conversion:**
- `ConvertSidToStringSidW` requires a `PSID` pointer (not a byte slice).
- Approach: cast `&[u8]` to `PSID` via `std::ptr::slice_from_raw_parts`, then
  call `ConvertSidToStringSidW`. This is `unsafe` and needs careful safety
  documentation.
- Alternative: manually parse the binary SID format (little-endian) to construct
  the string form. MSDN documents the binary layout.

**Binary SID format (from MS-DTYP):**
```
Byte 0:     Revision (must be 1)
Byte 1:     SubAuthorityCount (n)
Bytes 2-7:  IdentifierAuthority (6 bytes, big-endian)
Bytes 8+:   SubAuthorities (n × 4 bytes each, little-endian uint32)
```
String form: `S-1-{authority}-{sub1}-{sub2}...`

**Key question 4:** Is there a `windows` crate API that converts a SID byte array
to a string, or do we need manual parsing? The existing `session_identity.rs`
uses `ConvertSidToStringSidW` with a `PSID` pointer from token buffer. For a
byte slice, we'd need to reconstruct a `PSID` from the buffer. Recommendation:
implement a `parse_sid_bytes(bytes: &[u8]) -> Option<String>` helper that does
the manual parse per MS-DTYP, avoiding any `unsafe` PSID casting.

**Key question 5:** `tokenGroups` returns ALL group SIDs including the user's
own SID (the "primary group" concept). Do we need to filter out the user's own
SID from the result? The `Subject::groups` field documents it as "all AD groups
the user is a member of" — own SID is not a group membership, so it should be
filtered. Confirm this is the right behavior.

---

## 6. Machine Account (Kerberos) Authentication

The agent is a domain-joined Windows machine. It has a machine account
`WORKSTATION$@DOMAIN.CORP.INTERNAL` and a TGT in its Kerberos credential cache
(established at boot via `kinit` or automatic). The LDAP bind uses these
credentials, not a separate service account.

**Constructing the machine account DN:**
```
CN=WORKSTATION$,CN=Computers,DC=corp,DC=internal
```

The DN can be constructed from:
- `COMPUTERNAME` env var → workstation name
- `USERDOMAIN` env var → domain name (for the domain portion of base_dn)

The `base_dn` from the LDAP config provides the domain component. The machine
account's DN is: `CN=${COMPUTERNAME}$,CN=Computers,<base_dn>`. This assumes
a default `Computers` OU — if machines are in a different OU, the LDAP bind
will fail with an `InvalidCredentials` error. The LDAP config does not include
an OU field; machine accounts in non-default OUs would need config extended.

**Key question 6:** Should the LDAP config include a `machine_account_ou` field
for environments where machines are not in `CN=Computers`? Default to empty
(meaning `CN=Computers`), and if non-empty, substitute it.

**Kerberos bind with ldap3:**
```rust
// ldap3 supports GSSAPI / SPNEGO via Simple::GssApi
// The actual credential comes from the process's Kerberos cache.
// ldap3's Simple::GssApi uses the default creds from CCACHE.
let conn = ldap3::Ldap::async_connect(
    ldap3::LdapConnAsync::new(...)?,
    ldap3::LdapConnSettings::default()
).await?;
conn.simple_bind("", "").await?;  // empty user/pass = use GSSAPI creds
```

**Key question 7:** Does `ldap3`'s `Simple::GssApi` (or equivalent) work correctly
on Windows with the machine's TGT? Need to verify the ldap3 API for GSSAPI/Kerberos
bind on Windows. If not, fallback to:
```rust
// Construct machine account DN from COMPUTERNAME + base_dn
let machine_dn = format!("CN={},CN=Computers,{}", computer_name, base_dn);
// Bind with empty password — uses Kerberos credential cache
conn.simple_bind(&machine_dn, "").await?;
```

**Key question 8:** The server also needs to bind to AD for Phase 9 admin SID
resolution. The server may not be domain-joined. If not, it has no machine account
and no Kerberos TGT. Options:
- Server requires domain-join (simplest — `dlp-server` runs on a domain-joined
  management server).
- Server uses a service account credential stored in the LDAP config.
- Server uses LDAP simple bind with a service account DN + password stored in
  `ldap_config` (add a `bind_dn` / `bind_password` column).

Decision J in CONTEXT.md says "Kerberos/GSSAPI via ldap3" — this is the preferred
path for the agent (domain-joined). For the server, if it's not domain-joined,
we need a fallback. **Recommend:** require server to be domain-joined for Phase 7.
Document this as a deployment prerequisite. If a non-domain-joined server is
needed, a Phase 7.x can add `bind_dn` / `bind_password` fields.

---

## 7. `device_trust` — Domain-Join Check

```rust
pub fn get_device_trust() -> DeviceTrust {
    use windows::Win32::NetworkManagement::Ndis::NetIsPartOfDomain;
    // Returns TRUE if machine is joined to a domain.
    // SAFETY: NetIsPartOfDomain is a read-only query.
    unsafe {
        if NetIsPartOfDomain().as_bool() {
            DeviceTrust::Managed
        } else {
            DeviceTrust::Unmanaged
        }
    }
}
```

**Key question 9:** The `windows` crate feature needed for `NetIsPartOfDomain`
— checking the current `dlp-agent/Cargo.toml` to determine which features are
already enabled. The CONTEXT says "Win32_System_NetworkManagement_Miscellaneous"
but the actual feature name may differ. Need to verify the exact `windows` crate
feature string for `NetIsPartOfDomain`.

From `windows` crate documentation: `NetIsPartOfDomain` is in the
`Win32_NetworkManagement_Ndis` namespace, gated by the `Win32_System_NetworkManagement`
feature. Confirm this in `dlp-agent/Cargo.toml`.

---

## 8. `network_location` — AD Site Lookup

**Step 1: Get the current AD site name.**
```rust
// DsGetSiteName — returns the site the machine is currently in.
use windows::Win32::System::Registry::DsGetSiteNameW;  // NOT Registry!
// Or: use windows::Win32::System::RemoteDesktop::DsGetSiteNameW;
// Need to verify the correct windows crate feature for DsGetSiteName.
```

**Step 2: If on a VPN subnet (from config), return `CorporateVpn`.**

VPN subnet check:
```rust
fn is_on_vpn(local_ip: &str, vpn_subnets: &[CidrNet]) -> bool {
    let local: IpAddr = local_ip.parse().ok()?;
    vpn_subnets.iter().any(|cidr| cidr.contains(&local))
}
```

**Step 3: Otherwise, return `Corporate`.**

**Key question 10:** What Windows API provides the local machine's primary IP
address for VPN subnet comparison? Options:
- `getifaddrs` (cross-platform, available via `windows-sys` or `libc` on Windows).
- `ipconfig` command output parsing (fragile).
- `GetAdaptersAddresses` from `windows::Win32::NetworkManagement::Ndis`.
- Use the agent's `hostname` from the registration payload to derive it.

**Recommendation:** Use `GetAdaptersAddresses` (available in `Win32_NetworkManagement_IPHelper`
feature) to enumerate adapter addresses and find the first IPv4 address that
is not loopback, link-local, or multicast. This is the most robust approach.

**Key question 11:** The AD site name from `DsGetSiteName` is a simple string
(e.g., `"Default-First-Site-Name"`). When is a location NOT `Corporate`?
- Machine is not in any AD site (unusual domain join issue) → `Unknown`.
- Machine is in an AD site but we want to distinguish remote offices → this
  requires the VPN subnet check as the primary differentiator.

**Decision:** Per CONTEXT Decision H, `Corporate` is the default when the machine
is domain-joined. VPN subnet check overrides to `CorporateVpn`. AD site name is
logged for diagnostics but does not affect the `NetworkLocation` enum value in Phase 7.

---

## 9. Server-Side Admin API Integration (Phase 9 Linkage)

The server's `AdClient` is constructed at startup from the DB config and stored
in `AppState`:

```rust
// dlp-server/src/main.rs
let ad_client = AdClient::from_db(&db)?;  // loads ldap_config on startup
let state = Arc::new(AppState {
    db,
    siem,
    alert,
    ad: ad_client,   // NEW
});
```

```rust
// dlp-server/src/lib.rs — AppState extension
pub struct AppState {
    pub db: Arc<db::Database>,
    pub siem: siem_connector::SiemConnector,
    pub alert: alert_router::AlertRouter,
    pub ad: dlp_common::ad_client::AdClient,  // NEW
}
```

**Phase 9 integration point:** In the `login` handler (POST `/auth/login`), after
a successful password verification, call `ad.resolve_username_to_sid(username)`
and update `admin_users.user_sid` via a new `db.update_admin_user_sid()` method.
Cache the result in `admin_users` — no LDAP query on subsequent requests.

```rust
// Phase 9: admin_api.rs login handler extension
if let Ok(sid) = state.ad.resolve_username_to_sid(&username).await {
    db.update_admin_user_sid(&username, &sid)?;
}
```

This is the **Phase 9 linkage** in Decision K — Phase 7 builds the `AdClient`
with this method, Phase 9 wires it into the login flow.

---

## 10. Agent-Side Integration

### 10.1 `identity.rs` change

```rust
// BEFORE (placeholder)
pub fn to_subject(&self) -> Subject {
    Subject {
        user_sid: self.sid.clone(),
        user_name: self.username.clone(),
        groups: Vec::new(),
        device_trust: DeviceTrust::Unknown,
        network_location: NetworkLocation::Unknown,
    }
}

// AFTER (with AD)
pub async fn to_subject_with_ad(
    &self,
    ad_client: &AdClient,
) -> Subject {
    let groups = ad_client
        .resolve_user_groups(&self.username, &self.sid)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "AD group lookup failed — using empty groups");
            Vec::new()
        });

    let device_trust = ad_client::get_device_trust();
    let network_location = ad_client::get_network_location(
        &ad_client.vpn_subnets()
    ).await;

    Subject {
        user_sid: self.sid.clone(),
        user_name: self.username.clone(),
        groups,
        device_trust,
        network_location,
    }
}
```

**Key question 12:** `resolve_user_groups` is async but the call site in
`identity.rs → to_subject()` is currently synchronous. The call chain from
file interception → `identity.rs` → `engine_client.rs` needs to become async.
Need to trace the full call chain from the interception layer to see where
the `await` point would be introduced. This is a non-trivial async cascade
that could affect multiple call sites.

**Key question 13:** The `AdClient` instance must be shared across all
interception threads on the agent. It should be constructed at agent startup
(from pushed LDAP config) and stored in an `Arc` that all components hold a
reference to. Need to verify how the agent's global state is currently
structured (service.rs) to determine the right injection point.

### 10.2 LDAP config on the agent

The LDAP config is pushed to agents via Phase 6's `AgentConfigPayload`
mechanism. `AgentConfigPayload` (in `server_client.rs`) must be extended:

```rust
// server_client.rs — AgentConfigPayload extension
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentConfigPayload {
    pub monitored_paths: Vec<String>,
    pub heartbeat_interval_secs: u64,
    pub offline_cache_enabled: bool,
    pub ldap_config: Option<LdapConfigPayload>,  // NEW
}

// New payload type (not the full LdapConfig — no need for bind credentials)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapConfigPayload {
    pub ldap_url: String,
    pub base_dn: String,
    pub require_tls: bool,
    pub cache_ttl_secs: u64,
    pub vpn_subnets: String,  // comma-separated CIDRs
}
```

**Key question 14:** Should the agent persist the LDAP config to its local
`agent-config.toml` (like it does for `monitored_paths`, etc.)? This would mean
the LDAP config survives agent restarts without needing a re-poll. Recommend: yes,
persist it alongside other pushed config.

---

## 11. Fail-Open Behavior

Decision D: When AD is unreachable, proceed with operations using best-effort
attributes.

```rust
impl AdClient {
    /// Returns empty groups if AD is unreachable (fail-open).
    pub async fn resolve_user_groups(&self, ...) -> Result<Vec<String>, AdClientError> {
        match self.do_resolve_groups(...).await {
            Ok(groups) => Ok(groups),
            Err(e) => {
                tracing::warn!(error = %e, "AD unreachable — using empty group set (fail-open)");
                Ok(Vec::new())
            }
        }
    }
}
```

For `device_trust` and `network_location`:
- `device_trust`: `NetIsPartOfDomain` is a local API, not network-dependent → no fail-open needed.
- `network_location`: if the AD site lookup fails, return `NetworkLocation::Unknown`.

---

## 12. ldap3 Crate API Notes

**Connection pool:**
```rust
use ldap3::{Ldap, LdapPool, LdapConnAsync, Scope};

let (conn, pool) = LdapPool::new(
    ldap3::LdapConnAsync::with_settings(...)?
)?;
```

**Search with tokenGroups:**
```rust
let (rs, _) = conn.execute(
    LdapFilter::ExtFilter("(sAMAccountName=jsmith)"),
    Scope::Subtree,
    vec!["tokenGroups"],
    vec![],  // no attributes to return for base search
)?;
```

Wait — `Scope::Base` is needed for `tokenGroups` because it's a multivalued
attribute on the user object itself (not a search across the tree). The correct
query is:
```rust
// user_dn = "CN=jsmith,CN=Users,DC=corp,DC=internal"
conn.search(
    &user_dn,
    Scope::Base,
    "(objectClass=*)",
    vec!["tokenGroups"],
)?;
```

Using `sAMAccountName` filter (Option b from Question 3) first to get the DN:
```rust
let (rs, _conn) = conn.search(
    &self.config.base_dn,
    Scope::Subtree,
    &format!("(sAMAccountName={})", username),
    vec!["distinguishedName", "tokenGroups"],
)?;
```

**Key question 15:** `ldap3::Scope` — verify the correct enum variant names
(`Scope::Base`, `Scope::OneLevel`, `Scope::Subtree`). Also verify how the
search result's `tokenGroups` attribute is accessed. The `ldap3` crate returns
search results as `ldap3::SearchEntry` objects; attributes are accessed via
`.attrs.get("tokenGroups")`.

---

## 13. Async Runtime Considerations

- `ldap3` supports async via `LdapConnAsync` and `LdapPool`.
- All AD resolution functions (`resolve_user_groups`, `resolve_username_to_sid`,
  `get_network_location`) are `async`.
- The agent's file interception pipeline currently runs on `tokio` (the service
  uses `tokio::spawn` for background tasks). The main interception callbacks may
  be synchronous. Need to determine: does the agent use `tokio::spawn_blocking`
  for the synchronous interception path, or does the whole agent need to become
  async?

Looking at `session_identity.rs` — it uses Win32 APIs only, no async. The
interception layer likely calls `identity.rs::resolve_caller_identity()` synchronously.
The `to_subject_with_ad()` call would need to either:
- (a) Be called from within a `tokio::spawn_blocking` wrapper if already in async context.
- (b) Be called from a dedicated async task spawned at interception time.

The `engine_client.rs` HTTP call to the policy engine IS already async.
The `EvaluateRequest` is built before the HTTP call. So the ABAC attribute
resolution could happen inline before the HTTP call in the async handler.

**Recommendation:** Investigate whether `identity.rs` is called from an async
context or a blocking thread context. The simplest path: `AdClient` resolution
happens in `engine_client.rs` just before building `EvaluateRequest`, which is
already async. `identity.rs::resolve_caller_identity()` can remain synchronous
(to be called inside `tokio::spawn_blocking`), then the result (containing `sid`
and `username`) is passed to `ad_client.resolve_user_groups(username, sid)` which
is async.

---

## 14. Dependencies

**`dlp-common/Cargo.toml`** additions:
```toml
ldap3 = { version = "0.11", features = ["ldap3"] }  # check latest
tokio = { version = "1", features = ["rt", "sync"] }
ipnetwork = "0.20"   # for CIDR matching
serde = { version = "1", features = ["derive"] }
thiserror = "2"
parking_lot = "0.12"
```

**`dlp-agent/Cargo.toml`** additions (in addition to dlp-common deps):
```toml
# Already has windows crate; may need additional features:
# "Win32_NetworkManagement_Ndis" for NetIsPartOfDomain
# "Win32_System_RemoteDesktop" for DsGetSiteName (verify feature name)
# "Win32_NetworkManagement_IpHelper" for GetAdaptersAddresses
```

**Key question 16:** Confirm the exact `windows` crate feature names for:
- `NetIsPartOfDomain` → `Win32_System_NetworkManagement`
- `DsGetSiteName` → verify if it's in `Win32_System_RemoteDesktop` or elsewhere
- `GetAdaptersAddresses` → `Win32_NetworkManagement_IpHelper`

---

## 15. Threat Model Considerations

**TM-01: LDAP bind credentials — machine account (Kerberos)**
No stored password in the DB or config. Machine account TGT is used. TGT
is machine-bound. This is significantly better than storing a service account
password. Residual risk: if the machine is compromised, the TGT can be used
to query AD. This is standard for domain-joined endpoints and accepted.

**TM-02: LDAPS / TLS enforcement**
`require_tls` defaults to `true` (Decision C). Plaintext LDAP is rejected when
`require_tls = true`. When `require_tls = false` (non-production), the connection
is plaintext. This is documented in the `ldap_config` table semantics.

**TM-03: Fail-open security posture**
When AD is unreachable, `groups` returns `[]` (empty). A user who is a member
of `Domain Admins` will appear as a non-privileged user during AD outage.
This means the DLP cannot enforce group-based restrictions during outages but
will not block legitimate work. This is consistent with the project's
fail-open philosophy. **Document this as a known limitation.**

**TM-04: Cached group membership staleness**
The 5-minute TTL (default) means group membership changes take up to 5 minutes
to take effect. A user removed from a sensitive group can still access sensitive
data for up to 5 minutes. This is an accepted trade-off per Decision F.

---

## 16. Open Questions Summary

| # | Question | Recommendation | Blocking? |
|---|----------|---------------|-----------|
| 1 | `base_dn` default — auto-detect or explicit? | Explicit (safer) | No |
| 2 | Group cache key — `caller_sid` or `user_dn`? | `caller_sid` (more universally available) | No |
| 3 | DN availability in `WindowsIdentity` — how to get DN for LDAP? | Use `sAMAccountName` filter (Option b) — no DN needed | Yes |
| 4 | `tokenGroups` binary SID parsing — `unsafe` PSID cast vs. manual parse? | Manual parse per MS-DTYP (safer, no `unsafe`) | No |
| 5 | Filter own SID from `tokenGroups` result? | Yes — own SID is not a group membership | No |
| 6 | Machine account OU configurable? | Add `machine_account_ou` field, default `CN=Computers` | No |
| 7 | `ldap3` GSSAPI/Kerberos bind on Windows — API confirmed? | Verify `ldap3` docs; fallback to empty-passwd machine-account bind | Yes |
| 8 | Server AD bind — domain-join required or service account fallback? | Require domain-join for Phase 7; document as deployment prerequisite | Yes |
| 9 | `windows` crate feature for `NetIsPartOfDomain`? | `Win32_System_NetworkManagement` (verify) | Yes |
| 10 | Local IP address for VPN subnet check — Windows API? | `GetAdaptersAddresses` from `Win32_NetworkManagement_IpHelper` | No |
| 11 | AD site name → `NetworkLocation` mapping? | Corporate by default; VPN subnet check overrides to CorporateVpn | No |
| 12 | Async cascade from `identity.rs` through interception pipeline? | Investigate call chain; use `tokio::spawn_blocking` for sync path | Yes |
| 13 | `AdClient` shared state injection in agent service startup? | `Arc<AdClient>` in service global state | No |
| 14 | Persist LDAP config to `agent-config.toml`? | Yes, alongside other pushed config | No |
| 15 | `ldap3` `Scope` enum variants and `SearchEntry` attribute access? | Verify crate docs for exact API | Yes |
| 16 | Exact `windows` crate feature names for all Win32 APIs? | Verify via `windows` crate docs / search | Yes |

---

## 17. Risk Assessment

**High risk:**
- Async pipeline integration (Q12) — unknown call chain depth, could require
  significant refactoring of the interception layer.
- `ldap3` GSSAPI/Kerberos on Windows (Q7, Q8) — if Kerberos bind doesn't work,
  need service account fallback which requires DB schema change.

**Medium risk:**
- Binary SID parsing (Q4) — well-documented MS-DTYP format, implementation is
  straightforward but must be correct.
- VPN subnet detection (Q10) — `GetAdaptersAddresses` is reliable but may need
  careful handling of multi-homed machines.
- Windows crate features (Q9, Q16) — may need to add features, increase
  compile time, potential API changes between versions.

**Low risk:**
- DB schema (mirrors established pattern).
- Admin API (mirrors established pattern).
- Cache design (standard HashMap + Instant TTL pattern).
- `device_trust` via `NetIsPartOfDomain` — local API, no network dependency.

---

## 18. Implementation Order

1. **`dlp-common/src/ad_client.rs`** — core types, SID parsing, cache, client
   struct (no network I/O yet). Test with mock data.
2. **`dlp-server/src/db.rs`** — add `ldap_config` table.
3. **`dlp-server/src/admin_api.rs`** — add `GET/PUT /admin/ldap-config`.
4. **`dlp-common/src/ad_client.rs`** — implement LDAP bind + `resolve_user_groups`
   with `tokenGroups` (the hardest part).
5. **`dlp-server/src/main.rs`** — construct `AdClient` from DB, add to `AppState`.
6. **`dlp-server/src/lib.rs`** — add `ad` field to `AppState`, export module.
7. **`dlp-agent/src/identity.rs`** — inject `AdClient` call, replace placeholders.
8. **`dlp-agent/src/server_client.rs`** — extend `AgentConfigPayload` with LDAP config.
9. **`dlp-agent/src/service.rs`** — construct `AdClient` at startup from pushed config.
10. **Integration test** — UAT: ABAC evaluation uses real AD group membership.

Steps 1–3 and 5–6 are low risk (pure code addition following established patterns).
Steps 4 and 7–9 are where the novel AD-specific work lives and where Q3, Q7, Q12
answers are needed.

---

## 19. Test Strategy

### Unit tests
- `parse_sid_bytes()` — table-driven tests: valid SID bytes → string, invalid bytes → None.
- `GroupCache` — TTL eviction, cache key correctness.
- `CidrNet::contains()` — VPN subnet matching.
- `get_device_trust()` — mock-free (local API).
- `LdapConfigPayload` JSON roundtrip in `server_client.rs`.

### Integration tests
- Mock LDAP server (e.g., `ldap3` + `mockiato` or a real LDAP test container).
- `resolve_user_groups` → verify `tokenGroups` byte array → `Vec<String>` SID.
- `resolve_username_to_sid` → verify correct SID returned.
- AD unavailability → verify fail-open returns `Ok(Vec::new())`.
- Cache hit → verify no LDAP query on second call within TTL.

### No-AD environment tests
- All AD calls should gracefully degrade when no AD is available (fail-open).
- `device_trust` should return `Unmanaged` when `NetIsPartOfDomain` returns FALSE.

---

## 20. Deferred Items (Known Scope Creep Prevention)

These were identified during research but are out of Phase 7 scope. Document
to prevent accidental inclusion:

| Item | Reason deferred |
|------|----------------|
| Admin CLI LDAP config TUI screen | DB table + admin API is Phase 7; TUI is Phase 7.x |
| LDAPS certificate validation / pinned CA | Future hardening phase |
| Real-time group change notifications (LDAP persistent search) | Phase 7 explicitly out of scope |
| `machine_account_ou` field | Default `CN=Computers` covers most deployments |
| `bind_dn`/`bind_password` for non-domain-joined servers | Phase 7 requires server domain-join |
| Encryption of any future credentials at rest in DB | Machine account auth eliminates need |
