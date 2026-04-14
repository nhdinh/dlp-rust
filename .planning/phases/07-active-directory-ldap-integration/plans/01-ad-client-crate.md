---
wave: 1
depends_on: []
requirements:
  - R-05
files_modified:
  - dlp-common/src/ad_client.rs (NEW)
  - dlp-common/src/lib.rs
  - dlp-common/Cargo.toml
autonomous: false
---

# Plan 01: AD Client Crate (`dlp-common/src/ad_client.rs`)

## Goal

Implement the shared LDAP client in `dlp-common` so both `dlp-server` (Phase 9 admin SID resolution) and `dlp-agent` (ABAC group resolution) share the same code.

---

## must_haves

- `dlp-common/src/ad_client.rs` compiles with `cargo build -p dlp-common`
- `dlp-common/src/lib.rs` re-exports `ad_client` module
- `LdapConfig` struct has all 5 fields: `ldap_url`, `base_dn`, `require_tls`, `cache_ttl_secs`, `vpn_subnets`
- `AdClient::new(config)` opens an LDAP connection with machine account bind (empty password uses Kerberos TGT)
- `AdClient::resolve_user_groups(username, caller_sid)` queries `tokenGroups` on the user object and returns `Vec<String>` of group SIDs (fails open: returns `Ok(Vec::new())` on AD error)
- `AdClient::resolve_username_to_sid(username)` queries `base_dn` for `(sAMAccountName={username})` and returns the user's SID string
- `get_device_trust()` — no LDAP needed; uses `NetIsPartOfDomain()` Windows API; returns `DeviceTrust::Managed` if domain-joined, else `Unmanaged`
- `get_network_location(vpn_subnets)` — uses `GetAdaptersAddresses` to find local IPv4; if IP is in a VPN subnet range, returns `CorporateVpn`; otherwise `Corporate` (AD site name logged as debug)
- `GroupCache` — HashMap keyed by `caller_sid`; entries expire after `cache_ttl_secs`; returns `None` on miss; evict expired on every get/insert
- Binary SID parsing (`parse_sid_bytes(bytes: &[u8]) -> Option<String>`) — manual parse per MS-DTYP (revision byte + subauthority count + big-endian authority + little-endian subauthorities); string form `S-1-{authority}-{sub1}-...`; no `unsafe`
- Own SID filtered from `tokenGroups` result (check: if returned SID == caller's SID, skip it)
- All public functions have doc comments

---

## Tasks

### Task 1: Cargo dependencies (`dlp-common/Cargo.toml`)

<read_first>
`dlp-common/Cargo.toml`
</read_first>

<action>
Add the following dependencies to `dlp-common/Cargo.toml` in the `[dependencies]` section:
```
ldap3 = "0.11"
tokio = { version = "1", features = ["rt", "sync"] }
ipnetwork = "0.20"
parking_lot = "0.12"
```
</action>

<acceptance_criteria>
- `dlp-common/Cargo.toml` contains `ldap3`, `tokio` (rt + sync), `ipnetwork = "0.20"`, and `parking_lot = "0.12"`
- `grep -n "ldap3" dlp-common/Cargo.toml` returns a line with `ldap3`
- No duplicate entries
</acceptance_criteria>

---

### Task 2: `dlp-common/src/lib.rs` — add `pub mod ad_client`

<read_first>
`dlp-common/src/lib.rs`
</read_first>

<action>
Add `pub mod ad_client;` to `dlp-common/src/lib.rs` after the existing `pub mod` lines. Re-export the public types at the crate root:
```rust
pub mod ad_client;
pub use ad_client::{AdClient, LdapConfig, AdClientError, get_device_trust, get_network_location};
```
</action>

<acceptance_criteria>
- `dlp-common/src/lib.rs` contains `pub mod ad_client;`
- `grep -n "pub mod ad_client" dlp-common/src/lib.rs` returns exactly one line
</acceptance_criteria>

---

### Task 3: `dlp-common/src/ad_client.rs` — full implementation

<read_first>
`dlp-common/src/abac.rs` — for `DeviceTrust` and `NetworkLocation` enum definitions (do NOT copy, just read)
</read_first>

<action>
Create `dlp-common/src/ad_client.rs` with the full implementation. The file must contain (in order):

1. **Imports**: `std`, `tokio`, `ldap3::{Ldap, LdapConnAsync, Scope, LdapResult}`, `ipnetwork::IpNetwork`, `parking_lot::Mutex`, `thiserror`, `tracing`

2. **`parse_sid_bytes(bytes: &[u8]) -> Option<String>`** (no `unsafe`):
   - Byte 0 = revision (must be 1)
   - Byte 1 = subauthority count (n)
   - Bytes 2–7 = identifier authority (big-endian u48 → format as decimal, e.g. "5-21-1234")
   - Bytes 8+ = n × u32 subauthorities (little-endian)
   - Return format: `S-1-{authority}-{sub1}-{sub2}...`
   - If bytes.len() < 8 + n*4, return `None`

3. **`AdClientError`** (thiserror enum):
   ```
   #[error("LDAP connection failed: {0}")]
   LdapConnect(String)
   #[error("LDAP bind failed: {0}")]
   LdapBind(String)
   #[error("LDAP search failed: {0}")]
   LdapSearch(String)
   #[error("user not found in AD: {0}")]
   UserNotFound(String)
   #[error("invalid SID in tokenGroups: {0}")]
   InvalidSid(String)
   ```

4. **`GroupCache` struct**:
   ```rust
   struct GroupCache {
       entries: HashMap<String, (Vec<String>, Instant)>,
       ttl_secs: u64,
   }
   impl GroupCache {
       fn get(&self, sid: &str) -> Option<Vec<String>>;
       fn insert(&mut self, sid: String, groups: Vec<String>);
       fn evict_expired(&mut self);
   }
   ```

5. **`LdapConfig` struct** (serde, Debug, Clone):
   ```rust
   pub struct LdapConfig {
       pub ldap_url: String,         // e.g. "ldaps://dc.corp.internal:636"
       pub base_dn: String,          // e.g. "DC=corp,DC=internal"
       pub require_tls: bool,        // default true
       pub cache_ttl_secs: u64,      // min 60, max 3600, default 300
       pub vpn_subnets: String,      // comma-separated CIDRs, e.g. "10.10.0.0/16,172.16.0.0/12"
   }
   ```

6. **`AdClient` struct** (Clone):
   ```rust
   pub struct AdClient {
       ldap_url: String,
       base_dn: String,
       require_tls: bool,
       cache: Mutex<GroupCache>,
       cache_ttl_secs: u64,
       vpn_subnets: Vec<IpNetwork>,
   }
   ```

7. **`AdClient::new(config: LdapConfig) -> Result<Self, AdClientError>`**:
   - Parse `vpn_subnets` comma-separated string into `Vec<IpNetwork>`
   - Return error if any CIDR is unparseable
   - Initialize empty `GroupCache`

8. **`AdClient::resolve_user_groups(&self, username: &str, caller_sid: &str) -> Result<Vec<String>, AdClientError>`**:
   - Check cache first (key = `caller_sid`)
   - On cache hit, return `Ok(groups)`
   - On cache miss:
     a. Connect LDAP (prefer LDAPS port 636; fall back to port 389)
     b. Bind with machine account: `format!("CN={},CN=Computers,{}", std::env::var("COMPUTERNAME").unwrap_or_default(), self.base_dn)` with empty password (uses Kerberos TGT)
     c. Search `base_dn` for `(sAMAccountName={username})`, subtree scope, attrs: `["distinguishedName", "tokenGroups"]`
     d. If no results → `Err(AdClientError::UserNotFound(username))`
     e. Parse `tokenGroups` binary values via `parse_sid_bytes` → `Vec<String>`
     f. Filter out own SID (`caller_sid`) from the result
     g. Insert into cache with current `Instant`
     h. Return `Ok(groups)`

9. **`AdClient::resolve_username_to_sid(&self, username: &str) -> Result<String, AdClientError>`**:
   - Same connect + bind
   - Search `base_dn` for `(sAMAccountName={username})`, attrs: `["objectSid"]`
   - If no results → `Err(AdClientError::UserNotFound(username))`
   - Parse first `objectSid` binary → string via `parse_sid_bytes`
   - Return `Ok(sid)`

10. **`get_device_trust() -> DeviceTrust`** (no async, uses windows crate):
    - On non-Windows: return `DeviceTrust::Unknown`
    - On Windows: call `NetIsPartOfDomain()` from `Win32_System_NetworkManagement` feature
    - Return `DeviceTrust::Managed` if true, else `DeviceTrust::Unmanaged`
    - Include `#[cfg(windows)]` conditional compilation

11. **`get_network_location(vpn_subnets: &[IpNetwork]) -> NetworkLocation`** (async):
    - On non-Windows: return `NetworkLocation::Unknown`
    - On Windows: call `GetAdaptersAddresses` from `Win32_NetworkManagement_IpHelper`
    - Find first non-loopback, non-link-local, non-multicast IPv4 address of the machine
    - If any `vpn_subnets.contains(local_ip)`: return `NetworkLocation::CorporateVpn`
    - Otherwise: log AD site name at debug level and return `NetworkLocation::Corporate`
    - If no local IP found: return `NetworkLocation::Unknown`
    - Include `#[cfg(windows)]` conditional compilation

**Windows feature flags**: The file should use `#[cfg(windows)]` to gate the Windows-specific functions. In the `windows` crate, `NetIsPartOfDomain` requires `Win32_System_NetworkManagement` feature and `GetAdaptersAddresses` requires `Win32_NetworkManagement_IpHelper`. The windows features should NOT be added to `dlp-common/Cargo.toml` — those functions are only called from `dlp-agent` which already has the windows crate. On non-Windows, `get_device_trust` returns `DeviceTrust::Unknown` and `get_network_location` returns `NetworkLocation::Unknown`.

**Fail-open**: All LDAP operations return `Ok(Vec::new())` on error (never `Err` to the caller). The error is logged at `warn` level first.
</action>

<acceptance_criteria>
- `dlp-common/src/ad_client.rs` exists and is non-empty
- `grep -n "parse_sid_bytes" dlp-common/src/ad_client.rs` returns the function definition
- `grep -n "AdClientError" dlp-common/src/ad_client.rs` returns at least 5 error variants
- `grep -n "GroupCache" dlp-common/src/ad_client.rs` returns struct and impl
- `grep -n "LdapConfig" dlp-common/src/ad_client.rs` returns the struct definition with all 5 fields
- `grep -n "resolve_user_groups" dlp-common/src/ad_client.rs` returns the method
- `grep -n "resolve_username_to_sid" dlp-common/src/ad_client.rs` returns the method
- `grep -n "get_device_trust" dlp-common/src/ad_client.rs` returns the function with `#[cfg(windows)]`
- `grep -n "get_network_location" dlp-common/src/ad_client.rs` returns the function with `#[cfg(windows)]`
- `grep -n "pub struct AdClient" dlp-common/src/ad_client.rs` returns the struct
- No `unsafe` blocks in `parse_sid_bytes` (use manual parse only)
- `cargo build -p dlp-common` compiles without errors
</acceptance_criteria>

---

### Task 4: Unit tests in `ad_client.rs`

<read_first>
`dlp-common/src/ad_client.rs` (the file just created in Task 3)
</read_first>

<action>
Add `#[cfg(test)]` module at the end of `ad_client.rs` with these tests:

1. `test_parse_sid_bytes_valid` — feed known SID byte sequences, verify correct `S-1-5-21-...` output
2. `test_parse_sid_bytes_invalid_too_short` — returns `None` when bytes < 8
3. `test_parse_sid_bytes_invalid_revision` — revision byte != 1 → `None`
4. `test_filter_own_sid` — verify that `caller_sid` does not appear in the filtered group list
5. `test_group_cache_ttl_eviction` — insert entry, wait (mock Instant), verify eviction on get
6. `test_vpn_subnet_parsing` — `"10.10.0.0/16,172.16.0.0/12"` parses to 2 networks; `"invalid"` returns error
7. `test_get_device_trust_non_windows` — on non-windows cfg, returns `DeviceTrust::Unknown`

For `test_group_cache_ttl_eviction`, since we can't use real time, test the logic by checking the evict_expired method removes entries older than ttl.
</action>

<acceptance_criteria>
- `cargo test -p dlp-common` runs with no failures
- `test_parse_sid_bytes_valid` passes
- `test_parse_sid_bytes_invalid_too_short` passes
- `test_group_cache_ttl_eviction` passes
- `test_vpn_subnet_parsing` passes
</acceptance_criteria>

---

## Verification

After all tasks complete:
- `cargo build -p dlp-common` → exit code 0, no warnings
- `cargo test -p dlp-common` → exit code 0
- `grep -n "pub mod ad_client" dlp-common/src/lib.rs` → exactly 1 match
- `grep -n "pub use ad_client" dlp-common/src/lib.rs` → all public types re-exported
- Plan 01 is complete when all acceptance criteria pass