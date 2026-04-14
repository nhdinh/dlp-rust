---
wave: 2
depends_on:
  - "01-ad-client-crate"
  - "02-db-schema-and-admin-api"
requirements:
  - R-05
files_modified:
  - dlp-agent/src/identity.rs
  - dlp-agent/src/lib.rs
  - dlp-agent/src/server_client.rs
  - dlp-agent/Cargo.toml
  - dlp-agent/src/service.rs
autonomous: false
---

# Plan 04: Agent Integration — AD Group Resolution

## Goal

Wire the `AdClient` into `dlp-agent` so that `identity.rs`'s `WindowsIdentity::to_subject()` is replaced with AD-resolved attributes (`groups`, `device_trust`, `network_location`) instead of placeholder values. The LDAP config arrives via the pushed agent config (Phase 6 `AgentConfigPayload`).

---

## must_haves

- `AdClient` is constructed at agent startup (from pushed `LdapConfigPayload` in `AgentConfigPayload`)
- `AdClient` is stored in `Arc` so all interception threads share it
- `identity.rs` exposes `to_subject_with_ad(&self, ad_client: &AdClient)` that replaces placeholders with AD-resolved values
- `engine_client.rs`'s `EvaluateRequest` is built with AD-resolved `Subject` (groups, device_trust, network_location all populated)
- Fail-open: if AD is unreachable, `groups` returns `Vec::new()`, `device_trust` returns `Unmanaged`, `network_location` returns `Corporate`
- Agent compiles without errors

---

## Tasks

### Task 1: Add Windows crate features for AD resolution functions (`dlp-agent/Cargo.toml`)

<read_first>
`dlp-agent/Cargo.toml`
</read_first>

<action>
Add the following Windows crate features to `dlp-agent/Cargo.toml` to support `NetIsPartOfDomain`, `GetAdaptersAddresses`, and `DsGetSiteName` (AD site lookup):

In the existing `windows` dependency's `features` array, add these strings:
```
"Win32_System_NetworkManagement",
"Win32_NetworkManagement_IpHelper",
"Win32_System_RemoteDesktop",
```

**Important**: `DsGetSiteNameW` is confirmed to be in `Win32_System_RemoteDesktop` feature (already present as `"Win32_System_RemoteDesktop"`). `NetIsPartOfDomain` is in `Win32_System_NetworkManagement`. `GetAdaptersAddresses` is in `Win32_NetworkManagement_IpHelper`.
</action>

<acceptance_criteria>
- `dlp-agent/Cargo.toml` contains `"Win32_System_NetworkManagement"` in the windows features list
- `dlp-agent/Cargo.toml` contains `"Win32_NetworkManagement_IpHelper"` in the windows features list
- `grep -n "Win32_System_RemoteDesktop" dlp-agent/Cargo.toml` confirms it is already present (should be, per existing clipboard features)
</acceptance_criteria>

---

### Task 2: Add `LdapConfigPayload` to `AgentConfigPayload` (`dlp-agent/src/server_client.rs`)

<read_first>
`dlp-agent/src/server_client.rs` — find `AgentConfigPayload` struct definition
</read_first>

<action>
In `dlp-agent/src/server_client.rs`, add a new struct and embed it in `AgentConfigPayload`:

**Step A**: Add the new payload type after the imports:
```rust
/// LDAP configuration pushed from the server to the agent.
/// A subset of `dlp_common::ad_client::LdapConfig` — contains no credentials.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LdapConfigPayload {
    pub ldap_url: String,
    pub base_dn: String,
    pub require_tls: bool,
    pub cache_ttl_secs: u64,
    pub vpn_subnets: String,
}
```

**Step B**: Add the field to `AgentConfigPayload`:
Find the `AgentConfigPayload` struct in `server_client.rs` and add:
```rust
pub ldap_config: Option<LdapConfigPayload>,
```

**Step C**: Add the import for `dlp_common::AdClient` at the top of `server_client.rs` (for the `LdapConfigPayload` conversion):
```rust
use dlp_common::ad_client::LdapConfig as AdLdapConfig;
```

**Step D**: In the `AgentConfig` struct (the in-memory config that gets written to `agent-config.toml`), add an `ldap_config: Option<LdapConfigPayload>` field. This ensures the LDAP config is persisted to disk alongside other pushed config. When loading from disk at startup (before first config push), the field will be `None` and AD resolution will be skipped gracefully.

Look for `pub struct AgentConfig` in `server_client.rs` and add:
```rust
pub ldap_config: Option<LdapConfigPayload>,
```

**Step E**: Add the `From<AdLdapConfig> for LdapConfigPayload` conversion:
```rust
impl From<AdLdapConfig> for LdapConfigPayload {
    fn from(config: AdLdapConfig) -> Self {
        Self {
            ldap_url: config.ldap_url,
            base_dn: config.base_dn,
            require_tls: config.require_tls,
            cache_ttl_secs: config.cache_ttl_secs,
            vpn_subnets: config.vpn_subnets,
        }
    }
}
```

Note: This requires that `dlp_common::ad_client::LdapConfig` is public. Verify that `dlp-common/src/lib.rs` re-exports it (from Plan 01).
</action>

<acceptance_criteria>
- `grep -n "LdapConfigPayload" dlp-agent/src/server_client.rs` returns the struct definition
- `grep -n "ldap_config: Option<LdapConfigPayload>" dlp-agent/src/server_client.rs` returns the field in `AgentConfigPayload`
- `grep -n "pub ldap_config: Option<LdapConfigPayload>" dlp-agent/src/server_client.rs` returns the field in `AgentConfig`
- `grep -n "impl From<AdLdapConfig> for LdapConfigPayload" dlp-agent/src/server_client.rs` returns the conversion impl
- `grep -n "use dlp_common::ad_client" dlp-agent/src/server_client.rs` returns the import
</acceptance_criteria>

---

### Task 3: `identity.rs` — add `to_subject_with_ad()` method

<read_first>
`dlp-agent/src/identity.rs`
`dlp-common/src/ad_client.rs` — for `AdClient` and `get_device_trust`, `get_network_location` signatures
</read_first>

<action>
In `dlp-agent/src/identity.rs`, add a new async method to `WindowsIdentity`:

**Step A**: Add the import at the top of the file:
```rust
use dlp_common::ad_client::{self, AdClient, LdapConfigPayload};
```

**Step B**: Add a new method on `WindowsIdentity`:
```rust
/// Converts this identity into an ABAC [`Subject`] using Active Directory for attribute resolution.
///
/// This replaces the placeholder values in [`to_subject`](Self::to_subject) with live AD data.
///
/// # Arguments
///
/// * `ad_client` — the AD client (constructed from pushed LDAP config)
/// * `vpn_subnets` — VPN subnet ranges from LDAP config (comma-separated CIDR list)
///
/// # Fail-open behavior
///
/// When AD is unreachable, groups fall back to `Vec::new()`, `device_trust` to
/// `Unmanaged`, and `network_location` to `Corporate`. This is intentional — blocking
/// legitimate work during AD outages is worse than allowing it with reduced enforcement.
pub async fn to_subject_with_ad(
    &self,
    ad_client: &AdClient,
    vpn_subnets: &[String],
) -> Subject {
    // Resolve group membership via LDAP (fail-open: empty on error).
    let groups = ad_client
        .resolve_user_groups(&self.username, &self.sid)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(
                error = %e,
                sid = %self.sid,
                username = %self.username,
                "AD group lookup failed — using empty groups (fail-open)"
            );
            Vec::new()
        });

    // Resolve device trust via Windows API (local, no network dependency).
    let device_trust = ad_client::get_device_trust();

    // Resolve network location (AD site + VPN subnet check).
    let network_location = ad_client::get_network_location(vpn_subnets).await;

    Subject {
        user_sid: self.sid.clone(),
        user_name: self.username.clone(),
        groups,
        device_trust,
        network_location,
    }
}
```

**Step C**: Update the existing `to_subject()` doc comment to note it is now a fallback:
Add a `#[deprecated(since = "0.3.0", note = "Use to_subject_with_ad() instead")]`.
</action>

<acceptance_criteria>
- `grep -n "to_subject_with_ad" dlp-agent/src/identity.rs` returns the method definition
- `grep -n "pub async fn to_subject_with_ad" dlp-agent/src/identity.rs` returns the async method
- `grep -n "resolve_user_groups" dlp-agent/src/identity.rs` returns the call site
- `grep -n "get_device_trust" dlp-agent/src/identity.rs` returns the call site
- `grep -n "get_network_location" dlp-agent/src/identity.rs` returns the call site
- `grep -n "#[deprecated]" dlp-agent/src/identity.rs` returns the deprecation attribute on `to_subject()`
</acceptance_criteria>

---

### Task 4: Wire `AdClient` construction into agent service startup (`dlp-agent/src/service.rs`)

<read_first>
`dlp-agent/src/service.rs` — find the initialization section (where `EngineClient` is constructed, where `AgentConfig` is loaded)
</read_first>

<action>
In `dlp-agent/src/service.rs`, add `AdClient` construction at startup:

**Step A**: Add the import:
```rust
use dlp_common::ad_client::{AdClient, LdapConfig};
```

**Step B**: Find where `AgentConfig` is loaded (look for `agent_config.toml` or `AgentConfig::load`). After the config is loaded, construct the `AdClient` if `ldap_config` is present in the pushed config:

```rust
// Construct the AD client from pushed LDAP config (if present).
// AdClient is stored in Arc so all interception threads share it.
let ad_client: Option<AdClient> = agent_config
    .ldap_config
    .as_ref()
    .map(|ldap_config| {
        let config = LdapConfig {
            ldap_url: ldap_config.ldap_url.clone(),
            base_dn: ldap_config.base_dn.clone(),
            require_tls: ldap_config.require_tls,
            cache_ttl_secs: ldap_config.cache_ttl_secs,
            vpn_subnets: ldap_config.vpn_subnets.clone(),
        };
        match AdClient::new(config) {
            Ok(client) => {
                tracing::info!("AD client initialized from pushed config");
                client
            }
            Err(e) => {
                tracing::warn!(error = %e, "AD client initialization failed — AD features disabled for this session");
                // Return the client anyway; it will fail open at resolution time.
                // Create a minimal client with empty config so the Arc is still valid.
                AdClient::new(LdapConfig {
                    ldap_url: String::new(),
                    base_dn: String::new(),
                    require_tls: false,
                    cache_ttl_secs: 300,
                    vpn_subnets: String::new(),
                })
                .unwrap_or_else(|_| {
                    // This should never happen with empty config but handle defensively.
                    panic!("critical: cannot construct fallback AdClient");
                })
            }
        }
    });

let ad_client = Arc::new(ad_client);
```

**Step C**: Pass the `ad_client` arc to `engine_client.rs` and `identity.rs` call sites. Find the call sites that use the `IdentityResolver` or build `EvaluateRequest`. The `ad_client` should be passed as `Arc<Option<AdClient>>` so callers can check if AD is configured before attempting resolution.

```rust
let ad_client: Arc<Option<AdClient>> = ad_client.map(Arc::new).unwrap_or_else(|| Arc::new(None));
```

Note: Pass `Arc<Option<AdClient>>` rather than `Option<AdClient>` to avoid cloning the client on every file operation.
</action>

<acceptance_criteria>
- `grep -n "Arc<Option<AdClient>>" dlp-agent/src/service.rs` returns the field declaration
- `grep -n "AdClient::new" dlp-agent/src/service.rs` returns the construction call
- `grep -n "ad_client" dlp-agent/src/service.rs` returns at least 3 references (import, construction, storage)
- `cargo build -p dlp-agent --lib` → exit code 0, no warnings
</acceptance_criteria>

---

### Task 5: Update `engine_client.rs` to use AD-resolved `Subject`

<read_first>
`dlp-agent/src/engine_client.rs` — find where `EvaluateRequest` is built (look for `EvaluateRequest {` or `subject:`)
</read_first>

<action>
In `dlp-agent/src/engine_client.rs`, find where `EvaluateRequest` is built with `subject:` and update it to use AD-resolved attributes:

**Step A**: Add the import:
```rust
use dlp_common::ad_client::{self as ad_client_module, AdClient};
```

**Step B**: Find the `evaluate` method and the `EvaluateRequest` construction. The `subject:` field currently uses `identity.to_subject()` which has placeholder values. Replace it with a call to `to_subject_with_ad()`:

```rust
// Resolve AD attributes for the calling user.
// Pass the VPN subnets from the pushed LDAP config (if AD is configured).
let vpn_subnets: Vec<String> = ad_client
    .as_ref()
    .map(|client| {
        // Extract vpn_subnets from the client's internal config.
        // We need to expose vpn_subnets on AdClient (or pass it separately).
        // For now: parse from the stored config or use empty.
        Vec::new()
    })
    .unwrap_or_default();

let subject = if let Some(client) = ad_client.as_ref() {
    identity.to_subject_with_ad(client, &vpn_subnets).await
} else {
    identity.to_subject()  // fallback to placeholder (deprecation warning expected)
};
```

**Note**: If `AdClient` doesn't expose `vpn_subnets()` getter yet, add a helper method:
```rust
impl AdClient {
    /// Returns the configured VPN subnets as a slice of CIDR strings.
    pub fn vpn_subnets(&self) -> Vec<String> {
        // Parse from stored config string
        self.vpn_subnets
            .iter()
            .map(|n| n.to_string())
            .collect()
    }
}
```

Add this method to `dlp-common/src/ad_client.rs` in the `AdClient` impl block.

**Step C**: Update the `EvaluateRequest` construction to use the resolved `subject`:
```rust
let request = EvaluateRequest {
    subject,       // replaced: was identity.to_subject()
    resource,
    environment,
    action,
    agent: Some(AgentInfo {
        machine_name: Some(hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_default()),
        current_user: Some(identity.username.clone()),
    }),
};
```
</action>

<acceptance_criteria>
- `grep -n "to_subject_with_ad" dlp-agent/src/engine_client.rs` returns the call site
- `grep -n "EvaluateRequest {" dlp-agent/src/engine_client.rs` shows `subject` field is set to the resolved `subject`
- `cargo build -p dlp-agent --lib` → exit code 0, no warnings
</acceptance_criteria>

---

## Verification

After all tasks complete:
- `cargo build -p dlp-agent --lib` → exit code 0, no warnings
- `cargo test -p dlp-agent` → exit code 0
- `grep -n "to_subject_with_ad" dlp-agent/src/identity.rs` → returns the method definition
- `grep -n "LdapConfigPayload" dlp-agent/src/server_client.rs` → returns the struct
- Plan 04 is complete when all acceptance criteria pass