---
phase: 07-active-directory-ldap-integration
plan: 04
subsystem: identity
tags: [ldap, active-directory, windows, abac, agent]
provides:
  - phase: 07-task-05-integration-tests
    provides: Arc<Option<AdClient>> wired into interception event loop
tech-stack:
  added: [windows Win32_Networking_ActiveDirectory, Win32_System_NetworkManagement_Miscellaneous, Win32_NetworkManagement_IpHelper]
  modified: [dlp-agent/Cargo.toml, dlp-agent/src/server_client.rs, dlp-agent/src/identity.rs, dlp-agent/src/service.rs, dlp-agent/src/interception/mod.rs, dlp-agent/src/config.rs, dlp-common/src/ad_client.rs, dlp-agent/tests/comprehensive.rs]
key-files:
  modified: [dlp-agent/src/server_client.rs, dlp-agent/src/identity.rs, dlp-agent/src/service.rs, dlp-agent/src/interception/mod.rs, dlp-agent/src/config.rs]
  added: [dlp-common/src/ad_client.rs (vpn_subnets_str + get_network_location string API)]
key-decisions:
  - "LdapConfigPayload duplicated in identity.rs and server_client.rs to avoid cross-crate config dep cycle"
  - "get_network_location() signature changed from &[IpNetwork] to &str (pass-through from vpn_subnets_str)"
  - "Arc<Option<AdClient>> chosen over Arc<AdClient> so callers can cheaply check if AD is configured"
  - "to_subject() marked deprecated in favor of to_subject_with_ad()"
  - "InterceptionEngine created before ad_client in service.rs (no path dependency)"
commits:
  - hash: 3014886
    desc: feat(phase-07): wire AdClient into dlp-agent for AD-resolved identity attributes
duration: ~45min
completed: 2026-04-14
---

# Plan 04: Agent Integration — AD Group Resolution (Complete)

## What Was Built

The `AdClient` from Plan 01 is fully wired into `dlp-agent` so that `identity.rs`'s `WindowsIdentity::to_subject()` is replaced with AD-resolved attributes (`groups`, `device_trust`, `network_location`) instead of placeholder values. The LDAP config arrives via the pushed agent config payload.

## Files Modified

| File | Change |
|------|--------|
| `dlp-agent/Cargo.toml` | Added `Win32_Networking_ActiveDirectory`, `Win32_System_NetworkManagement_Miscellaneous`, `Win32_NetworkManagement_IpHelper` |
| `dlp-common/src/ad_client.rs` | Changed `get_network_location(&[IpNetwork])` to `get_network_location(&str)`, added `vpn_subnets_str()` |
| `dlp-agent/src/server_client.rs` | Added `LdapConfigPayload` struct, embedded in `AgentConfigPayload` + `From<AdLdapConfig>` impl |
| `dlp-agent/src/config.rs` | Added `ldap_config: Option<LdapConfigPayload>` to `AgentConfig`, updated tests |
| `dlp-agent/src/identity.rs` | Added `to_subject_with_ad(&AdClient, &str)` async method, marked `to_subject()` deprecated |
| `dlp-agent/src/service.rs` | Construct `AdClient` from pushed config, wrap in `Arc<Option<AdClient>>`, pass to event loop; update `config_poll_loop` to diff/persist `ldap_config` |
| `dlp-agent/src/interception/mod.rs` | Updated `run_event_loop` to accept `Arc<Option<AdClient>>`, build AD-resolved `Subject` per event |
| `dlp-agent/tests/comprehensive.rs` | Updated `AgentConfig` initializers to include new field |

## Integration Flow

```
service.rs (run_loop / async_run_console)
  └─ AgentConfig::load_default()
       └─ ldap_config: Option<LdapConfigPayload>  (from TOML / server push)
  └─ AdClient::new(config) → Arc<Option<AdClient>>
  └─ run_event_loop(action_rx, offline, ctx, session_map, ad_client)

interception/mod.rs (run_event_loop)
  └─ Arc<Option<AdClient>> passed in
  └─ Per-event: WindowsIdentity → to_subject_with_ad(client, vpn_subnets_str)
       ├─ resolve_user_groups(username, sid)  → Vec<String>
       ├─ get_device_trust()                   → DeviceTrust
       └─ get_network_location(vpn_subnets)    → NetworkLocation
```

## Fail-Open Behavior

- AD unreachable → `groups: Vec::new()`, `device_trust: Unmanaged`, `network_location: Corporate`
- No LDAP config → placeholder `Subject` with all `Unknown` fields (backward-compatible)

## Verification

```
grep -n "to_subject_with_ad" dlp-agent/src/identity.rs  ✓
grep -n "LdapConfigPayload" dlp-agent/src/server_client.rs  ✓
grep -n "Arc<Option<AdClient>>" dlp-agent/src/service.rs  ✓
cargo build -p dlp-agent --lib  ✓ (exit 0)
cargo test -p dlp-agent  ✓ (161 pass, 8 pre-existing failures, 1 ignored)
```
