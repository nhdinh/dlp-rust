---
id: T01
parent: S01
milestone: M015
key_files:
  - dlp-common/src/ad_client.rs
  - dlp-agent/src/identity.rs
key_decisions:
  - (none)
duration: 
verification_result: passed
completed_at: 2026-05-08T05:46:43.772Z
blocker_discovered: false
---

# T01: Active Directory LDAP integration with group membership, device trust, and network location.

**Active Directory LDAP integration with group membership, device trust, and network location.**

## What Happened

Implemented LDAP client using ldap3 crate. Queried AD for transitive group membership via tokenGroups. Device trust via NetGetJoinInformation. Network location via GetAdaptersAddresses + VPN subnet matching. Machine account Kerberos TGT bind. Channel-based async with cache. Fail-open on error.

## Verification

AD client and identity tests pass.

## Verification Evidence

| # | Command | Exit Code | Verdict | Duration |
|---|---------|-----------|---------|----------|
| 1 | `cargo test --package dlp-common ad_client:: && cargo test --package dlp-agent identity::` | 0 | ✅ pass | 20000ms |

## Deviations

None. Completed during original v0.3.0 phase execution (2026-04-16).

## Known Issues

None.

## Files Created/Modified

- `dlp-common/src/ad_client.rs`
- `dlp-agent/src/identity.rs`
