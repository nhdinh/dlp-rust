# S01: Active Directory LDAP Integration (Phase 7)

**Goal:** Integrate Active Directory LDAP for real ABAC attribute resolution.
**Demo:** AD group membership, device trust, and network location resolved via LDAP with configurable TTL cache.

## Must-Haves

- 1. LDAP queries for transitive group membership
- 2. Device trust via NetGetJoinInformation
- 3. Network location via VPN subnet matching
- 4. Channel-based async with cache

## Proof Level

- This slice proves: tested

## Integration Closure

Provides identity attributes for ABAC evaluator introduced in S05.

## Verification

- None — identity resolution.

## Tasks

- [x] **T01: Active Directory LDAP integration** `est:6h`
  Implement LDAP client using ldap3 crate. Query AD for transitive group membership via tokenGroups. Device trust via NetGetJoinInformation. Network location via GetAdaptersAddresses + VPN subnet matching. Machine account Kerberos TGT bind. Channel-based async with mpsc + oneshot. Configurable TTL cache. Fail-open on error.
  - Files: `dlp-common/src/ad_client.rs`, `dlp-agent/src/identity.rs`
  - Verify: cargo test --package dlp-common ad_client:: && cargo test --package dlp-agent identity::

## Files Likely Touched

- dlp-common/src/ad_client.rs
- dlp-agent/src/identity.rs
