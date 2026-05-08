---
estimated_steps: 1
estimated_files: 2
skills_used: []
---

# T01: Active Directory LDAP integration

Implement LDAP client using ldap3 crate. Query AD for transitive group membership via tokenGroups. Device trust via NetGetJoinInformation. Network location via GetAdaptersAddresses + VPN subnet matching. Machine account Kerberos TGT bind. Channel-based async with mpsc + oneshot. Configurable TTL cache. Fail-open on error.

## Inputs

- `ldap3 crate`
- `AD schema`
- `Kerberos TGT`

## Expected Output

- `ad_client.rs module`
- `LDAP query helpers`
- `Group cache`
- `Device trust check`
- `Network location check`
- `Unit tests`

## Verification

cargo test --package dlp-common ad_client:: && cargo test --package dlp-agent identity::
