---
sliceId: S06
title: LDAP config TUI
status: complete
completedAt: 2026-05-04
tasksCompleted: 3
---

# S06: LDAP config TUI

## What was delivered

Admin TUI screen for LDAP configuration management. Seven-row form (5 editable fields + Save + Back) allows configuring ldap_url, base_dn, require_tls, cache_ttl_secs, and vpn_subnets. Wired end-to-end with server LdapConfigPayload API.

## Key files

- `dlp-admin-cli/src/screens/` — LDAP config screen components
- `dlp-server/src/db/repositories/ldap_config.rs` — server-side LDAP config storage

## Decisions made

- 7 rows: 5 editable + Save + Back (mirrors AlertConfig sizing)
- Field order locked: ldap_url, base_dn, require_tls, cache_ttl_secs, vpn_subnets
- cache_ttl_secs validation range [60, 3600]
