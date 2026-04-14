---
phase: 07-active-directory-ldap-integration
plan: 01
subsystem: identity
tags: [ldap, active-directory, windows, kerberos, abac]
provides:
  - phase: 04-wire-alert-router-into-server
    provides: ldap_config table, GET/PUT /admin/ldap-config handlers
  - phase: 09-admin-operation-audit-logging
    provides: AdClient::resolve_username_to_sid for admin user_sid population
tech-stack:
  added: [ldap3, ipnetwork, parking_lot, windows 0.61]
  patterns: [machine-account Kerberos bind, TTL group cache, MS-DTYP binary SID parse, fail-open AD ops]
key-files:
  created: [dlp-common/src/ad_client.rs]
  modified: [dlp-common/src/lib.rs, dlp-common/Cargo.toml]
key-decisions:
  - "parse_sid_bytes reads 6-byte big-endian u48 authority per MS-DTYP (not 8-byte)"
  - "DsGetSiteNameW buffer allocated with std::alloc (no LocalFree in windows 0.61)"
patterns-established:
  - "Async LDAP via ldap3 with machine-account Kerberos (no stored credentials)"
  - "Group cache keyed by caller_sid with TTL eviction on every get/insert"
  - "Windows API for device trust: NetGetJoinInformation with NETSETUP_JOIN_STATUS(3)=domain-joined"
requirements-completed: [R-05]
commits:
  - hash: d0ded4c
    desc: task 1 add ldap3/ipnetwork/parking_lot to dlp-common deps
  - hash: 6cc8a63
    desc: feat(phase-07): complete AD client crate in dlp-common (full implementation + tests)
deviations:
  - "Fixed windows crate feature names: Win32_NetworkManagement_NetManagement (not System_NetworkManagement)"
  - "Removed Win32_NetworkManagement_Ndis duplicate, kept it (required for GetAdaptersAddresses)"
  - "Removed unused Win32_System_Memory (LocalFree not exported), allocated buffer manually instead"
  - "Fixed parse_sid_bytes test: MS-DTYP 6-byte authority, not 8-byte to_be_bytes"
  - "Fixed NetApiBufferFree: takes Option<*const c_void>, not raw pointer"
duration: ~30min
completed: 2026-04-14
---

# Plan 01: AD Client Crate (`dlp-common/src/ad_client.rs`) — Complete

AD/LDAP client implemented in `dlp-common` with machine-account Kerberos bind, TTL-based group cache, Windows API device trust via `NetGetJoinInformation`, and network location via `GetAdaptersAddresses` + VPN subnet check. Binary SID parsing follows MS-DTYP specification. All 40 dlp-common tests pass.
