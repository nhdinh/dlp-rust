---
phase: 07-active-directory-ldap-integration
plan: 03
subsystem: identity
tags: [ldap, active-directory, windows, app-state, fail-open]
provides:
  - phase: 09-admin-operation-audit-logging
    provides: AppState.ad for admin user_sid population on login
tech-stack: [axum, rusqlite, ldap3]
patterns: [fail-open AD initialization, DB-backed config loading, async AD client construction]
key-files:
  modified: [dlp-server/src/lib.rs, dlp-server/src/main.rs, dlp-agent/Cargo.toml]
key-decisions:
  - "AppState::ad is Option<AdClient> — None at startup when AD is unreachable"
  - "load_ldap_config() reads single-row ldap_config table; returns Option"
  - "AdClient::new() is async — awaited at startup; match drives fail-open"
  - "AppState derives Clone manually; custom Debug impl hides AdClient internals"
  - "dlp-agent gains Win32_Networking_ActiveDirectory feature for dlp_common re-export"
requirements-completed: [R-05]
commits:
  - hash: ebc7d93
    desc: feat(phase-07): wire AdClient into AppState with fail-open at startup
  - hash: a55581f
    desc: fix(phase-07): add Win32_Networking_ActiveDirectory feature to dlp-agent
deviations:
  - "load_ldap_config row parsing uses unwrap_or defaults (no early-return Option in closure)"
  - "AppState manually implements Debug instead of derive (AdClient lacks Debug)"
duration: ~15min
completed: 2026-04-14
---

# Plan 03: Server-Side AD Client Construction — Complete

`AdClient` is now constructed at `dlp-server` startup from the `ldap_config` DB table and made available via `AppState.ad` for Phase 9's admin SID resolution.

## What Was Done

1. **`AppState` extended** (`dlp-server/src/lib.rs`): Added `pub ad: Option<AdClient>` field. `AppState` manually implements `Debug` (via `impl std::fmt::Debug`) since `AdClient` does not implement `Debug`. The `ad` field in the `Debug` impl shows `"AdClient(...)"` or `"None"` to avoid leaking internals.

2. **`load_ldap_config()` helper** (`dlp-server/src/main.rs`): Reads the single-row `ldap_config` table, mapping columns to `LdapConfig` fields with sensible column-index access and `unwrap_or` defaults for all fields.

3. **Async AD client construction**: `main()` loads the config, awaits `AdClient::new(config)`, and wraps in a `match` — `Some(client)` on success, `None` + warning log on failure (fail-open). `AppState` is then built with `ad: ad_client`.

4. **dlp-agent windows feature fix** (`dlp-agent/Cargo.toml`): Added `Win32_Networking_ActiveDirectory` feature — required by `dlp_common::ad_client` re-exporting `DsGetSiteNameW` without which the workspace fails to resolve windows crate features.

## Verification

```
$ cargo build -p dlp-server
   Finished `dev` profile [unoptimized + debuginfo] target(s) in 4.73s
```

All acceptance criteria:
- `grep -n "use dlp_common::AdClient" dlp-server/src/lib.rs` → line 22
- `grep -n "pub ad:" dlp-server/src/lib.rs` → line 38
- `grep -n "Option<AdClient>" dlp-server/src/lib.rs` → line 38
- `grep -n "use dlp_common::ad_client" dlp-server/src/main.rs` → line 30
- `grep -n "load_ldap_config" dlp-server/src/main.rs` → line 42
- `grep -n "AdClient::new" dlp-server/src/main.rs` → line 187
- `grep -n "ad: ad_client" dlp-server/src/main.rs` → line 199
