# Plan 02 SUMMARY — DB Schema + Admin API (`dlp-server`)

**Phase:** 07 — Active Directory LDAP Integration
**Plan:** 02 — DB Schema + Admin API
**Status:** ✅ Complete
**Date:** 2026-04-16

---

## What Was Built

Added the `ldap_config` SQLite table and `GET/PUT /admin/ldap-config` admin API handlers to `dlp-server`, mirroring the established Phase 3.1/4 pattern for `siem_config` and `alert_router_config`.

---

## Files Changed

| File | Change |
|------|--------|
| `dlp-server/src/db/mod.rs` | Added `ldap_config` table + seed row + unit test |
| `dlp-server/src/db/repositories/ldap_config.rs` | New repository module (`LdapConfigRepository`, `LdapConfigRow`) |
| `dlp-server/src/db/repositories/mod.rs` | Re-exported `LdapConfigRepository`, `LdapConfigRow` |
| `dlp-server/src/admin_api.rs` | Added `LdapConfigPayload`, `GET /admin/ldap-config`, `PUT /admin/ldap-config` handlers |
| `dlp-server/src/admin_api.rs` | Added routes `get_ldap_config_handler`, `update_ldap_config_handler` |
| `dlp-server/Cargo.toml` | `ldap3 = { workspace = true }` already present (carried from Plan 01) |
| `dlp-server/tests/ldap_config_api.rs` | Integration tests (4 tests) |

---

## Tasks Executed

| # | Task | Result |
|---|------|--------|
| 1 | `ldap3` dependency check | ✅ Already present in workspace; `dlp-server/Cargo.toml` uses `ldap3 = { workspace = true }` |
| 2 | `ldap_config` table in `db/mod.rs` | ✅ Added with `CHECK (id = 1)`, all 6 columns, seed row via `INSERT OR IGNORE` |
| 3 | Unit test `test_ldap_config_seed_row` | ✅ Passes: table exists, exactly 1 seed row, defaults verified |
| 4 | `GET /admin/ldap-config` handler | ✅ `get_ldap_config_handler` — reads via `LdapConfigRepository::get`, returns `LdapConfigPayload` |
| 5 | `PUT /admin/ldap-config` handler | ✅ `update_ldap_config_handler` — validates `cache_ttl_secs` ∈ [60, 3600], writes via `LdapConfigRepository::update` |

---

## Verification Results

| Check | Result |
|-------|--------|
| `cargo build -p dlp-server` | ✅ Passes — zero warnings, zero errors |
| `cargo test -p dlp-server -- db::tests::test_ldap_config_seed_row` | ✅ Passes |
| `cargo test -p dlp-server` (full suite) | ✅ 4/4 LDAP integration tests pass; 105 total tests pass |
| `cargo clippy -p dlp-server -- -D warnings` | ✅ Passes — no warnings |
| `cargo fmt --check` | ✅ Passes — correctly formatted |

---

## Architecture Notes

- **DB layer:** Uses the Repository + Unit-of-Work pattern introduced in Phase 99. `LdapConfigRepository::get(pool)` and `LdapConfigRepository::update(uow, record)` follow the same contract as `SiemConfigRepository` and `AlertRouterConfigRepository`.
- **Admin API:** `LdapConfigPayload` struct (lines 211–228) covers all 5 editable columns. Both GET and PUT are under JWT protection (`.layer(middleware::from_fn(admin_auth::require_auth))`).
- **Validation:** `cache_ttl_secs` is clamped at read time by `LdapConfig::effective_cache_ttl()` in `dlp-common/src/ad_client.rs` (returns 60 if < 60, 3600 if > 3600) and validated at PUT time in the handler (rejects < 60 or > 3600 with `AppError::BadRequest`).
- **`ad` field in `AppState`:** `AppState` has `ad: Option<AdClient>` field — set to `None` here, wired in Plan 03.

---

## Dependencies

- `ldap3 = { workspace = true }` in `dlp-server/Cargo.toml` (added in Plan 01)
- `LdapConfigRepository` from `dlp-server/src/db/repositories/ldap_config.rs`

---

## Downstream Work

- **Plan 03:** Wire `AdClient` into `dlp-server` main.rs startup (construct from DB, add to `AppState.ad`)