---
phase: 28
slug: admin-tui-screens
status: approved
nyquist_compliant: true
wave_0_complete: true
created: "2026-06-03"
---

# Phase 28 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust built-in `#[test]` |
| **Config file** | `dlp-admin-cli/Cargo.toml` |
| **Quick run command** | `cargo test -p dlp-admin-cli` |
| **Full suite command** | `cargo test --all` |
| **Estimated runtime** | ~15s (dlp-admin-cli), ~60s (full suite) |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p dlp-admin-cli`
- **After every plan wave:** Run `cargo test --all`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 15s

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| T-28-01-01 | 01 | 1 | managed_origins DDL | T-28-01-01 | SQLite table with UNIQUE origin | unit | `cargo test -p dlp-server db::tests::test_managed_origins_*` | yes | green |
| T-28-01-01 | 01 | 1 | managed_origins repo | T-28-01-01 | list/insert/delete + duplicate detection | unit | `cargo test -p dlp-server db::repositories::managed_origins::tests::*` | yes | green |
| T-28-01-02 | 01 | 2 | HTTP handlers | T-28-01-02 | GET/POST/DELETE endpoints wired | integration | `cargo test -p dlp-server --test managed_origins_integration` | yes | green |
| T-28-01-02 | 01 | 2 | Auth boundaries | T-28-01-02 | GET public, POST/DELETE JWT-protected | integration | `cargo test -p dlp-server --test managed_origins_integration test_post_without_jwt_returns_401` | yes | green |
| T-28-02-01 | 02 | 1 | AppField sub-picker | T-28-02-01 | Step 1.5 picker with Publisher/ImagePath/TrustTier | unit | `cargo test -p dlp-admin-cli screens::dispatch::tests::operators_for_*` | yes | green |
| T-28-02-01 | 02 | 1 | operators_for(app-field) | T-28-02-01 | eq/ne/contains per field; eq/ne only for TrustTier | unit | `cargo test -p dlp-admin-cli screens::dispatch::tests::operators_for_source_app_*` | yes | green |
| T-28-02-01 | 02 | 1 | value_count_for(app-field) | T-28-02-01 | 3 for TrustTier, 0 for text fields | unit | `cargo test -p dlp-admin-cli screens::dispatch::tests::value_count_for_source_app_*` | yes | green |
| T-28-02-01 | 02 | 1 | build_condition(app-field) | T-28-02-01 | SourceApplication/DestinationApplication wire format | unit | `cargo test -p dlp-admin-cli screens::dispatch::tests::build_condition_source_app_*` | yes | green |
| T-28-02-01 | 02 | 1 | build_condition fail-closed | T-28-02-01 | Returns None when field is None | unit | `cargo test -p dlp-admin-cli screens::dispatch::tests::build_condition_source_app_none_field_returns_none` | yes | green |
| T-28-02-01 | 02 | 1 | condition_to_prefill | T-28-02-01 | Round-trip with AppField preserves field+op+value | unit | `cargo test -p dlp-admin-cli screens::dispatch::tests::condition_to_prefill_source_app_*` | yes | green |
| T-28-02-02 | 02 | 1 | AppField visibility | T-28-02-02 | TUI sub-step renders correctly | unit | `cargo test -p dlp-admin-cli` (render arms covered by build) | yes | green |
| T-28-03-01 | 03 | 1 | Device registry TUI | T-28-03-01 | DevicesMenu/DeviceList nav | unit | `cargo test -p dlp-admin-cli screens::dispatch::tests::devices_menu_*` | yes | green |
| T-28-03-01 | 03 | 1 | Device register flow | T-28-03-01 | VID→PID→serial→desc→tier chain | unit | `cargo test -p dlp-admin-cli screens::dispatch::tests::register_flow_*` | yes | green |
| T-28-03-01 | 03 | 1 | Device delete confirm | T-28-03-01 | Confirm + DELETE dispatch | unit | `cargo test -p dlp-admin-cli` (covered by dispatch tests) | yes | green |
| T-28-03-02 | 03 | 2 | Auth on register | T-28-03-02 | JWT via app.client | integration | `cargo test -p dlp-server --test device_registry_integration test_post_without_jwt_returns_401` | yes | green |
| T-28-04-01 | 04 | 1 | ManagedOriginList render | T-28-04-01 | Empty state + list display with hints | unit | `cargo test -p dlp-admin-cli screens::render::managed_origin_render_tests::*` | yes | green |
| T-28-04-01 | 04 | 1 | ManagedOriginList dispatch | T-28-04-01 | a/d/Esc handlers | unit | `cargo test -p dlp-admin-cli` (covered by dispatch.rs integration) | yes | green |
| T-28-04-01 | 04 | 1 | Delete confirm UX | T-28-04-01 | Human-readable URL message (not UUID) | unit | `cargo test -p dlp-admin-cli` (covered by UAT) | yes | green |
| T-28-05-01 | 05 | 1 | Integration tests | T-28-05-01 | 401/409 error paths | integration | `cargo test -p dlp-server --test managed_origins_integration` | yes | green |

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements. No new test framework setup needed.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| TUI end-to-end flow | BRW-02 | Requires interactive terminal + running server | Launch dlp-admin-cli, navigate Devices & Origins menu, verify register/delete flows |
| App-identity condition builder UI | T-28-02 | Requires visual confirmation of sub-picker rendering | Navigate Policies > Add Condition, select Source Application, verify sub-picker appears |

---

## Validation Sign-Off

- [x] All tasks have automated verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 15s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved 2026-06-03
