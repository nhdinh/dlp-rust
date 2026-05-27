---
phase: 52-dacl-tripwire-repair-watcher-protected-paths-dpapi-recovery-
validation: true
last_updated: 2026-05-27
---

# Phase 52 Validation Strategy

## Dimensions

| Dimension | Method | Coverage |
|-----------|--------|----------|
| Unit | `cargo test -p <crate> <module>` | All new modules (dacl_tripwire, dacl_repair_watcher, dacl_staging, protected_paths repository) |
| Integration | `cargo test --workspace` | Cross-module wiring (config diff -> staging -> watcher suppression) |
| Static | `cargo clippy --workspace -- -D warnings` | Linting across all modified crates |
| Documentation | `test -f docs/operations/dpapi-recovery.md` | Runbook existence and content verification |

## Test Strategy

### Per-Requirement Test Map

| Req ID | Behavior | Test Type | Automated Command | File |
|--------|----------|-----------|-------------------|------|
| DACL-01 | Tripwire writer applies Deny ACE to protected path | unit | `cargo test -p dlp-agent dacl_tripwire` | dlp-agent/src/dacl_tripwire.rs |
| DACL-01 | 60 KB ACL guard rejects oversized ACLs | unit | `cargo test -p dlp-agent dacl_tripwire` | dlp-agent/src/dacl_tripwire.rs |
| DACL-01 | Authenticated Users SID constructed via CreateWellKnownSid | unit | `cargo test -p dlp-agent dacl_tripwire::test_build_deny_authusers_dacl_sid` | dlp-agent/src/dacl_tripwire.rs |
| DACL-02 | Repair watcher detects ACL tamper and restores | integration | `cargo test -p dlp-agent dacl_repair_watcher` | dlp-agent/src/dacl_repair_watcher.rs |
| DACL-02 | 60s polling backstop catches missed events | integration | `cargo test -p dlp-agent dacl_repair_watcher` | dlp-agent/src/dacl_repair_watcher.rs |
| DACL-03 | Admin API CRUD for protected paths | unit | `cargo test -p dlp-server protected_paths` | dlp-server/src/db/repositories/protected_paths.rs |
| DACL-03 | Agent config sync includes protected paths | unit | `cargo test -p dlp-agent server_client` | dlp-agent/src/server_client.rs |
| DACL-04 | Staging row suppresses tamper alert on removal | integration | `cargo test -p dlp-agent dacl_staging` | dlp-agent/src/dacl_staging.rs |
| DACL-04 | GC removes expired staging rows after 5 min | integration | `cargo test -p dlp-agent dacl_staging` | dlp-agent/src/dacl_staging.rs |
| DACL-04 | Removal application task applies staged removals | integration | `cargo test -p dlp-agent dacl_repair_watcher` | dlp-agent/src/dacl_repair_watcher.rs |
| DACL-05 | DPAPI recovery runbook exists and is readable | doc | `test -f docs/operations/dpapi-recovery.md` | docs/operations/dpapi-recovery.md |

### Sampling Rate

- **Per task commit:** `cargo test -p dlp-agent dacl_tripwire` (quick filter)
- **Per wave merge:** `cargo test --workspace`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps (Closed)

- [x] `dlp-agent/src/dacl_tripwire.rs` — module creation + unit tests for `build_deny_authusers_dacl`
- [x] `dlp-agent/src/dacl_repair_watcher.rs` — module creation + mock watcher tests
- [x] `dlp-agent/src/dacl_staging.rs` — module creation + SQLite table tests
- [x] `dlp-server/src/db/repositories/protected_paths.rs` — repository + CRUD tests
- [x] `dlp-common/src/audit.rs` — add `DaclTamperDetected` and `DaclTripwireTooLarge` variants
- [x] `docs/operations/dpapi-recovery.md` — runbook creation

## Verification Checklist

- [ ] `cargo test --workspace -- --test-threads=1` passes
- [ ] `cargo clippy --workspace -- -D warnings` passes
- [ ] `cargo build --workspace` succeeds with zero warnings
- [ ] No `unwrap()` in new library code paths
- [ ] All public functions have doc comments
- [ ] `docs/operations/dpapi-recovery.md` exists with both recovery flows
- [ ] ROADMAP.md Phase 52 shows all plans complete
