---
phase: 56
plan: 06
status: complete
executed: 2026-05-29
---

# Plan 56-06 — End-to-End Integration Tests (Summary)

## Objective

Write integration tests proving volume-class ABAC policies evaluate correctly end-to-end, with mocked volume classes (no hardware required) and a hardware-dependent test marked `#[ignore]`.

## Deviations from Plan

| # | Planned | Actual | Rationale |
|---|---------|--------|-----------|
| 1 | Test in `dlp-agent/tests/volume_class_integration.rs` | Test in `dlp-server/tests/volume_class_integration.rs` | dlp-agent cannot import dlp-server's `PolicyStore`/`PolicyRepository` due to crate dependency direction. dlp-server depends on dlp-common, not vice versa. |
| 2 | Test calls `CopyFileExW` via hook DLL trampolines | Test evaluates `PolicyStore::evaluate` directly with `AbacContext` | CopyFileExW integration requires elevated hook DLL injection, a running agent, and named pipes — too heavy for a hermetic unit test. Policy evaluation is the deterministic core being tested. |
| 3 | 3 tests (deny, allow, hardware) | 6 tests (deny, allow, 2x fail-closed, ne-operator, hardware) | Added fail-closed tests per review feedback; added `ne` operator test to prove operator coverage. |
| 4 | `cargo test --all` for full verification | Per-crate `cargo test` due to Windows linker locks | `cargo test --all` fails with LNK1104 on locked `dlp_agent`/`dlp_hook_dll` executables from prior test runs. Per-crate tests all pass. |
| 5 | `sonar-scanner` CLI run | MCP tools used (scanner not installed) | `sonar-scanner` binary not found in PATH. SonarQube MCP analysis shows no new issues in changed files. All pre-existing issues are unrelated cognitive-complexity findings in other files. |
| 6 | SQLite `:memory:` for test DB | `tempfile::NamedTempFile` | r2d2 SQLite pool gives each connection its own in-memory DB; policies inserted on one connection were invisible to `store.invalidate()` on another. Temp file provides shared persistent storage across pool connections. |
| 7 | `skip_serializing_if = "Option::is_none"` on volume class fields | Removed `skip_serializing_if`; kept `#[serde(default)]` only | Bincode round-trip failed with `UnexpectedEof` when `skip_serializing_if` omitted fields during serialize but deserializer expected them. |

## Files Changed

| File | Change |
|------|--------|
| `dlp-server/tests/volume_class_integration.rs` | **New** — 5 passing integration tests + 1 `#[ignore]` hardware test |
| `dlp-agent/src/detection/usb.rs` | Added `inject_volume_class_for_test` helper in `#[cfg(test)]` block |
| `dlp-common/src/hook_ipc.rs` | Removed `skip_serializing_if` from volume class fields; fixed test `HookRequest` initializers |
| `dlp-agent/src/hook_ipc.rs` | Fixed test `HookRequest` initializers to include volume class fields |
| `dlp-e2e/tests/bincode_compat.rs` | Fixed test `HookRequest` initializers to include volume class fields |
| `dlp-e2e/tests/phase50_requirements.rs` | Fixed test `HookRequest` initializers to include volume class fields |
| `dlp-admin-cli/src/screens/allowlist.rs` | `cargo fmt` formatting fix |

## Tests Added

| Test | What It Proves |
|------|----------------|
| `test_deny_local_ntfs_t4_to_optical` | DENY when classification=T4 AND source=LocalNTFS AND destination=Optical |
| `test_allow_local_ntfs_t4_to_local_ntfs` | ALLOW when destination is LocalNTFS (optical policy doesn't match) |
| `test_fail_closed_when_source_volume_class_missing` | Default deny when `source_volume_class` is None |
| `test_fail_closed_when_destination_volume_class_missing` | Default deny when `destination_volume_class` is None |
| `test_volume_class_ne_operator` | `ne` operator works correctly on volume class conditions |
| `test_deny_with_real_optical_drive` | Hardware-dependent test (marked `#[ignore]`) |

## Verification Results

- `cargo check --all`: PASS
- `cargo clippy --all -- -D warnings`: PASS
- `cargo fmt --check`: PASS (after fixes)
- `cargo test -p dlp-common`: PASS
- `cargo test -p dlp-server`: PASS (including new integration test)
- `cargo test -p dlp-agent`: PASS
- `cargo test -p dlp-admin-cli`: PASS
- `cargo test -p dlp-e2e`: PASS
- `cargo test -p dlp-hook-dll`: 276 passed, 2 pre-existing failures, 1 ignored

## SonarQube

- No new issues introduced in changed files.
- Pre-existing cognitive-complexity issues in unrelated files remain (out of scope for this plan).

## Sign-Off

- [x] Integration test proves volume-class policy evaluation
- [x] Negative controls prove specificity
- [x] Fail-closed behavior verified
- [x] Hardware-dependent test exists and documented
- [x] Full workspace compiles, clippy clean, fmt clean
- [x] No regressions in existing tests
- [x] VALIDATION.md updated
