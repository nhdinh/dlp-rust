# S05: Integration & UAT — UAT

**Milestone:** M017
**Written:** 2026-05-09T02:10:00.824Z

# S05: Integration & UAT — UAT

**Milestone:** M017
**Written:** 2026-05-09

## UAT Type

- UAT mode: artifact-driven
- Why this mode is sufficient: S05's proof level is "contract" — it verifies compile-time correctness, serde round-trips, and unit-level screen constant invariants. Live admin-CLI round-trip to a running server (navigating the TUI, sending PUT /admin/agent-config, observing toggle persistence) is explicitly out of automated scope per the slice plan. The comprehensive test suite (172 tests) covers all agent-side enforcement paths that previous slices established.

## Not Proven By This UAT

- Live TUI smoke test: actual keyboard navigation through CloudConfig and PrintConfig screens on a running terminal
- Live HTTP round-trip: PUT /admin/agent-config with cloud/print fields followed by GET to confirm persistence
- Live enforcement: copy T4 file to OneDrive sync folder → block toast; print T4 doc → job cancelled; copy OneDrive share link → alert emitted (requires real Windows host with sync clients installed)

## Preconditions

- Rust toolchain installed (stable)
- Working directory: `C:/Users/nhdinh/dev/dlp-rust`
- No running DLP server required for automated checks

## Smoke Test

Run `cargo test -p dlp-admin-cli` — if 116 tests pass including `cloud_config::tests::*` and `print_config::tests::*`, the new screens are wired correctly.

## Test Cases

### 1. dlp-admin-cli clippy gate passes

1. Run: `cargo clippy -p dlp-admin-cli -- -D warnings`
2. **Expected:** exits 0, zero warnings. Previously emitted 4 errors (3× doc_lazy_continuation, 1× needless_borrow in dispatch.rs) — these must be absent.

### 2. dlp-admin-cli test suite passes with new screen tests

1. Run: `cargo test -p dlp-admin-cli`
2. **Expected:** 116 tests pass, 0 failed. Confirmed new tests present:
   - `cloud_config::tests::test_cloud_config_keys_length`
   - `cloud_config::tests::test_cloud_config_labels_match`
   - `cloud_config::tests::test_cloud_config_row_constants`
   - `print_config::tests::test_print_config_keys_length`
   - `print_config::tests::test_print_config_labels_match`
   - `print_config::tests::test_print_config_row_constants`
   - `print_config::tests::test_is_print_bool`
   - `print_config::tests::test_is_print_numeric`
   - `print_config::tests::test_is_print_picker`
   - `print_config::tests::test_picker_options`

### 3. dlp-server clippy gate passes with new fields

1. Run: `cargo clippy -p dlp-server -- -D warnings`
2. **Expected:** exits 0, zero warnings. Verifies AgentConfigPayload struct extension and validation code are lint-clean.

### 4. dlp-server test suite passes with new serde fields

1. Run: `cargo test -p dlp-server`
2. **Expected:** all tests pass, 0 failed. Serde round-trip tests exercise new fields via `..Default::default()` expansion.

### 5. Workspace build succeeds

1. Run: `cargo build --workspace`
2. **Expected:** exits 0. All crates compile — confirms no broken imports, missing constants, or type mismatches introduced by new Screen variants or constants modules.

### 6. Comprehensive integration tests — no regressions

1. Run: `cargo test --test comprehensive`
2. **Expected:** 172 passed, 0 failed. Verifies that cloud/print wiring did not break USB, clipboard, share-link, or any other enforcement path established by S01–S04.

### 7. SystemMenu item count is 9

1. Inspect `dlp-admin-cli/src/screens/render.rs` — the SystemMenu items vector
2. **Expected:** 9 items: LDAP Config, Agent Config, Audit Config, Classifier Config, ShareLink Config, USB Enforcement, Cloud Config, Print Config, Back. "Cloud Config" at index 6, "Print Config" at index 7, "Back" at index 8.

### 8. AgentConfigPayload has five new fields with serde defaults

1. Inspect `dlp-server/src/admin_api.rs` — `AgentConfigPayload` struct
2. **Expected:** fields `cloud_hook_enabled`, `print_enabled`, `print_xps_timeout_ms`, `print_unclassifiable_action`, `print_max_pages` are present with `#[serde(default)]` / `#[serde(default = "fn_name")]` attributes and matching `default_*` functions. A manual `Default` impl is present.

### 9. DB migrations include all ten new columns

1. Inspect `dlp-server/src/db/mod.rs`
2. **Expected:** 10 `run_alter` calls — 5 for `global_agent_config` (cloud_hook_enabled, print_enabled, print_xps_timeout_ms, print_unclassifiable_action, print_max_pages) and 5 for `agent_config_overrides` — all idempotent with defaults matching AgentConfigPayload defaults.

## Edge Cases

### print_unclassifiable_action validation rejects unknown values

1. Send `PUT /admin/agent-config` with `{"print_unclassifiable_action": "Log"}` (not in ["Block","Allow"])
2. **Expected:** HTTP 400 Bad Request returned. Only "Block" and "Allow" are accepted.

### cloud_hook_enabled toggles as bool (no picker)

1. Navigate to Cloud Config screen in the admin CLI
2. Press Enter on the `cloud_hook_enabled` row
3. **Expected:** value toggles between Enabled/Disabled in-place. No picker cycling occurs — it is a direct bool toggle following the USB enforcement pattern, not a multi-option picker.

### Back from CloudConfig returns cursor to SystemMenu index 6

1. Enter CloudConfig screen from SystemMenu
2. Press Esc or navigate to Back row and press Enter
3. **Expected:** returns to `Screen::SystemMenu { selected: 6 }`, placing the cursor on "Cloud Config" in the menu — consistent with all other config screens preserving cursor position on back navigation.
