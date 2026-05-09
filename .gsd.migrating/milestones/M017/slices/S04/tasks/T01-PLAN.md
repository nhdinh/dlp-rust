---
estimated_steps: 15
estimated_files: 5
skills_used: []
---

# T01: Add ABAC PRINT action, config fields, and dependencies

Add the foundational types and dependencies needed by all subsequent print tasks.

**Steps:**
1. Add `PRINT` variant to `Action` enum in `dlp-common/src/abac.rs` with doc comment "Print operation (Phase 46, M017/S04)."
2. Add `print_enabled: Option<bool>`, `print_xps_timeout_ms: Option<u64>`, `print_unclassifiable_action: Option<String>`, `print_max_pages: Option<usize>` to `AgentConfig` in `dlp-agent/src/config.rs`.
3. Add corresponding fields to `AgentConfigPayload` in `dlp-agent/src/server_client.rs`.
4. Add diff/apply logic in `apply_payload_to_config` in `dlp-agent/src/service.rs`, following the USB field pattern (None guard + empty-string guard).
5. Add `"Win32_Graphics_Printing"` to the `windows` crate features array in `dlp-agent/Cargo.toml`.
6. Add `zip = "2"` and `quick-xml = "0.36"` to `[dependencies]` in `dlp-agent/Cargo.toml`.

**Skills used:** rust-engineer

**Failure Modes:**
- If `windows` crate fails to compile with new feature, verify feature name spelling (`Win32_Graphics_Printing`) and that `windows` v0.62 supports it.
- If `zip`/`quick-xml` versions are incompatible, adjust to latest stable.

**Negative Tests:**
- Verify `cargo check` passes after adding deps — ensures no version conflicts.
- Verify `apply_payload_to_config` does NOT diff when payload fields equal defaults (None guard).

## Inputs

- `dlp-common/src/abac.rs`
- `dlp-agent/src/config.rs`
- `dlp-agent/src/server_client.rs`
- `dlp-agent/src/service.rs`
- `dlp-agent/Cargo.toml`

## Expected Output

- ``dlp-common/src/abac.rs` — `PRINT` variant added`
- ``dlp-agent/src/config.rs` — print config fields added`
- ``dlp-agent/src/server_client.rs` — payload fields added`
- ``dlp-agent/src/service.rs` — hot-reload plumbing added`
- ``dlp-agent/Cargo.toml` — windows feature and crates added`

## Verification

cargo check -p dlp-agent passes with zero new warnings

## Observability Impact

Config fields are now observable via `with_config` access; no runtime signals added yet.
