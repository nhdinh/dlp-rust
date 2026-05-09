---
estimated_steps: 22
estimated_files: 3
skills_used: []
---

# T01: Add Action::CLOUD_UPLOAD and cloud/WFP config fields

Add the `CLOUD_UPLOAD` variant to the `Action` enum in `dlp-common/src/abac.rs`, following the existing `DRAG_DROP` serde pattern (literal variant name). Add unit tests for serialization and deserialization. Add `cloud_hook_enabled`, `wfp_filter_enabled`, and `hook_classification_timeout_ms` fields to `AgentConfig` in `dlp-agent/src/config.rs` and to `AgentConfigPayload` in `dlp-agent/src/server_client.rs`, following the existing `Option<bool>` / `Option<u64>` patterns. Ensure all three crates compile.

## Steps
1. Open `dlp-common/src/abac.rs`, add `CLOUD_UPLOAD` to the `Action` enum.
2. Add serde test for `CLOUD_UPLOAD` round-trip (serialize → deserialize → assert_eq).
3. Open `dlp-agent/src/config.rs`, add the three new fields to `AgentConfig` with `#[serde(default)]`.
4. Open `dlp-agent/src/server_client.rs`, add the same three fields to `AgentConfigPayload` with `#[serde(default)]`.
5. Run `cargo check -p dlp-common -p dlp-agent`.

## Must-Haves
- [ ] `Action::CLOUD_UPLOAD` compiles and serializes to `"CLOUD_UPLOAD"`.
- [ ] `AgentConfig` and `AgentConfigPayload` contain the three new optional fields.
- [ ] `cargo check` passes for both crates.

## Verification
- `cargo check -p dlp-common -p dlp-agent`
- `cargo test -p dlp-common abac`

## Inputs
- `dlp-common/src/abac.rs`
- `dlp-agent/src/config.rs`
- `dlp-agent/src/server_client.rs`

## Expected Output
- `dlp-common/src/abac.rs` — new variant + tests
- `dlp-agent/src/config.rs` — new fields
- `dlp-agent/src/server_client.rs` — new payload fields

## Inputs

- `dlp-common/src/abac.rs`
- `dlp-agent/src/config.rs`
- `dlp-agent/src/server_client.rs`

## Expected Output

- `dlp-common/src/abac.rs`
- `dlp-agent/src/config.rs`
- `dlp-agent/src/server_client.rs`

## Verification

cargo check -p dlp-common -p dlp-agent && cargo test -p dlp-common abac
