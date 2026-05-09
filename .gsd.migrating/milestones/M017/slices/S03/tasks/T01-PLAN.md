---
estimated_steps: 12
estimated_files: 3
skills_used: []
---

# T01: Implement ShareLinkEnforcer detection module and add Action::SHARE_LINK

Add the Action::SHARE_LINK ABAC variant to dlp-common/src/abac.rs following the MEM026 pattern (variant + two serde round-trip tests). Create dlp-agent/src/share_link_enforcer.rs as a new pure-logic module with no Windows dependencies.

The module must export:
- `DetectedShareLink { provider: CloudProvider, url: String }` — one entry per matching share URL found in the pasted text
- `detect_share_links(text: &str) -> Vec<DetectedShareLink>` — scans lowercased text for per-provider share-path substrings; emits at most one entry per provider (first match wins); uses the patterns from the research doc (1drv.ms/, onedrive.live.com/, sharepoint.com/ with /s/ or ?share=; drive.google.com/file/d/, drive.google.com/drive/folders/, docs.google.com/ with /d/; dropbox.com/s/, dropbox.com/sh/, dropbox.com/scl/; box.com/s/, app.box.com/s/)
- `ShareLinkAlertResult { provider: String, url: String, decision: Decision }` — result of the enforcer check
- `ShareLinkEnforcer` (unit struct or zero-size) with `check(links: &[DetectedShareLink], classification: Classification) -> Option<Vec<ShareLinkAlertResult>>` returning Some(...) when classification >= T3 and links is non-empty; each DetectedShareLink becomes one ShareLinkAlertResult with Decision::Deny

Constraints:
- Import CloudProvider from crate::cloud_enforcer (same crate, dlp-agent)
- Import Classification and Decision from dlp-common
- No async, no Windows APIs — synchronous and cross-platform
- Add `pub mod share_link_enforcer;` to dlp-agent/src/lib.rs
- Unit tests inside share_link_enforcer.rs: at minimum test T1 no-alert, T3 alert, T4 alert, multi-provider paste, partial-domain no-false-positive (bare 'dropbox.com' without share path should not match)

## Inputs

- `dlp-common/src/abac.rs`
- `dlp-agent/src/lib.rs`
- `dlp-agent/src/cloud_enforcer.rs`

## Expected Output

- `dlp-agent/src/share_link_enforcer.rs`
- `dlp-common/src/abac.rs`
- `dlp-agent/src/lib.rs`

## Verification

cargo test -p dlp-common -- abac && cargo test -p dlp-agent share_link_enforcer -- --nocapture && cargo clippy -p dlp-common -p dlp-agent -- -D warnings
