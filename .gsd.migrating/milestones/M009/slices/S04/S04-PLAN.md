# S04: Audit Enrichment — App Identity Fields (Phase 42)

**Goal:** Close gaps in app identity fields across all interception paths.
**Demo:** All interception paths emit audit events with populated app identity and origin fields. AGENT-UNKNOWN sentinel for unresolvable identity.

## Must-Haves

- 1. File interception includes app identity
- 2. USB interception includes device identity
- 3. Clipboard includes source+dest app identity
- 4. AGENT-UNKNOWN schema guarantee

## Proof Level

- This slice proves: tested

## Integration Closure

Validates S01-S03 integration. Schema guarantee for non-null app identity.

## Verification

- AGENT-UNKNOWN frequency tracked per path.

## Tasks

- [x] **T01: Audit enrichment — app identity fields** `est:4h`
  Audit all interception paths (file, USB, clipboard, drag-and-drop, Chrome) to ensure app identity and origin fields are populated. Add AGENT-UNKNOWN sentinel for unresolvable identity. Server-side validation as hard gate. Update schema documentation.
  - Files: `dlp-agent/src/interception/mod.rs`, `dlp-agent/src/usb_enforcer.rs`, `dlp-agent/src/chrome/handler.rs`, `dlp-server/src/audit_store.rs`
  - Verify: cargo test --workspace audit::

## Files Likely Touched

- dlp-agent/src/interception/mod.rs
- dlp-agent/src/usb_enforcer.rs
- dlp-agent/src/chrome/handler.rs
- dlp-server/src/audit_store.rs
