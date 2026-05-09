# S01: Boolean Mode Engine + Wire Format (Phase 18)

**Goal:** Server-side delivery of flat boolean composition with backward-compatible default.
**Demo:** ABAC evaluator supports ALL/ANY/NONE boolean modes per policy. Legacy policies default to ALL.

## Must-Haves

- 1. policies.mode column with NOT NULL DEFAULT 'ALL'
- 2. PolicyPayload/PolicyResponse carry mode field
- 3. Evaluator honors ALL/ANY/NONE
- 4. Legacy policies evaluate identically

## Proof Level

- This slice proves: tested

## Integration Closure

Wire format change enables TUI mode picker in S02.

## Verification

- None — engine behavior.

## Tasks

- [x] **T01: Boolean mode engine and wire format** `est:4h`
  Add policies.mode column with NOT NULL DEFAULT 'ALL' via ALTER TABLE migration. Add mode field to PolicyPayload and PolicyResponse. Implement evaluator switch on mode: ALL (every condition matches), ANY (at least one), NONE (no condition matches). Add unit tests for three modes and legacy default path.
  - Files: `dlp-server/src/db.rs`, `dlp-common/src/abac.rs`, `dlp-server/src/policy_store.rs`
  - Verify: cargo test --package dlp-server policy_store:: && cargo test --package dlp-common abac::

## Files Likely Touched

- dlp-server/src/db.rs
- dlp-common/src/abac.rs
- dlp-server/src/policy_store.rs
