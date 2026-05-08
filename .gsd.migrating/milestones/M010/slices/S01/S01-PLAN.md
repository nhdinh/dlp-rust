# S01: AGENT-UNKNOWN Remediation (Phase 38.3)

**Goal:** Close audit gaps with AGENT-UNKNOWN sentinel and remediation path.
**Demo:** All audit events include non-null app identity fields with AGENT-UNKNOWN sentinel and remediation path.

## Must-Haves

- 1. All audit events include app identity fields
- 2. AGENT-UNKNOWN sentinel for missing identity
- 3. Remediation path documented
- 4. Metric counter tracks frequency

## Proof Level

- This slice proves: tested

## Integration Closure

Schema change across all audit emission points.

## Verification

- AGENT-UNKNOWN metric counter per interception path.

## Tasks

- [x] **T01: AGENT-UNKNOWN remediation** `est:3h`
  Add AGENT-UNKNOWN sentinel to all audit emission paths. Guarantee non-null app identity fields in schema. Add remediation documentation. Implement metric counter per interception path. Server-side validation rejects events with missing identity fields.
  - Files: `dlp-common/src/audit.rs`, `dlp-agent/src/interception/mod.rs`, `dlp-server/src/audit_store.rs`
  - Verify: cargo test --workspace audit::

## Files Likely Touched

- dlp-common/src/audit.rs
- dlp-agent/src/interception/mod.rs
- dlp-server/src/audit_store.rs
