# S02: Policy Create (Phase 14)

**Goal:** Create new policies with attached condition lists.
**Demo:** Multi-field form creates new policy with conditions. Form validates inline and submits to admin API.

## Must-Haves

- 1. Form captures name, description, priority, action, conditions
- 2. Submit posts to POST /admin/policies
- 3. Cache invalidated on success
- 4. Server errors surfaced inline

## Proof Level

- This slice proves: tested

## Integration Closure

Consumes S01 conditions builder. Invalidates PolicyStore cache on submit.

## Verification

- None — UI behavior.

## Tasks

- [x] **T01: Policy create implementation** `est:4h`
  Add Screen::PolicyCreate, ACTION_OPTIONS, and form_snapshot. Implement handle_policy_create and action_submit_policy. Fix CallerScreen Esc bug. Implement draw_policy_create render function. Add unit tests for form validation and submit.
  - Files: `dlp-admin-cli/src/screens/render.rs`, `dlp-admin-cli/src/screens/dispatch.rs`, `dlp-admin-cli/src/app.rs`
  - Verify: cargo test --package dlp-admin-cli

## Files Likely Touched

- dlp-admin-cli/src/screens/render.rs
- dlp-admin-cli/src/screens/dispatch.rs
- dlp-admin-cli/src/app.rs
