# S01: Conditions Builder (Phase 13)

**Goal:** Provide structured conditions builder without raw JSON entry.
**Demo:** Admin builds typed conditions via 3-step picker (attribute → operator → value). No raw JSON.

## Must-Haves

- 1. 3-step sequential picker
- 2. 5 attributes with typed value pickers
- 3. Pending conditions list with delete
- 4. No raw JSON editing

## Proof Level

- This slice proves: tested

## Integration Closure

Gates all policy authoring in this milestone.

## Verification

- None — UI behavior.

## Tasks

- [x] **T01: Conditions builder implementation** `est:5h`
  Create ConditionAttribute enum, CallerScreen, PolicyFormState, and Screen::ConditionsBuilder. Implement dispatch handler with 3-step picker: step 1 (attribute), step 2 (operator), step 3 (typed value). Implement render function with modal overlay. Add pending-conditions list with delete binding. Add unit tests.
  - Files: `dlp-admin-cli/src/screens/render.rs`, `dlp-admin-cli/src/screens/dispatch.rs`, `dlp-admin-cli/src/app.rs`
  - Verify: cargo test --package dlp-admin-cli

## Files Likely Touched

- dlp-admin-cli/src/screens/render.rs
- dlp-admin-cli/src/screens/dispatch.rs
- dlp-admin-cli/src/app.rs
