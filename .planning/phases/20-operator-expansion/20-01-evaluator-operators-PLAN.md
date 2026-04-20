---
phase: 20
plan: 01
name: "Evaluator: extend compare_op and memberof_matches with new operators"
wave: 1
depends_on: []
files_modified:
  - dlp-server/src/policy_store.rs
requirements_addressed:
  - POLICY-11
type: execute
autonomous: true
must_haves:
  truths:
    - "compare_op_classification handles 'gt'/'lt' using ordinal T1=1..T4=4 (T3 gt T2 is true; T1 gt T4 is false)"
    - "memberof_matches 'contains' arm returns true when any subject SID contains the target as a substring (case-sensitive)"
    - "All existing 'eq'/'neq'/'in'/'not_in' evaluation paths are unchanged — no regression in existing tests"
    - "classification_ord helper exists as a private fn in policy_store.rs (not on the Classification enum)"
  artifacts:
    - dlp-server/src/policy_store.rs
  key_links:
    - "compare_op_classification is called from condition_matches for PolicyCondition::Classification arms"
    - "memberof_matches is called from condition_matches for PolicyCondition::MemberOf arms"
---

## Overview

Wave 1 extends the ABAC evaluator in `policy_store.rs` to honor the new operators
from Phase 20's operator map. Two functions gain new match arms:

- `compare_op` — gains `"gt"` and `"lt"` for Classification via ordinal comparison
- `memberof_matches` — gains `"contains"` for case-sensitive SID substring match

Existing `"eq"` and `"neq"` paths are untouched; all existing tests continue to pass.

---

## Step 1 — Read source-of-truth files first

<read_first>

- `dlp-server/src/policy_store.rs` lines 237–265 — `compare_op` and `memberof_matches` (the two functions being modified)
- `dlp-server/src/policy_store.rs` lines 267–420 — existing test suite (patterns to follow)
- `dlp-common/src/classification.rs` — `Classification` enum; note it already derives `PartialOrd` (D-03 decision: do NOT use it; a plain helper is used instead)

</read_first>

---

## Step 2 — Add `classification_ord` helper

Add this private helper **just before** the `#[cfg(test)]` module at the bottom of `policy_store.rs`, before the test module:

```rust
/// Maps a Classification tier to its ordinal position (1–4).
///
/// T1 = 1 (lowest sensitivity), T4 = 4 (highest sensitivity).
/// Used only for `gt`/`lt` comparisons in `compare_op`.
/// Lives here rather than on `Classification` itself to avoid coupling risk
/// from the shared dlp-common enum deriving `PartialOrd` (per D-03).
fn classification_ord(c: &Classification) -> u8 {
    match c {
        Classification::T1 => 1,
        Classification::T2 => 2,
        Classification::T3 => 3,
        Classification::T4 => 4,
    }
}
```

<acceptance_criteria>

- `grep -n "fn classification_ord" dlp-server/src/policy_store.rs` returns exactly one match
- The function body contains `Classification::T1 => 1` through `Classification::T4 => 4`

</acceptance_criteria>

---

## Step 3 — Extend `compare_op` with `gt`/`lt` arms

Replace the current `compare_op` function body (lines 237–249) with:

```rust
/// Compares two values using the given operator string.
///
/// Supports `"eq"` and `"neq"` for all `T: PartialEq` types.
/// Supports `"gt"` and `"lt"` for `Classification` via ordinal comparison.
/// Operators `"in"` and `"not_in"` return `false` (not applicable to scalar types).
fn compare_op<T: PartialEq>(op: &str, actual: &T, expected: &T) -> bool {
    match op {
        "eq" => actual == expected,
        "neq" => actual != expected,
        // Defensive: "in"/"not_in" on non-MemberOf conditions never match.
        "in" | "not_in" => false,
        _ => false,
    }
}

/// Specialised Classification comparison for ordinal operators `gt`/`lt`.
///
/// Separate from the generic `compare_op` because ordinal semantics (T1 < T2 < T3 < T4)
/// differ from the inherited `PartialOrd` derive on `Classification` (lexicographic).
fn compare_op_classification(op: &str, actual: &Classification, expected: &Classification) -> bool {
    match op {
        "eq" => actual == expected,
        "neq" => actual != expected,
        "gt" => classification_ord(actual) > classification_ord(expected),
        "lt" => classification_ord(actual) < classification_ord(expected),
        _ => false,
    }
}
```

Then update the call sites in `condition_matches` (search for `compare_op` in the `PolicyCondition::Classification` arm) to use `compare_op_classification` instead of `compare_op`.

<acceptance_criteria>

- `grep -n "compare_op_classification" dlp-server/src/policy_store.rs` returns ≥ 2 matches (definition + call site)
- `grep -n '"gt"' dlp-server/src/policy_store.rs` shows the new arm in `compare_op_classification`
- `grep -n '"lt"' dlp-server/src/policy_store.rs` shows the new arm in `compare_op_classification`

</acceptance_criteria>

---

## Step 4 — Extend `memberof_matches` with `contains` arm

Replace the `match op` body in `memberof_matches` (lines 257–263) by adding a `"contains"` arm:

```rust
fn memberof_matches(op: &str, target_sid: &str, subject_groups: &[String]) -> bool {
    match op {
        "in" => subject_groups.iter().any(|sid| sid == target_sid),
        "not_in" => subject_groups.iter().all(|sid| sid != target_sid),
        // Fall back to scalar semantics for eq/neq (treat as single-element list).
        "eq" => subject_groups.iter().any(|sid| sid == target_sid),
        "neq" => subject_groups.iter().all(|sid| sid != target_sid),
        // Case-sensitive substring match on the full SID string (per D-05).
        "contains" => subject_groups.iter().any(|sid| sid.contains(target_sid)),
        _ => false,
    }
}
```

<acceptance_criteria>

- `grep -n '"contains"' dlp-server/src/policy_store.rs` returns a match inside the `memberof_matches` function
- `grep -n "sid.contains(target_sid)" dlp-server/src/policy_store.rs` returns exactly one match

</acceptance_criteria>

---

## Step 5 — Add unit tests inside the `#[cfg(test)]` module

Add the following tests **inside** the existing `mod tests {` block at the bottom of `policy_store.rs`. Place them after the existing `compare_op` tests (after `test_compare_op_in_not_applicable_to_scalars`).

```rust
// --- Phase 20: new operator tests ---

#[test]
fn test_compare_op_classification_gt() {
    // T3 > T2 is true (ordinal: 3 > 2)
    assert!(compare_op_classification("gt", &Classification::T3, &Classification::T2));
    // T4 > T1 is true (ordinal: 4 > 1)
    assert!(compare_op_classification("gt", &Classification::T4, &Classification::T1));
    // T1 > T4 is false (ordinal: 1 > 4 is false — highest boundary, per D-01)
    assert!(!compare_op_classification("gt", &Classification::T1, &Classification::T4));
    // T3 > T3 is false (same tier)
    assert!(!compare_op_classification("gt", &Classification::T3, &Classification::T3));
}

#[test]
fn test_compare_op_classification_lt() {
    // T1 < T2 is true (ordinal: 1 < 2)
    assert!(compare_op_classification("lt", &Classification::T1, &Classification::T2));
    // T2 < T4 is true (ordinal: 2 < 4)
    assert!(compare_op_classification("lt", &Classification::T2, &Classification::T4));
    // T4 < T1 is false (ordinal: 4 < 1 is false — highest boundary, per D-01)
    assert!(!compare_op_classification("lt", &Classification::T4, &Classification::T1));
    // T2 < T2 is false (same tier)
    assert!(!compare_op_classification("lt", &Classification::T2, &Classification::T2));
}

#[test]
fn test_compare_op_classification_boundary() {
    // Per D-01: T1 is lowest, T4 is highest. These are the boundary assertions.
    assert!(!compare_op_classification("gt", &Classification::T1, &Classification::T4));
    assert!(compare_op_classification("gt", &Classification::T4, &Classification::T1));
    assert!(!compare_op_classification("lt", &Classification::T4, &Classification::T1));
    assert!(compare_op_classification("lt", &Classification::T1, &Classification::T4));
}

#[test]
fn test_memberof_matches_contains() {
    // Substring anywhere in the SID matches (case-sensitive, per D-05).
    assert!(memberof_matches(
        "contains",
        "S-1-5-21-123",
        &["S-1-5-21-123-512".to_string(), "S-1-5-21-123-513".to_string()]
    ));
    // Partial prefix also matches.
    assert!(memberof_matches(
        "contains",
        "512",
        &["S-1-5-21-123-512".to_string()]
    ));
}

#[test]
fn test_memberof_matches_contains_no_match() {
    // Substring absent from all SIDs returns false.
    assert!(!memberof_matches(
        "contains",
        "S-1-5-21-999",
        &["S-1-5-21-123-512".to_string(), "S-1-5-21-123-513".to_string()]
    ));
    // Case-sensitive: uppercase-B in "S-1-5-21" does NOT match lowercase.
    assert!(!memberof_matches(
        "contains",
        "s-1-5-21-123",
        &["S-1-5-21-123-512".to_string()]
    ));
}

#[test]
fn test_memberof_matches_neq() {
    // "neq" for MemberOf: matches if NO group equals target.
    assert!(memberof_matches(
        "neq",
        "S-1-5-21-123-512",
        &["S-1-5-21-123-513".to_string()]
    ));
    assert!(!memberof_matches(
        "neq",
        "S-1-5-21-123-512",
        &["S-1-5-21-123-512".to_string()]
    ));
}
```

<acceptance_criteria>

- `grep -n "test_compare_op_classification_gt" dlp-server/src/policy_store.rs` returns exactly one match
- `grep -n "test_memberof_matches_contains_no_match" dlp-server/src/policy_store.rs` returns exactly one match
- `grep -n "test_memberof_matches_neq" dlp-server/src/policy_store.rs` returns exactly one match
- `cargo test -p dlp-server` passes with no warnings and no test failures

</acceptance_criteria>

---

## Step 6 — Verify build and tests

```sh
cargo fmt --check -p dlp-server
cargo build -p dlp-server --all-features
cargo test -p dlp-server
cargo clippy -p dlp-server -- -D warnings
```

<acceptance_criteria>

- `cargo fmt --check -p dlp-server` exits 0 (no formatting violations)
- All four commands complete with exit code 0 (no warnings, no failures)
- `grep -n "classification_ord" dlp-server/src/policy_store.rs` finds the helper
- `grep -n '"contains"' dlp-server/src/policy_store.rs` finds the new arm in `memberof_matches`
- `grep -n '"gt"' dlp-server/src/policy_store.rs` finds the new arms in `compare_op_classification`

</acceptance_criteria>
