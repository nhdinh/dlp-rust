---
estimated_steps: 12
estimated_files: 1
skills_used: []
---

# T01: Fix four pre-existing clippy errors in dlp-admin-cli/src/screens/dispatch.rs

Four clippy errors in dispatch.rs prevent `cargo clippy -p dlp-admin-cli -- -D warnings` from passing, which blocks the S05 quality gate. Three are `doc_lazy_continuation` (orphan doc comment lines that continue a preceding doc block but are separated by a non-doc line, causing clippy to treat them as dangling continuation lines). One is `needless_borrow`. This task fixes all four with minimal, surgical edits — no logic changes.

Why this task exists: T02 and T03 add new code to the admin-cli crate; the clippy gate must be green before those tasks ship so the pre-commit check doesn't fail on new code.

## Steps

1. Run `cargo clippy -p dlp-admin-cli -- -D warnings 2>&1` to get the exact error messages with file:line:col. Capture the output.
2. For each `doc_lazy_continuation` error: the fix is to either (a) merge the orphan line into the preceding doc block by removing the blank line between them, or (b) convert the orphan line to a non-doc comment `//` if it logically belongs to the function below. Inspect context around each reported line before choosing.
3. For the `needless_borrow` error: remove the `&` before the value that is being passed where a borrow is already implied or where the type already implements `Deref`.
4. After each fix, run `cargo clippy -p dlp-admin-cli -- -D warnings` to confirm the count decreases. Fix all four before moving to verification.
5. Do NOT change any logic, function signatures, or test behaviour — purely lint fixes.

## Must-Haves

- [ ] `cargo clippy -p dlp-admin-cli -- -D warnings` exits 0
- [ ] `cargo test -p dlp-admin-cli` still passes (106/106)
- [ ] No logic changes — only lint fixes

## Inputs

- `dlp-admin-cli/src/screens/dispatch.rs`

## Expected Output

- `dlp-admin-cli/src/screens/dispatch.rs`

## Verification

cargo clippy -p dlp-admin-cli -- -D warnings && cargo test -p dlp-admin-cli
