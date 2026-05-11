# Phase 47 Plan Check

**Verdict:** PASS-WITH-NOTES
**Confidence:** HIGH

## Summary

The plan is the strongest v1.0.0 phase artifact reviewed so far. All six locked CONTEXT decisions (D-Q1..D-Q6) have explicit, traceable task coverage; the success-criteria trace table at PLAN.md:775-790 is honest; and the threat model and risk table (lines 743-819) address every concern raised in the check brief.

The eleven-task structure is justified — the plan calls it out at line 232: HARD-01 is one indivisible deliverable.

What keeps the verdict from a clean PASS is a small set of internal inconsistencies and one task that is genuinely too large for an atomic commit (47-06). None prevents the phase from achieving its goal; they need polish, not rework.

## Goal Coverage Matrix

| Success Criterion | Tasks | Verdict |
|-------------------|-------|---------|
| 1 New rows encrypt and decrypt transparently | 47-01, 47-04, 47-05, 47-11 | PASS |
| 2 Migration upgrades cleartext rows; JWT env-var to DB | 47-03, 47-05, 47-06, 47-11 | PASS |
| 3 (amended) Transient legacy column; no persisted cleartext | 47-06, 47-11 | PASS |
| 4 Rotation documented and exercised | 47-08, 47-10 | PASS |
| 5 No cleartext in logs | 47-09, 47-11 | PASS |

All five criteria trace to at least one task whose acceptance criteria would prove the criterion when ticked. Cross-references checked against PLAN.md lines 775-790.

## Findings

### Blockers (must fix before execute)

None. The plan delivers all five amended success criteria and honors all six locked decisions.

### Notes (optional improvements)

**N1 — Task 47-06 is over-large and should be split.**

- Location: PLAN.md:472-527.
- Concern: 47-06 touches secrets_migration.rs (new approx 300 LOC), lib.rs, main.rs, AND db/mod.rs; implements the migration loop, the bootstrap wiring, the first-run KEK generation, AND the PRAGMA secure_delete add (per risk table line 818). That is at minimum three logical commits.
- Fix hint: Split into 47-06a (bootstrap + KEK + PRAGMA secure_delete) and 47-06b (migration loop + DROP COLUMN). 47-06b depends on 47-06a. Wave structure tolerates the split.

**N2 — Task 47-04 silently broadens its file scope beyond the files block.**

- Location: PLAN.md:387-423.
- Concern: The files block lists only siem_config.rs and alert_router_config.rs, but the action block at line 399 says: "Thread Arc<SecretCrypto> through AppState." Signature change cascades into AppState construction (main.rs, lib.rs) and every existing caller of get/update across admin_api.rs. None of those files are in 47-04 files.
- Fix hint: Either list cascading files in 47-04 files/frontmatter, or defer the Arc<SecretCrypto> threading to 47-06 and make 47-04 repository functions take &SecretCrypto as a free parameter. The latter is cleaner.

**N3 — STACK.md says rusqlite 0.39, RESEARCH.md says 0.32; plan only mentions 0.39 in passing.**

- Location: RESEARCH.md:215 references rusqlite 0.32; STACK.md:27 says rusqlite 0.39. Plan mentions 0.39 at line 488 in a comment.
- Concern: SQLite DROP COLUMN requires SQLite 3.35+. The plan asserts the bundled SQLite is past this but relies on a comment as verification. A future rusqlite downgrade silently breaks the migration.
- Fix hint: In Task 47-06, add a startup-time guard: SELECT sqlite_version() and return a typed error if less than 3.35.0.

**N4 — Task 47-08 introduces a new endpoint without listing the route-composition wiring file.**

- Location: PLAN.md:579-580.
- Concern: Plan says add POST /admin/secrets/rotate to the admin route composition. admin_api.rs is in files but if the workspace has a separate routes.rs or lib.rs composition step it is not listed.
- Fix hint: Add an integration assertion to 47-08 or 47-11 that hits /admin/secrets/rotate and asserts 401 unauthenticated, 200 authenticated. If the route is not wired the test fails fast.

**N5 — force_while_running policy in 47-08 depends on an unverified last_heartbeat field.**

- Location: PLAN.md:586. "If force == false and the agent registry has any agent with last_heartbeat within 60s, return Err."
- Concern: This depends on the agent registry exposing a recent-heartbeat query. The plan does not verify that field/query exists. If absent, the task silently expands to add it.
- Fix hint: Either verify before execution that dlp-server registry exposes active_within(Duration), or replace with a maintenance_mode=ON row in a small KV table. The KV-table approach is cleaner and matches CONTEXT D-Q5 "explicit lock" intent.

**N6 — secrets_jwt CHECK constraint is referenced in behavior but the action delegates to behavior for DDL.**

- Location: PLAN.md:347 (behavior: "holds at most one active row (CHECK id=1)") vs PLAN.md:357 (action: "add the new secrets_jwt table with schema per the behavior block").
- Concern: The action delegates schema details to the behavior block, which does not contain full DDL. Room for the CHECK to be silently dropped or for the table to gain INTEGER PRIMARY KEY instead of INTEGER PRIMARY KEY CHECK (id = 1).
- Fix hint: Inline the exact DDL in the action block. The CHECK is load-bearing for the at-most-one-active-row invariant.

**N7 — 47-09 changes repository return signatures, which cascades through callers not listed in files.**

- Location: PLAN.md:610-617 lists 7 files but the action at line 632-637 says "Update alert_router.rs, siem_connector.rs, admin_auth.rs to consume the new shapes."
- Concern: Changing SiemConfig.splunk_token from Option<String> to Option<SecretString> is a public-shape change. Any file that constructs or destructures SiemConfig (likely admin_api.rs too) must change.
- Fix hint: 47-09 verify already runs cargo clippy -p dlp-server -D warnings, which IS the right gate. Add a note in the action: "If cargo check reveals additional consumers, add them in-flight and record in the SUMMARY."

**N8 — Task 47-10 references a non-windows test stub but does not specify where it lives.**

- Location: PLAN.md:680-682. "factor the test so non-Windows builds use a stub MachineSecret that returns a fixed 32-byte seed (preferred)."
- Concern: This stub is a test-only escape hatch that bypasses DPAPI. It needs a definite home and must be unreachable from production builds.
- Fix hint: Add to 47-01 action: "Provide a cfg(all(test, not(windows))) stub MachineSecret::test_stub() returning a deterministic 32-byte seed. The stub MUST NOT be reachable from non-test builds."

### Praise

P1 — Success criteria trace table is honest and complete. PLAN.md:775-790 (success-criteria trace) and 783-789 (CONTEXT decision-to-task map) are exactly what plan-checkers want and rarely get. They make verification an order of magnitude cheaper.

P2 — STRIDE threat model with explicit accept/mitigate dispositions. Lines 756-770 are unusually thorough. The accept rows (T-47-06 DPAPI loss to Phase 52, T-47-07 SYSTEM-memory out of scope, T-47-12 KDF latency tolerable) explicitly invoke CONTEXT decisions and codify scope boundaries.

P3 — MSRV compliance is explicit per crate. Line 814 names every crate, its MSRV, and explicitly forbids the 0.11 / 0.13 / 0.6-rc series. This is the right defense against the most common silent-MSRV-bump failure mode.

P4 — Mask round-trip preservation is a dedicated task with its own regression test. Task 47-07 is the firewall between secrets are encrypted and secrets stay readable through the admin API. Many plans would fold this into 47-04; making it explicit means a future executor cannot ship 47-04 without proving the invariant.

P5 — Column-binding AAD is correctly identified as substitution-attack defense. The AAD format dlp:secret: + table + : + col (PLAN.md:137 plus threat-table line 759) prevents an attacker who can rewrite the SQLite file from moving a ciphertext blob between columns. Most plans would just say "use AEAD" and miss this.

P6 — Forensic decrypt test in 47-10 proves the rotation operational guarantee. Step 8 of the rotation test at line 679 (SecretCrypto::load_by_version(conn, 1) decrypts a saved v1 envelope) directly tests the retention guarantee from 47-08. Without this, the retention claim is unfalsifiable.

## Overall Recommendation

PROCEED TO EXECUTE with the eight Notes folded in. Specifically:

1. Address N6 (inline the secrets_jwt DDL) and N5 (replace last_heartbeat check with a maintenance-mode KV table or verify the field exists) before starting execution — both are 5-minute fixes that eliminate execution-time scope creep.
2. Split N1 (Task 47-06) during execution if the executor cannot commit atomically; the wave structure tolerates the split.
3. Treat N2 and N7 (signature-cascade scope) as documentation cleanups during execution — the cargo check gates will catch real breakage.
4. N3 (SQLite version guard), N4 (route reachability test), N8 (test stub placement) are quality polishing — fold in but they do not block.

The plan satisfies every line of the 10 check dimensions: goal coverage (5/5), locked-decision adherence (6/6, no scope reduction), task atomicity (10/11 atomic — 47-06 flagged), dependency correctness (wave graph acyclic and accurate), acceptance-criteria quality (concrete and testable), risk surface (all six brief-mentioned risks addressed in the risk table), test coverage (criteria 4 and 5 have named integration tests; crypto units cover round-trip + AAD + version byte), no scope creep (JWT and LDAP are in-scope per D-Q1; nothing else added), MSRV compliance (line 814 explicit), operational guidance (lines 743-769 plus 811 cover deploy/fail/revert).

This is execute-ready.
