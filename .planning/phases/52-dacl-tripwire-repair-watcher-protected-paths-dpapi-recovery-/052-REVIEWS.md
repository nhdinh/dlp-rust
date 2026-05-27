---
phase: 52
reviewers: [codex, opencode]
reviewed_at: 2026-05-27T10:15:00Z
plans_reviewed:
  - 52-01-PLAN.md
  - 52-02-PLAN.md
  - 52-03-PLAN.md
  - 52-04-PLAN.md
  - 52-05-PLAN.md
  - 52-06-PLAN.md
  - 52-07-PLAN.md
---

# Cross-AI Plan Review — Phase 52

## Codex Review

### Summary
The phase is generally well decomposed: Wave 1 establishes the writer and server-side model, Wave 2 adds API/sync/watcher/staging, and Wave 3 integrates suppression, removal, documentation, and verification. The design directly addresses the core invariant: T3/T4 roots must remain protected by kernel-enforced NTFS Deny ACEs even if the agent/hook layer is absent. The main risks are around Windows ACL correctness, canonical ordering, watcher reliability under real filesystem behavior, and the two-phase "operator removal vs tamper" distinction. The plans are directionally strong, but they need sharper contracts between writer, watcher, staging, and config sync to avoid false tamper alerts, missed repairs, or broken administrative removals.

### Strengths
- Clear separation between DACL construction/application, watcher repair, server schema/API, staging, and final integration.
- Uses NTFS DACL enforcement as the real control point, satisfying the "agent stopped and hook DLL absent" success criterion.
- Canonical SDDL snapshots plus replace-not-append repair is the right model; append-only ACL repair would drift over time.
- Explicit 60 KB ACL guard is called out early and should reduce risk of invalid or oversized security descriptors.
- Watcher has both event-driven monitoring and a polling backstop, which is important because security change notifications can be lossy.
- Two-phase staged removals are planned separately from tamper detection, which is necessary to suppress expected operator-initiated changes.
- Recursive limit, no symlink following, and junction skipping are good initial controls against expensive or dangerous tree walks.
- DPAPI recovery doc is correctly treated as a deliverable with UAT, not just an operational note.

### Concerns
- **HIGH: DACL canonicalization details are under-specified.** D-11 says Explicit Deny DLP first, Explicit Allow, Inherited, but the writer plan only says raw ACL construction and SDDL snapshot. It must define exactly how existing explicit ACEs are preserved and reordered. A malformed order can produce unexpected Windows access behavior or repeated self-repair loops.
- **HIGH: "Authenticated Users denied, SYSTEM and DLP-Admin unaffected" may not hold with a broad Authenticated Users deny.** Explicit deny ACEs generally override allows. If SYSTEM or DLP-Admin principals are also members of Authenticated Users, the plan must prove the deny does not block them, or use a more precise ACE strategy.
- **HIGH: Staged removal race conditions are not fully resolved.** Plans 52-04 and 52-07 imply staging occurs before config application, then watcher suppresses alerts. But the exact sequence matters: stage removal, unregister watcher, remove DACL, mark applied, persist config, restart/resync behavior. Crash or restart between those steps could leave a path unprotected or trigger a delayed false tamper event.
- **HIGH: Repair watcher may miss subtree tampering if only roots are watched.** `ReadDirectoryChangesW(FILE_NOTIFY_CHANGE_SECURITY)` on a directory needs clear recursive behavior. If it does not cover all descendants, then subtree ACL edits may only be caught by the 60-second polling backstop, which must walk enough of the protected tree to compare every relevant DACL.
- **MEDIUM: 10,000-file recursive limit needs failure semantics.** The plan mentions the limit but not whether partial application rolls back, emits audit, fails the protected-path registration, or marks the path degraded. Partial protection would be dangerous unless surfaced clearly.
- **MEDIUM: 60 KB ACL guard placement is ambiguous.** It appears in the writer and API requirements, but every ACL write path must enforce it: initial apply, recursive repair, server update, sync-derived config, and restore from SDDL snapshot.
- **MEDIUM: Path validation via regex is risky.** Windows path semantics are difficult: drive paths, UNC paths, extended-length `\\?\` paths, normalization, case folding, trailing separators, device names, junctions, and reparse points. A regex alone is unlikely to be sufficient.
- **MEDIUM: Protected path identity and rename/move behavior are unclear.** If a protected directory is renamed, deleted, moved, replaced by a junction, or recreated, the watcher and repository need deterministic behavior and audit output.
- **MEDIUM: Server-side `sync_from_labels` needs conflict rules.** Auto-populated T3/T4 paths plus manual entries and overrides can create duplicates, tier changes, path collisions, and stale label-derived rows.
- **MEDIUM: Watcher lifecycle with dedicated OS threads can become expensive.** Per-path threads are simple, but large protected-path sets could create many long-lived threads. The plan should define expected limits or a guardrail.
- **MEDIUM: Audit event routing is deferred too late.** 52-05 verifies `DaclTamperDetected` and `DaclTripwireTooLarge`, but event schema and SIEM compatibility should be included in earlier plans where events are introduced.
- **LOW: DPAPI doc is appropriately scoped but depends on real command names/env vars.** The plan should require verification against actual Phase 47 config names and service behavior, not placeholder snippets.

### Suggestions
- Add an explicit access-control proof or test matrix for Authenticated Users, normal domain users, SYSTEM, Administrators, and DLP-Admin.
- Define the canonical DACL algorithm precisely: read existing DACL, remove prior DLP tripwire ACE, insert one explicit deny ACE in canonical position, preserve non-DLP explicit allows/denies, preserve inherited ACEs, serialize to SDDL, then write.
- Make the SDDL snapshot include enough identity metadata to recognize "our" ACE reliably.
- Specify staging state transitions: `staged -> watcher suppressed/unregistered -> DACL removed -> applied -> config committed -> GC`. Also define crash recovery for each intermediate state.
- Add tests for stale staged rows: expired staged removal should produce tamper detection again, not permanent suppression.
- Require all repair paths to use replace-not-append and enforce the 60 KB guard before writing.
- Replace "absolute NTFS path regex" with canonicalization using Windows path APIs, plus explicit rejection of unsupported forms such as reparse points where appropriate.
- Define behavior for partial recursive apply. Prefer fail-closed: reject activation if the full tree cannot be protected within limits, emit audit, and do not mark the path active.
- Add negative UAT cases: chmod/write/delete denied with agent stopped; `icacls /reset` repaired; staged removal creates no tamper alert; expired staged removal does create alert; oversized ACL rejected; junction under protected tree skipped and audited or recorded.
- Add performance acceptance criteria for recursive scan and 60-second polling.
- Move audit event schema/routing validation into the specific plans that introduce events, then keep 52-05 as final end-to-end verification.

### Risk Assessment
**HIGH.** The phase is achievable and the decomposition is solid, but Windows DACL semantics are unforgiving. The main risk is not missing implementation pieces; it is getting edge-case behavior wrong around explicit deny precedence, canonical ACL replacement, recursive repair, and staged-removal races.

---

## OpenCode Review

### Summary
The plans are well-structured, logically decomposed, and aligned with the phase goals. The architecture choices (SDDL snapshots, watcher + polling, staged updates) are sound and appropriate for a security-sensitive system. However, the phase hinges on correct coordination between three concurrent systems (ACL writer, repair watcher, staging/suppression logic). Most risks are around race conditions and timing windows, ACL canonicalization correctness, Windows filesystem edge cases, and partial failure handling.

### Strengths
- Raw ACL construction instead of shelling out to `icacls` (correct for determinism).
- Explicit deny mask covers write/delete/ownership changes.
- SDDL snapshot enables canonical comparison and repair.
- Watcher combines event-driven (`ReadDirectoryChangesW`) with polling backstop for eventual consistency.
- Separation of OS threads and async repair pipeline.
- Clean normalized schema (`protected_paths` + `protected_path_aces`).
- Supports label-driven auto population (D-01).
- Explicit staging table with lifecycle timestamps and TTL-based GC.
- Full CRUD + sync endpoint with strong typing for tier/source enums.
- Clear diff-based application from config with staging-aware suppression.

### Concerns
- **HIGH: Canonical ordering not explicitly enforced during write (D-11).** Windows may reorder, but relying on it is risky.
- **HIGH: Missing explicit preservation of existing ACEs** (replace vs merge semantics unclear).
- **HIGH: Race between legitimate staged removal and watcher detection** (needs tight coordination with staging).
- **HIGH: Full DACL replacement may override legitimate admin-intended ACE changes.**
- **HIGH: Path validation via regex is insufficient for Windows edge cases** (UNC, device paths, trailing spaces).
- **HIGH: Race between watcher detection and staging flag propagation.**
- **HIGH: Ordering issues** (remove tripwire before unregister watcher vs after).
- **HIGH: No explicit locking per path** — concurrent operations may conflict.
- **MEDIUM: 10,000-file cap may silently leave partial coverage without audit escalation.**
- **MEDIUM: No retry/backoff on transient `ERROR_ACCESS_DENIED` / sharing violations.**
- **MEDIUM: Potential event storm under large subtree changes** — channel backpressure.
- **MEDIUM: No debounce/throttling strategy for repeated changes.**
- **MEDIUM: 60s polling may be too slow for high-security environments.**
- **MEDIUM: 5-minute TTL may be too coarse** (race with slow operations or long subtree changes).
- **MEDIUM: No transactional linkage between staging and actual ACL change.**
- **MEDIUM: No uniqueness constraint on `path`** (risk of duplicates).
- **MEDIUM: No versioning/audit history of changes.**
- **MEDIUM: Failure handling** (partial removal, crash mid-operation).
- **MEDIUM: GC may remove staging entry before operation completes.**
- **LOW: Deny mask may be overly broad** depending on enterprise expectations (WRITE_DAC/OWNER).
- **LOW: Thread-per-path model may not scale for many protected paths.**

### Suggestions
- Explicitly sort ACEs into canonical order before applying.
- Define clear merge strategy: prepend deny ACE without clobbering unrelated entries.
- Emit audit event when recursion cap is hit (partial enforcement visibility).
- Add retry logic with jitter for transient FS errors.
- Expand reparse-point detection beyond junctions.
- Introduce debounce window (e.g., 500ms–2s) before triggering repair.
- Tag staged operations with correlation IDs to suppress watcher precisely.
- Consider partial repair (only missing deny ACE) vs full replacement in some cases.
- Add bounded channel + drop/merge strategy under load.
- Make polling interval configurable.
- Add UNIQUE constraint on normalized path.
- Consider soft-delete or audit log for compliance.
- Normalize path casing (Windows case-insensitive).
- Use transactional boundary or durable marker before applying removal.
- Shorten GC interval or make TTL adaptive.
- Persist staging across restarts robustly (ensure WAL/durability).
- Add explicit state machine (STAGED -> APPLYING -> APPLIED).
- Introduce per-path mutex/lock to serialize operations.
- Define strict order: stage -> suppress watcher -> apply -> unregister -> mark applied.
- Add retry + rollback logic on failure.
- Ensure staging entry persists until confirmed applied.
- Add metrics (staged count, applied count, failures).

### Risk Assessment
**MEDIUM-HIGH.** The plans are well-structured and aligned with phase goals. If race conditions, locking, and validation are addressed with stricter ordering, the design should meet all success criteria reliably.

---

## Consensus Summary

Both reviewers independently identified the same core risk areas, indicating genuine architectural concerns that should be addressed before execution.

### Agreed Strengths
- Decomposition into 7 plans across 3 waves is logical and well-scoped.
- NTFS DACL as the kernel-enforced control point is the correct security foundation.
- SDDL snapshots + replace-not-append repair is the right canonicalization model.
- Hybrid event-driven + polling backstop watcher design is appropriate for reliability.
- Two-phase staged updates correctly distinguish operator intent from tampering.
- Raw Win32 API usage (not shelling out to icacls) ensures determinism.

### Agreed Concerns (by severity)

**HIGH (both reviewers):**
1. **ACL canonicalization is under-specified.** Neither plan defines the exact algorithm for reading existing ACEs, removing prior DLP tripwire ACEs, inserting the new deny ACE in canonical position, and preserving non-DLP explicit/inherited ACEs. This is the most critical correctness gap.
2. **Authenticated Users Deny vs SYSTEM/DLP-Admin interaction.** Both reviewers flagged that explicit deny ACEs for Authenticated Users could inadvertently block SYSTEM or DLP-Admin if those principals are also members of Authenticated Users. An access-control proof matrix is needed.
3. **Staged removal race conditions.** The exact sequencing of stage -> suppress -> remove -> mark applied -> GC is not fully specified. Crash/restart at intermediate states could leave paths unprotected or cause false tamper alerts.
4. **Watcher/subtree coverage gaps.** `ReadDirectoryChangesW(FILE_NOTIFY_CHANGE_SECURITY)` with `bWatchSubtree = true` on the root may not catch all descendant ACL changes reliably; the 60s polling backstop must walk the full protected tree.
5. **Path validation via regex is insufficient.** Windows path semantics (UNC, extended-length `\\?\`, reparse points, case folding, trailing spaces) require API-based canonicalization, not regex.
6. **Per-path concurrency / locking missing.** Plan 52-07 has no explicit locking per path; concurrent operations (staged removal + watcher repair + config sync) could conflict.

**MEDIUM (both reviewers):**
7. **10,000-file limit failure semantics undefined.** Partial recursive application could leave a subtree partially protected without clear operator visibility.
8. **60 KB ACL guard not enforced on all write paths.** Initial apply, recursive repair, server update, and restore from SDDL snapshot must all enforce the guard.
9. **Audit event routing deferred to Plan 52-05.** Event schema and SIEM compatibility should be validated in the plans that introduce the events (52-01, 52-02), not just at final integration.
10. **No debounce/throttling on watcher repair.** Rapid repeated ACL changes could cause event storms and channel backpressure.
11. **sync_from_labels conflict rules unspecified.** Auto-populated + manual + override paths need explicit precedence and collision handling.
12. **Staging TTL (5 min) may be too coarse.** Slow subtree operations or long config sync cycles could race with GC.

**LOW (both reviewers):**
13. **DPAPI doc should be verified against actual Phase 47 env vars and service names.**
14. **Thread-per-path watcher may not scale** for large protected-path sets.

### Divergent Views
- **Codex rates overall risk as HIGH**; **OpenCode rates it as MEDIUM-HIGH**. The difference is one of severity emphasis — Codex emphasizes that Windows DACL semantics are unforgiving and edge-case behavior is the primary risk, while OpenCode is slightly more optimistic that stricter ordering and locking will resolve the issues.
- **Codex calls out rename/move behavior** as a gap; OpenCode does not mention it.
- **OpenCode suggests partial repair** (only missing deny ACE) as an alternative to full replacement; Codex insists on full replace-not-append.

---

## Action Items for Planning

Before executing Phase 52, the following items should be addressed:

1. **Define the canonical DACL algorithm explicitly** in 52-01: read existing DACL, identify/remove prior DLP ACE, insert new deny ACE at position 0, preserve all non-DLP explicit ACEs in original order, preserve inherited ACEs, serialize to SDDL, enforce 60 KB guard, write atomically via `SetFileSecurityW`.

2. **Add access-control proof matrix** in 52-01 tests: verify that SYSTEM (S-1-5-18), DLP-Admin AD group, and normal domain users each receive the expected effective access on a protected path.

3. **Specify staging state machine** in 52-07: STAGED -> WATCHER_SUPPRESSED -> ACL_REMOVED -> APPLIED -> GC. Define crash recovery for each state.

4. **Replace regex path validation with Windows API canonicalization** in 52-06: use `GetFullPathNameW` or equivalent, reject UNC/extended-length/reparse-point paths explicitly.

5. **Add per-path locking** in 52-07: use `parking_lot::Mutex<PathBuf>` or a `DashMap<PathBuf, Mutex<()>>` to serialize concurrent operations on the same path.

6. **Define fail-closed behavior for 10K limit** in 52-01: reject protected-path activation if the full tree cannot be protected, emit audit, do not mark path active.

7. **Enforce 60 KB guard on all ACL write paths** in 52-01 and 52-02: initial apply, recursive repair, and SDDL snapshot restore.

8. **Add debounce window** in 52-02: 500ms-2s delay before triggering repair to batch rapid changes.

9. **Move audit event schema validation** into 52-01 and 52-02: verify `routed_to_siem()` and `triggers_alert()` at plan level, keep 52-05 as end-to-end verification only.

10. **Add negative UAT cases** to 52-05: expired staging produces tamper alert; partial recursive apply is rejected; junction under protected tree is skipped and audited.
