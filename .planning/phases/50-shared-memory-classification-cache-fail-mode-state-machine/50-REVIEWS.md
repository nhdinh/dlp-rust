---
phase: 50
reviewers: [codex, opencode]
reviewed_at: 2026-05-20T10:15:00Z
plans_reviewed:
  - 50-01-PLAN.md
  - 50-02-PLAN.md
  - 50-03-PLAN.md
  - 50-04-PLAN.md
  - 50-05-PLAN.md
  - 50-06-PLAN.md
---

# Cross-AI Plan Review — Phase 50 (Revised Plans)

> This is the second review cycle. The plans were revised in commit `19a4263` to address concerns from the first review (Codex + OpenCode, 2026-05-20). This review evaluates whether the revisions adequately resolved prior HIGH concerns and identifies any new issues.

---

## Codex Review

### Summary

The revised Phase 50 plans address most of the prior HIGH concerns: ABI/layout is now explicit, cache use is downgraded to a hint, DllMain work is avoided, LRU invalidation is tied to `cache_version`, fail-mode semantics are more deterministic, and the IPC inconsistency around `CacheDelta` is removed.

The plan is substantially stronger, but I would not treat it as execution-ready yet. The main remaining risks are cross-process memory safety, version compatibility, path identity correctness, and ensuring fail-open behavior cannot accidentally override the core invariant:

> NTFS ALLOW + ABAC DENY = FINAL DENY

The most important clarification: the shared-memory cache must never become an authorization source. Every plan should state that cache classifications are advisory only and that ABAC/policy enforcement still happens through authoritative agent/server decision paths.

---

### Plan 50-01: Extend IPC Protocol

#### Strengths

- Adds `protocol_version`, `cache_version`, and operation fields, which are necessary for mixed-version agent/hook behavior.
- Explicitly removes `CacheDelta`, resolving the earlier inconsistency.
- Backward-compatible bincode is called out directly.

#### Concerns

**HIGH: Bincode compatibility needs exact struct evolution rules.**
"Backward-compatible bincode" is not enough by itself. Bincode is positional and fragile unless the protocol uses enums/versioned wrappers carefully. Adding fields to existing structs can break old readers.

**MEDIUM: Version negotiation behavior is underspecified.**
The plan should define what happens when:
- Hook protocol version is newer than agent.
- Agent protocol version is newer than hook.
- `cache_version` is absent, zero, stale, or wraps.
- Unknown `op` values are received.

**MEDIUM: Removing `CacheDelta` may need migration handling.**
If any Phase 49 or existing hook IPC code still emits or expects deltas, the plan needs an explicit compatibility window or hard cutover.

#### Suggestions

- Use a versioned envelope, for example `IpcMessageV1`, `IpcMessageV2`, or an enum with stable discriminants.
- Add golden bincode fixtures for old request/response payloads.
- Define downgrade behavior explicitly: unknown protocol versions should fall back to pipe-only authoritative classification.
- Treat unknown ops as nonfatal protocol errors that trigger degraded behavior, not process failure.

#### Risk Assessment

**Medium.** The direction is right, but binary protocol evolution is a common source of silent compatibility bugs.

---

### Plan 50-02: Agent-Side Shared-Memory Cache

#### Strengths

- Formal ABI with magic, layout version, aligned header, and fixed-width offsets is a strong improvement.
- Security descriptor is explicitly scoped to SYSTEM full access and Builtin Administrators read-only.
- Release fence plus atomic flip addresses the previous memory-ordering gap.
- Overflow prioritization for T3/T4 aligns with safety goals.
- Debounced cache publishing should avoid rebuild thrash.

#### Concerns

**HIGH: Reader/writer snapshot consistency needs more detail.**
"Release fence + atomic flip" is promising, but the plan should specify the exact publication model. Readers need a way to detect torn reads or mid-update state across processes.

**HIGH: Shared-memory validation must cover all offsets and lengths.**
The ABI says `u64 offsets`, but the plan should require bounds checks for every offset, length, table count, string slice, and hash bucket before use.

**MEDIUM: Security descriptor may be insufficient for low-integrity or service boundary cases.**
The descriptor allows BA read access. That may be acceptable, but the threat model should confirm that elevated local admins reading classification hints is acceptable. If hooks run under standard users, they also need a safe read path; if they do not have direct SHM access, that should be explicit.

**MEDIUM: Cache rebuild atomicity and cleanup are not specified.**
Need details on old mapping lifetime, named mapping names, handle inheritance, and what happens when the agent crashes during rebuild.

#### Suggestions

- Use a sequence-lock style header: odd version while writing, even version when stable, with acquire/retry on readers.
- Include `total_size`, `generation`, `header_crc` or table checksum, and `payload_len`.
- Require all offsets to be relative to mapping base and reject anything outside mapping length.
- Document whether user-session hook DLLs can open the mapping under the stated DACL.
- Add corrupt-cache fuzz tests for invalid offsets, invalid counts, truncated mappings, wrong alignment, and wrong magic.

#### Risk Assessment

**High.** This is the core unsafe boundary of the phase. The plan is much better than before, but the execution must be exact.

---

### Plan 50-03: Hook DLL Cache Reader

#### Strengths

- Lazy `OnceLock` init avoids loader-lock issues.
- ABI validation on every lookup is the right posture for cross-process shared memory.
- Longest-prefix match and cache-version-aware LRU are good corrections.
- Treating classification as a hint only preserves the ABAC authority path.
- Rejecting 8.3 paths directly addresses one prior bypass concern.

#### Concerns

**HIGH: Path normalization remains the largest correctness risk.**
NT paths, DOS paths, UNC paths, symlinks, junctions, volume GUID paths, device paths, case folding, trailing dots/spaces, ADS streams, and reparse points can all affect identity. Rejecting 8.3 is good but not sufficient.

**HIGH: "ABI validation on every lookup" may threaten the 50us p95 target.**
Full validation every call could dominate lookup latency. The plan needs to distinguish cheap per-call validation from full mapping validation.

**MEDIUM: FNV-1a may be acceptable for lookup, but collision handling must be explicit.**
If the cache uses hashes, collisions must never produce a false positive classification. The matched path/prefix must still be compared byte-for-byte after canonicalization.

**MEDIUM: Thread-local LRU invalidation by `cache_version` needs wrap handling.**
If the version is `u64`, wrap is unlikely, but the comparison should be equality-based, not greater-than.

#### Suggestions

- Define one canonical path representation for cache keys, ideally derived from stable Windows APIs rather than string-only transformation.
- Explicitly handle reparse points and symlinks: either resolve them or force pipe classification.
- Split validation into:
  - full validation on map/open/version change,
  - cheap magic/layout/version/sequence checks per lookup.
- Add tests for UNC, `\\?\`, volume GUID paths, ADS, trailing separators, case differences, 8.3 aliases, symlinks, and junctions.
- Require byte comparison after hash lookup.

#### Risk Assessment

**High.** This plan handles prior concerns directionally, but Windows path identity is still a serious bypass surface.

---

### Plan 50-04: Fail-Mode State Machine

#### Strengths

- Four states are explicit.
- Deterministic thresholds are a major improvement over vague TTL semantics.
- Tier-gated decisions are aligned with risk: T3/T4 deny, T1/T2 allow.
- Polling only in `ISOLATED` limits overhead.
- Lazy init avoids DllMain risk.

#### Concerns

**HIGH: Fail-open behavior for T1/T2 must not bypass ABAC DENY.**
"Asymmetric tier-gated decisions" is reasonable during agent isolation, but the plan must be explicit that this is only when authoritative ABAC is unavailable. When ABAC responds DENY, final result must always be DENY.

**MEDIUM: Failure thresholds need classification by failure type.**
Timeouts, malformed responses, pipe unavailable, protocol mismatch, cache corruption, and access denied should not necessarily drive the same transition behavior.

**MEDIUM: RESYNC semantics are still thin.**
The plan says there is a `Resync` state, but should define entry, exit, allowed decisions, retry cadence, and whether stale cache hints are usable.

**LOW: Polling `version_word` every 100ms may miss liveness semantics.**
A version word changing proves cache publication, not necessarily IPC health or policy freshness.

#### Suggestions

- Add a transition table with event, guard, next state, action, and decision behavior.
- Separate transport health from cache freshness.
- Define per-tier behavior for each state, including whether pipe attempts are still made.
- Add tests for threshold edges: 2/3 failures, 3/3 failures, 9/10, 10/10, recovery, flapping, protocol mismatch, and corrupt SHM.
- Make "cache hint cannot authorize against ABAC denial" a named invariant test.

#### Risk Assessment

**Medium-High.** The state machine is much clearer, but it touches core enforcement semantics and needs invariant-level tests.

---

### Plan 50-05: Allowlist + Telemetry

#### Strengths

- Hardcoded system paths and full-path build-tool validation are stronger than basename-only matching.
- Operator-extended SHM allowlist gives operational flexibility.
- QPC histogram and thread-local counters are appropriate for low-overhead telemetry.
- Emission every 1000 calls limits hot-path cost.

#### Concerns

**HIGH: Allowlist semantics could become an authorization bypass.**
The plan must distinguish "allowed to use cache/fail-open optimization" from "allowed to bypass enforcement." Any allowlist that changes enforcement outcome needs strict policy control and auditability.

**MEDIUM: Hardcoded system paths are risky on localized or redirected Windows installs.**
System directories can vary by drive, architecture, redirection, and environment. Hardcoded strings can be both too broad and too narrow.

**MEDIUM: Build-tool validation needs signer/hash or canonical identity.**
Basename plus parent directory is better than basename alone, but a writable parent directory or path spoofing can still be abused.

**LOW: Telemetry emission every 1000 calls may lose rare failure signals.**
Aggregated counters are good for performance, but critical transitions should emit immediately.

#### Suggestions

- Define allowlist entries as canonical full paths plus optional signer/hash constraints.
- Include whether entries apply to cache usage, fail-open eligibility, telemetry suppression, or enforcement behavior.
- Require audit events for allowlist hits on T3/T4 or any fail-mode decision.
- Emit state transitions immediately, separate from periodic latency histograms.
- Add tests for path spoofing, writable directories, case variants, symlinks, and operator allowlist reload.

#### Risk Assessment

**Medium-High.** This plan addresses prior bypass feedback, but allowlists are inherently dangerous in DLP enforcement.

---

### Plan 50-06: Integration + Benchmarks

#### Strengths

- Pulls together agent IPC, cache warming, rebuild triggers, compatibility tests, and requirement-mapped tests.
- Explicit p95 micro-benchmark and CRIT-04 macro-benchmark are necessary.
- Bincode compatibility tests are correctly included.
- Requirement mapping across all 9 requirements is the right acceptance structure.

#### Concerns

**HIGH: Micro-benchmark may not reflect injected-hook reality.**
A synthetic lookup benchmark can pass while real hook paths fail due to TLS initialization, path normalization, SHM mapping, contention, or fallback pipe calls.

**MEDIUM: Requirement-mapped tests need negative/security cases, not just happy paths.**
Given this phase, corrupt cache, stale cache, protocol mismatch, and path bypass cases should be first-class tests.

**MEDIUM: CRIT-04 build overhead measurement needs stable methodology.**
"<= 25%" can vary heavily by machine, cache state, target project, antivirus, and warm/cold builds.

**LOW: Cache warming behavior needs bounds.**
If `cache_hint` warming is too aggressive, it could create memory growth or rebuild churn.

#### Suggestions

- Add an injected-process benchmark or integration harness that exercises the actual hook DLL reader path.
- Measure cold start, first lookup, steady-state hit, LRU hit, version-change invalidation, and fallback pipe path separately.
- Define CRIT-04 benchmark fixture, number of runs, warmup policy, and acceptable variance.
- Add requirement traceability table mapping CACHE-01..06 and FAIL-01..03 to exact tests.
- Add fault-injection tests for agent restart, mapping deletion, corrupt header, stale version, IPC timeout, and policy rebuild during lookup.

#### Risk Assessment

**Medium.** This is a good integration plan, but benchmark validity and negative test coverage need tightening.

---

### Cross-Plan Concerns (Codex)

**HIGH: Shared-memory cache must be non-authoritative everywhere.**
Plans 50-03 and 50-06 say this, but 50-02, 50-04, and 50-05 should repeat it as a hard invariant. Cache may improve routing or preclassification, but final enforcement must preserve ABAC authority.

**HIGH: Windows path identity remains the top bypass risk.**
The revised plan improved this, but it still needs a canonicalization strategy strong enough for reparse points, UNC/device paths, ADS, volume GUIDs, case behavior, and 8.3 aliases.

**HIGH: Cross-process ABI safety needs formal reader protocol.**
The header layout is now defined, but publication, validation, sequence consistency, and bounds checking need to be specified precisely.

**MEDIUM: Failure state and cache freshness are separate concepts.**
The plans sometimes imply cache version visibility can help determine health. IPC health, policy freshness, and SHM freshness should be tracked independently.

**MEDIUM: Tests should include adversarial cases.**
The requirement count is good, but this phase needs malicious/corrupt inputs, not only normal operation tests.

---

### Overall Risk Assessment (Codex)

**Overall risk: Medium-High.**

The revisions adequately address most prior review concerns at the design-intent level. I would approve moving into implementation only after tightening three areas:

1. Define the exact shared-memory publication and validation protocol.
2. Define canonical Windows path identity and bypass handling.
3. Make the enforcement invariant explicit across cache, fail-mode, and allowlist behavior.

Without those clarifications, the phase could pass performance benchmarks while still carrying enforcement bypass risk.

---

## OpenCode Review

### Plan 50-01: Extend IPC Protocol

#### Summary
Clean evolution of IPC with explicit versioning and removal of CacheDelta. Focuses on forward/backward compatibility and simpler semantics.

#### Strengths
- `protocol_version` + `cache_version` separation is correct and resolves earlier ambiguity.
- Removing `CacheDelta` eliminates state divergence class of bugs.
- Backward-compatible bincode shows awareness of rolling upgrades.
- Explicit `op` field reduces implicit coupling.

#### Concerns
- **MEDIUM:** bincode compatibility is underspecified. Bincode is not inherently self-describing; field reordering or enum evolution can silently break decoding.
- **MEDIUM:** No explicit handshake or capability negotiation beyond version fields. Risk of partial compatibility.
- **LOW:** No mention of max message size / DoS considerations.

#### Suggestions
- Lock serialization format: pin exact bincode config (endianness, varint, etc.) and document it as part of protocol ABI.
- Add a minimal handshake (agent <-> hook) to confirm compatible `protocol_version` before normal ops.
- Consider adding a checksum or message discriminator to detect decode drift early.

#### Risk Assessment
Medium risk. The design direction is correct, but serialization fragility could still cause subtle runtime failures during upgrades.

---

### Plan 50-02: Agent-Side Shared-Memory Cache

#### Summary
Defines a structured, versioned shared-memory cache with atomic publication and security boundaries.

#### Strengths
- ABI is now explicit: magic, layout_version, fixed header size, alignment. This addresses prior layout concerns well.
- Security descriptor is tightened (SY full, BA read). Good least-privilege baseline.
- Release fence + atomic flip indicates awareness of publish/consume ordering.
- Overflow prioritization (T3/T4) aligns with security invariant.
- Debounced push avoids thrash.

#### Concerns
- **HIGH:** Memory ordering still incomplete. Release fence on writer is mentioned, but reader-side Acquire semantics are not specified. Without Acquire on `version_word` read, visibility is not guaranteed.
- **MEDIUM:** Header evolution strategy unclear beyond `layout_version`. No reserved fields or size negotiation.
- **MEDIUM:** Security descriptor lacks explicit deny for non-admin users; relying on default inheritance may be risky.
- **LOW:** 128-byte header is fixed, but padding/packing rules across compilers need explicit static assertions.

#### Suggestions
- Require: writer uses `store(Ordering::Release)` on version; reader uses `load(Ordering::Acquire)` before accessing data. Document this invariant explicitly.
- Add `header_size` field + reserved bytes for forward compatibility.
- Harden DACL: explicitly deny `WD` (Everyone) if possible, or verify no unintended access via inheritance.
- Add `static_assert!(size_of::<Header>() == 128)` and offset checks.

#### Risk Assessment
Medium-high risk. ABI is solid, but memory ordering correctness is critical and currently only half-specified.

---

### Plan 50-03: Hook DLL Cache Reader

#### Summary
Safe, lazy-initialized reader with validation and local optimizations (LRU, prefix matching).

#### Strengths
- Avoids `DllMain` initialization -- prior loader lock concern resolved.
- ABI validation on every lookup is conservative and safe.
- Classification as HINT only preserves ABAC invariant -- critical correctness point.
- Thread-local LRU keyed by `cache_version` addresses invalidation concerns.
- Path normalization explicitly rejects 8.3 -- good hardening.

#### Concerns
- **HIGH:** Path normalization is still a major attack surface. NT/DOS/UNC handling is mentioned, but reparse points, symlinks, and device paths are not explicitly covered.
- **MEDIUM:** Longest-prefix match can be bypassed if normalization is incomplete or inconsistent with agent-side canonicalization.
- **MEDIUM:** FNV-1a hash is non-cryptographic; collision risk is low but attacker-controlled paths could degrade performance.
- **LOW:** Per-lookup ABI validation may add overhead relative to 50us target.

#### Suggestions
- Define a single canonicalization routine shared between agent and hook (byte-for-byte identical).
- Explicitly resolve or reject reparse points and device paths.
- Consider storing canonicalized paths in cache to avoid mismatch.
- Optionally guard hash table with secondary check (string compare) to eliminate collision ambiguity.

#### Risk Assessment
High risk. Path normalization inconsistencies are a classic bypass vector and not fully closed here.

---

### Plan 50-04: Fail-Mode State Machine

#### Summary
Explicit 4-state model with deterministic transitions and tier-aware behavior.

#### Strengths
- Clear state definitions (Healthy/Degraded/Isolated/Resync).
- Asymmetric decisions (deny T3/T4, allow T1/T2) respect security priorities.
- Deterministic thresholds (3/10) reduce flapping ambiguity.
- Background polling only in ISOLATED limits overhead.
- Lazy init avoids loader lock issues.

#### Concerns
- **HIGH:** RESYNC semantics still underspecified. What guarantees transition back to Healthy? Is cache atomically replaced or incrementally trusted?
- **MEDIUM:** Thresholds (3/10) are arbitrary; no hysteresis or time window definition -> risk of oscillation.
- **MEDIUM:** Staleness budgets per tier are mentioned but not concretely defined (time vs version delta).
- **LOW:** Polling every 100ms may be too slow for recovery or too fast for power-sensitive systems.

#### Suggestions
- Define RESYNC as a strict state: require monotonic `cache_version` advance + successful validation before exit.
- Add hysteresis (e.g., require N consecutive successes to leave Degraded/Isolated).
- Specify staleness in terms of `cache_version` delta + optional time cap.
- Consider event-driven wakeup (e.g., version change signal) instead of polling.

#### Risk Assessment
Medium-high risk. The structure is good, but incomplete RESYNC semantics could lead to inconsistent enforcement.

---

### Plan 50-05: Allowlist + Telemetry

#### Summary
Adds operational visibility and controlled bypass mechanisms.

#### Strengths
- Full-path validation (basename + parent) improves allowlist safety.
- Operator-extended SHM allowlist is flexible.
- QPC-based latency histogram is appropriate for microsecond targets.
- Thread-local counters reduce contention.

#### Concerns
- **HIGH:** Allowlist bypass risk remains. Basename + parent dir is insufficient if attacker can plant binaries in trusted directories (e.g., writable subdirs, DLL hijacking scenarios).
- **MEDIUM:** No signature or publisher validation for build tools.
- **MEDIUM:** Telemetry emission every 1000 calls may still be noisy or bursty under load.
- **LOW:** No mention of rate limiting or backpressure for telemetry channel.

#### Suggestions
- Require code-signing validation (Microsoft / trusted publisher) for allowlisted binaries.
- Validate full canonical path + deny if directory is user-writable.
- Add rate limiting or batching with time-based flush.
- Log allowlist hits explicitly for audit.

#### Risk Assessment
High risk. Allowlist is a common bypass vector and still too permissive.

---

### Plan 50-06: Integration + Benchmarks

#### Summary
End-to-end integration with performance validation and requirement coverage.

#### Strengths
- Clear linkage to success criteria (p95 <= 50us, CRIT-04).
- Includes compatibility tests and requirement-mapped coverage.
- Cache warming via `cache_hint` is a good optimization.
- Policy-change rebuild trigger ensures freshness.

#### Concerns
- **MEDIUM:** Micro-benchmark may not reflect real-world contention (multi-threaded hooks, cache misses, path normalization cost).
- **MEDIUM:** No explicit stress or adversarial tests (e.g., cache thrash, version churn, malformed SHM).
- **LOW:** CRIT-04 build overhead measurement methodology not described.

#### Suggestions
- Add multi-threaded benchmark simulating concurrent hook calls.
- Include adversarial tests: rapid cache_version flips, partial writes, corrupted header.
- Measure cold-start vs warm-cache separately.
- Define reproducible benchmark harness (CPU pinning, priority, etc.).

#### Risk Assessment
Medium risk. Likely to pass nominal benchmarks but may miss edge-case regressions.

---

### Overall Assessment (OpenCode)

**Have prior HIGH concerns been addressed?**
- ABI/layout: largely resolved (Plan 50-02 strong).
- Memory ordering: partially addressed, still incomplete (HIGH).
- Bincode compatibility: improved but still fragile (MEDIUM).
- DllMain loader lock: resolved.
- Security descriptor: improved but not fully hardened.
- ABAC bypass: mostly addressed via HINT-only model.
- CacheDelta inconsistency: resolved.
- LRU invalidation: addressed via `cache_version`.
- TTL semantics: still somewhat vague (staleness budgets).
- RESYNC semantics: still incomplete (HIGH).
- Allowlist bypass: still a HIGH concern.
- Path normalization: still a HIGH concern.

**Top Remaining Risks**
1. Path normalization inconsistencies enabling bypass.
2. Incomplete memory ordering contract (Release without guaranteed Acquire).
3. Allowlist security model too weak for adversarial environments.
4. Unspecified RESYNC semantics leading to inconsistent enforcement.

**Bottom Line**
The revision meaningfully improved structure and removed several systemic risks, but the remaining issues are concentrated in security-critical edges (path handling, allowlist, memory visibility). These must be tightened before implementation to avoid bypass-class vulnerabilities.

---

## Consensus Summary

### Agreed Strengths (2+ reviewers)

1. **ABI formalization is strong** — magic, layout_version, alignment, fixed-width offsets, and checksum address the prior HIGH concern well.
2. **DllMain loader lock resolved** — OnceLock lazy init is consistently used across Plans 50-03, 50-04, 50-05.
3. **CacheDelta inconsistency resolved** — SHM-only cache updates, no pipe broadcast.
4. **LRU invalidation addressed** — cache_version keying prevents stale entries across version flips.
5. **Classification-as-hint preserves ABAC authority** — cache hit = fast-path tier-gated decision; ABAC still evaluates on pipe.
6. **Security descriptor tightened** — BA read instead of AU read.
7. **Deterministic fail-mode thresholds** — 3/10 failure counts replace vague TTL-driven transitions.
8. **Explicit performance gates** — p95 <= 50us and CRIT-04 <= 25% are measurable and ambitious.

### Agreed Concerns (2+ reviewers)

| Concern | Severity | Reviewers | Plans |
|---------|----------|-----------|-------|
| Path normalization incomplete — reparse points, symlinks, volume GUIDs, ADS not covered | HIGH | Codex, OpenCode | 50-03 |
| Memory ordering incomplete — reader-side Acquire not explicitly specified | HIGH | Codex, OpenCode | 50-02 |
| Bincode compatibility still fragile — needs versioned envelope / golden fixtures | HIGH/MEDIUM | Codex, OpenCode | 50-01 |
| RESYNC semantics underspecified — entry/exit guards, retry cadence, stale hint handling | HIGH | Codex, OpenCode | 50-04 |
| Allowlist still a bypass risk — writable subdirs, no signature validation | HIGH | Codex, OpenCode | 50-05 |
| Shared-memory cache must be non-authoritative everywhere (not just 50-03/50-06) | HIGH | Codex | 50-02, 50-04, 50-05 |
| ABI validation on every lookup may threaten 50us p95 | HIGH | Codex | 50-03 |
| Micro-benchmark may not reflect injected-hook reality | MEDIUM | Codex, OpenCode | 50-06 |
| Need adversarial / negative test coverage | MEDIUM | Codex, OpenCode | 50-06 |
| Failure thresholds arbitrary — no hysteresis or time windows | MEDIUM | OpenCode | 50-04 |
| Build-tool allowlist needs signer/hash validation | MEDIUM | Codex, OpenCode | 50-05 |
| Hardcoded system paths risky on localized Windows | MEDIUM | Codex | 50-05 |

### Divergent Views

- **Codex rates overall risk as Medium-High**; **OpenCode rates individual plans as High (50-03, 50-05), Medium-High (50-02, 50-04), Medium (50-01, 50-06)**. Codex's overall rating reflects cross-cutting concerns about path identity and ABAC authority.
- **Codex emphasizes sequence-lock style header** (odd/even version); OpenCode emphasizes explicit Acquire load. Both are valid — the plan should pick one and document it.
- **OpenCode suggests event-driven wakeup** for RESYNC; Codex focuses on tightening polling-based semantics. Both are valid alternatives.
- **Codex raises "ABI validation on every lookup threatens 50us"** as HIGH; OpenCode raises it as LOW. The difference reflects uncertainty about validation cost — benchmarking will resolve this.

### Action Items for Planning

Before execution begins, the following items should be addressed:

1. **Specify reader-side memory ordering** — Document `load(Ordering::Acquire)` on `version_word` before any data access. Consider sequence-lock (odd/even version) for stronger consistency.
2. **Harden path normalization** — Define canonical Windows path representation covering: reparse points, symlinks, junctions, volume GUID paths, ADS, trailing dots/spaces. Either resolve via `GetFinalPathNameByHandleW` or force pipe fallback.
3. **Add versioned IPC envelope** — Use `IpcMessageV1 | IpcMessageV2` enum or stable discriminant wrapper. Add golden bincode fixtures for compatibility tests.
4. **Specify RESYNC semantics fully** — Define entry guards (pipe success + fresh version), exit guards (LRU flush + counter reset), allowed decisions, and retry cadence. Add transition table.
5. **Strengthen allowlist** — Consider code-signer validation for build tools, deny user-writable directories, emit audit events for all allowlist hits.
6. **Make cache-hint non-authoritative invariant explicit** — Repeat in Plans 50-02, 50-04, 50-05: cache stores classification hint only; ABAC authority is never bypassed.
7. **Add adversarial test cases** — Corrupt SHM, rapid version flips, partial writes, malformed headers, path bypass attempts, symlink/junction attacks.
8. **Split validation cost** — Full validation on map open/version change; cheap magic/version check per lookup. Benchmark to verify p95 <= 50us.
9. **Add failure-type classification** — Timeouts, malformed, pipe unavailable, protocol mismatch should not all drive identical transitions.
10. **Define CRIT-04 benchmark methodology** — Fixture project, number of runs, warmup policy, acceptable variance, CPU pinning.
