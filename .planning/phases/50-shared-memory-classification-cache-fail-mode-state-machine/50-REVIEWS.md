---
phase: 50
reviewers: [codex, opencode]
reviewed_at: 2026-05-20T00:00:00Z
plans_reviewed:
  - 50-01-PLAN.md
  - 50-02-PLAN.md
  - 50-03-PLAN.md
  - 50-04-PLAN.md
  - 50-05-PLAN.md
  - 50-06-PLAN.md
---

# Cross-AI Plan Review — Phase 50

## Codex Review

### Summary

The phase plan is directionally strong: it decomposes the cache, IPC, hook hot path, fail-mode behavior, allowlisting, telemetry, and benchmark validation into sensible waves. The major design risk is that several plans assume correctness from shared-memory layout, version flipping, TTL interpretation, and hook-process concurrency without explicitly specifying memory ordering, ABI/layout stability, malformed-cache handling, or Windows object security edge cases. The plan likely can achieve the phase goals, but only if the implementation treats the shared-memory cache as an untrusted, concurrently changing binary data structure and keeps the hook hot path extremely small.

### Strengths

- Clear wave ordering: protocol and shared cache foundation first, hook lookup/fail-mode next, integration and benchmarks last.
- Good performance posture: read-only mapping in hooked processes, double-buffered cache, atomic version word, thread-local LRU, and pipe avoidance on cache hits.
- Fail-mode states are explicitly modeled and tied to measurable transition triggers.
- Tier-gated behavior matches the core DLP invariant: sensitive writes fail closed while lower tiers can fail open.
- Operator-extendable allowlist is separated from hardcoded trusted paths, which is the right shape for operational flexibility.
- Success criteria include both correctness and performance gates, including CRIT-04 overhead and p95 cache-hit latency.

### Concerns

- **HIGH: Shared-memory ABI and validation are underspecified.**
  The cache layout needs explicit packed/aligned structs, magic/version fields, length bounds, checksums or generation validation, and defensive parsing. Hook DLLs must never trust counts, offsets, string lengths, or hash-table metadata from shared memory.

- **HIGH: Atomic flip correctness needs more detail.**
  "High 63 bits version, low bit active buffer" is reasonable, but the plan does not specify memory ordering. Writer must fully populate the inactive buffer before a release-store version flip; readers need acquire-load and must re-check version if reading multi-field data.

- **HIGH: Security descriptor may be too broad or semantically wrong.**
  `D:(A;;GA;;;SY)(A;;GR;;;AU)` gives SYSTEM full access and authenticated users read access. That may be acceptable for read-only classification metadata, but the object is named under `Global\`, so namespace squatting, creation races, integrity levels, service SID ACLs, and admin/operator access should be explicitly handled. The agent should create the mapping before hooks can map it and verify owner/security on open.

- **HIGH: Plan 50-01's bincode compatibility claim is risky.**
  `#[serde(default)]` helps deserialization for self-describing formats, but bincode compatibility with additive struct fields is not automatically safe unless using a compatible enum/versioned envelope strategy. This needs validation or a protocol version field.

- **HIGH: Cache-hit allow/deny semantics may be incomplete.**
  Plan 50-03 says T3/T4 write denied immediately on cache hit and T1/T2 allowed immediately. That sounds like classification-tier-only enforcement, but ABAC policy may depend on actor, process, destination, operation, device, or time. The cache must store a policy decision scope or classification hint, not accidentally bypass ABAC.

- **MEDIUM: CacheDelta push design conflicts with wording.**
  The success criterion says `HookMessage::CacheDelta` push flips the version word, but D-16 says no pipe broadcast, only shared-memory atomic flip. The plan should reconcile terminology: either there is no push to DLLs, or the "push" is agent-internal policy subscriber rebuild plus version flip.

- **MEDIUM: RESYNC transition may be underspecified.**
  D-07 requires successful pipe round-trip and newer cache version; D-14 says background thread polls the version word. Polling only the version word is not enough to prove pipe reachability. The transition should require both conditions before HEALTHY.

- **MEDIUM: In-flight decision guarantee is not designed.**
  "Without losing any in-flight decision" needs a concrete mechanism: per-call version snapshot, stable buffer selection, no freeing/remapping while calls are active, and fallback behavior if the active buffer flips during lookup.

- **MEDIUM: TTL model needs exact semantics.**
  D-12 says check `ttl_bits` against `cache_version_seen_at`, while success criteria specify wall-clock staleness budgets. Versions alone do not imply seconds unless version metadata includes timestamps or monotonic time. The plan needs a monotonic timestamp per buffer or per entry.

- **MEDIUM: Thread-local LRU may hide stale entries.**
  The LRU must be keyed by cache version or invalidated on version change. Otherwise stale decisions can survive a global version flip and violate policy-edit propagation.

- **MEDIUM: Allowlist ordering is ambiguous and potentially dangerous.**
  Plan 50-05 says `allowlist -> cache -> build-tool -> fail-mode -> pipe`, but D-09 says build tools are part of the allowlist and should bypass pipe entirely. The final order should be explicit and security-reviewed, especially for user-writable paths containing trusted executable names.

- **MEDIUM: Windows path normalization is a major edge case.**
  Prefix matching must handle NT paths, DOS paths, UNC paths, case-insensitivity, trailing separators, short 8.3 names, reparse points, symlinks, alternate data streams, and canonicalization races.

- **MEDIUM: Named object lifecycle and session boundary risks.**
  `Global\DlpClassificationCache` requires appropriate privileges and behavior across services, sessions, and process integrity levels. Startup ordering and stale mapping cleanup should be specified.

- **LOW: 2 MiB fixed cache may be too small without sizing evidence.**
  It may be fine, but the plan should define overflow behavior: truncation, priority eviction, root-prefix-only fallback, telemetry, and fail-safe behavior.

- **LOW: Telemetry every 1000 calls may be too expensive or noisy.**
  QPC is appropriate, but p95 computation and audit emission must stay off the hot path or be sampled/batched.

- **LOW: Test plan says "all 9 requirements," but the prompt lists CACHE-01..06 and FAIL-01..03 without mapping.**
  The final plan should map each requirement to explicit tests and success criteria.

### Suggestions

- Define a formal shared-memory cache ABI:
  - magic number, ABI version, total size, active buffer offset, counts, offsets, build timestamp, monotonic cache version, checksum/generation.
  - fixed-endian primitive fields.
  - no raw Rust `String`/`Vec`/enum layout in shared memory.
  - strict bounds checking in the DLL.

- Use a versioned IPC envelope instead of relying on additive bincode fields:
  - `HookRequestV1 | HookRequestV2` or add an explicit protocol version and compatibility tests against old/new agent/DLL pairs.

- Clarify what the cache stores:
  - classification hint only, policy decision, or tier-based fail-mode decision.
  - If ABAC can depend on runtime subject/context, the hook must not treat classification cache hits as unconditional allow/deny except in carefully defined fail-mode paths.

- Make memory-ordering rules part of Plan 50-02 and 50-03:
  - writer populates inactive buffer;
  - writer publishes with release-store;
  - reader acquire-loads version;
  - reader snapshots active buffer;
  - reader validates version before/after lookup if necessary.

- Key or invalidate thread-local LRU by `cache_version`. On version mismatch, drop entries or treat them as misses.

- Add explicit malformed/stale cache behavior:
  - bad magic/version/checksum/counts -> enter degraded/isolated-safe behavior;
  - T3/T4 writes deny;
  - T1/T2 writes allow only if policy permits fail-open;
  - emit telemetry once per state change, not per call.

- Reconcile RESYNC:
  - `ISOLATED -> RESYNC` when version word advances;
  - `RESYNC -> HEALTHY` only after successful pipe round-trip and local cache version confirmed;
  - timeout/failure sends back to ISOLATED or DEGRADED deterministically.

- Add Windows path canonicalization requirements:
  - normalize to NT namespace before prefix lookup;
  - case-fold consistently;
  - handle reparse points and UNC paths;
  - prevent `C:\Windows\System32Fake` from matching `C:\Windows\System32`.

- Treat allowlist as security-sensitive:
  - hardcoded allowlist should prefer signed binaries and protected directories;
  - operator allowlist entries should be canonicalized and audited;
  - process-name-only matching is insufficient for build tools.

- Add cache-size overflow behavior and telemetry. A partial cache should be observable and should not silently weaken enforcement.

- Split benchmark validation into micro and macro gates:
  - micro: cache-hit p50/p95/p99 with QPC/criterion-like harness;
  - macro: `cargo build --workspace --release` overhead;
  - stress: concurrent policy flips while many hooked processes perform lookups.

### Risk Assessment

**Overall risk: HIGH.**

The architecture is plausible and well decomposed, but this phase touches a hook DLL hot path, shared memory, Windows named objects, concurrent atomic publication, fail-open/fail-closed behavior, and policy correctness. Small mistakes could either exceed the 50 us p95 target or weaken enforcement during outage conditions. The plan should proceed only after tightening the shared-memory ABI, IPC compatibility strategy, path normalization, cache invalidation, and RESYNC/fail-mode semantics.

---

## OpenCode Review

### Summary

This is a strong, systems-level design that shows clear attention to latency constraints, Windows primitives, and failure semantics. The separation between shared-memory fast path and pipe-based slow path is appropriate for the <=50 us target, and the fail-mode state machine is well thought out. However, there are several high-risk areas around shared memory layout safety, cross-process synchronization, versioning semantics, and Windows-specific edge cases (especially around DLL injection lifecycle and security descriptors). The plan is close to viable but needs tightening around memory correctness, race conditions, and observability guarantees to reliably meet the success criteria.

### Strengths

- Clear latency-first architecture: shared-memory cache + pipe fallback is appropriate for <=50 us p95.
- Double-buffered version flip is a good approach to avoid in-place mutation hazards.
- Tiered fail-open/fail-closed behavior is explicitly defined and aligns with DLP safety goals.
- Two-tier cache (prefix + hash) is a solid tradeoff for path-heavy workloads.
- LRU + cache_hint warming reduces cold-start penalties effectively.
- Debounced cache rebuild (500 ms) avoids thrashing under policy churn.
- Allowlist separation (static + operator SHM) is flexible and avoids rebuilds.
- Explicit state machine transitions reduce ambiguity in degraded scenarios.
- Telemetry baked into hot path (QPC + histogram) ensures performance visibility.
- Backward-compatible IPC evolution using `#[serde(default)]` is well handled.

### Concerns

#### HIGH

- **Shared memory consistency and torn reads**
  Double-buffer flip via a single atomic bit is not sufficient alone. Readers may observe partially written buffers unless strict write ordering and memory barriers are enforced. There is no mention of:
  - `Release` semantics on writer
  - `Acquire` semantics on reader
  - Ensuring buffer write completion before version flip
  This can lead to corrupted lookups or undefined behavior.

- **Unsafe shared memory layout / ABI stability**
  The cache layout is not formally specified (alignment, padding, struct packing). Rust + cross-process memory without a strict `#[repr(C)]` schema and versioning header is fragile.

- **DllMain misuse risk**
  Mapping shared memory and initializing subsystems in `DllMain` is dangerous on Windows due to loader lock. This can deadlock or crash under real workloads.

- **Security descriptor too permissive**
  `AU` (Authenticated Users) with `GR` (read) allows any user process to inspect classification data. This may leak sensitive classification metadata.

- **Fail-mode correctness under partial initialization**
  If cache mapping fails or is unavailable at process start, behavior is undefined. The plan assumes cache always exists.

- **Version-based TTL logic ambiguity**
  TTL tied to `cache_version_seen_at` is underspecified:
  - What if version increments rapidly?
  - TTL vs wall-clock mismatch
  - No monotonic time source defined

#### MEDIUM

- **Hash table collision handling**
  Open addressing with only 8-byte hash verification risks false positives (low probability but non-zero at scale). No fallback to full path compare is mentioned.

- **Global namespace contention**
  `Global\DlpClassificationCache` requires SeCreateGlobalPrivilege in some contexts and can conflict across sessions/services.

- **Background thread model**
  Polling every 100 ms via `WaitForSingleObject` is vague:
  - What object is being waited on?
  - Polling suggests busy wakeups rather than event-driven design

- **LRU cache coherence**
  Thread-local LRU may serve stale entries beyond TTL if not invalidated on version flip.

- **Allowlist bypass risk**
  Build-tool bypass could become an exfiltration vector if abused (e.g., rename malicious binary to `cargo.exe`).

- **CacheDelta design inconsistency**
  Design says "no pipe broadcast", but success criteria mention `HookMessage::CacheDelta`. There is a mismatch.

#### LOW

- 2 MiB fixed size may be insufficient for large enterprises (deep paths, many entries).
- 500 ms debounce may still be too aggressive under heavy policy churn.
- Telemetry every 1000 calls may skew under bursty workloads.

### Suggestions

- **Memory safety and layout**
  - Define a strict shared memory schema with:
    - `#[repr(C)]`
    - explicit versioned header (`magic`, `layout_version`, `size`)
    - alignment guarantees
  - Use `AtomicU64` with explicit `store(Ordering::Release)` and `load(Ordering::Acquire)` for version flip.
  - Ensure full buffer write completes before flipping active bit.

- **Safer initialization**
  - Move all heavy initialization out of `DllMain` into a lazy init (`OnceLock` or similar) triggered on first hook invocation.

- **Strengthen cache correctness**
  - Add full-path verification on hash match to eliminate collision risk.
  - Add per-entry version stamp or generation ID to invalidate LRU entries on version flip.

- **Improve fail-mode robustness**
  - Define explicit behavior when:
    - shared memory mapping fails
    - cache is empty or uninitialized
  - Add a "NO_CACHE" fallback state distinct from DEGRADED.

- **TTL semantics**
  - Use monotonic clock (`QueryPerformanceCounter`) instead of version-based TTL.
  - Store absolute expiry timestamp per entry.

- **Security hardening**
  - Restrict shared memory ACL:
    - Replace `AU` with a specific SID group if possible (e.g., service + injected processes)
  - Validate allowlisted binaries via:
    - full path + signature (optional but safer)
    - not just filename

- **Event-driven resync**
  - Replace polling with:
    - named event (`CreateEvent`) signaled by agent on version flip
  - Reduces CPU overhead and latency to resync.

- **Global object handling**
  - Consider fallback to `Local\` namespace if `Global\` fails.
  - Document required privileges.

- **Observability**
  - Emit state transitions (HEALTHY -> DEGRADED etc.) as explicit audit events.
  - Include cache hit/miss ratio in telemetry.

- **Clarify CacheDelta design**
  - Either:
    - remove `HookMessage::CacheDelta` and rely purely on SHM version
    - or define when pipe push is used vs SHM polling

### Risk Assessment

**Overall: MEDIUM-HIGH**

The architecture is sound and appropriate for the performance target, but the implementation details around shared memory correctness, Windows loader constraints, and synchronization are non-trivial and currently under-specified. These are areas where small mistakes lead to rare, hard-to-debug crashes or silent policy bypasses. With the suggested fixes — especially around memory ordering, initialization, and TTL semantics — the risk can be reduced to MEDIUM.

---

## Consensus Summary

### Agreed Strengths

Both reviewers independently praised:

1. **Wave ordering is sensible** — protocol/cache foundation first, hook integration next, benchmarks last.
2. **Double-buffered atomic version flip** is the right concurrency primitive for this use case.
3. **Tier-gated fail-mode behavior** aligns correctly with DLP safety invariants.
4. **Thread-local LRU + cache hint warming** are well-designed performance optimizations.
5. **Separation of hardcoded vs operator-extended allowlist** provides operational flexibility.
6. **Explicit state machine with deterministic triggers** reduces ambiguity in degraded operation.
7. **Performance gates (CRIT-04, p95 <= 50us)** are appropriately ambitious and measurable.

### Agreed Concerns (2+ reviewers)

| Concern | Severity | Reviewers |
|---------|----------|-----------|
| Shared-memory ABI/layout underspecified — needs magic, version header, alignment, bounds checking | HIGH | Codex, OpenCode |
| Memory ordering for atomic flip not specified — needs Release (writer) / Acquire (reader) | HIGH | Codex, OpenCode |
| Bincode backward compatibility with additive fields is risky | HIGH | Codex |
| DllMain loader lock risk for shared-memory mapping and thread creation | HIGH | Codex, OpenCode |
| Security descriptor `AU` read access may leak classification metadata | HIGH | Codex, OpenCode |
| Cache-hit semantics may bypass ABAC if cache stores only tier, not full policy decision | HIGH | Codex |
| CacheDelta wording inconsistency (pipe broadcast vs no broadcast) | MEDIUM | Codex, OpenCode |
| Thread-local LRU not invalidated on version flip — stale entries possible | MEDIUM | Codex, OpenCode |
| TTL semantics ambiguous (version-based vs wall-clock) | MEDIUM | Codex, OpenCode |
| RESYNC transition underspecified (needs both pipe success AND fresh cache) | MEDIUM | Codex |
| Allowlist bypass risk (rename binary to `cargo.exe`) | MEDIUM | OpenCode |
| Windows path normalization edge cases unaddressed | MEDIUM | Codex |
| 2 MiB cache size overflow behavior undefined | LOW | Codex, OpenCode |

### Divergent Views

- **Codex rates overall risk as HIGH**; **OpenCode rates MEDIUM-HIGH**. The difference reflects Codex's stronger emphasis on the bincode compatibility risk and ABAC bypass risk, which OpenCode did not raise at the same severity.
- **OpenCode suggests event-driven resync** (named event signaled by agent); Codex focuses on tightening the polling-based approach. Both are valid — the plan should evaluate event-driven as an alternative.
- **OpenCode suggests `NO_CACHE` fallback state** distinct from DEGRADED; Codex suggests malformed-cache safe behavior within existing states. The plan should pick one approach and document it.

### Action Items for Planning

Before execution begins, the following items should be addressed:

1. **Formalize shared-memory ABI** — Add magic number, layout version, size fields, and explicit `#[repr(C, align(8))]` to `CacheHeader`. Document endianness and 32/64-bit compatibility.
2. **Specify memory ordering** — Document `fence(Release)` before atomic flip, `load(Acquire)` on reader, and version validation before/after multi-field reads.
3. **Resolve CacheDelta inconsistency** — Either remove `HookMessage::CacheDelta` and rely purely on SHM version flip, or document when pipe push is used vs SHM polling.
4. **Clarify cache-hit semantics** — Document that cache stores classification *hint* only; ABAC policy evaluation still occurs on pipe round-trip. Cache hit = fast-path tier-gated decision; cache miss = full ABAC evaluation via pipe.
5. **Add LRU invalidation on version flip** — Thread-local LRU must drop entries when `cache_version` changes.
6. **Define overflow behavior** — Document what happens when 2 MiB is exceeded: priority truncation, telemetry alert, fallback to pipe-only.
7. **Add path normalization requirements** — Document handling of NT paths, DOS paths, UNC paths, 8.3 names, reparse points, and case-insensitivity.
8. **Harden allowlist** — Consider full-path + signature validation for build tools, not just basename matching.
9. **Add malformed-cache safe behavior** — Define behavior when shared memory has bad magic, version mismatch, or corrupted counts: enter DEGRADED/ISOLATED-safe mode, deny T3/T4 writes, allow T1/T2.
10. **Reconcile RESYNC semantics** — Document that `RESYNC -> HEALTHY` requires both successful pipe round-trip AND confirmed fresh cache version.
