---
phase: 49
reviewers: [codex, opencode]
reviewed_at: 2026-05-19T17:25:00Z
plans_reviewed: [49-01-PLAN.md, 49-02-PLAN.md, 49-03-PLAN.md, 49-04-PLAN.md, 49-05-PLAN.md]
---

# Cross-AI Plan Review — Phase 49

## Codex Review

### Summary

The plans cover the major building blocks for Phase 49, but the current design has several gaps that could prevent the stated coverage guarantees from being met, especially the `>= 99% within 500 ms` target. The biggest risks are ETW filtering before allowlist logging, race-prone injection state transitions, uncertain PPL detection behavior, lack of explicit latency measurement, and incomplete treatment of AppInit/WoW64 registry realities. The phase is feasible, but the plans need tighter contracts around event flow, skip visibility, timing instrumentation, and operational update propagation.

### Strengths

- Good wave ordering: core registry/allowlist/AppInit first, server/TUI config in parallel, watcher/injector integration later.
- Dedicated ETW thread plus bounded channel matches the architecture decisions and keeps blocking APIs off Tokio.
- Startup `EnumProcesses` sweep correctly addresses the restart invariant.
- Separation between process discovery, allowlist matching, injection, telemetry, and admin configuration is sound.
- Explicit skip categories and visible logging are aligned with the success criteria.
- One retry after 50 ms matches D-12 and avoids unbounded retry loops.
- Server-side allowlist CRUD gives operators a path to extend exclusions without redeploying the agent.
- Installer rollback plan for AppInit registry state is a necessary safety measure.

### Concerns

- **HIGH: 49-03 ETW System32/WinSxS pre-filter conflicts with success criteria.** Dropping events before the registry/allowlist layer means skipped processes may not be visibly logged, and non-allowlisted user-mode processes launched from those paths would never be injected. This also weakens coverage accounting.

- **HIGH: 49-03 WMI backstop appears always-on, conflicting with D-07.** The plan says WMI backstop thread runs with subscription or polling fallback, but the architecture says WMI is active only when ETW primary is unhealthy. Always-on WMI could duplicate events, increase overhead, and complicate state races.

- **HIGH: 49-01 `should_skip` / registry state can race duplicate injection.** A check-then-record API over `DashMap` is not enough if ETW, WMI, startup sweep, and periodic sweep observe the same PID concurrently. The registry needs an atomic "claim injection" transition.

- **HIGH: 49-01 PPL detection is underspecified.** `GetProcessMitigationPolicy(ProcessSignaturePolicy)` may fail or be unavailable for some protected targets depending on access rights and OS version. Treating `AccessDenied` as PPL in 49-03 is pragmatic but can misclassify ACL failures, EDR tampering, or privilege issues.

- **HIGH: 49-03 no concrete latency instrumentation for the 500 ms SLA.** The plans describe injection and hello messages, but not how ProcessStart timestamp, injection start, DLL hello timestamp, timeout, and percentile/SLO reporting are correlated.

- **MEDIUM: 49-01 system-critical basename matching is spoofable.** A user process named `csrss.exe` outside a trusted Windows directory could be skipped incorrectly unless path, signer, session, and PID characteristics are checked.

- **MEDIUM: 49-01 self-image-path prefix matching can overmatch.** Prefix checks can accidentally allowlist sibling paths such as `C:\Program Files\DLP-Evil\...`. This should use canonical paths and directory-boundary checks.

- **MEDIUM: 49-01 Authenticode signer extraction may be expensive in hot paths.** Per-process certificate validation during bursty process creation could threaten the 500 ms target unless cached by image path/hash/signature metadata.

- **MEDIUM: 49-01/49-05 AppInit handling needs separate x86/x64 registry coverage.** AppInit_DLLs behavior differs across registry views and process bitness. The plan mentions x86 DLL injection but not x86 AppInit registration/verification.

- **MEDIUM: 49-02 allowlist API lacks audit/version semantics.** Operator allowlist changes are security-sensitive. The plan should include audit events, actor identity, optimistic concurrency or `updated_at` conflict handling, and a monotonically increasing config version for agents.

- **MEDIUM: 49-02 schema does not clearly model glob semantics.** `path` is described as path globs in 49-01, but the server schema just says `path`. Validation should distinguish exact path, prefix, and glob patterns, or the agent/server may interpret entries inconsistently.

- **MEDIUM: 49-03 startup sweep parallelism can become self-inflicted load.** `rayon par_chunks(16)` may still attempt many remote opens/injections at once. Without throttling and timeout budgets, restart sweep could degrade endpoint responsiveness or trip EDR.

- **MEDIUM: 49-04 30s polling weakens "operator can extend list without restart."** It technically satisfies no restart, but an operator exclusion may take up to 30 seconds. That may be unacceptable during incident response or when an EDR process is being repeatedly touched.

- **MEDIUM: 49-05 telemetry denominator is ambiguous.** `injected / (injected + skipped_non_ppl + failed)` excludes some skipped categories and may overstate coverage. Success criterion is based on non-allowlisted PIDs, so telemetry should separate eligibility, intentional skip, failed, timed out, and hello-confirmed.

- **LOW: 49-03 `crossbeam-channel` does not directly provide drop-oldest semantics.** This is implementable, but the plan should spell out the nonblocking receive-then-send behavior and associated metrics.

- **LOW: 49-05 cleanup of `Failed` every 60s may erase useful diagnostics.** Removing failed states too quickly could make operator troubleshooting and telemetry correlation harder.

### Suggestions

- Replace ETW pre-filtering with "fast classify and record skip" unless the process is truly impossible or irrelevant. If System32/WinSxS events are suppressed, document that this is a deliberate coverage gap and exclude them from the SLA denominator.
- Add an atomic registry method such as `try_claim_injection(pid, generation/process_start_time) -> ClaimResult` to prevent duplicate injections across ETW, WMI, startup sweep, and periodic sweep.
- Include process creation time in registry keys or state validation. PID reuse can otherwise corrupt state after exits.
- Make PPL detection a best-effort classifier with explicit outcomes: `Protected`, `LikelyProtectedAccessDenied`, `QueryFailed`, `NotProtected`. Log them differently instead of collapsing all `AccessDenied` into PPL.
- Add a latency pipeline: ETW/WMI event timestamp, injection attempt timestamp, DLL hello timestamp, timeout marker, and per-PID correlation ID. Report p50/p95/p99 and percentage under 500 ms.
- Require allowlist path canonicalization, trusted Windows directory checks for system-critical basenames, and exact directory-boundary prefix matching.
- Cache signer results by file identity, ideally path plus file ID/hash/signing timestamp, with invalidation on file metadata change.
- Model allowlist entries explicitly: `match_type = exact_path | path_glob | cert_subject | signer_thumbprint`, plus validation rules per type.
- Add admin audit events for allowlist create/update/delete, including actor, old value, new value, timestamp, and source.
- Add config versioning or ETag-style polling so agents can cheaply detect changes and TUI updates can confirm propagation.
- Throttle startup and periodic sweeps with bounded concurrency, per-process timeout, and counters for skipped due to overload/backpressure.
- Add integration tests beyond unit tests: simulated ETW event stream, duplicate PID events, PID reuse, allowlist update propagation, x86/x64 DLL selection, Secure Boot AppInit disabled event exactly once, and telemetry denominator correctness.

### Risk Assessment

**Overall risk: HIGH.**

The phase touches process creation monitoring, cross-process injection, Windows security boundaries, installer registry mutation, admin configuration, and telemetry. The plans are directionally strong, but several details directly affect the phase's core promise: universal coverage within 500 ms. The ETW pre-filter, state race risk, PPL ambiguity, and missing SLA instrumentation are the main blockers to trusting the implementation as planned. Addressing those before execution would reduce the risk to medium.

---

## OpenCode Review

### 49-01 — Agent Core Modules (Wave 1)

#### Summary
Solid foundation with clear separation of concerns (registry, allowlist, AppInit). The design aligns well with later ETW/injection stages and keeps state tracking explicit. However, some subtle correctness and Windows edge cases (PID reuse, race conditions, signer extraction cost) could undermine reliability at scale.

#### Strengths
- Clean ProcessState model with explicit lifecycle transitions
- DashMap is appropriate for concurrent ETW + injector access
- Allowlist ordering is deterministic and matches safety priorities
- Reuse of existing Authenticode extraction logic reduces duplication risk
- Secure Boot + AppInit validation correctly anticipates deployment pitfalls
- Unit test coverage is good for core logic

#### Concerns
- **HIGH: PID reuse not handled** — ProcessState keyed only by PID risks false "already injected" on rapid PID recycling
- **HIGH: Race between process exit and injection attempt** — stale entries may cause incorrect state transitions
- **MEDIUM: Authenticode extraction per process is expensive; may impact 500 ms SLA under load**
- **MEDIUM: PPL detection via GetProcessMitigationPolicy may fail on access-limited handles; unclear fallback behavior**
- **LOW: Glob matching for paths may be too permissive (operator-defined allowlist bypass risk)**
- **LOW: No explicit TTL or pruning strategy beyond cleanup_exited (memory growth under churn)**

#### Suggestions
- Key ProcessState by (PID + creation_time) or process start timestamp to avoid PID reuse bugs
- Add "ObservedStartTime" to ProcessState for ordering and deduplication
- Cache signer/cert_subject results per image path with TTL
- Explicitly handle GetProcessMitigationPolicy failure -> treat as "unknown" not "allowed"
- Add max size or LRU cleanup for registry to prevent unbounded growth
- Consider precomputing allowlist matchers (compiled glob set, normalized paths)

#### Risk Assessment
MEDIUM — Core is sound, but PID reuse + race conditions are correctness-critical for injection guarantees.

---

### 49-02 — Server-Side Allowlist (Wave 1)

#### Summary
Straightforward CRUD layer with appropriate validation and schema constraints. It integrates cleanly with the agent config model. The main risks are around expressiveness (path/cert matching ambiguity) and operational safety (bad allowlist entries weakening enforcement).

#### Strengths
- Clear schema with category constraint
- Separation via repository pattern
- JWT-protected admin API reuse
- Basic validation and test coverage included
- Index on category supports expected queries

#### Concerns
- **MEDIUM: No normalization of paths (case-insensitive Windows paths, symlinks, short paths)**
- **MEDIUM: cert_subject substring match is weak and spoofable**
- **MEDIUM: No precedence or conflict resolution between overlapping rules**
- **LOW: No audit trail beyond timestamps (who added/changed entries)**
- **LOW: No pagination/filtering on list_all (future scalability)**

#### Suggestions
- Normalize paths (GetFinalPathNameByHandleW-style canonicalization on agent side)
- Prefer full certificate thumbprint over subject substring
- Add rule priority or deterministic ordering guarantees
- Emit audit logs for create/update/delete actions
- Add optional "disabled" flag instead of hard delete for safer ops

#### Risk Assessment
LOW–MEDIUM — Functional but needs tightening for security correctness.

---

### 49-03 — ETW Watcher + Universal Injector (Wave 2)

#### Summary
This is the critical path and generally well-architected: ETW on a dedicated thread, bounded channel, async injector, and fallback mechanisms. It directly targets the 500 ms SLA. However, filtering strategy, backpressure handling, and injection reliability under load introduce real risk to coverage guarantees.

#### Strengths
- Correct separation: ETW (blocking) vs tokio (async injection)
- Bounded channel prevents unbounded memory growth
- Retry policy is simple and consistent with decisions (D-12)
- Startup sweep + periodic sweep cover missed events
- Explicit handling of AccessDenied -> PPL classification
- Parallel startup injection (rayon) aligns with 5s goal

#### Concerns
- **HIGH: Dropping events on full channel (drop-oldest) can violate 99% coverage SLA under burst load**
- **HIGH: ETW filter dropping System32/WinSxS may hide legitimate user processes (portable apps, side-loaded binaries)**
- **HIGH: No explicit latency measurement from ETW event -> injection completion (SLA not enforced/measured)**
- **MEDIUM: WMI backstop only on ETW unhealthy — but ETW can be "healthy" while silently dropping events**
- **MEDIUM: Injection retry policy (single retry) may be insufficient for transient race (process not fully initialized)**
- **MEDIUM: get_process_image_path via OpenProcess may fail frequently (permissions), impacting allowlist accuracy**
- **LOW: No CPU throttling or prioritization under high process churn**

#### Suggestions
- Track per-event timestamps and compute actual injection latency; emit histogram telemetry
- Replace drop-oldest with "drop + mark gap" and trigger immediate sweep when overflow occurs
- Reconsider ETW filtering — move filtering after allowlist check instead of path-based prefilter
- Add lightweight "delayed retry queue" (e.g., +200 ms) for processes that fail first injection
- Add heuristic: if OpenProcess fails -> still attempt injection unless explicitly skipped
- Periodically reconcile ETW counts vs injected counts to detect silent loss

#### Risk Assessment
HIGH — This phase determines success criteria. Event loss + filtering + retry limitations could break the 99%/500 ms guarantees.

---

### 49-04 — Config Wiring + Admin TUI (Wave 2)

#### Summary
Well-scoped integration layer connecting server allowlist to agent runtime and exposing operator controls. The design is conventional and low risk, but care is needed to avoid inconsistent state during config updates.

#### Strengths
- Clean config extension without overloading existing structures
- Poll-based update (30s) is simple and reliable
- TUI follows existing patterns -> consistency
- Full CRUD coverage in UI and client

#### Concerns
- **MEDIUM: 30s polling delay may be too slow for operational response (e.g., emergency allowlist)**
- **MEDIUM: No atomic swap of allowlist — race between update and injection decisions**
- **LOW: No validation feedback loop from agent (e.g., invalid glob patterns)**
- **LOW: No caching/versioning of config payloads**

#### Suggestions
- Use versioned config (etag/version field) and atomic replace in agent
- Allow manual "refresh now" trigger from TUI
- Validate allowlist entries on server before distribution
- Log config version applied in agent telemetry

#### Risk Assessment
LOW–MEDIUM — Mostly integration glue; correctness depends on atomicity and validation.

---

### 49-05 — Telemetry + Installer + Tests (Wave 3)

#### Summary
Completes the phase with observability and deployment support. Telemetry is useful but currently insufficient to prove SLA compliance. Installer work is pragmatic but touches sensitive registry areas that require strong safeguards.

#### Strengths
- Coverage metric aligns with success criteria
- Periodic cleanup and sweep reinforce resilience
- Installer backup/restore reduces risk of system breakage
- SIEM events provide visibility into failures

#### Concerns
- **HIGH: coverage_percent excludes timing dimension (500 ms SLA not measured)**
- **MEDIUM: Failed state cleanup may hide persistent issues (loss of forensic data)**
- **MEDIUM: AppInit registry modification is high-risk; no validation of DLL load success post-install**
- **MEDIUM: No integration tests simulating high process churn**
- **LOW: No per-category breakdown (PPL vs AV vs failures)**

#### Suggestions
- Add latency SLA metric: % injected within 500 ms
- Retain failed entries with capped history instead of full cleanup
- Add post-install verification step (spawn test process, confirm DLL load)
- Add stress test harness (spawn 1k short-lived processes)
- Emit richer telemetry: counts by reason, retry success rate

#### Risk Assessment
MEDIUM — Observability is close but not sufficient to validate guarantees.

---

## Overall Assessment (OpenCode)

### Summary
The plans are well-structured, logically decomposed, and aligned with the architecture decisions. The system design is realistic and avoids over-engineering. However, the hardest part — achieving reliable, low-latency universal injection under real-world load — is under-protected against edge cases like event loss, PID reuse, and transient injection failures.

### Key Cross-Cutting Risks
- Event loss (ETW + channel overflow) vs strict 99% coverage requirement
- Lack of end-to-end latency measurement for 500 ms SLA
- PID reuse and race conditions in process tracking
- Over-aggressive filtering before allowlist evaluation
- Weak allowlist matching (cert subject substring)

### Overall Risk Level
HIGH

The architecture is strong, but the guarantees (99% within 500 ms) are ambitious and currently not fully enforced or measured. Without tightening event handling, tracking correctness, and telemetry, the system may appear to work but fail under load or adversarial conditions.

---

## Consensus Summary

### Agreed Strengths

Both reviewers independently identified these strengths:

- **Wave ordering is sound.** Core infrastructure (registry, allowlist, AppInit) before integration (ETW, injector) before polish (telemetry, TUI, installer) is the right dependency structure.
- **ETW-on-dedicated-thread + bounded channel + tokio injector** is the correct architecture for keeping blocking kernel APIs off the async runtime.
- **Startup EnumProcesses sweep** correctly addresses the agent restart invariant.
- **Explicit skip categories** with visible logging directly satisfies BLOCK-6 success criterion.
- **Server-side CRUD + config poll** gives operators a no-restart path to extend allowlist entries.
- **Installer backup/restore** for AppInit registry is a necessary safety measure.

### Agreed Concerns

Concerns raised by BOTH reviewers (highest priority):

1. **HIGH: PID reuse and race conditions in process registry (49-01).** Both reviewers flagged that DashMap check-then-record is racy across ETW/WMI/sweep/periodic sweep. PID reuse without creation-time validation risks false "already injected" states. Consensus: needs atomic claim/transition or (PID + creation_time) composite key.

2. **HIGH: ETW System32/WinSxS pre-filter conflicts with coverage and visibility (49-03).** Both reviewers noted that dropping events at the ETW layer before allowlist evaluation means skipped processes may not be logged, and legitimate user processes from those paths would never be injected. Consensus: move filtering to after allowlist check, or document as deliberate gap and exclude from SLA denominator.

3. **HIGH: No concrete latency instrumentation for 500 ms SLA (49-03, 49-05).** Both reviewers independently identified that the plans describe injection but do not specify how ProcessStart -> injection -> DLL hello timestamps are correlated, measured, and reported. Consensus: add per-event latency pipeline with p50/p95/p99 and % under 500 ms.

4. **HIGH/MEDIUM: Authenticode signer extraction cost threatens 500 ms SLA (49-01).** Both reviewers flagged per-process cert validation as expensive under burst load. Consensus: cache signer results by image path/hash with TTL invalidation.

5. **MEDIUM: 30s config polling may be too slow for operational response (49-04).** Both reviewers noted that emergency allowlist updates taking up to 30s may be unacceptable during incident response. Consensus: consider push trigger or manual refresh from TUI.

6. **MEDIUM: PPL detection ambiguity / AccessDenied misclassification (49-01, 49-03).** Both reviewers flagged that collapsing all AccessDenied into PPL skip can mask ACL failures, EDR tampering, or privilege issues. Consensus: use explicit PPL classification outcomes instead of catch-all.

### Divergent Views

- **Codex flagged WMI always-on vs D-07 conditional activation as HIGH; OpenCode flagged it as MEDIUM** (focusing more on silent ETW event loss). Both agree WMI duplication is a risk but weight it differently. Worth investigating: does the plan's "subscription or polling fallback" language imply always-on or conditional?

- **OpenCode raised cert_subject substring spoofability as MEDIUM; Codex did not explicitly flag it** (focused more on schema expressiveness). Both agree stronger matching (thumbprint, canonicalization) is desirable but prioritize differently.

- **Codex raised AppInit x86/x64 registry coverage as MEDIUM; OpenCode did not explicitly flag it.** This is a Windows-specific gap that may only matter on mixed-architecture endpoints.

- **OpenCode suggested a delayed retry queue (+200ms); Codex did not.** This is a design alternative to the single 50ms retry — worth evaluating if transient PEB-not-ready failures are common.

---

*Review generated via cross-AI peer review. To incorporate feedback into planning: /gsd-plan-phase 49 --reviews*
