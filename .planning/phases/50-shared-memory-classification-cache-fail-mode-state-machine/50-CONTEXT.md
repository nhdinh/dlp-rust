# Phase 50: Shared-Memory Classification Cache + Fail-Mode State Machine - Context

**Gathered:** 2026-05-20
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 50 gives the hook DLL a survivable sub-50us hot path and a tier-gated asymmetric fail policy. It builds:

1. **Shared-memory classification cache** (`Global\DlpClassificationCache`, 2 MiB, double-buffered, atomic version flip) created and owned by the agent; populated from server-pushed classification deltas and policy_store changes.
2. **Two-tier cache layout** — root-prefix table (first tier) for fast directory-level classification + per-file FNV-1a hash table (second tier) for explicit overrides.
3. **Fail-mode state machine** — HEALTHY -> DEGRADED -> ISOLATED -> RESYNC with tier-gated asymmetric fail-closed/fail-open behavior.
4. **Trusted-path allowlist** — hardcoded common paths (System32, WinSxS, build tools) + operator-extended entries via shared memory.
5. **Per-tier staleness budgets** — T4=30s, T3=60s, T2=5min, T1=30min enforced on every cache lookup.
6. **RESYNC protocol** — pipe message triggers RESYNC in HEALTHY/DEGRADED; background thread polls atomic version in ISOLATED.

**Phase 50 does NOT build:**
- ntdll syscall-stub patching (Phase 51)
- DACL tripwire (Phase 52)
- ETW bypass detection (Phase 53)
- Admin TUI screens (Phase 54)

**Depends on:** Phase 49 (universal injection must be working; hook DLL must be loaded in processes)
**Requirements:** CACHE-01, CACHE-02, CACHE-03, CACHE-04, CACHE-05, CACHE-06, FAIL-01, FAIL-02, FAIL-03

</domain>

<decisions>
## Implementation Decisions

### Cache Layout and Lookup
- **D-01:** Two-tier structure: root-prefix table (first tier) + per-file hash table (second tier). The root-prefix table handles the majority of enterprise deployments where whole directories share one classification. The per-file hash table handles explicit overrides.
- **D-02:** Root-prefix matching uses longest-prefix wins. Prefixes are sorted by length (longest first). On lookup, try longest to shortest; first match wins. Natural for overlapping hierarchies (e.g., `C:\SecretDocs\* -> T2` but `C:\SecretDocs\Finance\* -> T4`).
- **D-03:** Per-file hash table uses FNV-1a 64-bit with open addressing and 8-byte hash verification. Fast, simple, well-understood pattern. Standard, well-understood pattern. 8-byte hash stored per entry for verification to handle collisions.
- **D-04:** Double-buffered version flip uses atomic u64: high 63 bits = monotonic version number, low bit = which buffer (0 or 1) is active. Agent increments version, writes to inactive buffer, then flips the bit atomically. DLLs read the atomic once to get both version and buffer index. No ABA risk with monotonic version.

### Fail-Mode Transition Triggers
- **D-05:** HEALTHY -> DEGRADED: 3 consecutive named-pipe round-trip failures (ConnectionRefused, Timeout, or Malformed). Simple, deterministic, matches requirement literally.
- **D-06:** DEGRADED -> ISOLATED: 10 consecutive pipe failures OR cache version older than the maximum tier TTL (T4=30s). Ties ISOLATED to both pipe health and cache freshness — even if pipe works, stale cache means isolated.
- **D-07:** ISOLATED -> RESYNC: successful pipe round-trip AND cache version in shared memory is greater than what the DLL last saw. Ensures the DLL only transitions to RESYNC when it has fresh data, not just a working pipe.
- **D-08:** DEGRADED behavior: uses cache for decisions but retries pipe every 10th call. ISOLATED behavior: cache-only, no pipe attempts. Clear separation — DEGRADED is "struggling but functional", ISOLATED is "on my own".

### Cache Warming and Allowlist Delivery
- **D-09:** Hybrid allowlist: common paths (System32, WinSxS, WindowsApps, Program Files\Common Files, devenv.exe, cargo.exe, msbuild.exe, rustc.exe, link.exe, gcc.exe) are hardcoded in the DLL as static arrays. Operator extensions flow through a separate shared-memory region.
- **D-10:** Operator-extended allowlist entries stored in a dedicated 64 KiB shared-memory region as a flat array of path prefixes. The DLL checks allowlist before touching the classification cache. Cleaner separation, no mixing of concerns.
- **D-11:** Cache warmup: agent pre-populates all registered T3/T4 Protected Path roots at startup. Everything else is lazy on first pipe request — the agent classifies the path and pushes a CacheDelta. Balanced approach.
- **D-12:** TTL enforcement: the DLL checks the entry's `ttl_bits` against `cache_version_seen_at` on every lookup. If expired, falls through to the pipe (in HEALTHY/DEGRADED) or fail-mode decision (in ISOLATED). Most accurate, ensures stale data is never served.

### RESYNC Protocol and Version Polling
- **D-13:** RESYNC detection (HEALTHY/DEGRADED path): when the agent recovers, it sends a `HookMessage::CacheDelta` through the pipe to each connected DLL. The message includes the new version. Fastest transition.
- **D-14:** ISOLATED-state RESYNC: a lightweight background thread in the DLL polls the atomic version word every 100ms. When version changes -> RESYNC. This is the ISOLATED-state detection path; pipe message is the HEALTHY/DEGRADED path.
- **D-15:** In-flight decisions during RESYNC: allowed to complete using the old cache. New decisions use the new cache. No blocking, no latency spike. Brief inconsistent window acceptable for cache update.
- **D-16:** CacheDelta push: agent only updates the shared-memory version word (atomic flip). No pipe broadcast needed for cache updates. DLLs detect the change via their background polling or next hook-call atomic read.

### Claude's Discretion
- FNV-1a 64-bit chosen over Wyhash for simplicity and proven correctness in this domain.
- Atomic u64 version word (vs separate atomics) chosen for single-read simplicity and no torn-read risk.
- DEGRADED uses cache + periodic pipe retry (vs still using pipe primarily) to reduce load on struggling agent.
- Separate allowlist array (vs same structure as cache) for cleaner separation of concerns.
- DLL checks TTL on every lookup for correctness over micro-optimization.
- Background thread for ISOLATED-state detection (vs periodic pipe probe) to respect isolation semantics.
- Allow in-flight decisions during RESYNC for zero-latency-spike transitions.
- Shared memory atomic flip only for cache updates — no pipe broadcast — because maintaining a connected-client list adds complexity without benefit.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements & Architecture
- `.planning/REQUIREMENTS.md` -- CACHE-01..06, FAIL-01..03 requirements
- `.planning/ROADMAP.md` -- Phase 50 goal and success criteria
- `.planning/PROJECT.md` -- v0.10.0 milestone context, asymmetric fail semantics decision
- `.planning/STATE.md` -- Recent decisions including shared-memory cache and fail-mode state machine

### Existing Code Patterns
- `dlp-hook-dll/src/lib.rs` -- Current hook DLL with IAT patching, 11 trampolines, `HOOKS` table. **MUST extend** with shared-memory cache lookup before pipe round-trip.
- `dlp-hook-dll/src/pipe_client.rs` -- Named-pipe client with thread-local 4KiB buffer. **Reuse** for pipe communication; add fail-mode bypass when cache hit.
- `dlp-hook-dll/src/crash_guard.rs` -- SEH + catch_unwind wrappers. **Reuse** — cache lookup happens inside the guard boundary.
- `dlp-hook-dll/src/fail_closed.rs` -- Fail-closed return value generation. **Reuse** — ISOLATED state uses same return values.
- `dlp-common/src/classification.rs` -- `Classification` enum with `is_sensitive()` method. **Reuse** for tier-gated fail decisions.
- `dlp-common/src/hook_ipc.rs` -- `HookRequest`, `HookResponse`, `HandleHookRequest` types. **Extend** with `cache_version`, `cache_hint` fields.
- `dlp-agent/src/service.rs` -- Agent service lifecycle. **Add** shared-memory cache initialization and CacheDelta push logic.
- `dlp-agent/src/hook_injector.rs` -- `HookInjector` with architecture detection. **Reuse** — Phase 50 does not change injection.

### Related Phase Context
- `.planning/phases/48-hook-dll-surface-expansion-crash-hardening-build-harness/48-CONTEXT.md` -- Hook DLL architecture decisions (D-01..D-21)
- `.planning/phases/49-universal-injection-etw-process-watcher-allowlist-appinit-fa/49-CONTEXT.md` -- Universal injection decisions (D-01..D-20), process registry pattern

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`HOOKS` table** (`dlp-hook-dll/src/lib.rs`): Metadata-driven IAT patching. Extend each `HookDescriptor` with a pre-pipe cache lookup call.
- **`pipe_client::send_request`** (`dlp-hook-dll/src/pipe_client.rs`): Thread-local 4KiB buffer, bincode framing. Wrap with cache-check-then-fallback pattern.
- **`Classification::is_sensitive()`** (`dlp-common/src/classification.rs`): Already distinguishes T3/T4 (sensitive) from T1/T2. Directly drives asymmetric fail decisions.
- **Agent config polling** (`dlp-agent/src/engine_client.rs`): 30s TOML poll with hash-based reload. Extend to include `[classification_cache]` section with staleness budgets.
- **`DashMap<u32, ProcessState>`** (Phase 49): Process registry pattern. Reuse for tracking which PIDs have which cache version.

### Established Patterns
- **Thread-local pre-allocated buffer**: `RefCell<Vec<u8>>` in `thread_local!()`. Cache lookup should not allocate — use stack-allocated path buffers.
- **Fail-closed returns**: `BOOL(0)`, `INVALID_HANDLE_VALUE`, `NTSTATUS(STATUS_ACCESS_DENIED)`. ISOLATED state for T3/T4 uses same returns.
- **Double-buffered atomic flip**: Pattern from game engines and lock-free data structures. Version word + buffer index bit is standard.
- **Longest-prefix matching**: Standard routing table / filesystem ACL pattern. Sort by length descending, stop at first match.

### Integration Points
- `dlp-hook-dll/src/lib.rs` -- Add `DllMain` shared-memory mapping (`OpenFileMappingW` + `MapViewOfFile`) after self-allowlist gate.
- `dlp-hook-dll/src/trampolines.rs` -- Add cache lookup before `pipe_client::send_request` in each trampoline.
- `dlp-agent/src/service.rs` -- Add `ClassificationCache` initialization, `CacheDelta` push on policy change, background cache maintenance thread.
- `dlp-agent/src/lib.rs` -- Add `classification_cache.rs` module.
- `dlp-common/src/hook_ipc.rs` -- Extend `HookRequest` with `cache_version: u64`, `HookResponse` with `cache_hint: Option<(PathBuf, Tier, ttl_secs)>`.
- `dlp-server/src/policy_sync.rs` -- Trigger `CacheDelta` push when policy changes.

</code_context>

<specifics>
## Specific Ideas

- The 2 MiB shared memory should be split: ~1.8 MiB for classification cache (double-buffered = two 900 KiB buffers), ~128 KiB for root-prefix table, ~64 KiB for allowlist array. Exact sizes tuned during implementation.
- Root-prefix table entries: `(prefix_len: u16, prefix_bytes: [u8; 260], tier: u8, ttl_secs: u16)`. 260 bytes = MAX_PATH in UTF-8. Entry size ~270 bytes = ~480 entries in 128 KiB.
- Per-file hash table: `(hash: u64, tier: u8, ttl_bits: u16)` = 11 bytes per entry. With 64-byte alignment = 64 bytes per slot. ~14K slots per 900 KiB buffer.
- The DLL's background thread for ISOLATED-state RESYNC detection should use `WaitForSingleObject` on a 100ms timer, not a busy loop.
- Cache hint in `HookResponse`: when the agent classifies a path not in cache, it returns the classification + TTL so the DLL can warm its own thread-local LRU (128 entries) and optionally push to the global cache via the next pipe message.
- The `cache_version` in `HookRequest` lets the agent detect stale DLLs and proactively push a CacheDelta.
- Fail-mode telemetry: emit `siem.fail_mode_transition` events with `old_state`, `new_state`, `reason` (e.g., "3_consecutive_pipe_failures", "cache_stale_T4").
</specifics>

<deferred>
## Deferred Ideas

- ntdll syscall-stub patching (Phase 51 -- BLOCK-08, BLOCK-09)
- DACL tripwire (Phase 52 -- DACL-01..05)
- ETW Kernel-File consumer for bypass detection (Phase 53 -- ETW-01..05)
- Admin TUI Protected Paths screen (Phase 54 -- UX-01)
- Admin TUI Bypass Alerts screen (Phase 54 -- UX-02)
- Monitor-only / audit-only per-policy mode (Phase 55 -- MODE-01)
- SD/optical/virtual drive enumeration (Phase 56 -- DRIVE-01..04)
- Deployment guide with per-vendor AV/EDR allowlist procedures (Phase 57 -- OPS-01..04)

</deferred>

---

*Phase: 50-shared-memory-classification-cache-fail-mode-state-machine*
*Context gathered: 2026-05-20*
