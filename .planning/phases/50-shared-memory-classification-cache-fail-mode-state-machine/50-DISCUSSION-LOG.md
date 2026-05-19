# Phase 50: Shared-Memory Classification Cache + Fail-Mode State Machine - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-20
**Phase:** 50-Shared-Memory Classification Cache + Fail-Mode State Machine
**Areas discussed:** Cache layout and lookup, Fail-mode transition triggers, Cache warming and allowlist delivery, RESYNC protocol and version polling

---

## Cache layout and lookup

| Option | Description | Selected |
|--------|-------------|----------|
| Open-addressing hash table | Fixed-size slots with linear probing. Fast O(1) but needs tombstones on delta updates. | |
| Flat sorted array + binary search | No collisions, no tombstones. O(log n) — acceptable for small n. | |
| Two-tier: root-prefix table + per-file hash table | Root-prefix for directory-level + hash table for explicit overrides. Matches FAIL-02 naturally. | ✓ |

**User's choice:** Two-tier: root-prefix table + per-file hash table
**Notes:** User chose this after explanation. Natural fit for the fail-mode root-prefix fallback requirement.

---

## Root-prefix matching

| Option | Description | Selected |
|--------|-------------|----------|
| Longest-prefix wins | Sort prefixes by length (longest first). First match wins. Natural for overlapping hierarchies. | ✓ |
| Explicit priority order | Each prefix carries numeric priority. Must scan entire table. | |
| First-match in insertion order | Fastest but can produce surprising results with overlapping prefixes. | |

**User's choice:** Longest-prefix wins
**Notes:** User chose after explanation. Standard routing table / filesystem ACL pattern.

---

## Per-file hash table

| Option | Description | Selected |
|--------|-------------|----------|
| FNV-1a 64-bit + open addressing | Fast, simple, well-understood. 8-byte hash verification. | ✓ (Claude discretion) |
| Wyhash 64-bit + open addressing | Faster on modern CPUs but more complex implementation. | |
| You decide | Claude picks based on performance/correctness. | |

**User's choice:** You decide
**Notes:** Claude selected FNV-1a for simplicity and proven correctness.

---

## Double-buffered version flip

| Option | Description | Selected |
|--------|-------------|----------|
| Atomic u64 version word + buffer index bit | 63-bit monotonic version + 1-bit active buffer. Single atomic read. | ✓ (Claude discretion) |
| Separate version atomic + active-buffer atomic | Two atomics, needs careful ordering to avoid torn reads. | |
| You decide | Claude picks based on correctness/simplicity. | |

**User's choice:** You decide
**Notes:** Claude selected atomic u64 for single-read simplicity and no ABA risk.

---

## Fail-mode transition triggers

### HEALTHY → DEGRADED

| Option | Description | Selected |
|--------|-------------|----------|
| 3 consecutive pipe failures | Simple, deterministic, matches requirement literally. | ✓ (Claude discretion) |
| 3 failures within 5 seconds | Sliding window avoids false transitions from transient blips. | |
| You decide | Claude picks based on tradeoffs. | |

**User's choice:** You decide
**Notes:** Claude selected 3 consecutive failures for deterministic simplicity.

---

### DEGRADED → ISOLATED

| Option | Description | Selected |
|--------|-------------|----------|
| 10 consecutive pipe failures | Simple, deterministic. | |
| 10 failures OR cache stale | Ties ISOLATED to both pipe health and cache freshness. | ✓ (Claude discretion) |
| You decide | Claude picks based on tradeoffs. | |

**User's choice:** You decide
**Notes:** Claude selected the hybrid for robustness — stale cache is as bad as no pipe.

---

### ISOLATED → RESYNC

| Option | Description | Selected |
|--------|-------------|----------|
| Pipe recovered + higher cache version | Ensures fresh data, not just working pipe. | ✓ (Claude discretion) |
| Pipe recovered only | Simpler but could RESYNC into stale data. | |
| You decide | Claude picks based on tradeoffs. | |

**User's choice:** You decide
**Notes:** Claude selected pipe + version for data freshness guarantee.

---

### DEGRADED vs ISOLATED behavior

| Option | Description | Selected |
|--------|-------------|----------|
| DEGRADED still uses pipe; ISOLATED cache-only | Clear separation. | |
| DEGRADED uses cache + periodic pipe retry; ISOLATED cache-only | More proactive recovery in DEGRADED. | ✓ (Claude discretion) |
| You decide | Claude picks based on tradeoffs. | |

**User's choice:** You decide
**Notes:** Claude selected cache + periodic retry for faster recovery detection.

---

## Cache warming and allowlist delivery

### Allowlist source

| Option | Description | Selected |
|--------|-------------|----------|
| Hardcoded in DLL binary | Zero lookup overhead, works before agent connection. | |
| Fully via shared memory | Flexible but requires agent connection first. | |
| Hybrid: hardcoded common + operator-extended via shared memory | Best of both. | ✓ |

**User's choice:** Hybrid: hardcoded common + operator-extended via shared memory
**Notes:** User explicitly chose hybrid after seeing all options.

---

### Allowlist structure in shared memory

| Option | Description | Selected |
|--------|-------------|----------|
| Same as cache entries | One data structure for everything. | |
| Separate allowlist array in shared memory | Cleaner separation, dedicated 64 KiB region. | ✓ (Claude discretion) |
| You decide | Claude picks based on simplicity/performance. | |

**User's choice:** You decide
**Notes:** Claude selected separate array for cleaner separation of concerns.

---

### Cache warmup strategy

| Option | Description | Selected |
|--------|-------------|----------|
| Full policy store scan | Most complete but potentially large startup cost. | |
| Lazy on first pipe request | Zero startup cost but first accesses slow. | |
| Hybrid: policy roots + lazy | Pre-populate T3/T4 roots, everything else lazy. | ✓ |

**User's choice:** Hybrid: policy roots + lazy
**Notes:** User explicitly chose hybrid. Balanced approach.

---

### TTL enforcement

| Option | Description | Selected |
|--------|-------------|----------|
| DLL checks TTL on every lookup | Most accurate, ensures no stale data served. | ✓ (Claude discretion) |
| DLL ignores TTL in healthy state | Reduces lookup overhead but serves stale data. | |
| You decide | Claude picks based on correctness/performance. | |

**User's choice:** You decide
**Notes:** Claude selected check-every-lookup for correctness over micro-optimization.

---

## RESYNC protocol and version polling

### RESYNC detection (HEALTHY/DEGRADED)

| Option | Description | Selected |
|--------|-------------|----------|
| Atomic poll on every hook call | Simplest, no extra threads. Adds one atomic read per call. | |
| Background thread polling | Zero hook-path overhead but 100ms latency. | |
| Pipe message triggers RESYNC | Fastest transition, requires working pipe. | ✓ |

**User's choice:** Pipe message triggers RESYNC
**Notes:** User explicitly chose pipe message. Fastest transition when agent recovers.

---

### ISOLATED-state RESYNC detection

| Option | Description | Selected |
|--------|-------------|----------|
| Periodic pipe probe in ISOLATED | Sacrifices isolation for faster recovery. | |
| Background thread polls atomic version | Respects isolation, 100ms detection latency. | ✓ (Claude discretion) |
| You decide | Claude picks based on tradeoffs. | |

**User's choice:** You decide
**Notes:** Claude selected background thread to respect ISOLATED semantics.

---

### In-flight decisions during RESYNC

| Option | Description | Selected |
|--------|-------------|----------|
| Allow in-flight decisions | No blocking, no latency spike. Brief inconsistent window. | ✓ (Claude discretion) |
| Block until RESYNC complete | Consistent but adds latency during swap. | |
| You decide | Claude picks based on tradeoffs. | |

**User's choice:** You decide
**Notes:** Claude selected allow in-flight for zero-latency-spike transitions.

---

### CacheDelta push mechanism

| Option | Description | Selected |
|--------|-------------|----------|
| Broadcast via pipe | Reliable but sequential, 100 DLLs = 100 sends. | |
| Shared memory atomic flip only | No pipe broadcast, DLLs detect via polling. | ✓ (Claude discretion) |
| Claude picks based on tradeoffs | | |

**User's choice:** Claude picks based on the tradeoffs.
**Notes:** Claude selected atomic flip only. Simpler, no client-list maintenance.

---

## Claude's Discretion

The following areas were delegated to Claude's discretion:

1. **Hash function**: FNV-1a 64-bit selected for simplicity and proven correctness.
2. **Version flip structure**: Atomic u64 (63-bit version + 1-bit buffer index) for single-read simplicity.
3. **DEGRADED behavior**: Cache + periodic pipe retry every 10th call.
4. **Allowlist structure**: Separate 64 KiB shared-memory array.
5. **TTL enforcement**: Check on every lookup for correctness.
6. **ISOLATED-state detection**: Background thread polling atomic version every 100ms.
7. **In-flight during RESYNC**: Allow to complete with old cache.
8. **CacheDelta push**: Shared memory atomic flip only.

## Deferred Ideas

None — discussion stayed within phase scope.

---

*Phase: 50-Shared-Memory Classification Cache + Fail-Mode State Machine*
*Discussion completed: 2026-05-20*
