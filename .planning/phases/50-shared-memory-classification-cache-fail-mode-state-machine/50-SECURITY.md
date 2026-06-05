---
phase: 50
slug: shared-memory-classification-cache-fail-mode-state-machine
status: verified
threats_open: 0
asvs_level: 1
created: 2026-06-05
---

# Phase 50 — Security

> Shared-Memory Classification Cache + Fail-Mode State Machine
> Per-phase security contract: threat register, accepted risks, and audit trail.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| Agent (SYSTEM) -> Shared Memory | Agent writes; all other processes read-only | ClassificationCache ABI (128-byte header, prefix/hash tables) |
| Shared Memory -> Hook DLLs | DLLs map read-only; Windows enforces at MMU level | FILE_MAP_READ mapping; validated via magic/checksum/bounds |
| DLL -> Agent pipe | Untrusted input crosses; bincode deserialization must not panic | HookRequest/HookResponse via IpcEnvelope V1 |
| Agent -> DLL pipe | Trusted output; DLL validates all fields before use | CacheHint (tier + TTL), cache_version |
| DLL -> Hooked Process | Cache lookup inside safe wrappers; malformed cache must not crash | Decision (Allow/Deny) with fallback to pipe |
| Hardcoded allowlist -> DLL | Static arrays compiled into DLL; cannot be modified at runtime | System path prefixes, build-tool basenames |
| Operator allowlist -> Shared Memory | Agent writes; DLL reads only; validated like cache header | AllowlistEntry entries in SHM region |
| Telemetry -> Pipe | Aggregated only; no sensitive path data in telemetry | Latency histogram buckets, hit/miss counters |

---

## Threat Register

| Threat ID | Category | Component | Disposition | Mitigation | Status |
|-----------|----------|-----------|-------------|------------|--------|
| T-50-01 | Tampering | HookRequest deserialization | mitigate | serde(default) on all new fields; IpcEnvelope enum for versioned evolution | closed |
| T-50-02 | Information Disclosure | CacheHint in HookResponse | accept | Tier-only (T1-T4), no sensitive policy details | closed |
| T-50-03 | Denial of Service | Bincode deserialization of malformed pipe data | mitigate | Length limits on strings; bounded types; catch deserialization errors; unknown variants trigger degraded behavior | closed |
| T-50-04 | Tampering | Malicious process writes to shared memory | mitigate | FILE_MAP_READ only for DLLs; SYSTEM-only write ACL | closed |
| T-50-05 | Information Disclosure | Classification metadata leaked via AU read | mitigate | Security descriptor: BA read only (not AU); classification is tier-only | closed |
| T-50-06 | Denial of Service | Cache overflow causes agent crash | mitigate | Priority truncation on overflow; graceful fallback to pipe-only | closed |
| T-50-07 | Elevation of Privilege | Namespace squatting on Global\DlpClassificationCache | mitigate | Agent creates mapping before hooks load; verify owner on open | closed |
| T-50-08 | Tampering | Malicious process modifies shared memory | mitigate | FILE_MAP_READ only; Windows MMU enforces write protection | closed |
| T-50-09 | Tampering | DLL reads partially-written cache during flip | mitigate | Acquire load on version_word; split validation (full on version change, cheap per lookup) | closed |
| T-50-10 | Denial of Service | Malformed cache causes DLL crash | mitigate | Bounds-check all offsets/counts; validate magic/checksum; SEH wrapper | closed |
| T-50-11 | Information Disclosure | Cache hint leaks classification via LRU | accept | LRU is thread-local; classification tier only (T1-T4) | closed |
| T-50-12 | Elevation of Privilege | Path normalization bypass (8.3, volume GUID, ADS) | mitigate | Reject 8.3 names, volume GUIDs, ADS, trailing dots/spaces; canonicalize paths; longest-prefix matching | closed |
| T-50-13 | Denial of Service | Rapid state oscillation | mitigate | Debounced transitions; hysteresis via failure/success counters | closed |
| T-50-14 | Tampering | Spoofed pipe success during ISOLATED | mitigate | Require BOTH pipe success AND fresh cache version AND full validation | closed |
| T-50-15 | Information Disclosure | Telemetry leaks process list | accept | Telemetry includes only current process image path, not full process list | closed |
| T-50-16 | Denial of Service | Background thread consumes CPU when healthy | mitigate | Thread only polls when ISOLATED/RESYNC; 100ms wait reduces CPU to near-zero | closed |
| T-50-17 | Elevation of Privilege | Rename attack on build tool | mitigate | Full-path validation (basename + parent dir + signer) | closed |
| T-50-18 | Tampering | Operator allowlist spoofed | mitigate | Shared-memory read-only mapping; header validation; bounds checking | closed |
| T-50-19 | Denial of Service | Telemetry every 1000 calls causes pipe congestion | mitigate | Aggregated counters only; 1000-call batching; state transitions emitted separately | closed |
| T-50-20 | Information Disclosure | Telemetry reveals cache hit patterns | accept | Aggregated histogram only; no per-path data | closed |
| T-50-21 | Denial of Service | Benchmark runs exhaust shared memory | mitigate | Tests use small fixed-size mappings; cleanup after each test | closed |
| T-50-22 | Information Disclosure | Benchmark prints classified path examples | mitigate | Benchmark uses synthetic paths only (e.g., C:\Test\File.txt) | closed |
| T-50-23 | Tampering | Malformed bincode in integration test | mitigate | Tests use serialize->deserialize round-trip; no untrusted input | closed |
| T-50-24 | Tampering | Bincode field reordering breaks compatibility | mitigate | IpcEnvelope enum with stable discriminants; pinned bincode config; golden fixtures verify compatibility | closed |
| T-50-25 | Denial of Service | Unknown protocol version causes failure loop | mitigate | negotiate_protocol returns error triggering pipe-only fallback; no retry loop on mismatch | closed |
| T-50-26 | Tampering | Corrupt cache header causes agent crash | mitigate | Bounds-check all offsets/counts; validate magic/checksum; fuzz tests for malformed headers | closed |
| T-50-27 | Information Disclosure | Reserved header fields leak memory | mitigate | Reserved fields zeroed on initialization; not read by DLL | closed |
| T-50-28 | Elevation of Privilege | Symlink/junction bypass | mitigate | Force pipe fallback for reparse points, symlinks, junctions; conservative approach | closed |
| T-50-29 | Elevation of Privilege | Hash collision produces false positive | mitigate | 64-bit FNV-1a + byte verification on hash match eliminates collision ambiguity | closed |
| T-50-30 | Denial of Service | RESYNC exit too fast causes flapping | mitigate | Hysteresis requires 5 consecutive successes before HEALTHY | closed |
| T-50-31 | Tampering | In-flight decisions during RESYNC bypass policy | mitigate | In-flight decisions use old cache (consistent); new decisions use new cache | closed |
| T-50-32 | Elevation of Privilege | Build tool in user-writable directory | mitigate | is_user_writable_directory check denies allowlist for user-writable paths | closed |
| T-50-33 | Elevation of Privilege | Unsigned binary matches build tool name | mitigate | WinVerifyTrust code-signer validation against TRUSTED_SIGNERS (stubbed; conservative deny fallback) | closed |
| T-50-34 | Information Disclosure | Allowlist audit logs leak paths | accept | Audit logs contain normalized paths only; necessary for compliance | closed |
| T-50-35 | Elevation of Privilege | Adversarial path bypass in tests | mitigate | Tests verify pipe fallback for all bypass attempts | closed |
| T-50-36 | Tampering | Corrupt SHM causes test crash | mitigate | Tests verify graceful handling of corrupt headers | closed |

*Status: closed — all 36 plan-time threats have verified mitigations or documented acceptance.*
*Disposition: mitigate (implementation required) · accept (documented risk) · transfer (third-party)*

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| R-50-01 | T-50-02 | CacheHint contains classification tier only (T1-T4), not sensitive policy details. Tier is necessary for cache warming and is not confidential in itself. | Plan-time | 2026-05-20 |
| R-50-02 | T-50-11 | LRU is thread-local (per-thread, not shared). Classification tier only (T1-T4) is leaked; no path or policy content. | Plan-time | 2026-05-20 |
| R-50-03 | T-50-15 | Telemetry includes only current process image path for context, not a full process list enumeration. Process image path is standard Windows logging data. | Plan-time | 2026-05-20 |
| R-50-04 | T-50-20 | Telemetry is aggregated histogram buckets only; no per-path or per-file data. Hit/miss counters are totals, not per-operation. | Plan-time | 2026-05-20 |
| R-50-05 | T-50-34 | Audit logs contain normalized paths for compliance and forensics. Path normalization removes ADS and bypass attempts before logging. | Plan-time | 2026-05-20 |

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-06-05 | 36 | 36 | 0 | gsd-security-auditor (phase-50 verification) |

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-06-05
