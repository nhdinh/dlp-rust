# Phase 58: Differentiators Bundle (Override + Diagnostic + Hash Evidence + Self-Health) - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-06-02
**Phase:** 58-Differentiators Bundle (Override + Diagnostic + Hash Evidence + Self-Health)
**Areas discussed:** Override Flow, Diagnostic Mode, Content Hash Evidence, Self-Health Dashboard
**Mode:** --auto (all gray areas auto-selected with recommended defaults)

---

## Override Flow (DIFF-01)

| Option | Description | Selected |
|--------|-------------|----------|
| Reuse Phase 61 approval workflow | Leverage existing approvals table, JWT tokens, approval cache, and TUI screen | ✓ |
| Build new override-specific schema | Create separate `overrides` table and API — more complex, duplicates approval logic | |
| Simple in-memory override (no server) | Agent-local override with no admin approval — insufficient for enterprise audit | |

**Auto-selected:** Reuse Phase 61 approval workflow
**Notes:** Existing infrastructure (`ApprovalCache`, `show_override_dialog`, `POST /admin/approvals`) covers all requirements. Hook DLL deny path wires to existing dialog → existing API → existing cache. TTL defaults to 1 hour (existing `valid_until` field), max 24 hours at API boundary.

---

## Diagnostic Mode (DIFF-02)

| Option | Description | Selected |
|--------|-------------|----------|
| In-memory ring buffer, admin TUI only | Hook DLL captures 1000-entry ring, agent polls every 30s, admin TUI displays | ✓ |
| Persisted to SQLite with long retention | Store diagnostic snapshots in DB for historical analysis — higher overhead, deferred | |
| User-facing diagnostic screen | Self-service false-positive triage in dlp-user-ui — out of scope for v0.10.0 | |

**Auto-selected:** In-memory ring buffer, admin TUI only
**Notes:** Ring buffer uses `crossbeam::queue::ArrayQueue` for lock-free multi-thread writes. 1000 entries ~1MB per process. 1-hour lazy expiry. Agent polls via named pipe. Admin TUI follows existing `BypassAlertList` pattern with detail popup.

---

## Content Hash Evidence (DIFF-03)

| Option | Description | Selected |
|--------|-------------|----------|
| SHA-256 from write buffer, blocked only, 100MB cap | Hash `lpBuffer` directly in trampoline; cap at 100MB; only for DENY | ✓ |
| SHA-256 for all writes (ALLOW + DENY) | Complete audit trail but significant hot-path overhead | |
| SHA-512 for higher assurance | Stronger hash but ~2x compute cost; deferred | |
| Read-back from file handle after write | Requires second open/seek/read — more accurate but much slower | |

**Auto-selected:** SHA-256 from write buffer, blocked only, 100MB cap
**Notes:** Compute happens on a 2-thread `rayon` pool inside hook DLL (lazy `OnceLock` init) to avoid blocking the hooked thread. If pool saturated, skip hash and set `hash_skipped: true`. `hash_truncated: true` when 100MB cap hit. Hash forwarded via `AuditEvent.content_sha256` through SIEM unchanged.

---

## Self-Health Dashboard (DIFF-04)

| Option | Description | Selected |
|--------|-------------|----------|
| Agent polls hooks every 60s, in-memory history, auto-alert on degraded | Extend `perf_telemetry.rs` with health counters; 5-min trend sparkline; thresholds: 80% cache hit rate | ✓ |
| Hooks push telemetry continuously | Lower latency but higher pipe overhead and hook DLL complexity | |
| Persist health history to SQLite | Enables long-term trending but adds DB write overhead in agent | |
| Fleet-wide aggregation | Cross-endpoint health view — deferred to v0.11.0+ | |

**Auto-selected:** Agent polls hooks every 60s, in-memory history, auto-alert on degraded
**Notes:** Health counters: injected_pids, patched_modules, pipe_round_trips_60s, cache_hit_rate_60s, current_fail_state. Thresholds: Healthy (hit_rate >= 80% + fail_state == Healthy), Degraded (hit_rate < 80% OR fail_state == Degraded), Critical (fail_state == Isolated OR 0 pipe_round_trips). Auto-alert after 2 consecutive degraded polls (2 minutes). Admin TUI uses `ratatui::Sparkline` for 5-min trend.

---

## Claude's Discretion

- Diagnostic ring buffer: `crossbeam::queue::ArrayQueue` for lock-free writes
- Hash thread pool: 2-thread `rayon` pool inside hook DLL, lazy `OnceLock` init
- Health counter wire format: `HookHealthSnapshot` (~64 bytes, `bincode` serialized)
- Diagnostic API filters: `since`, `user_sid`, `policy_id` for targeted triage
- Self-health dashboard read-only — no restart/re-inject actions from TUI

## Deferred Ideas

- User-facing diagnostic screen (self-service false-positive triage) — deferred to operational efficiency phase
- Cross-endpoint health aggregation — deferred to v0.11.0+ fleet management
- Automated agent restart/re-injection from TUI — deferred; manual per deployment guide
- Content hashing for ALLOW decisions — deferred; blocked-only for v0.10.0
- SHA-512 hash option — deferred; SHA-256 sufficient for v0.10.0
- Diagnostic data persistence to SQLite/SIEM long-term — deferred; in-memory only
- ML-based false-positive prediction from diagnostics — deferred to post-v1.0
