# Phase 53 Discussion Log

**Date:** 2026-05-27
**Mode:** `--auto` (autonomous decision selection)
**Phase:** 53 — ETW Kernel-File Consumer + Bypass Correlator + Hook Journal Ring

---

## Gray Areas Identified and Resolved

### Area 1: Journal Ring Lifecycle and Discovery
**Q:** Who creates the hook journal shared memory? How does the agent discover it? Who cleans up?
**Options:**
1. Agent pre-creates journals for all processes (race-prone, doesn't know when DLL loads)
2. Hook DLL creates lazily on first write; agent discovers via ProcessWatcher; agent cleans up on exit
3. Hybrid: agent creates on injection, DLL just maps

**[auto] Selected:** Option 2 — Hook DLL lazy creation, agent discovers via ProcessWatcher, 5s grace-period cleanup. Matches existing shared-memory cache pattern and avoids injection-time races.

### Area 2: Correlation Key (FILE_OBJECT vs HANDLE vs Path)
**Q:** ETW events provide FILE_OBJECT pointers; hook DLL receives HANDLEs. What is the correlation key?
**Options:**
1. Use FILE_OBJECT and resolve from HANDLE via NtQuerySystemInformation (expensive, complex)
2. Use HANDLE value as proxy (unreliable across kernel/user boundary)
3. Correlate by (pid, path_hash, op, ts_qpc) — path is the stable semantic identifier

**[auto] Selected:** Option 3 — Path-hash correlation. FNV-1a 64-bit of normalized path. Same normalization as classification cache. FILE_OBJECT stored for forensics only.

### Area 3: Severity Mapping
**Q:** How do correlation reasons map to severity levels?
**Options:**
1. Fixed mapping by reason only
2. Dynamic mapping by reason + path sensitivity (protected path vs not)
3. Dynamic mapping by reason + tier + operation type

**[auto] Selected:** Option 2 — Fixed mapping with protected path awareness: NoHookJournal on protected path = crit, NoHookJournal elsewhere = warn, OpMismatch = warn, HookOverwritten = crit, PatchRaced = info. crit triggers alert router; warn/info go to SIEM only.

### Area 4: Agent-Side Allowlist for Pre-Correlation Filtering
**Q:** How does the agent know which PIDs to drop before correlation?
**Options:**
1. Agent maintains separate allowlist config (duplication, drift risk)
2. Agent reads the same Global\DlpAllowlistCache shared memory as the hook DLL
3. Agent gets allowlist from server on each policy_sync

**[auto] Selected:** Option 2 — Reuse shared-memory allowlist cache. Re-reads every 30s. Plus hardcoded emergency filter for system-critical processes (System, Registry, smss, csrss, lsass).

### Area 5: ETW Consumer Enable Gate
**Q:** Should the ETW consumer always run, or be gated by a feature flag?
**Options:**
1. Always run (produces alerts even during rollout, may alarm operators)
2. Gated by enable_ntdll_patching flag (simplifies operator rollout)
3. Separate enable_etw_correlator flag (maximum control, more config complexity)

**[auto] Selected:** Option 2 — Reuse enable_ntdll_patching flag. When off, correlator runs in reduced mode (info-only alerts, no alert router triggers). One flag controls both ntdll patching and bypass detection.

---

## Decisions Summary

| ID | Decision | Rationale |
|---|---|---|
| D-01 | DLL lazy-creates journal shared memory | Avoids injection-time races, matches cache pattern |
| D-02 | Agent discovers journals via ProcessWatcher | Reuses existing process creation event stream |
| D-03 | 5-second cleanup grace period on exit | Captures trailing ETW events without handle leaks |
| D-04 | 64 KiB ring, 48-byte entries, ~1365 slots | Bounded, single-producer single-consumer |
| D-05 | Correlation by (pid, path_hash, op, ts_qpc) | Path is stable semantic ID across user/kernel |
| D-06 | FNV-1a 64-bit path hash | Reuses classification cache normalization and hashing |
| D-07 | op as compact enum (Create/Write/Delete/SetInfo) | Efficient, maps from ETW opcode + keyword |
| D-08 | +/-5 ms QPC tolerance | ROADMAP spec, tuned for low false-negative rate |
| D-09 | Best-effort correlation, false negatives primary concern | Detection is defense-in-depth, not enforcement |
| D-10 | Fixed severity mapping with protected path awareness | Clear operator semantics, crit triggers alert router |
| D-11 | crit -> alert_router + SIEM; warn/info -> SIEM only | Matches existing DENY_WITH_ALERT pattern |
| D-12 | Agent reads shared-memory allowlist cache | Zero config drift, same source as hook DLL |
| D-13 | Pre-correlation PID filtering with 60s TTL | Reduces noise, handles PID reuse |
| D-14 | Hardcoded emergency filter for system processes | Prevents system-critical process flooding |
| D-15 | ETW consumer mirrors ProcessWatcher architecture | Proven pattern, consistent codebase |
| D-16 | Consumer-side System32/WinSxS path filter | ETW layer too coarse for path filtering |
| D-17 | Lost-event monitoring as test verification | Not runtime alert; tuning feedback only |
| D-18 | enable_ntdll_patching gates ETW consumer | Simplifies operator rollout |
| D-19 | POST /audit/bypass with batch of 100 alerts | Reduces server load and network overhead |
| D-20 | GET /admin/bypass-alerts with since/severity/ack/limit/offset | Standard paginated admin API pattern |
| D-21 | POST /admin/bypass-alerts/:id/ack with idempotent semantics | Operator UX, safe to retry |
| D-22 | bypass_alerts schema matches ARCHITECTURE.md exactly | Single source of truth, no drift |
| D-23 | Journal write BEFORE returning decision | Guarantees denials are journaled |
| D-24 | Release/Acquire synchronization via write_index | Correct for SPSC ring buffer |
| D-25 | Silent continue on journal creation failure | Fail-safe: degraded detection beats crash |

---

## Deferred Ideas

- Admin TUI Bypass Alerts screen → Phase 54 (UX-02)
- Admin TUI Protected Paths screen → Phase 54 (UX-01)
- Monitor-only / audit-only mode awareness → Phase 55 (MODE-01)
- SD/optical/virtual drive volume-class filtering → Phase 56 (DRIVE-01..04)
- Automatic remediation of bypassed operations → post-v0.10.0
- ML-based false-positive suppression → post-v0.10.0
- Real-time bypass alert WebSocket streaming → post-v0.10.0

---

*Auto-generated discussion log for Phase 53*
