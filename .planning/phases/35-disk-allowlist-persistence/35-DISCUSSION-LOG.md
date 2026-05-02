# Phase 35: Disk Allowlist Persistence — Discussion Log

**Date:** 2026-05-03
**Status:** Complete — CONTEXT.md written

---

## Areas Selected

User selected all 4 gray areas: Write trigger, Disconnected disk policy, Encryption fields persistence, Allowlist cache design.

---

## Area 1: Write trigger

| Question | Options | Selected |
|----------|---------|----------|
| When should the agent write the allowlist to TOML? | After enumeration only / After encryption check too / On every status change | After enumeration only |
| On subsequent restarts, when do we write if new disks appear? | Immediately after merge / Only if new disks were added | Immediately after merge |
| Use AgentConfig::save() or dedicated writer? | Same AgentConfig::save() / Dedicated allowlist writer | Same AgentConfig::save() |
| How to pass AgentConfig to the enumeration task? | Arc<RwLock<AgentConfig>> / Clone at task spawn | Arc<RwLock<AgentConfig>> |

**Decisions locked:**
- Write after enumeration succeeds (encryption fields = None at this point)
- Immediate TOML write on merge — no defer-to-shutdown
- Reuse AgentConfig::save() — add disk_allowlist field to struct
- AgentConfig wrapped as Arc<RwLock<AgentConfig>> and passed to task

---

## Area 2: Disconnected disk policy

| Question | Options | Selected |
|----------|---------|----------|
| Disk in TOML but not found by enumeration? | Keep it / Remove it / Keep + flag in TOML | Keep it |
| Disk found by both TOML and enumeration — which wins? | Fresh enumeration wins / TOML version wins | Fresh enumeration wins |

**Decisions locked:**
- Allowlist is additive — absent disks stay in allowlist until admin removes them (Phase 37/38)
- Live enumeration data replaces TOML snapshot for present disks

---

## Area 3: Encryption fields persistence

| Question | Options | Selected |
|----------|---------|----------|
| What to persist to [[disk_allowlist]] in TOML? | Full DiskIdentity / Identity-only subset / Full minus timestamps | Full DiskIdentity |
| Re-write TOML after Phase 34 startup encryption check? | No — leave TOML as-is / Yes — re-write after check | No — leave TOML as-is |

**Decisions locked:**
- Full DiskIdentity serialized (skip_serializing_if handles None fields cleanly)
- TOML is enumeration identity snapshot; Phase 34 updates in-memory only

---

## Area 4: Allowlist cache design

| Question | Options | Selected |
|----------|---------|----------|
| Where should the in-memory allowlist live? | Inside DiskEnumerator / New DiskAllowlist singleton | Inside DiskEnumerator |
| When is enumeration_complete set to true? | Only after live enumeration / After TOML load | Only after live enumeration |
| One unified map or separate allowlist field? | No — unified map / Yes — separate field | No — unified map |

**Decisions locked:**
- DiskEnumerator.instance_id_map IS the allowlist (no new singleton)
- enumeration_complete only set true after live enumeration succeeds
- One unified map: TOML-loaded + live entries, absent entries persist in map

---

## User freeform input

> "tell me what information will be contained in DiskIdentity struct?"

Answered inline: full DiskIdentity field list with Phase 33 (instance_id, bus_type, model, drive_letter, serial, size_bytes, is_boot_disk) and Phase 34 additions (encryption_status, encryption_method, encryption_checked_at).

---

## Deferred Ideas

- TOML re-write after Phase 34 encryption re-checks
- Diff-gate on TOML write (skip if no changes)
- Separate disk-allowlist.toml file
- DiskAllowlist new singleton
- `absent = true` flag on disconnected TOML entries
- Admin removal of disks from allowlist (Phase 37/38)

---

*Generated: 2026-05-03*
