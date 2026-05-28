# Phase 55: Monitor-Only / Audit-Only Per-Policy Enforcement Mode - Context

**Gathered:** 2026-05-28
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 55 delivers a **per-policy enforcement mode** (`Audit`, `Block`, `AuditAndBlock`) so operators can safely roll out v0.10.0 in monitor-first mode, tune false positives, and only then enable blocking. A system-wide global toggle provides a single-flip convenience for initial deployment.

**What Phase 55 builds:**
1. **Policy schema extension** — `enforcement_mode: Audit | Block | AuditAndBlock` field on `Policy`, with `Block` as the serde default for backward compatibility.
2. **Global override** — `global_enforcement_mode` server config (`Audit | Block | PerPolicy`, default `PerPolicy`) that overrides all per-policy modes when not `PerPolicy`.
3. **Hook DLL awareness** — the hook evaluates policy, and if the effective mode is `Audit`, returns ALLOW while still emitting a full audit event (`policy_mode = Audit`, `would_have_denied = true`).
4. **DACL tripwire awareness** — the tripwire (Phase 52) only writes Deny ACEs for policies whose effective mode is `Block` or `AuditAndBlock`; `Audit` mode policies get no Deny ACE.
5. **Alert router awareness** — `DenyWithAlert` policies in `Audit` mode emit audit events at `info` severity to the alert router (SIEM still receives full event); `crit` alerts are suppressed during monitoring.
6. **Bypass alert independence** — ETW bypass alerts (Phase 53) emit at their mapped severity regardless of policy mode; a bypass is a real security event, not a policy-mode artifact.
7. **Conditions Builder TUI** — dropdown for `enforcement_mode` alongside the existing `PolicyMode` (ALL/ANY/NONE) composition dropdown.
8. **Integration tests** — round-trip `Audit → Block → AuditAndBlock` through `PUT /admin/policies/:id`, verified within one `policy_sync` cycle.

**What Phase 55 does NOT build:**
- Policy-level scheduling (e.g., "Audit during business hours, Block after hours") — deferred to operational efficiency phase
- Gradual rollout by percentage (e.g., "Audit for 10% of users") — deferred
- Automatic mode escalation based on time or event count — deferred
- Admin TUI screen dedicated to global enforcement mode management (a config form field is sufficient)

**Depends on:** Phases 48-50 (hook DLL must exist and observe mode); independent of 51-54
**Requirements:** MODE-01

</domain>

<decisions>
## Implementation Decisions

### DACL Tripwire in Monitor Mode
- **D-01:** The DACL tripwire follows the policy's effective enforcement mode. Audit mode policies get no Deny ACE written. Block and AuditAndBlock policies get Deny ACEs as normal. This makes monitor mode truly non-blocking, allowing operators to observe real-world behavior for tuning.

### Global Audit Toggle
- **D-02:** A system-wide `global_enforcement_mode` config field (default `PerPolicy`) with three values: `Audit`, `Block`, `PerPolicy`. When `Audit` or `Block`, it overrides every policy's individual `enforcement_mode`. When `PerPolicy`, each policy's own mode applies. This lives in the server-side operator config (SQLite) and syncs to agents via the existing `policy_sync` mechanism.

### Alert Suppression in Audit Mode
- **D-03:** Policies with `action = DenyWithAlert` in `Audit` mode still emit audit events but the alert router receives them at `info` severity instead of `crit`. SIEM relay receives the full event unchanged. This provides visibility without pager fatigue during monitoring.

### Bypass Alerts in Monitor Mode
- **D-04:** ETW bypass alerts (from Phase 53 correlator) emit at their full mapped severity regardless of policy mode. A bypass indicates a real evasion (syscall bypass, hook unloaded, etc.) and is independent of policy mode. In correctly-functioning Audit mode, the hook journal shows ALLOW, so no bypass alert is generated.

### Audit Event Fields
- **D-05:** The audit event for an Audit-mode violation carries two new fields: `policy_mode: "Audit"` and `would_have_denied: true`. These are added to the existing `AuditEvent` struct in `dlp-common/src/audit.rs` as optional fields with serde default.

### Conditions Builder TUI Placement
- **D-06:** The `enforcement_mode` dropdown is added as a new row in the Conditions Builder form, positioned after the `action` row and before the existing `PolicyMode` (ALL/ANY/NONE) composition row. Label: "Enforcement Mode". Values: Audit, Block, AuditAndBlock.

### Backward Compatibility
- **D-07:** Absent `enforcement_mode` in the database or JSON deserializes to `Block` via `#[serde(default = "Block")]`. Existing v0.9.0 policies continue blocking as before. The migration adds the column with `DEFAULT 'Block'`.

### Claude's Discretion
- The effective enforcement mode is computed as: `if global != PerPolicy { global } else { policy.enforcement_mode }`. This evaluation should happen in the ABAC engine's `evaluate()` method so both hook DLL and server-side code see the same effective mode.
- The `enforcement_mode` field should be stored in the `policies` SQLite table as a TEXT column with CHECK constraint (`CHECK(enforcement_mode IN ('Audit', 'Block', 'AuditAndBlock'))`).
- The agent config TOML should include a new `[enforcement]` section with `global_mode = "PerPolicy"` that mirrors the server-side config.
- The shared-memory classification cache (Phase 50) does NOT need to store enforcement mode; the hook DLL queries the effective mode via the existing policy evaluation path. Cache invalidation on policy change already handles this.
</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements & Architecture
- `.planning/ROADMAP.md` — Phase 55 goal, 4 success criteria, requirements MODE-01
- `.planning/PROJECT.md` — v0.10.0 milestone context, asymmetric fail semantics, minifilter ban
- `.planning/STATE.md` — Decision 4: asymmetric fail semantics; Decision 6: DACL tripwire design

### Prior Phase Context
- `.planning/phases/52-dacl-tripwire-repair-watcher-protected-paths-dpapi-recovery-/52-CONTEXT.md` — DACL tripwire architecture, repair watcher, staged updates, SDDL snapshots
- `.planning/phases/53-etw-kernel-file-consumer-bypass-correlator-hook-journal-ring/53-CONTEXT.md` — Bypass correlator, severity mapping, ETW consumer, journal ring buffer
- `.planning/phases/54-admin-tui-protected-paths-bypass-alerts-screens/54-CONTEXT.md` — Admin TUI screen patterns, Conditions Builder form layout
- `.planning/phases/50-shared-memory-classification-cache-fail-mode-state-machine/50-CONTEXT.md` — Shared-memory cache, fail-mode state machine, policy sync

### Existing Code Patterns
- `dlp-common/src/abac.rs` — `Policy` struct, `Decision` enum, `PolicyMode` enum (ALL/ANY/NONE). **Extend** `Policy` with `enforcement_mode` field. `Decision` enum already has ALLOW/DENY/AllowWithLog/DenyWithAlert.
- `dlp-common/src/audit.rs` — `AuditEvent` types. **Add** `policy_mode` and `would_have_denied` optional fields.
- `dlp-server/src/db/repositories/policies.rs` — `PolicyRow`, `PolicyRepository` CRUD. **Add** `enforcement_mode` column.
- `dlp-server/src/admin_api.rs` — `PolicyPayload`, `PolicyResponse`. **Extend** with `enforcement_mode`.
- `dlp-server/src/policy_store.rs` — In-memory policy cache. **Include** enforcement_mode in cache entries.
- `dlp-server/src/policy_sync.rs` — Agent config sync. **Add** `global_enforcement_mode` to sync payload.
- `dlp-agent/src/engine_client.rs` — Agent config parsing. **Parse** `[enforcement]` section.
- `dlp-agent/src/service.rs` — Agent startup. **Pass** effective mode to hook DLL via shared memory.
- `dlp-hook-dll/src/trampolines.rs` — File-I/O trampoline bodies. **Check** effective mode before returning ALLOW vs DENY.
- `dlp-admin-cli/src/app.rs` — `PolicyFormState`, `Screen::ConditionsBuilder`. **Add** `enforcement_mode` field.
- `dlp-admin-cli/src/screens/dispatch.rs` — Policy form dispatch handlers, `policy_mode_to_wire`. **Add** `enforcement_mode_to_wire` and form wiring.
- `dlp-admin-cli/src/screens/render.rs` — Policy form render functions. **Add** `format_enforcement_mode_field`.

### Code Conventions
- `.planning/codebase/CONVENTIONS.md` — Rust coding standards, naming, error handling
- `.planning/codebase/STRUCTURE.md` — Workspace module organization

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`Policy` struct** (`dlp-common/src/abac.rs`): Already has `action: Decision`, `mode: PolicyMode` (ALL/ANY/NONE), `enabled: bool`. Add `enforcement_mode: EnforcementMode` as a new field. Use `#[serde(default)]` for backward compatibility.
- **`Decision` enum** (`dlp-common/src/abac.rs`): Four variants (ALLOW, DENY, AllowWithLog, DenyWithAlert). In Audit mode, the physical return is ALLOW regardless of Decision, but the audit event records what the Decision would have been.
- **`PolicyFormState`** (`dlp-admin-cli/src/app.rs`): Existing form struct for the Conditions Builder. Add `enforcement_mode: EnforcementMode` field.
- **`EngineClient`** (`dlp-admin-cli/src/client.rs`): HTTP client for admin API calls. Add `update_policy_enforcement_mode` or extend existing `update_policy`.
- **Shared-memory classification cache** (`dlp-hook-dll/src/classification_cache.rs`): Stores `path → classification` mappings. Enforcement mode evaluation happens in the policy engine, not the cache, so no cache changes needed.
- **`PolicyStore`** (`dlp-server/src/policy_store.rs`): In-memory cache of policies. Already refreshes every 5 minutes. Enforcement mode will be included in cached policy entries.

### Established Patterns
- **Repository pattern**: `PolicyRepository` in `dlp-server/src/db/repositories/policies.rs` with `list`, `get_by_id`, `create`, `update`, `delete`. Add `enforcement_mode` to `PolicyRow` and `PolicyUpdateRow`.
- **Admin API CRUD**: `GET /admin/policies`, `POST /admin/policies`, `PUT /admin/policies/:id`, `DELETE /admin/policies/:id`. Extend `PolicyPayload` with `enforcement_mode`.
- **Agent config TOML poll**: 30s cadence, hash-based reload. New `[enforcement]` section with `global_mode`.
- **SIEM audit events**: `siem_connector::relay(audit_event)` for structured audit logging. Audit events gain `policy_mode` and `would_have_denied` fields.
- **Alert router**: `alert_router::send_alert(event)` for email/webhook. Severity is downgraded to `info` for Audit-mode DenyWithAlert policies.
- **Migration pattern**: `dlp-server/src/db/mod.rs` `run_migrations()` with incremental ALTER TABLE. Add `enforcement_mode` column with `DEFAULT 'Block'`.

### Integration Points
- `dlp-common/src/abac.rs` — Add `EnforcementMode` enum; extend `Policy` struct.
- `dlp-common/src/audit.rs` — Add `policy_mode` and `would_have_denied` to `AuditEvent`.
- `dlp-server/src/db/mod.rs` — Migration: add `enforcement_mode` to `policies` table.
- `dlp-server/src/db/repositories/policies.rs` — Include `enforcement_mode` in CRUD operations.
- `dlp-server/src/policy_store.rs` — Cache enforcement_mode with policy entries.
- `dlp-server/src/admin_api.rs` — Accept and return `enforcement_mode` in policy payloads.
- `dlp-server/src/policy_sync.rs` — Include `global_enforcement_mode` in agent config payload.
- `dlp-agent/src/engine_client.rs` — Parse `[enforcement]` section from TOML.
- `dlp-agent/src/service.rs` — Compute effective mode, pass to evaluation context.
- `dlp-hook-dll/src/trampolines.rs` — Check effective mode: Audit → return ALLOW after audit.
- `dlp-admin-cli/src/app.rs` — Add `EnforcementMode` enum, add field to `PolicyFormState`.
- `dlp-admin-cli/src/screens/dispatch.rs` — Wire enforcement_mode in form submit and edit flows.
- `dlp-admin-cli/src/screens/render.rs` — Render enforcement_mode dropdown in Conditions Builder.
</code_context>

<specifics>
## Specific Ideas

- The `EnforcementMode` enum should have three variants: `Audit`, `Block`, `AuditAndBlock`. Use `#[derive(Default)]` with `Block` as default for backward compatibility.
- The `global_enforcement_mode` should live in the same operator config SQLite table as other system settings (like SMTP, SIEM, alert config), not in a new table. Reuse the existing key-value config pattern.
- The admin TUI should display the effective mode (global override applied) in the PolicyList screen, perhaps as a suffix like " (Audit)" or " [GLOBAL: Audit]" when the global override is active.
- When `global_enforcement_mode` is not `PerPolicy`, the Conditions Builder should show a banner or note indicating that per-policy mode is currently overridden. This prevents operator confusion.
- The audit event for an Audit-mode violation should include the original `Decision` value (e.g., `would_have_been: "DENY"`) so operators can see what would have happened.
- For the integration test, create a policy with `enforcement_mode = Audit`, trigger a violation, verify the file operation succeeds, and verify the audit event contains `would_have_denied = true`.
- The `policy_sync` response should include both the per-policy `enforcement_mode` and the `global_enforcement_mode` so the agent can compute the effective mode locally without extra round-trips.
</specifics>

<deferred>
## Deferred Ideas

- Policy-level scheduling (time-based mode switching) — deferred to operational efficiency phase
- Gradual rollout by percentage or user group — deferred to pilot expansion phase
- Automatic mode escalation based on violation count or time in Audit — deferred
- Dedicated admin TUI screen for global enforcement mode management — unnecessary; config form field is sufficient
- Machine-learning-based recommendation for when to switch from Audit to Block — deferred to post-v1.0

</deferred>

---

*Phase: 55-Monitor-Only / Audit-Only Per-Policy Enforcement Mode*
*Context gathered: 2026-05-28*
