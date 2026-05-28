# Phase 55: Monitor-Only / Audit-Only Per-Policy Enforcement Mode - Research

**Researched:** 2026-05-28
**Domain:** Rust enterprise DLP — per-policy enforcement mode with global override
**Confidence:** HIGH

## Summary

Phase 55 introduces a three-state `EnforcementMode` (`Audit`, `Block`, `AuditAndBlock`) on every policy, plus a system-wide `global_enforcement_mode` override (`Audit`, `Block`, `PerPolicy`). This is the industry-standard safe-rollout pattern used by Forcepoint, Symantec DLP, and Microsoft Purview. The effective mode is computed as `if global != PerPolicy { global } else { policy.enforcement_mode }`.

The implementation touches 13 files across 5 workspace crates. The core challenge is ensuring the **same effective mode is visible to both the server-side ABAC evaluator and the agent-side hook DLL**, while keeping the shared-memory classification cache (Phase 50) unchanged — enforcement mode lives in the policy evaluation path, not the cache.

**Primary recommendation:** Compute effective mode in `PolicyStore::evaluate()` (server) and in the agent's `run_event_loop` / hook IPC handler (agent). Return the original `Decision` plus the effective `EnforcementMode` in `EvaluateResponse` so the agent can emit `would_have_denied = true` audit events. The hook DLL receives the final decision (ALLOW for Audit mode) via the existing `HookResponse::decision` field — no protocol changes needed.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Policy schema + storage | API / Backend | — | SQLite is source of truth; admin API owns CRUD |
| Effective mode computation | API / Backend | Agent (mirror) | `PolicyStore::evaluate()` computes it; agent mirrors for hook DLL |
| Hook DLL decision override | Agent (hook DLL) | — | Hook DLL receives final decision from agent; no mode awareness needed in DLL |
| DACL tripwire mode-awareness | Agent (service) | — | Tripwire writer reads effective mode from agent config |
| Alert severity downgrade | API / Backend | — | `AlertRouter::send_alert()` checks `policy_mode` on `AuditEvent` |
| Audit event enrichment | Agent (service) | — | `emit_audit()` adds `policy_mode` + `would_have_denied` |
| Global config sync | API / Backend | Agent | Server pushes `global_enforcement_mode` via existing policy sync |
| Admin TUI mode picker | Browser / Client | — | `dlp-admin-cli` Conditions Builder adds dropdown |

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `serde` | 1.0 | JSON/TOML serialization of `EnforcementMode` | Already used throughout workspace |
| `rusqlite` | 0.32 | SQLite `enforcement_mode` column + migrations | Existing DB layer |
| `tokio` | 1.4 | Async runtime for config poll loop | Already used in agent |
| `ratatui` | 0.29 | Admin TUI dropdown rendering | Already used in `dlp-admin-cli` |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `serde_json` | 1.0 | Wire format for `EvaluateResponse` with new fields | Admin API + agent HTTP |
| `toml` | 0.8 | Agent config TOML parse for `[enforcement]` section | Agent config load |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `EnforcementMode` enum in `dlp-common` | Per-crate enum + conversion fns | Duplication; single shared enum is cleaner |
| Global mode in `system_kv` table | New dedicated table | `system_kv` already exists; no schema growth needed |

**Installation:** No new external packages required — all dependencies already in workspace `Cargo.toml` files.

## Package Legitimacy Audit

> No new external packages are required for this phase. All functionality uses existing workspace dependencies.

## Architecture Patterns

### System Architecture Diagram

```text
                    Admin TUI (dlp-admin-cli)
                           |
                           v
              POST/PUT /admin/policies/:id
                           |
                    +-------------+
                    | dlp-server  |
                    |  admin_api  |
                    +-------------+
                           |
          +----------------+----------------+
          |                                 |
          v                                 v
   +-------------+                  +-------------+
   | PolicyStore |                  | system_kv   |
   | (evaluate)  |                  | (global_mode)|
   +-------------+                  +-------------+
          |                                 |
          v                                 v
   EvaluateResponse                policy_sync payload
   {decision,                      {policies[],
    matched_policy_id,             global_enforcement_mode}
    enforcement_mode,              |
    would_have_denied}             v
                           +-------------+
                           | dlp-agent   |
                           |  (service)  |
                           +-------------+
                                  |
                    +-------------+-------------+
                    |                           |
                    v                           v
           +-------------+             +-------------+
           | Hook DLL    |             | DACL        |
           | trampolines |             | tripwire    |
           | (receives   |             | (reads mode |
           |  final dec) |             |  from agent)|
           +-------------+             +-------------+
                    |
                    v
           AuditEvent emitted
           {policy_mode, would_have_denied}
                    |
        +-----------+-----------+
        |                       |
        v                       v
   +---------+           +---------+
   | SIEM    |           | Alert   |
   | relay   |           | router  |
   | (full)  |           | (info   |
   |         |           |  for    |
   |         |           |  Audit) |
   +---------+           +---------+
```

### Recommended Project Structure

No new modules required. Changes are additive to existing files:

```
dlp-common/src/
  abac.rs          # + EnforcementMode enum, + Policy.enforcement_mode
  audit.rs         # + policy_mode, + would_have_denied

dlp-server/src/
  db/mod.rs        # + migration for enforcement_mode column
  db/repositories/
    policies.rs    # + enforcement_mode in PolicyRow/PolicyUpdateRow
  policy_store.rs  # + effective mode computation in evaluate()
  admin_api.rs     # + enforcement_mode in PolicyPayload/PolicyResponse
  policy_sync.rs   # + global_enforcement_mode in agent config payload
  alert_router.rs  # + severity downgrade for Audit mode

dlp-agent/src/
  config.rs        # + [enforcement] section with global_mode
  server_client.rs # + global_enforcement_mode in AgentConfigPayload
  service.rs       # + apply global_mode from payload
  interception/mod.rs  # + effective mode in run_event_loop
  audit_emitter.rs # + policy_mode, would_have_denied fields

dlp-admin-cli/src/
  app.rs           # + EnforcementMode, + PolicyFormState.enforcement_mode
  screens/dispatch.rs  # + enforcement_mode wiring
  screens/render.rs    # + format_enforcement_mode_field
```

### Pattern 1: Effective Mode Computation
**What:** Compute `if global != PerPolicy { global } else { policy.enforcement_mode }` at the evaluation boundary.
**When to use:** Both server-side `PolicyStore::evaluate()` and agent-side event loop.
**Example:**
```rust
// Source: dlp-server/src/policy_store.rs (existing evaluate() method)
// After Phase 55 modification:
pub fn evaluate(
    &self,
    ctx: &AbacContext,
    label_service: Option<&LabelService>,
    label_aware_enabled: bool,
    global_mode: EnforcementMode, // NEW parameter
) -> EvaluateResponse {
    // ... existing label-aware evaluation ...

    for policy in cache.iter() {
        if !policy.enabled {
            continue;
        }
        let conditions_match = match policy.mode {
            // ... existing condition matching ...
        };
        if conditions_match {
            let effective_mode = if global_mode != EnforcementMode::PerPolicy {
                global_mode
            } else {
                policy.enforcement_mode
            };

            let (decision, would_have_denied) = match effective_mode {
                EnforcementMode::Audit => {
                    // In Audit mode, physical return is ALLOW regardless of policy.action
                    (Decision::ALLOW, policy.action.is_denied())
                }
                EnforcementMode::Block => {
                    (policy.action, false)
                }
                EnforcementMode::AuditAndBlock => {
                    // Same as Block but audit event records AuditAndBlock mode
                    (policy.action, false)
                }
            };

            return EvaluateResponse {
                decision,
                matched_policy_id: Some(policy.id.clone()),
                reason: format!("matched policy '{}' (mode: {:?})", policy.name, effective_mode),
                enforcement_mode: Some(effective_mode), // NEW field
                would_have_denied,                      // NEW field
            };
        }
    }
    // ... default-deny fallback ...
}
```

### Pattern 2: Audit Event Enrichment
**What:** Add `policy_mode` and `would_have_denied` to `AuditEvent` when the agent processes an evaluation response.
**When to use:** In the agent's `run_event_loop` after receiving `EvaluateResponse`.
**Example:**
```rust
// Source: dlp-agent/src/interception/mod.rs (run_event_loop)
let response = offline.evaluate(&request).await;

let event_type = match response.decision {
    Decision::ALLOW | Decision::AllowWithLog => EventType::Access,
    Decision::DENY => EventType::Block,
    Decision::DenyWithAlert => EventType::Alert,
};

let mut audit_event = AuditEvent::new(
    event_type,
    user_sid.clone(),
    user_name.clone(),
    path.clone(),
    classification,
    abac_action,
    response.decision,
    ctx.agent_id.clone(),
    ctx.session_id,
)
.with_access_context(AuditAccessContext::Local)
.with_policy(
    response.matched_policy_id.unwrap_or_default(),
    response.reason.clone(),
);

// NEW: Phase 55 audit enrichment
if let Some(mode) = response.enforcement_mode {
    audit_event.policy_mode = Some(mode.to_string());
}
audit_event.would_have_denied = response.would_have_denied;

emit_audit(&ctx, &mut audit_event);
```

### Pattern 3: Alert Severity Downgrade
**What:** When `policy_mode == Audit` and `event_type == Alert` (from DenyWithAlert), downgrade severity to `info` before sending to alert router.
**When to use:** In `AlertRouter::send_alert()` or at the call site before `send_alert()`.
**Example:**
```rust
// Source: dlp-server/src/alert_router.rs
pub async fn send_alert(&self, event: &AuditEvent) -> Result<(), AlertError> {
    let mut event = event.clone();

    // Phase 55: Downgrade severity for Audit-mode DenyWithAlert policies
    if event.event_type == EventType::Alert
        && event.policy_mode.as_deref() == Some("Audit")
    {
        event.severity = Some("info".to_string());
        tracing::info!(
            policy_id = %event.policy_id.as_deref().unwrap_or("unknown"),
            "alert severity downgraded to info (Audit mode)"
        );
    }

    let row = self.load_config()?;
    // ... rest of existing send_alert logic ...
}
```

### Anti-Patterns to Avoid
- **Do NOT put enforcement mode in the shared-memory cache:** The cache stores `path -> classification` only. Mode is a policy attribute, not a classification attribute. Putting it in the cache would require cache schema changes and complicate invalidation.
- **Do NOT make the hook DLL mode-aware:** The hook DLL should receive the final decision (ALLOW for Audit mode) from the agent via the existing `HookResponse::decision` field. Adding mode awareness to the DLL increases complexity in the injected process.
- **Do NOT store global mode in a new table:** Use the existing `system_kv` table (key = `global_enforcement_mode`, value = `"Audit"|"Block"|"PerPolicy"`).

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Enum serialization | Custom serde impls | `#[derive(Serialize, Deserialize)]` with `#[serde(rename_all = "PascalCase")]` | Standard, maintainable, handles JSON/TOML uniformly |
| Config migration | One-off scripts | `run_alter()` in `db/mod.rs` | Idempotent, safe for fresh + existing DBs |
| Global config storage | New dedicated table | `system_kv` (existing) | Already has single-row semantics, no schema growth |
| TUI dropdown | Custom widget | ratatui `List` with stateful selection | Existing pattern in Conditions Builder |

## Runtime State Inventory

> This phase is NOT a rename/refactor/migration. It adds new fields and behavior. No runtime state inventory needed.

## Common Pitfalls

### Pitfall 1: Hook DLL Still Denies in Audit Mode
**What goes wrong:** The agent returns the raw `Decision::DENY` from `PolicyStore::evaluate()` to the hook DLL, causing file operations to be blocked even in Audit mode.
**Why it happens:** The agent's IPC handler doesn't apply the effective mode override before returning the decision to the DLL.
**How to avoid:** Apply effective mode in the agent's `run_event_loop` or in a dedicated `evaluate_with_mode()` wrapper. The `HookResponse::decision` must be `ALLOW` when effective mode is `Audit`.
**Warning signs:** Integration test fails — file write succeeds in Block mode but fails in Audit mode.

### Pitfall 2: DACL Tripwire Writes Deny ACE in Audit Mode
**What goes wrong:** The DACL tripwire applies Deny ACEs for all policies, including Audit mode policies, making monitor mode effectively blocking at the kernel level.
**Why it happens:** The tripwire writer doesn't check the policy's effective enforcement mode before writing the ACE.
**How to avoid:** Filter the protected paths list by effective mode before passing to the tripwire writer. Only include paths for policies whose effective mode is `Block` or `AuditAndBlock`.
**Warning signs:** File operations blocked on protected paths even when all policies are in Audit mode.

### Pitfall 3: Alert Router Still Pages in Audit Mode
**What goes wrong:** `DenyWithAlert` policies in Audit mode trigger `crit` severity alerts, causing pager fatigue during monitoring.
**Why it happens:** The alert router doesn't check the `policy_mode` field on the audit event before routing.
**How to avoid:** Downgrade severity to `info` in `AlertRouter::send_alert()` when `policy_mode == "Audit"` and `event_type == Alert`.
**Warning signs:** SMTP/webhook alerts fired during integration test with Audit-mode policy.

### Pitfall 4: Backward Compatibility Break
**What goes wrong:** Existing v0.9.0 policies without `enforcement_mode` fail to deserialize or default to `Audit` (non-blocking), breaking production deployments.
**Why it happens:** Missing `#[serde(default)]` or wrong default variant.
**How to avoid:** Use `#[serde(default = "EnforcementMode::default")]` with `Block` as the default variant. Add DB migration with `DEFAULT 'Block'`.
**Warning signs:** Policies loaded from DB have `enforcement_mode = Audit` after upgrade.

### Pitfall 5: Global Override Not Synced to Agents
**What goes wrong:** Server sets global mode to `Audit`, but agents continue evaluating in `PerPolicy` mode because the global mode isn't in the sync payload.
**Why it happens:** `AgentConfigPayload` doesn't include `global_enforcement_mode`, or the agent doesn't apply it.
**How to avoid:** Add `global_enforcement_mode` to `AgentConfigPayload` (server) and `AgentConfig` (agent). Apply it in `apply_payload_to_config()`.
**Warning signs:** Agent-side behavior differs from server-side behavior for same policy set.

## Code Examples

### EnforcementMode Enum (dlp-common/src/abac.rs)
```rust
/// Per-policy enforcement mode.
///
/// - `Audit`: log violations but always allow the operation.
/// - `Block`: enforce the policy action (DENY/DenyWithAlert).
/// - `AuditAndBlock`: enforce AND emit audit event with mode annotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub enum EnforcementMode {
    /// Monitor mode — observe without blocking.
    Audit,
    /// Default — enforce policy action.
    #[default]
    Block,
    /// Enforce with explicit audit annotation.
    AuditAndBlock,
}
```

### Policy Struct Extension (dlp-common/src/abac.rs)
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub priority: u32,
    pub conditions: Vec<PolicyCondition>,
    pub action: Decision,
    pub enabled: bool,
    #[serde(default)]
    pub mode: PolicyMode,
    /// Phase 55: Per-policy enforcement mode.
    #[serde(default)]
    pub enforcement_mode: EnforcementMode,
    pub version: u64,
}
```

### EvaluateResponse Extension (dlp-common/src/abac.rs)
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateResponse {
    pub decision: Decision,
    pub matched_policy_id: Option<String>,
    pub reason: String,
    /// Phase 55: Effective enforcement mode that produced this decision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforcement_mode: Option<EnforcementMode>,
    /// Phase 55: True if the policy would have denied but mode was Audit.
    #[serde(default)]
    pub would_have_denied: bool,
}
```

### AuditEvent Extension (dlp-common/src/audit.rs)
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    // ... existing fields ...

    /// Phase 55: Effective enforcement mode ("Audit", "Block", "AuditAndBlock").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_mode: Option<String>,

    /// Phase 55: True if the policy would have denied but was in Audit mode.
    #[serde(default)]
    pub would_have_denied: bool,
}
```

### DB Migration (dlp-server/src/db/mod.rs)
```rust
pub fn run_migrations(conn: &SqliteConn) -> anyhow::Result<()> {
    // ... existing migrations ...

    // Phase 55: Per-policy enforcement mode.
    run_alter(
        conn,
        "ALTER TABLE policies ADD COLUMN enforcement_mode TEXT NOT NULL DEFAULT 'Block' CHECK(enforcement_mode IN ('Audit', 'Block', 'AuditAndBlock'))",
        "enforcement_mode",
        "policies",
    )?;

    // Phase 55: Global enforcement mode in system_kv.
    conn.execute(
        "INSERT OR IGNORE INTO system_kv (key, value) VALUES ('global_enforcement_mode', 'PerPolicy')",
        [],
    )?;

    Ok(())
}
```

### PolicyRow Extension (dlp-server/src/db/repositories/policies.rs)
```rust
#[derive(Debug, Clone)]
pub struct PolicyRow {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub priority: i64,
    pub conditions: String,
    pub action: String,
    pub enabled: i64,
    pub mode: String,
    /// Phase 55: Enforcement mode.
    pub enforcement_mode: String,
    pub version: i64,
    pub updated_at: String,
}
```

### deserialize_policy_row Extension (dlp-server/src/policy_store.rs)
```rust
fn deserialize_policy_row(
    row: &crate::db::repositories::policies::PolicyRow,
) -> Result<Policy, serde_json::Error> {
    // ... existing action/mode parsing ...

    let enforcement_mode = match row.enforcement_mode.to_lowercase().as_str() {
        "audit" => EnforcementMode::Audit,
        "block" => EnforcementMode::Block,
        "auditandblock" => EnforcementMode::AuditAndBlock,
        _ => EnforcementMode::Block, // defensive fallback
    };

    Ok(Policy {
        // ... existing fields ...
        enforcement_mode,
        // ...
    })
}
```

### Agent Config Extension (dlp-agent/src/config.rs)
```rust
/// Phase 55: Global enforcement mode override.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct EnforcementConfig {
    /// Global mode override: "Audit", "Block", or "PerPolicy".
    #[serde(default)]
    pub global_mode: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AgentConfig {
    // ... existing fields ...

    /// Phase 55: Enforcement mode configuration.
    #[serde(default)]
    pub enforcement: EnforcementConfig,
}
```

### AgentConfigPayload Extension (dlp-agent/src/server_client.rs)
```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentConfigPayload {
    // ... existing fields ...

    /// Phase 55: Global enforcement mode override from server.
    #[serde(default = "default_global_enforcement_mode")]
    pub global_enforcement_mode: String,
}

fn default_global_enforcement_mode() -> String {
    "PerPolicy".to_string()
}
```

### PolicyFormState Extension (dlp-admin-cli/src/app.rs)
```rust
#[derive(Debug, Clone, Default)]
pub struct PolicyFormState {
    pub name: String,
    pub description: String,
    pub priority: String,
    pub action: usize,
    pub enabled: bool,
    /// Phase 55: Index into ENFORCEMENT_MODE_OPTIONS.
    pub enforcement_mode: usize,
    pub conditions: Vec<dlp_common::abac::PolicyCondition>,
    pub id: String,
    pub mode: dlp_common::abac::PolicyMode,
}

pub const ACTION_OPTIONS: [&str; 4] = ["ALLOW", "DENY", "AllowWithLog", "DenyWithAlert"];
pub const ENFORCEMENT_MODE_OPTIONS: [&str; 3] = ["Audit", "Block", "AuditAndBlock"];
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Single blocking mode | Per-policy Audit/Block/AuditAndBlock | Phase 55 (v0.10.0) | Safe rollout; monitor-first deployment |
| No global override | `global_enforcement_mode` in system_kv | Phase 55 (v0.10.0) | Single-flip convenience for operators |
| Alert router always fires | Severity downgrade in Audit mode | Phase 55 (v0.10.0) | No pager fatigue during monitoring |

**Deprecated/outdated:**
- None — this is a new feature, not a replacement.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `system_kv` table exists and is the right place for global config | Standard Stack | If wrong, need new table + migration |
| A2 | The agent's `run_event_loop` is the right place to apply effective mode before emitting audit | Architecture Patterns | If wrong, hook DLL may still block in Audit mode |
| A3 | `EvaluateResponse` can be extended with new fields without breaking existing agents | Code Examples | If wrong, need protocol versioning or backward-compat shim |
| A4 | The DACL tripwire reads protected paths from agent config, not directly from policies | Common Pitfalls | If wrong, tripwire may need policy parsing logic |

## Open Questions (RESOLVED)

1. **RESOLVED: Hook DLL protocol compatibility**
   - What we know: `HookResponse` currently has `decision`, `reason`, `cache_hint`, `cache_version`.
   - Resolution: Use `#[serde(default)]` on new `EvaluateResponse` fields. Old agents will ignore them. The server can send them unconditionally. Implemented in Plan 55-01.

2. **RESOLVED: Agent config TOML backward compatibility**
   - What we know: `serde_ignored` is used to detect unknown keys without aborting.
   - Resolution: A one-time warning is acceptable. The warning will stop once the server pushes the new config. The agent defaults to `PerPolicy` when `[enforcement]` section is absent. Implemented in Plan 55-03.

3. **RESOLVED: Integration test scope**
   - What we know: The CONTEXT.md specifies round-trip `Audit -> Block -> AuditAndBlock` via PUT.
   - Resolution: The integration test (Plan 55-07) verifies both the PUT round-trip AND the actual file operation succeeds in Audit mode with `would_have_denied = true` in the audit event.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Rust toolchain | All crates | Yes | 1.82 | — |
| SQLite | dlp-server DB | Yes | 3.46 | — |
| Windows SDK | dlp-agent, dlp-hook-dll | Yes | 10.0.26100 | — |
| tokio runtime | dlp-agent async | Yes | 1.40 | — |

**Missing dependencies with no fallback:** None.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Built-in `#[test]` + `cargo test` |
| Config file | None — workspace-level |
| Quick run command | `cargo test -p dlp-common` |
| Full suite command | `cargo test --workspace` |

### Phase Requirements -> Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| MODE-01 | Policy with Audit mode allows operation but emits audit event with `would_have_denied = true` | Integration | `cargo test -p dlp-e2e` | No — needs new test |
| MODE-01 | Global override `Audit` forces all policies to Audit mode | Unit | `cargo test -p dlp-server policy_store` | No — needs new test |
| MODE-01 | Alert router downgrades severity to `info` for Audit-mode DenyWithAlert | Unit | `cargo test -p dlp-server alert_router` | No — needs new test |
| MODE-01 | DACL tripwire skips Deny ACE for Audit-mode policies | Unit | `cargo test -p dlp-agent dacl_watcher` | No — needs new test |
| MODE-01 | Admin TUI renders enforcement mode dropdown | Unit | `cargo test -p dlp-admin-cli` | No — needs new test |
| MODE-01 | Backward compat: absent `enforcement_mode` defaults to `Block` | Unit | `cargo test -p dlp-common` | No — needs new test |

### Sampling Rate
- **Per task commit:** `cargo test -p <crate>`
- **Per wave merge:** `cargo test --workspace`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `dlp-common/src/abac.rs` — unit tests for `EnforcementMode` serde round-trip
- [ ] `dlp-common/src/audit.rs` — unit tests for `AuditEvent` with new fields
- [ ] `dlp-server/src/policy_store.rs` — unit tests for effective mode computation
- [ ] `dlp-server/src/alert_router.rs` — unit tests for severity downgrade
- [ ] `dlp-agent/src/interception/mod.rs` — integration test for Audit-mode allow
- [ ] `dlp-admin-cli/src/screens/dispatch.rs` — unit tests for form submission with enforcement_mode

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No | — |
| V3 Session Management | No | — |
| V4 Access Control | Yes | Enforcement mode is an access control feature |
| V5 Input Validation | Yes | `EnforcementMode` deserialization validates against known variants |
| V6 Cryptography | No | — |

### Known Threat Patterns for DLP Stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Attacker sets policy to Audit to evade blocking | Tampering | Admin API requires JWT auth; only dlp-admin can change policies |
| Agent receives tampered global_mode from compromised server | Tampering | HTTPS + agent auth hash; server compromise is out of threat model |
| Audit log omission for Audit-mode violations | Repudiation | Audit event emitted locally before network; offline queue persists |

## Sources

### Primary (HIGH confidence)
- `dlp-common/src/abac.rs` — `Policy` struct, `Decision` enum, `PolicyMode` enum
- `dlp-common/src/audit.rs` — `AuditEvent` struct, `EventType` enum
- `dlp-server/src/policy_store.rs` — `PolicyStore::evaluate()`, `deserialize_policy_row()`
- `dlp-server/src/db/repositories/policies.rs` — `PolicyRow`, `PolicyRepository`
- `dlp-server/src/admin_api.rs` — `PolicyPayload`, `PolicyResponse`
- `dlp-server/src/alert_router.rs` — `AlertRouter::send_alert()`
- `dlp-server/src/siem_connector.rs` — `SiemConnector::relay_events()`
- `dlp-agent/src/interception/mod.rs` — `run_event_loop()`
- `dlp-agent/src/audit_emitter.rs` — `emit_audit()`
- `dlp-agent/src/config.rs` — `AgentConfig`
- `dlp-agent/src/server_client.rs` — `AgentConfigPayload`
- `dlp-hook-dll/src/trampolines.rs` — `classify_and_log_path()`
- `dlp-admin-cli/src/app.rs` — `PolicyFormState`
- `dlp-admin-cli/src/screens/dispatch.rs` — form submit handlers
- `dlp-admin-cli/src/screens/render.rs` — form render functions

### Secondary (MEDIUM confidence)
- `.planning/phases/55-monitor-only-audit-only-per-policy-enforcement-mode/55-CONTEXT.md` — Locked decisions D-01 through D-07
- `.planning/phases/55-monitor-only-audit-only-per-policy-enforcement-mode/55-DISCUSSION-LOG.md` — User-confirmed decisions
- `.planning/ROADMAP.md` — Phase 55 goal, MODE-01 requirement
- `.planning/STATE.md` — v0.10.0 milestone context

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — no new packages, existing patterns
- Architecture: HIGH — CONTEXT.md provides clear decisions, codebase patterns are consistent
- Pitfalls: HIGH — identified from prior phase experience and explicit decisions

**Research date:** 2026-05-28
**Valid until:** 2026-06-28 (stable — no fast-moving dependencies)
