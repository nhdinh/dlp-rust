# Phase 55: Monitor-Only / Audit-Only Per-Policy Enforcement Mode - Pattern Map

**Mapped:** 2026-05-28
**Files analyzed:** 14
**Analogs found:** 14 / 14

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `dlp-common/src/abac.rs` | model | CRUD | `dlp-common/src/abac.rs` (existing) | exact (extend in place) |
| `dlp-common/src/audit.rs` | model | CRUD | `dlp-common/src/audit.rs` (existing) | exact (extend in place) |
| `dlp-server/src/db/mod.rs` | migration | batch | `dlp-server/src/db/mod.rs` (existing `run_migrations`) | exact |
| `dlp-server/src/db/repositories/policies.rs` | repository | CRUD | `dlp-server/src/db/repositories/policies.rs` (existing) | exact (extend in place) |
| `dlp-server/src/policy_store.rs` | service | request-response | `dlp-server/src/policy_store.rs` (existing `evaluate()`) | exact (extend in place) |
| `dlp-server/src/admin_api.rs` | controller | request-response | `dlp-server/src/admin_api.rs` (existing `PolicyPayload`) | exact (extend in place) |
| `dlp-server/src/policy_sync.rs` | service | request-response | `dlp-server/src/policy_sync.rs` (existing sync pattern) | exact (extend in place) |
| `dlp-server/src/alert_router.rs` | service | event-driven | `dlp-server/src/alert_router.rs` (existing `send_alert()`) | exact (extend in place) |
| `dlp-agent/src/engine_client.rs` | service | request-response | `dlp-agent/src/engine_client.rs` (existing `evaluate()`) | exact (extend in place) |
| `dlp-agent/src/config.rs` | model | CRUD | `dlp-agent/src/config.rs` (existing `AgentConfig`) | exact (extend in place) |
| `dlp-agent/src/service.rs` | service | event-driven | `dlp-agent/src/service.rs` (existing config poll loop) | exact (extend in place) |
| `dlp-hook-dll/src/trampolines.rs` | middleware | request-response | `dlp-hook-dll/src/trampolines.rs` (existing `classify_and_log_path()`) | exact (extend in place) |
| `dlp-admin-cli/src/app.rs` | model | CRUD | `dlp-admin-cli/src/app.rs` (existing `PolicyFormState`) | exact (extend in place) |
| `dlp-admin-cli/src/screens/dispatch.rs` | controller | event-driven | `dlp-admin-cli/src/screens/dispatch.rs` (existing `handle_policy_create`) | exact (extend in place) |
| `dlp-admin-cli/src/screens/render.rs` | component | request-response | `dlp-admin-cli/src/screens/render.rs` (existing `draw_policy_create`) | exact (extend in place) |

## Pattern Assignments

### `dlp-common/src/abac.rs` (model, CRUD)

**Analog:** `dlp-common/src/abac.rs` (self — extend existing types)

**Enum pattern** (lines 80-114, existing `Decision`):
```rust
/// The system action the ABAC engine returns after evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Decision {
    #[default]
    ALLOW,
    DENY,
    #[serde(rename = "ALLOW_WITH_LOG")]
    AllowWithLog,
    #[serde(rename = "DENY_WITH_ALERT")]
    DenyWithAlert,
}

impl Decision {
    #[must_use]
    pub fn is_denied(self) -> bool {
        matches!(self, Self::DENY | Self::DenyWithAlert)
    }
}
```

**New enum to add** (pattern: same as `Decision` / `PolicyMode`):
```rust
/// Per-policy enforcement mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub enum EnforcementMode {
    Audit,
    #[default]
    Block,
    AuditAndBlock,
}
```

**Struct extension pattern** (lines 464-485, existing `Policy`):
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
    pub version: u64,
}
```

**Add to `Policy`** (after `mode`, before `version`):
```rust
    /// Phase 55: Per-policy enforcement mode.
    #[serde(default)]
    pub enforcement_mode: EnforcementMode,
```

**EvaluateResponse extension** (lines 272-303):
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateResponse {
    pub decision: Decision,
    pub matched_policy_id: Option<String>,
    pub reason: String,
}
```

**Add to `EvaluateResponse`**:
```rust
    /// Phase 55: Effective enforcement mode that produced this decision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforcement_mode: Option<EnforcementMode>,
    /// Phase 55: True if the policy would have denied but mode was Audit.
    #[serde(default)]
    pub would_have_denied: bool,
```

---

### `dlp-common/src/audit.rs` (model, CRUD)

**Analog:** `dlp-common/src/audit.rs` (self — extend `AuditEvent`)

**Optional field pattern** (lines 172-275, existing `AuditEvent`):
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: EventType,
    // ... many fields ...
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_sid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_user: Option<String>,
}
```

**Add to `AuditEvent`** (after `owner_user` or at end of struct):
```rust
    /// Phase 55: Effective enforcement mode ("Audit", "Block", "AuditAndBlock").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_mode: Option<String>,
    /// Phase 55: True if the policy would have denied but was in Audit mode.
    #[serde(default)]
    pub would_have_denied: bool,
```

**Builder method pattern** (lines 337-342, existing `with_policy`):
```rust
    pub fn with_policy(mut self, policy_id: String, policy_name: String) -> Self {
        self.policy_id = Some(policy_id);
        self.policy_name = Some(policy_name);
        self
    }
```

---

### `dlp-server/src/db/mod.rs` (migration, batch)

**Analog:** `dlp-server/src/db/mod.rs` (existing `run_migrations`)

**Migration pattern** (from RESEARCH.md and prior phases):
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

---

### `dlp-server/src/db/repositories/policies.rs` (repository, CRUD)

**Analog:** `dlp-server/src/db/repositories/policies.rs` (self)

**Row struct pattern** (lines 10-32, existing `PolicyRow`):
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
    pub version: i64,
    pub updated_at: String,
}
```

**Add to `PolicyRow`** (after `mode`):
```rust
    /// Phase 55: Enforcement mode.
    pub enforcement_mode: String,
```

**PolicyUpdateRow pattern** (lines 39-59):
```rust
#[derive(Debug, Clone)]
pub struct PolicyUpdateRow<'a> {
    pub name: &'a str,
    pub description: Option<&'a str>,
    pub priority: i64,
    pub conditions: &'a str,
    pub action: &'a str,
    pub enabled: i64,
    pub mode: &'a str,
    pub updated_at: &'a str,
    pub id: &'a str,
}
```

**Add to `PolicyUpdateRow`** (after `mode`):
```rust
    /// Phase 55: Enforcement mode.
    pub enforcement_mode: &'a str,
```

**SQL SELECT pattern** (lines 78-82, `list()`):
```rust
        let mut stmt = conn.prepare(
            "SELECT id, name, description, priority, conditions, action, \
             enabled, mode, version, updated_at \
             FROM policies ORDER BY priority ASC",
        )?;
```

**Update all SELECTs** to include `enforcement_mode` column and bind it in the row mapper.

**SQL INSERT pattern** (lines 111-127, `insert()`):
```rust
        uow.tx.execute(
            "INSERT INTO policies (id, name, description, priority, conditions, \
             action, enabled, mode, version, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![...],
        )?;
```

**Update INSERT** to include `enforcement_mode` and add `?11` param.

**SQL UPDATE pattern** (lines 183-201, `update()`):
```rust
        uow.tx.execute(
            "UPDATE policies SET \
                    name = ?1, description = ?2, priority = ?3, \
                    conditions = ?4, action = ?5, enabled = ?6, \
                    mode = ?7, version = version + 1, updated_at = ?8 \
             WHERE id = ?9",
            params![...],
        )
```

**Update UPDATE** to include `enforcement_mode = ?10` and add the param.

---

### `dlp-server/src/policy_store.rs` (service, request-response)

**Analog:** `dlp-server/src/policy_store.rs` (self — `evaluate()` and `deserialize_policy_row()`)

**Evaluate pattern** (lines 135-223, existing `evaluate()`):
```rust
    pub fn evaluate(
        &self,
        ctx: &AbacContext,
        label_service: Option<&crate::label_service::LabelService>,
        label_aware_enabled: bool,
    ) -> EvaluateResponse {
        // ... label-aware evaluation ...
        let cache = self.cache.read();
        for policy in cache.iter() {
            if !policy.enabled {
                continue;
            }
            let conditions_match = match policy.mode {
                // ... condition matching ...
            };
            if conditions_match {
                return EvaluateResponse {
                    decision: policy.action,
                    matched_policy_id: Some(policy.id.clone()),
                    reason: format!("matched policy '{}'", policy.name),
                };
            }
        }
        // default-deny fallback
    }
```

**Modify the match block** to compute effective mode and return enriched response:
```rust
            if conditions_match {
                let effective_mode = if global_mode != EnforcementMode::PerPolicy {
                    global_mode
                } else {
                    policy.enforcement_mode
                };

                let (decision, would_have_denied) = match effective_mode {
                    EnforcementMode::Audit => {
                        (Decision::ALLOW, policy.action.is_denied())
                    }
                    EnforcementMode::Block => {
                        (policy.action, false)
                    }
                    EnforcementMode::AuditAndBlock => {
                        (policy.action, false)
                    }
                };

                return EvaluateResponse {
                    decision,
                    matched_policy_id: Some(policy.id.clone()),
                    reason: format!("matched policy '{}' (mode: {:?})", policy.name, effective_mode),
                    enforcement_mode: Some(effective_mode),
                    would_have_denied,
                };
            }
```

**deserialize_policy_row pattern** (lines 256-288):
```rust
fn deserialize_policy_row(
    row: &crate::db::repositories::policies::PolicyRow,
) -> Result<Policy, serde_json::Error> {
    let conditions: Vec<PolicyCondition> = serde_json::from_str(&row.conditions)?;
    let action = match row.action.to_lowercase().as_str() {
        "allow" => Decision::ALLOW,
        "deny" => Decision::DENY,
        "allow_with_log" | "allowwithlog" => Decision::AllowWithLog,
        "deny_with_alert" | "denywithalert" => Decision::DenyWithAlert,
        _ => Decision::DENY,
    };
    let mode = match row.mode.as_str() {
        "ALL" => PolicyMode::ALL,
        "ANY" => PolicyMode::ANY,
        "NONE" => PolicyMode::NONE,
        other => return Err(serde::de::Error::custom(format!("invalid policy mode: {other}"))),
    };
    Ok(Policy {
        id: row.id.clone(),
        name: row.name.clone(),
        description: row.description.clone(),
        priority: row.priority as u32,
        conditions,
        action,
        enabled: row.enabled != 0,
        mode,
        version: row.version as u64,
    })
}
```

**Add enforcement_mode parsing** before the `Ok(Policy {` block:
```rust
    let enforcement_mode = match row.enforcement_mode.to_lowercase().as_str() {
        "audit" => EnforcementMode::Audit,
        "block" => EnforcementMode::Block,
        "auditandblock" => EnforcementMode::AuditAndBlock,
        _ => EnforcementMode::Block, // defensive fallback
    };
```

**Add to `Policy` construction**:
```rust
        enforcement_mode,
```

---

### `dlp-server/src/admin_api.rs` (controller, request-response)

**Analog:** `dlp-server/src/admin_api.rs` (self — `PolicyPayload` and `PolicyResponse`)

**Payload pattern** (lines 141-160, existing `PolicyPayload`):
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPayload {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub priority: u32,
    pub conditions: serde_json::Value,
    pub action: String,
    pub enabled: bool,
    #[serde(default)]
    pub mode: PolicyMode,
}
```

**Add to `PolicyPayload`** (after `mode`):
```rust
    /// Phase 55: Per-policy enforcement mode.
    #[serde(default)]
    pub enforcement_mode: dlp_common::abac::EnforcementMode,
```

**Response pattern** (lines 163-186, existing `PolicyResponse`):
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub priority: u32,
    pub conditions: serde_json::Value,
    pub action: String,
    pub enabled: bool,
    #[serde(default)]
    pub mode: PolicyMode,
    pub version: i64,
    pub updated_at: String,
}
```

**Add to `PolicyResponse`** (after `mode`):
```rust
    /// Phase 55: Per-policy enforcement mode.
    #[serde(default)]
    pub enforcement_mode: dlp_common::abac::EnforcementMode,
```

**AgentConfigPayload extension** (lines 414-466, existing `AgentConfigPayload`):
```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentConfigPayload {
    pub monitored_paths: Vec<String>,
    // ... many fields ...
    #[serde(default)]
    pub protected_paths: Vec<ProtectedPathConfig>,
}
```

**Add to `AgentConfigPayload`** (after `protected_paths`):
```rust
    /// Phase 55: Global enforcement mode override from server.
    #[serde(default = "default_global_enforcement_mode")]
    pub global_enforcement_mode: String,
```

**Add default function** (near other `default_*` helpers at line 468):
```rust
fn default_global_enforcement_mode() -> String {
    "PerPolicy".to_string()
}
```

**Add to `AgentConfigPayload::default()`** (line 488-507):
```rust
            protected_paths: Vec::new(),
            global_enforcement_mode: default_global_enforcement_mode(),
```

---

### `dlp-server/src/alert_router.rs` (service, event-driven)

**Analog:** `dlp-server/src/alert_router.rs` (self — `send_alert()`)

**send_alert pattern** (lines 271-322):
```rust
    pub async fn send_alert(&self, event: &AuditEvent) -> Result<(), AlertError> {
        let row = self.load_config()?;
        let mut errors: Vec<AlertError> = Vec::new();
        // SMTP path ...
        // Webhook path ...
        if let Some(e) = errors.into_iter().next() {
            return Err(e);
        }
        Ok(())
    }
```

**Add severity downgrade at top of `send_alert`**:
```rust
    pub async fn send_alert(&self, event: &AuditEvent) -> Result<(), AlertError> {
        let mut event = event.clone();

        // Phase 55: Downgrade severity for Audit-mode DenyWithAlert policies.
        if event.event_type == dlp_common::EventType::Alert
            && event.policy_mode.as_deref() == Some("Audit")
        {
            event.severity = Some("info".to_string());
            tracing::info!(
                policy_id = %event.policy_id.as_deref().unwrap_or("unknown"),
                "alert severity downgraded to info (Audit mode)"
            );
        }

        let row = self.load_config()?;
        // ... rest unchanged
```

---

### `dlp-agent/src/config.rs` (model, CRUD)

**Analog:** `dlp-agent/src/config.rs` (self — `AgentConfig`)

**Config struct pattern** (from RESEARCH.md, matching existing `AgentConfig` serde style):
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

---

### `dlp-agent/src/service.rs` (service, event-driven)

**Analog:** `dlp-agent/src/service.rs` (self — config poll loop)

**Config poll pattern** (lines 40-68, existing `with_config`):
```rust
pub fn with_config<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&crate::config::AgentConfig) -> R,
{
    CONFIG.get().map(|arc| {
        let cfg = arc.lock();
        f(&cfg)
    })
}
```

**In the config poll loop**, after applying the payload to config, read `global_enforcement_mode`:
```rust
// Phase 55: Apply global enforcement mode from server payload.
if let Some(global_mode) = payload.get("global_enforcement_mode").and_then(|v| v.as_str()) {
    cfg.enforcement.global_mode = global_mode.to_string();
}
```

---

### `dlp-hook-dll/src/trampolines.rs` (middleware, request-response)

**Analog:** `dlp-hook-dll/src/trampolines.rs` (self — `classify_and_log_path()`)

**Decision pattern** (lines 177-199, Healthy path):
```rust
                match crate::classify_path(path, action, crate::DEFAULT_PIPE_NAME) {
                    Ok(crate::Decision::ALLOW) | Ok(crate::Decision::AllowWithLog) => {
                        fail_state.record_pipe_success(cache_version);
                        None
                    }
                    Ok(crate::Decision::DENY) | Ok(crate::Decision::DenyWithAlert) => {
                        fail_state.record_pipe_success(cache_version);
                        Some(crate::fail_closed::DenyReturn::BoolFalse)
                    }
                    Err(_) => {
                        fail_state.record_pipe_failure();
                        Some(crate::fail_closed::DenyReturn::BoolFalse)
                    }
                }
```

**Per RESEARCH.md anti-pattern D-02:** The hook DLL should NOT be mode-aware. The agent's IPC handler (or the server-side `evaluate()`) already applies the effective mode and returns the final decision. The hook DLL receives `Decision::ALLOW` for Audit mode via the existing `HookResponse::decision` field.

**No code changes needed in trampolines.rs.** The agent-side `run_event_loop` or IPC handler is where effective mode is applied before returning to the DLL.

---

### `dlp-admin-cli/src/app.rs` (model, CRUD)

**Analog:** `dlp-admin-cli/src/app.rs` (self — `PolicyFormState`)

**Form state pattern** (lines 296-316, existing `PolicyFormState`):
```rust
#[derive(Debug, Clone, Default)]
pub struct PolicyFormState {
    pub name: String,
    pub description: String,
    pub priority: String,
    pub action: usize,
    pub enabled: bool,
    pub conditions: Vec<dlp_common::abac::PolicyCondition>,
    pub id: String,
    pub mode: dlp_common::abac::PolicyMode,
}
```

**Add to `PolicyFormState`** (after `enabled`, before `conditions`):
```rust
    /// Phase 55: Index into ENFORCEMENT_MODE_OPTIONS.
    pub enforcement_mode: usize,
```

**Options constant pattern** (line 323, existing `ACTION_OPTIONS`):
```rust
pub const ACTION_OPTIONS: [&str; 4] = ["ALLOW", "DENY", "AllowWithLog", "DenyWithAlert"];
```

**Add new constant** (after `ACTION_OPTIONS`):
```rust
pub const ENFORCEMENT_MODE_OPTIONS: [&str; 3] = ["Audit", "Block", "AuditAndBlock"];
```

**PolicyResponse pattern** (lines 557-575):
```rust
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct PolicyResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub priority: u32,
    pub conditions: serde_json::Value,
    pub action: String,
    pub enabled: bool,
    #[serde(default)]
    pub version: i64,
    #[serde(default)]
    pub updated_at: String,
    #[serde(default)]
    pub mode: dlp_common::abac::PolicyMode,
}
```

**Add to `PolicyResponse`** (after `mode`):
```rust
    /// Phase 55: Per-policy enforcement mode.
    #[serde(default)]
    pub enforcement_mode: dlp_common::abac::EnforcementMode,
```

**PolicyPayload pattern** (lines 581-593):
```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PolicyPayload {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub priority: u32,
    pub conditions: serde_json::Value,
    pub action: String,
    pub enabled: bool,
    #[serde(default)]
    pub mode: dlp_common::abac::PolicyMode,
}
```

**Add to `PolicyPayload`** (after `mode`):
```rust
    /// Phase 55: Per-policy enforcement mode.
    #[serde(default)]
    pub enforcement_mode: dlp_common::abac::EnforcementMode,
```

**From impl pattern** (lines 595-608):
```rust
impl From<PolicyResponse> for PolicyPayload {
    fn from(r: PolicyResponse) -> Self {
        Self {
            id: r.id,
            name: r.name,
            description: r.description,
            priority: r.priority,
            conditions: r.conditions,
            action: r.action,
            enabled: r.enabled,
            mode: r.mode,
        }
    }
}
```

**Add `enforcement_mode` to the `From` impl**:
```rust
            mode: r.mode,
            enforcement_mode: r.enforcement_mode,
```

---

### `dlp-admin-cli/src/screens/dispatch.rs` (controller, event-driven)

**Analog:** `dlp-admin-cli/src/screens/dispatch.rs` (self — `handle_policy_create`, `action_submit_policy`, `action_load_policy_for_edit`)

**Row constant pattern** (lines 1212-1227):
```rust
const POLICY_NAME_ROW: usize = 0;
const POLICY_DESC_ROW: usize = 1;
const POLICY_PRIORITY_ROW: usize = 2;
const POLICY_ACTION_ROW: usize = 3;
const POLICY_ENABLED_ROW: usize = 4;
const POLICY_MODE_ROW: usize = 5;
const POLICY_ADD_CONDITIONS_ROW: usize = 6;
const POLICY_CONDITIONS_DISPLAY_ROW: usize = 7;
const POLICY_SAVE_ROW: usize = 8;
const POLICY_ROW_COUNT: usize = 9;
```

**Add new row constant** (after `POLICY_MODE_ROW`, shift subsequent rows):
```rust
const POLICY_ENFORCEMENT_MODE_ROW: usize = 6;
const POLICY_ADD_CONDITIONS_ROW: usize = 7;
const POLICY_CONDITIONS_DISPLAY_ROW: usize = 8;
const POLICY_SAVE_ROW: usize = 9;
const POLICY_ROW_COUNT: usize = 10;
```

**Cycle pattern** (lines 1241-1248, `cycle_mode`):
```rust
fn cycle_mode(mode: dlp_common::abac::PolicyMode) -> dlp_common::abac::PolicyMode {
    use dlp_common::abac::PolicyMode;
    match mode {
        PolicyMode::ALL => PolicyMode::ANY,
        PolicyMode::ANY => PolicyMode::NONE,
        PolicyMode::NONE => PolicyMode::ALL,
    }
}
```

**Add cycle function for enforcement mode**:
```rust
fn cycle_enforcement_mode(idx: usize) -> usize {
    (idx + 1) % crate::app::ENFORCEMENT_MODE_OPTIONS.len()
}
```

**Nav enter pattern** (lines 2279-2308, `policy_create_nav_enter`):
```rust
fn policy_create_nav_enter(app: &mut App, selected: usize) {
    match selected {
        POLICY_SAVE_ROW => { ... }
        POLICY_ENABLED_ROW => { form.enabled = !form.enabled; }
        POLICY_MODE_ROW => { form.mode = cycle_mode(form.mode); }
        POLICY_ACTION_ROW => { form.action = (form.action + 1) % ACTION_OPTIONS.len(); }
        POLICY_ADD_CONDITIONS_ROW => policy_create_open_conditions(app),
        POLICY_CONDITIONS_DISPLAY_ROW => {}
        _ => policy_create_enter_edit(app, selected),
    }
}
```

**Add enforcement_mode arm** (after `POLICY_MODE_ROW`):
```rust
        POLICY_ENFORCEMENT_MODE_ROW => {
            if let Screen::PolicyCreate { form, .. } = &mut app.screen {
                form.enforcement_mode = cycle_enforcement_mode(form.enforcement_mode);
            }
        }
```

**Space-bar toggle pattern** (lines 2319-2323):
```rust
        KeyCode::Char(' ') if selected == POLICY_MODE_ROW => {
            if let Screen::PolicyCreate { form, .. } = &mut app.screen {
                form.mode = cycle_mode(form.mode);
            }
        }
```

**Add space-bar toggle for enforcement_mode**:
```rust
        KeyCode::Char(' ') if selected == POLICY_ENFORCEMENT_MODE_ROW => {
            if let Screen::PolicyCreate { form, .. } = &mut app.screen {
                form.enforcement_mode = cycle_enforcement_mode(form.enforcement_mode);
            }
        }
```

**Submit payload pattern** (lines 2372-2426, `action_submit_policy`):
```rust
    let payload = serde_json::json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "name": form.name.trim(),
        "description": ...,
        "priority": priority,
        "conditions": conditions_json,
        "action": action_str,
        "enabled": form.enabled,
        "mode": policy_mode_to_wire(form.mode),
    });
```

**Add `enforcement_mode` to payload**:
```rust
        "mode": policy_mode_to_wire(form.mode),
        "enforcement_mode": crate::app::ENFORCEMENT_MODE_OPTIONS[form.enforcement_mode],
```

**Load-for-edit pattern** (lines 2456-2515, `action_load_policy_for_edit`):
```rust
            let form = PolicyFormState {
                name: policy["name"].as_str().unwrap_or("").to_string(),
                description: policy["description"].as_str().unwrap_or("").to_string(),
                priority: policy["priority"].as_i64().map(|n| n.to_string()).unwrap_or_default(),
                action: action_idx,
                enabled: policy["enabled"].as_bool().unwrap_or(true),
                conditions,
                mode: match policy["mode"].as_str() {
                    Some("ALL") => PolicyMode::ALL,
                    Some("ANY") => PolicyMode::ANY,
                    Some("NONE") => PolicyMode::NONE,
                    _ => PolicyMode::ALL,
                },
                id: id.to_string(),
            };
```

**Add `enforcement_mode` to form construction**:
```rust
                enforcement_mode: match policy["enforcement_mode"].as_str() {
                    Some("Audit") => 0,
                    Some("Block") => 1,
                    Some("AuditAndBlock") => 2,
                    _ => 1, // default Block
                },
```

**Policy edit nav enter pattern** (lines 2640-2663, `policy_edit_nav_enter`):
Mirror the same changes as `policy_create_nav_enter` for `POLICY_ENFORCEMENT_MODE_ROW`.

**Policy edit submit pattern** (lines 2692-2744, `action_submit_policy_update`):
Mirror the same payload change as `action_submit_policy` for `enforcement_mode`.

---

### `dlp-admin-cli/src/screens/render.rs` (component, request-response)

**Analog:** `dlp-admin-cli/src/screens/render.rs` (self — `draw_policy_create`, `draw_policy_edit`, format helpers)

**Field labels pattern** (lines 1051-1061, `POLICY_FIELD_LABELS`):
```rust
const POLICY_FIELD_LABELS: [&str; 9] = [
    "Name",
    "Description",
    "Priority",
    "Action",
    "Enabled",
    "Mode",
    "[Add Conditions]",
    "Conditions",
    "[Submit]",
];
```

**Update to 10 elements**, inserting "Enforcement Mode" after "Mode":
```rust
const POLICY_FIELD_LABELS: [&str; 10] = [
    "Name",
    "Description",
    "Priority",
    "Action",
    "Enabled",
    "Mode",
    "Enforcement Mode",
    "[Add Conditions]",
    "Conditions",
    "[Submit]",
];
```

**draw_policy_create pattern** (lines 1423-1477):
```rust
    for (i, label) in POLICY_FIELD_LABELS.iter().enumerate() {
        let line = match i {
            0 => format_policy_name_field(label, form, selected, editing, buffer),
            1 => format_policy_description_field(label, form, selected, editing, buffer),
            2 => format_policy_priority_field(label, form, selected, editing, buffer),
            3 => format_policy_action_field(label, form),
            4 => format_policy_enabled_field(label, form),
            5 => format_policy_mode_field(label, form),
            6 => Line::from(format!("  {label}")),
            7 => format_policy_conditions_field(label, form),
            8 => Line::from(format!("  {label}")),
            _ => Line::from(""),
        };
        items.push(ListItem::new(line));
    }
```

**Update match arms** (insert enforcement_mode at index 6, shift rest):
```rust
            3 => format_policy_action_field(label, form),
            4 => format_policy_enabled_field(label, form),
            5 => format_policy_mode_field(label, form),
            6 => format_enforcement_mode_field(label, form),
            7 => Line::from(format!("  {label}")),
            8 => format_policy_conditions_field(label, form),
            9 => Line::from(format!("  {label}")),
```

**draw_policy_edit pattern** (lines 1495-1550):
Mirror the same index shift as `draw_policy_create`.

**Format helper pattern** (lines 1333-1340, `format_policy_mode_field`):
```rust
fn format_policy_mode_field(label: &str, form: &crate::app::PolicyFormState) -> Line<'static> {
    let mode_label = match form.mode {
        PolicyMode::ALL => "ALL",
        PolicyMode::ANY => "ANY",
        PolicyMode::NONE => "NONE",
    };
    Line::from(format!("{label}:              {mode_label}"))
}
```

**Add format helper for enforcement mode**:
```rust
fn format_enforcement_mode_field(label: &str, form: &crate::app::PolicyFormState) -> Line<'static> {
    let mode_label = crate::app::ENFORCEMENT_MODE_OPTIONS[form.enforcement_mode];
    Line::from(format!("{label}:              {mode_label}"))
}
```

**Policy list table pattern** (lines 1641-1704, `draw_policy_list`):
```rust
    let header = Row::new(vec!["Priority", "Name", "Action", "Enabled"])
        .style(Style::default().add_modifier(Modifier::BOLD))
        .bottom_margin(1);
```

**Add "Mode" column** to header and row mapping:
```rust
    let header = Row::new(vec!["Priority", "Name", "Action", "Enabled", "Mode"])
        .style(Style::default().add_modifier(Modifier::BOLD))
        .bottom_margin(1);
```

In the row mapper, add:
```rust
            let mode = p["enforcement_mode"].as_str().unwrap_or("Block");
```

And include it in `Row::new(vec![...])`.

---

## Shared Patterns

### Serde Default for Backward Compatibility
**Source:** `dlp-common/src/abac.rs` (line 482), `dlp-common/src/audit.rs` (line 211)
**Apply to:** All new enum/struct fields
```rust
#[serde(default)]
pub mode: PolicyMode,
```
Pattern: Use `#[serde(default)]` on all new fields so absent JSON keys deserialize to the default value. For enums, derive `Default` with the backward-compatible variant (`Block` for `EnforcementMode`, `ALL` for `PolicyMode`).

### DB Migration with run_alter
**Source:** `dlp-server/src/db/mod.rs` (existing `run_migrations`)
**Apply to:** New column additions
Pattern: Use `run_alter(conn, sql, column_name, table_name)` for idempotent ALTER TABLE. The helper checks if the column already exists before running the ALTER.

### String-to-Enum Parsing in Repository Layer
**Source:** `dlp-server/src/policy_store.rs` (lines 260-276, `deserialize_policy_row`)
**Apply to:** `enforcement_mode` parsing from DB row
Pattern: Match lowercase string against known variants; fall back to the default variant defensively. Log warnings for unrecognized values.

### Form Index Cycling in TUI
**Source:** `dlp-admin-cli/src/screens/dispatch.rs` (lines 1241-1248, `cycle_mode`)
**Apply to:** `enforcement_mode` picker
Pattern: `(idx + 1) % OPTIONS.len()` cycles through a fixed array of string options. The array index is stored in form state; the string is only resolved at wire-time.

### Row Index Constants for TUI Forms
**Source:** `dlp-admin-cli/src/screens/dispatch.rs` (lines 1212-1227)
**Apply to:** PolicyCreate/PolicyEdit form rows
Pattern: Define `const POLICY_*_ROW: usize` for each field. When inserting a new row, increment all subsequent constants and `POLICY_ROW_COUNT`. Update both `dispatch.rs` (nav + enter handlers) and `render.rs` (draw + format helpers).

### Alert Severity Downgrade
**Source:** `dlp-server/src/alert_router.rs` (lines 271-322, `send_alert`)
**Apply to:** Audit-mode alert suppression
Pattern: Clone the event at the top of `send_alert`, check `event_type == Alert && policy_mode == Some("Audit")`, mutate `event.severity = Some("info".to_string())`, then proceed with normal delivery. Log at `info` level so operators can observe the downgrade.

## No Analog Found

No files lack a close analog. All 14 files have exact in-place matches within the same file.

## Metadata

**Analog search scope:**
- `dlp-common/src/abac.rs`
- `dlp-common/src/audit.rs`
- `dlp-server/src/db/repositories/policies.rs`
- `dlp-server/src/policy_store.rs`
- `dlp-server/src/admin_api.rs`
- `dlp-server/src/policy_sync.rs`
- `dlp-server/src/alert_router.rs`
- `dlp-agent/src/engine_client.rs`
- `dlp-agent/src/config.rs`
- `dlp-agent/src/service.rs`
- `dlp-hook-dll/src/trampolines.rs`
- `dlp-admin-cli/src/app.rs`
- `dlp-admin-cli/src/screens/dispatch.rs`
- `dlp-admin-cli/src/screens/render.rs`

**Files scanned:** 14
**Pattern extraction date:** 2026-05-28
