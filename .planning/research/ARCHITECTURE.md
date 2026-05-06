# Architecture Patterns: Application-Aware DLP (v0.8.0)

**Domain:** Enterprise DLP — UWP App Identity, OLE Drag-and-Drop Enforcement, Browser Origin Policies
**Researched:** 2026-05-06
**Confidence:** HIGH (existing codebase fully understood; Windows APIs well-documented)

---

## Executive Summary

v0.8.0 extends the existing application-aware DLP foundation (v0.6.0 Phases 25-26) in three directions:
1. **UWP app identity** — AUMID resolution for Store apps and Desktop Bridge apps
2. **Drag-and-drop enforcement** — OLE interception as a new exfiltration vector
3. **Browser origin policies** — Origin-level granularity in Chrome Enterprise Connector

All three features are **extensions of existing subsystems**, not new architectural layers. The four-layer defense stack (Identity/Access/Policy/Enforcement) remains unchanged.

**Key architectural decision:** Phase 39 (UWP AUMID) must ship first because it changes the shared `AppIdentity` schema that Phases 40 and 42 depend on. Phases 40 and 41 are independent of each other but both depend on Phase 39.

---

## Recommended Architecture

### High-Level Component Changes

```
dlp-common (shared types)
  └─ AppIdentity ──[ADD]──> aumid: Option<String>
  └─ AbacContext ──[ADD]──> source_origin, destination_origin
  └─ AuditEvent ──[ADD]──> source_origin, destination_origin, drag_drop fields

dlp-agent (Windows Service)
  └─ detection/app_identity.rs ──[EXTEND]──> AUMID fallback resolution
  └─ interception/drag_drop.rs ──[NEW]──> IDropTarget hook, policy evaluation
  └─ chrome/ ──[EXTEND]──> origin field extraction from protobuf
  └─ run_event_loop ──[EXTEND]──> drag_drop check before USB check

dlp-server (HTTP API)
  └─ admin_api.rs ──[EXTEND]──> managed-origins CRUD (already exists)
  └─ evaluate endpoint ──[EXTEND]──> origin attribute evaluation

dlp-admin-cli (TUI)
  └─ conditions builder ──[EXTEND]──> AUMID field, origin fields
  └─ managed-origins screen ──[EXTEND]──> origin policy authoring hints
```

---

## Component Details

### Phase 39: UWP App Identity (APP-07)

**Changes `AppIdentity` schema:**

```rust
// dlp-common/src/endpoint.rs
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppIdentity {
    pub image_path: Option<String>,
    pub publisher: Option<String>,
    pub trust_tier: Option<AppTrustTier>,
    pub hash: Option<String>,
    pub aumid: Option<String>,  // <-- NEW
}
```

**AUMID resolution logic (in `dlp-agent/src/detection/app_identity.rs`):**

```rust
fn resolve_app_identity(hwnd: HWND) -> AppIdentity {
    let mut identity = base_identity_from_hwnd(hwnd); // existing path
    
    // UWP fallback
    if is_uwp_host_process(&identity.image_path) {
        if let Ok(aumid) = get_aumid_from_window(hwnd) {
            identity.aumid = Some(aumid);
            // Derive publisher from AUMID package family
            identity.publisher = derive_publisher_from_aumid(&aumid);
        }
    }
    
    identity
}
```

**ABAC integration:**
- Add `AppField::Aumid` to the `AppField` enum
- Add `aumid` arm to `condition_matches()` in policy evaluator
- Add AUMID to admin CLI conditions builder (Step 1 attribute picker)

**Where it lives:** `dlp-agent/src/detection/app_identity.rs` (extend), `dlp-common/src/abac.rs` (extend), `dlp-common/src/endpoint.rs` (extend)

---

### Phase 40: Drag-and-Drop Enforcement (APP-08)

**New component: `DragDropEnforcer`**

```rust
// dlp-agent/src/interception/drag_drop.rs
pub struct DragDropEnforcer {
    policy_store: Arc<PolicyStore>,
    audit_emitter: AuditEmitter,
    cooldown: RwLock<HashMap<(String, String), Instant>>, // (source, dest) → last_notify
}

impl DragDropEnforcer {
    pub fn check_drop(&self, source: &AppIdentity, dest: &AppIdentity, data: &DropData) -> Decision {
        let context = AbacContext {
            source_application: Some(source.clone()),
            destination_application: Some(dest.clone()),
            ..Default::default()
        };
        self.policy_store.evaluate(&context)
    }
}
```

**Integration into `run_event_loop`:**

```
run_event_loop:
  1. File interception check
  2. Disk enforcer check (pre-ABAC)
  3. USB enforcer check (pre-ABAC)
  4. Drag-drop check (pre-ABAC) ← NEW
  5. ABAC evaluation
```

**IPC changes:**
- New `Pipe3AgentMsg::DragDropAlert` variant
- Agent receives drag-drop events from UI process (if UI handles the hook) or from agent's global hook

**Toast notification:**
- Reuse existing toast infrastructure from Phase 27
- 5-second cooldown per (source, destination) pair

**Where it lives:** `dlp-agent/src/interception/drag_drop.rs` (new), `dlp-agent/src/interception/mod.rs` (extend), `dlp-common/src/ipc/pipe3.rs` (extend)

---

### Phase 41: Browser Origin Clipboard Policies (BRW-04)

**Chrome Enterprise Connector extension:**

The existing `dlp-agent/src/chrome/dispatch.rs` handles `ContentAnalysisRequest` from Chrome. Extend it to:

1. Extract `source_url` and `destination_url` from the request (if Chrome sends them)
2. Look up origins in the managed-origins cache (already built in Phase 29)
3. Build `AbacContext` with `source_origin` and `destination_origin`
4. Evaluate policy with origin attributes

**ABAC integration:**

```rust
// dlp-common/src/abac.rs
pub struct AbacContext {
    // ... existing fields ...
    pub source_origin: Option<String>,      // <-- NEW
    pub destination_origin: Option<String>, // <-- NEW
}

// New condition attributes
pub enum Attribute {
    // ... existing ...
    SourceOrigin,      // <-- NEW
    DestinationOrigin, // <-- NEW
}
```

**Policy examples:**
- `IF source_origin matches managed-origins AND destination_origin NOT in managed-origins AND classification >= T2 THEN DENY`
- `IF destination_origin contains "chatgpt" AND classification >= T3 THEN DENY`

**Where it lives:** `dlp-agent/src/chrome/` (extend), `dlp-common/src/abac.rs` (extend), `dlp-server/src/admin_api.rs` (extend managed-origins if needed)

---

### Phase 42: Audit Enrichment (AUDIT-04)

**Audit event schema update:**

```rust
// dlp-common/src/audit.rs
pub struct AuditEvent {
    // ... existing fields ...
    pub source_application: Option<AppIdentity>,      // ensure populated
    pub destination_application: Option<AppIdentity>, // ensure populated
    pub source_origin: Option<String>,                // <-- NEW
    pub destination_origin: Option<String>,           // <-- NEW
    pub drag_drop_source: Option<AppIdentity>,        // <-- NEW
    pub drag_drop_destination: Option<AppIdentity>,   // <-- NEW
}
```

**Validation sweep:**
- File interception: verify `source_application` / `destination_application` populated
- USB interception: verify `device_identity` populated (already done in v0.7.1)
- Clipboard interception: verify both source and destination app identity populated
- Drag-and-drop: verify new fields populated
- Browser events: verify origin fields populated

**Where it lives:** `dlp-common/src/audit.rs` (extend), `dlp-agent/src/audit_emitter.rs` (extend all emit paths)

---

## Integration Points

| Phase | New/Modified | Consumes | Consumed By |
|-------|-------------|----------|-------------|
| 39 UWP AUMID | `AppIdentity.aumid`, `AppField::Aumid` | existing `AppIdentity` | Phase 40, 42 |
| 40 Drag-Drop | `DragDropEnforcer`, `Pipe3AgentMsg::DragDropAlert` | Phase 39 `AppIdentity` | Phase 42 |
| 41 Browser Origin | `AbacContext` origin fields, `Attribute::SourceOrigin` | existing Chrome connector | Phase 42 |
| 42 Audit | `AuditEvent` extended fields | Phases 39, 40, 41 | SIEM relay, alert router |

---

## Phase Ordering Rationale

1. **Phase 39 first:** Changes shared `AppIdentity` schema. All subsequent phases need `aumid` field.
2. **Phases 40 and 41 in parallel:** Independent of each other. Both depend on Phase 39.
3. **Phase 42 last:** Validation/cleanup phase. Needs all other phases complete to verify audit coverage.

---

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Schema change ripple | HIGH | Rust compiler enforces exhaustive match; all sites must be updated |
| AUMID API | HIGH | Stable Win32 API |
| Drag-drop COM | MEDIUM-HIGH | Complex but well-documented |
| Chrome origin fields | MEDIUM | Version-dependent |
| Audit pipeline | HIGH | Reuses existing infrastructure |

---

## Sources

- `dlp-common/src/endpoint.rs` — existing `AppIdentity`, `DeviceIdentity`
- `dlp-common/src/abac.rs` — existing `AbacContext`, `Attribute`
- `dlp-common/src/audit.rs` — existing `AuditEvent`
- `dlp-agent/src/detection/app_identity.rs` — existing process identity resolution
- `dlp-agent/src/chrome/` — existing Chrome Enterprise Connector
- `dlp-agent/src/interception/mod.rs` — existing event loop
- Microsoft Learn — Application User Model IDs
- Microsoft Learn — OLE Drag and Drop
