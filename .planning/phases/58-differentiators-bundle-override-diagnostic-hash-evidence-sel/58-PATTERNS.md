# Phase 58: Differentiators Bundle - Pattern Map

**Mapped:** 2026-06-02
**Files analyzed:** 16
**Analogs found:** 14 / 16

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `dlp-hook-dll/src/diagnostic_ring.rs` | utility | event-driven | `dlp-hook-dll/src/hook_journal.rs` | exact |
| `dlp-hook-dll/src/hash_compute.rs` | utility | transform | `dlp-hook-dll/src/perf_telemetry.rs` | role-match |
| `dlp-hook-dll/src/health_counters.rs` | utility | event-driven | `dlp-hook-dll/src/perf_telemetry.rs` | exact |
| `dlp-agent/src/diagnostic_aggregator.rs` | service | CRUD | `dlp-agent/src/approval_cache.rs` | role-match |
| `dlp-agent/src/health_aggregator.rs` | service | event-driven | `dlp-agent/src/approval_cache.rs` | role-match |
| `dlp-server/src/admin_api.rs` | controller | request-response | `dlp-server/src/admin_api.rs` (list_bypass_alerts_handler) | exact (same file) |
| `dlp-admin-cli/src/screens/diagnostic_list.rs` | component | request-response | `dlp-admin-cli/src/screens/bypass_alerts.rs` | exact |
| `dlp-admin-cli/src/screens/self_health_dashboard.rs` | component | request-response | `dlp-admin-cli/src/screens/bypass_alerts.rs` | exact |
| `dlp-common/src/hook_ipc.rs` | model | request-response | `dlp-common/src/hook_ipc.rs` (existing variants) | exact (same file) |
| `dlp-common/src/audit.rs` | model | event-driven | `dlp-common/src/audit.rs` (existing fields) | exact (same file) |
| `dlp-hook-dll/src/trampolines.rs` | middleware | request-response | `dlp-hook-dll/src/trampolines.rs` (HookWriteFile) | exact (same file) |
| `dlp-hook-dll/src/perf_telemetry.rs` | utility | event-driven | `dlp-hook-dll/src/perf_telemetry.rs` | exact (same file) |
| `dlp-agent/src/interception/mod.rs` | service | event-driven | `dlp-agent/src/interception/mod.rs` (run_event_loop) | exact (same file) |
| `dlp-admin-cli/src/app.rs` | model | config | `dlp-admin-cli/src/app.rs` (Screen enum) | exact (same file) |
| `dlp-admin-cli/src/client.rs` | utility | request-response | `dlp-admin-cli/src/client.rs` (list_bypass_alerts) | exact (same file) |
| `dlp-admin-cli/src/screens/dispatch.rs` | component | event-driven | `dlp-admin-cli/src/screens/dispatch.rs` (handle_bypass_alert_list) | exact (same file) |

## Pattern Assignments

### `dlp-hook-dll/src/diagnostic_ring.rs` (utility, event-driven)

**Analog:** `dlp-hook-dll/src/hook_journal.rs`

**Imports pattern** (lines 1-31):
```rust
use std::sync::atomic::{fence, Ordering};
use std::sync::OnceLock;

use windows::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, INVALID_HANDLE_VALUE};
use windows::Win32::System::Memory::{
    CreateFileMappingW, MapViewOfFile, OpenFileMappingW, FILE_MAP_ALL_ACCESS,
    MEMORY_MAPPED_VIEW_ADDRESS, PAGE_READWRITE,
};
```

**Core ring buffer pattern** (lines 36-44, 89-128, 235-287):
```rust
/// Total size of the shared-memory journal mapping (64 KiB).
const JOURNAL_SIZE: usize = 64 * 1024;
/// Size of each journal entry in bytes.
const ENTRY_SIZE: usize = 56;
/// Number of entries that fit in the ring buffer after the header.
const ENTRY_CAPACITY: usize = (JOURNAL_SIZE - std::mem::size_of::<JournalHeader>()) / ENTRY_SIZE;

/// Global lazy-initialized journal instance.
static JOURNAL: OnceLock<Option<HookJournal>> = OnceLock::new();

impl HookJournal {
    pub fn get() -> Option<&'static HookJournal> {
        let opt = JOURNAL.get_or_init(|| {
            unsafe { Self::try_init() }
        });
        opt.as_ref()
    }

    unsafe fn try_init() -> Option<HookJournal> {
        let pid = std::process::id();
        let name = format!("Global\\DlpHookJournal_{}", pid);
        // ... CreateFileMappingW / OpenFileMappingW / MapViewOfFile
    }
}
```

**Write API pattern** (lines 235-287):
```rust
pub fn journal_write(handle_value: u64, op: u8, path: &str, ts_qpc: u64, etw_timestamp: u64) {
    let Some(journal) = HookJournal::get() else { return; };
    let path_hash = dlp_common::fnv1a_64(path.as_bytes());
    unsafe {
        let write_index = std::ptr::read_volatile(std::ptr::addr_of!((*journal.header).write_index));
        let slot = write_index as usize % journal.capacity;
        let entry_ptr = journal.entries.add(slot);
        std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).seq), seq);
        // ... write all fields
        fence(Ordering::Release);
        let new_write_index = write_index.wrapping_add(1);
        std::ptr::write_volatile(std::ptr::addr_of_mut!((*journal.header).write_index), new_write_index);
    }
}
```

**Key adaptation for diagnostic_ring.rs:**
- Use `crossbeam::queue::ArrayQueue` instead of shared-memory (DIFF-02 is in-memory only, not shared-memory).
- Follow the same `OnceLock` lazy-init pattern (NOT from DllMain).
- Use `std::sync::OnceLock<ArrayQueue<DiagnosticSnapshot>>` with `RING_CAPACITY = 1000`.
- Push silently drops oldest on full (`let _ = ring.push(snapshot);`).
- Include 1-hour lazy eviction by checking `timestamp_qpc` during drain.

---

### `dlp-hook-dll/src/hash_compute.rs` (utility, transform)

**Analog:** `dlp-hook-dll/src/perf_telemetry.rs` (thread pool + lazy init pattern)

**Lazy thread pool initialization pattern** (lines 43-58):
```rust
static FAIL_STATE: OnceLock<Arc<FailModeState>> = OnceLock::new();

fn get_fail_state() -> &'static Arc<FailModeState> {
    FAIL_STATE.get_or_init(|| {
        let state = Arc::new(FailModeState::new());
        // ... background thread start
        state
    })
}
```

**Thread-local buffer pattern** (from `pipe_client.rs`, lines 17-25):
```rust
thread_local! {
    pub static PIPE_BUFFER: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(4096));
}
```

**Core hash computation pattern** (from RESEARCH.md):
```rust
use rayon::{ThreadPool, ThreadPoolBuilder};
use sha2::{Sha256, Digest};
use std::sync::OnceLock;

static HASH_POOL: OnceLock<ThreadPool> = OnceLock::new();
const HASH_CAP_BYTES: usize = 100 * 1024 * 1024; // 100MB

fn get_hash_pool() -> &'static ThreadPool {
    HASH_POOL.get_or_init(|| {
        ThreadPoolBuilder::new()
            .num_threads(2)
            .thread_name(|i| format!("dlp-hash-{i}"))
            .build()
            .expect("hash pool creation")
    })
}

pub fn compute_content_hash(buffer: *const u8, len: u32) -> (Option<String>, bool, bool) {
    if buffer.is_null() || len == 0 {
        return (None, false, false);
    }
    let actual_len = (len as usize).min(HASH_CAP_BYTES);
    let truncated = (len as usize) > HASH_CAP_BYTES;
    let slice = unsafe { std::slice::from_raw_parts(buffer, actual_len) };
    let mut hasher = Sha256::new();
    hasher.update(slice);
    let result = hasher.finalize();
    let hex = hex::encode(result);
    (Some(hex), truncated, false)
}
```

**Key adaptation:**
- Initialize `HASH_POOL` from first trampoline invocation (NOT DllMain).
- For buffers < 64KB, compute inline; for larger, use `get_hash_pool().install(|| compute_content_hash(...))`.
- Return `(Option<String>, bool, bool)` = (hash, truncated, skipped).
- If pool is saturated, return `(None, false, true)`.

---

### `dlp-hook-dll/src/health_counters.rs` (utility, event-driven)

**Analog:** `dlp-hook-dll/src/perf_telemetry.rs`

**Imports pattern** (lines 1-24):
```rust
use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};
use crate::fail_mode::FailState;
```

**Atomic counter + thread-local pattern** (lines 58-85, 173-175):
```rust
pub struct PerfTelemetry {
    buckets: [AtomicU64; BUCKET_COUNT],
    call_count: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
}

impl PerfTelemetry {
    pub fn new() -> Self {
        let buckets: [AtomicU64; BUCKET_COUNT] = std::array::from_fn(|_| AtomicU64::new(0));
        Self { buckets, call_count: AtomicU64::new(0), cache_hits: AtomicU64::new(0), cache_misses: AtomicU64::new(0) }
    }
}

thread_local! {
    static TELEMETRY: RefCell<PerfTelemetry> = RefCell::new(PerfTelemetry::new());
}
```

**Emission cadence pattern** (lines 98-117):
```rust
pub fn record_latency(&self, elapsed_qpc: u64, is_cache_hit: bool) {
    let count = self.call_count.fetch_add(1, Ordering::Relaxed) + 1;
    if is_cache_hit {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    } else {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }
    if count.is_multiple_of(EMIT_INTERVAL) {
        self.emit_telemetry();
    }
}
```

**Key adaptation for health_counters.rs:**
- Extend `PerfTelemetry` with `HealthCounters` struct containing `AtomicU64` fields.
- Add `injected_pids`, `patched_modules`, `pipe_round_trips_60s`, `cache_hits_60s`, `cache_misses_60s`, `current_fail_state: AtomicU8`.
- Emit alongside existing telemetry every 1000 calls (D-18, D-19).
- Compute `cache_hit_rate_60s` as `hits / (hits + misses)` at emission time.
- Include `timestamp_secs` in emitted `HookHealthSnapshot`.

---

### `dlp-agent/src/diagnostic_aggregator.rs` (service, CRUD)

**Analog:** `dlp-agent/src/approval_cache.rs`

**Imports pattern** (lines 1-37):
```rust
use std::sync::Arc;
use chrono::Utc;
use dashmap::DashMap;
use dlp_common::approval::{ApprovalCacheKey, ApprovalClaims, CachedApproval};
use dlp_common::{Decision, EvaluateResponse};
use tracing::{debug, warn};
```

**DashMap + Arc pattern** (lines 54-70):
```rust
#[derive(Debug, Clone)]
pub struct ApprovalCache {
    pub cache: Arc<DashMap<String, CachedApproval>>,
    verifying_key: Arc<std::sync::RwLock<Option<ed25519_dalek::VerifyingKey>>>,
}

impl ApprovalCache {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(DashMap::new()),
            verifying_key: Arc::new(std::sync::RwLock::new(None)),
        }
    }
}
```

**Periodic sweep pattern** (lines 210-225):
```rust
pub fn sweep_expired(&self) {
    let now = Utc::now();
    let to_remove: Vec<String> = self
        .cache
        .iter()
        .filter(|e| now > e.expires_at)
        .map(|e| e.key().clone())
        .collect();
    for key in to_remove {
        self.cache.remove(&key);
    }
}
```

**Key adaptation for diagnostic_aggregator.rs:**
- Use `DashMap<String, Vec<DiagnosticSnapshot>>` keyed by `pid` or `agent_id`.
- Poll every 30s via named pipe (`HookMessage::PullDiagnostics`).
- Aggregate snapshots in-memory; no persistence.
- Serve via agent-side API or forward to server.
- Support filtering by `since`, `user_sid`, `policy_id`.

---

### `dlp-agent/src/health_aggregator.rs` (service, event-driven)

**Analog:** `dlp-agent/src/approval_cache.rs` + `dlp-server/src/alert_router.rs`

**Alert emission pattern** (from `alert_router.rs`, lines 271-322):
```rust
pub async fn send_alert(&self, event: &AuditEvent) -> Result<(), AlertError> {
    let row = self.load_config()?;
    let mut errors: Vec<AlertError> = Vec::new();
    // SMTP path
    if row.smtp_enabled && !row.smtp_host.is_empty() && !row.smtp_to.is_empty() {
        // ... send_email
    }
    // Webhook path
    if row.webhook_enabled && !row.webhook_url.is_empty() {
        // ... send_webhook
    }
    if let Some(e) = errors.into_iter().next() {
        return Err(e);
    }
    Ok(())
}
```

**Audit event construction** (from `alert_router.rs`, lines 337-374):
```rust
let event = AuditEvent {
    timestamp: chrono::Utc::now(),
    event_type: dlp_common::EventType::Alert,
    user_sid: "S-1-5-18".to_string(),
    // ... other fields
};
```

**Key adaptation for health_aggregator.rs:**
- Poll every 60s via named pipe (`HookMessage::PullHealth`).
- Store last 12 snapshots per host in `VecDeque<HookHealthSnapshot>`.
- Compute thresholds: Healthy (cache_hit_rate >= 80%, fail_state == Healthy, pipe_round_trips > 0), Degraded, Critical.
- On transition from Healthy -> Degraded for 2 consecutive polls, emit `siem.hook_health_degraded` audit event at `warn` severity.
- On transition to Critical, emit at `crit` severity and route through `alert_router::send`.

---

### `dlp-server/src/admin_api.rs` (controller, request-response)

**Analog:** `dlp-server/src/admin_api.rs` (`list_bypass_alerts_handler`, lines 5380-5413)

**Handler pattern** (lines 5380-5413):
```rust
async fn list_bypass_alerts_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(q): axum::extract::Query<BypassAlertQuery>,
) -> Result<Json<BypassAlertListResponse>, AppError> {
    let severity_list = q.severity.map(|s| {
        s.split(',')
            .map(|part| part.trim().to_string())
            .filter(|part| !part.is_empty())
            .collect::<Vec<String>>()
    });
    let filter = BypassAlertFilter {
        since: q.since,
        severity: severity_list,
        acknowledged: q.acknowledged,
        agent_id: q.agent_id,
        pid: q.pid,
        limit: q.limit,
        offset: q.offset,
    };
    let pool = Arc::clone(&state.pool);
    let rows = tokio::task::spawn_blocking(move || -> Result<Vec<BypassAlertRow>, AppError> {
        BypassAlertsRepository::list_by_filters(&pool, &filter).map_err(AppError::Database)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;
    let total = rows.len();
    Ok(Json(BypassAlertListResponse { total, alerts: rows }))
}
```

**Route registration pattern** (lines 1275-1280):
```rust
.route("/admin/bypass-alerts", get(list_bypass_alerts_handler))
.route(
    "/admin/bypass-alerts/{id}/ack",
    post(ack_bypass_alert_handler),
)
```

**Key adaptation:**
- Add `GET /admin/diagnostics` handler following the same `Query<T>` + `spawn_blocking` + repository pattern.
- Query struct: `since: Option<String>`, `user_sid: Option<String>`, `policy_id: Option<String>`, `limit: Option<usize>`, `offset: Option<usize>`.
- Response struct: `DiagnosticListResponse { total: usize, snapshots: Vec<DiagnosticSnapshot> }`.
- No DB persistence — data comes from in-memory agent aggregation.

---

### `dlp-admin-cli/src/screens/diagnostic_list.rs` (component, request-response)

**Analog:** `dlp-admin-cli/src/screens/bypass_alerts.rs` + `dispatch.rs` + `render.rs`

**Screen constants pattern** (from `bypass_alerts.rs`, lines 1-15):
```rust
pub const BYPASS_ALERT_LIST_HINTS: &str =
    "[a] Ack  [f] Filter Severity  [h] Hide Ack'd  [r] Refresh  [Enter] Detail  [PgUp/PgDn] Page  [Esc] Back";
pub const BYPASS_ALERT_LIST_EMPTY: &str = "No bypass alerts found.";
```

**Dispatch handler pattern** (from `dispatch.rs`, lines 7741-7859):
```rust
fn handle_bypass_alert_list(app: &mut App, key: KeyEvent) {
    let (alerts, selected, filter, hide_acknowledged, page, page_size, total, pending_ack_ids) =
        match &mut app.screen { ... };
    match key.code {
        KeyCode::Up | KeyCode::Down => { nav(selected, alerts.len(), key.code); }
        KeyCode::Char('f') => { action_load_bypass_alert_list(app, filter.next(), hide_acknowledged, 0); }
        KeyCode::Enter => { app.screen = Screen::BypassAlertDetail { alert: alert.clone() }; }
        KeyCode::Esc => app.screen = Screen::SystemMenu { selected: 11 },
        _ => {}
    }
}
```

**Action loader pattern** (from `dispatch.rs`, lines 7872-7927):
```rust
fn action_load_bypass_alert_list(app: &mut App, filter: BypassAlertSeverityFilter, hide_acknowledged: bool, page: usize) {
    let page_size = 20usize;
    let severity_filter = filter.as_str();
    let ack_filter = if hide_acknowledged { Some(false) } else { None };
    let offset = page * page_size;
    match app.rt.block_on(app.client.list_bypass_alerts(severity_filter, ack_filter, page_size, offset)) {
        Ok(response) => {
            let alerts = response.get("alerts").and_then(|a| a.as_array()).cloned().unwrap_or_default();
            let total = response.get("total").and_then(|t| t.as_u64()).map(|t| t as usize).unwrap_or(alerts.len());
            app.screen = Screen::BypassAlertList { alerts, selected: 0, filter, hide_acknowledged, page, page_size, total, pending_ack_ids: std::collections::HashSet::new() };
        }
        Err(e) => { app.set_status(format!("Error loading bypass alerts: {e}"), StatusKind::Error); }
    }
}
```

**Render pattern** (from `render.rs`, lines 4148-4287):
```rust
fn draw_bypass_alert_list(
    frame: &mut Frame, area: Rect, alerts: &[serde_json::Value],
    selected: usize, filter: BypassAlertSeverityFilter, hide_acknowledged: bool,
    page: usize, page_size: usize, total: usize,
) {
    if alerts.is_empty() {
        let paragraph = Paragraph::new(BYPASS_ALERT_LIST_EMPTY)
            .block(Block::default().title(" Bypass Alerts (0) ").borders(Borders::ALL))
            .alignment(Alignment::Center);
        frame.render_widget(paragraph, area);
        draw_hints(frame, area, BYPASS_ALERT_LIST_HINTS);
        return;
    }
    let header = Row::new(vec!["Severity", "Time", "Image", "File", "Reason"])
        .style(Style::default().add_modifier(Modifier::BOLD));
    let rows: Vec<Row> = alerts.iter().map(|a| { ... }).collect();
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().title(" Bypass Alerts ").borders(Borders::ALL))
        .row_highlight_style(Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD))
        .highlight_symbol("> ");
    let mut state = ratatui::widgets::TableState::default();
    state.select(Some(selected));
    frame.render_stateful_widget(table, area, &mut state);
}
```

**Key adaptation for diagnostic_list.rs:**
- Create `diagnostic_list.rs` with constants `DIAGNOSTIC_LIST_HINTS` and `DIAGNOSTIC_LIST_EMPTY`.
- Add `Screen::DiagnosticList` variant to `app.rs` with fields: `snapshots: Vec<serde_json::Value>`, `selected: usize`, `filter: DiagnosticFilter`, `page: usize`, `page_size: usize`, `total: usize`.
- Add `DiagnosticFilter` enum (All, CacheHit, CacheMiss, Pipe) with `next()` and `as_str()` methods.
- Implement `handle_diagnostic_list()` in `dispatch.rs` following `handle_bypass_alert_list` pattern.
- Implement `draw_diagnostic_list()` in `render.rs` with columns: Time, User, Path, Tier, Policy, Latency, Source.
- Implement `draw_diagnostic_detail()` popup showing full ABAC context as nested key-value pairs.
- Add `action_load_diagnostic_list()` that calls `app.client.list_diagnostics(filter, page_size, offset)`.

---

### `dlp-admin-cli/src/screens/self_health_dashboard.rs` (component, request-response)

**Analog:** `dlp-admin-cli/src/screens/bypass_alerts.rs` + `render.rs`

**Sparkline pattern** (from RESEARCH.md / ratatui 0.29):
```rust
use ratatui::widgets::{Sparkline, Block, Borders};

let sparkline = Sparkline::default()
    .block(Block::default().title("Cache Hit Rate (5 min)").borders(Borders::ALL))
    .data(&hit_rate_data)
    .style(Style::default().fg(Color::Green));
frame.render_widget(sparkline, area);
```

**Key adaptation for self_health_dashboard.rs:**
- Create `self_health_dashboard.rs` with constants `SELF_HEALTH_HINTS`.
- Add `Screen::SelfHealthDashboard` variant to `app.rs` with fields: `snapshot: Option<HookHealthSnapshot>`, `history: Vec<HookHealthSnapshot>`, `selected_tab: usize`.
- Implement `handle_self_health_dashboard()` in `dispatch.rs` — read-only, only `r` refresh and `Esc` back.
- Implement `draw_self_health_dashboard()` in `render.rs`:
  - Top half: current snapshot with color-coded status (green=Healthy, yellow=Degraded, red=Isolated/Critical).
  - Bottom half: two `Sparkline` widgets for `cache_hit_rate` and `pipe_round_trips` over last 5 minutes.
  - Color sparkline green above 80%, yellow 60-80%, red below 60%.
- Add `action_load_self_health()` that calls `app.client.get_self_health()`.

---

### `dlp-common/src/hook_ipc.rs` (model, request-response)

**Analog:** `dlp-common/src/hook_ipc.rs` (existing `IpcPayloadV1` enum)

**Enum extension pattern** (lines 74-92):
```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IpcPayloadV1 {
    Request(HookRequest),
    Response(HookResponse),
    VolumeClassQuery(VolumeClassQuery),
    VolumeClassResponse(VolumeClassResponse),
}
```

**Key adaptation:**
- Add variants to `IpcPayloadV1`:
  ```rust
  RequestOverride(OverrideRequest),
  PullDiagnostics(PullDiagnosticsRequest),
  DiagnosticsResponse(DiagnosticsResponse),
  PullHealth(PullHealthRequest),
  HealthResponse(HealthResponse),
  ```
- Add structs:
  ```rust
  #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
  pub struct OverrideRequest { pub requester_sid: String, pub data_object_id: String, pub action: String, pub destination_scope: Option<String>, pub justification: String, pub resource_path: String }
  
  #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
  pub struct PullDiagnosticsRequest { pub max_entries: usize }
  
  #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
  pub struct DiagnosticsResponse { pub snapshots: Vec<DiagnosticSnapshot> }
  
  #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
  pub struct PullHealthRequest;
  
  #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
  pub struct HealthResponse { pub snapshot: HookHealthSnapshot }
  ```
- Use `#[serde(default)]` on all new fields for backward compat.

---

### `dlp-common/src/audit.rs` (model, event-driven)

**Analog:** `dlp-common/src/audit.rs` (existing optional fields)

**Optional field pattern** (lines 176-296):
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    // ... existing fields ...
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_mode: Option<String>,
    #[serde(default)]
    pub would_have_denied: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume_class: Option<crate::VolumeClass>,
}
```

**Builder method pattern** (lines 361-559):
```rust
pub fn with_policy(mut self, policy_id: String, policy_name: String) -> Self {
    self.policy_id = Some(policy_id);
    self.policy_name = Some(policy_name);
    self
}
```

**Key adaptation:**
- Add fields to `AuditEvent`:
  ```rust
  #[serde(skip_serializing_if = "Option::is_none")]
  pub content_sha256: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub hash_truncated: Option<bool>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub hash_skipped: Option<bool>,
  ```
- Add builder method:
  ```rust
  pub fn with_content_hash(mut self, hash: String, truncated: bool, skipped: bool) -> Self {
      self.content_sha256 = Some(hash);
      self.hash_truncated = Some(truncated);
      self.hash_skipped = Some(skipped);
      self
  }
  ```

---

### `dlp-hook-dll/src/trampolines.rs` (middleware, request-response)

**Analog:** `dlp-hook-dll/src/trampolines.rs` (`HookWriteFile`, lines 627-696)

**Trampoline deny pattern** (lines 638-645):
```rust
crate::crash_guard::with_reentrancy_guard(
    || {
        let handle_value = hfile.0 as u64;
        if let Some(_deny) = classify_and_log_handle(handle_value, "WRITE", "WriteFile", 2, "") {
            return crate::fail_closed!(BoolFalse);
        }
        // ... call original
    },
    || { /* fallback */ }
)
```

**Key adaptation for DIFF-03 (hash) + DIFF-02 (diagnostic) + DIFF-01 (override):**
- In `HookWriteFile` and `HookWriteFileEx`, after `classify_and_log_handle` returns `Some(deny)`:
  1. Compute content hash: `let (hash, truncated, skipped) = crate::hash_compute::compute_content_hash(lpbuffer, nnumberofbytestowrite);`
  2. Emit diagnostic snapshot: `crate::diagnostic_ring::push_snapshot(DiagnosticSnapshot { ... });`
  3. Request override: `let _ = crate::pipe_client::send_override_request(...);` (fire-and-forget via pipe)
  4. Attach hash to audit event (forwarded through agent).
- For `WriteFileEx` with OVERLAPPED: compute hash synchronously before returning (D-17).

---

### `dlp-admin-cli/src/app.rs` (model, config)

**Analog:** `dlp-admin-cli/src/app.rs` (existing `Screen` enum variants)

**Screen enum pattern** (lines 1177-1197):
```rust
BypassAlertList {
    alerts: Vec<serde_json::Value>,
    selected: usize,
    filter: BypassAlertSeverityFilter,
    hide_acknowledged: bool,
    page: usize,
    page_size: usize,
    total: usize,
    pending_ack_ids: std::collections::HashSet<i64>,
},
BypassAlertDetail { alert: serde_json::Value },
```

**Key adaptation:**
- Add `Screen::DiagnosticList` variant with fields matching `BypassAlertList` pattern.
- Add `Screen::DiagnosticDetail` variant with `snapshot: serde_json::Value`.
- Add `Screen::SelfHealthDashboard` variant with `snapshot: Option<serde_json::Value>`, `history: Vec<serde_json::Value>`, `selected_tab: usize`.
- Add `DiagnosticFilter` enum (All, CacheHit, CacheMiss, Pipe) with `next()` and `as_str()` methods, following `BypassAlertSeverityFilter` pattern.

---

### `dlp-admin-cli/src/client.rs` (utility, request-response)

**Analog:** `dlp-admin-cli/src/client.rs` (`list_bypass_alerts`, lines 589-604)

**Client method pattern** (lines 589-604):
```rust
pub async fn list_bypass_alerts(
    &self,
    severity: Option<&str>,
    acknowledged: Option<bool>,
    limit: usize,
    offset: usize,
) -> Result<serde_json::Value> {
    let mut path = format!("admin/bypass-alerts?limit={limit}&offset={offset}");
    if let Some(s) = severity {
        path.push_str(&format!("&severity={}", urlencoding::encode(s)));
    }
    if let Some(a) = acknowledged {
        path.push_str(&format!("&acknowledged={a}"));
    }
    self.get(&path).await
}
```

**Key adaptation:**
- Add `list_diagnostics(&self, since: Option<&str>, user_sid: Option<&str>, policy_id: Option<&str>, limit: usize, offset: usize) -> Result<serde_json::Value>`.
- Add `get_self_health(&self) -> Result<serde_json::Value>`.
- Follow same query parameter building pattern with `urlencoding::encode`.

---

## Shared Patterns

### Authentication
**Source:** `dlp-server/src/admin_api.rs` (line 1282)
**Apply to:** All new admin API endpoints (`GET /admin/diagnostics`)
```rust
.route_layer(middleware::from_fn(admin_auth::require_auth))
```
All new `/admin/*` routes are automatically protected by the existing JWT auth middleware.

### Error Handling
**Source:** `dlp-server/src/admin_api.rs` (lines 1320-1353)
**Apply to:** All new server handlers
```rust
async fn list_policies(State(state): State<Arc<AppState>>) -> Result<Json<Vec<PolicyResponse>>, AppError> {
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);
    let rows = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        // ... DB work
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;
    Ok(Json(rows))
}
```

### Rate Limiting
**Source:** `dlp-server/src/admin_api.rs` (lines 1065-1282)
**Apply to:** New `/admin/diagnostics` endpoint
New admin routes fall under the `default_config()` rate limiter (100/min) applied to all protected routes.

### TUI Screen Pattern
**Source:** `dlp-admin-cli/src/screens/` (four-file pattern)
**Apply to:** `diagnostic_list.rs`, `self_health_dashboard.rs`
Every TUI screen follows:
1. `screens/<name>.rs` — constants (hints, empty messages)
2. `dispatch.rs` — `handle_<name>()` event handler + `action_load_<name>()` loader
3. `render.rs` — `draw_<name>()` ratatui widget function
4. `client.rs` — HTTP client method for API calls
5. `app.rs` — `Screen::<Name>` enum variant

### Hook DLL Lazy Initialization
**Source:** `dlp-hook-dll/src/hook_journal.rs` (lines 111-128), `perf_telemetry.rs` (lines 43-58)
**Apply to:** `diagnostic_ring.rs`, `hash_compute.rs`, `health_counters.rs`
```rust
static THING: OnceLock<Option<Thing>> = OnceLock::new();

pub fn get() -> Option<&'static Thing> {
    THING.get_or_init(|| unsafe { Self::try_init() })
}
```
CRITICAL: All `OnceLock` initialization must happen from the first trampoline invocation, NOT from `DllMain`.

### IPC Versioned Envelope
**Source:** `dlp-common/src/hook_ipc.rs` (lines 56-92)
**Apply to:** All new IPC types
```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IpcPayloadV1 {
    // existing variants...
    // NEW variants added at end
}
```
All new fields must use `#[serde(default)]` for JSON backward compat. Bincode requires exact layout match — use a new protocol version if needed.

### Audit Event Builder
**Source:** `dlp-common/src/audit.rs` (lines 298-559)
**Apply to:** All new audit event fields
```rust
pub fn with_<field>(mut self, value: T) -> Self {
    self.field = Some(value);
    self
}
```
Optional fields use `#[serde(skip_serializing_if = "Option::is_none")]`.

## No Analog Found

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| None | — | — | All files have strong analogs in the codebase |

## Metadata

**Analog search scope:** `dlp-hook-dll/src/`, `dlp-agent/src/`, `dlp-server/src/`, `dlp-admin-cli/src/`, `dlp-common/src/`
**Files scanned:** 20+
**Pattern extraction date:** 2026-06-02
