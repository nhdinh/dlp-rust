# Phase 53: ETW Kernel-File Consumer + Bypass Correlator + Hook Journal Ring - Pattern Map

**Mapped:** 2026-05-27
**Files analyzed:** 17
**Analogs found:** 16 / 17

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `dlp-agent/src/etw_kernel_file.rs` | producer | event-driven | `dlp-agent/src/process_watcher.rs` | exact |
| `dlp-agent/src/bypass_correlator.rs` | service | event-driven | `dlp-agent/src/service.rs` (spawn patterns) | role-match |
| `dlp-hook-dll/src/hook_journal.rs` | component | file-I/O | `dlp-hook-dll/src/classification_cache.rs` | role-match |
| `dlp-common/src/path_hash.rs` | utility | transform | `dlp-hook-dll/src/classification_cache.rs` (normalize_path) | role-match |
| `dlp-server/src/db/repositories/bypass_alerts.rs` | repository | CRUD | `dlp-server/src/db/repositories/labels.rs` | exact |
| `dlp-server/tests/bypass_alerts_integration.rs` | test | request-response | `dlp-server/tests/admin_audit_integration.rs` | role-match |
| `dlp-agent/tests/etw_consumer_integration.rs` | test | event-driven | `dlp-agent/src/process_watcher.rs` tests | role-match |
| `dlp-agent/src/lib.rs` | config | -- | `dlp-agent/src/lib.rs` (existing mod declarations) | exact |
| `dlp-agent/src/service.rs` | service | event-driven | `dlp-agent/src/service.rs` (ProcessWatcher init) | exact |
| `dlp-hook-dll/src/lib.rs` | config | -- | `dlp-hook-dll/src/lib.rs` (existing mod declarations) | exact |
| `dlp-hook-dll/src/trampolines.rs` | component | request-response | `dlp-hook-dll/src/trampolines.rs` (classify_and_log_path) | exact |
| `dlp-common/src/lib.rs` | config | -- | `dlp-common/src/lib.rs` (existing pub mod) | exact |
| `dlp-common/src/hook_ipc.rs` | model | -- | `dlp-common/src/hook_ipc.rs` (BypassReason enum) | exact |
| `dlp-server/src/lib.rs` | config | -- | `dlp-server/src/lib.rs` (AppState field additions) | exact |
| `dlp-server/src/admin_api.rs` | controller | request-response | `dlp-server/src/admin_api.rs` (protected_paths routes) | exact |
| `dlp-server/src/db/mod.rs` | config | -- | `dlp-server/src/db/mod.rs` (init_tables) | exact |
| `dlp-server/src/db/repositories/mod.rs` | config | -- | `dlp-server/src/db/repositories/mod.rs` | exact |
| `dlp-common/src/audit.rs` | model | -- | `dlp-common/src/audit.rs` (EventType additions) | exact |

## Pattern Assignments

### `dlp-agent/src/etw_kernel_file.rs` (producer, event-driven)

**Analog:** `dlp-agent/src/process_watcher.rs`

**Imports pattern** (lines 1-15):
```rust
use crossbeam_channel::{bounded, Receiver, Sender, TrySendError};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
```

**Core ETW consumer pattern** (lines 58-118):
```rust
pub struct ProcessWatcher {
    etw_shutdown: Arc<AtomicBool>,
    etw_handle: Option<thread::JoinHandle<()>>,
    event_tx: Sender<ProcessEvent>,
    event_rx: Receiver<ProcessEvent>,
    etw_healthy: Arc<AtomicBool>,
    overflow_count: AtomicUsize,
}

const CHANNEL_CAPACITY: usize = 1024;
const ETW_BUFFER_SIZE_KB: u32 = 256;
const ETW_BUFFER_COUNT: u32 = 200;

impl ProcessWatcher {
    pub fn new() -> Self {
        let (tx, rx) = bounded::<ProcessEvent>(CHANNEL_CAPACITY);
        Self {
            etw_shutdown: Arc::new(AtomicBool::new(false)),
            etw_handle: None,
            event_tx: tx,
            event_rx: rx,
            etw_healthy: Arc::new(AtomicBool::new(true)),
            overflow_count: AtomicUsize::new(0),
        }
    }

    pub fn start(&mut self, sweep_trigger: Sender<SweepTrigger>) -> anyhow::Result<()> {
        let tx = self.event_tx.clone();
        let shutdown = Arc::clone(&self.etw_shutdown);
        let healthy = Arc::clone(&self.etw_healthy);

        let handle = thread::Builder::new()
            .name("etw-process-watcher".into())
            .spawn(move || {
                run_etw_loop(tx, shutdown, healthy, sweep_trigger);
            })?;

        self.etw_handle = Some(handle);
        Ok(())
    }

    pub fn receiver(&self) -> &Receiver<ProcessEvent> {
        &self.event_rx
    }

    pub fn stop(&mut self) {
        self.etw_shutdown.store(true, Ordering::Relaxed);
        if let Some(h) = self.etw_handle.take() {
            let _ = h.join();
        }
    }
}
```

**ETW trace loop pattern** (lines 130-236):
```rust
fn run_etw_loop(
    tx: Sender<ProcessEvent>,
    shutdown: Arc<AtomicBool>,
    healthy: Arc<AtomicBool>,
    sweep_trigger: Sender<SweepTrigger>,
) {
    use ferrisetw::provider::{kernel_providers, Provider};
    use ferrisetw::schema_locator::SchemaLocator;
    use ferrisetw::trace::{KernelTrace, LoggingMode, TraceProperties, TraceTrait};
    use ferrisetw::EventRecord;

    let process_provider = Provider::kernel(&kernel_providers::PROCESS_PROVIDER)
        .add_callback(
            move |record: &EventRecord, schema_locator: &SchemaLocator| {
                if record.event_id() != 1 { return; }
                let ts = Instant::now();
                match schema_locator.event_schema(record) {
                    Ok(schema) => {
                        let parser = ferrisetw::parser::Parser::create(record, &schema);
                        let pid: u32 = parser.try_parse("ProcessID").unwrap_or(0);
                        // ... push to channel
                        match tx.try_send(event) {
                            Ok(()) => {}
                            Err(TrySendError::Full(_)) => {
                                tracing::warn!("ETW event channel full");
                                let _ = sweep_trigger.try_send(SweepTrigger::ChannelOverflow);
                            }
                            Err(TrySendError::Disconnected(_)) => {}
                        }
                    }
                    Err(e) => { tracing::warn!("ETW schema error: {:?}", e); }
                }
            },
        )
        .build();

    let props = TraceProperties {
        buffer_size: ETW_BUFFER_SIZE_KB,
        min_buffer: ETW_BUFFER_COUNT,
        max_buffer: ETW_BUFFER_COUNT,
        flush_timer: Duration::from_secs(1),
        log_file_mode: LoggingMode::EVENT_TRACE_REAL_TIME_MODE
            | LoggingMode::EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING,
    };

    let trace_builder = KernelTrace::new()
        .named(String::from("DlpProcessWatcher"))
        .set_trace_properties(props)
        .enable(process_provider);

    let (trace, trace_handle) = match trace_builder.start() {
        Ok(result) => result,
        Err(e) => {
            tracing::error!(error = ?e, "ETW trace start failed");
            healthy.store(false, Ordering::Relaxed);
            return;
        }
    };

    let process_shutdown = Arc::clone(&shutdown);
    let process_handle = std::thread::spawn(move || {
        let _ = ferrisetw::trace::KernelTrace::process_from_handle(trace_handle);
    });

    loop {
        if process_shutdown.load(Ordering::Relaxed) { break; }
        std::thread::sleep(Duration::from_millis(100));
    }

    if let Err(e) = trace.stop() {
        tracing::warn!(error = ?e, "ETW trace stop failed");
    }
    let _ = process_handle.join();
}
```

**Key differences from analog:**
- Use `Microsoft-Windows-Kernel-File` provider GUID `{EDD08927-9CC4-4E65-B970-C2560FB5C289}` instead of `PROCESS_PROVIDER`
- Filter for event IDs 12 (Create), 16 (Write), 18 (Delete), 30 (Rename) instead of event ID 1
- Parse `FileName`, `FileObject`, `ProcessId` fields instead of `ImageName`, `ParentProcessID`
- Thread name: `"etw-kernel-file"` instead of `"etw-process-watcher"`
- Trace name: `"DlpKernelFileWatcher"` instead of `"DlpProcessWatcher"`

---

### `dlp-agent/src/bypass_correlator.rs` (service, event-driven)

**Analog:** `dlp-agent/src/service.rs` (tokio spawn patterns + ProcessWatcher consumer)

**Tokio spawn pattern** (from service.rs lines 2030-2044):
```rust
let injector_for_events = Arc::clone(&universal_injector);
let event_rx = process_watcher.receiver().clone();
tokio::spawn(async move {
    while let Ok(event) = event_rx.recv() {
        let injector = Arc::clone(&injector_for_events);
        tokio::spawn(async move {
            injector.handle_event(event, &sweep).await;
        });
    }
});
```

**Batch flush pattern** (from service.rs lines 1104, 1150):
```rust
// Use tokio::time::interval for periodic flush
tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    loop {
        interval.tick().await;
        // drain batch and POST
    }
});
```

**DashMap concurrent map pattern** (from existing approval_cache.rs usage):
```rust
use dashmap::DashMap;
// For per-PID journal handles:
let journals: DashMap<u32, JournalHandle> = DashMap::new();
// For image SHA-256 cache:
let image_sha_cache: DashMap<String, String> = DashMap::new();
```

**Error handling pattern:**
- Use `tracing::warn!` for non-fatal correlation misses
- Use `tracing::error!` for journal mapping failures
- All correlation is best-effort; never panic

---

### `dlp-hook-dll/src/hook_journal.rs` (component, file-I/O)

**Analog:** `dlp-hook-dll/src/classification_cache.rs`

**Shared-memory creation pattern** (lines 180-235):
```rust
unsafe fn try_init() -> Option<CacheLookup> {
    use windows::Win32::System::Memory::{MapViewOfFile, OpenFileMappingW, FILE_MAP_READ};

    let name_wide: Vec<u16> = CACHE_NAME
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let handle = OpenFileMappingW(
        FILE_MAP_READ.0,
        false,
        windows::core::PCWSTR::from_raw(name_wide.as_ptr()),
    );

    let handle = match handle {
        Ok(h) => h,
        Err(_) => { return None; }
    };

    let view = MapViewOfFile(handle, FILE_MAP_READ, 0, 0, 0);
    let mapping = match view {
        windows::Win32::System::Memory::MEMORY_MAPPED_VIEW_ADDRESS { Value: ptr }
            if !ptr.is_null() =>
        {
            ptr as *const u8
        }
        _ => { return None; }
    };
    // ...
}
```

**Lazy OnceLock initialization pattern** (lines 156-172):
```rust
static CACHE_LOOKUP: OnceLock<Option<CacheLookup>> = OnceLock::new();

impl CacheLookup {
    pub fn get() -> Option<&'static CacheLookup> {
        let opt = CACHE_LOOKUP.get_or_init(|| {
            unsafe { Self::try_init() }
        });
        opt.as_ref()
    }
}
```

**Key differences from analog:**
- Journal is created with `CreateFileMappingW` (not `OpenFileMappingW`) by the hook DLL
- Name is `Global\DlpHookJournal_<pid>` (per-process, not global singleton)
- Size is 64 KiB (not 2 MiB)
- Protection is `PAGE_READWRITE` for DLL, agent opens with `FILE_MAP_READ`
- Uses `Release`/`Acquire` ordering on `write_index` for SPSC synchronization
- Write happens BEFORE returning decision in trampolines

---

### `dlp-common/src/path_hash.rs` (utility, transform)

**Analog:** `dlp-hook-dll/src/classification_cache.rs` (normalize_path + fnv1a_64)

**Path normalization pattern** (lines 545-627):
```rust
pub fn normalize_path(path: &str) -> Option<Cow<'_, str>> {
    if path.is_empty() { return None; }

    let s = if path.starts_with(r"\\?\") || path.starts_with(r"\\.\") {
        &path[4..]
    } else { path };

    if path.starts_with(r"\\.\") { return None; }

    if let Some(colon_pos) = s.find(':') {
        if colon_pos != 1 || s.len() < 2 || s.as_bytes()[1] != b':' {
            return None;
        }
        if s[2..].contains(':') { return None; }
    }

    if s.to_ascii_uppercase().contains("VOLUME{") { return None; }
    if is_eight_three_short_name(s) { return None; }

    let mut result = s.replace('/', "\\");
    // collapse backslashes, to-uppercase, strip trailing, etc.
    Some(Cow::Owned(result))
}
```

**FNV-1a hash pattern** (from `dlp-common/src/hash.rs`):
```rust
pub fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}
```

**Key differences:**
- Extract `normalize_path` from classification_cache.rs into dlp-common so both DLL and correlator share identical normalization
- Add `path_hash(path: &str) -> u64` convenience function that normalizes then hashes

---

### `dlp-server/src/db/repositories/bypass_alerts.rs` (repository, CRUD)

**Analog:** `dlp-server/src/db/repositories/labels.rs`

**Repository pattern** (lines 71-104):
```rust
use rusqlite::params;
use crate::db::{Pool, UnitOfWork};

#[derive(Debug, Clone)]
pub struct LabelRow {
    pub id: String,
    pub path: String,
    // ...
}

pub struct LabelRepository;

impl LabelRepository {
    pub fn list(pool: &Pool) -> rusqlite::Result<Vec<LabelRow>> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        let mut stmt = conn.prepare("SELECT ... FROM labels ORDER BY path ASC")?;
        let rows = stmt.query_map([], |row| {
            Ok(LabelRow { id: row.get(0)?, ... })
        })?;
        rows.collect()
    }

    pub fn insert(uow: &UnitOfWork, record: &LabelUpsertRow) -> rusqlite::Result<()> {
        uow.tx.execute("INSERT INTO labels (...) VALUES (...)", params![...])?;
        Ok(())
    }
}
```

**Filter + pagination pattern** (from labels.rs lines 112-204):
```rust
pub fn list_by_filters(
    pool: &Pool,
    state: Option<&str>,
    tier: Option<&str>,
    // ...
    limit: Option<usize>,
    offset: Option<usize>,
) -> rusqlite::Result<Vec<LabelRow>> {
    // Build parameterized query with WHERE clauses
    let mut sql = String::from("SELECT ... FROM labels WHERE 1=1");
    let mut param_count = 0;
    if state.is_some() { param_count += 1; sql.push_str(&format!(" AND label_state = ?{param_count}")); }
    // ...
    sql.push_str(" ORDER BY path ASC");
    if let Some(_lim) = limit {
        param_count += 1;
        sql.push_str(&format!(" LIMIT ?{param_count}"));
        if let Some(_off) = offset {
            param_count += 1;
            sql.push_str(&format!(" OFFSET ?{param_count}"));
        }
    }
    // execute...
}
```

**Key differences:**
- Table: `bypass_alerts` instead of `labels`
- Row struct: `BypassAlertRow` with fields: `id, agent_id, pid, image_path, image_sha256, file_path, operation, file_object, qpc_timestamp, created_at, severity, ack_by, ack_at, correlation_reason`
- Methods: `list`, `list_by_filters`, `insert`, `ack_by_id` (no update/delete)
- `ack_by_id` takes `uow`, `id`, `ack_by` username, sets `ack_at = now()`
- Filter params: `since`, `severity`, `acknowledged`, `agent_id`

---

### `dlp-server/src/admin_api.rs` additions (controller, request-response)

**Analog:** `dlp-server/src/admin_api.rs` (protected_paths routes, lines 1231-1245)

**Route registration pattern** (lines 1231-1245):
```rust
// Phase 52: Protected paths admin API (DACL-03)
.route(
    "/admin/protected-paths",
    get(list_protected_paths_handler).post(create_protected_path_handler),
)
.route(
    "/admin/protected-paths/{id}",
    get(get_protected_path_handler)
        .put(update_protected_path_handler)
        .delete(delete_protected_path_handler),
)
```

**Handler pattern** (from protected_paths handlers, lines 4832-4846):
```rust
async fn list_protected_paths_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<ProtectedPathResponse>>, AppError> {
    let rows = tokio::task::spawn_blocking(move || {
        ProtectedPathsRepository::list_all(&state.pool)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("spawn blocking: {e}")))??;

    let responses: Vec<ProtectedPathResponse> = rows.into_iter().map(Into::into).collect();
    Ok(Json(responses))
}
```

**Key additions for bypass alerts:**
```rust
// Phase 53: Bypass alerts admin API (ETW-04)
.route(
    "/admin/bypass-alerts",
    get(list_bypass_alerts_handler),
)
.route(
    "/admin/bypass-alerts/{id}/ack",
    post(ack_bypass_alert_handler),
)
// Agent-facing bypass alert batch ingest (no JWT -- agent-authenticated)
.route(
    "/audit/bypass",
    post(bypass_batch_ingest_handler),
)
```

---

### `dlp-server/src/lib.rs` AppState addition (config)

**Analog:** `dlp-server/src/lib.rs` (existing AppState field additions, lines 73-75)

**Pattern** (lines 42-75):
```rust
#[derive(Clone)]
pub struct AppState {
    pub pool: Arc<db::Pool>,
    pub crypto: Arc<crypto::SecretCrypto>,
    pub policy_store: Arc<PolicyStore>,
    pub siem: siem_connector::SiemConnector,
    pub alert: alert_router::AlertRouter,
    pub ad: Option<AdClient>,
    pub label_service: Arc<label_service::LabelService>,
    // ...
    /// Phase 52: Protected paths repository
    pub protected_paths: Arc<db::repositories::protected_paths::ProtectedPathsRepository>,
}
```

**Addition:**
```rust
    /// Phase 53: Bypass alerts repository
    pub bypass_alerts: Arc<db::repositories::bypass_alerts::BypassAlertsRepository>,
```

---

### `dlp-server/src/db/mod.rs` table addition (config)

**Analog:** `dlp-server/src/db/mod.rs` (existing table definitions, lines 470-498)

**Pattern** (lines 470-498):
```rust
CREATE TABLE IF NOT EXISTS protected_paths (
    id          TEXT PRIMARY KEY,
    path        TEXT NOT NULL UNIQUE,
    source      TEXT NOT NULL CHECK(source IN ('auto', 'manual')),
    is_override INTEGER NOT NULL DEFAULT 0,
    tier        TEXT NOT NULL CHECK(tier IN ('T3', 'T4')),
    label_id    TEXT REFERENCES labels(id) ON DELETE SET NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_protected_paths_path ON protected_paths(path);
```

**Addition for bypass_alerts:**
```sql
CREATE TABLE IF NOT EXISTS bypass_alerts (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id            TEXT NOT NULL,
    pid                 INTEGER NOT NULL,
    image_path          TEXT NOT NULL,
    image_sha256        TEXT NULL,
    file_path           TEXT NOT NULL,
    operation           TEXT NOT NULL,
    file_object         INTEGER NOT NULL,
    qpc_timestamp       INTEGER NOT NULL,
    created_at          TEXT NOT NULL,
    severity            TEXT NOT NULL CHECK(severity IN ('info', 'warn', 'crit')),
    ack_by              TEXT NULL REFERENCES admin_users(username),
    ack_at              TEXT NULL,
    correlation_reason  TEXT NOT NULL CHECK(correlation_reason IN ('no_hook_journal', 'op_mismatch', 'hook_overwritten'))
);
CREATE INDEX IF NOT EXISTS idx_bypass_alerts_agent ON bypass_alerts(agent_id);
CREATE INDEX IF NOT EXISTS idx_bypass_alerts_severity ON bypass_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_bypass_alerts_created_at ON bypass_alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_bypass_alerts_ack ON bypass_alerts(ack_by, ack_at);
```

---

### `dlp-common/src/hook_ipc.rs` BypassReason extension (model)

**Analog:** `dlp-common/src/hook_ipc.rs` (existing BypassReason enum, lines 161-170)

**Pattern**:
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BypassReason {
    HookOverwritten,
    PatchRaced,
    EdrDetected,
}
```

**Extension:**
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BypassReason {
    HookOverwritten,
    PatchRaced,
    EdrDetected,
    /// Phase 53: No hook journal entry found for correlated ETW event
    NoHookJournal,
    /// Phase 53: Journal entry found but operation type mismatched
    OpMismatch,
}
```

---

### `dlp-common/src/audit.rs` EventType extension (model)

**Analog:** `dlp-common/src/audit.rs` (existing EventType additions, lines 68-78)

**Pattern**:
```rust
/// Phase 52: The repair watcher detected out-of-band ACL modification.
DaclTamperDetected,
```

**Addition:**
```rust
/// Phase 53: ETW Kernel-File consumer detected a bypass (no hook journal match).
BypassAlertDetected,
```

Also add to `routed_to_siem()` and `triggers_alert()` match arms.

---

### `dlp-hook-dll/src/trampolines.rs` journal_write call (component)

**Analog:** `dlp-hook-dll/src/trampolines.rs` (existing classify_and_log_path, lines 70-111)

**Pattern** (allowlist early-return path, lines 95-110):
```rust
if allowlisted {
    let msg = format!("[dlp-hook] ALLOW(allowlist) {} hash={:016x}\0", fn_name, path_hash);
    crate::debug_log(&msg);
    // ...
    return None;
}
```

**Extension:** In EVERY trampoline, BEFORE returning (both allow and deny paths), call:
```rust
// Phase 53: Write to hook journal BEFORE returning decision
crate::hook_journal::journal_write(handle_value, op, path, ts_qpc);
```

The `classify_and_log_path` function should accept `handle_value: u64` and `ts_qpc: u64` parameters and call `journal_write` at each return point.

---

### `dlp-agent/src/service.rs` initialization (service)

**Analog:** `dlp-agent/src/service.rs` (ProcessWatcher initialization, lines 2012-2044)

**Pattern** (lines 2012-2028):
```rust
let mut process_watcher = crate::process_watcher::ProcessWatcher::new();
if let Err(e) = process_watcher.start(sweep_tx.clone()) {
    tracing::warn!(error = %e, "ProcessWatcher start failed");
    // ... fallback
}
```

**Addition** (after ProcessWatcher startup, around line 2044):
```rust
// Phase 53: Start ETW Kernel-File consumer
let mut etw_consumer = crate::etw_kernel_file::EtwKernelFileConsumer::new();
if let Err(e) = etw_consumer.start() {
    tracing::warn!(error = %e, "ETW Kernel-File consumer start failed");
}

// Phase 53: Start bypass correlator
let correlator = crate::bypass_correlator::BypassCorrelator::new(
    etw_consumer.receiver().clone(),
    process_watcher.receiver().clone(),
    server_client.clone(),
);
tokio::spawn(async move {
    correlator.run().await;
});
```

---

## Shared Patterns

### Authentication
**Source:** `dlp-server/src/admin_api.rs` (middleware layer)
**Apply to:** All `/admin/bypass-alerts*` routes
All admin routes are under `protected_routes` which gets JWT middleware via `.layer(middleware::from_fn(admin_auth::jwt_middleware))`.

### Error Handling
**Source:** `dlp-server/src/lib.rs` (AppError enum, lines 124-171)
**Apply to:** All server-side handlers
```rust
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("not found: {0}")]
    NotFound(String),
    // ...
}
```

### SIEM Relay
**Source:** `dlp-server/src/siem_connector.rs` (lines 222-230)
**Apply to:** `POST /audit/bypass` handler
```rust
pub async fn relay_events(&self, events: &[AuditEvent]) -> Result<(), SiemError> {
    if events.is_empty() { return Ok(()); }
    let row = self.load_config()?;
    // ... relay to Splunk/ELK
}
```

### Alert Router
**Source:** `dlp-server/src/alert_router.rs` (lines 271-285)
**Apply to:** `POST /audit/bypass` handler for crit severity
```rust
pub async fn send_alert(&self, event: &AuditEvent) -> Result<(), AlertError> {
    let row = self.load_config()?;
    // SMTP + webhook paths
}
```

### Windows Shared Memory
**Source:** `dlp-hook-dll/src/classification_cache.rs`
**Apply to:** `dlp-hook-dll/src/hook_journal.rs`
- Use `windows` crate: `CreateFileMappingW`, `MapViewOfFile`, `OpenFileMappingW`
- Name prefix: `Global\Dlp{Purpose}`
- Lazy initialization via `OnceLock`
- Silent continue on failure (never crash host process)

### Crossbeam Channel
**Source:** `dlp-agent/src/process_watcher.rs`
**Apply to:** `dlp-agent/src/etw_kernel_file.rs`
- `crossbeam::bounded(1024)` between ETW thread and tokio task
- `try_send` with `TrySendError::Full` handling
- Overflow triggers warning log (not silent drop)

---

## No Analog Found

| File | Role | Data Flow | Reason |
|---|---|---|---|
| None | -- | -- | All files have strong analogs in the codebase |

**Note:** The `hook_journal.rs` SPSC ring buffer is novel in layout (48-byte entries, 64 KiB total) but the underlying Windows shared-memory creation pattern is proven in `classification_cache.rs`. The correlator's QPC timestamp conversion and path-hash matching are novel algorithms but use proven primitives (`QueryPerformanceCounter`, `fnv1a_64`, `normalize_path`).

---

## Metadata

**Analog search scope:**
- `dlp-agent/src/` — ProcessWatcher, service.rs spawn patterns
- `dlp-hook-dll/src/` — classification_cache, trampolines, lib.rs
- `dlp-common/src/` — hook_ipc, audit, hash, lib.rs
- `dlp-server/src/` — admin_api, lib.rs (AppState), db/mod.rs, db/repositories/, siem_connector, alert_router

**Files scanned:** 12
**Pattern extraction date:** 2026-05-27
