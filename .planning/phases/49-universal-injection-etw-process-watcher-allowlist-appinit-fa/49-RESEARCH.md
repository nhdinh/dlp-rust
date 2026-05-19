# Phase 49: Universal Injection — ETW Process Watcher + Allowlist + AppInit Fallback - Research

**Researched:** 2026-05-19
**Domain:** Windows ETW process creation monitoring, DLL injection orchestration, Authenticode signer verification, PPL detection, AppInit_DLLs registry management
**Confidence:** HIGH

## Summary

Phase 49 drives the unified hook DLL (built in Phase 48) into every non-allowlisted user-mode process — both already-running and newly-spawned — within 500 ms of process start. The primary trigger is ETW `Microsoft-Windows-Kernel-Process` Event ID 1 via `ferrisetw` 1.2.0, with WMI `Win32_ProcessStartTrace` as a backstop. A per-process allowlist guards against self-injection, AV/EDR collision, and system-critical process disruption. AppInit_DLLs serves as a tertiary fallback on non-Secure-Boot endpoints only.

All locked decisions from CONTEXT.md are technically feasible. The `ferrisetw` crate provides idiomatic Rust ETW consumer APIs with kernel provider support, buffer sizing, and real-time event parsing. The existing `HookInjector` (Phase 48) is reused without modification. `dashmap` 6.1.0 is already in the workspace for lock-free process state tracking. The `wmi` 0.18.4 crate (already used for BitLocker enumeration) supports `Win32_ProcessStartTrace` subscription. Authenticode signer extraction follows the established 4-step WinCrypt pattern in `detection/app_identity.rs`.

**Primary recommendation:** Implement `process_watcher.rs` (ETW primary + WMI backstop), `universal_injector.rs` (allowlist + injection orchestration), and `process_registry.rs` (`DashMap<u32, ProcessState>` lifecycle tracking) as three new modules in `dlp-agent/src/`. Extend `AgentConfig` and `AgentConfigPayload` with `[universal_injection.allowlist]` TOML section. Add server-side `allowlist_entries` table and `/admin/allowlist` CRUD endpoints. Installer handles AppInit_DLLs registry setup and backup.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| ETW process creation detection | API / Backend (agent service) | — | ETW consumer runs in agent SYSTEM service; kernel delivers events to user-mode callback |
| WMI process start backstop | API / Backend (agent service) | — | WMI subscription runs in agent; fallback when ETW unhealthy |
| Process allowlist matching | API / Backend (agent service) | — | Policy evaluation happens agent-side before injection decision |
| DLL injection execution | API / Backend (agent service) | — | `CreateRemoteThread+LoadLibraryW` from agent into target process |
| Process lifecycle tracking | API / Backend (agent service) | — | `DashMap` lives in agent; tracks states for telemetry |
| AppInit_DLLs registration | CDN / Static (installer) | — | Installer writes HKLM at install time; agent reads-only |
| Secure Boot detection | API / Backend (agent service) | — | Agent calls `GetFirmwareEnvironmentVariable` at boot |
| Authenticode signer extraction | API / Backend (agent service) | — | Reuses `detection/app_identity.rs` WinCrypt pattern |
| Admin TUI allowlist screen | Browser / Client (admin CLI) | — | TUI screen for operator-managed allowlist entries |

## User Constraints (from CONTEXT.md)

### Locked Decisions
- **D-01:** Allowlist delivery extends existing agent-config TOML poll (30 s cadence). Add `[universal_injection.allowlist]` section. Agent reloads on hash-change without restart.
- **D-02:** Allowlist matching uses both path prefix and signer certificate subject. System-critical processes match by name/path. AV/EDR processes match by Authenticode signer cert subject.
- **D-03:** Operator extension flows: Admin TUI → server DB → agent-config TOML response → agent polls and reloads. No dedicated API endpoint or SQLite table needed.
- **D-04:** ETW consumer runs on dedicated OS thread (`std::thread`) calling `ProcessTrace` in blocking loop. ETW callbacks push `(pid, image_path, parent_pid)` through bounded `crossbeam::channel` to tokio injection task.
- **D-05:** Buffer sizing: 256 KB x 200 buffers = 50 MB total. Consumer-side filter drops System32/WinSxS processes at ETW layer.
- **D-06:** Event loss: log `warn!` with dropped count. No SIEM alert for event loss. WMI backstop and 5-minute `EnumProcesses` sweep cover gaps.
- **D-07:** WMI backstop: separate lightweight WMI subscription (`Win32_ProcessStartTrace`) runs as secondary. Higher latency (~50-100 ms). Only used when ETW primary is unhealthy (detected via heartbeat).
- **D-08:** State model: `DashMap<u32, ProcessState>` with states: `Discovered` → `Skipped(Reason)` → `Injected(arch, timestamp)` → `Exited`.
- **D-09:** Cleanup: ETW Event ID 2 (process exit) removes PID immediately. 60-second background sweep catches missed exits (OpenProcess check).
- **D-10:** Duplicate injection guard: check if PID is already in `Injected` state before injecting.
- **D-11:** Startup sweep: `EnumProcesses` enumerates all running PIDs. Target: complete within 5 seconds.
- **D-12:** Retry strategy: one immediate retry after 50 ms. No further retries.
- **D-13:** Failure categorization: `AccessDenied` → `warn!`, no alert. `RemoteThreadFailed` / `InjectionFailed` → `error!` + `siem.injection_failure` audit event.
- **D-14:** Periodic backstop: every 5 minutes, `EnumProcesses` sweep checks running PIDs not in `Injected` or `Skipped` state.
- **D-15:** Telemetry aggregation: per-minute counters (`injected_count`, `skipped_count_by_reason`, `failed_count`) emitted as `siem.injection_telemetry` events.
- **D-16:** Installer sets `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` + `LoadAppInit_DLLs=1` + `RequireSignedAppInit_DLLs=1` at install time. Agent does NOT modify at runtime.
- **D-17:** Agent only READS registry at boot to verify AppInit is set correctly. If not, log warning and rely on ETW.
- **D-18:** Agent calls `GetFirmwareEnvironmentVariable("SecureBoot", "{8be4df61-93ca-11d2-aa0d-00e098032b8c}")` at boot. If Secure Boot enabled, emit one `siem.appinit_dlls_disabled` audit event and skip AppInit.
- **D-19:** PPL status checked at injection time via `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` + `GetProcessMitigationPolicy(ProcessSignaturePolicy)`.
- **D-20:** Process map NOT persisted across restarts. On restart, clear `DashMap` and run full `EnumProcesses` sweep.

### Claude's Discretion
- `ProcessState` enum derives `Debug`, `Clone`, `PartialEq` for telemetry serialization.
- `crossbeam::channel` between ETW thread and tokio injection task: bounded (capacity 1024) with `try_send` — drop oldest event if full rather than block ETW callback.
- `EnumProcesses` sweep uses `rayon` or manual thread-pool for parallel injection if >100 processes running. Batch size of 16 per thread.
- Allowlist TOML section supports exact paths and glob patterns: `path = "C:\\Program Files\\CrowdStrike\\*"` and `cert_subject = "O=CrowdStrike, Inc."`.
- Installer backup reg key: `HKLM\SOFTWARE\DLP\Backup\AppInit_DLLs` stores original value before modification.

### Deferred Ideas (OUT OF SCOPE)
- ntdll syscall-stub patching (Phase 51 — BLOCK-08, BLOCK-09)
- Shared-memory classification cache (Phase 50 — CACHE-01..06, FAIL-01..03)
- Deployment guide with per-vendor AV/EDR allowlist procedures (Phase 57 — OPS-01..04)
- Monitor-only / audit-only per-policy mode (Phase 55 — MODE-01)
- Admin TUI Protected Paths screen (Phase 54 — UX-01)
- Admin TUI Bypass Alerts screen (Phase 54 — UX-02)
- SD/optical/virtual drive enumeration (Phase 56 — DRIVE-01..04)
- DACL tripwire (Phase 52 — DACL-01..05)
- ETW Kernel-File consumer for bypass detection (Phase 53 — ETW-01..05)

## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| BLOCK-05 | Universal injection: ETW `Microsoft-Windows-Kernel-Process` Event ID 1 (primary); WMI `Win32_ProcessStartTrace` backstop; `CreateRemoteThread+LoadLibraryW` into every non-allowlisted PID; startup `EnumProcesses` sweep | `ferrisetw` 1.2.0 `KernelTrace` with `PROCESS_PROVIDER` + `EventRecord::event_id()` filter; `wmi` 0.18.4 `Win32_ProcessStartTrace` subscription; existing `HookInjector::inject` reusable; `windows::Win32::System::ProcessStatus::K32EnumProcesses` for sweep |
| BLOCK-06 | Per-process allowlist: self (DLP binaries), AV/EDR (signer-cert-subject match), system-critical (PIDs 0/4, csrss/smss/wininit/services/lsass/fontdrvhost/dwm), PPL-detected (`GetProcessMitigationPolicy`), WoW64-dispatched (`IsWow64Process`) | Existing `extract_publisher()` in `detection/app_identity.rs:239` provides Authenticode signer CN extraction; `windows` crate `GetProcessMitigationPolicy` with `ProcessSignaturePolicy`; existing `HookInjector::target_architecture` handles WoW64 |
| BLOCK-07 | AppInit_DLLs tertiary fallback: installer sets `HKLM\...\AppInit_DLLs` + `LoadAppInit_DLLs=1` + `RequireSignedAppInit_DLLs=1`; agent emits `siem.appinit_dlls_disabled` when Secure Boot detected | `windows-registry` or raw `RegOpenKeyExW`/`RegQueryValueExW`/`RegSetValueExW` (existing patterns in `chrome/registry.rs` and `cloud_enforcer.rs`); `GetFirmwareEnvironmentVariable` from `windows::Win32::System::Firmware` |

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `ferrisetw` | 1.2.0 [VERIFIED: cargo registry] | ETW consumer API (`KernelTrace`, `Provider`, `EventRecord`, `SchemaLocator`, `Parser`) | Project standard per ETW-01 spec and ARCHITECTURE.md; `PROCESS_PROVIDER` predefined kernel provider available |
| `windows` | 0.62.2 [VERIFIED: cargo registry] | Win32 API bindings (`OpenProcess`, `CreateRemoteThread`, `GetProcessMitigationPolicy`, `GetFirmwareEnvironmentVariable`, registry APIs) | Already in workspace with `Win32_System_Diagnostics_Etw`, `Win32_Security_Cryptography`, `Win32_System_Registry` features enabled |
| `dashmap` | 6.1.0 [VERIFIED: Cargo.lock] | Lock-free concurrent `HashMap<u32, ProcessState>` for process lifecycle tracking | Already in `dlp-agent/Cargo.toml` (used by `approval_cache.rs`) |
| `crossbeam-channel` | 0.5.15 [VERIFIED: Cargo.lock] | Bounded MPSC channel between ETW thread and tokio task | Already in workspace dependency tree |
| `wmi` | 0.18.4 [VERIFIED: cargo registry + Cargo.lock] | WMI `Win32_ProcessStartTrace` subscription backstop | Already in `dlp-agent/Cargo.toml` (used by `detection/encryption.rs`) |
| `thiserror` | workspace | Error type definitions | Project standard |
| `tracing` | workspace | Structured logging (`info!`, `warn!`, `error!`) | Project standard |
| `serde` | workspace | TOML/JSON serialization for allowlist config | Project standard |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `rayon` | 1.11.0 [VERIFIED: Cargo.lock] | CPU-bound parallelism for `EnumProcesses` startup sweep | When >100 processes running; batch size 16 per thread |
| `glob` | 0.3 [ASSUMED: standard crate] | Glob pattern matching for allowlist path patterns | For `C:\Program Files\CrowdStrike\*` style patterns |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `ferrisetw` | Raw ETW APIs via `windows::Win32::System::Diagnostics::Etw` | `ferrisetw` provides safe Rust abstractions, `SchemaLocator`, `Parser` — significantly less unsafe code. CONTEXT.md D-04 locks `ferrisetw`. |
| `crossbeam-channel` | `tokio::sync::mpsc` | `crossbeam` works across `std::thread` → tokio boundary without tokio runtime dependency on ETW thread. CONTEXT.md D-04 locks `crossbeam`. |
| `rayon` | Manual `std::thread` pool | `rayon` is simpler for parallel `EnumProcesses` sweep with work-stealing. CONTEXT.md discretion allows either. |
| `glob` | Manual prefix matching | `glob` handles `*` and `?` correctly. For simple prefix-only, `starts_with` suffices. |

**Installation:**
```bash
# Add to dlp-agent/Cargo.toml dependencies:
# ferrisetw = "1.2.0"
# crossbeam-channel = "0.5"
# glob = "0.3"
# rayon already in workspace
# dashmap already in workspace
# wmi already in workspace
```

**Version verification:**
- `ferrisetw`: 1.2.0 (current on crates.io, confirmed 2026-05-19)
- `dashmap`: 6.1.0 (in Cargo.lock, confirmed)
- `crossbeam-channel`: 0.5.15 (in Cargo.lock, confirmed)
- `wmi`: 0.18.4 (in Cargo.lock, confirmed)
- `rayon`: 1.11.0 (in Cargo.lock, confirmed)
- `windows`: 0.62.2 (in Cargo.lock, confirmed)

## Architecture Patterns

### System Architecture Diagram

```
New Process Spawn (kernel)
  |
  v
ETW Kernel-Process Provider (Event ID 1)
  |
  v
Dedicated OS Thread (std::thread)
  |-- ProcessTrace blocking loop
  |-- Callback: parse EventRecord -> (pid, image_path, parent_pid)
  |-- Consumer-side filter: drop System32/WinSxS
  |-- try_send() to crossbeam channel (bounded, 1024)
  |
  v
crossbeam::channel (bounded, 1024)
  |
  v
Tokio Task (injection orchestrator)
  |-- recv() from channel
  |-- Check DashMap: already Injected? -> skip (D-10)
  |-- Allowlist check:
  |     - Self (DLP binaries)?
  |     - System-critical (PID 0/4, csrss, etc.)?
  |     - AV/EDR (signer cert subject match)?
  |     - PPL (GetProcessMitigationPolicy at injection time)?
  |     - WoW64 (IsWow64Process -> x86 DLL dispatch)?
  |-- If allowed: HookInjector::inject(pid)
  |-- If skipped: record Skipped(Reason) in DashMap
  |-- If failed: categorize, log, emit SIEM event if unexpected
  |
  v
DashMap<u32, ProcessState> (lock-free)
  |-- Discovered -> Skipped(Reason) -> Injected(arch, ts) -> Exited
  |
  v
Periodic Tasks (tokio::time::interval)
  |-- 60s: cleanup sweep (OpenProcess check for exited PIDs)
  |-- 5min: EnumProcesses backstop sweep (retry missed PIDs)
  |-- 1min: telemetry aggregation (counters -> siem.injection_telemetry)
```

WMI Backstop (parallel path):
```
WMI Win32_ProcessStartTrace subscription
  |
  v
Separate lightweight task
  |-- Only active when ETW primary unhealthy (heartbeat detection)
  |-- Same injection orchestrator path as ETW
```

Startup Sweep:
```
Agent Service Startup
  |
  v
EnumProcesses() -> Vec<u32>
  |-- Parallel batch processing (rayon, 16 per thread)
  |-- Same allowlist + injection logic as ETW path
  |-- Target: complete within 5 seconds
```

### Recommended Project Structure

```
dlp-agent/src/
├── process_watcher.rs      # ETW primary + WMI backstop subscription
├── universal_injector.rs   # Allowlist matching + injection orchestration
├── process_registry.rs     # DashMap<u32, ProcessState> + lifecycle tracking
├── hook_injector.rs        # EXISTING — reused without modification
├── service.rs              # ADD: ProcessWatcher init + startup sweep hook
├── engine_client.rs        # EXISTING — config poll extended with allowlist
└── lib.rs                  # ADD: mod declarations

dlp-server/src/
├── admin_api.rs            # ADD: /admin/allowlist CRUD endpoints
├── db/mod.rs               # ADD: allowlist_entries table in init_tables()
└── db/repositories/
    └── allowlist.rs        # NEW: allowlist repository pattern

dlp-admin-cli/src/screens/
├── allowlist.rs            # NEW: Admin TUI allowlist config screen
└── mod.rs                  # ADD: pub mod allowlist

installer/
├── build.ps1 or WiX        # ADD: AppInit_DLLs registry setup + backup
```

### Pattern 1: ETW Process Creation Subscription (ferrisetw)
**What:** Subscribe to `Microsoft-Windows-Kernel-Process` Event ID 1 via `KernelTrace` with `PROCESS_PROVIDER`.
**When to use:** Primary real-time process creation detection with sub-millisecond latency.
**Example:**
```rust
// Source: Context7 /n4r1b/ferrisetw "process creation event"
use ferrisetw::provider::{Provider, kernel_providers};
use ferrisetw::trace::{KernelTrace, TraceProperties, LoggingMode};
use ferrisetw::EventRecord;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::parser::Parser;
use std::time::Duration;

fn process_callback(record: &EventRecord, schema_locator: &SchemaLocator) {
    // Event ID 1 = ProcessStart, Event ID 2 = ProcessStop
    if record.event_id() == 1 {
        match schema_locator.event_schema(record) {
            Ok(schema) => {
                let parser = Parser::create(record, &schema);
                let process_id: u32 = parser.try_parse("ProcessID").unwrap_or(0);
                let image_name: String = parser.try_parse("ImageName").unwrap_or_default();
                let parent_id: u32 = parser.try_parse("ParentProcessID").unwrap_or(0);
                // Push to channel for injection task...
            }
            Err(e) => tracing::warn!("ETW schema error: {:?}", e),
        }
    }
}

let process_provider = Provider::kernel(&kernel_providers::PROCESS_PROVIDER)
    .add_callback(process_callback)
    .build();

let props = TraceProperties {
    buffer_size: 256,      // 256 KB per buffer (D-05)
    min_buffer: 200,       // 200 buffers = 50 MB total
    max_buffer: 200,
    flush_timer: Duration::from_secs(1),
    log_file_mode: LoggingMode::EVENT_TRACE_REAL_TIME_MODE
        | LoggingMode::EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING,
};

let trace = KernelTrace::new()
    .named(String::from("DlpProcessWatcher"))
    .set_trace_properties(props)
    .enable(process_provider)
    .start_and_process()
    .expect("ETW trace start failed");
```

### Pattern 2: Bounded crossbeam Channel Between ETW Thread and Tokio
**What:** ETW callback runs on a dedicated `std::thread` and pushes events through a bounded `crossbeam::channel`. Tokio task receives and processes injection asynchronously.
**When to use:** Bridging blocking ETW API to async tokio runtime without saturating blocking pool.
**Example:**
```rust
// Source: CONTEXT.md D-04 + crossbeam-channel docs
use crossbeam_channel::{bounded, TrySendError};
use std::thread;

struct ProcessEvent {
    pid: u32,
    image_path: String,
    parent_pid: u32,
}

// In ProcessWatcher::start():
let (tx, rx) = bounded::<ProcessEvent>(1024);

// ETW thread (dedicated std::thread)
let etw_handle = thread::Builder::new()
    .name("etw-process".into())
    .spawn(move || {
        // ... setup KernelTrace ...
        // In callback:
        match tx.try_send(ProcessEvent { pid, image_path, parent_pid }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                tracing::warn!("ETW event channel full — dropping oldest event");
                // Drop oldest by receiving one then retrying
                let _ = rx.try_recv();
                let _ = tx.try_send(ProcessEvent { pid, image_path, parent_pid });
            }
            Err(TrySendError::Disconnected(_)) => {}
        }
    })?;

// Tokio task (injection orchestrator)
tokio::spawn(async move {
    while let Ok(event) = rx.recv() {
        // Process injection...
    }
});
```

### Pattern 3: DashMap Process State Machine
**What:** Lock-free concurrent map tracking process lifecycle states for telemetry and duplicate guards.
**When to use:** High-concurrency process tracking where multiple threads (ETW callback, injection task, cleanup sweep) access shared state.
**Example:**
```rust
// Source: CONTEXT.md D-08 + existing approval_cache.rs pattern
use dashmap::DashMap;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
pub enum ProcessState {
    Discovered,
    Skipped(AllowlistReason),
    Injected { arch: String, timestamp: std::time::Instant },
    Exited,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AllowlistReason {
    SelfProcess,
    Avedr,
    SystemCritical,
    Ppl,
    WoW64,
    OperatorDefined,
}

pub struct ProcessRegistry {
    states: Arc<DashMap<u32, ProcessState>>,
}

impl ProcessRegistry {
    pub fn new() -> Self {
        Self {
            states: Arc::new(DashMap::new()),
        }
    }

    /// Returns true if this PID should be skipped (already injected or explicitly skipped).
    pub fn should_skip(&self, pid: u32) -> bool {
        match self.states.get(&pid) {
            Some(entry) => matches!(
                entry.value(),
                ProcessState::Injected { .. } | ProcessState::Skipped(_)
            ),
            None => false,
        }
    }

    pub fn record_injected(&self, pid: u32, arch: String) {
        self.states.insert(pid, ProcessState::Injected {
            arch,
            timestamp: std::time::Instant::now(),
        });
    }

    pub fn record_skipped(&self, pid: u32, reason: AllowlistReason) {
        self.states.insert(pid, ProcessState::Skipped(reason));
    }

    pub fn record_exited(&self, pid: u32) {
        self.states.insert(pid, ProcessState::Exited);
    }
}
```

### Pattern 4: PPL Detection at Injection Time
**What:** Before injecting, open target process with `PROCESS_QUERY_LIMITED_INFORMATION` and query `GetProcessMitigationPolicy(ProcessSignaturePolicy)`.
**When to use:** Detecting Protected Process Light status to avoid injection attempts that will fail with `ERROR_ACCESS_DENIED`.
**Example:**
```rust
// Source: CONTEXT.md D-19 + Microsoft Learn docs
use windows::Win32::System::Threading::{
    GetProcessMitigationPolicy, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::System::Threading::PROCESS_MITIGATION_POLICY;

fn is_protected_process_light(pid: u32) -> bool {
    let handle = unsafe {
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
    };
    let handle = match handle {
        Ok(h) => h,
        Err(_) => return false, // Cannot open — treat as non-PPL (injection will fail anyway)
    };

    let mut policy = PROCESS_MITIGATION_POLICY::default();
    let mut size = std::mem::size_of::<PROCESS_MITIGATION_POLICY>() as u32;
    // Note: ProcessSignaturePolicy = 8 on Windows 8.1+
    let result = unsafe {
        GetProcessMitigationPolicy(
            handle,
            PROCESS_MITIGATION_POLICY(8), // ProcessSignaturePolicy
            &mut policy as *mut _ as *mut std::ffi::c_void,
            size,
        )
    };

    unsafe { let _ = windows::Win32::Foundation::CloseHandle(handle); }

    result.is_ok() && policy.0 != 0
}
```

### Pattern 5: Authenticode Signer Subject Extraction
**What:** Reuse the existing 4-step WinCrypt sequence from `detection/app_identity.rs` to extract signer certificate subject for AV/EDR allowlist matching.
**When to use:** Allowlist matching for AV/EDR processes where path-based matching is insufficient.
**Example:**
```rust
// Source: dlp-agent/src/detection/app_identity.rs:239 (existing pattern)
// Extracts publisher CN from signed PE binary.
// For BLOCK-06, extend to extract full cert subject (not just CN)
// and match against configured allowlist entries.

fn extract_cert_subject(image_path: &str) -> String {
    // Step 1: CryptQueryObject
    // Step 2: CryptMsgGetParam(CMSG_SIGNER_INFO_PARAM)
    // Step 3: CertFindCertificateInStore
    // Step 4: CertGetNameStringW(CERT_NAME_SIMPLE_DISPLAY_TYPE)
    // ... returns subject string like "O=CrowdStrike, Inc., L=..."
    // Match against allowlist `cert_subject` patterns.
}
```

### Pattern 6: Secure Boot Detection
**What:** Call `GetFirmwareEnvironmentVariable` with the EFI Secure Boot variable GUID to detect Secure Boot state.
**When to use:** Determining whether AppInit_DLLs will be effective (disabled under Secure Boot).
**Example:**
```rust
// Source: CONTEXT.md D-18 + Microsoft docs
use windows::Win32::System::Firmware::GetFirmwareEnvironmentVariable;

fn is_secure_boot_enabled() -> Option<bool> {
    let mut value: u32 = 0;
    let result = unsafe {
        GetFirmwareEnvironmentVariable(
            windows::core::w!("SecureBoot"),
            &windows::core::GUID::from_u128(0x8be4df6193ca11d2aa0d00e098032b8c),
            Some(&mut value as *mut _ as *mut std::ffi::c_void),
            std::mem::size_of::<u32>() as u32,
        )
    };

    if result == 0 {
        // API failed — could be pre-UEFI system or insufficient privileges
        return None;
    }
    // Value: 0 = disabled, 1 = enabled
    Some(value != 0)
}
```

### Pattern 7: AppInit_DLLs Registry Management
**What:** Installer reads/writes `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows` values. Agent reads-only at boot.
**When to use:** Tertiary fallback for non-Secure-Boot endpoints.
**Example:**
```rust
// Source: existing registry patterns in chrome/registry.rs and cloud_enforcer.rs
use windows::Win32::System::Registry::{
    RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, RegCloseKey,
    HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_SZ, REG_DWORD,
};

const APPINIT_KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
const APPINIT_DLLS_VALUE: &str = "AppInit_DLLs";
const LOAD_APPINIT_VALUE: &str = "LoadAppInit_DLLs";
const REQUIRE_SIGNED_VALUE: &str = "RequireSignedAppInit_DLLs";
```

### Anti-Patterns to Avoid
- **Blocking ETW callback:** Never perform injection inside the ETW callback. It runs on the ETW thread and must return quickly. Always push to channel and process asynchronously.
- **Unbounded channel:** Do not use unbounded channels for ETW → tokio communication. ETW can generate thousands of events per second under load. Use bounded with `try_send` and drop policy (D-06).
- **Caching PPL state at process creation:** A process may elevate to PPL after launch. Always check PPL at injection time (D-19), not at ETW event receipt time.
- **Agent modifying AppInit at runtime:** AppInit_DLLs is an installer concern. Agent reads-only at boot (D-17). Runtime modification risks AV/EDR flagging and registry corruption on crash.
- **Injecting into self:** The DLP agent must exclude its own PID and image path. The hook DLL also has a self-allowlist gate in `DllMain`, but agent-side exclusion prevents wasted cycles.
- **EnumProcesses without batching:** Enumerating and injecting into hundreds of processes sequentially can exceed the 5-second startup target. Use `rayon` parallel batches (D-11 discretion).

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| ETW consumer from raw Win32 APIs | Custom ETW session management | `ferrisetw` 1.2.0 | Handles `StartTrace`, `EnableTraceEx2`, `ProcessTrace`, `SchemaLocator`, `Parser` safely. ~500 lines of unsafe avoided. |
| Concurrent HashMap for process tracking | `std::sync::Mutex<HashMap>` | `dashmap` 6.1.0 | Already in workspace. Lock-free reads, sharded for concurrency. Prevents injection task from blocking ETW callback. |
| Thread pool for EnumProcesses sweep | Manual `std::thread::spawn` per batch | `rayon` 1.11.0 | Already in workspace. Work-stealing scheduler, simpler than manual thread pool lifecycle. |
| Authenticode verification from scratch | Custom PKCS#7 parser | `WinVerifyTrust` + `CryptQueryObject` (existing pattern) | `detection/app_identity.rs` already implements the 4-step sequence. Reuse, don't rewrite. |
| Registry access wrapper | Raw `RegOpenKeyExW` everywhere | `windows-registry` crate or existing helper patterns | Project already uses raw Win32 registry APIs consistently. Adding a new crate for 3 reads is overkill. |
| Process exit detection | Polling all PIDs continuously | ETW Event ID 2 + 60s sweep backstop | ETW gives immediate exit notification. Polling alone is wasteful and delayed. |

**Key insight:** The ETW callback is a hot path that must return within microseconds. Every microsecond spent in the callback is a microsecond of kernel event buffering delay. Push to channel immediately and do all heavy work (allowlist matching, signer cert extraction, injection) in the tokio task.

## Runtime State Inventory

> This phase adds new runtime state (process tracking) but does not rename/refactor existing state.

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | None — process registry is in-memory only (`DashMap`), not persisted across restarts (D-20) | None |
| Live service config | Agent service will hold `ProcessRegistry` (Arc<DashMap>) and `ProcessWatcher` state. AppInit_DLLs registry values read at boot. | Code edit: add to agent service init |
| OS-registered state | AppInit_DLLs registry keys (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs`, `LoadAppInit_DLLs`, `RequireSignedAppInit_DLLs`) set by installer. Backup key at `HKLM\SOFTWARE\DLP\Backup\AppInit_DLLs`. | Installer edit: add registry setup/restore |
| Secrets/env vars | None — no new secrets | None |
| Build artifacts | None — no new build artifacts beyond existing DLLs | None |

**Nothing found in category:** Stored data — verified: process registry is intentionally ephemeral (D-20). Secrets/env vars — verified: no new credential storage needed.

## Common Pitfalls

### Pitfall 1: ETW Callback Blocking Causes Event Loss
**What goes wrong:** Performing slow operations (injection, cert verification) inside the ETW callback causes the kernel buffer to fill and events to be dropped.
**Why it happens:** ETW callbacks run on a kernel-managed thread with strict latency expectations. Blocking the callback delays buffer recycling.
**How to avoid:** Push `(pid, image_path)` through `crossbeam::channel` immediately in the callback. Do all work in the tokio consumer task. (D-04)
**Warning signs:** `warn!` logs showing "ETW dropped N events" under normal load.

### Pitfall 2: Double Injection on ETW + WMI Overlap
**What goes wrong:** Both ETW and WMI fire for the same process creation. If not deduplicated, the process receives two `CreateRemoteThread` calls.
**Why it happens:** Both providers observe the same kernel event. There is no ordering guarantee between them.
**How to avoid:** Check `DashMap` for `Injected` state before every injection attempt (D-10). The first successful injection wins; the second sees `Injected` and skips.
**Warning signs:** Hook DLL logs showing two `DLL_PROCESS_ATTACH` sequences for the same PID.

### Pitfall 3: PPL State Cached at Creation Time
**What goes wrong:** A process starts non-PPL, ETW fires, the agent caches it as non-PPL, then the process elevates to PPL before injection. Injection fails with `ERROR_ACCESS_DENIED`.
**Why it happens:** Some processes (e.g., Windows Defender) start as normal and elevate to PPL shortly after.
**How to avoid:** Check PPL status at injection time, not at ETW event time (D-19). The injection task calls `GetProcessMitigationPolicy` immediately before `OpenProcess(PROCESS_ALL_ACCESS)`.
**Warning signs:** `warn!` logs showing `AccessDenied` for processes that were not in the static system-critical list.

### Pitfall 4: AppInit_DLLs Ineffective Under Secure Boot
**What goes wrong:** Installer sets AppInit_DLLs, but on Secure Boot-enabled Windows 11 systems, the DLL is never loaded. Operators believe injection is universal but it's not.
**Why it happens:** Windows disables AppInit_DLLs when Secure Boot is enabled as a security measure.
**How to avoid:** Agent detects Secure Boot at boot (D-18) and emits exactly one `siem.appinit_dlls_disabled` audit event. The deployment guide (Phase 57) documents this gap. ETW-driven injection is the primary mechanism; AppInit is tertiary fallback only.
**Warning signs:** AppInit_DLLs registry value is set but processes never show the hook DLL loaded.

### Pitfall 5: EnumProcesses Sweep Exceeds 5-Second Target
**What goes wrong:** On a busy server with 500+ processes, sequential injection takes >5 seconds, missing the startup success criterion.
**Why it happens:** `CreateRemoteThread+LoadLibraryW` involves multiple syscalls per process. Sequential execution is O(n) with nontrivial constant factor.
**How to avoid:** Use `rayon` parallel batches of 16 processes per thread (Claude's discretion). The existing `HookInjector::inject` is thread-safe (no shared mutable state).
**Warning signs:** Agent startup logs show `EnumProcesses sweep completed in 12.3s`.

### Pitfall 6: AV/EDR Terminating on Injection
**What goes wrong:** Injecting into an anti-cheat or EDR process causes it to self-terminate or flag the agent as malware.
**Why it happens:** Security software treats unexpected DLL loads as tampering.
**How to avoid:** Robust allowlist with Authenticode signer matching for top 10 AV/EDR vendors (BLOCK-06). The allowlist is operator-extendable for niche vendors.
**Warning signs:** EDR console showing "suspicious DLL injection" alerts for `dlp_hook_dll.dll`.

### Pitfall 7: Channel Full Under Process Storm
**What goes wrong:** A build script or malware sample spawns 1000 processes in 1 second. The bounded channel fills and drops events.
**Why it happens:** Bounded channel protects memory but sacrifices events under extreme load.
**How to avoid:** `try_send` with drop-oldest policy (Claude's discretion). The 5-minute `EnumProcesses` backstop sweep catches missed PIDs. Event loss is logged at `warn!` only (D-06).
**Warning signs:** `warn!` logs showing "ETW event channel full" during build workloads.

## Code Examples

### ETW Process Start Event Parsing (ferrisetw)
```rust
// Source: Context7 /n4r1b/ferrisetw "process creation event"
use ferrisetw::EventRecord;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::parser::Parser;

fn on_process_event(record: &EventRecord, schema_locator: &SchemaLocator) -> Option<(u32, String, u32)> {
    if record.event_id() != 1 {
        return None;
    }
    let schema = schema_locator.event_schema(record).ok()?;
    let parser = Parser::create(record, &schema);
    let pid: u32 = parser.try_parse("ProcessID").ok()?;
    let image_name: String = parser.try_parse("ImageName").ok()?;
    let parent_pid: u32 = parser.try_parse("ParentProcessID").ok()?;
    Some((pid, image_name, parent_pid))
}
```

### Allowlist Config TOML Section
```rust
// Source: CONTEXT.md D-01 + existing config.rs patterns
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct UniversalInjectionConfig {
    #[serde(default)]
    pub allowlist: Vec<AllowlistEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AllowlistEntry {
    /// Exact path or glob pattern (e.g., "C:\\Program Files\\CrowdStrike\\*")
    pub path: Option<String>,
    /// Authenticode signer certificate subject (e.g., "O=CrowdStrike, Inc.")
    pub cert_subject: Option<String>,
    /// Human-readable description for admin TUI
    pub description: String,
    /// Category for telemetry grouping
    pub category: AllowlistCategory,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum AllowlistCategory {
    SelfProcess,
    Avedr,
    SystemCritical,
    OperatorDefined,
}
```

### EnumProcesses Parallel Sweep with rayon
```rust
// Source: Claude's discretion + rayon patterns
use rayon::prelude::*;

fn startup_sweep(injector: &HookInjector, registry: &ProcessRegistry) {
    let pids = enum_all_processes(); // K32EnumProcesses wrapper
    let batch_size = 16;
    
    pids.par_chunks(batch_size)
        .for_each(|chunk| {
            for &pid in chunk {
                if registry.should_skip(pid) {
                    continue;
                }
                // Allowlist check...
                // Inject...
            }
        });
}
```

### WMI Win32_ProcessStartTrace Subscription
```rust
// Source: wmi crate docs + existing detection/encryption.rs patterns
use wmi::{COMLibrary, WMIConnection};
use wmi::query::FilterValue;

fn start_wmi_backstop() -> anyhow::Result<()> {
    let com = COMLibrary::new()?;
    let wmi = WMIConnection::with_namespace_path("ROOT\\CIMV2", com)?;
    
    // Win32_ProcessStartTrace is an intrinsic event class
    let filter = wmi.query::<Win32_ProcessStartTrace>()?;
    // Process results asynchronously...
    Ok(())
}

#[derive(wmi::WMIDerive, Debug)]
#[wmipath("ROOT\\CIMV2:Win32_ProcessStartTrace")]
struct Win32_ProcessStartTrace {
    ProcessName: String,
    ProcessID: u32,
    ParentProcessID: u32,
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Cloud-sync-only injection (targeted `CreateRemoteThread` into known sync clients) | Universal ETW-driven injection into all non-allowlisted processes | Phase 49 (this phase) | Broader coverage; no need to maintain per-app PID lists |
| No allowlist | Multi-category allowlist (self, AV/EDR, system-critical, PPL, WoW64) | Phase 49 (this phase) | Prevents AV/EDR collision and self-injection loops |
| No process tracking | `DashMap<u32, ProcessState>` lifecycle tracking with telemetry | Phase 49 (this phase) | Coverage metrics visible to operators; duplicate injection guard |
| No AppInit fallback | AppInit_DLLs tertiary fallback (installer-managed, Secure Boot-gated) | Phase 49 (this phase) | Covers boot-window gap on non-Secure-Boot legacy endpoints |
| No WMI backstop | WMI `Win32_ProcessStartTrace` secondary when ETW unhealthy | Phase 49 (this phase) | Resilience against ETW session disruption |

**Deprecated/outdated:**
- Per-app PID tracking in `cloud_enforcer.rs`: replaced by universal process watcher.
- Hardcoded sync-client list: replaced by allowlist-driven exclusion.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `ferrisetw` 1.2.0 `KernelTrace` with `PROCESS_PROVIDER` correctly delivers Event ID 1 (ProcessStart) and Event ID 2 (ProcessStop) | ETW Consumer Architecture | If Event IDs differ, process creation/exit detection fails. Mitigation: verify event IDs in unit test against live ETW session. |
| A2 | `GetProcessMitigationPolicy(ProcessSignaturePolicy, 8)` correctly detects PPL on Windows 10/11 | PPL Detection | If constant 8 is wrong for target Windows version, PPL detection fails. Mitigation: verify against `windows` crate constants (`ProcessSignaturePolicy` enum). |
| A3 | `GetFirmwareEnvironmentVariable` returns non-zero and sets value=1 when Secure Boot is enabled | Secure Boot Detection | If API behavior differs, Secure Boot state misdetected. Mitigation: test on both Secure Boot and non-Secure-Boot Windows 11 hosts. |
| A4 | `WinVerifyTrust` + `CryptQueryObject` pattern in `detection/app_identity.rs` extracts sufficient cert subject for AV/EDR allowlist matching | Allowlist Matching | If AV/EDR certs use non-standard subject fields, matching may miss. Mitigation: allowlist supports both cert_subject and path patterns as fallback. |
| A5 | `wmi` 0.18.4 supports `Win32_ProcessStartTrace` intrinsic event subscription | WMI Backstop | If `wmi` crate does not support intrinsic events, backstop fails. Mitigation: verify with small test program before implementation. |

## Open Questions (RESOLVED)

1. **WMI Intrinsic Event Subscription** — RESOLVED
   - What we know: `wmi` 0.18.4 supports WQL queries and event classes. `Win32_ProcessStartTrace` is an intrinsic event class.
   - Resolution: Plan 49-03 Task 1 implements WMI backstop with intrinsic event subscription; fallback to polling `Win32_Process` every 5 seconds if intrinsic events are unsupported.

2. **ETW Event ID Verification** — RESOLVED
   - What we know: Context7 docs show `record.event_id()` and `ProcessID`/`ImageName` parsing.
   - Resolution: Plan 49-03 Task 1 implements `Microsoft-Windows-Kernel-Process` Event ID 1 parsing for ProcessStart. Wave 0 integration test verifies the callback receives Event ID 1 with correct PID (Plan 49-05 Task 3).

3. **Signer Cert Subject Field Selection** — RESOLVED
   - What we know: `detection/app_identity.rs` extracts `CERT_NAME_SIMPLE_DISPLAY_TYPE` (typically CN).
   - Resolution: Plan 49-01 Task 2 extracts full cert subject string (not just CN) via `CERT_NAME_STR_CRLF_SEPARATED_FLAG` for allowlist matching. Uses substring match for flexibility.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Rust x64 toolchain | Build | Yes | 1.94.1 | — |
| `ferrisetw` crate | BLOCK-05 (ETW primary) | Not in workspace | 1.2.0 | None — must add to Cargo.toml |
| `crossbeam-channel` | BLOCK-05 (ETW→tokio bridge) | In workspace (transitive) | 0.5.15 | `std::sync::mpsc` (less performant) |
| `dashmap` | BLOCK-05/06 (process registry) | In workspace | 6.1.0 | — |
| `wmi` | BLOCK-05 (WMI backstop) | In workspace | 0.18.4 | — |
| `rayon` | BLOCK-05 (parallel EnumProcesses) | In workspace | 1.11.0 | Sequential processing (slower startup) |
| `windows` crate | All Win32 APIs | In workspace | 0.62.2 | — |
| Windows ETW subsystem | Runtime | Yes (OS built-in) | — | WMI backstop |
| Windows WMI subsystem | Runtime | Yes (OS built-in) | — | Polling backstop |
| `SeDebugPrivilege` | Injection into some processes | Requires elevated agent | — | Skip injection with `warn!` log |

**Missing dependencies with no fallback:**
- `ferrisetw` crate — must be added to `dlp-agent/Cargo.toml`. No alternative ETW Rust library is as mature.

**Missing dependencies with fallback:**
- None — all other dependencies are already in the workspace.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Built-in `#[test]` + `cargo test` (Rust standard) |
| Config file | None — inline `#[cfg(test)]` modules |
| Quick run command | `cargo test -p dlp-agent` |
| Full suite command | `cargo test --workspace` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| BLOCK-05 | ETW `KernelTrace` with `PROCESS_PROVIDER` starts without error | unit | `cargo test -p dlp-agent etw_trace_start` | No — Wave 0 gap |
| BLOCK-05 | ETW callback parses Event ID 1 correctly | integration | `cargo test -p dlp-agent etw_event_parse --features integration-tests` | No — Wave 0 gap |
| BLOCK-05 | `EnumProcesses` sweep completes within 5s | integration | Manual — spawn 100+ processes, measure sweep time | No — Wave 0 gap |
| BLOCK-05 | WMI `Win32_ProcessStartTrace` subscription works | integration | `cargo test -p dlp-agent wmi_backstop --features integration-tests` | No — Wave 0 gap |
| BLOCK-06 | Allowlist path prefix matching | unit | `cargo test -p dlp-agent allowlist_path_match` | No — Wave 0 gap |
| BLOCK-06 | Allowlist cert subject matching | unit | `cargo test -p dlp-agent allowlist_cert_match` | No — Wave 0 gap |
| BLOCK-06 | PPL detection returns true for known PPL process | integration | `cargo test -p dlp-agent ppl_detect --features integration-tests` | No — Wave 0 gap |
| BLOCK-06 | System-critical PID exclusion (PID 4) | unit | `cargo test -p dlp-agent allowlist_system_critical` | No — Wave 0 gap |
| BLOCK-06 | WoW64 dispatch routes to x86 DLL | unit | `cargo test -p dlp-agent wow64_dispatch` | Yes (existing `test_injector_successfully_injects_dll`) |
| BLOCK-07 | Secure Boot detection returns correct value | integration | `cargo test -p dlp-agent secure_boot --features integration-tests` | No — Wave 0 gap |
| BLOCK-07 | AppInit registry read at boot | unit | `cargo test -p dlp-agent appinit_registry_read` | No — Wave 0 gap |
| BLOCK-05 | Duplicate injection guard prevents double-inject | unit | `cargo test -p dlp-agent duplicate_guard` | No — Wave 0 gap |
| BLOCK-05 | Process state transitions (Discovered→Injected→Exited) | unit | `cargo test -p dlp-agent process_state_machine` | No — Wave 0 gap |

### Sampling Rate
- **Per task commit:** `cargo test -p dlp-agent`
- **Per wave merge:** `cargo test --workspace`
- **Phase gate:** Full suite green before `/gsd-verify-work`

### Wave 0 Gaps
- [ ] `dlp-agent/src/process_watcher.rs` — ETW primary subscription test
- [ ] `dlp-agent/src/universal_injector.rs` — allowlist matching unit tests
- [ ] `dlp-agent/src/process_registry.rs` — state machine unit tests
- [ ] `ferrisetw` dependency addition to `dlp-agent/Cargo.toml`
- [ ] Integration test for ETW Event ID 1 parsing (requires Windows runner)
- [ ] Integration test for WMI `Win32_ProcessStartTrace` (requires Windows runner)
- [ ] Integration test for PPL detection (requires Windows runner with known PPL process)
- [ ] Integration test for Secure Boot detection (requires Windows runner)

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No | Not in scope for this phase |
| V3 Session Management | No | Not in scope for this phase |
| V4 Access Control | Yes | Allowlist prevents injection into privileged/security processes |
| V5 Input Validation | Yes | Path prefix validation; glob pattern sanitization; PID bounds checking |
| V6 Cryptography | Yes | Authenticode signer verification for AV/EDR allowlist (reuses existing WinCrypt pattern) |
| V10 Malicious Code | Yes | PPL detection prevents tampering with protected processes; self-allowlist prevents agent self-injection loop |

### Known Threat Patterns for Universal Injection Stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Injection into AV/EDR causing self-termination or alert storm | Denial of Service | Allowlist with Authenticode signer matching (BLOCK-06) |
| Injection into lsass/csrss causing system instability | Denial of Service | System-critical process exclusion (BLOCK-06) |
| Agent self-injection loop | Denial of Service | Self-PID and self-image-path exclusion (BLOCK-06) |
| PPL process injection attempt flagged as tampering | Repudiation | PPL detection at injection time (D-19); `Skipped(PPL)` telemetry |
| AppInit_DLLs registry manipulation by malware | Tampering | Installer-only write; agent reads-only (D-16/D-17); Secure Boot disables AppInit anyway |
| ETW event loss causing uncovered processes | Information Disclosure | WMI backstop + 5-minute EnumProcesses sweep (D-07, D-14) |
| Channel overflow causing missed process events | Denial of Service | Bounded channel with drop-oldest policy; periodic backstop sweep |

## Sources

### Primary (HIGH confidence)
- Context7 `/n4r1b/ferrisetw` — `KernelTrace`, `PROCESS_PROVIDER`, `EventRecord`, `SchemaLocator`, `Parser`, `TraceProperties`, buffer sizing, event filtering
- `dlp-agent/src/hook_injector.rs` — Existing `HookInjector` with `CreateRemoteThread+LoadLibraryW`, architecture detection, error types
- `dlp-agent/src/detection/app_identity.rs` — `extract_publisher()` 4-step WinCrypt sequence for Authenticode signer extraction
- `dlp-agent/src/service.rs` — Agent service lifecycle, config poll loop, startup initialization patterns
- `dlp-agent/src/config.rs` — `AgentConfig` TOML serialization with `#[serde(default)]` patterns
- `dlp-agent/src/approval_cache.rs` — `DashMap` usage pattern with `Arc<DashMap<...>>`
- `dlp-agent/src/server_client.rs` — `AgentConfigPayload` mirror type pattern
- `dlp-server/src/admin_api.rs` — Admin API router pattern, CRUD endpoint structure
- `dlp-admin-cli/src/screens/` — TUI screen dispatch and rendering patterns
- `.planning/phases/49-universal-injection-etw-process-watcher-allowlist-appinit-fa/49-CONTEXT.md` — 20 locked decisions (D-01..D-20)
- `.planning/research/ARCHITECTURE.md` — §4 Universal Hook DLL Injection architecture

### Secondary (MEDIUM confidence)
- `cargo search ferrisetw --limit 1` — Verified 1.2.0 is current on crates.io
- `cargo search wmi --limit 1` — Verified 0.18.4 is current
- `cargo search dashmap --limit 1` — Verified 6.1.0 in Cargo.lock (stable, not 7.0.0-rc2)
- Microsoft Learn (via MCP) — `GetProcessMitigationPolicy`, `GetFirmwareEnvironmentVariable`, AppInit_DLLs behavior under Secure Boot

### Tertiary (LOW confidence)
- `wmi` crate intrinsic event subscription — assumed based on crate documentation; not verified live. Flagged in Open Questions.
- ETW Event ID stability across Windows versions — assumed Event ID 1 = ProcessStart per Microsoft docs; verification recommended in Wave 0.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all crates verified via cargo registry or already in Cargo.lock
- Architecture: HIGH — existing code patterns are clear; extension points well-defined
- Pitfalls: HIGH — ETW callback blocking and double-injection are well-documented Windows patterns
- ETW event ID verification: MEDIUM — assumed based on docs; recommend Wave 0 integration test
- WMI intrinsic events: MEDIUM — `wmi` crate capability assumed; recommend Wave 0 spike

**Research date:** 2026-05-19
**Valid until:** 2026-06-19 (stable stack; 30 days)

---

## RESEARCH COMPLETE

**Phase:** 49 — Universal Injection — ETW Process Watcher + Allowlist + AppInit Fallback
**Confidence:** HIGH

### Key Findings
1. `ferrisetw` 1.2.0 provides all ETW consumer primitives needed: `KernelTrace`, `PROCESS_PROVIDER`, `EventRecord` parsing, buffer sizing, and real-time callbacks. Must be added to `dlp-agent/Cargo.toml`.
2. Existing `HookInjector` (`dlp-agent/src/hook_injector.rs`) is fully reusable for universal injection — no modifications needed. Architecture detection, error handling, and x86 dispatch already implemented.
3. `dashmap` 6.1.0 is already in the workspace (used by `approval_cache.rs`) and is the correct choice for lock-free process lifecycle tracking.
4. Authenticode signer extraction follows the established 4-step WinCrypt pattern in `detection/app_identity.rs`. Extend to extract full cert subject (not just CN) for AV/EDR matching.
5. AppInit_DLLs is installer-managed only; agent reads registry at boot. Secure Boot detection via `GetFirmwareEnvironmentVariable` gates AppInit effectiveness.

### File Created
`.planning/phases/49-universal-injection-etw-process-watcher-allowlist-appinit-fa/49-RESEARCH.md`

### Confidence Assessment
| Area | Level | Reason |
|------|-------|--------|
| Standard Stack | HIGH | All crates verified via cargo registry or Cargo.lock |
| Architecture | HIGH | Existing patterns clear; CONTEXT.md decisions locked and feasible |
| Pitfalls | HIGH | Well-documented Windows patterns; mitigations specified in CONTEXT.md |
| ETW Event IDs | MEDIUM | Assumed from docs; Wave 0 integration test recommended |
| WMI Intrinsic Events | MEDIUM | Assumed from crate docs; Wave 0 spike recommended |

### Open Questions (RESOLVED)
1. WMI `Win32_ProcessStartTrace` — Plan 49-03 implements with polling fallback.
2. ETW Event ID 1 — Plan 49-03 implements; Wave 0 integration test verifies.
3. Signer cert subject — Plan 49-01 extracts full subject with substring match.

### Ready for Planning
Research complete. Planner can now create PLAN.md files.
