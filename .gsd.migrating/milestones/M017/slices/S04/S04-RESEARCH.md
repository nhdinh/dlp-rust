# S04 Research: Print Spooler Interception

## Summary

S04 delivers print spooler interception using a user-mode-only approach:
1. Watch the Windows print spooler directory for new jobs using `FindFirstPrinterChangeNotification`
2. Parse SHD (spooler header) files to extract document name, user, and printer
3. Parse SPL/XPS files to extract text content for classification
4. Call `SetJob(..., JOB_CONTROL_DELETE)` to cancel blocked jobs before they reach the printer
5. Admin-configurable settings via agent config hot-reload

This slice owns requirements **R003** (print spooler interception with XPS content extraction) and **R005** (admin-configurable print settings).

## Calibrated Depth: Deep

Print spooler APIs are unfamiliar to this codebase. XPS parsing has performance and format risks. The `SetJob` cancellation timing is critical — must happen before the spooler dispatches to the printer port. Multiple approaches exist (port monitor DLL vs directory watch vs print processor). This requires broad exploration.

---

## Existing Codebase Landscape

### Enforcer Pattern (Well-Established)
`UsbEnforcer` (`dlp-agent/src/usb_enforcer.rs`) and `DiskEnforcer` (`dlp-agent/src/disk_enforcer.rs`) follow the same pattern:
- `new(...) -> Self`
- `check(&self, path: &str, action: &FileAction) -> Option<BlockResult>`
- `BlockResult` carries `decision: Decision`, `notify: bool`, identity metadata
- Enforcers constructed in `service.rs` `run_loop_init()` and passed to `run_event_loop()`

**Print enforcer will follow this pattern** but with a different trigger: instead of `FileAction` from the file monitor, it runs on a dedicated thread watching the spooler directory.

### Service Lifecycle Pattern
`service.rs` `run_loop_init()` initializes subsystems in order, stores handles in `RunLoopContext`, tears down in `run_loop_shutdown()`.

**Print watcher will follow this pattern** — construct in `run_loop_init`, store shutdown handle in `RunLoopContext`, signal stop via `watch::Sender<bool>`.

### Windows API Usage
The `windows` crate (v0.62) is already used. Relevant features already enabled:
- `Win32_System_Threading` — process/thread APIs
- `Win32_System_Pipes` — Named pipes (not needed for print)
- `Win32_UI_WindowsAndMessaging` — window/message APIs
- `Win32_System_LibraryLoader` — module handles
- `Win32_Storage_FileSystem` — file APIs

**Missing features needed for print spooler:**
- `Win32_Graphics_Printing` — `OpenPrinterW`, `SetJobW`, `GetJobW`, `FindFirstPrinterChangeNotification`, `FindNextPrinterChangeNotification`, `FindClosePrinterChangeNotification`
- `Win32_Graphics_Gdi` — may need for EMF fallback (deferred to R018)

Must add `"Win32_Graphics_Printing"` to `dlp-agent/Cargo.toml`.

### ABAC Types
`dlp-common/src/abac.rs` `Action` enum needs new variant:
```rust
PRINT,
```
Serialized as `"PRINT"` (literal variant name, following `DRAG_DROP` pattern).

### Config Schema
`AgentConfig` (`dlp-agent/src/config.rs`) and `AgentConfigPayload` (`dlp-agent/src/server_client.rs`) need new fields:
```rust
#[serde(default)]
pub print_enabled: Option<bool>,
#[serde(default)]
pub print_xps_timeout_ms: Option<u64>,
#[serde(default)]
pub print_unclassifiable_action: Option<String>, // "DENY" or "ALLOW"
```

Config hot-reload is already implemented via `apply_payload_to_config()` in `service.rs` — follow the USB config field pattern (diff + apply + empty-string guard).

### Audit Pipeline
`audit_emitter.rs` shows the pattern. Print events should use `EventType::Block` for cancelled jobs and `EventType::Alert` for `SetJob` failures. Need to enrich with printer name, document name, and job ID.

### Test Pattern
`dlp-agent/tests/comprehensive.rs` has stub tests TC-50..52 for print interception. Need real implementations.

---

## Implementation Landscape

### Natural Seams

1. **Print Spooler Watcher (new module: `dlp-agent/src/print_watcher.rs`)**
   - Dedicated std thread with `FindFirstPrinterChangeNotification`
   - Waits for `PRINTER_CHANGE_ADD_JOB` + `PRINTER_CHANGE_WRITE_JOB` events
   - On job added: parse SHD file, parse SPL/XPS file, classify, decide
   - On DENY: call `SetJob(..., JOB_CONTROL_DELETE)`
   - On T3 (`require_auth`): emit Alert event, cancel job (auth dialog deferred — no UI hook in S04)

2. **SHD Parser (new module: `dlp-agent/src/print_shd_parser.rs`)**
   - Parse Windows spooler SHD (spooler header) files
   - Extract: document name, user name, printer name, job ID, submission time
   - SHD format is undocumented but well-reversed in security research
   - Alternative: use `GetJobW` API instead of parsing SHD — simpler and more reliable

3. **XPS Parser (new module: `dlp-agent/src/print_xps_parser.rs`)**
   - SPL files for XPS print jobs are actually ZIP archives containing XML
   - Extract `Documents/1/Pages/1.xml` (or all pages) and parse text content
   - Use `zip` crate + `quick_xml` crate (both pure Rust, no Windows deps)
   - Extract text nodes from `FixedPage` elements
   - Performance concern: parse only first N pages (configurable, default 5)

4. **Print Enforcer (new module: `dlp-agent/src/print_enforcer.rs`)**
   - Thin wrapper around the watcher + parser
   - `PrintEnforcer::new(config) -> Self`
   - `start(&self) -> Result<()>` — spawns watcher thread
   - `stop(&self)` — signals watcher thread to exit
   - Configurable via hot-reload: `update_config(&mut self, new_config)`

5. **ABAC Integration**
   - Add `Action::PRINT` to `dlp-common/src/abac.rs`
   - Add print policy rules to `PolicyMapper` or evaluate via `OfflineManager`
   - Resource path = document name (or printer name + job ID)

6. **Service Integration**
   - Construct `PrintEnforcer` in `service.rs` `run_loop_init()`
   - Store shutdown sender in `RunLoopContext`
   - Signal stop in `run_loop_shutdown()`

### What to Build First (Risk Order)

1. **SHD metadata via `GetJobW`** — Lowest risk. Use Win32 API instead of parsing binary SHD files. Extract doc name, user, status directly.
2. **XPS text extraction** — Build the ZIP+XML parser. Test against sample XPS files.
3. **Print watcher skeleton** — `FindFirstPrinterChangeNotification` loop. Detect jobs, log them, do NOT cancel yet.
4. **Classification integration** — Feed extracted XPS text into `ContentClassifier` (already exists in `policy_mapper.rs`).
5. **Job cancellation** — Wire `SetJob(..., JOB_CONTROL_DELETE)`. This is the highest-risk action (could accidentally cancel legitimate jobs).
6. **ABAC + config integration** — Add `Action::PRINT`, config fields, hot-reload.
7. **End-to-end** — Full flow: print job → detected → parsed → classified → cancelled → audit event.

### Riskiest Element

**`SetJob` cancellation timing.** The spooler may dispatch the job to the printer port between detection and cancellation. Mitigation: watch for `JOB_STATUS_SPOOLING` and cancel before `JOB_STATUS_PRINTING`. If the job transitions to `JOB_STATUS_PRINTING`, emit Alert (detective-only).

---

## Technology Deep-Dive

### Print Spooler APIs

**Detection:** `FindFirstPrinterChangeNotification(hPrinter, dwFilter, dwOptions, pPrinterNotifyOptions)`
- Filter: `PRINTER_CHANGE_ADD_JOB | PRINTER_CHANGE_WRITE_JOB | PRINTER_CHANGE_SET_JOB`
- Returns a handle; wait on it with `WaitForSingleObject`
- On signaled, call `FindNextPrinterChangeNotification` to get change details

**Job Info:** `GetJobW(hPrinter, JobId, Level, pJob, cbBuf, pcbNeeded)`
- Level 1: `JOB_INFO_1W` — basic info (document name, status, priority)
- Level 2: `JOB_INFO_2W` — extended info (user name, machine name, driver name, data type)
- `pDatatype` tells us if it's "XPS_PASS" or "RAW" or "EMF"

**Cancellation:** `SetJobW(hPrinter, JobId, Level, pJobInfo, Command)`
- `Command = JOB_CONTROL_DELETE` — deletes the job
- Requires `JOB_ACCESS_ADMINISTER` access on the printer handle
- `OpenPrinterW` with `PRINTER_ACCESS_ADMINISTER`

**Rust bindings:** Add `"Win32_Graphics_Printing"` to `windows` crate features. All needed APIs are there.

### XPS Content Extraction

XPS spool files are ZIP archives with this structure:
```
[Content_Types].xml
FixedDocumentSequence.fdseq
Documents/1/FixedDocument.fdoc
Documents/1/Pages/1.fpage
Documents/1/Pages/2.fpage
...
```

Each `.fpage` file is XML containing `Glyphs` elements with `UnicodeString` attributes.

**Parsing approach:**
1. Read SPL file as ZIP (`zip::read::ZipArchive`)
2. Iterate entries matching `Documents/*/Pages/*.fpage`
3. For each page: parse XML with `quick_xml::Reader`, extract `UnicodeString` from `Glyphs` elements
4. Concatenate all text, feed to `ContentClassifier::classify()`
5. Stop after N pages (default 5, configurable via `print_xps_timeout_ms` or `print_max_pages`)

**Performance:** A 100-page XPS with images could be large. Limit to first 5 pages for classification. Most sensitive content (headers, footers, first paragraphs) is on early pages anyway.

**Fallback:** If `pDatatype != "XPS_PASS"`, skip XPS parsing and use metadata-only classification (document name + user). Config-driven: `print_unclassifiable_action` = `"DENY"` or `"ALLOW"`.

### SHD Parsing Alternative

Instead of parsing binary SHD files, use `GetJobW(Level 2)` to get:
- `pDocument` — document name
- `pUserName` — submitting user
- `pMachineName` — submitting machine
- `pPrinterName` — printer name
- `Status` — job status bits
- `pDatatype` — "XPS_PASS", "RAW", "EMF", etc.

This is the **recommended approach** — avoids brittle binary parsing, uses documented APIs.

### EMF Fallback (R018 — Deferred)

If `pDatatype == "EMF"`, we cannot easily extract text. Options:
1. Use `GdiGetPageContent` / `GdiGetPageMedia` (undocumented, complex)
2. Convert EMF to XPS via `XpsPrintJobStream` (requires Windows 8+ XPS print APIs)
3. Fallback to metadata-only (document name heuristic)

**Decision for S04:** Metadata-only fallback for EMF. Log a warning. This covers the majority of modern print jobs (XPS is default on Windows 10+).

---

## What Files Change / New Files

### New Files
| File | Purpose |
|------|---------|
| `dlp-agent/src/print_enforcer.rs` | Main print enforcement engine (start/stop/config) |
| `dlp-agent/src/print_watcher.rs` | Spooler directory watcher thread |
| `dlp-agent/src/print_job_info.rs` | `GetJobW` wrapper + `JOB_INFO_1W`/`JOB_INFO_2W` structs |
| `dlp-agent/src/print_xps_parser.rs` | ZIP + XML XPS text extractor |

### Modified Files
| File | Change |
|------|--------|
| `dlp-agent/Cargo.toml` | Add `"Win32_Graphics_Printing"` to windows features; add `zip` and `quick_xml` deps |
| `dlp-common/src/abac.rs` | Add `Action::PRINT` |
| `dlp-agent/src/config.rs` | Add `print_enabled`, `print_xps_timeout_ms`, `print_unclassifiable_action`, `print_max_pages` |
| `dlp-agent/src/server_client.rs` | Add corresponding payload fields |
| `dlp-agent/src/service.rs` | Construct `PrintEnforcer` in `run_loop_init`; shut down in `run_loop_shutdown`; add to `RunLoopContext` |
| `dlp-agent/tests/comprehensive.rs` | Implement TC-50..52 |

---

## Verification Strategy

| Check | How |
|-------|-----|
| `FindFirstPrinterChangeNotification` detects jobs | Unit test: mock print job creation, verify watcher thread detects it |
| `GetJobW` extracts metadata | Unit test: create print job, call `GetJobW`, verify document name matches |
| XPS text extraction works | Unit test: create sample XPS ZIP, extract text, verify content |
| `ContentClassifier` classifies XPS text | Unit test: feed extracted SSN/credit-card text, verify T4 |
| `SetJob(..., JOB_CONTROL_DELETE)` cancels job | Integration test: print document, verify job deleted before printing |
| Config hot-reload updates print settings | Unit test: change `print_enabled` in payload, verify watcher starts/stops |
| EMF fallback to metadata-only | Integration test: print EMF job, verify warning logged, metadata-only classification applied |
| No handle leaks | Run watcher start/stop 1000x, verify no HANDLE leaks via Process Explorer |

---

## Open Questions / Blockers

1. **Admin privilege for `SetJob`:** `OpenPrinterW` with `PRINTER_ACCESS_ADMINISTER` requires admin rights. The agent runs as SYSTEM — this is fine. But verify on non-admin test runs.
2. **XPS print job SPL file path:** The spooler stores SPL files in `C:\Windows\System32\spool\PRINTERS\`. Need to verify this path is consistent across Windows 10/11 versions and locale settings.
3. **Race condition:** Job may complete between `FindNextPrinterChangeNotification` and `SetJob`. Need to check `Status` for `JOB_STATUS_PRINTING` before attempting delete. If already printing, emit Alert instead of cancel.
4. **Print-to-PDF:** Windows "Microsoft Print to PDF" creates XPS files too. Should we intercept these? Yes — it's an exfiltration vector. The XPS parser will handle them.

---

## Sources & References

- Windows Print Spooler APIs: `resolve_library` → `windows` crate docs for `Win32_Graphics_Printing`
- XPS format: ECMA-388 standard (open standard, well-documented ZIP+XML structure)
- SHD format: Undocumented; prefer `GetJobW` API over binary parsing
- `zip` crate: `resolve_library` → `zip` crate docs for ZIP archive reading
- `quick_xml` crate: already familiar; used in other Rust projects

---

## Recommendation to Planner

Decompose S04 into these tasks (in dependency order):
1. **T01:** Add `Action::PRINT` to ABAC types + tests
2. **T02:** Add print config fields to `AgentConfig`/`AgentConfigPayload` + hot-reload plumbing
3. **T03:** Build `print_job_info.rs` — `GetJobW` wrapper, `OpenPrinterW`, `SetJobW` + unit tests
4. **T04:** Build `print_xps_parser.rs` — ZIP+XML text extraction + unit tests with sample XPS
5. **T05:** Build `print_watcher.rs` — `FindFirstPrinterChangeNotification` loop, detect jobs, log metadata
6. **T06:** Integrate XPS parser + `ContentClassifier` into watcher; classify job content
7. **T07:** Wire `SetJob(..., JOB_CONTROL_DELETE)` cancellation with status checks
8. **T08:** Build `print_enforcer.rs` — wrapper with start/stop/config; integrate into `service.rs`
9. **T09:** Implement audit event emission for print blocks/alerts
10. **T10:** Implement TC-50..52 test stubs
