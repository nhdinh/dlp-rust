# Feature Landscape — v0.10.0 Real-Time File Access Prevention

**Domain:** Endpoint DLP file-access blocking on Windows via user-mode hooks + DACL tripwire + ETW bypass detection
**Researched:** 2026-05-12
**Mode:** Subsequent-milestone project research (only NEW features for v0.10.0; existing USB/disk/cloud-sync/print/clipboard/drag-drop coverage NOT re-researched)
**Overall confidence:** MEDIUM-HIGH (industry patterns: HIGH from Microsoft Learn / Forcepoint docs; performance numbers: MEDIUM from Detours benchmarks scaled to modern CPUs)

---

## Reading Order

1. Sections 1-2 set the framing (table-stakes vs differentiator vs anti-feature, complexity hints)
2. Section 3 is the coverage matrix the roadmapper needs to size phases
3. Sections 4-5 are operator UX and audit/forensic field design — feeds the admin-CLI screens phase
4. Section 6 is the performance budget — feeds the hook-DLL latency budget for the per-file decision phase
5. Section 7 is dependencies — feeds phase ordering
6. Section 8 is the SEED-004 fold-in
7. Section 9 is the MVP / cut-list recommendation for the roadmapper

---

## 1. Table Stakes (Must-Ship in v0.10.0)

Industry-standard. If absent, operators evaluating against Microsoft Purview / Forcepoint / Symantec will mark v0.10.0 as not a serious DLP. Sourced from Microsoft Learn Endpoint DLP docs and Forcepoint admin guide.

| Feature | Why Expected | Complexity | Existing Analog |
|---------|--------------|------------|-----------------|
| Universal hook-DLL injection (every user-mode process) | Without this, only registered cloud-sync processes are covered; Explorer copy/move stays passive audit. Closes the v0.9.0 HIGH-severity debt item. | XL | `dlp-agent/src/hook_injector.rs` (CreateRemoteThread template) — generalize from per-process-list to all-user-processes via `AppInit_DLLs` + agent-driven CRT on process-creation events |
| Expanded IAT/inline hook surface: `CreateFileW/A`, `NtCreateFile`, `WriteFile`, `MoveFileExW`, `CopyFileExW`, `DeleteFileW`, `SetFileInformationByHandle` (rename via FILE_RENAME_INFO) | A DLP that blocks open but not rename/delete-after-write is bypassable by a 5-line script. All listed APIs are mandatory in Microsoft Purview's "always audit file activity" surface. | XL | `dlp-hook-dll/src/lib.rs` (currently only `CreateFileW` + `NtCreateFile` for cloud-sync) — pattern reused, surface grows |
| ntdll syscall-stub patching (Detours-style trampoline) | Closes the direct-syscall bypass hole called out explicitly in PROJECT.md outstanding debt. Without this, malware using `syswhispers` / `Hell's Gate` walks past every IAT hook. | L | New module under `dlp-hook-dll/`. No existing analog — `hook_injector` patches IAT, not ntdll syscall entries |
| Per-process AV/EDR allowlist for injection (skip-list) | Injecting into CrowdStrike Falcon, SentinelOne, or Windows Defender will be flagged as malicious DLL injection and either be blocked, cause an EDR alert storm, or crash the AV agent. This is the operational landmine called out in STATE.md decision #10. | M | New `process_allowlist` table; admin-CLI screen new; injection skip in `hook_injector` |
| AV/EDR-safe injection mode: lazy/on-demand injection rather than `AppInit_DLLs` for high-risk processes | `AppInit_DLLs` is well-known to AV/EDR vendors as a malware persistence mechanism. Microsoft has been deprecating it since Win8. Pure-AppInit injection will trip CrowdStrike heuristics. Need fallback to `CreateRemoteThread` for processes spawned after agent start. | L | `dlp-agent/src/hook_injector.rs` (CRT pattern proven for cloud sync) — apply same path to fallback channel |
| DACL tripwire for T3/T4 root paths | Defense in depth: even if the hook DLL crashes or is unloaded, the NTFS kernel still refuses access for non-privileged identities. This is what makes the v0.10.0 architecture credible without a minifilter. | L | New module; closest analog is `wfp_manager.rs` (defense-in-depth network filter that backs the cloud-sync hook) |
| DACL tripwire repair watcher | An AD group reorg, robocopy with `/COPY:DATSOU`, or a domain admin running `icacls /reset` will wipe the Deny ACEs. Without repair, the tripwire silently degrades to zero protection. Mirrors AV "tamper protection" expectation. | M | New module; `notify` 6.x already in deps for filesystem watching; pattern similar to `health_monitor.rs` self-healing loop |
| Local classification cache on hook DLL (`path → classification`) | When the agent is unreachable, the hook cannot block-or-allow a real-time I/O without an answer. Cached classification turns "is this T4?" into a memory lookup. **This is the keystone that makes asymmetric fail semantics actually work** — without it, fail-closed for T3/T4 degrades to fail-closed for *all* files including T1, which breaks the user session. | L | `dlp-common/src/classification.rs` (definitions) — cache is new, lives in hook DLL process |
| Asymmetric fail semantics (fail-closed T3/T4, fail-open T1/T2) | An always-fail-closed hook DLL becomes a denial-of-service to the user session if the agent crashes. An always-fail-open DLL is a DLP bypass. Tier-gated semantics are the standard reconciliation, documented in STATE.md decision #5. | S | Existing fail-closed pattern in cloud enforcer (MEM017) — extend, not replace |
| ETW Kernel-File consumer (suspected syscall-bypass detection) | Once you have ntdll syscall patching, you still need *evidence* that the patching is holding. ETW Kernel-File events that match a path but were never seen by the hook DLL = either a malware-driven bypass or a hook DLL crash. Either deserves an alert. | M | New module in `dlp-agent/src/detection/` (subdir already exists per STRUCTURE.md). No existing ETW consumer in tree |
| Admin CLI Protected Paths screen | Operators MUST be able to view/add/remove DACL-tripwire roots. Without this, the operator's only option is to hand-edit SQLite, which violates the established "no raw-config editing" pattern (Conditions Builder shipped v0.4.0 specifically to retire raw JSON). | M | `dlp-admin-cli/src/screens/` — mirror the disk/USB allowlist screen pattern shipped v0.7.0 |
| Admin CLI Bypass Alerts screen | ETW-detected bypass events without a UI are invisible. Mirror the alert-router shape already wired for SIEM. | M | `dlp-admin-cli/src/screens/` — shape similar to existing audit log screen |
| SIEM relay + alert router wired to bypass events | Bypass events MUST go to SIEM (compliance evidence) and to the alert router (SOC paging). Reuse existing infrastructure. | S | `siem_connector.rs` and `alert_router.rs` exist; just wire the new event type |
| Audit event enrichment for blocked-file events | Today's `AuditEvent` does not carry hook-fired, classification-source, decision-latency, or which-API fields. Forensic investigations need these. See section 5 for field list. | M | `dlp-common/src/audit.rs` — additive change |
| Block-with-deny `ERROR_ACCESS_DENIED` return contract | Already established in v0.9.0 cloud enforcer (MEM017). Same return value across all expanded hooks. Without uniform return, applications see inconsistent errors. | S | `dlp-hook-dll/src/lib.rs` — pattern reused |
| Monitor-only / audit-only deployment mode (per-policy, not global) | EVERY industry DLP guide (Forcepoint, Symantec, Microsoft, ManageEngine) says: deploy in monitor mode first, tune false positives, only then move to block. Without this, v0.10.0 cannot be safely deployed to a production fleet. Operators will refuse. | M | `dlp-common/src/abac.rs` — add `enforcement_mode: Audit/Block/AuditAndBlock` field to policy; PolicyMode already structured |
| Deployment guide: AV/EDR allowlist procedure for global injection | OPS- requirement already in PROJECT.md. The single most likely operational failure for v0.10.0 is "CrowdStrike kills our hook DLL on every endpoint." Document the allowlist procedure for the top 5 EDRs. | S | `docs/operations/` — new doc; no code |
| SD card / optical / virtual drive enumeration (SEED-004) | Bring SD/optical/virtual into the device enumeration registry the same way USB/disk are already enumerated. Most of the *enforcement* falls out for free from the universal hook (it doesn't care about volume class), but the device-list, allowlist, and audit-enrichment UX requires explicit work. | M | `dlp-agent/src/device_registry.rs`, WMI integration already in v0.7.0 via `wmi` crate |

**Subtotal table-stakes complexity: 1 XL × 2, 1 L × 4, 1 M × 7, 1 S × 4 ≈ 4 phases of 1-2 weeks each, including testing**

---

## 2. Differentiators (Ship in v0.10.0 if Scope Allows)

These distinguish v0.10.0 from "another endpoint DLP" and align with the project's defensible position: no kernel driver, no EV cert, but real-time blocking + ABAC + AD.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| Diagnostic mode (which hook fired, why DENY, classification source, decision latency) | Most DLPs answer "was this blocked?" with a one-line audit entry. A diagnostic mode that shows the full decision tree (hook function → classification lookup → policy evaluated → fail mode → decision) cuts incident triage time from hours to minutes. Forcepoint's audit log only carries policy + action; no DLP in the comparison set surfaces the API-level path. | M | New admin-CLI screen; reads from enriched `AuditEvent`. Cheap because the data is already in section 5's enrichment. |
| Override-with-justification dialog (user-facing) | Microsoft Purview has this; Forcepoint has this; Symantec has this. The justification text + per-user override-rate is a leading indicator of policy mis-tuning. Project already has `dlp-user-ui` (iced + tray-icon) so the canvas exists. | M | New `dlp-user-ui/src/dialogs/override.rs`; named-pipe protocol additions for round-trip user-justification → agent → audit |
| Override approval workflow (admin grants temporary exception via TUI) | Once the user submits "I need this for the Q3 close, please grant me 4 hours of T3 access to `\\corp-finance$\`": the request appears in the admin TUI; admin can approve with TTL, audit log captures the chain. `exception_store` schema already exists in tree. | L | `dlp-server/src/exception_store.rs` exists; needs request-state machine; new admin-CLI screen |
| Scheduled enforcement windows (per-policy time-of-day) | "Block T4 to USB outside 7am-7pm corp-time" is a frequent operator ask and not well-supported in the comparison set without custom scripting. Project's ABAC engine already has time-of-day as one of the 5 attributes (PROJECT.md), so the policy-engine work is zero — only operator UX work. | S | `dlp-admin-cli/src/screens/policies/` — new condition-builder option; engine support already shipped v0.5.0 |
| Per-process exemption (transactional, not blanket) | Operator marks `7za.exe` as exempt from T2 hook-firing during a known archive operation, with TTL. Useful when a legitimate enterprise tool fails the universal-hook injection and crashes. | M | Mirror per-process AV/EDR allowlist UX, but with TTL semantics |
| Bypass-alert correlation (which process bypassed, prior process behavior history) | Raw ETW events are noisy. Correlate "process X opened path Y via syscall while not in the hook log" with "process X has prior cloud-uploads to non-corp domain" to elevate severity from yellow to red. This is the kind of analytical layer that separates a DLP from a security platform. | L | Cross-references existing audit store; new aggregation logic |
| Block-event evidence capture (hash of file content at block time) | When DLP blocks a file, capturing SHA-256 of the file content (NOT shipping the bytes — Microsoft Purview does ship the bytes to Azure storage, which is overkill on-prem) gives an investigator a tamper-evident fingerprint of the artifact the user attempted to exfiltrate. Cheap, high forensic value. **Differentiator: hash, not bytes** — matches enterprise legal team preference for "evidence of intent, not chain of custody for content." | S | `dlp-common/src/audit.rs` — extend AuditEvent; small addition |
| Hook-DLL self-health telemetry (per-process inject succeeded/failed, hook-installed/failed counts) | "Did this endpoint actually get hooked?" is a question every operator will ask. Surface per-process inject status via the existing agent → server heartbeat channel. | M | Extend `health_monitor.rs`; admin-CLI heartbeat screen extension |
| AV/EDR-impact dashboard | Aggregate count of "this endpoint reports CrowdStrike present + our hook DLL succeeded/failed/was-uninstalled-within-N-minutes." Tells the operator at a glance whether the AV allowlist procedure is actually being followed. | M | Aggregation only; data sourced from hook-self-health |

**Subtotal differentiator complexity: 1 L × 2, 1 M × 5, 1 S × 2 ≈ 2-3 phases if all included; can be cut individually**

---

## 3. Anti-Features (DO NOT SHIP in v0.10.0)

Things that *look* like obvious wins but should NOT be in v0.10.0 scope. Each is explicitly called out so the roadmapper doesn't drift into them and the planner of each phase doesn't quietly add them.

| Anti-Feature | Why Not | What to Do Instead |
|--------------|---------|-------------------|
| Kernel minifilter driver | PROJECT.md "What This Is Not" + Key Decision: no EV cert. Re-reaffirmed in v0.10.0 milestone scope (REQUIREMENTS.md Out of Scope, PROJECT.md decision context). | Stick to user-mode hooks + DACL tripwire + ETW. |
| Content inspection / pattern matching at hook time | Inspecting file contents inside `CreateFileW` adds N×milliseconds of latency per open. Classification is already resolved upstream (filesystem walk; v0.6.0/v0.7.0 enumeration). Hook is *enforcement*, not classification. | Hook does path → classification cache lookup only. If cache miss, ask agent. Agent owns content inspection. |
| Shipping file bytes to a central evidence store (Microsoft Purview model) | Bandwidth, storage cost, GDPR/PII regulatory headaches. On-prem DLP customers explicitly reject this in vendor evaluations. | Ship SHA-256 hash + file path + classification only (see section 2 differentiator). |
| Blocking SYSTEM-account file access (kernel-mode-like behavior) | Hook is user-mode; SYSTEM-session processes either are the agent itself or are trusted Windows services that the hook should never block. Blocking SYSTEM = self-deadlock. | Identity layer in hook decision: SYSTEM = always-allow path. |
| Per-file decryption / re-encryption (digital rights management) | PROJECT.md "What This Is Not": file encryption at rest is out of scope. NTFS ACLs + ABAC + tripwire are the access-control story. | Defer DRM forever. |
| Real-time content reclassification on file modify | Watching every WriteFile to see if a T1 file gained T3 content would 5-10× the hook overhead. Reclassification is a background pass. | Background `notify` watcher (already in deps) marks files dirty; agent reclassifies async; hook reads cache. |
| Network share write-blocking at the TCP layer (mirror of cloud WFP backstop) | UNC paths reach `CreateFileW` cleanly. WFP is the cloud-sync HTTPS bypass backstop. SMB write goes through the same IAT hook as local writes. No new layer needed. | Universal hook covers UNC. Done. |
| User-mode "Yes/No" prompt that gates *every* T3/T4 access in real time | UX disaster. Even Microsoft Purview only prompts on policy-tip-with-override of a discrete user-initiated action (drag, copy, send). | Use override-with-justification only when policy blocks AND policy is `BlockWithOverride`, not on every access. |
| Centralized cloud-hosted policy engine for v0.10.0 | PROJECT.md "What This Is Not": on-prem with AD dependency. | Defer forever. |
| Browser extension for file-upload introspection | PROJECT.md / REQUIREMENTS.md: deferred to v1.3. Tempting to fold into v0.10.0 since cloud-sync hook already handles browser file pickers via `CreateFileW`. Don't. | Defer to v1.3. Cloud upload already covered by hook-on-browser-process. |
| Inline content-scanning regex engine in the hook DLL | Adds 10s-100s of microseconds per open and creates a fragile second classification path. | Single classification authority: agent's classification module. Hook is decision, not inspection. |
| Replacing existing PnP / Volume-DACL USB+disk enforcement with universal hook | "If you have a hammer, everything looks like a nail." PnP disable is faster, OS-enforced, and shipped. Hook-based USB blocking adds latency for no benefit. | Universal hook is *additive* — covers logical file I/O. USB physical block stays as v0.7.x ships it. |
| Bypass-detection auto-remediation (terminate suspected-bypass processes) | False-positive cost is catastrophic (kill explorer.exe, kill teams.exe). | Detect, alert, log. Operator-initiated remediation only. |

---

## 4. Coverage Matrix — Source × Destination × Action × Tier

### 4.1 Cell-by-cell breakdown

Source/destination volume classes:
- **Local NTFS** (`C:\`, `D:\` fixed disk)
- **Network share / UNC** (`\\corp-fs01\share\`)
- **Removable USB** (already enforced at v0.7.1 PnP layer; hook is additive for content-aware decisions)
- **SD card** (SEED-004 fold-in; presents as a removable volume; hook covers transparently)
- **Optical** (CD/DVD/Blu-ray; presents as a removable volume; write path also goes through `IMAPI2`, but for v0.10.0 the file-system view via `CreateFileW` is what matters)
- **Virtual drive** (mounted ISO via Explorer or Daemon Tools; presents as a fixed-drive-letter volume; hook covers transparently)

Actions:
- **Read / Open (`GENERIC_READ`)** — opening for read
- **Write (`GENERIC_WRITE` on existing file)** — modifying an existing file
- **Create** — `CreateFileW` with `CREATE_ALWAYS` / `CREATE_NEW` (new file)
- **Copy-out** — `CopyFileExW` where dest volume ≠ source volume
- **Move-out** — `MoveFileExW` where dest volume ≠ source volume
- **Rename** — `SetFileInformationByHandle(FileRenameInfo)` or `MoveFileExW` same-volume
- **Delete** — `DeleteFileW` or `SetFileInformationByHandle(FileDispositionInfo)`

Tiers: T1 / T2 / T3 / T4 per PROJECT.md classification.

### 4.2 Required policy support (cells the policy engine must address explicitly)

The ABAC engine evaluates 5 attributes: user identity, resource (path + classification), action, environment (time, host), and now (v0.10.0) source-volume-class + destination-volume-class. **Most cells fall out of ABAC for free; only the source/destination volume-class pair needs new explicit policy support.**

| Cell pattern | Coverage | Notes |
|--------------|----------|-------|
| **Any source → Any dest, T1/T2, any action** | Inferred (ABAC default-allow with audit) | Hook fires, audit recorded; no block. |
| **Any source → Local NTFS, T3/T4, read** | Inferred (ABAC + DACL) | DACL tripwire denies non-privileged; hook redundantly denies; double safety. |
| **Local NTFS T3/T4 → Removable (USB/SD), write/copy-out/move-out** | **Explicit policy** | The single highest-risk exfil cell. New volume-class attribute in policy. |
| **Local NTFS T3/T4 → Network share (UNC), write/copy-out/move-out** | **Explicit policy** | UNC dest detection in path normalization. Allowlist `\\corp-*\` per logical-storage-monitoring-strategy.md. |
| **Local NTFS T3/T4 → Optical (CD/DVD), write** | **Explicit policy (SEED-004)** | New volume-class. Low-frequency but compliance-relevant. |
| **Local NTFS T3/T4 → Virtual drive (mounted ISO), write** | **Explicit policy (SEED-004)** | Virtual ISO is a common malware-staging path; explicit DENY default. |
| **Network share → Local NTFS, read** | Inferred | Pulling FROM corp share is normal; ABAC default-allow with audit. |
| **Network share T3/T4 → Removable, write** | **Explicit policy** | Cross-volume copy-out — same risk profile as local→removable. |
| **Any source → Any dest, delete on T3/T4** | **Explicit policy** | Delete needs its own enforcement axis; operators ask for "T4 read-only" mode. |
| **Any source → Any dest, rename on T3/T4** | **Explicit policy** | Rename is the classic re-classification bypass (T4 file → `report.txt` → T1 cache hit → exfil). Block default; explicit allow-rename. |

**Decision for roadmapper:** add `source_volume_class` and `destination_volume_class` to the ABAC attribute set. Existing user/resource/action/environment attributes plus these two cover the entire matrix above. **5 attributes become 7 attributes** — but only the two new ones require code; existing operators see them as new dropdowns in the Conditions Builder.

### 4.3 Cells that should be explicit but are commonly missed

- **Move-out vs copy-out distinction** — Move-out leaves no source artifact; the operator audit story differs from copy-out ("the file is now on the USB and also on disk" vs. "the file is now only on the USB"). Hook needs to emit a different audit `Action` value.
- **Cross-volume rename** — `MoveFileExW` across volumes is implemented as copy+delete; the hook must detect this and emit `copy-out` semantics, not `rename`.
- **Hard link / junction creation pointing into T3/T4** — `CreateHardLinkW` / `CreateSymbolicLinkW` bypass file-content classification by aliasing the path. Either hook these too, or DACL-deny on the source path mitigates.

---

## 5. Audit / Forensic Field Design

Current `AuditEvent` (per `dlp-common/src/audit.rs` referenced in STRUCTURE.md) carries the basic shape. For a real-time-block event, the additional fields below are forensic table stakes. Sourced from Microsoft Endpoint DLP diagnostic logs schema, Forcepoint audit log fields, and Windows Event 4663 conventions.

| Field | Type | Purpose | Source for Value |
|-------|------|---------|------------------|
| `hook_function` | enum `{ CreateFileW, NtCreateFile, WriteFile, MoveFileExW, CopyFileExW, DeleteFileW, SetFileInformationByHandle, RenameInfo, DispositionInfo }` | Which API the hook fired in. Diagnostic-mode critical. | Hook DLL records on entry. |
| `decision_path` | enum `{ CacheHit, CacheMissPipeOK, CacheMissPipeFail_FailClosed, CacheMissPipeFail_FailOpen }` | How the decision was reached. Tells investigator whether the agent pipe was healthy. | Hook DLL emits. |
| `decision_latency_us` | u64 | Microseconds from hook entry to decision returned. Performance regression detector. | Hook DLL measures via `QueryPerformanceCounter`. |
| `classification_source` | enum `{ InProcessCache, AgentPipe, FailModeDefault, NoClassification }` | Where the T1/T2/T3/T4 came from. Critical for "why did this T3 file get treated as T1?" investigations. | Hook DLL records. |
| `classification_age_sec` | u64 | How stale the cached classification was. Long staleness → reclassification overdue. | Hook DLL records from cache entry timestamp. |
| `source_volume_class` | enum `{ LocalFixed, NetworkShare, RemovableUSB, RemovableSD, Optical, VirtualMounted }` | The new ABAC attribute for cross-volume policy. | Hook DLL via `GetDriveTypeW` + path parsing. |
| `destination_volume_class` | same enum | The other new ABAC attribute. Only populated for copy/move actions. | Hook DLL. |
| `process_image_path` | String | Full path of the process that fired the hook. Forensic anchor for "which app tried to exfil." | Hook DLL via `GetModuleFileNameExW`. |
| `process_command_line` | String | Full command line — distinguishes `7za.exe a` from `7za.exe x`. | Hook DLL via PEB walk or NtQueryInformationProcess. |
| `process_authenticode_signer` | Option<String> | Signing identity (if signed). Already collected in v0.6.0 APP-01; reuse. | `dlp-common` identity module. |
| `parent_process_image_path` | String | Anchors "Word spawned WScript spawned 7za" exfil chain. | Hook DLL via process snapshot. |
| `aumid` | Option<String> | UWP / packaged app identity (v0.8.0 shipped). | Existing identity module. |
| `policy_id` + `policy_version` | (Uuid, u32) | Which policy fired, and its version at decision time. Critical for "did this block decision come from the new policy or the old one?" reconciliation. | Agent records on policy lookup. |
| `policy_mode` | enum `{ Audit, Block, BlockWithOverride }` | Was this policy in audit-only when it fired? Distinguishes "would have blocked" from "did block." | Agent. |
| `override_token` | Option<Uuid> | If the user invoked override-with-justification, the token that links this event to the justification record. | Agent. |
| `override_justification_text` | Option<String> | The actual text the user typed. Mandatory for compliance trails. | Agent. |
| `tripwire_dacl_state` | enum `{ Present, Missing, Repaired, NotApplicable }` | At decision time, what was the DACL tripwire state on the path? Telemetry for tripwire health. | Agent samples; not on hot path. |
| `etw_bypass_correlation_id` | Option<Uuid> | If a matching ETW Kernel-File event was logged within the correlation window without a corresponding hook event, this links them. | Agent correlation pass. |
| `content_sha256` | Option<\[u8; 32\]> | SHA-256 of file content at decision time, if file existed pre-decision. Differentiator per section 2. Skip on Create/CreateNew (no content yet). | Agent (off hot path) on decision. |

**Total: 19 new fields.** All are additive to `AuditEvent`; existing audit consumers (SIEM relay, alert router) need only schema bumps, not breaking changes.

---

## 6. Performance Budget for the Per-File Decision

### 6.1 Target

**p95 ≤ 50 microseconds, p99 ≤ 200 microseconds** for the per-file decision when the classification cache hits.
**p95 ≤ 2 milliseconds, p99 ≤ 10 milliseconds** when the cache misses and the named-pipe round-trip to the agent is required.

### 6.2 Citations and reasoning

- **Microsoft Detours instrumentation overhead is < 400 ns on 200 MHz hardware** (per Microsoft Research Detours paper, surfaced via Apriorit comparison). Modern hardware is 15-25× faster, so the inline hook overhead alone is sub-30-ns on contemporary endpoint CPUs. This is the floor.
- **MinHook overhead is comparable** to Detours per the project author's own benchmarks; both use the same trampoline approach this project's `dlp-hook-dll` already follows for cloud-sync hooks.
- **Antivirus minifilter research** (the closest published analog) measured most overhead on file OPEN, in the low-millisecond range for full content scanning. **v0.10.0 hook does no content scan in-hook** — it does a path-key hashtable lookup against the local classification cache, then a policy-id lookup. Lookups, not scans.
- **Hot-path budget breakdown (target):**
  - Hook entry + register save: < 1 µs
  - Path normalization (lowercase + UNC normalization): 2-5 µs
  - Classification cache lookup (DashMap or RwLock<HashMap>): 1-3 µs
  - Policy evaluation (in-memory PolicyStore, already shipped v0.3.0): 5-15 µs
  - Decision return + audit-event queue (lock-free MPSC): 2-5 µs
  - **Total in-hook: ~15-30 µs typical, ~50 µs p95**
- **Cold-path (cache miss) breakdown:**
  - Above + named-pipe write request: 100-500 µs
  - Agent processing + classify (worst case: filesystem walk): 0.5-5 ms
  - Named-pipe response read: 100-500 µs
  - **Total cold-path: ~1-2 ms typical, ~10 ms p99**

### 6.3 What can blow the budget

| Pitfall | Latency Cost | Mitigation |
|---------|--------------|-----------|
| Synchronous SIEM relay from hook context | 10-500 ms | Audit queue is lock-free MPSC; SIEM relay drains async from agent process, never blocks hook. Already the v0.9.0 pattern. |
| Synchronous DACL repair from hook context | 50-200 ms | DACL repair runs in `notify` watcher, separate thread. Hook never repairs. |
| ETW correlation join in hook | 1-100 ms | Correlation runs on the agent side, post-decision. Hook emits its event; correlator pairs later. |
| classification cache cold start on process attach | 100-500 ms | Cache prefilled from agent on inject; lazy-fill on miss. First-N requests per process pay cache-miss cost; not the steady state. |
| Lock contention on shared cache across threads in same process | 5-50 µs spikes | Use `DashMap` or sharded `RwLock<HashMap>`; avoid `Mutex` per coding standard 9.12. |
| Polling `IsDebuggerPresent` / sanity checks per hook | 1-5 µs each, adds up | Move ALL non-decision logic off the hot path. |

### 6.4 Confidence

- Detours benchmark: HIGH (Microsoft Research paper; cross-referenced via Apriorit)
- Antivirus minifilter analog: MEDIUM (research paper, not a published vendor benchmark)
- The 50 µs / 200 µs p95/p99 target: MEDIUM. It's an engineering target based on the breakdown above. Will need validation at v0.10.0 UAT (HARD-05 fold-in). If real measurements come in at 2× target, that's still inside what users will perceive as "no latency"; if 10× over, redesign required.

---

## 7. Feature Dependencies (Graph for Roadmapper Phase Ordering)

```
Universal hook-DLL injection (BLOCK-)
  ├── Expanded IAT/inline hook surface (BLOCK-)
  │     └── ntdll syscall-stub patching (BLOCK-)
  ├── Per-process AV/EDR allowlist (BLOCK- + OPS-)
  │     └── Deployment guide for AV/EDR allowlist (OPS-)
  ├── Local classification cache on hook DLL (CACHE-)
  │     └── Asymmetric fail semantics (FAIL-)
  │           └── Audit event enrichment for blocked-file events (FAIL- + audit fields §5)
  └── DACL tripwire for T3/T4 (DACL-)
        ├── DACL repair watcher (DACL-)
        └── Admin CLI Protected Paths screen (UX-)

ETW Kernel-File consumer (ETW-)
  └── Admin CLI Bypass Alerts screen (UX-)
        └── SIEM + alert router wiring for bypass events (existing infra; trivial)

SD/optical/virtual enumeration (DRIVE-, SEED-004)
  └── Volume-class ABAC attribute extension (Coverage matrix §4.2)
        └── Source/Destination volume-class in Conditions Builder (UX-)

Monitor-only / Audit-only deployment mode (per-policy)
  └── (no upstream dependencies; can land in parallel with first BLOCK- phase)

Differentiators (any order, parallel with above):
  - Diagnostic mode → depends on audit field enrichment
  - Override workflow → depends on audit field enrichment + exception_store
  - Hash evidence capture → depends on audit field enrichment
  - Hook self-health telemetry → depends on hook-DLL pattern in place
```

**Critical-path observation for the roadmapper:** the BLOCK- chain (universal injection → expanded surface → ntdll patching) is the longest single dependency chain and the highest-complexity (XL). It should be the spine of v0.10.0. Everything else can branch in parallel.

**Suggested phase grouping:**
1. Phase 48-49 — Universal hook injection + AV/EDR allowlist + deployment guide (BLOCK- + OPS-)
2. Phase 50 — Expanded hook surface (BLOCK-)
3. Phase 51 — ntdll syscall-stub patching (BLOCK-)
4. Phase 52 — Local classification cache + asymmetric fail semantics + audit enrichment (CACHE- + FAIL- + audit)
5. Phase 53 — DACL tripwire + repair watcher (DACL-)
6. Phase 54 — ETW Kernel-File consumer + bypass alerts wiring (ETW-)
7. Phase 55 — Admin CLI Protected Paths + Bypass Alerts screens (UX-)
8. Phase 56 — SD/optical/virtual enumeration + volume-class ABAC attribute (DRIVE-, SEED-004)
9. Phase 57 — Monitor-only mode + override-with-justification + admin override approval (differentiators that materially improve deployability)
10. Phase 58 — UAT on real Windows host (folds in HARD-05 informally, per PROJECT.md decision)

---

## 8. SEED-004 Fold-In: What's Free, What's Explicit Work

### 8.1 What falls out for free from the universal IAT hook

**Detection of file I/O on SD / optical / virtual drives** — `CreateFileW(L"E:\\sensitive.docx", ...)` is the same call shape regardless of whether `E:` is a fixed disk, SD card, mounted ISO, or DVD. The universal hook fires identically. No SD-specific, optical-specific, or virtual-specific code needed in the hook DLL.

**Classification & policy evaluation** — Same path → classification → policy pipeline. Classification doesn't know or care about volume class for the decision; only the policy engine does (via the new `source_volume_class` attribute).

**Audit & SIEM** — Same `AuditEvent` shape with the volume-class enrichment field.

### 8.2 What requires explicit work (the SEED-004 surface area in v0.10.0)

| Feature | Why it doesn't fall out for free | Complexity |
|---------|---------------------------------|------------|
| Volume-class enumeration (mark `E:` as SD / Optical / Virtual on mount) | `GetDriveTypeW` returns DRIVE_REMOVABLE for both USB and SD; DRIVE_CDROM for optical; DRIVE_FIXED for mounted ISO (because Windows treats it as a fixed drive). Disambiguation requires WMI queries against `Win32_DiskDrive` and `Win32_LogicalDisk` (already in v0.7.0 pattern). | M |
| Device-allowlist UX for SD readers | Mirrors v0.7.0 USB allowlist screen exactly. New row in device registry; same TUI shape. | S |
| Optical write-mode detection (`IMAPI2` session start) | Optical *writes* via `IMAPI2` happen out of band with `CreateFileW`. For v0.10.0, accept the gap: block at the file-system layer (the staging directory `CreateFileW`s), don't try to hook IMAPI2. | S (but anti-feature: don't hook IMAPI2 in v0.10.0) |
| Virtual-drive mount detection (ISO mount via Explorer or Daemon Tools) | Same `WM_DEVICECHANGE` infrastructure already in v0.7.0 disk enforcer; add a handler branch for virtual mounts. | S |
| Audit enrichment with `source_volume_class` / `destination_volume_class` | Already covered by section 5 audit fields. | (already counted) |
| Policy condition builder UX for volume class | New dropdown in Conditions Builder (admin-CLI). Engine support already exists once attribute is added. | S |

**Total SEED-004 incremental cost on top of universal hook: 1 M + 3 S ≈ a single mid-sized phase. Mostly UX work; the *enforcement* genuinely is free.**

### 8.3 Anti-features inside SEED-004

- **Do not hook IMAPI2 for optical burning in v0.10.0** — diminishing threat surface per SEED-004 doc itself; cost > benefit.
- **Do not enumerate inside ISO contents** — virtual drive enforcement treats the ISO as a black-box mount point; if a T4 file is dragged into it, the hook fires on the `CreateFileW(L"V:\\copy.docx")` inside the mount. No archive introspection.
- **Do not auto-classify SD card contents on insert** — same reasoning as removable USB; classification is on access, not on enumeration.

---

## 9. MVP Recommendation for the Roadmapper

If v0.10.0 must ship a narrower scope (e.g., timeline pressure), here is the cut-list ranked by least-painful-to-defer.

### 9.1 Must-ship (cannot drop without breaking the milestone goal)

1. Universal hook injection + AV/EDR allowlist + deployment guide
2. Expanded hook surface (CreateFile + Write + Move + Copy + Delete + Rename)
3. ntdll syscall-stub patching (drop this and v0.10.0 is no better than v0.9.0 for direct-syscall malware)
4. Local classification cache + asymmetric fail semantics
5. DACL tripwire (the only defense if the hook is uninstalled by AV)
6. Audit event enrichment (forensic completeness)
7. Monitor-only / audit-only deployment mode (cannot safely roll to production without this)
8. ETW consumer + bypass alerts (the architectural promise of the milestone)
9. Admin CLI Protected Paths + Bypass Alerts screens (no UI = invisible feature)

### 9.2 Should-ship (defer with explicit user impact note)

10. DACL repair watcher (without it, tripwires silently degrade — but workaround is manual `icacls`)
11. SD/optical/virtual enumeration (SEED-004) — universal hook already covers I/O; the missing piece is operator UX for the device list
12. Volume-class ABAC attribute — without it, T3-to-USB and T3-to-network-share collapse into one policy rule

### 9.3 Can defer to v0.10.1

13. Override-with-justification dialog (user friction high without it; defer with documented limitation)
14. Admin override approval workflow (manual workaround via PolicyStore edit)
15. Diagnostic mode admin-CLI screen (data is in the audit log; operator can grep)
16. Hook self-health telemetry (operator can SSH onto endpoints to check)
17. Block-event hash evidence capture (audit log captures the path; hash is forensic-bonus)
18. AV/EDR-impact dashboard (data is in heartbeat; aggregator is UX polish)
19. Per-process exemption with TTL (operator can hand-edit AV/EDR allowlist as a workaround)
20. Bypass-alert correlation logic (raw ETW alerts work; correlation reduces SOC fatigue but isn't blocking)

**Recommended MVP: items 1-12. Items 13-20 to v0.10.1 if needed.**

---

## 10. Confidence Assessment

| Area | Confidence | Reason |
|------|------------|--------|
| Table-stakes feature set | HIGH | Cross-referenced Microsoft Purview docs, Forcepoint admin guide, Symantec product reviews, ManageEngine endpoint DLP — convergent feature set |
| Anti-feature calls | HIGH | All grounded in explicit PROJECT.md decisions or REQUIREMENTS.md out-of-scope items |
| Coverage matrix completeness | MEDIUM-HIGH | Source/destination/action axes covered; tier integration is straightforward; edge cases (hard links, junctions) called out |
| Audit field design | HIGH | Forensic field set is standard; Microsoft Endpoint DLP diagnostic logs schema is the primary reference; new fields are additive |
| Performance budget | MEDIUM | Detours benchmark is HIGH; the 50µs/200µs target is engineering judgment scaled from sub-30-ns floor + breakdown — needs UAT validation |
| SEED-004 fold-in scope | HIGH | SEED-004 doc + logical-storage-monitoring-strategy.md both already scope this; v0.10.0 fold-in is mechanical |
| Phase ordering | HIGH | Dependency graph in §7 is derived from REQUIREMENTS.md REQ-IDs and STATE.md decisions; no ambiguity |

## 11. Sources

Microsoft Learn:
- [Using Endpoint DLP](https://learn.microsoft.com/en-us/purview/endpoint-dlp-using)
- [Configure endpoint DLP settings](https://learn.microsoft.com/en-us/purview/dlp-configure-endpoint-settings)
- [Learn about Endpoint data loss prevention](https://learn.microsoft.com/en-us/purview/endpoint-dlp-learn-about)
- [Data Loss Prevention policy reference](https://learn.microsoft.com/en-us/purview/dlp-policy-reference)
- [Get started with oversharing pop ups](https://learn.microsoft.com/en-us/purview/dlp-osp-get-started)
- [Learn about evidence collection for file activities on devices](https://learn.microsoft.com/en-us/purview/dlp-copy-matched-items-learn)
- [Analyze Endpoint DLP Diagnostic Logs](https://learn.microsoft.com/en-us/troubleshoot/microsoft-365/purview/data-loss-prevention/analyze-endpoint-dlp-diagnostic-logs)
- [Event 4663](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4663)
- [Minifilter Diagnostics](https://learn.microsoft.com/en-us/windows-hardware/test/assessments/minifilter-diagnostics)

Forcepoint:
- [Tuning policies](https://help.forcepoint.com/dlp/90/dlphelp/81ECF879-800B-47DA-A3EA-BD16F263F6A3.html)
- [Fine-tuning DLP Policies](https://learn.forcepoint.com/learn/article/fine-tuning-dlp-policies)
- [The Forcepoint DLP audit log](https://help.forcepoint.com/dlp/10/dlphelp/4A2A1968-75E6-45B3-B409-6EE4115CB493.html)
- [Forcepoint DLP 10.0 Deployment Guide](https://help.forcepoint.com/dlp/10/dlp_deploy/dlp_deploy.pdf)

API hooking and performance:
- [Apriorit — API Hooking Libraries Comparison](https://www.apriorit.com/dev-blog/win-comparison-of-api-hooking-libraries)
- [MinHook GitHub](https://github.com/TsudaKageyu/minhook)
- [How to analyze Windows minifilter performance impact](https://illuminati.services/2022/09/15/how-to-analyze-windows-minifilter-performance-impact-one-simple-method/)
- [Precise Performance Characterization of Antivirus on the File System Operations (research)](https://www.researchgate.net/publication/343510445_Precise_Performance_Characterization_of_Antivirus_on_the_File_System_Operations)

DLP product context:
- [Symantec DLP Tuning](https://symantec-enterprise-blogs.security.com/blogs/expert-perspectives/tuning-dlp-success)
- [ManageEngine — False Positives Handling](https://www.manageengine.com/endpoint-dlp/false-positives-handling.html)
- [Custom Oversharing Dialog for Purview DLP](https://office365itpros.com/2026/02/12/custom-oversharing-dialog-dlp/)

Internal references:
- `.planning/PROJECT.md`
- `.planning/REQUIREMENTS.md`
- `.planning/STATE.md`
- `.planning/deferred-ideas/SEED-004-sd-optical-virtual-drive-monitoring.md`
- `.planning/research/logical-storage-monitoring-strategy.md`
- `.planning/codebase/STRUCTURE.md`
