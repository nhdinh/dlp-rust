# Domain Pitfalls — v0.10.0 Real-Time File Access Prevention

**Domain:** Windows endpoint DLP — universal user-mode hook DLL + DACL tripwire + ETW bypass detection
**Researched:** 2026-05-12
**Scope:** Adding active blocking to a v0.9.0 codebase that today blocks USB / disk / cloud-sync / print / drag-and-drop / clipboard. No kernel driver, no minifilter, no EV code-signing cert.
**Confidence:** HIGH on Microsoft-documented behaviour (AppInit_DLLs, PPL, ACE order, ETW buffers); MEDIUM on vendor-specific AV/EDR allowlist procedures (vendor docs are public but quickly stale).

---

## Critical Pitfalls

Mistakes that cause rewrites, BSODs, mass endpoint outages, or fundamental milestone failure.

---

### CRIT-01 — AppInit_DLLs is silently disabled on Secure-Boot endpoints

**What goes wrong:** The agent registers `dlp-hook-dll.dll` in `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` and sets `LoadAppInit_DLLs = 1`. On every endpoint where UEFI Secure Boot is enabled (the default on every Windows 10/11 OEM machine since 2016), the loader **never reads the key**. The hook DLL is never injected into any user process. The DACL tripwire and ETW consumer still work — so the agent looks healthy and audit events flow — but real-time CreateFile blocking silently does nothing.

**Why it happens:** Microsoft hard-disabled the AppInit_DLLs codepath in `kernel32!_BaseDllInitialize` when Secure Boot is on, starting with Windows 8. Microsoft explicitly documents this as an anti-malware countermeasure ("no-compromise approach"). There is no registry override. There is no Group Policy to re-enable it. The replacement Microsoft recommends is: do not do global DLL injection.

**Consequences:**
- Silent failure mode — DLP appears to be enforcing but is not. Worst-possible compliance posture (audit says "we have DLP" but no enforcement is happening).
- Test environments (often dev VMs with Secure Boot off) will not catch this; production endpoints (Secure Boot on) will fail.
- Customer endpoints where IT has hardened the BIOS will be the first to fail.

**Prevention:**
- AppInit_DLLs is the **fallback only**. Primary injection MUST be agent-driven `CreateRemoteThread` (already implemented in `dlp-agent/src/hook_injector.rs`) hooked to a process-creation event source (WMI `Win32_ProcessStartTrace` or ETW `Microsoft-Windows-Kernel-Process`).
- At service start, the agent MUST query Secure Boot status via `GetFirmwareEnvironmentVariableW` / `Win32_DeviceGuard` and log a WARNING `siem.appinit_dlls_disabled = true` audit event so SOC can see when the fallback is dead.
- Health-check ping from hook DLL: on `DLL_PROCESS_ATTACH`, fire a one-shot named-pipe "hello" to the agent within 500 ms; the agent maintains a `process → injected?` map and alerts when freshly spawned user processes never check in.
- Document in deployment guide: "Secure Boot endpoints rely on `CreateRemoteThread` injection only; AppInit_DLLs is a no-op there."

**Detection:** Health-check telemetry comparing ETW process-create count to hook-DLL-attach count; mismatch = injection failure.

**Recommended phase:** **Phase 1 (BLOCK-injection)** — the injection mechanism must be designed Secure-Boot-aware from day one. Adding it later forces a re-architecture of the injection loop.

**Sources:** [AppInit DLLs and Secure Boot — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/dlls/secure-boot-and-appinit-dlls) — confidence HIGH (official Microsoft doc, primary source).

---

### CRIT-02 — Hook DLL crash inside CreateFileW terminates the host process

**What goes wrong:** The hook DLL panics or dereferences a null pointer inside `HookCreateFileW`. Rust panic in a `extern "system"` function is undefined behaviour; in practice it aborts the process. The "host process" is whatever happened to call `CreateFileW`: Word saving a draft, Outlook flushing OST, an installer, `lsass` rotating SAM, `svchost` writing the event log. The user sees the host process crash, loses unsaved data, and blames DLP. Repeated crashes get DLP uninstalled enterprise-wide within a week.

**Why it happens:** The current `dlp-hook-dll` code path does several risky things in hot path:
- `std::time::Instant::now()` (allocates TLS on first call in some host loaders).
- `format!` with allocator calls (allocator may be poisoned if host has its own).
- A blocking named-pipe round-trip with 50 ms timeout that can race with shutdown.
- `pcwstr_to_string` walks an attacker-influenced wide string with no length cap.

A single null `lpfilename` (legal per CreateFileW docs for some flag combinations on `\\?\` paths) walks past page boundaries and AVs.

**Consequences:**
- Catastrophic reputation hit. Each host crash is a P0 ticket from the customer.
- Microsoft Office crashes are the highest visibility — Word/Excel/PowerPoint will be the most-exercised CreateFileW callers on any endpoint.
- Crash dumps in `WerFault` will name `dlp_hook_dll.dll`, making attribution unmistakable.

**Prevention:**
- Wrap the entire hook body in `std::panic::catch_unwind`. On catch, fall through to the original `CreateFileW` (fail-OPEN, not fail-closed) and log via `OutputDebugStringW` only. **Rationale:** crash-then-deny is worse than crash-then-allow for a hook DLL — denying writes corrupts the host's state machine; allowing keeps the host alive and the file gets caught by DACL tripwire or ETW anyway.
- Cap `pcwstr_to_string` at 32,768 chars (Windows MAX path limit including `\\?\` prefix) — the current implementation has no cap.
- Pre-allocate the pipe buffer in `init()`, never in the hot path.
- Replace `format!` debug logs with a fixed-size stack buffer + `core::fmt::Write` to avoid the allocator entirely in the hot path.
- Build hook DLL with `panic = "abort"` in release **with** SEH translation: in MSVC-style `__try/__except` around each hook entry, return original function on `EXCEPTION_ACCESS_VIOLATION`. Rust's `windows-targets` and `seh` crates support this.
- Crash domain isolation: chaos-test the hook DLL with `AddressSanitizer` + a fuzzer feeding malformed `OBJECT_ATTRIBUTES` and adversarial wide strings.

**Detection:** `WerFault` event log entries mentioning `dlp_hook_dll`. SIEM rule: any `Application Error` event with FaultModuleName=`dlp_hook_dll.dll` is a P0.

**Recommended phase:** **Phase 2 (BLOCK-hook-DLL hardening)** — defensive coding must be designed in, not bolted on. Existing v0.9.0 hook DLL needs the same retrofit.

**Sources:** Code review of `dlp-hook-dll/src/lib.rs` (current state); CLAUDE.md §9.10 "MUST call `.clone()` explicitly", `dlp-agent/src/clipboard/listener.rs` SAFETY pattern (existing convention).

---

### CRIT-03 — ntdll syscall-stub patching collides with EDR ntdll hooks

**What goes wrong:** v0.10.0 patches `ntdll!NtCreateFile` (and friends) with an inline trampoline to close the direct-syscall bypass. CrowdStrike, SentinelOne, Carbon Black, and Defender for Endpoint **all do the same thing** to ntdll, often with longer prologue overwrites (10-20 bytes). Two cases play out:

1. **EDR patches first, DLP patches second:** Our overwrite destroys the EDR's first-jump instruction. EDR loses telemetry on that process. Some EDRs reactively repatch every N seconds, creating a hook ping-pong that consumes CPU. Worse, some EDRs detect tampering and flag dlp-hook-dll as malware → quarantine.
2. **DLP patches first, EDR patches second:** EDR's overwrite destroys our trampoline. Our hook silently dies. Same silent-failure mode as CRIT-01.

If both sides chain trampolines naively (jmp to jmp to jmp) and one side's trampoline points to a now-freed VirtualAlloc region after a process recycles handles, AV in handler → process crash (CRIT-02).

**Why it happens:** ntdll syscall stubs are global per-process; first-write-wins. There is no Windows-blessed coordination protocol between user-mode hooking products.

**Consequences:**
- Direct-syscall bypass remains open (the hole we tried to close stays open).
- EDR may classify the agent as malicious; mass quarantine event.
- Host process crashes on hook chain corruption.

**Prevention:**
- **Detect-before-patch.** Before overwriting any ntdll syscall stub, read the first 16 bytes and check the byte pattern. Microsoft's standard syscall prologue is `4C 8B D1 B8 ?? ?? ?? ?? F6 04 25 ...` (`mov r10, rcx; mov eax, <syscall_num>; test [...]`). If the prologue differs (e.g., starts with `E9` near-jump, or `48 B8` movabs+jmp), an EDR is already there. **Do not patch.** Skip that syscall and rely on the IAT hook + DACL tripwire + ETW as fallback.
- Document the supported-EDR matrix: list which EDRs we co-exist with (by detecting their prologue signature) vs which we refuse to load alongside.
- **Never** restore "clean" ntdll bytes from disk (the DoppelGate / NtUnhook technique). That technique stomps EDR hooks deliberately and will get DLP flagged by every modern EDR as evasion malware.
- Phase the ntdll patching deployment behind a feature flag (`enable_ntdll_patching = false` by default). Roll out per-customer after compatibility testing.
- Add a startup compatibility test: agent enumerates known EDR processes (CSFalconService.exe, SentinelAgent.exe, MsMpEng.exe, CarbonBlack/cb.exe, etc.); if any are present, log a compatibility-mode warning and disable ntdll patching for that endpoint.

**Detection:** Health-check telemetry on every endpoint reports "ntdll patching: enabled / disabled-by-edr-detected"; SIEM dashboard shows coverage gap.

**Recommended phase:** **Dedicated phase: BLOCK-ntdll-coexistence** — this cannot be folded into a generic "ntdll patching" phase; it is its own risk surface. Put it after the IAT hook is stable so we can rely on a fallback.

**Sources:** [Detecting Hooked Syscalls — ired.team](https://www.ired.team/offensive-security/defense-evasion/detecting-hooked-syscall-functions), [An Introduction to Bypassing User Mode EDR Hooks — malwaretech.com](https://malwaretech.com/2023/12/an-introduction-to-bypassing-user-mode-edr-hooks.html), [DoppelGate (GitHub)](https://github.com/asaurusrex/DoppelGate). Confidence MEDIUM-HIGH (well-documented in offensive-security literature; EDR vendors do not publish their hook details).

---

### CRIT-04 — Performance death-spiral on build/install workloads

**What goes wrong:** A developer runs `cargo build` (or an installer extracts thousands of files). The build opens 50,000 files per minute. Every `CreateFileW` becomes a named-pipe round-trip to the agent. Even at 1 ms per round-trip, that is 50 seconds of latency injected into a 60-second build. With 50 ms timeouts (current spec) and any agent congestion, builds take 10× longer or hang. Users hate DLP and IT escalates.

**Why it happens:** The classification cache (planned: `path → classification`) is only effective for repeated paths. First-touch latency on every new path goes through the pipe. A typical compile touches MSVC system headers, Cargo dependency .rlibs, and target/ artifacts — many are first-touch every build.

**Consequences:**
- Power-user complaints (devs, sysadmins, install techs).
- Pressure to disable hooks for "trusted apps" → process allowlist becomes a giant bypass surface.
- AV/EDR baseline workload doubles (their hooks + ours, both serialized).

**Prevention:**
- **Per-process allowlist.** Inject the hook DLL into every process, but inside the DLL, check `GetModuleFileNameW(NULL)` against an allowlist of trusted binaries (devenv.exe, cargo.exe, msbuild.exe, msiexec.exe). For allowlisted hosts, the hook calls `original` directly without a pipe round-trip. The DACL tripwire + ETW still catch real T3/T4 access from these processes.
- **Trusted-path allowlist.** Inside the hook, skip pipe round-trip when path starts with `C:\Windows\System32\`, `C:\Windows\WinSxS\`, `C:\Program Files\WindowsApps\`, `%SystemRoot%\Microsoft.NET\`. These paths can never be T3/T4 by policy.
- **Local classification cache.** Already in v0.10.0 scope (CACHE-). Critical that cache is per-process (in-DLL, not in-agent) so cache hits never cross the IPC boundary. TTL 5 minutes, max 4096 entries (≈400 KB).
- **Batch / coalesce.** If the same process opens the same path 100× in 1 second, only the first should hit the agent. The DLL caches the decision for that (path, sid) pair.
- **Async non-blocking mode for T1/T2.** For paths that classify provisionally as T1/T2 (e.g., not under any DACL-tripwire root), the hook calls `original` immediately and queues an after-the-fact telemetry event. Only T3/T4 paths block-and-wait.
- **Benchmark gate.** Before merging the hook DLL, run a canonical build workload (`cargo build --workspace --release` on dlp-rust itself) with and without DLP. Block merge if overhead > 25%.

**Detection:** Hook DLL emits p50/p99 latency metrics every 1000 calls; agent rolls them up and alerts on regression.

**Recommended phase:** **Phase 4 (CACHE-) and Phase 5 (perf-validation)** — cannot ship without a perf-validation phase.

**Sources:** Existing v0.9.0 hook DLL pattern (no per-process allowlist today — confirmed by reading `dlp-hook-dll/src/lib.rs`). General industry experience with global hooks.

---

### CRIT-05 — Cannot inject into Protected Process Light (PPL) processes

**What goes wrong:** Major processes on every endpoint are PPL: `lsass.exe` (when LSA protection is on — default on Windows 11), `csrss.exe`, `services.exe` (WinTcb), `smss.exe`, `MsMpEng.exe` (Defender), `WdNisSvc.exe`, EDR agents (CrowdStrike CSFalconService, SentinelAgent, etc.). `CreateRemoteThread` and `OpenProcess(PROCESS_ALL_ACCESS)` fail with `ERROR_ACCESS_DENIED` against these from a non-PPL caller, **even from SYSTEM**. A T4 file copied or opened by any of these processes is unblocked by the hook DLL.

**Why it happens:** PPL is by design: a process with protection level N can only be opened with full access by a process of protection level ≥ N + signer level. SYSTEM is not enough; the caller must itself be a higher-tier PPL. dlp-agent is not signed at WindowsTcb signer level (we have no EV cert and no Microsoft kernel-mode signing). Therefore PPL processes are unreachable.

**Consequences:**
- A coverage gap. T4 file read/write by a PPL process is invisible to the hook DLL.
- Real-world attack: an attacker who escalates to a service running as PPL (rare but possible via CVE chains) bypasses DLP entirely.
- Compliance auditor question: "is DLP universal?" Honest answer: no, PPL processes are uninstrumented.

**Prevention:**
- **Document the gap.** This is not fixable in v0.10.0 without kernel-mode signing. The deployment guide MUST list PPL processes as out-of-scope for hook-based enforcement.
- **DACL tripwire is the backstop.** PPL processes still go through NTFS. Explicit Deny ACEs for the operator's AD group on T3/T4 root paths block PPL writes (and reads, if Deny includes `FILE_READ_DATA`). DACL is kernel-enforced — PPL doesn't bypass NTFS.
- **ETW is the backstop telemetry.** `Microsoft-Windows-Kernel-File` records file events from all processes including PPL. If a PPL process opens a T3/T4 path, ETW catches it. Surface as "PPL access" event in the Bypass Alerts screen.
- **Threat model statement.** PPL processes are part of the Trusted Computing Base. We trust them. If they are compromised, the endpoint is compromised — DLP is not the layer to defend against that.
- **Operational guidance.** Customers worried about PPL-based exfiltration should use Defender ASR rules, not expect DLP to cover this gap.

**Detection:** Agent enumerates running processes, attempts `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`, and reports which it could NOT open. The list is the PPL-coverage gap, reported once per boot.

**Recommended phase:** **Phase 1 (BLOCK-injection)** — must define which processes we inject into and which we don't, documented as accepted gap.

**Sources:** [Configure added LSA protection — Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection), [The Evolution of Protected Processes — CrowdStrike](https://www.crowdstrike.com/en-us/blog/evolution-protected-processes-part-1-pass-hash-mitigations-windows-81/). Confidence HIGH.

---

### CRIT-06 — AV/EDR vendors quarantine the agent as malware

**What goes wrong:** dlp-agent runs `OpenProcess(PROCESS_ALL_ACCESS)` + `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` on every user process startup. This is the textbook signature of malware. Defender for Endpoint, CrowdStrike Falcon, SentinelOne, and Carbon Black **all** ship behavioural rules that detect this exact pattern. Within minutes of deployment on a fleet running EDR:
- CrowdStrike: "Suspicious Process Injection — Detection" → process killed, file quarantined, alert to SOC.
- Defender: "Behavior:Win32/SuspInjector" → file quarantined.
- SentinelOne: Behavioral AI engine flags `CreateRemoteThread` from a service into user processes → killed.

Result: agent is killed on every endpoint within hours. v0.10.0 ships and immediately rolls back.

**Why it happens:** The injection technique is **identical** to malware. There is no API-level distinction between malicious and legitimate `CreateRemoteThread`.

**Consequences:**
- Mass deployment failure.
- Customer support firefighting.
- Possible signature retraining cycle from AV vendors (weeks).

**Prevention (must be done per-vendor, before customer deployment):**
- **Microsoft Defender for Endpoint**: Customer admin adds an Indicator → file hash allow for `dlp-agent.exe` and `dlp_hook_dll.dll`. Documented at `https://learn.microsoft.com/en-us/defender-endpoint/manage-indicators`. ASR rule "Block process creations originating from PSExec and WMI commands" (`d1e49aac-...`) needs explicit exception for dlp-agent.
- **CrowdStrike Falcon**: Customer admin adds dlp-agent path + hash to "ML Exclusions" and "IOA Exclusions" in Falcon console. Documented per CrowdStrike Support article (customer-only access). Specifically, "ML Hash" exclusion for dlp_hook_dll.dll; "Sensor Visibility Exclusions" for the agent install path.
- **SentinelOne**: Customer admin creates a Path Exclusion (Mode: Suppress Alerts) for the agent install dir, plus a Hash Exclusion for the hook DLL. Process Exclusion for dlp-agent.exe.
- **Carbon Black (VMware/Broadcom)**: Customer admin sets the agent path to "Allow & Log" in the Policy editor → Permissions tab. Add path rules for `C:\Program Files\DLP\*`.
- **Sophos Intercept X**: Tamper-protection often blocks injection even when allowlisted; need explicit "Allow application" + "Disable detection of suspicious behaviour" for the agent. Last-resort vendor.
- **Trend Micro Apex One**: Behaviour Monitoring exception list.

**Vendors with known coexistence problems (likely cannot ship alongside without explicit pre-prod testing):**
- **Sophos Intercept X with HitmanPro.Alert** — aggressive tamper protection.
- **Bitdefender Advanced Threat Defense** — even allowlisted, may intercept `CreateRemoteThread` calls.
- Any vendor in "lockdown" or "tamper-proof" mode by policy.

**Mitigations beyond allowlisting:**
- **Authenticode-sign** every binary (agent .exe, hook DLL, all crates). Regular Authenticode certs ($300/year) — see CRIT-08 — significantly reduce false-positive rate even without EV.
- **Submit binaries to Microsoft for analysis** (`https://www.microsoft.com/en-us/wdsi/filesubmission`) to get them on the Defender clean-list.
- **Publish hashes** in the deployment guide so admins can pre-allowlist before install.
- **Use a custom thread-name** ("DLP-Hook-Loader") on the remote thread to aid SOC triage of what is actually a known-good injection.

**Recommended phase:** **Phase 8 (OPS-deployment-guide)** — but vendor outreach should start in Phase 1 so support contacts and reference customers exist by ship date.

**Sources:** [SentinelOne — What is Process Injection](https://www.sentinelone.com/cybersecurity-101/cybersecurity/process-injection/), [Black Lantern Security — Detecting Process Injection](https://blog.blacklanternsecurity.com/p/detecting-process-injection). Vendor-specific allowlist procedures: customer-facing console docs (URLs change frequently). Confidence MEDIUM (allowlist procedures are documented but vendor UIs evolve).

---

## Moderate Pitfalls

Mistakes that cause significant rework, deployment friction, or partial feature failure.

---

### MOD-01 — RequireSignedAppInit_DLLs is on by default on Windows 8+, AppInit_DLLs without an Authenticode signature is silently ignored

**What goes wrong:** Agent registers `dlp_hook_dll.dll` in AppInit_DLLs. The DLL is unsigned (debug build, or shipped without code signing). `RequireSignedAppInit_DLLs = 1` is the default on Windows 8 and later. The loader silently refuses to load the unsigned DLL. Same silent-failure mode as CRIT-01.

**Why it happens:** Microsoft set this default as a defence against AppInit_DLLs malware. The registry value lives under the same key as `AppInit_DLLs`.

**Prevention:**
- **Authenticode-sign the hook DLL.** A regular code-signing certificate from Sectigo, DigiCert, or GlobalSign costs ~$300/year and is sufficient — `RequireSignedAppInit_DLLs` does NOT require EV. (EV is only required by Microsoft for **kernel-mode** drivers and SmartScreen reputation, not user-mode AppInit_DLLs.)
- The signing process: `signtool sign /tr http://timestamp.digicert.com /td sha256 /fd sha256 /a dlp_hook_dll.dll`. Timestamp is mandatory so signature outlasts cert expiry.
- Build pipeline must sign on every release build. Debug builds for dev can set `RequireSignedAppInit_DLLs = 0` on the dev box only (documented as dev-only).
- HSM or Windows Token: store the signing key on a YubiKey or Azure Key Vault. **Never** check the key into git.

**Recommended phase:** **Phase 8 (OPS-deployment-guide)** for production; **Phase 1 (BLOCK-injection)** for the build/sign harness so dev/test work end-to-end.

**Sources:** [Authenticode Signing — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/dxtecharts/authenticode-signing-for-game-developers). Confidence HIGH for Authenticode-vs-EV distinction.

---

### MOD-02 — AppInit_DLLs needs separate x86 and x64 registry entries for WoW64

**What goes wrong:** Agent registers the x64 hook DLL in `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs`. Every 32-bit user process (still common: 32-bit Office add-ins, legacy LOB apps, many installers, older Java apps) loads through the WoW64 view at `HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs`. The x64 DLL cannot load into a 32-bit process. Half the processes on a typical endpoint go uninstrumented.

**Why it happens:** WoW64 reflects HKLM\Software to Wow6432Node for 32-bit clients. The AppInit_DLLs key follows the standard redirection rule.

**Prevention:**
- Build **two hook DLLs**: `dlp_hook_dll_x64.dll` (target = x86_64-pc-windows-msvc) and `dlp_hook_dll_x86.dll` (target = i686-pc-windows-msvc). The current `HookInjector::dll_path_x86: Option<PathBuf>` field anticipates this — must be populated, not left None.
- Register the x64 DLL in the native registry path; register the x86 DLL in the Wow6432Node path.
- Both DLLs share the same Rust crate; only build target differs. CI builds both.
- `CreateRemoteThread` injection MUST check target architecture (already done in `target_architecture()` via `IsWow64Process` — confirmed by reading the source) and select the right DLL.

**Recommended phase:** **Phase 1 (BLOCK-injection)** — build matrix must include both targets from the start.

**Sources:** [WoW64 registry redirection — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/sysinfo/32-bit-and-64-bit-application-data-in-the-registry). Confidence HIGH.

---

### MOD-03 — DACL canonical-order pitfall: inherited Allow can override explicit Deny on a child

**What goes wrong:** Operator adds an explicit Deny ACE on `C:\T4_Data\` for "Everyone except DLP-Admin." Underneath, `C:\T4_Data\subdir\file.docx` already has an explicit Allow ACE inherited from a parent share permission (e.g., a previously set "Authenticated Users:Modify"). According to canonical ACE order, **explicit Allow on the child overrides inherited Deny from the parent**. The file is accessible despite the parent Deny.

**Why it happens:** Microsoft's documented evaluation order:
1. Explicit Deny ACEs on the object itself.
2. Explicit Allow ACEs on the object itself.
3. Inherited Deny ACEs.
4. Inherited Allow ACEs.

If a child has its own explicit ACEs (set by previous operator, app installer, or backup tool), they take precedence over parent inheritance.

**Prevention:**
- **Tripwire writer enumerates the subtree.** Before declaring "T4 is protected," walk the tree and replace, not append, ACE entries on every descendant. Use `SetNamedSecurityInfoW` with `PROTECTED_DACL_SECURITY_INFORMATION` to break inheritance on the root, then re-apply explicit Deny + Allow tuple to every descendant.
- Audit log every ACE conflict found ("file X had explicit Allow for SID Y; tripwire replaced it").
- ACL size limit is **64 KB**, not 1024 ACEs as in the original question — large groups with many SIDs can hit it.
- ACL size check: before writing, compute total bytes; if > 60 KB, fail with a clear operator error ("DACL exceeds 64 KB Windows limit; consolidate group membership").
- **Write_DAC permission**: agent runs as SYSTEM, which has implicit `SeRestorePrivilege` allowing DACL write on any file regardless of current ACEs. But on **mapped network shares** (UNC paths), SYSTEM is a local context — it has no permission on the remote DC. Document: tripwire works for local NTFS only; UNC tripwire requires a server-side agent.

**Recommended phase:** **Phase 3 (DACL-tripwire)** — must design the canonicalization step before writing the first ACE.

**Sources:** [Order of ACEs in a DACL — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/order-of-aces-in-a-dacl), [MS-DTYP ACL](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/20233ed8-a6c6-4097-aafa-dd545ed24428). Confidence HIGH.

---

### MOD-04 — DACL repair watcher TOCTOU race lets through brief access window

**What goes wrong:** Agent watches `C:\T4_Data\` via `ReadDirectoryChangesW` for ACE changes. An attacker (or an unaware admin via the GUI) removes the Deny ACE at time T. The agent sees the change notification at T+50ms and reverts at T+200ms. In that 200 ms window, the attacker reads the file. Audit log records the change-and-revert but the data has already exfiltrated.

**Why it happens:** `ReadDirectoryChangesW` is async and asynchronous: notification arrives after the change is committed. Even synchronous polling has a poll-interval-sized gap.

**Prevention:**
- **Synchronous repair via SACL auditing.** Apply a SACL audit ACE on the same root so any ACE modification fires a `Security` event log entry (Event ID 4670). Subscribe to the security log via ETW `Microsoft-Windows-Security-Auditing`. SACL events fire before user-mode notification — the gap is microseconds rather than milliseconds. Still not zero.
- **Cannot achieve zero TOCTOU** without a minifilter that intercepts SetSecurityFile. Accept the residual gap; document in deployment guide.
- **Defence in depth:** the hook DLL (when injected) blocks the file open even if DACL was briefly modified. Tripwire is the backstop, not the primary control.
- **Alert on every ACE change.** If the operator authorized it, they can clear the alert; otherwise SOC investigates. The deterrent value is meaningful even when the protection is not perfect.

**Recommended phase:** **Phase 3 (DACL-tripwire)** — must be designed with TOCTOU explicitly accepted and documented.

**Sources:** [ReadDirectoryChangesW — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw). Confidence HIGH on the API; MEDIUM on the SACL-auditing latency claim.

---

### MOD-05 — ETW Kernel-File event drops under load

**What goes wrong:** Microsoft-Windows-Kernel-File can emit 10,000+ events/sec on a busy build server. Default ETW session buffer (`128 KB × 50 buffers`) drops events when consumer is slow. Lost events = missed bypass alerts = false sense of coverage.

**Why it happens:** ETW is "best effort." Sessions configured with `EVENT_TRACE_BUFFERING_MODE` or default circular mode silently drop when buffers wrap. The `LOST_EVENT` indicator is reported but not always loud.

**Prevention:**
- Configure session with 256 KB × 200 buffers (Microsoft's recommendation for high-volume providers).
- Run consumer in a dedicated tokio task with bounded mpsc channel (drop oldest when full, log drops).
- Subscribe to `Microsoft-Windows-Kernel-EventTracing/Admin` Event ID 2 (lost-events) and emit a self-monitoring telemetry event so we know when we lost coverage.
- **Filter at provider level.** Only enable event keywords for file create/write/delete (`KERNEL_FILE_KEYWORD_CREATE`, `_WRITE`, `_DELETE`); skip reads and stat operations. Reduces volume 10-50×.
- **Filter at consumer level.** Drop events where `FileObject` path resolves to System32/WinSxS — they are the bulk of volume and never T3/T4.
- ETW provider enable requires `SeSystemProfilePrivilege` for kernel providers; the dlp-agent service already runs as SYSTEM and inherits this, but a hardening policy that strips it would silently break ETW. Document in deployment guide: "Do not remove SeSystemProfilePrivilege from the agent service account."

**Recommended phase:** **Phase 6 (ETW-bypass-detection)** — buffer tuning is part of the consumer design.

**Sources:** [About Event Tracing — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing). Confidence HIGH.

---

### MOD-06 — Process startup race: hook DLL not loaded before first file open

**What goes wrong:** `CreateProcess` returns; the process is created but `DllMain` for the injected hook DLL hasn't run yet. Between process creation and `DLL_PROCESS_ATTACH`, the process may have already executed early initialization (CRT init, static constructors) and opened files. Specifically, the loader maps `ntdll.dll`, `kernel32.dll`, then the EXE's import-table DLLs, **before** AppInit_DLLs are loaded. Any CreateFile call from a statically-linked dependency's init runs un-hooked.

**Why it happens:** The Windows loader's order is: ntdll → kernel32 → static imports → AppInit_DLLs → the EXE's entrypoint. AppInit_DLLs loads via a `LoadLibraryW` call inside `kernel32!_BaseDllInitialize`, which happens after all static imports are mapped. For `CreateRemoteThread`-based injection, the gap is even larger: the injector observes process creation via WMI/ETW (latency 100 ms-2 s) and then injects.

**Consequences:**
- A short window (typically 50-500 ms for AppInit_DLLs; up to 2 s for CRT injection) where the process can read T4 files unhooked.
- Worst case: malware spawns, reads T4, exits — all before our hook arrives.

**Prevention:**
- **Suspended-create proxy.** For high-value process types (identified by image-path policy: e.g., known data-exfil tools, scripting hosts like powershell.exe), use an EDR-like pattern: agent intercepts process create via ETW `Microsoft-Windows-Kernel-Process` (which fires synchronously in `PsSetCreateProcessNotifyRoutineEx`), but we cannot suspend from user mode.
- **Realistic mitigation:** accept the race for the first 100-500 ms of process life; rely on DACL tripwire to block early file opens (DACL is kernel-enforced from process start, before any user-mode code runs).
- **For AppInit_DLLs path:** the gap is small (10s of ms) because AppInit DLLs load during loader initialization, before the EXE entrypoint.
- **For CreateRemoteThread path:** Subscribe to ETW `Microsoft-Windows-Kernel-Process/Analytic` for `ProcessStart` events (latency ~10 ms). Don't use WMI `Win32_ProcessStartTrace` (latency 500-2000 ms).
- Document the race as an accepted gap; DACL is the backstop.

**Recommended phase:** **Phase 1 (BLOCK-injection)** — race-window characterization must inform the injection design. Phase 3 (DACL) closes the gap.

**Sources:** [DLL injection on suspended process — Win32 newsgroup archive](https://groups.google.com/g/comp.os.ms-windows.programmer.win32/c/gGXUm2Q7MaE), [DLL injection — Wikipedia](https://en.wikipedia.org/wiki/DLL_injection). Confidence MEDIUM (timing varies by Windows version; the 100-500 ms range is observed in practice, not in MS docs).

---

### MOD-07 — Go and Rust binaries with custom syscall stubs bypass IAT hooks

**What goes wrong:** Go's runtime on Windows uses its own scheduler and calls ntdll syscalls **directly** via assembly stubs, not via the kernel32 path that IAT hooks intercept. A Go binary copying T4 data via `os.WriteFile` may bypass `HookCreateFileW` (kernel32 IAT) entirely. Go does call `ntdll!NtCreateFile`, so the v0.10.0 ntdll-stub patch catches it — but if CRIT-03 caused us to back off ntdll patching due to EDR coexistence, Go binaries are uninstrumented.

Rust uses libc/MSVCRT for std::fs::File, which goes through kernel32!CreateFileW — Rust is fine.

**Other blind spots:**
- Anything using LoadLibrary+GetProcAddress to resolve CreateFileW dynamically: GetProcAddress returns the real address, not our IAT entry. Common in installers and malware.
- DotNet System.IO uses P/Invoke to CreateFileW: hooked correctly.
- `node.exe` uses libuv which calls Win32 directly: hooked correctly.
- Any binary built with `/DELAYLOAD:kernel32.dll`: the delay-load thunk resolves at first call; our IAT hook is bypassed because the import was never in the static IAT.

**Prevention:**
- **ntdll syscall-stub patch is the catch-all** for Go and delay-loaded kernel32. If we disable it due to EDR coexistence (CRIT-03), explicitly document Go binaries as a coverage gap.
- **GetProcAddress hook.** Add `GetProcAddress` to our IAT hook list. When a caller resolves `CreateFileW`, return our trampoline address. This catches dynamic-loading patterns.
- **Defender-style EAT hook.** Patch the export address table (EAT) of kernel32 and ntdll, not just the IAT. EAT hooks affect GetProcAddress lookups. More invasive — risks EDR coexistence (see CRIT-03).
- Document blind spots; acceptable for v0.10.0 given DACL + ETW backstops.

**Recommended phase:** **Phase 2 (BLOCK-hook-coverage)** — coverage analysis is part of the hook design.

**Sources:** [Hooking Go from Rust — MetalBear](https://metalbear.com/blog/hooking-go-from-rust-hitchhikers-guide-to-the-go-laxy/), [go-direct-syscall — pkg.go.dev](https://pkg.go.dev/github.com/carved4/go-direct-syscall). Confidence HIGH for Go; HIGH for Rust libc path.

---

### MOD-08 — Hook DLL named-pipe storm overwhelms agent

**What goes wrong:** N user processes × M files/sec each = N×M concurrent pipe connections to the agent. Default named-pipe instance limit is 255 (`PIPE_UNLIMITED_INSTANCES` raises it but the agent still has to serve each connection). At 1000 hook calls/sec, the agent's named-pipe server saturates, response latency spikes, fail-closed kicks in, T1/T2 file operations get denied, users see legitimate work blocked.

**Why it happens:** v0.9.0 cloud-sync hook DLL has only ~10-100 calls/sec per process (cloud sync is rare). Universal v0.10.0 hooking takes this to 10,000+/sec per endpoint.

**Prevention:**
- **Aggressive in-DLL caching** (already in scope: CACHE-) — most CreateFile calls should not reach the agent.
- **Pipe pooling.** Each process keeps 1-2 persistent connections, not one-per-request. Multiplex requests over a single pipe with frame IDs (existing frame protocol in `dlp-agent/src/ipc/frame.rs` supports this).
- **Agent-side rate limiting.** Per-process budget (e.g., 100 req/sec/process); over-budget requests get an immediate "ALLOW with logging" response. The DACL tripwire and ETW catch real T3/T4 access even when the hook is rate-limited.
- **Backpressure-friendly fail mode.** When pipe times out (50 ms), fall back to local cache; if cache miss and classification is provisional T1/T2, ALLOW (fail-open T1/T2 already in scope: FAIL-asymmetric).
- **Async pipe server.** Agent's `HookIpcServer` must use IOCP-based async I/O (tokio's named-pipe support) with a worker pool, not thread-per-connection.
- **Benchmark.** Phase 5 perf-validation must measure pipe throughput at 10,000 req/sec.

**Recommended phase:** **Phase 4 (CACHE-) + Phase 5 (perf-validation)** — pipe scaling is co-designed with the cache.

**Sources:** Code review of `dlp-agent/src/hook_ipc.rs` (named pipe server). Confidence HIGH on the architectural constraint.

---

### MOD-09 — Token-group resolution against AD hits the DC on every hook call

**What goes wrong:** Hook calls agent; agent calls `LookupAccountSidW` to resolve the SID to a username; this hits the AD DC. AD round-trip latency 10-100 ms. At 1000 hook calls/sec across an endpoint, that's 10× saturation of the DC. Worst case: DC blacklists the endpoint or the entire fleet, breaks login for everyone.

**Why it happens:** ABAC evaluation uses group membership; the hook payload (`HookRequest`) has only `path` + `action`. The agent must enrich with subject SID and group membership before calling the policy engine. Group enumeration via `NetUserGetGroups` or `LookupAccountSidW` reaches AD.

**Prevention:**
- **Cache group membership at session start.** When a user logs in (WTSEnumerateSessions or LogonUI hook), the agent fetches their full group SID list once and caches for the session lifetime. Hook calls then resolve SID locally.
- **Cache TTL: refresh on token-change events** (`WTS_SESSION_LOCK`, `WTS_SESSION_UNLOCK`) or every 15 minutes.
- **Negative caching.** If AD is unreachable, fall back to last-known group list; flag policy decision with `degraded_identity=true`; document this in the audit event.
- v0.6.0 session-identity resolution already documents the AD-unreachable fallback (CONCERNS.md: "Session Identity Resolution"). Extend that pattern.

**Recommended phase:** **Phase 1 (BLOCK-injection) or Phase 4 (CACHE-)** — must be designed before per-call enrichment is wired.

**Sources:** Code review of `dlp-agent/src/session_identity.rs` (existing pattern); CONCERNS.md "Session Identity Resolution." Confidence HIGH.

---

## Minor Pitfalls

Items that cause friction or partial degradation but not failure.

---

### MIN-01 — AppInit_DLLs registration requires a reboot OR a session logout to take effect

**Manifestation:** Operator installs v0.10.0, runs the agent, expects immediate enforcement. Existing user sessions don't load the hook DLL until next login. Existing running processes are not touched.

**Prevention:** Agent at start time enumerates existing user processes and runs `CreateRemoteThread` injection against each (already implemented in HookInjector). Document in deployment guide: "AppInit_DLLs covers new sessions; CreateRemoteThread sweep covers existing processes; full coverage in <5 seconds after agent start."

**Recommended phase:** Phase 8 (OPS-deployment-guide).

---

### MIN-02 — Hook DLL build target naming collisions

**Manifestation:** `dlp_hook_dll.dll` (existing v0.9.0 name) vs new universal hook. Either we keep one name and the v0.9.0 functionality lives in the same DLL (recommended), or we ship two DLLs and confuse the installer.

**Prevention:** Single DLL. v0.10.0 expands the existing hook surface; v0.9.0's cloud-sync handler is one branch inside the same DLL. Keeps injection logic simple.

**Recommended phase:** Phase 2 (BLOCK-hook-DLL design).

---

### MIN-03 — `RequireSignedAppInit_DLLs = 0` is a hardening regression

**Manifestation:** Deployment guide tells admins to set `RequireSignedAppInit_DLLs = 0` if they don't want to deal with code signing. This regresses every endpoint's malware posture — any unsigned DLL can now AppInit-inject.

**Prevention:** Never recommend disabling `RequireSignedAppInit_DLLs`. Sign the DLL with Authenticode (see MOD-01). Cost ~$300/year; benefit is the customer's existing hardening posture stays intact.

**Recommended phase:** Phase 8 (OPS-deployment-guide).

---

### MIN-04 — `DllMain` cannot call LoadLibrary or named-pipe APIs synchronously

**Manifestation:** Hook DLL's `DllMain` tries to initialize the named-pipe client synchronously on `DLL_PROCESS_ATTACH`. The loader lock is held; LoadLibrary call from inside DllMain (transitively required by the pipe APIs) deadlocks. Process hangs at startup.

**Prevention:** Current `dlp-hook-dll/src/lib.rs` `init()` only patches IAT (safe under loader lock) and resolves kernel32/ntdll module handles (already loaded). Named-pipe connections happen lazily on first hook call, on a normal thread, outside loader lock. This is correct. **Document the constraint** so future contributors don't add LoadLibrary calls to init().

**Recommended phase:** Phase 2 (BLOCK-hook-DLL design) — encode constraint in code comments.

---

### MIN-05 — Hot-reload of `ProtectedPaths` config invalidates the in-DLL classification cache

**Manifestation:** Operator adds `D:\NewSecretData\` to Protected Paths via admin TUI. The agent updates config. The hook DLL's local cache still has stale classifications for paths under that root. Files in `D:\NewSecretData\` get treated as T1 for the cache TTL window (5 min).

**Prevention:** When config changes, agent sends a "cache flush" message to all connected hook DLLs (broadcast via pipe). Cache versioning: each cache entry tagged with config-revision; mismatched revision = miss.

**Recommended phase:** Phase 4 (CACHE-).

---

### MIN-06 — Hooks fire on access by the dlp-agent itself, causing recursion

**Manifestation:** Hook DLL is injected into every user process. Agent writes audit logs to `C:\ProgramData\DLP\audit.jsonl` from SYSTEM, but if any user process happens to query that path (Explorer thumbnail preview, Defender scan), the hook fires, calls the agent, which writes more audit log, fires more hooks...

**Prevention:**
- The hook DLL never injects into the agent service (agent runs in session 0; AppInit_DLLs do not load into Windows services by default — services use `LoadLibrary` after a different init path). Verify with `IsService` check in DllMain.
- Hook checks `GetModuleFileNameW(NULL)` and exits immediately if the host is dlp-agent.exe or dlp-user-ui.exe.
- Hook checks if `path` is under `C:\ProgramData\DLP\` and returns ALLOW immediately without IPC.

**Recommended phase:** Phase 2 (BLOCK-hook-DLL design).

---

## Phase-Specific Warnings

| Phase Topic | Likely Pitfall | Mitigation |
|---|---|---|
| **Phase 1: Universal injection** | CRIT-01 (Secure Boot), CRIT-05 (PPL), MOD-02 (WoW64), MOD-06 (startup race) | Secure-Boot-aware fallback chain (CRT + AppInit_DLLs); document PPL gap; ship x86+x64 DLLs; ETW kernel-process for startup detection |
| **Phase 2: Hook DLL coverage expansion** | CRIT-02 (host crash), MOD-07 (Go bypass), MIN-04 (DllMain lock), MIN-06 (self-recursion) | `catch_unwind` + SEH; document Go gap; lazy pipe init; agent self-allowlist |
| **Phase 3: DACL tripwire** | MOD-03 (canonical order), MOD-04 (TOCTOU), 64 KB ACL limit | Replace-not-append ACE writer; SACL audit backstop; consolidate group SIDs |
| **Phase 4: CACHE- local classification** | CRIT-04 (perf), MOD-08 (pipe storm), MOD-09 (AD lookups), MIN-05 (cache invalidation) | Per-process allowlist + trusted paths; pipe pooling; session-scoped group cache; config-revision-tagged entries |
| **Phase 5: Perf validation** | CRIT-04 manifestation | Build-workload benchmark gate; latency telemetry |
| **Phase 6: ETW bypass detection** | MOD-05 (event drops) | 256 KB×200 buffers; provider-side filtering; SeSystemProfilePrivilege doc |
| **Phase 7: ntdll syscall patching** | CRIT-03 (EDR coexistence) | Detect-before-patch; feature flag default-off; per-customer rollout |
| **Phase 8: OPS deployment guide** | CRIT-06 (AV/EDR), MOD-01 (signing), MIN-01 (reboot), MIN-03 (hardening) | Vendor-specific allowlist procedures; Authenticode signing; documented activation flow |

---

## Integration Pitfalls (v0.9.0 → v0.10.0)

### INT-01 — v0.9.0 cloud-sync hook DLL conflicts with universal v0.10.0 hook DLL

**Manifestation:** Two DLLs hooking the same `CreateFileW` IAT entry. Whichever loads second sees the first's trampoline as "original" — calls go: process → DLL_A → DLL_B → real CreateFileW. Adds latency. If one unhooks (UnhookAll), it restores the wrong address, leaving the other's pointer dangling. Crash.

**Prevention:** Merge into a single DLL. The v0.9.0 cloud-sync logic becomes a path-classifier branch inside the universal hook. Existing `pipe_client::send_request` is unchanged; the agent's handler dispatches based on path (cloud-sync paths → existing CloudEnforcer; everything else → universal classification).

**Phase:** Phase 2 (BLOCK-hook-DLL design).

---

### INT-02 — v0.9.0 WFP rules don't cover the v0.10.0 hook's new file-I/O surface

**Manifestation:** WFP layer in v0.9.0 catches cloud-sync uploads (network-bound). v0.10.0's universal hook covers local NTFS + UNC. The two are complementary, not overlapping — but the audit pipeline needs to distinguish "blocked by WFP" vs "blocked by hook" vs "blocked by DACL." If audit events conflate them, SOC can't triage.

**Prevention:** Audit event schema gets a new `enforcement_layer` field with values `wfp`, `hook_dll`, `dacl_tripwire`, `etw_detected_bypass`. Existing `dlp-common::AuditEvent` needs the field (additive, non-breaking).

**Phase:** Phase 6 (ETW-bypass-detection) — same phase wires SIEM.

---

### INT-03 — Existing PolicyMapper::provisional_classification stub returns synthetic results

**Manifestation:** v0.9.0 `PolicyMapper::provisional_classification(path)` returns a path-prefix-based heuristic (e.g., "C:\\Restricted\\" → T4). v0.10.0 universal hooking exercises this on millions of new paths; heuristic is too coarse, classifies every random user file as T4 (false positive) or misses real T3 data (false negative).

**Prevention:** Phase 4 (CACHE-) replaces the stub with a real classification cache backed by:
1. Operator-defined Protected Paths (admin TUI).
2. Optional content-classification (out-of-scope for v0.10.0; deferred).
3. Default: unknown path → T1.

The stub stays as the cold-cache fallback, but only fires for paths not yet seen.

**Phase:** Phase 4 (CACHE-).

---

### INT-04 — Audit volume explodes; SQLite ingestion lock contention

**Manifestation:** v0.9.0 audit volume is ~100 events/sec/endpoint. v0.10.0 universal hooking emits an event per CreateFile = 10,000+ events/sec/endpoint at the upper bound. SQLite's `Arc<Mutex<Connection>>` (documented in CONCERNS.md: "SQLite Database Lock Contention") becomes the choke point.

**Prevention:**
- **Sampling.** ALLOW events for T1/T2 paths are sampled 1-in-100. Only DENY and T3/T4 ALLOW events get full audit.
- **Batching.** Hook DLL batches up to 50 events per IPC frame; agent batches up to 500 events per SQLite transaction.
- **Append-only audit log.** Local JSONL file is the source of truth; SQLite ingestion is best-effort (already the pattern in `dlp-agent/src/audit_emitter.rs`).
- **Async ingest.** Agent's audit pipeline goes through a bounded mpsc channel; if SQLite falls behind, oldest events drop with a logged warning.

**Phase:** Phase 5 (perf-validation) — must be measured before ship.

---

## Sources

### Microsoft-Authoritative (HIGH confidence)
- [AppInit DLLs and Secure Boot — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/dlls/secure-boot-and-appinit-dlls)
- [Order of ACEs in a DACL — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/order-of-aces-in-a-dacl)
- [MS-DTYP ACL specification — Microsoft Learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/20233ed8-a6c6-4097-aafa-dd545ed24428)
- [About Event Tracing — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
- [Configure added LSA protection — Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [32-bit and 64-bit Application Data in the Registry — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/sysinfo/32-bit-and-64-bit-application-data-in-the-registry)
- [Authenticode Signing for Game Developers — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/dxtecharts/authenticode-signing-for-game-developers)
- [AppInit_DLLs in Windows 7 — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/win7appqual/appinit-dlls-in-windows-7-and-windows-server-2008-r2)

### Vendor / Industry (MEDIUM confidence)
- [The Evolution of Protected Processes — CrowdStrike](https://www.crowdstrike.com/en-us/blog/evolution-protected-processes-part-1-pass-hash-mitigations-windows-81/)
- [Bypassing LSA Protection in Userland — SCRT](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/)
- [What is Process Injection — SentinelOne](https://www.sentinelone.com/cybersecurity-101/cybersecurity/process-injection/)
- [Detecting Process Injection — Black Lantern Security](https://blog.blacklanternsecurity.com/p/detecting-process-injection)
- [4 Ways Adversaries Hijack DLLs — CrowdStrike](https://www.crowdstrike.com/en-us/blog/4-ways-adversaries-hijack-dlls/)

### Offensive Security (MEDIUM confidence — accurate but adversarial framing)
- [Detecting Hooked Syscalls — ired.team](https://www.ired.team/offensive-security/defense-evasion/detecting-hooked-syscall-functions)
- [An Introduction to Bypassing User Mode EDR Hooks — malwaretech.com](https://malwaretech.com/2023/12/an-introduction-to-bypassing-user-mode-edr-hooks.html)
- [Userland Hook Detection — Medium](https://medium.com/@s12deff/userland-hook-detection-76f0eb5035cc)
- [Implementing syscall hooks in Rust — fluxsec.red](https://fluxsec.red/implementing-syscall-hooking-rust)
- [Monitoring NTDLL In-Memory Patching — fluxsec.red](https://fluxsec.red/monitoring-ntdll-for-memory-patching-etw-hacking-bypass-in-rust-EDR)
- [Hooking Go from Rust — MetalBear](https://metalbear.com/blog/hooking-go-from-rust-hitchhikers-guide-to-the-go-laxy/)
- [DoppelGate — GitHub](https://github.com/asaurusrex/DoppelGate)

### General Reference (LOW-MEDIUM confidence — useful for breadth)
- [DLL injection — Wikipedia](https://en.wikipedia.org/wiki/DLL_injection)
- [Event Triggered Execution: AppInit DLLs (T1546.010) — MITRE ATT&CK](https://attack.mitre.org/techniques/T1546/010/)
- [WoW64 — Wikipedia](https://en.wikipedia.org/wiki/WoW64)
- [Kernel Event Tracing — copyprogramming.com](https://copyprogramming.com/howto/kernel-event-tracing)
