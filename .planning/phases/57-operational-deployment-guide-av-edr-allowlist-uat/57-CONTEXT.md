# Phase 57: Operational Deployment Guide + AV/EDR Allowlist + UAT - Context

**Gathered:** 2026-05-30
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 57 is the **v0.10.0 milestone ship gate**. It delivers the operational documentation and UAT evidence required for a production deployment of the real-time file access prevention stack.

**What Phase 57 builds:**
1. **Deployment guide** — `docs/operations/deployment-guide.md` documenting per-vendor AV/EDR allowlist procedures for Microsoft Defender for Endpoint, CrowdStrike Falcon, SentinelOne, Carbon Black, Sophos, and Trend Micro Apex One. Each vendor section includes: (a) expected detection behavior, (b) console/UI allowlist steps with screenshots, (c) hash/IOC exclusion examples, (d) verification commands.
2. **Release documentation** — `RELEASE_NOTES.md` with SHA-256 + SHA-512 hashes for every shipped binary; Microsoft WDSI submission flow documented; `signtool verify /pa` command for Authenticode timestamp verification.
3. **Deployment reality documentation** — Secure Boot implications (AppInit_DLLs inert, `siem.appinit_dlls_disabled` event), PPL coverage gap (lsass/MsMpEng/EDR-self) and DACL-tripwire backstop, `SeSystemProfilePrivilege` preservation across upgrades, post-install reboot requirement for hook activation.
4. **UAT execution and capture** — Real Windows 11 host with real cloud clients (OneDrive, Google Drive, Dropbox, Box), real printers, and real USB/SD/optical/virtual drives. Full v0.9.0 cloud-sync regression test suite plus v0.10.0 active-blocking scenarios. CRIT-04 benchmark gate (<=25% wall-clock overhead) enforced. Results captured in `.planning/milestones/v0.10.0-UAT.md`.

**What Phase 57 does NOT build:**
- Automated CI-driven UAT (no Windows CI runner available — manual UAT only)
- Vendor outreach or commercial relationships (procedures are documentation-only)
- Code signing automation (signtool is documented but run manually)
- Automated hash generation in CI (hashes are documented manually per release)
- Post-deployment monitoring or health-check tooling (deferred to Phase 58 / DIFF-04)

**Depends on:** Phases 48-56 (deployment guide must reflect every shipped capability; UAT exercises every shipped feature)
**Requirements:** OPS-01, OPS-02, OPS-03, OPS-04

</domain>

<decisions>
## Implementation Decisions

### Deployment Guide Format and Delivery
- **D-01:** Single comprehensive markdown document at `docs/operations/deployment-guide.md`. Per-vendor subsections follow a consistent template: Detection Behavior → Allowlist Procedure → Hash Exclusion → Verification. Document is versioned in-tree alongside code and distributed as a release artifact.
- **D-02:** The deployment guide is organized into major sections: (1) Prerequisites, (2) Installation Steps, (3) AV/EDR Allowlist Procedures (per-vendor), (4) Secure Boot & PPL Considerations, (5) Post-Install Verification, (6) Troubleshooting. This structure mirrors enterprise software deployment guides the target audience is familiar with.

### AV/EDR Vendor Coverage
- **D-03:** Cover the top 6 vendors explicitly: Microsoft Defender for Endpoint, CrowdStrike Falcon, SentinelOne, Carbon Black (VMware), Sophos Intercept X, Trend Micro Apex One. Each gets its own subsection with console screenshots and step-by-step procedures.
- **D-04:** Provide an extensible template at the end of the vendor section for adding new vendors. Template includes placeholder headings matching the 6 covered vendors' structure. This future-proofs the guide without expanding scope now.
- **D-05:** Allowlist procedures cover BOTH path-based exclusions (for the installation directory `C:\Program Files\DLP\`) AND hash-based exclusions (for `dlp-agent.exe`, `dlp_hook_dll.dll`, `dlp-user-ui.exe`). Hash exclusions use the SHA-256 published in RELEASE_NOTES.md.

### Hash Publishing and Signing Verification
- **D-06:** SHA-256 and SHA-512 hashes for every release binary (`dlp-agent.exe`, `dlp-server.exe`, `dlp-admin-cli.exe`, `dlp-user-ui.exe`, `dlp_hook_dll.dll`, `dlp_hook_dll_x86.dll`) are published in `RELEASE_NOTES.md` under each release heading.
- **D-07:** Microsoft WDSI (Windows Defender SmartScreen Intelligence) binary submission flow is documented as a manual operator step, not automated. The guide includes the direct URL (`https://www.microsoft.com/en-us/wdsi/filesubmission`) and expected turnaround time (24-72 hours).
- **D-08:** `signtool verify /pa dlp-agent.exe` is the documented verification command for Authenticode timestamp validation. The guide explains what "/pa" means (use default Authenticode policy) and what a clean output looks like.

### UAT Scope and Methodology
- **D-09:** UAT scope is COMPREHENSIVE, not a smoke test: all v0.9.0 cloud-sync regression tests (OneDrive, Google Drive, Dropbox, Box clipboard/share-link blocking) PLUS all v0.10.0 active-blocking scenarios (universal hook injection, ntdll patching, DACL tripwire, ETW bypass detection, volume-class ABAC, monitor/audit mode).
- **D-10:** Each UAT scenario has a binary pass/fail criterion and is documented in `.planning/milestones/v0.10.0-UAT.md` with: Scenario ID, Prerequisites, Steps, Expected Result, Actual Result, Pass/Fail, Notes.
- **D-11:** CRIT-04 benchmark is a HARD GATE: representative workloads (`cargo build` on a Rust project, Microsoft Word launch and save) must show <=25% wall-clock overhead with hooks enabled vs. hooks disabled. If the benchmark fails, the milestone does NOT ship.

### UAT Environment Specification
- **D-12:** UAT runs on a PHYSICAL Windows 11 Pro or Enterprise host, not a VM. Physical hardware is required to test real USB/SD/optical drive interactions and printer drivers.
- **D-13:** Required peripherals: USB 3.0 flash drive, SD card (with reader), optical drive (or USB optical drive / mounted ISO fallback), network printer (or PDF printer), network share (SMB).
- **D-14:** Required cloud clients: OneDrive (built-in Windows), Google Drive for Desktop, Dropbox, Box Drive. All must be installed and signed in with test accounts.
- **D-15:** The UAT host must have at least one of the 6 covered EDRs installed for the allowlist verification portion. If no EDR is present, that section of UAT is marked N/A with a note.

### Release Documentation Structure
- **D-16:** `RELEASE_NOTES.md` at repo root follows a structured format per release: Release Date → Summary → Binaries (table with filename, SHA-256, SHA-512) → Breaking Changes → Migration Notes → Known Issues → Deployment Guide Link.
- **D-17:** Release notes are manually authored, not auto-generated from git log. The author (release engineer) writes human-readable summaries of changes, not commit lists.

### Placeholder and Evidence Policy
- **D-18:** Placeholder policy: Screenshot placeholders are acceptable as `[Screenshot: ...]` only if noted "to be added during UAT execution"; hashes must be replaced with actual release artifact hashes before ship. No unresolved `[TO BE FILLED]` text may remain in any shipped artifact.
- **D-19:** Artifact provenance: RELEASE_NOTES.md must include build ID (CI run or manual build identifier), commit SHA, and pipeline reference for traceability.
- **D-20:** Screenshot policy: Screenshots must be sourced from lab/test environments only. Each screenshot must include a "last verified" date and EDR version. Text-only procedures are acceptable for untested vendors; no fake screenshots.
- **D-21:** WDSI detection name: Use `Trojan:Win32/Wacatac.B!ml` as an example only. Operators must record their actual detection name from the Defender console.
- **D-22:** UAT evidence requirements: Each scenario must capture: Windows version/build, hardware specs, EDR product/version, cloud client versions, printer/share details, test account, policy bundle/version, binary hashes, timestamped tester sign-off.
- **D-23:** CRIT-04 benchmark protocol: Warm-up run, 3 measured runs, median calculation, baseline without hooks, test with hooks, exact overhead formula `((with - baseline) / baseline) * 100`, no-ship threshold >25%.
- **D-24:** Canonical ownership: Plan 57-04 is the sole owner of Secure Boot, PPL, DACL tripwire, SeSystemProfilePrivilege, and reboot documentation. Plan 57-01 references 57-04 for detailed content.
- **D-25:** Rollback procedure: Deployment guide must document service stop, MSI uninstall, DACL restoration via `icacls /reset`, and optional ProgramData cleanup.
- **D-26:** Ship decision severity tiers: Blocking (prevents ship), Major (degraded but workaround exists), Minor (cosmetic). Ship requires 0 Blocking failures.
- **D-27:** Approval authority: Ship decision requires sign-off from both engineering lead and QA lead.

### Claude's Discretion
- The deployment guide should include a "Quick Start" checklist at the top for experienced operators (5-10 bullets) before diving into the detailed per-vendor sections.
- Include PowerShell one-liners for common verification tasks (e.g., `Get-Process | Where-Object {$_.Modules -match "dlp_hook_dll"}` to verify injection).
- The UAT document should include a "UAT Sign-Off" section with signature lines for: Tester Name, Date, Version Tested, Overall Pass/Fail.
- Consider adding a "Rollback Procedure" subsection to the deployment guide documenting how to safely uninstall the agent and restore original DACLs.
</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements & Architecture
- `.planning/ROADMAP.md` — Phase 57 goal, 4 success criteria, requirements OPS-01..04
- `.planning/PROJECT.md` — v0.10.0 milestone context, architecture constraints (no kernel driver, no EV cert)
- `.planning/STATE.md` — Phase completion status, shipped features to document

### Prior Phase Context (Capabilities to Document/Test)
- `.planning/phases/48-hook-dll-surface-expansion-crash-hardening-build-harness/48-CONTEXT.md` — Hook DLL architecture, crash hardening, Authenticode signing
- `.planning/phases/49-universal-injection-etw-process-watcher-allowlist-appinit-fa/49-CONTEXT.md` — Universal injection, allowlist, AppInit_DLLs fallback, ETW process watcher
- `.planning/phases/50-shared-memory-classification-cache-fail-mode-state-machine/50-CONTEXT.md` — Shared-memory cache, fail-mode state machine, asymmetric fail semantics
- `.planning/phases/51-ntdll-syscall-stub-trampolines-edr-coexistence/51-CONTEXT.md` — ntdll patching, EDR detection, thread suspender, background verification
- `.planning/phases/52-dacl-tripwire-repair-watcher-protected-paths-dpapi-recovery-/52-CONTEXT.md` — DACL tripwire, repair watcher, protected paths, DPAPI recovery
- `.planning/phases/53-etw-kernel-file-consumer-bypass-correlator-hook-journal-ring/53-CONTEXT.md` — ETW consumer, bypass correlator, hook journal ring
- `.planning/phases/54-admin-tui-protected-paths-bypass-alerts-screens/54-CONTEXT.md` — Admin TUI screens
- `.planning/phases/55-monitor-only-audit-only-per-policy-enforcement-mode/55-CONTEXT.md` — Enforcement modes, monitor-only rollout
- `.planning/phases/56-sd-optical-virtual-drive-enumeration-volume-class-abac-seed-/56-CONTEXT.md` — Volume-class ABAC, device enumeration

### Existing Documentation Patterns
- `docs/operations/dpapi-recovery.md` — DPAPI recovery runbook (Phase 52) — follow this style for deployment guide
- `.planning/phases/47-secrets-encryption-at-rest/` — Phase 47 HARD-01 artifacts, key rotation procedures

### Code Conventions
- `.planning/codebase/CONVENTIONS.md` — Rust coding standards, naming, error handling
- `.planning/codebase/STRUCTURE.md` — Workspace module organization

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`docs/operations/dpapi-recovery.md`** — Existing operational runbook with re-init-from-env-vars and restore-from-backup flows. Use as the style template for the deployment guide (section structure, code snippets, UAT checklists).
- **`.planning/milestones/v0.10.0-UAT.md`** — UAT results document (to be created). Follow the same structured format as Phase 52's verification docs.
- **`Cargo.toml` workspace definition** — Source of truth for crate names and binary names that need hashes in RELEASE_NOTES.md.
- **`.github/workflows/release.yml`** (if exists) — CI pipeline for release builds; document how it produces signed binaries.

### Established Patterns
- **Documentation style** — `dpapi-recovery.md` uses: prerequisites list, numbered steps, PowerShell snippets, verification commands, UAT checklist. Deployment guide follows this exactly.
- **Release artifact naming** — `dlp-agent.exe`, `dlp-server.exe`, `dlp-admin-cli.exe`, `dlp-user-ui.exe`, `dlp_hook_dll.dll`, `dlp_hook_dll_x86.dll`. Consistent naming across installer, CI, and documentation.
- **AV/EDR allowlist patterns** — Phase 49's allowlist module (`dlp-agent/src/allowlist.rs`) documents the process categories that are skipped. Deployment guide maps these to vendor-specific exclusion procedures.

### Integration Points
- `docs/operations/` — New `deployment-guide.md` joins `dpapi-recovery.md` in the operations docs directory.
- `RELEASE_NOTES.md` — New file at repo root, or appended to existing release notes.
- `.planning/milestones/v0.10.0-UAT.md` — New UAT results document.
- `dlp-agent/src/allowlist.rs` — Reference for AV/EDR process categories that need allowlisting.
- `dlp-agent/src/service.rs` — Reference for AppInit_DLLs behavior, Secure Boot detection, `siem.appinit_dlls_disabled` event.
- `dlp_hook_dll/src/background_thread.rs` — Reference for self-health counters (DIFF-04 deferred, but relevant for troubleshooting section).
</code_context>

<specifics>
## Specific Ideas

- Deployment guide should open with a "Quick Start for Experienced Operators" checklist (10 bullets max) covering: install signed MSI, verify signtool, add hash exclusions for 1 EDR, reboot, verify injection via Process Hacker, test a T4 copy denial.
- Each AV/EDR vendor section should include a screenshot placeholder (e.g., `[Screenshot: CrowdStrike Falcon console → Prevention → Exclusions]`) so the document can be completed with actual screenshots during UAT.
- The Microsoft WDSI submission section should include the exact form fields and values: Product name = "DLP-RUST Endpoint Agent", Company = "[Customer Name]", File type = "Executable", Detection name = "Trojan:Win32/Wacatac.B!ml" (common false-positive), Additional information = "Enterprise DLP agent using global DLL injection for file-access monitoring."
- Include a "Troubleshooting" section with common issues: "Hook not injecting" → check allowlist, verify SeSystemProfilePrivilege, check Event Viewer for `siem.appinit_dlls_disabled`; "T4 file still writable" → check DACL tripwire, verify agent service running, check Protected Paths screen; "High CPU" → check ETW buffer size, verify allowlist coverage.
- UAT scenarios should be numbered UAT-57-01 through UAT-57-NN with categories: Hook Injection, File Blocking, Cloud Sync, Print, USB/SD/Optical, DACL Tripwire, ETW Bypass, Monitor Mode, Volume Class, Performance.
- CRIT-04 benchmark should use `cargo build --release` on the dlp-rust workspace itself as the representative workload, measured with `Measure-Command` in PowerShell, comparing with-hooks vs. without-hooks (stop agent service).
</specifics>

<deferred>
## Deferred Ideas

- Automated CI-driven UAT on Windows runner — deferred until Windows CI runner available (HARD-04 backlog)
- Vendor outreach program (commercial partnerships) — deferred; documentation-only for now
- Automated hash generation in CI — deferred; manual per-release is sufficient for v0.10.0
- Post-deployment health monitoring dashboard (DIFF-04) — deferred to Phase 58 or v0.10.1
- Self-updating agent (auto-download new version) — deferred to v0.11.0+
- GPO/Intune deployment package (MSI + ADMX templates) — deferred to v0.11.0+

</deferred>

---

*Phase: 57-Operational Deployment Guide + AV/EDR Allowlist + UAT*
*Context gathered: 2026-05-30*
