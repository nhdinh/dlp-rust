---
phase: 57
reviewers: [codex, claude, opencode]
reviewed_at: 2026-05-30T09:15:00Z
plans_reviewed:
  - 57-01-PLAN.md
  - 57-02-PLAN.md
  - 57-03-PLAN.md
  - 57-04-PLAN.md
  - 57-05-PLAN.md
  - 57-06-PLAN.md
---

# Cross-AI Plan Review — Phase 57

## Codex Review

### Summary

The plan set is broadly well-structured and maps cleanly to OPS-01 through OPS-04. It separates documentation, release evidence, UAT execution, ship decision, and final consistency checks in a sensible sequence. The largest weakness is that several "autonomous" documentation tasks depend on facts that may not be safely inferable from the repo alone: real vendor console procedures, current EDR UI behavior, exact binary inventory, actual signing/timestamp state, and physical Windows UAT results. The phase can achieve its goals, but only if the plans explicitly distinguish authored guidance, verified evidence, and placeholder-free final artifacts.

### Strengths

- Clear requirement coverage: OPS-01, OPS-02, OPS-03, and OPS-04 each have dedicated plans.
- Good wave ordering: docs and release notes first, UAT execution second, ship decision and integration verification last.
- Strong recognition of hard ship gates, especially CRIT-04 and physical-host UAT.
- Secure Boot, PPL, DACL tripwire, privilege persistence, and reboot behavior are treated as first-class operational risks.
- Final integration verification is appropriately scoped to catch consistency drift across docs.
- UAT plan structure is practical: scenario IDs, prerequisites, steps, expected/actual result, pass/fail, notes, and sign-off.

### Concerns

- **HIGH: Vendor allowlist procedures may become unverified documentation.**
  Plan 57-01 requires detailed console/UI steps and screenshot placeholders for six EDR products. Unless the team has access to each console version, this risks producing plausible but inaccurate operator guidance.

- **HIGH: Screenshot placeholders conflict with "no unresolved TODO/placeholder text."**
  Plan 57-01 explicitly asks for screenshot placeholders, while Plan 57-06 requires no unresolved placeholders. The plans need a rule for whether screenshots are required before ship or whether placeholder-free textual procedures are acceptable.

- **HIGH: Plan 57-02 may publish placeholder hashes.**
  Success criteria require every shipped binary to have SHA-256 and SHA-512 hashes published and reproducible. Placeholder v0.10.0 entries are acceptable early, but the plan must include a final replacement step using actual release artifacts.

- **HIGH: UAT execution cannot be autonomous and may block all downstream work.**
  Plans 57-03 and 57-05 depend on physical hardware, real cloud clients, real printer/network share, at least one EDR, and benchmark execution. This is correctly marked non-autonomous, but Plan 57-06 should not run final completeness checks until UAT results are real.

- **MEDIUM: Binary inventory is assumed, not derived.**
  Multiple plans mention "6 binaries," but the workspace has five crates and may produce more or fewer deployable artifacts depending on MSI/service/UI/CLI/helper DLL outputs. The plan should define the authoritative release artifact list.

- **MEDIUM: Authenticode verification is under-specified.**
  `signtool verify /pa` is required by decision D-08, but timestamp verification usually needs explicit handling and expected certificate chain behavior. The plan should include failure modes: missing timestamp, expired cert but valid timestamp, wrong publisher, unsigned MSI.

- **MEDIUM: WDSI detection name is too specific.**
  Hardcoding `Trojan:Win32/Wacatac.B!ml` may be useful as an example, but the guide should instruct operators to use their actual detection name. Otherwise the procedure becomes misleading.

- **MEDIUM: Threat model accepts too much repudiation risk.**
  UAT results, release notes, and ship decisions are all "accepted" because they are version controlled. For a ship gate, that is weak. At minimum, require tester identity, date, artifact hashes, host details, and reviewer sign-off.

- **MEDIUM: CRIT-04 benchmark method may be too thin.**
  Three `Measure-Command` runs with median is reasonable, but cargo builds and Office launch timings are noisy. The plan should specify warm-up behavior, clean vs incremental build, machine power profile, background workload control, and exact pass/fail formula.

- **LOW: Duplication between 57-01 and 57-04.**
  Both document Secure Boot, PPL, privilege, and reboot behavior. This risks contradictory content unless one plan owns canonical content and the other only expands/reviews it.

- **LOW: "Coverage identical" for fallback injection may be too strong.**
  Plan 57-04 says ETW Kernel-Process + CreateRemoteThread fallback has identical coverage. If there are timing windows, privilege requirements, or protected-process exclusions, the guide should state them precisely.

- **LOW: Link checking is mentioned but not operationalized.**
  Plan 57-06 says automated link checking, but does not specify the tool or command. That matters if final verification is expected to be reproducible.

### Suggestions

- Add a preflight task before 57-01/57-02 to derive the authoritative release artifact list from the build/package output and use that list everywhere.
- Change vendor procedures to a consistent evidence model: "Verified in lab" for any EDR actually tested; "Vendor-console procedure template" for untested vendors; no fake screenshots.
- Add a final hash publication task after release build/signing: build, verify Authenticode, generate hashes, paste into RELEASE_NOTES.md, re-run verification.
- Make 57-03 produce two sections: `Test Plan` and `Execution Results`. The plan can be committed early; the results should only be filled after physical-host execution.
- Strengthen UAT evidence requirements: Windows version/build, hardware specs, EDR product/version, cloud client versions, printer/share details, test account, policy bundle/version, binary hashes, timestamped tester sign-off.
- Clarify CRIT-04 benchmark protocol: warm-up run, three measured runs, median calculation, baseline without hooks, test with hooks, exact overhead formula, and no-ship threshold.
- Make Plan 57-05 explicitly blocked on completed 57-03 execution results.
- Assign one canonical owner for Secure Boot/PPL/DACL/privilege/reboot documentation.
- Replace hardcoded WDSI detection language with "example detection name" and require operators to record their actual Defender detection name and submission ID.
- In 57-06, define exact verification commands (markdown lint, link checker, hash verification, placeholder search).

### Risk Assessment

**Overall risk: MEDIUM-HIGH.**

The plan architecture is sound and likely sufficient for the phase if executed rigorously. The main risk is evidentiary quality: this phase is a ship gate, but several artifacts can be produced as polished documentation without proving that the release artifacts, EDR procedures, signing flow, and physical-host UAT actually work. Tightening artifact derivation, placeholder policy, UAT evidence, and final verification commands would reduce the risk to medium or low.

---

## Claude Review

### Plan 57-01: Deployment Guide Scaffolding + Quick Start + Vendor Procedures

**Summary:** A well-structured plan that creates the primary operational artifact for the v0.10.0 ship gate. It correctly follows the established `dpapi-recovery.md` style and covers all 6 EDR vendors with a consistent template. However, it has significant scope overlap with 57-04 and a circular content dependency with 57-02.

**Strengths:**
- Clear section structure mirroring enterprise deployment guides (Prerequisites -> Installation -> Vendor Procedures -> Secure Boot -> Verification -> Troubleshooting)
- Quick Start checklist appropriately targets experienced operators
- Per-vendor template is consistent and extensible (D-04 satisfied)
- Good threat model acceptance for screenshot leakage (test environment only)

**Concerns:**
- **HIGH:** Task 3 overlaps almost entirely with Plan 57-04. Both plans write Secure Boot, PPL, SeSystemProfilePrivilege, and post-install sections to the same file. This will cause merge conflicts or duplicate content. 57-01 should limit Task 3 to scaffolding/placeholder headers only, leaving the detailed content to 57-04.
- **MEDIUM:** The Quick Start says "add hash exclusions" but hash values come from RELEASE_NOTES.md (57-02), which `depends_on` 57-01. The Quick Start will reference hashes that don't exist yet when 57-01 runs. Cross-plan content sequencing needs adjustment.
- **MEDIUM:** SentinelOne section says "certificate hash" and Carbon Black says "MD5 hash" -- both conflict with D-05 (SHA-256 from RELEASE_NOTES.md). These need alignment with the CONTEXT decision.
- **LOW:** D-16 (CONTEXT) suggests a Rollback Procedure subsection, but no plan task includes it.

**Suggestions:**
- Remove Secure Boot/PPL/SeSystemProfilePrivilege content from 57-01 Task 3; keep only placeholder headers with `<!-- See 57-04 for detailed content -->`
- Add a placeholder reference in Quick Start for hash exclusions: `[SHA-256 from RELEASE_NOTES.md]` to make the temporal dependency explicit
- Standardize all vendor hash references to SHA-256 per D-05; note SentinelOne certificate hash as an exception with explanation
- Add a Rollback Procedure task to 57-01 or 57-04 covering: service stop, MSI uninstall, DACL restoration via `icacls /reset`, ProgramData cleanup option

---

### Plan 57-02: RELEASE_NOTES.md + Hash Generation + WDSI + signtool

**Summary:** A focused plan that creates the release integrity artifact and documents hash verification and Microsoft submission flows. The structured format is clear and the PowerShell snippets are operator-friendly.

**Strengths:**
- Structured release notes format with all required sections (Summary, Binaries, Breaking Changes, Migration Notes, Known Issues)
- PowerShell hash generation snippet is reproducible and well-formed
- WDSI submission documents exact form fields and expected turnaround
- Good acceptance of hash collision risk (SHA-512 provides additional resistance)

**Concerns:**
- **MEDIUM:** Hash placeholders use `[TO BE FILLED AT RELEASE]` but no plan task actually fills them at release time. There is no "Release Day" plan or task to populate these hashes after the build.
- **MEDIUM:** WDSI detection name `"Trojan:Win32/Wacatac.B!ml"` is overly specific. The actual heuristic detection name may vary by build. Should note "or similar heuristic detection" and advise operators to copy the exact name from their Defender alert.
- **LOW:** No mention of code signing certificate thumbprint or issuer, which operators may need for certificate-based EDR exclusions (e.g., SentinelOne per 57-01).

**Suggestions:**
- Add a note in RELEASE_NOTES.md that hashes are populated at release time by the release engineer, or create a follow-up task/bead to track hash population
- Soften WDSI detection name to: `Trojan:Win32/Wacatac.B!ml` (or similar heuristic detection name shown in your Defender console)
- Consider adding a "Signing Certificate" subsection with thumbprint and issuer for certificate-based allowlisting

---

### Plan 57-03: UAT Test Plan + Execution

**Summary:** The most critical plan for the ship gate. It comprehensively covers 25+ scenarios across 9 categories with a hard CRIT-04 performance gate. The physical host requirement is correctly specified per D-12.

**Strengths:**
- Excellent category coverage: injection, blocking, cloud sync regression, print, removable media, DACL tripwire, ETW bypass, monitor mode, performance
- CRIT-04 benchmark is well-specified: `Measure-Command`, 3 repetitions, median, explicit 25% threshold
- Binary pass/fail criteria for every scenario (D-10 satisfied)
- UAT Sign-Off section with signature fields

**Concerns:**
- **HIGH:** Several operational scenarios from the deployment guide are missing from UAT: (a) verifying EDR allowlist actually prevents quarantine, (b) verifying Authenticode signature with signtool, (c) verifying SeSystemProfilePrivilege assignment, (d) verifying Secure Boot fallback behavior. These are "deploy and verify" steps that an operator would follow -- UAT should exercise them.
- **MEDIUM:** UAT-57-A04 "Agent restart sweeps all running processes within 5s" -- the term "sweeps" is ambiguous. Does it mean injects into all existing processes? Re-injects into previously injected processes? Clarify expected behavior.
- **MEDIUM:** UAT-57-C05 "Clipboard cloud link detection works" is miscategorized under Cloud Sync. It should be in Category B (File Blocking) or a separate Clipboard category, since it doesn't test cloud sync client behavior.
- **LOW:** No time estimate or suggested session pacing for 25+ scenarios on a physical host. Could be a full day of testing.
- **LOW:** No fallback if a required peripheral is missing (e.g., no optical drive on test laptop). Should specify "N/A with justification" protocol.

**Suggestions:**
- Add Category J: Operational Verification with 4-5 scenarios: J01 Authenticode verification, J02 EDR allowlist verification (no quarantine), J03 SeSystemProfilePrivilege verification, J04 Secure Boot fallback verification, J05 Hash verification against RELEASE_NOTES.md
- Clarify A04: "Agent restart injects hook DLL into all newly observed running user processes within 5 seconds"
- Move C05 to a new Category J or rename Category C to "Cloud Sync and Clipboard"
- Add a "Peripheral Availability" section to the Environment preamble with N/A protocol

---

### Plan 57-04: Secure Boot + PPL + DACL + Privilege + Reboot Reality

**Summary:** A critical operational reality plan that documents the gap between ideal architecture and actual Windows behavior. The content is accurate and important for operator understanding.

**Strengths:**
- Correctly identifies Secure Boot inertness of AppInit_DLLs and the ETW+CreateRemoteThread fallback
- PPL coverage gap documentation with ASCII table is excellent for operator comprehension
- Two-phase staged update mechanism is documented (operator removal vs. tamper alert distinction)
- Three privilege assignment methods cover enterprise deployment options

**Concerns:**
- **HIGH:** As noted for 57-01, this plan's entire scope overlaps with 57-01 Task 3. Both write Secure Boot, PPL, SeSystemProfilePrivilege, and reboot sections to the same file. This is the most significant structural problem across all Phase 57 plans.
- **MEDIUM:** Event ID verification uses `Get-WinEvent -FilterHashtable @{LogName='Application'; ID=1000}` -- Event ID 1000 is the generic Windows Application Error crash event, not the DLP agent's custom event. This will produce false positives. Should use the actual event source (e.g., `DlpAgent` or `DLP-RUST`) or the correct custom event ID.
- **MEDIUM:** PowerShell privilege assignment via `Invoke-Command` with `secedit` is vague. Operators need a copy-pasteable command. The LSA API call approach is especially underspecified.
- **LOW:** "Reboot is NOT required for service restarts" -- this is only true for the ETW+CreateRemoteThread path. If Secure Boot is OFF and AppInit_DLLs is the mechanism, a service restart won't re-activate AppInit_DLLs for existing processes. The statement needs mechanism-context qualification.

**Suggestions:**
- **Merge with 57-01 or scope-split:** Either move ALL Secure Boot/PPL/privilege/reboot content to 57-04 and remove Task 3 from 57-01, OR keep 57-01 as pure scaffolding/vendor-procedures and make 57-04 the definitive operational-reality plan. The latter is cleaner.
- Fix Event ID reference to use the correct DLP agent event source/ID; verify against `dlp-agent/src/service.rs`
- Replace vague PowerShell privilege assignment with a concrete `secedit` command or reference to a script
- Add mechanism-qualified reboot guidance: "If AppInit_DLLs is active (Secure Boot OFF), reboot required for new processes to load hook. If ETW fallback is active (Secure Boot ON), service restart is sufficient."

---

### Plan 57-05: UAT Analysis + Ship Decision + STATE/ROADMAP Update

**Summary:** A clear decision-making plan with unambiguous ship/no-ship criteria. The artifact production (VERIFICATION.md, COMPLETION.md) is well-specified.

**Strengths:**
- Explicit blocking vs. non-blocking failure categorization
- 0 blocking = SHIP / 1+ blocking = NO-SHIP is unambiguous
- VERIFICATION.md structure covers all 4 OPS requirements
- v0.10.0 milestone completion document is a good handoff artifact

**Concerns:**
- **MEDIUM:** If NO-SHIP, the task says "plan fix phase" but provides no mechanism to file issues or create follow-up work. In a beads workflow, this should create blocking issues.
- **MEDIUM:** v0.10.0-COMPLETION.md is created unconditionally, but if NO-SHIP, it should be named v0.10.0-BLOCKED.md or contain conditional language. A "COMPLETION" document for a non-shipping milestone is misleading.
- **LOW:** No task to update the deployment guide with UAT-discovered corrections or clarifications. UAT often reveals documentation gaps.

**Suggestions:**
- Add a conditional task: if NO-SHIP, create issues for each blocking failure using `bd create`, and create `.planning/milestones/v0.10.0-BLOCKED.md` instead of COMPLETION.md
- Add a task to update the deployment guide with any operational clarifications discovered during UAT
- Link VERIFICATION.md from STATE.md explicitly

---

### Plan 57-06: Final Integration Verification

**Summary:** A solid integration-check plan that catches the common documentation pitfalls: stale version references, broken links, inconsistent terminology, and formatting issues.

**Strengths:**
- Cross-reference checks between all 3 major artifacts
- Explicit binary name consistency verification against Cargo.toml
- Version reference checks (catching v1.0.0 stragglers)
- Capability-to-phase mapping verification
- Markdown lint checklist is comprehensive

**Concerns:**
- **MEDIUM:** The placeholder check exempts "Screenshot placeholder" but by Wave 3 (after 57-03 UAT execution), screenshots should ideally be filled. However, since 57-03 is manual, the automated 57-06 may run before screenshots are captured. The verification should distinguish between "placeholder noted for future UAT" and "placeholder that should now be resolved."
- **LOW:** The verification grep checks for `v1.0.0` but should also check for stale `v0.9.x` references that should be `v0.10.0` in the current milestone context.
- **LOW:** No automated link validation is actually implemented -- the threat model mentions "automated link checking" as mitigation for T-57-13, but the task only does grep-based consistency checks, not actual relative link resolution.

**Suggestions:**
- Add a version check for `v0.9` (without `v0.10.0` nearby) to catch stale milestone references
- Consider adding a simple markdown link validator: `grep -oP '\[.*?\]\(\K[^)]+' docs/operations/deployment-guide.md | while read link; do test -f "$link" || echo "Broken: $link"; done`
- Clarify screenshot placeholder policy: if UAT is complete (57-03 done), placeholders must be resolved; if UAT is pending, placeholders are acceptable with a note

---

### Risk Assessment: MEDIUM

The Phase 57 plans are comprehensive, well-structured, and largely achieve the phase goals. The 25+ UAT scenarios provide good coverage, the deployment guide structure follows established patterns, and the CRIT-04 hard gate is appropriately positioned as a ship blocker.

However, **two HIGH-severity concerns elevate the overall risk:**

1. **Plan 57-01 and 57-04 have near-total scope overlap on Secure Boot, PPL, SeSystemProfilePrivilege, and reboot documentation.** Both plans write the same sections to the same file. Without resolution, this will produce merge conflicts, duplicate content, or inconsistent documentation. This is a structural planning defect that must be fixed before execution.

2. **Plan 57-03 is missing operational verification scenarios.** The UAT exercises product functionality thoroughly but does not verify the operational steps in the deployment guide (Authenticode verification, EDR allowlist effectiveness, privilege assignment). A UAT that passes all product tests but misses "the operator can't actually follow the guide" would be a false positive for ship readiness.

**Secondary risks:**
- The WDSI detection name assumption (57-02) is brittle and may confuse operators if the actual heuristic differs.
- The circular content dependency between 57-01 (references hashes) and 57-02 (produces hashes) could result in stale placeholder text if not explicitly managed.

**Recommendation:** Resolve the 57-01/57-04 overlap before executing Wave 1. Add operational verification scenarios to 57-03. Soften the WDSI detection name. These changes would reduce the overall risk to LOW.

---

## OpenCode Review

### Summary

The Phase 57 plan set is strong, thorough, and aligned with a real-world "ship gate" for an enterprise endpoint product. It correctly emphasizes operator reproducibility, EDR coexistence, and hard acceptance criteria (UAT + CRIT-04). The structure is logical (docs -> validation -> decision -> integration), and most critical deployment realities (Secure Boot, PPL, privilege persistence) are explicitly handled. The main risks are around **practical executability** (screenshots, vendor UI drift, UAT environment variability), **verifiability of claims**, and **missing edge-case handling in EDR behavior and upgrade flows**. Overall, this is close to production-ready but needs tightening around reproducibility and failure modes.

### Strengths

- Clear mapping to OPS-01..04 and explicit success criteria
- Strong operator-focused design (step-by-step, verification-driven)
- Realistic handling of Windows constraints (Secure Boot, PPL, privileges)
- UAT defined as a hard gate with measurable criteria (CRIT-04 <=25%)
- Vendor coverage is comprehensive and standardized (template-driven)
- Good separation of concerns across plans (docs vs execution vs decision)
- Hash publication + signtool + WDSI flow increases trust and deployability
- Inclusion of DACL tripwire as fallback demonstrates defense-in-depth
- Final integration plan ensures cross-doc consistency (often missed)

### Concerns

#### Plan 57-01 (Deployment Guide)
- **HIGH:** Screenshot requirement is underspecified. No guidance on how screenshots are sourced, versioned, or kept up to date with constantly changing EDR UIs.
- **MEDIUM:** Vendor procedures may drift quickly. EDR consoles change frequently; static instructions risk becoming invalid within months.
- **MEDIUM:** "Expected detection behavior" not concretely defined. Needs explicit examples (process name, alert name, severity) or operators cannot validate correctness.
- **LOW:** Quick Start checklist mixes validation depth. Some steps are shallow (e.g., "test T4 denial") without defining how.

#### Plan 57-02 (Release Notes + Hashes)
- **HIGH:** Hash generation is manual and error-prone. No validation step ensuring hashes correspond to shipped artifacts.
- **MEDIUM:** No binding between binaries and build provenance. Missing build reproducibility or artifact source trace (e.g., CI artifact ID).
- **LOW:** WDSI flow assumes specific detection name. "Wacatac.B!ml" may change; brittle documentation.

#### Plan 57-03 (UAT)
- **HIGH:** UAT reproducibility risk. "Real host + real EDR" introduces high variability; results may not be repeatable across environments.
- **HIGH:** No rollback or isolation strategy. Running 25+ invasive scenarios on a single host can contaminate later tests.
- **MEDIUM:** Performance benchmark methodology too coarse. Measure-Command + 3 runs may not be statistically stable.
- **MEDIUM:** No logging/telemetry capture requirement. Pass/fail without artifacts (logs, ETW traces) weakens auditability.

#### Plan 57-04 (Secure Boot / PPL / Privileges)
- **MEDIUM:** CreateRemoteThread fallback not risk-assessed. Some EDRs explicitly block this; potential compatibility gap not addressed.
- **MEDIUM:** DACL tripwire explanation may be too abstract. Needs concrete operator-visible behavior and failure modes.
- **LOW:** Privilege persistence across domain policy refresh not addressed.

#### Plan 57-05 (Ship Decision)
- **MEDIUM:** Binary PASS/FAIL classification too coarse. No severity weighting or partial degradation model.
- **LOW:** No explicit sign-off authority model (who approves ship?)

#### Plan 57-06 (Final Integration)
- **LOW:** "No TODOs" check is manual. Easy to miss without automation.
- **LOW:** Link checking mentioned but not defined (tooling unclear).

### Suggestions

#### Deployment Guide
- Define a **screenshot policy**: source (lab environment only), naming/versioning convention, fallback (text-only steps if UI differs)
- Add **"last verified date + EDR version"** per vendor section
- Include **expected alert examples**: process name, detection string, severity, console location

#### Release Notes / Hashes
- Add a **verification step**: script that recomputes hashes and compares to RELEASE_NOTES.md
- Include **artifact provenance**: build ID, commit SHA, CI pipeline reference
- Replace hardcoded detection name with: "example detection (may vary by model version)"

#### UAT
- Require **artifact capture per scenario**: logs (agent + system), screenshots, event IDs
- Add **environment snapshot section**: Windows build, EDR version, policy config
- Improve performance methodology: >=5 runs, discard outliers, report variance
- Define **test isolation strategy**: reboot between categories or use clean baseline checkpoints

#### Secure Boot / PPL Section
- Add **EDR compatibility note for CreateRemoteThread**: explicitly list known vendors where this may fail
- Provide **operator-visible signals**: "If injection fails, you will see X event, Y behavior"

#### Ship Decision
- Introduce **severity tiers**: Blocking / Major / Minor
- Define **approval authority**: e.g., "Ship requires sign-off from engineering + QA"

#### Integration Verification
- Automate: link checking (e.g., markdown link checker), TODO detection (`grep TODO`)
- Add **doc consistency checklist script** if possible

### Risk Assessment

**Overall Risk: MEDIUM**

- **Why not LOW:** The plans rely heavily on manual execution (docs, screenshots, UAT, hash generation). Without tighter reproducibility and validation mechanisms, there is a real risk of incorrect deployment instructions, non-reproducible UAT results, and hash mismatches or operator error.
- **Why not HIGH:** Core architecture, sequencing, and coverage are solid. Critical deployment realities are addressed, and the ship gate is clearly defined with measurable criteria.

**Bottom line:** The phase is well-designed and close to production-grade, but needs **stronger guarantees around reproducibility, validation, and operational drift** to fully meet enterprise deployment expectations.

---

## Consensus Summary

### Agreed Strengths

All three reviewers independently identified the following strengths:

1. **Clear requirement mapping** -- OPS-01..04 are each assigned dedicated plans with explicit success criteria.
2. **Good wave ordering** -- documentation first, UAT execution second, ship decision and integration verification last is the correct sequencing.
3. **Strong operator focus** -- step-by-step procedures, PowerShell snippets, verification commands, and troubleshooting sections all target the actual deployer.
4. **Hard ship gates are well-positioned** -- CRIT-04 <=25% overhead and physical-host UAT are correctly identified as blocking criteria.
5. **Windows operational realities are first-class** -- Secure Boot, PPL, privilege persistence, and reboot behavior are all explicitly documented rather than assumed.
6. **Defense-in-depth is demonstrated** -- DACL tripwire as backstop, ETW fallback for Secure Boot, and dual-hash (SHA-256 + SHA-512) all show mature security thinking.

### Agreed Concerns

All three reviewers raised or concurred on the following HIGH-severity concerns:

1. **57-01 / 57-04 scope overlap (HIGH)** -- Codex, Claude, and OpenCode all identified that Plans 57-01 and 57-04 write overlapping content (Secure Boot, PPL, SeSystemProfilePrivilege, reboot) to the same file. Claude called this "the most significant structural problem across all Phase 57 plans." Codex rated it LOW but still flagged it. Consensus: this must be resolved before execution.

2. **Placeholder / evidentiary quality risk (HIGH)** -- Codex and Claude both flagged that screenshot placeholders in 57-01 conflict with 57-06's "no unresolved placeholders" rule. Codex also flagged that 57-02's placeholder hashes lack a final replacement step. OpenCode flagged manual hash generation as error-prone. Consensus: the phase needs a clear "placeholder policy" and a final artifact-verification step.

3. **UAT missing operational verification (HIGH)** -- Claude explicitly called out that 57-03 does not verify deployment-guide operational steps (Authenticode, EDR allowlist effectiveness, privilege assignment). OpenCode flagged UAT reproducibility risk and lack of rollback/isolation. Codex flagged that 57-06 should not run until UAT results are real. Consensus: UAT needs a Category J (Operational Verification) and stronger evidence requirements.

4. **WDSI detection name brittleness (MEDIUM, near-consensus HIGH)** -- Codex, Claude, and OpenCode all flagged that hardcoding `Trojan:Win32/Wacatac.B!ml` is brittle. Consensus: soften to "example detection name; use actual name from your Defender console."

### Divergent Views

- **Overall risk rating:** Codex rated MEDIUM-HIGH; Claude rated MEDIUM; OpenCode rated MEDIUM. The divergence is on whether evidentiary quality (Codex's concern) is severe enough to push to HIGH. Consensus settles on **MEDIUM** with the understanding that resolving the agreed concerns would lower it to LOW.

- **Screenshot policy:** Claude suggested keeping placeholders with explicit notes; OpenCode suggested a full screenshot policy with versioning; Codex suggested either real screenshots or removing the requirement. The project should adopt OpenCode's structured policy but allow text-only procedures for untested vendors.

- **CRIT-04 benchmark rigor:** OpenCode wanted >=5 runs with outlier discard; Claude found 3 runs acceptable; Codex wanted warm-up and background-control specification. Consensus: adopt Codex's protocol (warm-up, 3 measured runs, median, explicit formula) as the minimum, with OpenCode's >=5 runs as an optional enhancement.

---

## Action Items for Planning

| # | Concern | Severity | Suggested Fix | Owner Plan |
|---|---------|----------|---------------|------------|
| 1 | 57-01 / 57-04 overlap | HIGH | Remove Task 3 from 57-01; make 57-04 the canonical owner of all Secure Boot/PPL/privilege/reboot content | 57-01, 57-04 |
| 2 | Placeholder policy undefined | HIGH | Add explicit placeholder policy to CONTEXT.md: screenshots acceptable as "[Screenshot: ...]" only if noted "to be added during UAT"; hashes must be replaced before ship | CONTEXT.md |
| 3 | UAT missing operational verification | HIGH | Add Category J to 57-03 with 4-5 operational scenarios (Authenticode, EDR allowlist, privilege, Secure Boot fallback, hash verification) | 57-03 |
| 4 | WDSI detection name brittle | MEDIUM | Soften to example language; require operators to record actual detection name | 57-02 |
| 5 | Hash placeholder -> final step missing | MEDIUM | Add explicit task in 57-02 or 57-06 to replace placeholders with actual release artifact hashes | 57-02, 57-06 |
| 6 | CRIT-04 benchmark under-specified | MEDIUM | Add warm-up run, background workload control, and exact overhead formula to 57-03 | 57-03 |
| 7 | 57-06 runs before UAT complete | MEDIUM | Add explicit dependency: 57-06 blocked on 57-03 execution completion, not just plan existence | 57-06 |
| 8 | Link checking not operationalized | LOW | Add concrete markdown link validation command to 57-06 | 57-06 |
| 9 | Rollback procedure missing | LOW | Add Rollback Procedure subsection to 57-01 or 57-04 | 57-01 |
| 10 | Signing certificate info missing | LOW | Add thumbprint/issuer subsection to 57-02 for certificate-based EDR allowlisting | 57-02 |

---

*Review conducted 2026-05-30 by Codex CLI, Claude CLI, and OpenCode.*
*To incorporate feedback: /gsd:plan-phase 57 --reviews*
