---
phase: 56
reviewers: [codex, opencode, claude]
reviewed_at: 2026-05-29T17:05:00Z
plans_reviewed:
  - 56-01-PLAN.md
  - 56-02-PLAN.md
  - 56-03-PLAN.md
  - 56-04-PLAN.md
  - 56-05-PLAN.md
  - 56-06-PLAN.md
---

# Cross-AI Plan Review -- Phase 56

## Codex Review (gpt-5.5)

### Summary

The six-plan breakdown is directionally solid and covers the main vertical slice: shared model changes, endpoint classification, hook-side propagation, server ABAC matching, admin UI exposure, and verification. The biggest risks are cross-plan contract mismatches and Windows device-classification reliability. In particular, Plan 03 assumes `dlp-hook-dll` exists and can use common types/shared-memory/named-pipe classification, but the project context lists only five crates and Phase 56 says prior hook phases "cover I/O for free"; that dependency needs to be verified. The plans also need sharper definitions for how `source_volume_class` and `destination_volume_class` move through IPC/server evaluation, how duplicate arrival events are keyed, and how virtual/SD/optical classification behaves when WMI is slow, unavailable, or ambiguous.

### Strengths

- Clean layering: common enum and ABAC schema first, then agent/server/UI/test integration.
- Good recognition that `GetDriveTypeW` alone is insufficient and WMI disambiguation is required.
- Preserves the existing 500 ms deferred device-processing pattern, which is important for Windows mount timing.
- Adds policy authoring support, not just backend enforcement.
- Includes both positive and negative authorization tests for volume-class ABAC.
- Uses optional ABAC context fields, which keeps backward compatibility for existing serialized policy/evaluation requests.
- Explicitly includes `NetworkShare`, avoiding a common blind spot for UNC paths.

### Concerns

- **HIGH: Hook DLL crate and IPC contract ambiguity.** Plan 03 modifies `dlp-hook-dll`, but the project context lists five crates and does not include that crate. If it exists from phases 48-50, the plan should say so explicitly. If not, Plan 03 is not executable.
- **HIGH: End-to-end requirement may not be met by Plan 06.** The success criterion requires blocking an actual `CopyFileExW` to a registered optical drive on a test endpoint. The described test mostly sounds like policy evaluation with injected classes, not a true Windows endpoint copy interception test.
- **HIGH: Classification reliability is underspecified.** SD vs USB vs optical vs virtual needs a concrete WMI strategy. `Win32_DiskDrive`, `Win32_LogicalDisk`, `Win32_LogicalDiskToPartition`, `Win32_DiskDriveToDiskPartition`, PNP IDs, media types, bus types, and mounted ISO/VHD cases need explicit mapping rules.
- **MEDIUM: Duplicate suppression is vague.** "Single distinct device-arrival audit event" needs a stable key, probably volume GUID or device instance ID plus drive letter/mount path, not just drive letter.
- **MEDIUM: Race conditions around arrival handling.** A 500 ms delay may still be insufficient for WMI relationships or Explorer ISO mounts to settle. The plan should include bounded retry/backoff.
- **MEDIUM: Fail-closed behavior may cause compatibility surprises.** Plan 04 says volume-class match fails closed on `None`. That is right for a condition requiring a class, but existing policies without these conditions must remain unaffected.
- **MEDIUM: Server-side path resolution may be misleading.** Server evaluation often lacks endpoint-local drive topology. Resolving `C:\...` on the server may classify the server's `C:` rather than the endpoint's. Prefer endpoint-provided context unless the server has authoritative endpoint volume inventory.
- **MEDIUM: Cache invalidation risk.** Plan 03's 30s thread-local cache can produce stale decisions after drive removal/remount or letter reuse. That is risky for enforcement.
- **MEDIUM: Shared enum serialization must be stable.** `PascalCase` values must match policy JSON, audit payloads, SIEM output, and TUI round-trips. Any previous lowercase/snake-case conventions should be checked.
- **LOW: `Default` for `VolumeClass` may hide bugs.** If `Default` is `LocalNTFS`, accidental defaults could silently loosen classification. Prefer no default on the enum unless needed for serde compatibility.
- **LOW: Admin UI badge colors include red for Virtual.** Red often implies danger/error; if used only as a category badge, it may create misleading visual semantics.
- **LOW: Full release build and sonar quality gate in Plan 06 may be environment-sensitive.** Good as a gate, but the plan should distinguish mandatory local checks from CI-only checks.

### Suggestions

- Add a shared "volume classification contract" before implementation:
  - enum values and serde names;
  - classification precedence;
  - unknown/error behavior;
  - duplicate event key;
  - IPC payload fields;
  - audit JSON shape.
- Make endpoint classification authoritative. The agent should maintain and expose a volume inventory keyed by drive letter, volume GUID, and device instance ID. The server should avoid local path classification for endpoint paths unless it is evaluating server-local resources.
- Replace or qualify enum `Default`. If a default is needed, consider `Unknown` as a seventh internal-only variant, or keep `Option<VolumeClass>` and avoid defaulting to `LocalNTFS`.
- Define WMI mapping rules explicitly:
  - `DRIVE_CDROM` -> `Optical`;
  - UNC / `DRIVE_REMOTE` -> `NetworkShare`;
  - removable with SD/card-reader indicators -> `SDCard`;
  - removable USB bus/device IDs -> `USBRemovable`;
  - fixed disk backed by VHD/VHDX/ISO/virtual bus/provider -> `Virtual`;
  - fixed NTFS physical disk -> `LocalNTFS`.
- Add bounded retries after `WM_DEVICECHANGE`, for example 500 ms, 1 s, 2 s, then emit once with the best resolved class or a logged classification error.
- In Plan 03, invalidate cache on device-change notifications or compare volume serial/device instance ID, not only drive letter plus TTL.
- Make Plan 04 depend explicitly on Plan 01 and Plan 03/agent IPC contract. Server ABAC cannot reliably evaluate destination volume class unless the hook/agent passes it.
- Expand Plan 06 into two test tiers:
  - deterministic unit/integration tests with injected classes;
  - Windows-only ignored/manual or CI-labeled test that performs actual `CopyFileExW` against mounted optical/ISO media.
- Add tests for serialization/backward compatibility: old ABAC contexts without volume fields, existing policies without new conditions, and policy JSON containing the new enum values.
- Add audit tests verifying exactly one `VolumeArrival` event per mount and correct SIEM routing/payload.
- Add UI round-trip tests for condition builder prefill/display if the admin CLI already has test scaffolding.

### Risk Assessment

Overall risk: **MEDIUM-HIGH**.

The design is coherent, but the implementation touches enforcement-critical paths, Windows device detection, audit semantics, policy evaluation, and UI policy authoring. The largest risks are not the enum or match arms; they are correct endpoint-local classification, stale cache behavior, and proving that the new ABAC fields actually reach the enforcement decision for real `CopyFileExW` operations. Tightening the IPC/classification contract and adding a real Windows endpoint test would bring this closer to **MEDIUM**.

---

## OpenCode Review (gpt-5.3-chat-latest)

### Overall Summary

This is a well-structured, layered plan that cleanly extends the system's existing architecture (agent -> hook -> server -> UI) without breaking core invariants. The separation into waves is logical, and responsibilities are mostly well-scoped per crate. The design correctly recognizes that volume classification must be consistent across agent and hook paths, and that WMI is required beyond `GetDriveTypeW`. The biggest risks are around **classification correctness**, **cross-component consistency**, and **runtime edge cases (hotplug timing, cache staleness, virtual drive ambiguity)**. Nothing is fundamentally flawed, but a few gaps could cause subtle misclassification or policy bypass if not tightened.

---

### Plan 01 Review (dlp-common)

**Summary**: Solid foundational schema work. The enum + ABAC extensions are minimal and consistent with existing patterns. This is the right place to centralize shared logic, but the classification helper risks being underspecified relative to real Windows edge cases.

**Strengths**:
- Clean extension of `AbacContext` using `Option` + serde defaults (backward compatible)
- Enum is explicit and future-proof (covers all required classes)
- Centralizing `resolve_volume_class_from_path` is correct for cross-crate reuse
- Audit event addition aligns with SIEM pipeline expectations

**Concerns**:
- **HIGH**: `resolve_volume_class_from_path` abstraction is underspecified. The lookup closure hides critical complexity (drive letter vs GUID vs UNC vs subst drives). Risk of inconsistent implementations across agent/hook/server.
- **MEDIUM**: No explicit handling for volume GUID paths (`\\?\Volume{...}`), SUBST drives, reparse points / symlinks.
- **MEDIUM**: `Default` for `VolumeClass` is not defined semantically. If it defaults to `LocalNTFS`, that may silently misclassify unknowns.
- **LOW**: `op: String` in `PolicyCondition` is loosely typed (existing issue, but worsens with new conditions)

**Suggestions**:
- Define strict contract for `resolve_volume_class_from_path`: input normalization rules (absolute paths only, UNC detection first, etc.)
- Add explicit `Unknown` variant OR enforce `Option<VolumeClass>` everywhere (prefer the latter for fail-closed)
- Document canonical mapping rules (e.g., UNC -> NetworkShare always)
- Consider strongly-typed operator enum instead of `String` (if not already planned elsewhere)

**Risk Assessment**: MEDIUM -- foundational correctness risk; errors propagate everywhere.

---

### Plan 02 Review (Agent Classification)

**Summary**: Correctly places authoritative classification in the agent using WMI + Win32 APIs. The hybrid approach is necessary, but WMI reliability and timing issues introduce risk.

**Strengths**:
- Correct use of WMI to disambiguate beyond `GetDriveTypeW`
- `volume_class_map` cache avoids repeated expensive queries
- Duplicate suppression + 500ms delay aligns with prior architecture
- Clear separation of classification logic (`disambiguate_*` helpers)

**Concerns**:
- **HIGH**: WMI latency and failure handling not addressed. WMI can block or fail transiently -> classification may be missing or wrong at arrival time.
- **HIGH**: Race condition between device arrival and WMI availability. 500ms may not always be sufficient (especially for VHD/ISO mount).
- **MEDIUM**: Cache invalidation not defined. Drive letter reuse (e.g., USB removed -> new device gets same letter) can cause stale classification.
- **MEDIUM**: Virtual vs LocalNTFS disambiguation is fragile. VHD/VHDX may appear as fixed disks indistinguishable from physical without deeper inspection.
- **LOW**: `RwLock<HashMap<...>>` may be overkill if writes are rare (but acceptable)

**Suggestions**:
- Add retry/backoff for WMI classification if initial attempt fails
- Add timestamp/versioning to `volume_class_map` entries to avoid stale reuse
- Explicitly detect BusType (USB vs SD vs Virtual) and PNPDeviceID patterns for virtual devices
- Add fallback classification with audit warning if WMI fails
- Log classification source (WMI vs fallback) for debugging

**Risk Assessment**: HIGH -- classification correctness is critical to enforcement.

---

### Plan 03 Review (Hook DLL Cache)

**Summary**: Performance-conscious design that avoids IPC overhead. Thread-local cache with TTL is appropriate, but consistency with agent classification is a major risk.

**Strengths**:
- Thread-local cache minimizes contention
- TTL prevents permanent staleness
- Early classification before pipe round-trip improves latency
- UNC fast-path is correct

**Concerns**:
- **HIGH**: Divergence from agent classification logic. Hook has its own resolution logic -> risk of mismatch with agent -> inconsistent policy decisions.
- **HIGH**: TTL-based cache can produce incorrect enforcement. Example: drive letter reassigned within 30s -> stale classification used.
- **MEDIUM**: Volume GUID fallback to `LocalNTFS` is unsafe. Could misclassify virtual or optical volumes.
- **MEDIUM**: Shared memory + named pipe fallback chain is complex and failure-prone
- **LOW**: `RefCell` in thread-local is fine but needs careful panic handling

**Suggestions**:
- Make agent the source of truth: Hook should prefer querying agent cache, not re-implement classification
- Reduce TTL or tie cache invalidation to WM_DEVICECHANGE events
- Do not default GUID -> LocalNTFS; instead return `None` (fail-closed)
- Add consistency check: If agent response differs from cached value -> invalidate

**Risk Assessment**: HIGH -- inconsistency here can bypass ABAC enforcement.

---

### Plan 04 Review (Server ABAC Evaluation)

**Summary**: Minimal and correct extension of policy evaluation. The fail-closed behavior is appropriate, but server-side fallback classification is questionable.

**Strengths**:
- Fail-closed on `None` is correct for security
- Clean integration into existing condition matching
- Helper function keeps logic isolated
- Integration test included

**Concerns**:
- **HIGH**: Server-side classification duplicates logic again. Introduces third source of truth (agent + hook + server).
- **MEDIUM**: Evaluating from `resource_path` may not reflect actual runtime device. Especially for network shares or mapped drives.
- **LOW**: No explicit logging when classification is missing

**Suggestions**:
- Treat agent-provided context as authoritative
- Only use server fallback for: offline evaluation / audit replay
- Log when fallback classification is used
- Consider rejecting evaluation if volume_class is missing in live enforcement

**Risk Assessment**: MEDIUM -- mostly safe, but duplication increases drift risk.

---

### Plan 05 Review (Admin TUI)

**Summary**: Straightforward UI extension. Fits existing patterns and keeps UX consistent.

**Strengths**:
- Dropdown-based selection prevents invalid input
- Operator support (`eq/ne/in`) is flexible
- Round-trip (prefill/display) handled
- Visual badges improve clarity

**Concerns**:
- **LOW**: Hardcoded index mapping (0-5) is brittle
- **LOW**: No validation for incompatible combinations (e.g., NetworkShare as destination in certain contexts)
- **LOW**: Color mapping may not be accessible (contrast issues)

**Suggestions**:
- Replace index mapping with enum-driven iteration
- Add validation hints in UI for invalid policy combinations
- Consider accessibility (colorblind-safe palette)

**Risk Assessment**: LOW -- mostly cosmetic and UX-level.

---

### Plan 06 Review (Integration Test)

**Summary**: Good end-to-end validation of the core use case. Covers both positive and negative paths.

**Strengths**:
- Tests real enforcement path (CopyFileExW)
- Includes negative control
- Uses test injection to avoid hardware dependency
- Includes full quality gate

**Concerns**:
- **MEDIUM**: Test injection bypasses real classification path. Does not validate WMI + detection correctness.
- **MEDIUM**: Optical drive requirement may be hard to reproduce in CI
- **LOW**: Only one policy scenario tested

**Suggestions**:
- Add additional cases: USB -> Optical, Virtual -> NetworkShare
- Add test for classification correctness, not just policy evaluation
- Mock WMI layer to simulate edge cases (failure, delay)
- Add regression test for cache staleness (drive letter reuse)

**Risk Assessment**: MEDIUM -- good coverage of logic, weaker on real-world conditions.

---

### Cross-Plan Issues

**Critical Risks**:
- **Multiple classification implementations (Agent, Hook, Server)** -> drift and inconsistency
- **Drive letter reuse + cache TTL** -> stale classification -> policy bypass
- **WMI timing/availability** -> incorrect or missing classification at enforcement time

**Architectural Concern**: There is no clearly enforced **single source of truth** for `VolumeClass`.

### Key Recommendations

1. **Unify classification authority** -- Agent = canonical source; Hook + Server = consumers, not independent classifiers
2. **Fail closed everywhere** -- Unknown classification -> DENY or explicit audit
3. **Handle device lifecycle explicitly** -- Invalidate caches on device removal; track volume serial/device ID, not just drive letter
4. **Strengthen classification signals** -- Use BusType, PNPDeviceID, and volume metadata; avoid relying on `GetDriveTypeW` beyond coarse filtering
5. **Add observability** -- Log classification source and confidence; emit warnings on fallback paths

### Final Risk Assessment

**Overall: MEDIUM-HIGH**

- The design is strong and aligned with the system architecture.
- The main risk is **classification correctness and consistency**, which directly impacts enforcement integrity.
- If classification is unified and cache invalidation is tightened, risk drops to **MEDIUM**.

---

## Claude Review (Claude CLI -- claude-3-7-sonnet-latest)

### Overall Assessment

The six-plan structure correctly decomposes the phase goal across three waves with sensible dependencies: shared types first, then agent-side detection, then hook/server/UI integration, finally E2E validation. The hybrid WMI + GetDriveTypeW classification approach is architecturally correct. However, several plans have execution risks around synchronous WMI in hot paths, unclear shared-memory IPC boundaries, and hardware-dependent integration tests that could destabilize CI.

**Overall Risk Level: MEDIUM**

---

### Plan 01: VolumeClass enum + AbacContext extension (Wave 1)

**Summary**: Solid foundational plan. The `VolumeClass` enum design is clean, the generic `resolve_volume_class_from_path<F>` helper is testable, and the `#[serde(default, skip_serializing_if = "Option::is_none")]` on context fields preserves backward compatibility. This is exactly the right scope for a Wave 1 common crate change.

**Strengths**:
- Generic lookup function enables unit testing without WMI dependencies
- `serde(rename_all = "PascalCase")` matches existing JSON policy format conventions
- `EventType::VolumeArrival` with builder pattern follows established audit.rs patterns

**Concerns**:
- **MEDIUM**: `#[derive(Default)]` on `VolumeClass` will default to `LocalNTFS` (first variant). This is fine for serialization but could be dangerous if used as a fallback in enforcement code -- any plan relying on `VolumeClass::default()` for unclassifiable paths must be explicit.
- **LOW**: `op: String` in `PolicyCondition` variants is consistent with existing code but loses type safety. Consider (in a future phase) migrating to an `enum ComparisonOp { Eq, Ne, In }`.

**Suggestions**:
- Add a doc comment on `VolumeClass` explicitly documenting that `LocalNTFS` is the first variant and therefore the `Default`.
- Consider adding a `VolumeClass::is_removable(self) -> bool` helper in this plan to avoid repeated match arms elsewhere.

---

### Plan 02: Agent-side volume classification + VolumeArrival emission (Wave 1)

**Summary**: The hybrid `GetDriveTypeW + WMI` approach correctly addresses the requirement that `GetDriveTypeW` alone cannot distinguish USB from SD or LocalNTFS from Virtual. However, the plan under-specifies error handling and the structural naming of `UsbDetector` becomes a misnomer when it classifies optical and virtual drives.

**Strengths**:
- Correctly identifies `Win32_DiskDrive` + `Win32_LogicalDisk` as the disambiguation source
- Preserves the 500ms deferred processing pattern from v0.7.0
- Duplicate suppression on `DBT_DEVICEARRIVAL` prevents audit log spam

**Concerns**:
- **HIGH**: WMI queries can fail (timeout, permission denied, WMI service unavailable). The plan does not specify fallback behavior. If WMI fails and the code falls back to `GetDriveTypeW` alone, SD cards may be misclassified as `USBRemovable` or virtual drives as `LocalNTFS`, causing policy bypasses or false blocks.
- **HIGH**: The struct is still named `UsbDetector` but now manages a `volume_class_map` for six volume classes. This is technical debt. At minimum, rename to `VolumeDetector` or `DeviceDetector` in this plan.
- **MEDIUM**: The plan says "DBT_DEVICEARRIVAL" but virtual mounts (VHDX via Explorer, Daemon Tools) may not always arrive through the same `WM_DEVICECHANGE` path as physical USB insertions. The plan should verify these specific virtual mount scenarios or add a fallback polling mechanism.
- **MEDIUM**: `volume_class_map: RwLock<HashMap<char, VolumeClass>>` uses `char` for drive letters. This is fine for A-Z but cannot represent volume GUID paths (`\\?\Volume{...}`), which the hook DLL (Plan 03) must classify. A path-to-class map may be needed.

**Suggestions**:
- Define explicit fallback semantics: if WMI fails, classify as `Unknown` (new variant) or fail-closed to the most restrictive class, never silently default to `LocalNTFS`.
- Rename `UsbDetector` -> `VolumeDetector` now, before cross-references multiply.
- Add a `VolumeClass::Unknown` variant or document that `None` represents classification failure.
- Consider a `HashMap<PathBuf, VolumeClass>` instead of `HashMap<char, VolumeClass>` to support volume GUID paths.

---

### Plan 03: Hook DLL thread-local cache + trampoline integration (Wave 2)

**Summary**: The 30s TTL thread-local cache is a pragmatic performance optimization for the hook DLL hot path. The fallback chain (UNC -> NetworkShare, drive letter -> cache, volume GUID -> LocalNTFS) is reasonable but contains a security-critical default that needs hardening.

**Strengths**:
- Thread-local `RefCell<HashMap>` avoids cross-thread synchronization overhead in hooked I/O paths
- Named pipe query to agent for cache misses is the correct IPC pattern
- `resolve_volume_class_from_path` is shared with the server via dlp-common

**Concerns**:
- **HIGH**: "volume GUID -> LocalNTFS fallback" is a policy bypass vector. If a virtual drive mounted at a volume GUID path (common for VHDX and ISO mounts) is misclassified as `LocalNTFS`, a policy of "DENY T4 to Virtual" will not fire. The fallback for unclassifiable paths must be fail-closed.
- **HIGH**: The shared-memory cache ("shared-memory cache first, then named pipe query") is mentioned but not defined in any plan. If this is new infrastructure, it is a significant omission -- which crate creates the shared memory, what is the layout, and how is concurrency handled?
- **MEDIUM**: 30s TTL may be too long for rapid insert/remove cycles (e.g., SD card swapped within 30s). Consider 5-10s TTL or invalidation on `DBT_DEVICEREMOVECOMPLETE`.
- **MEDIUM**: `CopyFileExW/MoveFileExW` resolve both source and destination. For a move operation, if the source is being moved *off* the machine (e.g., to a USB drive), both classifications are relevant. Ensure the `MoveFileExW` trampoline correctly handles cross-volume moves where source and destination have different classes.

**Suggestions**:
- Change the volume GUID fallback to `VolumeClass::Unknown` or add an explicit `Virtual` guess for GUID paths rather than defaulting to `LocalNTFS`.
- If shared memory is new, either add it to Plan 02 (agent creates the SHM) or document it as a prerequisite.
- Add cache invalidation on device removal events, not just TTL expiration.
- Document the named pipe protocol (message format, timeout) for the query to the agent.

---

### Plan 04: Server-side ABAC evaluation (Wave 2)

**Summary**: Clean server-side extension. The `volume_class_matches` helper with fail-closed on `None` is correct. The server-side path resolution fallback is a good defensive measure but introduces a subtle mismatch risk.

**Strengths**:
- Fail-closed (`None` -> false) in `volume_class_matches` is the correct security posture
- Adding server-side `resolve_volume_class_from_path` when context fields are missing provides defense in depth
- The integration test target ("DENY LocalNTFS T4 to Optical") directly maps to success criterion #2

**Concerns**:
- **MEDIUM**: Server-side `resolve_volume_class_from_path` when `ctx.fields are None` may produce a different classification than the agent. The server does not have the agent's `volume_class_map` or WMI context. If the server resolves a path differently than the agent, audit logs may show a different `volume_class` than what was enforced.
- **MEDIUM**: The integration test is listed under this plan but actually requires the hook DLL (Plan 03) and agent (Plan 02) to be functional. It should probably live in Plan 06.

**Suggestions**:
- Remove server-side path resolution for volume class; trust the agent-provided context. If `source_volume_class` or `destination_volume_class` is `None`, treat volume-class conditions as `false` (fail-closed) rather than guessing.
- Move the integration test to Plan 06 where the full stack is available.

---

### Plan 05: Admin TUI Conditions Builder (Wave 2)

**Summary**: Straightforward UI extension. The dropdown picker with six values and color-coded badges is well-specified. The round-trip support for `condition_to_prefill` and `condition_display` is critical for edit flows.

**Strengths**:
- `operators_for` returns `eq/ne/in` -- `in` allows future multi-select without UI changes
- Color-coded badges improve operator situational awareness
- Round-trip support preserves existing edit-flow invariants

**Concerns**:
- **LOW**: `ATTRIBUTES` array grows to 11. Ensure the array ordering matches the `ConditionAttribute` discriminant order to avoid off-by-one picker bugs.
- **LOW**: The `in` operator for volume class is semantically odd (a drive cannot be both Optical and USB), but harmless for consistency.

**Suggestions**:
- Add a unit test that verifies `ATTRIBUTES.len() == ConditionAttribute::VARIANT_COUNT` (or equivalent) to catch drift.
- Consider restricting volume class operators to `eq/ne` only since `in` is meaningless for mutually exclusive enums.

---

### Plan 06: End-to-end integration test + quality gate (Wave 3)

**Summary**: Appropriate final wave. The test-only injection helper is the right pattern for deterministic testing. The negative control and full workspace verification are necessary. However, the test depends on physical or virtual hardware that may not exist in all environments.

**Strengths**:
- `inject_volume_class_for_test` avoids environment-dependent test flakiness
- Negative control (LocalNTFS destination) proves the policy is specific, not blanket
- Full quality gate catches regressions

**Concerns**:
- **HIGH**: The integration test description says "blocks an actual CopyFileExW to a registered optical drive on the test endpoint." This implies a real optical drive or a mounted virtual ISO must be present. If the CI environment lacks these, the test will skip or fail. The test should use the injection helper to mock the volume class entirely, not require actual hardware.
- **MEDIUM**: The quality gate includes `sonar-scanner Quality Gate`. Ensure the `SONAR_TOKEN` environment variable is exported in CI, or this step will fail.

**Suggestions**:
- Rewrite the test to mock the volume class via `inject_volume_class_for_test` and verify the ABAC engine decision directly, without requiring an actual optical drive.
- Add `#[ignore]` to the hardware-dependent test and document the environment requirements in a comment.

---

### Cross-Plan Issues

**Dependency ordering**:
- Plan 02 renames/extends `UsbDetector`. Plan 03 queries it via named pipe. The named pipe protocol must be stable before Plan 03 can compile. Consider defining the query message type in `dlp-common` (Plan 01) so both sides agree.
- Plan 03 and Plan 04 both use `resolve_volume_class_from_path`. Ensure they share the same fallback semantics.

**Security -- Fail-Closed Semantics**:
- Plans 02, 03, and 04 all have classification fallbacks. They MUST agree on a single fail-closed behavior. I recommend: **classification failure -> `None` -> volume-class condition evaluates to `false` -> DENY if the policy requires a match**. Document this invariant explicitly in Plan 01's `VolumeClass` doc comment.

**Performance**:
- Plan 02's WMI queries in `handle_volume_event` run on the device-arrival thread. If WMI is slow, the 500ms deferred processing may not help if the WMI query itself blocks. Offload WMI to a `tokio::task::spawn_blocking` or a dedicated thread.

**Scope creep**:
- Plan 03 mentions "shared-memory cache" without specifying which crate creates it or how it is structured. If this is new infrastructure, it should be its own plan or explicitly added to Plan 02.

### Risk Assessment: **MEDIUM**

**Justification**:
- **HIGH-severity security concern**: The fallback to `LocalNTFS` for unclassifiable paths (especially volume GUIDs in Plan 03) creates a policy bypass vector for "DENY to Optical/Virtual/SDCard" policies. This must be changed to a fail-closed default before merge.
- **HIGH-severity test concern**: Plan 06's integration test requires physical/virtual hardware that may not exist in CI. Without mocking, this test will be flaky or skipped.
- **MEDIUM structural concern**: `UsbDetector` is now a misnomer; renaming it is low effort and prevents future confusion.
- **MEDIUM operational concern**: WMI failures are not handled explicitly in Plan 02.

The plans are well-structured and will achieve the phase goals once the fail-closed semantics and test mocking issues are resolved. The 3-wave breakdown is appropriate.

---

## Consensus Summary

### Agreed Strengths (all 3 reviewers)

- Clean wave-ordered layering (types -> agent -> hook -> server -> UI -> E2E test)
- Correct hybrid `GetDriveTypeW + WMI` approach for classification
- Optional `AbacContext` fields with `#[serde(default)]` preserve backward compatibility
- Thread-local cache in hook DLL is the right performance optimization
- Fail-closed on `None` in `volume_class_matches` is correct security posture
- Color-coded badges in admin TUI improve operator awareness

### Agreed Concerns (2+ reviewers)

| Concern | Severity | Reviewers | Plans |
|---------|----------|-----------|-------|
| **Fallback to `LocalNTFS` for unclassifiable paths is fail-open** | HIGH | Codex, OpenCode, Claude | 02, 03 |
| **WMI failure handling is underspecified** | HIGH | Codex, OpenCode, Claude | 02 |
| **Hook DLL cache TTL (30s) creates stale classification window** | HIGH | Codex, OpenCode, Claude | 03 |
| **Integration test requires physical hardware / non-hermetic** | HIGH | Codex, OpenCode, Claude | 06 |
| **Shared-memory IPC mentioned but not designed** | HIGH | Codex, Claude | 03 |
| **Server-side path resolution may mismatch agent classification** | MEDIUM | Codex, OpenCode, Claude | 04 |
| **Duplicate suppression mechanism vague** | MEDIUM | Codex, Claude | 02 |
| **No cache invalidation on device removal** | MEDIUM | Codex, OpenCode, Claude | 02, 03 |
| **`UsbDetector` name is now a misnomer** | MEDIUM | OpenCode, Claude | 02 |
| **`in` operator semantically odd for mutually exclusive enum** | LOW | Codex, Claude | 04, 05 |

### Divergent Views

- **OpenCode rates overall risk as MEDIUM-HIGH**; **Claude rates MEDIUM**. The difference is that Claude believes the issues are addressable within the existing plan structure, while OpenCode sees the multiple-classification-sources problem as more structurally risky.
- **Codex suggests adding `Unknown` variant** to `VolumeClass`; **Claude suggests keeping `Option<VolumeClass>`** with explicit `None` handling. Both achieve fail-closed; the choice is stylistic.
- **OpenCode advocates removing server-side path resolution entirely**; **Claude and Codex see it as acceptable defense-in-depth** with appropriate caveats.

### Recommended Actions Before Execution

1. **Change all classification fallbacks to fail-closed** (`None` or `Unknown` -> DENY), never `LocalNTFS`. This is the highest-priority security fix.
2. **Add explicit WMI failure fallback chain** in Plan 02 with tracing warnings and safe defaults.
3. **Reduce hook DLL cache TTL to 5-10s** and add invalidation on `DBT_DEVICEREMOVECOMPLETE` or a shared-memory generation counter.
4. **Make integration test hardware-independent** using mocked `volume_class_map` and `#[ignore]`-gated hardware tests.
5. **Document the named pipe query protocol** for hook-to-agent volume class queries in Plan 01 (shared types) or Plan 02.
6. **Consider renaming `UsbDetector` -> `VolumeDetector`** in Plan 02 to reflect expanded scope.
