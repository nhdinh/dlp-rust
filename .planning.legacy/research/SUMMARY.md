# Project Research Summary

**Project:** DLP-RUST v0.8.0 Application-Aware DLP
**Domain:** UWP App Identity, OLE Drag-and-Drop Enforcement, Browser Origin Clipboard Policies
**Researched:** 2026-05-06
**Confidence:** HIGH

---

## Executive Summary

v0.8.0 extends the application-aware DLP foundation shipped in v0.6.0 (APP-01..06) with three new capabilities: UWP app identity via AUMID (Phase 39), OLE drag-and-drop enforcement (Phase 40), and browser origin-aware clipboard policies via Chrome Enterprise Connector (Phase 41). A final audit enrichment phase (Phase 42) ensures all interception paths populate app identity and origin fields correctly.

**Zero new external crates required.** All APIs are available in the existing `windows` 0.62 crate (`GetApplicationUserModelIdFromWindow`, `IDropTarget`, `RegisterDragDrop`) or are protobuf schema extensions in the existing `prost` pipeline.

**Key dependency:** Phase 39 must ship first because it adds `aumid: Option<String>` to the shared `AppIdentity` struct in `dlp-common`. Phases 40 and 42 both consume this schema change. Phases 40 and 41 are independent of each other.

---

## Key Findings

### Recommended Stack

No dependency delta. All work reuses existing infrastructure:
- `windows` 0.62 — AUMID resolution (`Win32::UI::Shell`) and OLE drag-and-drop (`Win32::System::Ole`)
- `prost` — Chrome Content Analysis protobuf schema extension for origin fields
- Existing ABAC evaluator, audit pipeline, admin TUI patterns

### Expected Features

**Must have (table stakes):**
- UWP AUMID resolution — Store apps and Desktop Bridge apps are common in enterprise Windows
- Drag-and-drop blocking — closes known clipboard bypass vector
- Browser origin policies — distinguishes managed/unmanaged origins inside Chrome
- Audit enrichment — all interception paths populate identity and origin fields

**Should have (competitive):**
- Desktop Bridge AUMID support — bridges UWP and Win32 app identity
- Drag-and-drop deduplication — prevents notification flood
- Origin-specific policy rules in conditions builder

**Defer (v0.9.0+):**
- Native browser extension (Manifest V3) — high cost, store review delays
- Firefox/Safari origin support — different ecosystem
- Rich-text/image drag-and-drop — niche formats

### Architecture Approach

All three features are **extensions of existing subsystems**, not new architectural layers:

1. **UWP AUMID (Phase 39):** Extend `AppIdentity` with `aumid` field. Add `AppField::Aumid` to ABAC evaluator. Add AUMID to admin CLI conditions builder. AUMID resolution is a fallback in `resolve_app_identity` when the process image path is a UWP host.

2. **Drag-and-Drop (Phase 40):** New `DragDropEnforcer` in `dlp-agent/src/interception/drag_drop.rs`. Hooks `IDropTarget::Drop()` or global message hook for `WM_DROPFILES`. Evaluates ABAC before allowing drop. New `Pipe3AgentMsg::DragDropAlert` variant. Integrated into `run_event_loop` as a pre-ABAC check.

3. **Browser Origin (Phase 41):** Extend existing Chrome connector dispatch to extract `source_url`/`destination_url` from Content Analysis requests. Add `source_origin`/`destination_origin` to `AbacContext` and `AuditEvent`. Add `Attribute::SourceOrigin`/`DestinationOrigin` to policy evaluator.

4. **Audit Enrichment (Phase 42):** Validation sweep across all interception paths (file, USB, clipboard, drag-drop, browser) to ensure app identity and origin fields are populated. Update audit schema guarantees.

### Critical Pitfalls

1. **UWP apps resolve as "Unknown" without AUMID path** — `ApplicationFrameHost.exe` masks real app identity. Prevention: add `aumid` to `AppIdentity`, implement `GetApplicationUserModelIdFromWindow` fallback.

2. **AUMID schema change breaks backward compatibility** — serde deserialization of old `AppIdentity` without `aumid` field fails. Prevention: `#[serde(default)]` on new field.

3. **OLE drag-and-drop blocks Explorer thread** — returning `DROPEFFECT_NONE` from `IDropTarget::Drop` on the wrong thread hangs Explorer. Prevention: evaluate on background thread, return `DROPEFFECT_COPY` immediately if evaluation is async.

4. **Chrome destination origin unavailable** — older Chrome versions don't send `destination_url` in Content Analysis requests. Prevention: version-aware fallback (block if origin cannot be determined for sensitive data).

5. **AppField enum changes require 7+ coordinated updates** — Rust compiler catches misses, but admin CLI has many match sites. Prevention: update all sites in a single commit.

---

## Implications for Roadmap

### Recommended Phase Ordering

1. **Phase 39: UWP App Identity** — Schema change must come first. All subsequent phases depend on it.
2. **Phase 40: Drag-and-Drop Enforcement** — Depends on Phase 39 `AppIdentity` schema. High security value (closes clipboard bypass).
3. **Phase 41: Browser Origin Policies** — Extends Chrome connector. Independent of Phase 40 but depends on Phase 39.
4. **Phase 42: Audit Enrichment** — Final validation sweep. Must be last.

### Phase Ordering Rationale

- Phase 39 must be first because `AppIdentity` is central to all app-aware features.
- Phases 40 and 41 are independent — can parallelize if team size permits.
- Phase 42 is a validation/cleanup phase and must be last.

### Research Flags

- Phase 39: Needs verification of `GetApplicationUserModelIdFromWindow` behavior with Desktop Bridge apps.
- Phase 40: Needs research on `IDropTarget` vtable construction in `windows-rs` and thread safety.
- Phase 41: Needs verification of minimum Chrome version supporting `destination_url`.
- Phase 42: Standard pattern — audit schema validation is well-understood from AUDIT-05.

---

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | Zero new crates; all APIs in existing `windows` 0.62 |
| Features | HIGH | Requirements (APP-07, APP-08, BRW-04, AUDIT-04) are clear |
| Architecture | HIGH | All patterns are extensions of existing proven subsystems |
| Pitfalls | HIGH | Deep codebase knowledge + Win32 API patterns + Chrome SDK review |

**Overall confidence:** HIGH

---

## Gaps to Address

- **Desktop Bridge AUMID behavior:** Do Desktop Bridge apps return AUMID via `GetApplicationUserModelIdFromWindow` or require token-based resolution? Needs runtime testing.
- **Chrome destination origin version:** What is the minimum Chrome Enterprise version that sends `destination_url`? Affects fallback strategy.
- **`IDropTarget` Rust vtable:** The `windows-rs` `implement` macro for custom COM interfaces needs verification for `IDropTarget` specifically.
- **Drag-and-drop deduplication granularity:** Is 5-second cooldown sufficient? Should key include `source_pid + dest_pid` or just `content_hash`?

---

## Sources

### Primary (HIGH confidence)
- `dlp-common/src/endpoint.rs` — existing `AppIdentity`, `DeviceIdentity`
- `dlp-common/src/abac.rs` — existing `AbacContext`, `Attribute`, `AppField`
- `dlp-common/src/audit.rs` — existing `AuditEvent`
- `dlp-agent/src/detection/app_identity.rs` — existing process identity resolution
- `dlp-agent/src/chrome/` — existing Chrome Enterprise Connector (Phase 29)
- `dlp-agent/src/interception/mod.rs` — existing event loop with pre-ABAC checks
- Microsoft Learn — `GetApplicationUserModelIdFromWindow`, Application User Model IDs
- Microsoft Learn — `IDropTarget`, `RegisterDragDrop`, OLE Drag and Drop
- Chrome Enterprise Connector Protocol Specification

### Secondary (MEDIUM confidence)
- Competitor documentation (Microsoft Purview, Symantec, Forcepoint) — capability matrix
- `windows-rs` COM `implement` macro documentation — `IDropTarget` specifics

---
*Research completed: 2026-05-06*
*Ready for roadmap: yes*
