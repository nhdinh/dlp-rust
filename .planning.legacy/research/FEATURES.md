# Feature Landscape: Application-Aware DLP (v0.8.0)

**Domain:** Enterprise Endpoint DLP — UWP App Identity, Drag-and-Drop Enforcement, Browser Origin Policies
**Researched:** 2026-05-06
**Research Mode:** Ecosystem

---

## Table Stakes

Features users expect from any enterprise DLP product with application-aware policy enforcement.

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| **UWP app identity resolution** | Enterprise apps increasingly ship via Microsoft Store / MSIX. UWP apps (Edge, Mail, Photos, Calculator) are common in modern Windows deployments. A DLP that cannot identify them is incomplete. | Medium | Requires AUMID resolution via `GetApplicationUserModelIdFromWindow`. UWP apps run inside host processes (`ApplicationFrameHost.exe`). |
| **Drag-and-drop blocking** | Users bypass clipboard blocks by dragging files/text between apps. Without drag-and-drop enforcement, clipboard policy is trivially bypassed. | High | OLE `IDropTarget` hooking is fundamentally different from clipboard monitoring. Must handle both Win32 and UWP drag sources. |
| **Browser origin-aware policies** | The browser is a single process containing both managed (SharePoint, Salesforce) and unmanaged (Gmail, ChatGPT) origins. Blocking ALL browser paste is too blunt; distinguishing by origin is required. | Medium | Extends existing Chrome Enterprise Connector (Phase 29). Requires `source_origin` + `destination_origin` ABAC attributes. |
| **Audit enrichment for all paths** | Compliance requires complete audit trails. If drag-and-drop or browser events lack app identity fields, the audit is incomplete. | Low | Reuse existing audit pipeline. Populate `source_application`, `destination_application`, `source_origin`, `destination_origin`. |
| **Admin TUI for origin management** | Admins need to manage the managed-origins list (trusted web domains). Already partially implemented in Phase 28; needs extension for origin-based policy authoring. | Low | Mirror existing managed-origins screen pattern. |

### Sources — Table Stakes
- [Microsoft Purview Endpoint DLP — Application Restrictions](https://techcommunity.microsoft.com/t5/security-compliance-and-identity/effectively-protect-sensitive-data-in-cloud-and-devices-using/ba-p/3733599)
- [Symantec DLP Endpoint — Application Monitoring](https://knowledge.broadcom.com/external/article/155346/)
- [Forcepoint DLP — Application Control](https://help.forcepoint.com/F1E/en-us/v20/ep_install/)
- [Digital Guardian — Application-Aware Policies](https://hstechdocs.helpsystems.com/)

---

## Differentiators

Features that set a product apart in enterprise evaluations.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| **Desktop Bridge AUMID support** | Desktop Bridge (Centennial) apps are Win32 apps packaged as MSIX. They have AUMIDs but run as normal processes. Detecting them bridges the gap between UWP and Win32 app identity. | Medium | `GetApplicationUserModelIdFromWindow` works for Desktop Bridge apps too, but the process image path may also be valid. Need dual-resolution. |
| **Drag-and-drop deduplication** | A single drag operation generates many `DragOver` + `Drop` events. Without deduplication, the user sees a flood of toast notifications and the audit log fills with duplicates. | Low-Medium | 5-second per-source-dest cooldown, similar to USB toast cooldown from Phase 27. |
| **Origin-specific policy rules** | Policies like "Allow paste from SharePoint to Jira, block paste from SharePoint to Gmail" require origin-level granularity in the conditions builder. | Medium | New ABAC attributes (`source_origin`, `destination_origin`) + new condition builder steps. |
| **Anti-spoofing for UWP AUMID** | AUMIDs are stable and non-forgeable (signed by Microsoft Store / enterprise cert). This is cheaper anti-spoofing than Authenticode hash verification. | Low | AUMID is derived from package family name, which is signed. No additional verification needed. |

---

## Anti-Features

Features to explicitly NOT build.

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| **Browser extension (Manifest V3)** | High engineering cost, store review delays, separate build toolchain (Node.js). Chrome Enterprise Connector already provides origin data. | Extend existing Chrome Enterprise Connector (Path B). Defer native extension (Path A) to v0.9.0+. |
| **Full OLE COM server for drag-and-drop** | Implementing a complete OLE `IDataObject` + `IDropSource` is overkill. We only need to intercept and evaluate, not initiate drag operations. | Hook existing `IDropTarget::Drop()` calls and evaluate before forwarding. |
| **Firefox / Safari origin support** | Outside Chromium ecosystem. Firefox has no equivalent to Chrome Enterprise Connector. Safari uses Apple's private APIs. | Document Chrome/Edge support only for v0.8.0. Evaluate Firefox in v0.9.0+. |
| **Granular per-tab origin in non-managed browsers** | Without Chrome Enterprise Connector or our extension, OS-level DLP cannot distinguish browser tabs. | Only support managed Chrome/Edge deployments for origin-aware policies. |
| **Drag-and-drop for non-file data** | Text drag-and-drop uses `CF_UNICODETEXT` (same as clipboard). File drag-and-drop uses `CF_HDROP`. Other formats (images, rich text) are niche. | Support text and file drag-and-drop only. Document other formats as best-effort. |

---

## Feature Dependencies

```
UWP AUMID Resolution (Phase 39)
    --> Drag-and-Drop Enforcement (Phase 40) — needs AppIdentity with AUMID for source/dest
    --> Audit Enrichment (Phase 42) — needs AppIdentity schema finalized

Chrome Origin Enrichment (Phase 41)
    --> Audit Enrichment (Phase 42) — needs origin fields in AuditEvent

Audit Enrichment (Phase 42)
    <-- UWP AUMID Resolution (needs AUMID field)
    <-- Drag-and-Drop (needs drag-drop alert type)
    <-- Chrome Origin (needs origin fields)
```

---

## MVP Recommendation

### Prioritize (v0.8.0 scope)

1. **UWP AUMID resolution** — Schema change first. All other phases depend on `AppIdentity` having an `aumid` field.
2. **Drag-and-drop interception** — Closes a known clipboard bypass. High security value.
3. **Chrome origin-aware policies** — Extends existing Phase 29 investment. Medium engineering cost.
4. **Audit enrichment sweep** — Ensures all new interception paths populate audit fields.

### Defer (v0.9.0+)

- **Native browser extension (Path A from SEED-002)** — Full Manifest V3 extension with forced-install policy.
- **Firefox/Safari support** — Different ecosystem, no Chrome Enterprise Connector equivalent.
- **Rich-text / image drag-and-drop** — Niche formats, high complexity.
- **Per-app grace period for drag-and-drop** — Operational convenience, not security-critical.

---

## Competitor Capability Matrix

| Capability | Microsoft Purview | Symantec DLP | Forcepoint DLP | Digital Guardian | DLP-RUST (Target) |
|------------|-------------------|--------------|----------------|------------------|-------------------|
| UWP app identification | Yes (via AUMID) | Limited | Limited | No | **Yes (v0.8.0)** |
| Drag-and-drop blocking | Yes | Yes | Yes | Yes | **Yes (v0.8.0)** |
| Browser origin policies | Yes (Purview + Edge) | Yes (via extension) | Yes (via extension) | Yes (via extension) | **Yes (Chrome Connector)** |
| Anti-spoofing (AUMID) | Yes | No | No | No | **Yes (v0.8.0)** |
| Chrome Enterprise Connector | N/A (native integration) | No | No | No | **Yes (v0.6.0+)** |

---

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Competitor capabilities | MEDIUM | Based on public documentation |
| UWP AUMID API | HIGH | Stable Win32 API |
| OLE drag-and-drop | MEDIUM-HIGH | Well-documented, but Rust COM implementation needs care |
| Chrome origin fields | MEDIUM | Depends on Chrome version; `destination_url` availability varies |
| Audit enrichment | HIGH | Reuses existing pipeline |

---

## Sources

- Microsoft Purview Endpoint DLP Documentation
- Symantec DLP Endpoint Application Monitoring
- Chrome Enterprise Connector Protocol Specification
- Microsoft Learn — Application User Model IDs
- Microsoft Learn — OLE Drag and Drop
