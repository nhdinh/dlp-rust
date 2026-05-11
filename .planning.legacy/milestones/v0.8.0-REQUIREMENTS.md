# Requirements: DLP-RUST

**Defined:** 2026-05-06
**Milestone:** v0.8.0 Application-Aware DLP
**Core Value:** Prevent data exfiltration via a layered enforcement stack (NTFS + ABAC + AD identity)

---

## v0.8.0 Requirements

### Application Identity

- [x] **APP-07**: Agent resolves UWP process identity to AUMID using `GetApplicationUserModelIdFromWindow` or equivalent Win32 API
- [x] **APP-07.1**: AUMID is captured as a first-class `source_application` / `destination_application` attribute alongside existing Win32 process identity
- [x] **APP-07.2**: UWP identity flows through the same ABAC evaluator without special-casing
- [x] **APP-07.3**: Admin can author policies using AUMID conditions in the TUI conditions builder

### Interception

- [x] **APP-08**: Agent intercepts OLE drag-and-drop operations (`IDropTarget`, `DoDragDrop` hooks) to identify source application
- [x] **APP-08.1**: Source application identity is resolved for both Win32 and UWP drag sources
- [x] **APP-08.2**: ABAC policy is evaluated before drop completes; denied drops are blocked with a toast notification
- [x] **APP-08.3**: Audit events include `source_application`, `destination_application`, and action fields for drag-and-drop blocks

### Browser

- [x] **BRW-04**: Chrome Enterprise Connector messages include tab origin (URL / domain) for clipboard read/write operations
- [x] **BRW-04.1**: ABAC evaluator supports `source_origin` and `destination_origin` as condition attributes
- [x] **BRW-04.2**: Admin can author policies that allow/deny clipboard operations based on managed-origins list and specific URL patterns
- [x] **BRW-04.3**: Paste from protected origin to unmanaged origin is blocked and audited with origin fields populated

### Audit

- [x] **AUDIT-04**: All audit events from file interception include `source_application` and `destination_application` fields where applicable
- [x] **AUDIT-04.1**: All audit events from USB interception include device identity fields (VID, PID, serial, description)
- [x] **AUDIT-04.2**: All audit events from clipboard interception include both source and destination application identity
- [x] **AUDIT-04.3**: All audit events from drag-and-drop interception include source and destination application identity
- [x] **AUDIT-04.4**: All audit events from browser interception include `source_origin` and `destination_origin` fields
- [x] **AUDIT-04.5**: Audit schema guarantees non-null app identity fields; missing identity is flagged as `AGENT-UNKNOWN` with remediation path

---

## v2 Requirements (Deferred)

### Browser Extension

- **BRW-05**: Native Chrome/Edge Manifest V3 extension for tab-level origin control (Path A from SEED-002)
- **BRW-06**: Firefox WebExtensions support for origin-aware policies

### Application Identity

- **APP-09**: Electron app detection and publisher verification (all Electron apps look like `electron.exe`)
- **APP-10**: Print and save-as enforcement (file-monitor integration for app-aware path restrictions)

---

## Out of Scope

| Feature | Reason |
|---------|--------|
| Native browser extension (Manifest V3) | High engineering cost, store review delays. Chrome Enterprise Connector (Path B) sufficient for v0.8.0. Path A deferred to v0.9.0+ per SEED-002. |
| Firefox / Safari origin support | No Chrome Enterprise Connector equivalent. Different ecosystem entirely. |
| Rich-text / image drag-and-drop | Niche formats, high complexity. Text and file drag-and-drop cover the exfiltration threat. |
| Per-app grace period for drag-and-drop | Operational convenience, not security-critical. |
| Electron app specific detection | Requires maintaining publisher allowlist. All Electron apps resolve as `electron.exe` today. |

---

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| APP-07 | Phase 39 | Complete |
| APP-07.1 | Phase 39 | Complete |
| APP-07.2 | Phase 39 | Complete |
| APP-07.3 | Phase 39 | Complete |
| APP-08 | Phase 40 | Complete |
| APP-08.1 | Phase 40 | Complete |
| APP-08.2 | Phase 40 | Complete |
| APP-08.3 | Phase 40 | Complete |
| BRW-04 | Phase 41 | Complete |
| BRW-04.1 | Phase 41 | Complete |
| BRW-04.2 | Phase 41 | Complete |
| BRW-04.3 | Phase 41 | Complete |
| AUDIT-04 | Phase 42 | Complete |
| AUDIT-04.1 | Phase 42 | Complete |
| AUDIT-04.2 | Phase 42 | Complete |
| AUDIT-04.3 | Phase 42 | Complete |
| AUDIT-04.4 | Phase 42 | Complete |
| AUDIT-04.5 | Phase 42 | Complete |

**Coverage:**
- v0.8.0 requirements: 18 total
- Mapped to phases: 18
- Unmapped: 0

---
*Requirements defined: 2026-05-06*
*Last updated: 2026-05-07 after milestone v0.8.0 audit*
