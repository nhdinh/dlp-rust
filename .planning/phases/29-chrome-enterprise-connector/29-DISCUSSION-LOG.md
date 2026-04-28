# Phase 29: Chrome Enterprise Connector - Discussion Log

**Date:** 2026-04-29
**Participants:** Hung Dinh (user), Claude (assistant)

---

## Discussion Summary

User ran `/gsd-discuss-phase 29` and selected all 4 gray areas. User requested recommended options for all areas rather than discussing each individually.

### Area 1: Protobuf Protocol
- **Options presented:** A) `prost` with full official `.proto`, B) Hand-rolled frame parser, C) `prost` with minimal vendored `.proto`
- **User choice:** "pick recommended options for me"
- **Recommendation (accepted):** Option C — minimal `prost` with vendored `content_analysis.proto` containing only Request, Response, and Action messages
- **Rationale:** Type-safe, maintainable, consistent with codebase's approach of adding deps when they solve problems cleanly

### Area 2: Decision Logic
- **Options presented:** Poll + local cache, Server evaluate per-paste, Hybrid
- **Recommendation (accepted):** Poll + local cache, mirroring Phase 24's `DeviceRegistryCache` pattern
- **Rationale:** Avoids HTTPS round-trip on every paste, reuses proven pattern, keeps decisions local

### Area 3: HKLM Registration
- **Options presented:** Self-registration at startup, Installer-time, CLI flag
- **Recommendation (accepted):** Self-registration at service startup with `DLP_SKIP_CHROME_REG=1` test override
- **Rationale:** Operationally simplest, consistent with Phase 30 env-var testability pattern

### Area 4: Audit Event Fields
- **Options presented:** New Option<String> fields, Reuse resource_path, New EventType variant
- **Recommendation (accepted):** Two new `Option<String>` fields (`source_origin`, `destination_origin`) on `AuditEvent`
- **Rationale:** Mirrors Phase 22 optional-field pattern, no new EventType needed

---

## Decisions Locked

| ID | Area | Decision |
|----|------|----------|
| D-01 | Protobuf | `prost` with minimal vendored `.proto` (Request/Response/Action only) |
| D-02 | Decision logic | Poll + `ManagedOriginsCache` (mirrors `DeviceRegistryCache`) |
| D-03 | HKLM registration | Self-registration at startup; `DLP_SKIP_CHROME_REG=1` test override |
| D-04 | Audit fields | New `source_origin` + `destination_origin` `Option<String>` fields |
| D-05 | Pipe architecture | 4th dedicated IPC thread in new `chrome` module (not mixed with P1/P2/P3) |
| D-06 | Request handling | Normalize URLs to origins, cache lookup, construct protobuf response |

## Claude's Discretion Items

- `prost-build` vs `tonic` configuration (recommend `prost-build` only)
- Origin string normalization (trailing slash handling)
- Exact HKLM registry key path
- Wildcard pattern support (deferred — exact match only)
- Malformed protobuf frame error handling strategy

## Deferred Ideas

- Wildcard origin matching (`*.sharepoint.com`)
- Edge for Business / Microsoft Purview integration
- Native Chrome extension (Manifest V3)
- Per-tab origin tracking
- Chrome Enterprise policy via GPO

---

*Phase: 29-chrome-enterprise-connector*
*Discussion completed: 2026-04-29*
