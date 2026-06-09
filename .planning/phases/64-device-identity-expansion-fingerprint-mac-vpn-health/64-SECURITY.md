---
phase: 64
slug: device-identity-expansion-fingerprint-mac-vpn-health
status: verified
threats_open: 0
asvs_level: 1
created: 2026-06-09
---

# Phase 64 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| Type system | Strong types prevent accidental mixing of health status with other enums | Typed enums across crate boundaries |
| Serde wire format | `#[serde(default)]` ensures old payloads deserialize without error | Heartbeat JSON, ABAC context |
| Ord ordering | Documented ordering (`Healthy < Degraded < Offline < Tampered`) prevents ambiguous ABAC comparisons | Policy evaluation |
| Windows API layer | Registry reads and network adapter enumeration | OS-level adapter metadata |
| Fingerprint computation | SHA-256 of stable hardware attributes | Fingerprint string |
| Registry storage | HKLM write requires admin; agent runs as SYSTEM | `HKLM\SOFTWARE\DLP\Agent` |
| Agent -> Server HTTP | Heartbeat payload crosses network; HTTPS encrypts in transit | Device identity JSON |
| Server DB | SQLite stores device identity; access controlled by pool | `agents` table rows |
| Server validation | MAC and fingerprint format validation before persistence | Validated strings |
| Validation alerting | Structured `tracing::warn!` on validation failure prevents silent trust boundary weakening | Log events |
| DB CHECK constraint | Enforces valid `health_status` values at the schema layer | `('healthy','degraded','offline','tampered')` |
| Agent health state | `AtomicU8` prevents race conditions across tamper/connectivity detection paths | Health status ordinal |
| ABAC evaluation | `DeviceHealth` condition is one signal among many; never sole decision factor | Policy decision input |
| Audit log | Health transitions are append-only audit events with prev/new state | `AuditEvent` records |
| Registry persistence | Health status survives agent restart | `HKLM\SOFTWARE\DLP\Agent\health_status` |
| Async safety | `spawn_blocking` prevents registry I/O from blocking the Tokio reactor | Registry write offload |

---

## Threat Register

| Threat ID | Category | Component | Disposition | Mitigation | Status |
|-----------|----------|-----------|-------------|------------|--------|
| T-64-01 | Spoofing | Health status in heartbeat | mitigate | Agent-computed; server validates formats and stores with CHECK constraint; not sole ABAC decision factor | closed |
| T-64-02 | Information Disclosure | MAC addresses in JSON payload | accept | MACs are already broadcast on local network; HTTPS encrypts the payload | closed |
| T-64-SC | Tampering | npm/pip/cargo installs | mitigate | No new external packages required; all functionality uses existing workspace dependencies (`sha2`, `serde`, `windows` already present) | closed |
| T-64-03 | Spoofing | MAC spoofing changes fingerprint | accept | Fingerprint change is a signal, not a vulnerability; approval tokens bind to fingerprint | closed |
| T-64-04 | Information Disclosure | Registry reads expose OS info | accept | OS version is not sensitive data | closed |
| T-64-05 | Denial of Service | Registry read failure blocks fingerprint | mitigate | Best-effort with safe fallback; if registry read fails, compute on-the-fly (`read_fingerprint_from_registry().unwrap_or_else(|| compute_fingerprint(...))`) | closed |
| T-64-06 | Tampering | Fingerprint registry value modified | mitigate | HKLM requires admin; agent runs as SYSTEM and writes to `HKLM\SOFTWARE\DLP\Agent` | closed |
| T-64-07 | Elevation of Privilege | VPN keyword heuristic false negatives | accept | VPN detection is heuristic (documented limitation in `VPN_KEYWORDS`); defense-in-depth with IP subnet check from existing `get_network_location()` | closed |
| T-64-08 | Information Disclosure | MAC addresses stored in SQLite | accept | MACs are not secrets; DB is server-local | closed |
| T-64-09 | Denial of Service | Large `mac_addresses` JSON floods DB | mitigate | MAC list is bounded by physical NIC count (typically < 20); server rejects > 32 MACs in `validate_device_identity()` | closed |
| T-64-10 | Elevation of Privilege | Agent sends arbitrary `health_status` | mitigate | Health status is agent-reported telemetry; policy decisions use it as one signal among many; DB CHECK constraint prevents invalid values | closed |
| T-64-11 | Spoofing | Agent sends malformed MAC/fingerprint | mitigate | Server-side validation rejects invalid formats with structured `tracing::warn!`; graceful degradation to defaults | closed |
| T-64-12 | Denial of Service | Rapid health transitions flood audit log | mitigate | Atomic swap prevents spurious transitions; `emit_health_change_audit_event()` only emits when `prev_u8 != new_u8` | closed |
| T-64-13 | Elevation of Privilege | Agent reports Healthy after tamper | mitigate | Tamper detection paths call `report_tamper_detected()` which sets Tampered; recovery to Healthy requires successful heartbeat | closed |
| T-64-14 | Repudiation | Health transition not audited | mitigate | Every transition emits `AuditEvent` with `EventType::DeviceHealthChange` via `emit_health_change_audit_event()` | closed |
| T-64-15 | Information Disclosure | Health status in registry | accept | Health status is not sensitive; HKLM access requires admin | closed |
| T-64-16 | Denial of Service | Registry write blocks heartbeat loop | mitigate | Async wrapper `transition_health_async()` uses `tokio::task::spawn_blocking(persist_health_to_registry)` | closed |

*Status: open / closed*
*Disposition: mitigate (implementation required) / accept (documented risk) / transfer (third-party)*

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| R-64-01 | T-64-02 | MACs are already broadcast on local network; HTTPS encrypts payload | gsd-security-auditor | 2026-06-09 |
| R-64-02 | T-64-03 | Fingerprint change is a signal, not a vulnerability; approval tokens bind to fingerprint | gsd-security-auditor | 2026-06-09 |
| R-64-03 | T-64-04 | OS version is not sensitive data | gsd-security-auditor | 2026-06-09 |
| R-64-04 | T-64-07 | VPN detection is heuristic (documented limitation); defense-in-depth with IP subnet check | gsd-security-auditor | 2026-06-09 |
| R-64-05 | T-64-08 | MACs are not secrets; DB is server-local | gsd-security-auditor | 2026-06-09 |
| R-64-06 | T-64-11 (Plan 04) | Health status is telemetry, not a security boundary; ABAC uses it as one condition among many | gsd-security-auditor | 2026-06-09 |
| R-64-07 | T-64-15 | Health status is not sensitive; HKLM access requires admin | gsd-security-auditor | 2026-06-09 |

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-06-09 | 16 | 16 | 0 | gsd-security-auditor |

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-06-09
