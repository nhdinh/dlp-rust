# Phase 64: Device Identity Expansion — Fingerprint + MAC + VPN + Health

**Gathered:** 2026-06-06
**Status:** Ready for planning
**Mode:** Auto-generated (discuss skipped via workflow.skip_discuss)

<domain>
## Phase Boundary

Expand the agent's device identity collection to support full pilot requirements. The target architecture requires device fingerprint, MAC addresses, VPN state, domain state, and health status for every endpoint. Current DeviceIdentity only has hostname. This data is needed for ABAC evaluation, audit events, and pilot acceptance criteria.

**Requirements:** DEVICE-01, DEVICE-02, DEVICE-03, DEVICE-04, DEVICE-05

**Success Criteria:**
1. Device fingerprint hash computed at install and stored in registry (DEVICE-01)
2. All active NIC MACs collected and sent with heartbeat (DEVICE-02)
3. VPN state detected at runtime and reflected in ABAC context (DEVICE-03)
4. Domain state included in agent heartbeat (DEVICE-04)
5. Health status transitions on tamper detection or connectivity loss (DEVICE-05)
6. All new code passes clippy, tests, and sonar-scanner

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion
All implementation choices are at Claude's discretion — discuss phase was skipped per user setting. Use ROADMAP phase goal, success criteria, and codebase conventions to guide decisions.

Key design points:
- Fingerprint = SHA-256 of hostname + MACs + OS version + install date (deterministic, stable)
- MAC collection via `GetAdaptersAddresses` (Windows API, covers IPv4/IPv6)
- VPN detection via WMI `Win32_NetworkAdapter` + `GetAdaptersAddresses` (look for TAP/Virtual adapters)
- Domain state via `NetGetJoinInformation` (Windows API)
- Health status enum: Healthy, Degraded, Offline, Tampered
- All data flows through existing heartbeat mechanism

</decisions>

<code_context>
## Existing Code Insights

Codebase context will be gathered during plan-phase research.

Key existing types to extend:
- `DeviceIdentity` in dlp-common (currently has hostname only)
- Heartbeat emission in dlp-agent
- ABAC context construction

</code_context>

<specifics>
## Specific Ideas

- Extend `DeviceIdentity` struct with fingerprint, mac_addresses, vpn_state, domain_joined, health_status
- Add `NetworkLocation::CorporateVpn` variant for VPN state
- Add `DeviceHealthStatus` enum
- Update agent heartbeat to populate all fields
- Update ABAC environment evaluation to include device health

</specifics>

<deferred>
## Deferred Ideas

None — discuss phase skipped.
</deferred>
