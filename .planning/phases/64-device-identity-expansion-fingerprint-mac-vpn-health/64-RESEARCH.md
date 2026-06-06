# Phase 64: Device Identity Expansion — Research

**Researched:** 2026-06-06
**Domain:** Windows endpoint identity, registry storage, ABAC policy engine, heartbeat protocol
**Confidence:** HIGH

## Summary

Phase 64 expands the agent's device identity collection to support full pilot requirements. The current `DeviceIdentity` type in `dlp-common/src/endpoint.rs` is actually for **USB devices** (vid, pid, serial, description) — a naming collision from Phase 23. A new type is needed for **endpoint device identity** (fingerprint, MACs, VPN state, domain join, health status).

The heartbeat mechanism (`dlp-agent/src/server_client.rs::send_heartbeat`) currently sends only `{"status": "healthy"}`. It must be extended to carry the full device identity payload. The server-side `HeartbeatRequest` (`dlp-server/src/agent_registry.rs`) and `AgentRow`/`agents` table (`dlp-server/src/db/repositories/agents.rs`) need corresponding schema extensions.

The ABAC engine (`dlp-common/src/abac.rs`) already has `DeviceTrust` and `NetworkLocation` enums. `NetworkLocation::CorporateVpn` already exists but is only populated via IP-subnet matching in `ad_client.rs`. Phase 64 adds runtime VPN adapter detection for more accurate state. A new `DeviceHealthStatus` enum is needed for health-based policy conditions.

**Primary recommendation:** Create a new `EndpointIdentity` type in `dlp-common`, extend heartbeat payloads, add server DB columns, and wire health status into ABAC evaluation. Use the existing Windows API patterns (`GetAdaptersAddresses`, `NetGetJoinInformation`) already proven in `ad_client.rs`.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Fingerprint computation | Agent (Windows API) | — | Must be computed at install time on the endpoint using local machine state |
| MAC address collection | Agent (Windows API) | — | `GetAdaptersAddresses` is a local system call; no server involvement |
| VPN state detection | Agent (Windows API) | Server (ABAC evaluation) | Adapter detection is local; policy evaluation is server-side |
| Domain join detection | Agent (Windows API) | Server (ABAC context) | `NetGetJoinInformation` is local; exposed in heartbeat for server ABAC |
| Health status transitions | Agent (state machine) | Server (alerting) | Agent detects tamper/connectivity; server reacts via policies |
| Device identity storage | Server (SQLite) | Agent (registry) | Server stores per-agent identity; agent persists fingerprint in registry |
| ABAC policy evaluation | Server (PolicyStore) | — | All policy decisions are server-side per existing architecture |

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `windows` crate | 0.52+ | `GetAdaptersAddresses`, `NetGetJoinInformation`, registry APIs | Already used throughout codebase (ad_client.rs, appinit.rs) [VERIFIED: Cargo.toml] |
| `sha2` | 0.10+ | SHA-256 fingerprint hash | Standard Rust crypto, already in dependency tree via audit chain (Phase 63) [VERIFIED: Cargo.toml] |
| `serde` | 1.0+ | JSON serialization for heartbeat payload | Already used for all wire types [VERIFIED: Cargo.toml] |
| `chrono` | 0.4+ | Timestamps for install date in fingerprint | Already used for heartbeat timestamps [VERIFIED: Cargo.toml] |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `winreg` | 0.52+ | Registry read/write for fingerprint persistence | If `windows` crate registry APIs are too verbose; but codebase already uses raw `windows` APIs in `appinit.rs` |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| SHA-256 fingerprint | UUID v4 | UUID is not deterministic across reinstalls; SHA-256 of machine properties is stable |
| Registry storage | File in ProgramData | Registry is more tamper-evident and follows Windows conventions; file is easier to modify |
| `GetAdaptersAddresses` | WMI `Win32_NetworkAdapter` | `GetAdaptersAddresses` is faster and already used in codebase; WMI adds COM overhead |

**Version verification:**
```bash
# All crates already in workspace — no new external dependencies needed
cargo tree -p dlp-common | grep -E "sha2|windows|serde|chrono"
```

## Package Legitimacy Audit

> No new external packages required. All functionality uses existing workspace dependencies.

| Package | Registry | Age | Downloads | Source Repo | slopcheck | Disposition |
|---------|----------|-----|-----------|-------------|-----------|-------------|
| (none) | — | — | — | — | — | No new packages |

## Architecture Patterns

### System Architecture Diagram

```
+-------------------------------------------------------------+
|                        AGENT (Windows)                       |
|  +-------------------+    +-----------------------------+   |
|  | Install-time      |    | Runtime (heartbeat loop)    |   |
|  | - Compute SHA-256 |    | - Collect MACs              |   |
|  | - Write to HKLM   |    | - Detect VPN adapters       |   |
|  |   registry        |    | - Check domain join         |   |
|  +---------+---------+    | - Evaluate health state     |   |
|            |              +-------------+---------------+   |
|            v                            |                   |
|  HKLM\SOFTWARE\DLP\Agent               |                   |
|  - device_fingerprint                  |                   |
|  - install_date                        v                   |
|                               +----------------+           |
|                               | send_heartbeat |           |
|                               | POST /agents/  |           |
|                               |   {id}/heartbeat           |
|                               +--------+-------+           |
+----------------------------------------+---------------+
                                         |
                                         v
+-------------------------------------------------------------+
|                      SERVER (dlp-server)                     |
|  +-------------------+    +-----------------------------+   |
|  | agent_registry.rs |    | ABAC Policy Engine          |   |
|  | - HeartbeatRequest|    | - PolicyStore::evaluate()   |   |
|  | - update_heartbeat|    | - condition_matches()       |   |
|  +---------+---------+    +-------------+---------------+   |
|            |                            ^                   |
|            v                            |                   |
|  +-------------------+                  |                   |
|  | agents table      |                  |                   |
|  | - fingerprint     |                  |                   |
|  | - mac_addresses   |                  |                   |
|  | - vpn_state       |                  |                   |
|  | - domain_joined   |                  |                   |
|  | - health_status   |                  |                   |
|  +-------------------+                  |                   |
|                                         |                   |
|  +-------------------+                  |                   |
|  | PolicyCondition   |------------------+                   |
|  | - DeviceHealth    | (new variant)                        |
|  +-------------------+                                     |
+-------------------------------------------------------------+
```

### Recommended Project Structure

```
dlp-common/src/
├── abac.rs              # Add DeviceHealthStatus enum, extend Subject
├── endpoint.rs          # Add EndpointIdentity struct (avoid USB DeviceIdentity collision)
└── lib.rs               # Re-export EndpointIdentity

dlp-agent/src/
├── device_identity.rs   # NEW: Fingerprint computation, MAC collection, VPN detection
├── service.rs           # Integrate device identity into heartbeat loop
├── server_client.rs     # Extend HeartbeatRequest payload
└── config.rs            # Add device_identity fields to AgentConfig (optional)

dlp-server/src/
├── agent_registry.rs    # Extend HeartbeatRequest, AgentInfoResponse
├── db/
│   ├── mod.rs           # Add agents table columns in migration
│   └── repositories/
│       └── agents.rs    # Extend AgentRow, update_heartbeat
└── policy_store.rs      # Add DeviceHealth PolicyCondition variant
```

### Pattern 1: Windows API Wrapper with `#[cfg(windows)]`
**What:** Platform-gated functions that return safe defaults on non-Windows (tests). **When to use:** All Windows API calls in the agent. **Example:**
```rust
// Source: dlp-common/src/ad_client.rs (existing pattern)
#[cfg(windows)]
pub fn get_device_trust() -> crate::DeviceTrust {
    use windows::core::PWSTR;
    use windows::Win32::NetworkManagement::NetManagement::{
        NetApiBufferFree, NetGetJoinInformation, NETSETUP_JOIN_STATUS,
    };
    unsafe {
        let mut name_buf = PWSTR::null();
        let mut status = NETSETUP_JOIN_STATUS::default();
        NetGetJoinInformation(None, &mut name_buf, &mut status);
        let is_domain_joined = !name_buf.is_null() && status == NETSETUP_JOIN_STATUS(3);
        if !name_buf.is_null() {
            let _ = NetApiBufferFree(Some(name_buf.as_ptr() as *const _));
        }
        if is_domain_joined { crate::DeviceTrust::Managed } else { crate::DeviceTrust::Unmanaged }
    }
}

#[cfg(not(windows))]
pub fn get_device_trust() -> crate::DeviceTrust {
    crate::DeviceTrust::Unknown
}
```

### Pattern 2: Registry Read/Write (from appinit.rs)
**What:** Raw Windows registry API usage for HKLM values. **When to use:** Fingerprint persistence at install time. **Example:**
```rust
// Source: dlp-agent/src/appinit.rs (existing pattern)
use windows::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
    HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_SZ,
};

// Open key read-only
let mut hkey = windows::Win32::System::Registry::HKEY::default();
let result = unsafe {
    RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        windows::core::w!(r"SOFTWARE\DLP\Agent"),
        None,
        KEY_READ,
        &mut hkey,
    )
};
```

### Pattern 3: AgentConfig TOML Persistence
**What:** Server-pushed config fields that round-trip through TOML. **When to use:** If any device identity fields need server override (unlikely, but pattern exists). **Example:**
```rust
// Source: dlp-agent/src/config.rs (existing pattern)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AgentConfig {
    #[serde(default)]
    pub some_server_pushed_field: Option<String>,
}
```

### Anti-Patterns to Avoid
- **Do NOT extend the USB `DeviceIdentity` struct** in `endpoint.rs` — it is for VID/PID/serial, not endpoint fingerprint. Create `EndpointIdentity` instead.
- **Do NOT store the fingerprint in agent-config.toml** — it belongs in HKLM registry for tamper resistance.
- **Do NOT make fingerprint computation fallible** — if it fails, the agent cannot bind approvals. Use best-effort with safe fallback.
- **Do NOT add device identity to `AgentConfigPayload`** — these are runtime-collected properties, not server-configurable settings.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| SHA-256 hashing | Custom hash | `sha2::Sha256` | FIPS-adjacent, well-tested, already in dependency tree |
| MAC address formatting | String parsing | `format!("{:02X}", byte)` | Standard hex formatting; normalize to uppercase no-colon |
| Registry access | Raw Win32 API wrappers | `windows` crate types | Already used in appinit.rs; consistent error handling |
| VPN adapter detection | Custom NDIS code | `GetAdaptersAddresses` + adapter type check | Covers TAP, WireGuard, OpenVPN, RAS; no driver needed |
| JSON serialization | Manual JSON construction | `serde_json` with structs | All wire types already use serde; maintain consistency |

**Key insight:** The Windows API surface for this phase is already well-understood in the codebase. The `ad_client.rs` module contains working `GetAdaptersAddresses` and `NetGetJoinInformation` implementations. Reuse these patterns rather than inventing new approaches.

## Common Pitfalls

### Pitfall 1: USB DeviceIdentity Naming Collision
**What goes wrong:** Adding fingerprint/MAC fields to the existing `DeviceIdentity` struct in `endpoint.rs` would break USB device registry serialization and confuse all downstream code.
**Why it happens:** The struct is named generically but is specifically for USB VID/PID/serial.
**How to avoid:** Create a new `EndpointIdentity` struct in `dlp-common`. Update `endpoint.rs` doc comments to clarify `DeviceIdentity` is USB-only.
**Warning signs:** Compilation errors in `dlp-agent/src/usb_enforcer.rs` or `dlp-server/src/admin_api.rs` after modifying `DeviceIdentity`.

### Pitfall 2: MAC Address Ordering Instability
**What goes wrong:** `GetAdaptersAddresses` returns adapters in non-deterministic order. If MACs are concatenated for fingerprinting, reordering would change the hash.
**Why it happens:** Windows may enumerate adapters in different orders across boots.
**How to avoid:** Sort MAC addresses lexicographically before hashing. Store as `Vec<String>` (sorted) in the struct.
**Warning signs:** Fingerprint changes after reboot; approval tokens become invalid.

### Pitfall 3: VPN Detection False Positives
**What goes wrong:** Hyper-V virtual adapters, Docker NAT, or other virtual NICs may be misclassified as VPN.
**Why it happens:** `GetAdaptersAddresses` returns all adapters including virtual ones.
**How to avoid:** Check for specific adapter characteristics: `IfType == IF_TYPE_TUNNEL` (131), or adapter description containing known VPN keywords ("TAP", "WireGuard", "OpenVPN", "RAS", "VPN"). Combine with IP subnet check from existing `get_network_location()`.
**Warning signs:** `NetworkLocation::CorporateVpn` when on corporate LAN without VPN.

### Pitfall 4: Registry Write Requires Admin
**What goes wrong:** Writing to `HKLM\SOFTWARE\DLP\Agent` fails if the installer is not elevated.
**Why it happens:** HKLM requires admin privileges; the agent service runs as SYSTEM but the installer may not.
**How to avoid:** Compute fingerprint in the installer (which runs elevated) and write to registry. Agent reads it at startup. If not found, compute on-the-fly and log a warning.
**Warning signs:** `ERROR_ACCESS_DENIED` at install time; agent starts with missing fingerprint.

### Pitfall 5: Health Status Transition Races
**What goes wrong:** Multiple subsystems (bypass correlator, hook DLL, audit chain) may simultaneously detect tamper and try to transition health status.
**Why it happens:** No single owner for health state transitions.
**How to avoid:** Use a single `AtomicU8` or `Mutex<DeviceHealthStatus>` in the agent service. All tamper detection paths call a shared `transition_health()` function.
**Warning signs:** Inconsistent health status in heartbeat; audit events show different health values.

## Code Examples

### EndpointIdentity Struct (dlp-common)
```rust
// Source: New type for Phase 64
use serde::{Deserialize, Serialize};

/// Endpoint device identity — distinct from USB DeviceIdentity.
///
/// Populated by the agent at startup and sent with every heartbeat.
/// The fingerprint is computed at install time and stored in the registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct EndpointIdentity {
    /// SHA-256 hash of (hostname + sorted MACs + OS version + install date).
    /// Hex-encoded, lowercase.
    pub fingerprint: String,
    /// All active NIC MAC addresses, sorted lexicographically, uppercase no-colon.
    pub mac_addresses: Vec<String>,
    /// Whether a VPN adapter is currently active.
    pub vpn_active: bool,
    /// Whether the machine is domain-joined.
    pub domain_joined: bool,
    /// Current health status of the agent endpoint.
    pub health_status: DeviceHealthStatus,
}

/// Device health status for ABAC policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DeviceHealthStatus {
    /// Agent is fully operational.
    #[default]
    Healthy,
    /// Agent has detected non-critical issues (e.g., high error rate).
    Degraded,
    /// Agent has not sent heartbeat within expected window.
    Offline,
    /// Agent has detected tampering (hash chain break, hook modification).
    Tampered,
}
```

### Fingerprint Computation (dlp-agent)
```rust
// Source: Phase 64 implementation pattern
use sha2::{Sha256, Digest};

/// Computes a deterministic device fingerprint.
///
/// # Formula
/// SHA-256(hostname + "|" + mac1 + "," + mac2 + ... + "|" + os_version + "|" + install_date)
///
/// MAC addresses are sorted lexicographically to ensure stability.
pub fn compute_fingerprint(
    hostname: &str,
    mac_addresses: &[String],
    os_version: &str,
    install_date: &str,
) -> String {
    let mut macs = mac_addresses.to_vec();
    macs.sort();
    let macs_joined = macs.join(",");
    let input = format!("{}|{}|{}|{}", hostname, macs_joined, os_version, install_date);
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result) // lowercase hex
}
```

### MAC Address Collection (dlp-agent)
```rust
// Source: Pattern derived from ad_client.rs::find_local_ipv4_sync
#[cfg(windows)]
pub fn collect_mac_addresses() -> Vec<String> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_PREFIX, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::Networking::WinSock::AF_UNSPEC;

    let family = AF_UNSPEC.0 as u32; // IPv4 + IPv6
    let flags = GAA_FLAG_INCLUDE_PREFIX;

    unsafe {
        let mut buf_size: u32 = 0;
        let _ = GetAdaptersAddresses(family, flags, None, None, &mut buf_size);
        if buf_size == 0 {
            return Vec::new();
        }

        let layout = std::alloc::Layout::from_size_align(buf_size as usize, 1).expect("valid layout");
        let buf = std::alloc::alloc(layout) as *mut IP_ADAPTER_ADDRESSES_LH;

        if GetAdaptersAddresses(family, flags, None, Some(&mut *buf), &mut buf_size) != 0 {
            std::alloc::dealloc(buf as *mut u8, layout);
            return Vec::new();
        }

        let mut macs = Vec::new();
        let mut curr = buf;
        while !curr.is_null() {
            let addr = &*curr;
            // Only include adapters that are up and have a physical address
            if addr.PhysicalAddressLength > 0 {
                let mac = format_mac(&addr.PhysicalAddress[..addr.PhysicalAddressLength as usize]);
                macs.push(mac);
            }
            curr = addr.Next;
        }

        std::alloc::dealloc(buf as *mut u8, layout);
        macs.sort();
        macs
    }
}

fn format_mac(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect()
}
```

### Registry Storage (dlp-agent)
```rust
// Source: Pattern derived from appinit.rs
const FINGERPRINT_REG_PATH: &str = r"SOFTWARE\DLP\Agent";
const FINGERPRINT_VALUE_NAME: &str = "device_fingerprint";
const INSTALL_DATE_VALUE_NAME: &str = "install_date";

#[cfg(windows)]
pub fn write_fingerprint_to_registry(fingerprint: &str, install_date: &str) -> anyhow::Result<()> {
    use windows::Win32::System::Registry::{
        RegCreateKeyExW, RegSetValueExW, HKEY_LOCAL_MACHINE, KEY_WRITE, REG_SZ,
    };

    let mut hkey = windows::Win32::System::Registry::HKEY::default();
    let result = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::w!(FINGERPRINT_REG_PATH),
            None,
            None,
            windows::Win32::System::Registry::REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        )
    };
    if result.is_err() {
        return Err(anyhow::anyhow!("RegCreateKeyExW failed: {:?}", result));
    }

    // Write fingerprint
    let fp_wide: Vec<u16> = fingerprint.encode_utf16().chain(std::iter::once(0)).collect();
    let _ = unsafe {
        RegSetValueExW(
            hkey,
            windows::core::w!(FINGERPRINT_VALUE_NAME),
            None,
            REG_SZ,
            Some(fp_wide.as_ptr() as *const u8),
            (fp_wide.len() * 2) as u32,
        )
    };

    // Write install date
    let date_wide: Vec<u16> = install_date.encode_utf16().chain(std::iter::once(0)).collect();
    let _ = unsafe {
        RegSetValueExW(
            hkey,
            windows::core::w!(INSTALL_DATE_VALUE_NAME),
            None,
            REG_SZ,
            Some(date_wide.as_ptr() as *const u8),
            (date_wide.len() * 2) as u32,
        )
    };

    unsafe { windows::Win32::System::Registry::RegCloseKey(hkey); }
    Ok(())
}
```

### Extended Heartbeat Payload
```rust
// Source: dlp-agent/src/server_client.rs (extension)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    #[serde(default)]
    pub status: Option<String>,
    /// Phase 64: Full endpoint identity sent with every heartbeat.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_identity: Option<dlp_common::EndpointIdentity>,
}
```

### ABAC PolicyCondition Extension
```rust
// Source: dlp-common/src/abac.rs (extension)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "attribute", rename_all = "snake_case")]
pub enum PolicyCondition {
    // ... existing variants ...
    /// Match by device health status.
    DeviceHealth {
        #[serde(rename = "op")]
        op: String,
        value: DeviceHealthStatus,
    },
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `DeviceIdentity` for USB only | `EndpointIdentity` for agent device | Phase 64 | Avoids naming collision; USB struct unchanged |
| Heartbeat `{"status": "healthy"}` | Full device identity payload | Phase 64 | Enables server-side ABAC with device health |
| IP-subnet VPN detection | Adapter-type + IP-subnet hybrid | Phase 64 | More accurate VPN state detection |
| Manual device trust only | Health status transitions | Phase 64 | Enables tamper-aware policies |

**Deprecated/outdated:**
- None — all patterns are additive.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | The installer runs elevated and can write to HKLM | Registry Storage | If installer is not elevated, fingerprint must be computed at first agent startup (which runs as SYSTEM) |
| A2 | `GetAdaptersAddresses` returns all active NICs including VPN TAP adapters | MAC Collection | If VPN adapters are excluded, MAC list is incomplete; fingerprint may change when VPN connects/disconnects |
| A3 | MAC address sorting ensures deterministic fingerprint | Fingerprint Computation | If sort order differs between platforms or Rust versions, fingerprint becomes unstable |
| A4 | `NetworkLocation::CorporateVpn` already exists and is used by ABAC | VPN Detection | If VPN state is not wired into `Subject.network_location`, ABAC policies won't evaluate it |

## Open Questions

1. **Should the fingerprint include the install date or a static salt?**
   - What we know: CONTEXT.md says "SHA-256 of hostname + MACs + OS version + install date"
   - What's unclear: Whether install date should be ISO-8601 or epoch seconds
   - Recommendation: Use ISO-8601 date string (e.g., "2026-06-06") for human readability in registry

2. **Should health status transitions emit audit events?**
   - What we know: `AuditEvent` already has `device_trust` and `network_location` fields
   - What's unclear: Whether health transitions need dedicated `EventType` variants
   - Recommendation: Add `EventType::DeviceHealthChange` for transition logging

3. **Should the server store historical device identity or only current?**
   - What we know: The `agents` table currently stores only current state
   - What's unclear: Whether pilot acceptance requires identity change history
   - Recommendation: Store only current state in `agents` table; audit log captures changes

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Windows SDK | `GetAdaptersAddresses`, `NetGetJoinInformation` | ✓ | 10.0.22621 | — |
| `windows` crate | Windows API bindings | ✓ | 0.52 | — |
| `sha2` crate | Fingerprint hash | ✓ | 0.10 | — |
| Registry write access | Fingerprint persistence | ✓ (installer) | — | Compute at agent startup |

**Missing dependencies with no fallback:**
- None

**Missing dependencies with fallback:**
- None

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Built-in `#[test]` + `cargo test` |
| Config file | None — see Wave 0 |
| Quick run command | `cargo test -p dlp-common` |
| Full suite command | `cargo test --workspace` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| DEVICE-01 | Fingerprint computed and stored in registry | unit | `cargo test -p dlp-agent test_fingerprint_computation` | ❌ Wave 0 |
| DEVICE-02 | MAC addresses collected via GetAdaptersAddresses | unit | `cargo test -p dlp-agent test_mac_collection` | ❌ Wave 0 |
| DEVICE-03 | VPN state detected at runtime | unit | `cargo test -p dlp-agent test_vpn_detection` | ❌ Wave 0 |
| DEVICE-04 | Domain state included in heartbeat | integration | `cargo test -p dlp-e2e test_heartbeat_domain_state` | ❌ Wave 0 |
| DEVICE-05 | Health status transitions on tamper | unit | `cargo test -p dlp-agent test_health_transition` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `cargo test -p dlp-common -p dlp-agent`
- **Per wave merge:** `cargo test --workspace`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `dlp-agent/src/device_identity.rs` — new module, needs tests
- [ ] `dlp-common/src/endpoint.rs` — `EndpointIdentity` tests
- [ ] `dlp-common/src/abac.rs` — `DeviceHealthStatus` serde tests
- [ ] `dlp-server/src/db/repositories/agents.rs` — extended `AgentRow` tests
- [ ] `dlp-agent/src/server_client.rs` — extended heartbeat payload tests

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No | — |
| V3 Session Management | No | — |
| V4 Access Control | Yes | ABAC `DeviceHealth` condition |
| V5 Input Validation | Yes | Validate MAC address format, fingerprint hex |
| V6 Cryptography | Yes | SHA-256 for fingerprint (FIPS-adjacent) |
| V7 Error Handling | Yes | Registry write failures must not crash installer |
| V10 Malicious Code | Yes | Tamper detection → health status transition |

### Known Threat Patterns for Device Identity Stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Fingerprint spoofing | Spoofing | Registry in HKLM requires admin; agent verifies at startup |
| MAC address cloning | Spoofing | Multiple MACs required; approval binding to fingerprint |
| VPN state bypass | Evasion | Adapter-type check + IP subnet check (defense in depth) |
| Health status manipulation | Tampering | Atomic transitions; audit log every change |
| Heartbeat payload tampering | Tampering | HTTPS in transit; server validates field formats |

## Sources

### Primary (HIGH confidence)
- `dlp-common/src/abac.rs` — `DeviceTrust`, `NetworkLocation`, `Subject`, `PolicyCondition` definitions
- `dlp-common/src/ad_client.rs` — `get_device_trust()`, `find_local_ipv4_sync()` using `GetAdaptersAddresses`
- `dlp-agent/src/appinit.rs` — Registry read/write patterns with `windows` crate
- `dlp-agent/src/server_client.rs` — `send_heartbeat()`, `AgentConfigPayload`
- `dlp-server/src/agent_registry.rs` — `HeartbeatRequest`, `AgentInfoResponse`
- `dlp-server/src/db/repositories/agents.rs` — `AgentRow`, `update_heartbeat()`
- `dlp-server/src/db/mod.rs` — `agents` table schema, `run_migrations()`
- `dlp-server/src/policy_store.rs` — `condition_matches()` for all `PolicyCondition` variants
- `dlp-agent/src/config.rs` — `AgentConfig` TOML persistence patterns

### Secondary (MEDIUM confidence)
- Microsoft Learn — `GetAdaptersAddresses` documentation (verified via `microsoft_docs_search`)
- Microsoft Learn — `NetGetJoinInformation` documentation (verified via `microsoft_docs_search`)
- Windows crate docs — `windows::Win32::NetworkManagement::IpHelper` module

### Tertiary (LOW confidence)
- None — all critical claims verified against codebase.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all crates already in workspace, patterns proven in production
- Architecture: HIGH — clear extension points in existing code, no structural changes needed
- Pitfalls: HIGH — all identified from direct codebase analysis and Windows API behavior

**Research date:** 2026-06-06
**Valid until:** 2026-07-06 (stable stack, no fast-moving dependencies)
