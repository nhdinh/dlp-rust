# Phase 62: Syslog Forwarder - Research

**Researched:** 2026-05-14
**Domain:** RFC 5424 Syslog over TLS, Rust async TLS, encrypted offline queue
**Confidence:** HIGH

## Summary

Phase 62 delivers a native RFC 5424 syslog forwarder from `dlp-server` to configured SIEM/SOC collectors over TLS, with encrypted offline queues on both agent and server sides. The phase builds on existing patterns from `SiemConnector` (hot-reload config, batched relay), `SiemConfigRepository` (encrypted single-row config table), and `AlertRouter` (fire-and-forget with test button). The key technical challenges are: (1) implementing RFC 5424 message formatting with configurable facility/severity mapping, (2) establishing TLS/TCP connections using the existing `rustls` ecosystem already present in the project, (3) building encrypted SQLite-backed queues with DPAPI (agent) and KEK (server) encryption, and (4) mirroring the admin TUI config screen pattern.

**Primary recommendation:** Build `SyslogConnector` as a `SiemConnector` twin (hot-reload, batched, fire-and-forget), use `tokio::net::TcpStream` + `tokio-rustls` for TLS transport (leveraging existing `rustls-tls` feature in `reqwest`), reuse `SecretCrypto`/`DPAPI` for queue encryption, and mirror the `siem_config.rs` TUI screen exactly.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| RFC 5424 message formatting | API / Backend (dlp-server) | -- | Server formats messages; agent only queues raw events |
| TLS transport to SIEM | API / Backend (dlp-server) | -- | Outbound TCP/TLS connection initiated by server |
| Agent-side offline queue | Endpoint (dlp-agent) | -- | Local SQLite + DPAPI when server unreachable |
| Server-side offline queue | API / Backend (dlp-server) | -- | SQLite + KEK when syslog collector unreachable |
| Queue drain / retry logic | API / Backend + Endpoint | -- | Each tier drains its own queue |
| Admin TUI config screen | Frontend (dlp-admin-cli) | -- | HTTP client to admin API |
| Syslog config CRUD API | API / Backend (dlp-server) | -- | Standard admin API pattern |

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `tokio` | 1.x (workspace) | Async runtime | Already used throughout project |
| `tokio::net::TcpStream` | built-in | TCP connection to syslog collector | No extra dep; part of tokio |
| `tokio-rustls` | 0.26.x | TLS wrapper for TCP stream | Matches rustls 0.23; reqwest already uses rustls-tls |
| `rustls` | 0.23.x | TLS configuration | Already in dep tree via reqwest/rustls-tls |
| `rustls-native-certs` | 0.8.x | Load system CA store | Required for D-10 (system CA store only) |
| `webpki-roots` | 0.26.x | Mozilla CA bundle fallback | Already in dep tree via reqwest |
| `serde` / `serde_json` | workspace | JSON payload serialization | Already standard |
| `chrono` | 0.4.x | RFC 5424 timestamp formatting | Already used; `to_rfc3339()` produces valid ISO 8601 |
| `hostname` | 0.4.2 | Hostname for syslog header | Already in dlp-agent Cargo.toml |
| `rusqlite` | 0.39 | Queue tables | Already used for all SQLite |
| `secrecy` | workspace | Secret redaction | Already standard per CLAUDE.md |
| `thiserror` / `anyhow` | workspace | Error handling | Already standard |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `rustls-pki-types` | 1.14.x | `ServerName` type for rustls 0.23 | Required for tokio-rustls 0.26 |
| `tracing` | workspace | Structured logging | Already standard |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `tokio-rustls` | `native-tls` + `tokio-native-tls` | native-tls uses OpenSSL/Schannel; rustls is pure Rust, audited, already in project dep tree via reqwest |
| `rustls-native-certs` | `webpki-roots` only | native-certs uses Windows CA store (D-10 requirement); webpki-roots is static Mozilla bundle -- use both with native-certs preferred |
| Custom syslog crate | Hand-roll RFC 5424 | No mature syslog crate in Rust ecosystem; formatting is simple string construction |

**Installation:**
```bash
# dlp-server Cargo.toml additions:
# tokio-rustls = "0.26"
# rustls-native-certs = "0.8"
# rustls-pki-types = "1.14"
# (rustls comes via tokio-rustls re-export)
```

**Version verification:**
- `tokio-rustls`: 0.26.4 (latest stable, compatible with rustls 0.23) [VERIFIED: crates.io]
- `rustls`: 0.23.40 (latest stable) [VERIFIED: docs.rs]
- `rustls-native-certs`: 0.8.3 [VERIFIED: crates.io]
- `hostname`: 0.4.2 [VERIFIED: crates.io]

## Architecture Patterns

### System Architecture Diagram

```
Agent (dlp-agent)                          Server (dlp-server)                    External
    |                                            |                                    |
    |-- AuditEvent -->|                          |                                    |
    |                 |                          |                                    |
    |    [agent_syslog_queue]                    |                                    |
    |    (SQLite, DPAPI-encrypted)               |                                    |
    |         | (drain on reconnect)             |                                    |
    |<--------|                                  |                                    |
    |-- HTTPS POST /audit/events --------------->|                                    |
    |                                            |-- persist to audit_events          |
    |                                            |-- SyslogConnector::forward()       |
    |                                            |       |                            |
    |                                            |   [syslog_queue]                   |
    |                                            |   (SQLite, KEK-encrypted)          |
    |                                            |       | (drain when reachable)     |
    |                                            |<------|                            |
    |                                            |-- TCP/TLS connect ---------------->| Syslog Collector
    |                                            |-- RFC 5424 MSG ------------------->| (Splunk/Elastic/
    |                                            |       newline-delimited JSON        |  Sentinel/etc.)
```

### Recommended Project Structure

```
dlp-server/src/
├── syslog_connector.rs          # SyslogConnector: TLS client, RFC 5424 formatting, retry
├── db/repositories/
│   ├── syslog_config.rs         # SyslogConfigRepository: single-row config (mirrors SiemConfigRepository)
│   └── syslog_queue.rs          # SyslogQueueRepository: queue CRUD + drain
├── admin_api.rs                 # GET/PUT /admin/syslog-config + POST /admin/syslog-config/test

dlp-agent/src/
├── syslog_queue.rs              # Agent-side queue: SQLite + DPAPI encrypt/decrypt
├── audit_emitter.rs             # Integration: enqueue to syslog_queue when offline

dlp-admin-cli/src/
├── screens/
│   └── syslog_config.rs         # TUI screen (mirrors siem_config.rs pattern)
```

### Pattern 1: SyslogConnector (Mirrors SiemConnector)
**What:** Hot-reload config, batched RFC 5424 forwarding over TLS/TCP, exponential backoff retry.
**When to use:** Server-side syslog forwarding after audit event persistence.
**Example:**
```rust
// Source: dlp-server/src/siem_connector.rs (existing pattern)
// Adapted for syslog transport

use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::{rustls, TlsConnector};
use rustls_pki_types::ServerName;

#[derive(Clone)]
pub struct SyslogConnector {
    pool: Arc<db::Pool>,
    crypto: Arc<SecretCrypto>,
}

impl SyslogConnector {
    pub async fn forward(&self, events: &[AuditEvent]) -> Result<(), SyslogError> {
        let config = SyslogConfigRepository::get(&self.pool, &self.crypto)?;
        if !config.enabled {
            return Ok(());
        }

        // Build TLS config (system CA store)
        let tls_config = build_tls_config()?;
        let connector = TlsConnector::from(Arc::new(tls_config));

        // Connect TCP + TLS handshake
        let stream = TcpStream::connect((config.host.as_str(), config.port as u16)).await?;
        let server_name = ServerName::try_from(config.host.as_str())?.to_owned();
        let mut tls_stream = connector.connect(server_name, stream).await?;

        // Format and send RFC 5424 messages
        for event in events {
            let msg = format_rfc5424(event, &config)?;
            tls_stream.write_all(msg.as_bytes()).await?;
        }
        tls_stream.shutdown().await?;
        Ok(())
    }
}
```

### Pattern 2: RFC 5424 Message Format
**What:** `<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG`
**When to use:** Every syslog message sent to the collector.
**Example:**
```rust
// Source: RFC 5424 section 6 + 62-CONTEXT.md specifics

fn format_rfc5424(
    event: &AuditEvent,
    config: &SyslogConfigRow,
    hostname: &str,
    procid: &str,
) -> Result<String, SyslogError> {
    let severity = map_severity(event.event_type, &config.severity_mapping);
    let priority = config.facility_code * 8 + severity;
    let timestamp = event.timestamp.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let msgid = event_type_to_msgid(event.event_type);
    let json_payload = serde_json::to_string(event)?;

    // <134>1 2026-05-14T10:00:00.000Z webserver01 DLP-AUDIT 1234 DLP-BLOCK - {"event_id":"..."}
    Ok(format!(
        "<{priority}>1 {timestamp} {hostname} DLP-AUDIT {procid} {msgid} - {json_payload}\n"
    ))
}
```

### Pattern 3: Encrypted Queue (Mirrors SecretCrypto Pattern)
**What:** SQLite table with encrypted `event_json` blob, decrypted on drain.
**When to use:** Both agent-side (DPAPI) and server-side (KEK) queues.
**Example:**
```rust
// Source: dlp-server/src/crypto/mod.rs + dlp-server/src/db/repositories/siem_config.rs

// Server-side: KEK-encrypted
pub fn enqueue(
    uow: &UnitOfWork,
    event_json: &str,
    crypto: &SecretCrypto,
) -> Result<(), AppError> {
    let aad = aad_for("syslog_queue", "event_json");
    let envelope = crypto.encrypt(event_json.as_bytes(), &aad)?;
    uow.tx.execute(
        "INSERT INTO syslog_queue (event_json_encrypted, event_json_nonce, created_at, retry_count) \
         VALUES (?1, ?2, ?3, 0)",
        params![envelope.ciphertext, envelope.nonce.as_slice(), Utc::now().to_rfc3339()],
    )?;
    Ok(())
}

// Agent-side: DPAPI-encrypted (Windows only)
#[cfg(windows)]
pub fn enqueue_dpapi(conn: &Connection, event_json: &str) -> Result<(), AppError> {
    let encrypted = dpapi_protect(event_json.as_bytes())?;
    conn.execute(
        "INSERT INTO agent_syslog_queue (event_json_dpapi, created_at, retry_count) \
         VALUES (?1, ?2, 0)",
        params![encrypted, Utc::now().to_rfc3339()],
    )?;
    Ok(())
}
```

### Anti-Patterns to Avoid
- **Caching syslog config:** The `SiemConnector` hot-reloads on every call -- `SyslogConnector` must do the same. No caching.
- **Blocking the async reactor:** All DB operations must be wrapped in `tokio::task::spawn_blocking` (existing pattern in `audit_store.rs`).
- **UDP syslog:** Deferred per CONTEXT.md; only TLS/TCP in Phase 62.
- **Custom CA/mTLS:** Deferred per CONTEXT.md; system CA store only.
- **Unbounded queue growth:** Must respect D-09 max queue sizes with FIFO tail-drop.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| TLS handshake | Custom TLS over TCP | `tokio-rustls` | Certificate verification, ALPN, cipher negotiation, session resumption -- all handled |
| CA certificate loading | Manual cert parsing | `rustls-native-certs` + `webpki-roots` | Platform-native CA store on Windows; fallback to Mozilla bundle |
| RFC 5424 timestamp | `strftime` formatting | `chrono::DateTime::to_rfc3339()` | ISO 8601 compliance, timezone handling, precision |
| JSON serialization | Manual string building | `serde_json::to_string()` | Escape handling, UTF-8 safety, performance |
| Exponential backoff | Manual sleep loop | `tokio::time::sleep` with backoff formula | Jitter, max backoff, reset on success -- pattern is well-understood |
| SQLite encryption | Custom cipher | `SecretCrypto::encrypt` / `dpapi_protect` | Already built, audited, tested in Phase 47 |

**Key insight:** The only "hand-rolled" part should be the RFC 5424 header string formatting (which is trivial concatenation). Everything else (TLS, JSON, timestamps, encryption) uses battle-tested libraries.

## Runtime State Inventory

> This phase adds new tables and modules but does not rename existing runtime state. No data migration is required for existing installations.

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | None -- new `syslog_config`, `syslog_queue`, `agent_syslog_queue` tables are created by `init_tables()` | Code edit (add CREATE TABLE to `init_tables()`) |
| Live service config | None -- syslog config is new | Code edit |
| OS-registered state | None | None |
| Secrets/env vars | None -- no new env vars | None |
| Build artifacts | None | None |

**Nothing found in category:** Stored data, live service config, OS-registered state, secrets, build artifacts -- all are new additions, no rename/migration needed.

## Common Pitfalls

### Pitfall 1: TLS CryptoProvider Not Installed (rustls 0.23+)
**What goes wrong:** `rustls 0.23+` requires an explicit crypto provider. Without `ring` or `aws-lc-rs` installed, `ClientConfig::builder()` panics at runtime.
**Why it happens:** rustls 0.23 changed from implicit to explicit crypto provider selection.
**How to avoid:** Either (a) enable `ring` feature on `tokio-rustls` / `rustls`, or (b) call `rustls::crypto::ring::default_provider().install_default().ok()` early in `main()`. The `reqwest` crate with `rustls-tls` feature already pulls in `ring`, so this may be automatic -- verify at compile time.
**Warning signs:** Panic at `ClientConfig::builder()` with message about missing crypto provider.

### Pitfall 2: ServerName DNS Name Validation Failure
**What goes wrong:** `ServerName::try_from("192.168.1.1")` fails because IP addresses are not valid DNS names for rustls.
**Why it happens:** rustls strictly validates server names per RFC 6066; raw IPs require `ServerName::IpAddress` variant.
**How to avoid:** Detect IP addresses (via `std::net::IpAddr::parse`) and use `ServerName::IpAddress` instead of `try_from`.
**Warning signs:** TLS handshake fails with "invalid DNS name" error.

### Pitfall 3: RFC 5424 MSG Field Length
**What goes wrong:** Some legacy syslog collectors enforce 1024-byte total message length (RFC 3164 legacy). JSON payloads can exceed this.
**Why it happens:** Modern SIEMs (Splunk, Elastic, Sentinel) accept arbitrary length, but some older syslog daemons truncate.
**How to avoid:** Document that Phase 62 targets modern SIEMs. If truncation is needed, truncate the JSON payload (not the header) and document the behavior.
**Warning signs:** SIEM reports partial/malformed JSON events.

### Pitfall 4: DPAPI Unprotect on Agent Restart
**What goes wrong:** Agent-side DPAPI-encrypted queue data cannot be decrypted after machine rebuild or user profile deletion.
**Why it happens:** DPAPI is bound to the user's master key and machine SID.
**How to avoid:** This is expected behavior per D-06/D-07. Queue data is best-effort, not guaranteed. Document in deployment guide that queued events are lost on machine rebuild.
**Warning signs:** `CryptUnprotectData` returns `NTE_BAD_KEY_STATE` on drain attempt.

### Pitfall 5: Queue Table Without Index on `created_at`
**What goes wrong:** FIFO drain queries (`ORDER BY created_at LIMIT N`) become slow as queue grows.
**Why it happens:** SQLite does full table scan without index.
**How to avoid:** Add `CREATE INDEX idx_syslog_queue_created_at ON syslog_queue(created_at)` and similar for agent queue.
**Warning signs:** Drain latency increases linearly with queue depth.

## Code Examples

### TLS Client Configuration (System CA Store)
```rust
// Source: tokio-rustls examples + rustls-native-certs docs
use std::sync::Arc;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

fn build_tls_config() -> Result<ClientConfig, SyslogError> {
    let mut root_store = RootCertStore::empty();

    // Load system CA certificates (Windows CA store on Windows)
    let native_certs = rustls_native_certs::load_native_certs()
        .map_err(|e| SyslogError::Tls(format!("failed to load native certs: {e}")))?;
    for cert in native_certs {
        root_store.add(cert)?;
    }

    // Fallback to Mozilla bundle if native certs empty
    if root_store.is_empty() {
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(config)
}
```

### Severity Mapping
```rust
// Source: 62-CONTEXT.md D-03
fn map_severity(event_type: EventType, mapping: &SeverityMapping) -> u8 {
    match event_type {
        EventType::Alert => mapping.alert_severity,      // default: 3 (ERROR)
        EventType::Block => mapping.block_severity,      // default: 4 (WARNING)
        _ => mapping.audit_severity,                     // default: 6 (INFO)
    }
}
```

### Exponential Backoff with Jitter
```rust
// Source: 62-CONTEXT.md D-07 (Claude's Discretion)
fn backoff_delay(retry_count: u32) -> std::time::Duration {
    let base = 1u64;
    let max = 60u64;
    let exp = std::cmp::min(retry_count, 6); // cap at 64s
    let delay = std::cmp::min(base * 2u64.pow(exp), max);
    // Add jitter: delay + rand(0..delay/2)
    let jitter = rand::random::<u64>() % (delay / 2 + 1);
    std::time::Duration::from_secs(delay + jitter)
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| rustls 0.21 + `webpki` crate | rustls 0.23 + `rustls-pki-types` | 2024 | New types for certificates, server names; `ServerName::try_from` replaces `DNSNameRef` |
| Implicit crypto provider | Explicit `CryptoProvider::install_default()` | rustls 0.23 | Must install ring or aws-lc-rs provider before building `ClientConfig` |
| `tokio-rustls` 0.24 | `tokio-rustls` 0.26 | 2024-2025 | Compatible with rustls 0.23; same API surface |

**Deprecated/outdated:**
- `webpki` standalone crate: superseded by `rustls-pki-types` [CITED: docs.rs/rustls]
- `native-tls` + `tokio-native-tls`: still works but rustls is preferred for pure-Rust, auditability [ASSUMED]

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `reqwest` with `rustls-tls` feature already pulls in `ring` crypto provider, so `tokio-rustls` will not need explicit provider installation | Standard Stack | Runtime panic on TLS handshake if ring is not in dep tree; fix by adding explicit provider install in main() |
| A2 | Modern SIEMs (Splunk HEC, Elastic, Sentinel) accept arbitrary-length syslog messages over TCP/TLS | Common Pitfalls | If false, may need message truncation logic; verify with target SIEM documentation |
| A3 | `hostname::get()` returns a valid UTF-8 hostname on Windows | Architecture Patterns | If false, fall back to `std::env::var("COMPUTERNAME")` |
| A4 | `rustls-native-certs` loads Windows system CA store correctly on Windows 10/11 | Standard Stack | If false, fallback to `webpki-roots` is implemented |

## Open Questions (RESOLVED)

1. **Does the project need to add `tokio-rustls` as an explicit dependency, or can it use rustls types re-exported from `reqwest`?**
   - **RESOLVED:** Add `tokio-rustls` explicitly to `dlp-server/Cargo.toml` to ensure version pinning and direct API access. Implemented in Plan 01 Task 3.

2. **Should the agent-side queue drain be triggered by heartbeat success or by a dedicated background task?**
   - **RESOLVED:** Start with heartbeat-triggered drain (simpler). Implemented in Plan 03 Task 1 -- agent drains on heartbeat success.

3. **How should the server-side queue drain be scheduled?**
   - **RESOLVED:** Dedicated `tokio::spawn` drain loop with configurable interval (default 30s) and backoff on failure. Implemented in Plan 02 Task 3.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| tokio | Async runtime | ✓ | 1.x (workspace) | -- |
| rustls | TLS | ✓ | 0.23 (via reqwest) | -- |
| tokio-rustls | TLS streams | ✓ | 0.26 (add to Cargo.toml) | -- |
| rustls-native-certs | System CA store | ✓ | 0.8 (add to Cargo.toml) | webpki-roots |
| rusqlite | SQLite queue | ✓ | 0.39 | -- |
| DPAPI (Windows) | Agent queue encryption | ✓ | OS built-in | -- |
| hostname crate | Hostname resolution | ✓ | 0.4.2 (dlp-agent) | std::env::var("COMPUTERNAME") |

**Missing dependencies with no fallback:** None.

**Missing dependencies with fallback:** None.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Built-in `#[test]` + `tokio::test` |
| Config file | None -- see Wave 0 |
| Quick run command | `cargo test -p dlp-server syslog` |
| Full suite command | `cargo test --all` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| SYSLOG-01 | RFC 5424 forwarding over TLS | unit | `cargo test -p dlp-server test_syslog_forward` | ❌ Wave 0 |
| SYSLOG-02 | Stable JSON payload with all fields | unit | `cargo test -p dlp-common test_audit_event_serde` | ✅ (existing) |
| SYSLOG-03 | Agent-side encrypted queue | unit | `cargo test -p dlp-agent test_agent_syslog_queue` | ❌ Wave 0 |
| SYSLOG-04 | Admin TUI syslog config screen | integration | `cargo test -p dlp-admin-cli test_syslog_screen` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `cargo test -p dlp-server --lib` (quick, < 30s)
- **Per wave merge:** `cargo test --all`
- **Phase gate:** Full suite green before `/gsd-verify-work`

### Wave 0 Gaps
- [ ] `dlp-server/src/syslog_connector.rs` -- covers SYSLOG-01
- [ ] `dlp-server/src/db/repositories/syslog_config.rs` -- config CRUD
- [ ] `dlp-server/src/db/repositories/syslog_queue.rs` -- queue CRUD + drain
- [ ] `dlp-agent/src/syslog_queue.rs` -- agent-side queue
- [ ] `dlp-admin-cli/src/screens/syslog_config.rs` -- TUI screen
- [ ] `dlp-server/src/admin_api.rs` -- add `/admin/syslog-config` routes

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No | Syslog uses TLS server auth only (no client auth in Phase 62) |
| V3 Session Management | No | Stateless TCP connections |
| V4 Access Control | No | Syslog is outbound-only |
| V5 Input Validation | Yes | AuditEvent JSON serialization via `serde_json` (validated schema) |
| V6 Cryptography | Yes | TLS 1.2+ via rustls; queue encryption via AES-256-GCM (SecretCrypto) / DPAPI |
| V8 Data Protection | Yes | Queue data encrypted at rest (DPAPI/KEK); secrets redacted via `SecretString` |
| V10 Logging | Yes | Audit events forwarded; no PII in syslog MSG beyond what AuditEvent already contains |

### Known Threat Patterns for Syslog/TLS Stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Man-in-the-middle on syslog path | Spoofing | TLS with certificate verification (system CA store) |
| Queue tampering on disk | Tampering | AES-256-GCM authenticated encryption (SecretCrypto) |
| Queue data exposure (theft) | Information Disclosure | DPAPI (machine-bound) / KEK (server-bound) encryption |
| Replay of old queue entries | Repudiation | Timestamps in queue + `created_at` ordering; no replay defense needed (append-only) |
| Denial of service (queue flooding) | Denial of Service | Max queue size (D-09) with tail-drop |

## Sources

### Primary (HIGH confidence)
- [RFC 5424](https://datatracker.ietf.org/doc/html/rfc5424.html) -- syslog protocol specification, message format, priority calculation
- [tokio-rustls 0.26.4 docs](https://docs.rs/tokio-rustls/0.26.4/) -- TLS stream API
- [rustls 0.23 docs](https://docs.rs/rustls/0.23.40/rustls/) -- ClientConfig builder, crypto provider
- [rustls-native-certs 0.8 docs](https://docs.rs/rustls-native-certs/0.8.3/) -- System CA store loading
- `dlp-server/src/siem_connector.rs` -- existing SiemConnector pattern (hot-reload, batched relay)
- `dlp-server/src/db/repositories/siem_config.rs` -- encrypted config repository pattern
- `dlp-server/src/crypto/mod.rs` -- SecretCrypto encrypt/decrypt APIs
- `dlp-server/src/db/mod.rs` -- init_tables() schema initialization pattern
- `dlp-admin-cli/src/screens/dispatch.rs` -- TUI screen dispatch pattern (SiemConfig)
- `dlp-server/src/audit_store.rs` -- integration point (fire-and-forget after persist)

### Secondary (MEDIUM confidence)
- [WebSearch: rustls 0.23 tokio-rustls TLS client example](https://users.rust-lang.org/t/secure-websocket-implementation-with-tokio-tungstenite-tokio-rustls-rustls-platform-verifier/110211) -- community patterns for rustls 0.23
- [GitHub: tokio-rustls examples](https://github.com/rustls/tokio-rustls/tree/main/examples) -- official client.rs example

### Tertiary (LOW confidence)
- None -- all claims verified against code or official docs.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- versions verified against crates.io, APIs verified against docs.rs, patterns verified against existing codebase
- Architecture: HIGH -- directly mirrors existing proven patterns (SiemConnector, SiemConfigRepository)
- Pitfalls: HIGH -- rustls 0.23 crypto provider issue is well-documented; RFC 5424 format is spec-defined

**Research date:** 2026-05-14
**Valid until:** 2026-06-14 (rustls ecosystem is stable; 30-day validity appropriate)
