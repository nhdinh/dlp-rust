---
phase: 04-wire-alert-router-into-server
reviewed: 2026-04-10T00:00:00Z
depth: standard
files_reviewed: 10
files_reviewed_list:
  - dlp-server/Cargo.toml
  - dlp-server/src/db.rs
  - dlp-server/src/alert_router.rs
  - dlp-server/src/lib.rs
  - dlp-server/src/main.rs
  - dlp-server/src/admin_api.rs
  - dlp-server/src/audit_store.rs
  - dlp-admin-cli/src/app.rs
  - dlp-admin-cli/src/screens/render.rs
  - dlp-admin-cli/src/screens/dispatch.rs
findings:
  blocker: 1
  high: 2
  medium: 3
  low: 3
  info: 4
  total: 13
status: issues
---

# Phase 4: Code Review Report

**Reviewed:** 2026-04-10
**Depth:** standard (advisory — does not block execution)
**Files Reviewed:** 10
**Status:** issues

## Summary

Phase 4 successfully wires `AlertRouter` into the server hot path, migrates config
from env vars to a DB-backed `alert_router_config` table, adds GET/PUT
`/admin/alert-config` handlers with 26-case SSRF-hardened webhook URL validation,
and delivers a matching `dlp-admin-cli` TUI screen. The four ratified threat-model
decisions (TM-01 through TM-04) are honored at the spot-check level:

- **TM-01 (plaintext `smtp_password`):** Matches Phase 3.1 `splunk_token`
  precedent. No new encryption; acceptable per ratified decision. Not flagged.
- **TM-02 (textual-only webhook URL validation):** Logic in
  `admin_api.rs:189-227` correctly rejects `http://`, loopback IPv4
  (`127/8`), link-local IPv4 (`169.254/16`), IPv6 `::1`, and the `fe80::/10`
  manual bitmask. **However, one IPv6 bypass exists — see BL-01.**
- **TM-03 (full `AuditEvent` in email):** Verified via
  `grep sample_content|content_snippet|snippet|preview|payload_content|clipboard_text|file_excerpt|plaintext`
  against `dlp-common/src/audit.rs` — zero hits. The module doc comment at
  `alert_router.rs:7-19` documents the forward-compat rule. Compliant.
- **TM-04 (warn-only, no metrics):** `grep -c 'tracing::warn' dlp-server/src/alert_router.rs` = **2**;
  `grep -cE 'AtomicU64|counter|metrics|prometheus|opentelemetry' dlp-server/src/alert_router.rs` = **0**;
  no new admin endpoints beyond GET/PUT `/admin/alert-config`. Compliant.

Deleted symbols (`from_env`, `load_smtp_config`, `load_webhook_config`,
`test_from_env_no_vars`) are fully gone from `dlp-server/src/alert_router.rs`
and unreferenced elsewhere in `dlp-server/`. Remaining grep hits live in
`dlp-admin-cli`, `dlp-agent`, `dlp-user-ui`, and `dlp-server/src/policy_sync.rs` —
all unrelated to the alert router.

One BLOCKER-class SSRF bypass, two HIGH-impact findings on the fire-and-forget
alert path, and several MEDIUM/LOW polish items follow.

---

## Critical Issues

### BL-01: IPv4-mapped IPv6 loopback/link-local bypasses `validate_webhook_url`

**File:** `dlp-server/src/admin_api.rs:208-220`
**Severity:** BLOCKER
**Category:** Security (SSRF)

**Issue:** The IPv6 branch uses `std::net::Ipv6Addr::is_loopback()`, which on
stable Rust returns `true` **only** for the exact address `::1` — it does
**not** consider IPv4-mapped-IPv6 forms. Therefore all of the following are
accepted by the validator today:

- `https://[::ffff:127.0.0.1]` — IPv4-mapped loopback
- `https://[::ffff:7f00:1]` — same address, hex form
- `https://[::ffff:169.254.169.254]` — **AWS / Azure / GCP instance metadata
  endpoint** via IPv4-mapped form
- `https://[::ffff:10.0.0.1]` — (intentionally OK because 10/8 is ALLOWED,
  but worth noting the mapped form works)

On a dual-stack host where the kernel routes `::ffff:127.0.0.1` to the v4
loopback, an attacker who can configure a webhook URL can hit loopback
services, link-local cloud metadata, and any other blocked v4 range by
wrapping the address in `::ffff:`.

This directly contradicts TM-02's intent (reject loopback + link-local) and
is explicitly called out in the review brief as a target.

**Fix:** After the existing IPv6 checks, convert IPv4-mapped addresses back
to v4 and re-run the v4 guards:

```rust
Some(url::Host::Ipv6(ip)) => {
    if ip.is_loopback() {
        return Err("loopback addresses not allowed".to_string());
    }
    let first_segment = ip.segments()[0];
    if (first_segment & 0xffc0) == 0xfe80 {
        return Err("link-local addresses not allowed".to_string());
    }
    // TM-02 hardening: IPv4-mapped IPv6 (::ffff:a.b.c.d) must be
    // evaluated against the v4 blocklist, otherwise `[::ffff:127.0.0.1]`
    // and `[::ffff:169.254.169.254]` bypass the check.
    if let Some(v4) = ip.to_ipv4_mapped() {
        if v4.is_loopback() {
            return Err("loopback addresses not allowed (IPv4-mapped)".to_string());
        }
        if v4.is_link_local() {
            return Err("link-local addresses not allowed (IPv4-mapped)".to_string());
        }
    }
    Ok(())
}
```

`Ipv6Addr::to_ipv4_mapped` is stable since Rust 1.63. If the MSRV is older,
fall back to `to_ipv4()` (which maps both `::ffff:a.b.c.d` AND IPv4-compatible
`::a.b.c.d` — the broader conversion, also acceptable here because both are
loopback-equivalent on dual-stack hosts).

Add explicit test cases to the 26-case table in `admin_api.rs:934`:

```rust
("https://[::ffff:127.0.0.1]", false),         // 27 IPv4-mapped loopback
("https://[::ffff:169.254.169.254]", false),   // 28 IPv4-mapped cloud metadata
```

---

## High

### HI-01: `reqwest::Client::new()` has no timeout — webhook tasks can hang indefinitely

**File:** `dlp-server/src/alert_router.rs:121`
**Severity:** HIGH
**Category:** Security / Resource Management

**Issue:** `Client::new()` uses reqwest defaults, which include **no connect
timeout and no read timeout**. Combined with the fire-and-forget
`tokio::spawn` in `audit_store.rs:169`, a slow or hung webhook endpoint
(dropped packets, attacker-controlled tarpit, half-open TCP) will pin a
tokio task indefinitely, holding the cloned `AuditEvent` and associated
buffers in memory. Under a burst of `DenyWithAlert` events against a hung
endpoint, memory grows unbounded until OOM.

The admin PUT path (`update_alert_config_handler`) validates the URL is
`https` and not loopback/link-local, but a malicious or misconfigured admin
can still point the webhook at a remote tarpit.

**Fix:** Configure timeouts when building the client:

```rust
pub fn new(db: Arc<Database>) -> Self {
    let client = Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("reqwest client build (static config)");
    Self { db, client }
}
```

The same reasoning applies to the SMTP path — consider passing a
`.timeout(Duration::from_secs(10))` equivalent to the lettre transport
builder (lettre exposes `timeout()` on `AsyncSmtpTransportBuilder`).

---

### HI-02: `send_email` rebuilds the SMTP transport on every call

**File:** `dlp-server/src/alert_router.rs:263-268`
**Severity:** HIGH (correctness + resource)
**Category:** Code Quality / Resource Management

**Issue:** `AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(...).port(...).credentials(...).build()`
is called inside `send_email`, i.e. for **every alert**. `lettre`'s SMTP
transport is designed to be constructed once and reused — it maintains an
internal connection pool and can amortize the STARTTLS handshake.
Rebuilding on every send means:

1. A fresh DNS lookup and TCP+TLS handshake per alert.
2. Credentials are cloned on every send (line 263).
3. Under a burst of `DenyWithAlert` events, you spawn N tasks each opening
   N independent SMTP connections.

Combined with HI-01 (no timeout on the HTTP client) this amplifies the
blast radius when the SMTP server is slow.

**Fix:** Because config is hot-reloaded, you cannot cache the transport as
a permanent field on `AlertRouter` without invalidating on config change.
Options:

- **Option A (recommended):** Cache transport keyed by `(host, port, username)`
  hash; rebuild only when the key changes. Store as
  `parking_lot::RwLock<Option<(CacheKey, AsyncSmtpTransport<...>)>>` on
  `AlertRouter`. Invalidate on mismatch.
- **Option B (simpler, defer):** Accept the per-call cost and document that
  alert volume is expected to be low. File a follow-up ticket.

Given TM-04 explicitly pushes observability/optimization to a later phase,
Option B with an explicit
`// TODO(phase-N): cache SMTP transport keyed by config hash` comment is
acceptable for this PR. The HIGH severity is for visibility, not to block
the merge.

---

## Medium

### ME-01: GET `/admin/alert-config` returns `smtp_password` and `webhook_secret` in plaintext

**File:** `dlp-server/src/admin_api.rs:721-763`
**Severity:** MEDIUM
**Category:** Security (secret exposure)

**Issue:** The GET handler SELECTs `smtp_password` and `webhook_secret`
from the DB and returns them verbatim in the response body. Any admin
with a valid JWT can retrieve plaintext secrets via
`curl -H "Authorization: Bearer …" https://host/admin/alert-config`.

The TUI masks for display (`render.rs:322-328`), but the masking happens
client-side **after** the plaintext has already crossed the wire. This means:

1. Any admin can exfiltrate SMTP credentials over HTTPS (today the system
   has a single `dlp-admin` superuser, so the practical blast radius is
   limited, but the contract is still "plaintext on the wire").
2. The plaintext appears in server access logs if any middleware logs bodies.
3. Backup/export of API responses leaks secrets.

This is consistent with the Phase 3.1 SIEM config precedent
(`splunk_token` / `elk_api_key` are also returned plaintext), so it is a
**consistency-level** finding rather than a new regression. However,
reviewing Phase 4 is the right time to flag both.

**Fix (recommended, deferred acceptable):** Return `"***"` or an empty
string for the two secret fields on GET, and teach the TUI save path to
preserve the stored secret when the buffer still equals `"***"` (i.e.,
distinguish "user kept the mask" from "user cleared the field"). This is
the standard admin-API secret-handling pattern and is directly what the
review brief target #6 asks about.

If you accept the current contract per TM-01, document it explicitly in
the phase SUMMARY and the follow-up phase that eventually addresses
encryption-at-rest. The SIEM config in Phase 3.1 has the same property
and should be updated at the same time for consistency.

---

### ME-02: `send_email` partial-failure leaves remaining recipients unsent

**File:** `dlp-server/src/alert_router.rs:270-286`
**Severity:** MEDIUM
**Category:** Correctness

**Issue:** The `for recipient in &config.to` loop uses `?` on
`mailer.send(email).await` (line 282-285). If the first recipient fails
(e.g., one bad address in a 5-address distribution list), the function
returns `Err` and the remaining 4 recipients are never attempted. For
multi-recipient alerts this is wrong — security operations teams expect
best-effort delivery across all recipients, mirroring the best-effort
channel semantics at the outer `send_alert` level.

**Fix:** Collect per-recipient errors into a `Vec<AlertError>`, continue
the loop, and return the first error only after the loop completes
(mirroring the pattern already used in `send_alert` at lines 187-232):

```rust
let mut errors = Vec::new();
for recipient in &config.to {
    let to_mailbox: Mailbox = match recipient.parse() {
        Ok(mb) => mb,
        Err(e) => {
            tracing::warn!(recipient, error = %e, "invalid to address, skipping");
            errors.push(AlertError::Email(format!("invalid to address {recipient}: {e}")));
            continue;
        }
    };
    let email = match Message::builder()
        .from(from_mailbox.clone())
        .to(to_mailbox)
        .subject(&subject)
        .body(body.clone())
    {
        Ok(m) => m,
        Err(e) => {
            errors.push(AlertError::Email(format!("message build error for {recipient}: {e}")));
            continue;
        }
    };
    if let Err(e) = mailer.send(email).await {
        tracing::warn!(recipient, error = %e, "SMTP send failed for recipient");
        errors.push(AlertError::Email(format!("SMTP send error to {recipient}: {e}")));
    }
}
if let Some(e) = errors.into_iter().next() {
    return Err(e);
}
```

---

### ME-03: `load_config` holds the DB mutex inside an async fn — intentional, but asymmetry with PUT path deserves a doc pointer

**File:** `dlp-server/src/alert_router.rs:136-168`
**Severity:** MEDIUM (policy consistency)
**Category:** Code Quality

**Issue:** `load_config` calls `self.db.conn().lock()` directly inside an
async context. CLAUDE.md `db.rs:5` says "All axum handlers should wrap DB
calls in `tokio::task::spawn_blocking`". The doc comment at lines 128-130
explicitly defends the choice (single-row SELECT, matches
`SiemConnector::load_config` precedent). That's fine, but the defense
should also cover the admin PUT path in `admin_api.rs:790-814`, which
**does** use `spawn_blocking` for the same table. The asymmetry is
intentional but non-obvious:

- `update_alert_config_handler` PUT: wraps in `spawn_blocking` because it
  writes under a transaction (long-ish lock).
- `AlertRouter::load_config` (called from `send_alert`): does not wrap
  because it's a single-row SELECT on the fire-and-forget alert path.

**Fix:** No code change required. Add one line to the `load_config` doc
comment cross-referencing the `admin_api.rs` PUT path and noting the
asymmetry is deliberate, so the next reviewer doesn't "fix" one to match
the other.

---

## Low

### LO-01: `send_alert` collects all channel errors but returns only the first

**File:** `dlp-server/src/alert_router.rs:187-232`
**Severity:** LOW
**Category:** Correctness / API Design

**Issue:** `let mut errors: Vec<AlertError> = Vec::new();` collects both
SMTP and webhook errors, then `errors.into_iter().next()` returns the first
one. The second error is silently dropped at the return level (it **is**
logged at `warn!` inside each branch so the operator sees it). This is
fine for TM-04, but:

- A future test that asserts "webhook error was returned when SMTP
  succeeded and webhook failed" is correct.
- A test that asserts "both errors were returned" would fail silently.

**Fix:** Either (a) add a doc comment to `send_alert` explicitly noting
"returns the first error encountered; all errors are logged at `warn!`",
or (b) collapse the Vec to an `Option<AlertError>` since only the first
matters. No runtime change needed; this is a documentation nit.

---

### LO-02: `send_email` subject-line extraction round-trips through `serde_json::Value`

**File:** `dlp-server/src/alert_router.rs:242-250`
**Severity:** LOW
**Category:** Code Quality / Defensive programming

**Issue:** The chain
`serde_json::to_value(event.event_type).unwrap_or_default().as_str().unwrap_or("UNKNOWN")`
is tolerant (two `unwrap_or`s) but roundtripping through
`serde_json::Value` just to extract an enum discriminant string is
wasteful and fragile. If `EventType` ever gains a tuple/struct variant,
`as_str()` returns `None` and the subject silently becomes "UNKNOWN".

**Fix:** In a follow-up phase, add `impl Display for EventType` in
`dlp-common/src/audit.rs` (or a `const fn as_str(&self) -> &'static str`)
and replace the chain with
`format!("[DLP ALERT] {} on {} by {}", event.event_type, event.resource_path, event.user_name)`.
Not a blocker for Phase 4.

---

### LO-03: `audit_store::ingest_events` clones the full event batch twice on the hot path

**File:** `dlp-server/src/audit_store.rs:77, 147-151`
**Severity:** LOW
**Category:** Performance

**Issue:** Line 77 clones `events` → `relay_events` (for SIEM). Lines
147-151 then iterate `relay_events` and `.cloned()` the `DenyWithAlert`
subset into `alert_events`. So each `DenyWithAlert` event is cloned twice:
once into `relay_events`, again into `alert_events`. For a burst of N
events this is 2N allocations of each `AuditEvent`.

This is documented as `G7` in the code comment, so it was considered. For
now the cost is bounded by batch size and `AuditEvent`'s size is small
(a few hundred bytes). Low priority.

**Fix (optional):** Wrap events in `Arc<AuditEvent>` at ingestion time so
the spawns share ownership instead of cloning. Requires downstream type
changes to `SiemConnector::relay_events` and `AlertRouter::send_alert`.
Defer to a future optimization phase.

---

## Info

### IN-01: `dlp-server/Cargo.toml` `url = "2"` — version matches reqwest's transitive dep

**File:** `dlp-server/Cargo.toml:36`
**Severity:** INFO
**Category:** Dependency hygiene

**Note:** `cargo tree -p dlp-server --depth 2 | grep url` confirms
`url v2.5.8` is the only resolved version and is shared with reqwest's
transitive `url` dep. No duplicate linkage. Default features on `url 2.x`
include `idna` and `percent-encoding`, both of which are used implicitly
by the parser in `validate_webhook_url`. Fine as-is. The review brief
target #8 is satisfied.

---

### IN-02: `audit_store.rs` fire-and-forget spawn is correctly isolated from panics

**File:** `dlp-server/src/audit_store.rs:156-176`
**Severity:** INFO (positive finding)
**Category:** Concurrency

**Note:** Verified:

- Uses `tokio::spawn(async move { ... })` with NO `.await` in the ingest
  handler path (lines 156, 169).
- `alert_events` is a `Vec<AuditEvent>` moved into the closure (not a
  reference), so borrow checker passes without needing `Arc`.
- The filter predicate `matches!(e.decision, dlp_common::Decision::DenyWithAlert)`
  matches the exact variant in `dlp-common/src/abac.rs:53`.
- A panic inside the spawned task will abort only that task; tokio does
  not propagate task panics to the runtime. Ingest latency is unaffected
  by alert I/O.
- `state.alert.clone()` at line 168 is cheap — `AlertRouter` contains an
  `Arc<Database>` and a `reqwest::Client`, both of which are Arc-backed
  and clone to bump refcounts.

Correct implementation. Review brief target #1 is satisfied.

---

### IN-03: Admin API auth — `/admin/alert-config` is correctly behind JWT middleware

**File:** `dlp-server/src/admin_api.rs:281-300`
**Severity:** INFO (positive finding)
**Category:** Authentication

**Note:** Both `/admin/alert-config` routes are added to `protected_routes`
(lines 298-299) **before** the
`.layer(middleware::from_fn(admin_auth::require_auth))` call at line 300.
The `test_get_alert_config_requires_auth` integration test at lines
1019-1045 exercises this end-to-end and asserts 401 Unauthorized for an
unauthenticated GET. Correct. Review brief target #4 is satisfied.

---

### IN-04: TUI save payload correctly sends `smtp_port` as JSON Number

**File:** `dlp-admin-cli/src/screens/dispatch.rs:911-912`
**Severity:** INFO (positive finding)
**Category:** Type safety across API boundary

**Note:** Lines 911-912 explicitly write
`serde_json::Value::Number(serde_json::Number::from(port))` after parsing
the buffer as `u16`. This matches the server-side `smtp_port: u16` in
`AlertRouterConfigPayload` (`admin_api.rs:132`) and the `G9` comment in
the TUI documents the exact contract.

Also verified:

- Bool toggles (line 969) use `Value::Bool`, not `Value::String`.
- Text fields (line 933) use `Value::String`.
- The System menu navigates with `nav(selected, 5, key.code)` (5 items:
  Server Status, Agent List, SIEM Config, Alert Config, Back) and the
  render side (`render.rs:71-78`) lists the same 5 items in the same
  order. Menu extension 4→5 is consistent across render and dispatch.

All three payload shapes match the server's `#[derive(Deserialize)]`
expectations. Correct. Review brief target #5 is satisfied.

---

_Reviewed: 2026-04-10_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard (advisory, non-blocking)_
