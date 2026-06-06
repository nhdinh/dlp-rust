# Phase 63: Tamper-Evident Audit SHA-256 Hash Chain — Context

**Gathered:** 2026-06-06
**Status:** Ready for planning
**Source:** Handoff from paused execution session + existing plan `C:\Users\nhdinh\.claude\plans\inherited-weaving-papert.md`

<domain>
## Phase Boundary

Add cryptographic tamper detection to the DLP audit log so compliance audits can verify log integrity for T3/T4 events. Currently audit events are append-only JSONL with NTFS ACLs but no cryptographic protection. A SHA-256 hash chain provides integrity verification: each event's hash incorporates the previous event's hash, making undetected tampering computationally infeasible.

**In scope for this phase:**
- dlp-common hash chain helpers (`genesis_hash`, `canonical_json_for_hash`, `compute_chain_hash`)
- `AuditEvent` extensions (`prev_hash`, `chain_hash`)
- `EventType::ChainBreakDetected` with SIEM routing and alert triggering
- Server DB schema migration for `prev_hash` and `chain_hash` columns
- Agent-side chain computation in `AuditEmitter`
- Server-side chain verification on ingestion with tamper alert emission
- `GET /admin/audit/integrity` endpoint for periodic integrity reports

**Out of scope:**
- Merkle tree or signature-based verification (deferred)
- Cross-agent chain synchronization (each agent maintains independent chain)
- UI screen for integrity reports (admin API endpoint only)

**Already completed prior to this planning session (Wave 1 partial):**
- `dlp-common/Cargo.toml`: `sha2 = "0.10"` and `hex = "0.4"` added
- `dlp-common/src/audit.rs`: `EventType::ChainBreakDetected` added with `routed_to_siem()` and `triggers_alert()` wired
- `dlp-common/src/audit.rs`: `prev_hash: Option<String>` and `chain_hash: Option<String>` fields added to `AuditEvent` with `#[serde(default, skip_serializing_if = "Option::is_none")]`
- `dlp-common/src/audit.rs`: `genesis_hash()`, `canonical_json_for_hash()`, `compute_chain_hash()` helpers added

</domain>

<decisions>
## Implementation Decisions

### D-01: Hash fields live in `AuditEvent` with serde default

`prev_hash: Option<String>` and `chain_hash: Option<String>` added to `AuditEvent` in dlp-common with `#[serde(default, skip_serializing_if = "Option::is_none")]`. Old agents omit them; new agents include them. Server deserializes missing fields to `None`.

### D-02: Canonical JSON excludes hash fields

To avoid circular hashing, canonical JSON for hash computation serializes the event with hash fields temporarily excluded. A `canonical_json_for_hash()` helper in dlp-common does this via `serde_json::to_value`, removes hash keys, sorts keys deterministically, then returns a compact JSON string.

### D-03: Genesis hash is deterministic

`GENESIS_HASH = hex(sha256("DLP-AUDIT-CHAIN-v1-GENESIS"))` — hardcoded, documented, same across all agents and server. First event from any agent uses this as `prev_hash`.

### D-04: Per-agent chain verification on server

Each agent maintains its own independent chain. Server verifies `prev_hash` against the last stored `chain_hash` for that `agent_id`. Gaps across different agents are not chain breaks.

### D-05: Backward-compatible ingestion

Events without hash fields (from pre-Phase 63 agents) are accepted without verification. The server stores `NULL` for hash columns. Verification only triggers when `chain_hash` is present.

### D-06: Tamper alert is synthetic AuditEvent

On chain break, the server constructs a synthetic `AuditEvent` with `EventType::ChainBreakDetected`, `Decision::DenyWithAlert`, and routes it through `alert_router.send_alert()`. A new event type keeps tamper alerts distinct from policy blocks.

### Claude's Discretion

- Use `parking_lot::Mutex<String>` for `last_chain_hash` in `AuditEmitter` (consistent with existing `Mutex<BufWriter<File>>`)
- Implement JSONL tail-read recovery using `rev_buf_reader` or manual seek-to-near-end strategy
- Return `AuditIntegrityResponse` with summary counts and per-agent chain statuses

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Existing audit patterns
- `dlp-common/src/audit.rs` — `AuditEvent`, `EventType`, routing helpers
- `dlp-agent/src/audit_emitter.rs` — `AuditEmitter`, `emit_audit`, `EmitContext`
- `dlp-server/src/audit_store.rs` — `ingest_events`, `store_events_sync`
- `dlp-server/src/db/mod.rs` — schema definition, `run_alter`, `run_migrations`
- `dlp-server/src/db/repositories/audit_events.rs` — `AuditEventRepository`, `AuditEventRow`, `AuditEventFilter`
- `dlp-server/src/admin_api.rs` — route registration for admin endpoints
- `dlp-server/src/siem_connector.rs` — `relay_events` for SIEM routing
- `dlp-server/src/alert_router.rs` — `send_alert` for real-time alert emission

### Requirement source
- `.planning/PROJECT.md` — v0.11.0 scope; HASH-01..04 requirements
- `.planning/ROADMAP.md` — Phase 63 goal and success criteria

</canonical_refs>

<specifics>
## Specific Ideas

### Genesis hash constant
```rust
pub const GENESIS_HASH: &str = "b8c8a5c0e6e8e6f1e5e6e8e6f1e5e6e8e6f1e5e6e8e6f1e5e6e8e6f1e5e6e8";
```

### Hash computation
```rust
chain_hash = SHA256(prev_hash || canonical_json)
```
where `canonical_json` excludes `prev_hash` and `chain_hash` fields.

### DB schema changes
```sql
ALTER TABLE audit_events ADD COLUMN prev_hash TEXT;
ALTER TABLE audit_events ADD COLUMN chain_hash TEXT;
CREATE INDEX idx_audit_events_agent_chain ON audit_events(agent_id, id);
```

### Integrity endpoint contract
```rust
#[derive(Serialize)]
struct AuditIntegrityResponse {
    total_events: i64,
    verified_events: i64,
    chain_breaks: Vec<ChainBreak>,
    agents: Vec<AgentChainStatus>,
}
```

</specifics>

<deferred>
## Deferred Ideas

None — PRD covers phase scope.
</deferred>

---

*Phase: 63-tamper-evident-audit-sha-256-hash-chain*
*Context gathered: 2026-06-06 via handoff recovery*
