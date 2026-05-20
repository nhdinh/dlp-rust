# Plan 50-01 Summary: IPC Protocol Extension

**Status:** Complete
**Commit:** 5687d9a

## What Was Built

Extended the IPC protocol between hook DLL and agent to support cache versioning, cache hint warming, and operation-type discrimination.

### Changes

| File | Change |
|------|--------|
| `dlp-common/src/hook_ipc.rs` | Added HookOp, CacheHint, IpcEnvelope, IpcMessageV1, IpcPayloadV1, ProtocolError; extended HookRequest/HookResponse with cache_version, protocol_version, op, cache_hint; added version negotiation |
| `dlp-common/Cargo.toml` | Added `bincode = "1.3"` dev-dependency |

### Key Design Decisions

- **Versioned envelope (`IpcEnvelope`)** provides forward-compatible protocol evolution
- **Additive fields with `serde(default)`** preserve JSON backward compatibility
- **Bincode is pinned** to little-endian, fixed-width for serialization stability
- **Cache updates are SHM-only** — no `CacheDelta` pipe variant by design
- **Cache non-authoritative invariant** documented: ABAC authority is never bypassed

### Tests

14 unit tests pass covering:
- HookOp/CacheHint roundtrips
- IpcEnvelope V1 roundtrip
- Old request/response JSON deserialization with defaults
- New request/response bincode roundtrips
- Protocol version default (= 1)
- Version negotiation (same, newer hook, newer agent, zero versions)

### Verification

- `cargo test -p dlp-common` — 199 passed
- `cargo clippy -p dlp-common -- -D warnings` — clean
