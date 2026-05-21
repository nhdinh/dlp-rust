---
phase: 62-syslog-forwarder
plan: 04
subsystem: agent

tags: [sqlite, rusqlite, dpapi, offline-queue, audit-emitter, heartbeat, syslog]

requires:
  - phase: 62-03
    provides: offline_audit_queue module with init, enqueue, drain, delete, count, lock

provides:
  - Agent SQLite DB initialised on startup with offline_audit_queue table
  - Audit emitter fallback to offline queue when server relay unavailable
  - Synthetic queue_overflow audit event on AtCapacity (R-62-16)
  - Heartbeat-driven drain loop with atomic single-worker guard
  - Pre-serialised JSON event forwarding via send_audit_events_json

affects:
  - dlp-agent runtime event pipeline
  - dlp-server audit event ingestion

tech-stack:
  added: []
  patterns:
    - "OnceLock<Mutex<Connection>> for global SQLite access across sync/async boundary"
    - "spawn_blocking for all SQLite ops in async contexts"
    - "Atomic compare_exchange drain lock for single-worker queue drain"
    - "Synthetic audit event emission for operational health signals"

key-files:
  created: []
  modified:
    - dlp-agent/src/offline_audit_queue.rs - enqueue_with_overflow_event helper
    - dlp-agent/src/service.rs - AGENT_DB static, init_agent_db(), init_table call
    - dlp-agent/src/audit_emitter.rs - offline queue fallback + synthetic queue_overflow event
    - dlp-agent/src/server_client.rs - send_audit_events_json(), flush fallback enqueue
    - dlp-agent/src/offline.rs - heartbeat success drain loop with try_acquire_drain_lock

key-decisions:
  - "Wrapped rusqlite::Connection in std::sync::Mutex inside OnceLock because Connection is not Sync"
  - "Used spawn_blocking for all SQLite operations in async heartbeat_loop to satisfy Send bounds"
  - "Emitted synthetic queue_overflow as EventType::AdminAction with resource_path=queue_overflow"
  - "Chose heartbeat_loop (not server_client.rs) for drain to reuse existing server_connected detection"

patterns-established:
  - "Global DB static: OnceLock<Mutex<Connection>> with accessor function returning Option<&Mutex<Connection>>"
  - "Async-safe SQLite: always spawn_blocking, never hold Connection ref across .await"
  - "Single-worker drain: AtomicBool compare_exchange acquire/release ordering"

requirements-completed:
  - SYSLOG-03
  - SYSLOG-04

metrics:
  duration: 45min
  completed: 2026-05-14T11:47:42Z
---

# Phase 62 Plan 04: Gap Closure — Wire Offline Audit Queue into Production Pipeline

**Agent-side offline audit queue fully operational: init on startup, enqueue on server failure, drain on heartbeat success, synthetic queue_overflow on AtCapacity**

## Performance

- **Duration:** 45 min
- **Started:** 2026-05-14T11:02:00Z
- **Completed:** 2026-05-14T11:47:42Z
- **Tasks:** 1 (single composite task)
- **Files modified:** 5

## Accomplishments

- Closed verification gap #18: `offline_audit_queue` now called from production code
- Closed verification gap #19: synthetic `queue_overflow` audit event emitted on AtCapacity
- Agent startup initialises SQLite DB and `offline_audit_queue` table
- Audit emitter falls back to offline queue when `AUDIT_BUFFER` is unavailable
- Failed audit buffer flushes enqueue events instead of dropping them
- Heartbeat success triggers drain with `try_acquire_drain_lock` single-worker guard
- Drained events forwarded via HTTP, deleted only after server confirms receipt

## Task Commits

1. **Task 1: Add enqueue_with_overflow_event helper** — `e2abd66` (feat)
2. **Task 1: Initialise agent DB and queue table on startup** — `f4afe56` (feat)
3. **Task 1: Wire offline queue fallback + synthetic queue_overflow event** — `ac73252` (feat)
4. **Task 1: Enqueue failed flushes + send_audit_events_json** — `298fc23` (feat)
5. **Task 1: Drain on heartbeat success with atomic lock guard** — `d7d999c` (feat)

## Files Created/Modified

- `dlp-agent/src/offline_audit_queue.rs` — Added `enqueue_with_overflow_event()` helper that serialises `AuditEvent` to JSON and calls `enqueue()`; returns `AtCapacity` for caller to handle
- `dlp-agent/src/service.rs` — Added `AGENT_DB` static (`OnceLock<Mutex<Connection>>`), `init_agent_db()` function, call during `run_loop_init`; exports `agent_db()` accessor
- `dlp-agent/src/audit_emitter.rs` — When `AUDIT_BUFFER` not set, enqueues to offline queue; on `AtCapacity`, emits synthetic `queue_overflow` `AuditEvent` to JSONL (R-62-16)
- `dlp-agent/src/server_client.rs` — `AuditBuffer::flush()` now enqueues failed events to offline queue; added `send_audit_events_json()` for pre-serialised JSON forwarding
- `dlp-agent/src/offline.rs` — `heartbeat_loop()` drains offline queue on successful heartbeat using `try_acquire_drain_lock` / `release_drain_lock`; SQLite ops run in `spawn_blocking`

## Decisions Made

- **Mutex-wrapped Connection**: `rusqlite::Connection` is not `Sync`, so it cannot live in `OnceLock` directly. Wrapped in `std::sync::Mutex` — callers lock briefly for each operation.
- **spawn_blocking for SQLite in async**: The heartbeat loop is async but SQLite is sync. All queue operations (count, drain, delete) run inside `tokio::task::spawn_blocking` to avoid blocking the reactor and to satisfy `Send` bounds.
- **Synthetic event shape**: Used `EventType::AdminAction` with `resource_path = "queue_overflow"` and `agent_id` copied from the original event. This makes it filterable in SIEM without introducing a new event type.
- **Drain in offline.rs vs server_client.rs**: The heartbeat loop already detects `server_connected` — placing drain there avoids duplicating the connectivity check and keeps server-client focused on HTTP transport.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 — Bug] rusqlite::Connection not Sync — compilation failure**
- **Found during:** Task 1 (service.rs AGENT_DB static)
- **Issue:** `static AGENT_DB: OnceLock<rusqlite::Connection>` fails because `Connection` contains `RefCell` and is not `Sync`
- **Fix:** Wrapped in `std::sync::Mutex<rusqlite::Connection>`; updated all callers to `.lock()` before use
- **Files modified:** `dlp-agent/src/service.rs`, `dlp-agent/src/audit_emitter.rs`, `dlp-agent/src/server_client.rs`, `dlp-agent/src/offline.rs`
- **Verification:** `cargo test --all --lib` passes, `cargo clippy -p dlp-agent -- -D warnings` clean
- **Committed in:** f4afe56, ac73252, 298fc23, d7d999c (part of respective commits)

**2. [Rule 1 — Bug] Connection not Send — async heartbeat_loop compilation failure**
- **Found during:** Task 1 (offline.rs drain integration)
- **Issue:** Holding `&rusqlite::Connection` across `.await` in `heartbeat_loop` violates `Send` bound for `tokio::spawn`
- **Fix:** Restructured drain logic to perform all SQLite ops inside `tokio::task::spawn_blocking` closures; async code only handles HTTP forwarding
- **Files modified:** `dlp-agent/src/offline.rs`
- **Verification:** `cargo test -p dlp-agent --lib` passes
- **Committed in:** d7d999c

**3. [Rule 3 — Blocking] Missing send_audit_events_json method**
- **Found during:** Task 1 (offline.rs drain forwarding)
- **Issue:** Offline queue stores raw JSON strings, but `ServerClient` only had `send_audit_events(&[AuditEvent])` which requires deserialising back to structs
- **Fix:** Added `send_audit_events_json(&[String])` that builds a JSON array body from pre-serialised strings
- **Files modified:** `dlp-agent/src/server_client.rs`
- **Verification:** `cargo test --all --lib` passes
- **Committed in:** 298fc23

---

**Total deviations:** 3 auto-fixed (2 Rule 1 bugs, 1 Rule 3 blocking issue)
**Impact on plan:** All auto-fixes were necessary for compilation and correctness. No scope creep.

## Issues Encountered

- `rusqlite::Connection` is neither `Sync` nor `Send` — required Mutex wrapping and spawn_blocking isolation
- Clippy flagged collapsible `if` in `offline.rs` — fixed by combining conditions

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- Phase 62 is complete. All 19 verification truths now pass.
- Agent queue is fully operational end-to-end.
- No blockers for subsequent phases.

---
*Phase: 62-syslog-forwarder*
*Completed: 2026-05-14*
