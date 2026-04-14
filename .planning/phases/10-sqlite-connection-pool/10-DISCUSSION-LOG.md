# Phase 10: SQLite Connection Pool — Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-14
**Phase:** 10-sqlite-connection-pool
**Areas discussed:** Pool crate selection, Pool API shape, Pool size, Pool configuration

---

## Area 1: Pool Crate Selection

| Option | Description | Selected |
|--------|-------------|----------|
| r2d2 | Mature (2015+), simple sync API, battle-tested. PoolManager::new(conn, config) wraps any Connection. | ✓ |
| deadpool-sqlite | Async-first, more complex. Better for future async DB ops. Adds async complexity to sync codebase. | |
| Custom pool | Keep Mutex<Connection> with multiple connections. Adds complexity without async benefit. | |

**User's choice:** r2d2 (Recommended)
**Notes:** User confirmed r2d2 as the recommended mature choice. deadpool rejected for async complexity.

---

## Area 2: Pool API Shape

| Option | Description | Selected |
|--------|-------------|----------|
| db.pool().get() | Minimal diff. Replace conn().lock() with pool.get().expect() everywhere. Keep Database::conn() returning the pool. | |
| db.get() method | Add db.get() returning Pooled<Connection>. Cleaner separation but requires renaming. | |
| Pool in AppState directly | AppState holds r2d2::Pool directly. Database wrapper removed. Most invasive but cleanest. | ✓ |

**User's choice:** Pool in AppState directly
**Notes:** User preferred direct pool exposure in AppState. The Database wrapper adds a layer with no benefit given the refactor scope.

---

## Area 3: Pool Size

| Option | Description | Selected |
|--------|-------------|----------|
| 5 | Modest. SQLite with WAL handles concurrent reads well, but writes serialize to one writer. 5 covers most real-world concurrency. | ✓ |
| 10 | More headroom. Overkill for SQLite's single-writer constraint but harmless. | |
| 3 | Minimal. Only useful if most requests complete very quickly. | |

**User's choice:** 5 (Recommended)
**Notes:** 5 is the right balance for SQLite's WAL concurrency profile. 10 was noted as acceptable but unnecessary.

---

## Area 4: Pool Configuration

| Option | Description | Selected |
|--------|-------------|----------|
| Hardcoded constant | Pool size is a const in db.rs. No new config surface. Works fine for v1. | ✓ |
| Environment variable | Read pool size from DLP_POOL_SIZE env var. More flexible but added surface for minimal benefit. | |

**User's choice:** Hardcoded constant (Recommended)
**Notes:** Consistent with the project's pattern of hardcoding infrastructure tuning details until they prove insufficient.

---

## Summary

All 4 gray areas resolved in a single pass. User confirmed all recommended defaults (r2d2, pool in AppState directly, size 5, hardcoded constant). No follow-up questions needed.
