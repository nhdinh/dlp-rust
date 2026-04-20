# Phase 18: Boolean Mode Engine + Wire Format - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-20
**Phase:** 18-boolean-mode-engine-wire-format
**Areas discussed:** PolicyMode enum shape, DB migration strategy, Empty-conditions edge cases, serde default for missing mode

---

## PolicyMode Enum Shape

### Q1: Where should the PolicyMode enum live?

| Option | Description | Selected |
|--------|-------------|----------|
| dlp-common::abac (Recommended) | Co-locate with Policy struct; shared by server + future crates; matches Decision/PolicyCondition location. | OK |
| dlp-server::admin_api only | Wire-format-only; dlp_common::abac::Policy needs a separate internal representation; creates a mapping layer. | |

**User's choice:** dlp-common::abac

### Q2: JSON serialization form for the mode values?

| Option | Description | Selected |
|--------|-------------|----------|
| SCREAMING "ALL"/"ANY"/"NONE" (Recommended) | Matches Decision (ALLOW/DENY) precedent and REQUIREMENTS.md wording verbatim; no rename needed. | OK |
| PascalCase "All"/"Any"/"None" | Matches DeviceTrust/NetworkLocation precedent via serde(rename_all = "PascalCase"). | |
| lowercase "all"/"any"/"none" | Matches AccessContext precedent; most compact on wire. | |

**User's choice:** SCREAMING "ALL" / "ANY" / "NONE"

### Q3: How should downstream code get a default PolicyMode?

| Option | Description | Selected |
|--------|-------------|----------|
| derive(Default) with ALL as default (Recommended) | Mark ALL with #[default]; enables serde(default) on wire types cleanly. | OK |
| No Default, explicit mode everywhere | Every construction names the mode; needs a helper fn default_mode() for serde(default). | |

**User's choice:** derive(Default) with ALL

### Q4: Should Policy also gain a Default impl to spare 15+ PolicyStore test fixtures?

| Option | Description | Selected |
|--------|-------------|----------|
| Yes — derive Default on Policy (Recommended) | Tests use Policy { ..Default::default() }; matches Subject/Resource/Environment precedent. | OK |
| No — update each fixture explicitly | Keep Policy without Default; update ~15 test fixtures. | |

**User's choice:** Yes — derive Default on Policy

---

## DB Migration Strategy

### Q1: How should Phase 18 migrate existing databases to add the policies.mode column?

| Option | Description | Selected |
|--------|-------------|----------|
| CREATE TABLE with mode + ALTER TABLE catches duplicate-column error (Recommended) | Fresh DBs get the column in CREATE TABLE; existing DBs get ALTER TABLE ADD COLUMN with message-match error swallow. Idempotent. Matches STATE.md promised pattern. | OK |
| PRAGMA table_info pre-check | Query before ALTER; no error-swallowing; extra query on startup. | |
| Formal schema_version table | First migration infrastructure; overkill for one migration. | |

**User's choice:** CREATE TABLE + ALTER TABLE with duplicate-column error swallow

### Q2: Where should the ALTER TABLE live in the codebase?

| Option | Description | Selected |
|--------|-------------|----------|
| New run_migrations() in db/mod.rs, called after init_tables() (Recommended) | Keeps init_tables CREATE-only; future column-adds append in one place. | OK |
| Inline ALTER inside init_tables() | Smallest diff; mixes CREATE and ALTER semantics. | |

**User's choice:** New run_migrations() fn in db/mod.rs, called after init_tables()

### Q3: How do we test the migration path works from an existing (no-mode) database?

| Option | Description | Selected |
|--------|-------------|----------|
| Dedicated unit test with pre-created legacy table (Recommended) | In-memory DB, manually CREATE v0.4.0 policies table, insert sample row, call run_migrations(), assert column + backfill. | OK |
| Rely on integration + PolicyStore tests | Trust SQLite's ALTER behavior; no project-specific test. | |

**User's choice:** Dedicated unit test that pre-creates a legacy policies table

---

## Empty-conditions Edge Cases

### Q1: How should the evaluator treat a policy with an empty conditions list under each mode?

| Option | Description | Selected |
|--------|-------------|----------|
| Natural short-circuit semantics (Recommended) | ALL+[]=match, ANY+[]=no-match, NONE+[]=match; lean on iterator defaults; documented via tests. | OK |
| Force ANY+[] and NONE+[] to no-match | Safer default; extra branch; asymmetric with ALL+[]. | |
| Forbid empty conditions when mode is ANY or NONE | Server 400 rejection; cleanest semantics but new wire constraint not in REQUIREMENTS.md. | |

**User's choice:** Natural short-circuit semantics

### Q2: Should the create/update handlers validate conditions length at all?

| Option | Description | Selected |
|--------|-------------|----------|
| No — accept any length including 0 (Recommended) | Preserves v0.4.0 contract exactly; tests document edges. | OK |
| Yes — require conditions.len() >= 1 | Tighter invariant; potentially breaks any zero-condition v0.4.0 policies. | |

**User's choice:** No — accept any length including 0

---

## Serde Default for Missing Mode

### Q1: How to implement the "legacy payload without mode defaults to ALL" contract?

| Option | Description | Selected |
|--------|-------------|----------|
| serde(default) leans on PolicyMode::default()==ALL (Recommended) | One-line change per struct; zero helper fns; uniform with Default source-of-truth. | OK |
| serde(default = "default_mode") helper fn | Explicit but duplicates intent already captured by derive(Default). | |
| Option<PolicyMode> + unwrap_or(ALL) | More expressive (absent vs explicit ALL); leaks optionality. | |

**User's choice:** #[serde(default)] on mode field, relies on PolicyMode::default()==ALL

### Q2: How does deserialize_policy_row() handle the mode value read from DB?

| Option | Description | Selected |
|--------|-------------|----------|
| Parse row.mode as PolicyMode; migration guarantees non-null 'ALL' (Recommended) | Match on string; malformed triggers existing skip-with-warn path. | OK |
| Treat invalid mode strings as ALL silently | More lenient; hides data corruption. | |

**User's choice:** Parse row.mode as PolicyMode; migration guarantees non-null 'ALL'

### Q3: Which JSON deserialization tests prove POLICY-12 backward compat?

| Option | Description | Selected |
|--------|-------------|----------|
| Two tests on PolicyPayload + one on PolicyResponse + parity test (Recommended) | (a) no-mode payload, (b) mode=ANY roundtrip, (c) no-mode response, (d) parity: legacy vs explicit ALL evaluate identically. | OK |
| One round-trip test only | Single legacy-shaped payload round-trip; satisfies letter of criterion. | |

**User's choice:** Two unit tests on PolicyPayload + one on PolicyResponse (plus parity per D-25)

---

## Claude's Discretion

- Helper placement for the PolicyMode-to-SQL-string conversion (free fn, impl method, or inline match).
- Exact wording of the extended warn-log when deserialize_policy_row encounters a malformed mode.
- PolicyUpdateRow.mode as &str vs &PolicyMode — match surrounding field style.

## Deferred Ideas

- TUI mode picker (Phase 19).
- Expanded operators (Phase 20).
- In-place condition editing (Phase 21).
- Nested expression trees (out of milestone scope).
- Formal schema_version table (deferred; run_migrations idempotent ADD COLUMN suffices).
- Mode validation on create/update (considered, rejected; revisit on operational feedback).
- Batch import endpoint / POLICY-F5 (deferred to v0.5.x Server Hardening).
