# M006: Content Classification Engine

**Gathered:** 2026-05-05
**Status:** Ready for planning

## Project Description

Replace the hardcoded content classification in `dlp-common/src/classifier.rs` with a production-grade regex-based engine backed by admin-configurable rules stored in SQLite, synced to agents, and manageable through the admin TUI. Ship a built-in PII pattern library covering common data types (SSN, credit card, passport, phone, IBAN) organized by regulatory category.

## Why This Milestone

The current classifier is the weakest link in the DLP pipeline. It uses hand-rolled substring matching for only SSN and credit card patterns, plus 6 keywords. Everything is hardcoded — admins cannot add, modify, or disable detection patterns without recompiling the agent. The 8KB scan limit means most document content is never inspected. This milestone makes the classification engine admin-configurable, extensible, and production-ready.

## User-Visible Outcome

### When this milestone is complete, the user can:

- Create regex-based classifier rules from the admin TUI or API, specifying pattern, classification tier, category, and description
- See rules propagate to all agents within 30 seconds
- Observe the agent detecting PII types it couldn't before (passport numbers, phone numbers, IBAN) from built-in patterns
- Disable or modify any built-in pattern to match organizational needs
- Filter rules by regulatory category (GDPR, HIPAA, PCI-DSS)

### Entry point / environment

- Entry point: Admin TUI (`dlp-admin-cli`) and REST API (`dlp-server`)
- Environment: Windows endpoint (agent), any machine with TUI/API access (admin)
- Live dependencies involved: SQLite database, agent-server HTTP sync

## Completion Class

- Contract complete means: unit tests prove every built-in pattern (true positive + false positive), integration tests prove rule CRUD + sync round-trip, `cargo test` passes
- Integration complete means: agent actually classifies file content using server-synced rules in a running system
- Operational complete means: migration from hardcoded to dynamic rules has no detection gap; agent falls back to built-in patterns when server unreachable

## Final Integrated Acceptance

To call this milestone complete, we must prove:

- Admin creates a custom regex rule via TUI → agent syncs it → file matching that pattern is classified at the specified tier
- All built-in PII patterns detect their target data types in sample content
- Removing all server-synced rules causes agent to fall back to built-in defaults (no detection gap)
- Existing hardcoded patterns produce identical classification results when converted to regex equivalents

## Scope

### In Scope

- Regex-based classification engine in `dlp-common` using the `regex` crate
- Built-in PII pattern library: SSN (US), credit card (Luhn-validated), passport (US/UK/EU formats), phone (E.164 + common national formats), IBAN, email address
- `classifier_rules` SQLite table with CRUD via admin API
- Rule sync endpoint for agents (piggyback on existing config poll)
- Admin TUI screen for rule management (list, create, edit, delete, toggle, category filter)
- Configurable scan depth (default 64KB, max 1MB) via agent config
- Migration from hardcoded patterns to DB-stored equivalent rules
- Rule categories: GDPR, HIPAA, PCI-DSS, CUSTOM
- Documentation updates: SRS, ARCHITECTURE.md, CONFIGURATION.md

### Out of Scope / Non-Goals

- PDF/DOCX/XLSX parsing — raw bytes + UTF-8 lossy only for M006
- ML/AI classification — deterministic regex only
- Document fingerprinting — pattern matching, not document identity
- Exact data matching — generic patterns, not organization-specific data
- Real-time push — continues using 30s polling
- Luhn checksum validation in the agent hot path (too expensive per-file; just regex shape)

## Architectural Decisions

### Regex engine: `regex` crate

**Decision:** Use the Rust `regex` crate for all pattern matching.

**Rationale:** The `regex` crate guarantees linear-time matching (no catastrophic backtracking), which is critical since pattern matching runs on every file write in the agent's event loop. The crate is mature, widely used, and already idiomatic Rust. The existing code comments explicitly reference it as the production target.

**Alternatives Considered:**
- `fancy-regex` — Supports lookaround/backreferences but loses linear-time guarantee. ReDoS risk on the hot path is unacceptable.
- `aho-corasick` — Multi-pattern string matching, but doesn't support regex syntax. Would require two engines.
- Hand-rolled patterns — Current approach. Not extensible, not admin-configurable.

### Rule storage: SQLite `classifier_rules` table

**Decision:** Store classifier rules in the existing SQLite database alongside policies, served via admin API.

**Rationale:** Follows the established pattern — policies, device registry, SIEM config, alert config, LDAP config all use SQLite + admin API + TUI. No new infrastructure needed. Agent syncs rules via the same HTTP polling mechanism used for config.

**Alternatives Considered:**
- Embedded rules in agent TOML — Not centrally manageable; no audit trail; divergence risk across fleet.
- Separate rule service — Over-engineered for the scale; adds a deployment dependency.

### Rule sync: extend existing agent config poll

**Decision:** Agent fetches classifier rules via a new GET endpoint during its existing 30-second config poll cycle.

**Rationale:** The agent already polls the server every 30s for config updates (`agent-config/{id}`). Adding a classifier rules endpoint to the same poll cycle is minimal code change and reuses the existing retry/fallback infrastructure.

**Alternatives Considered:**
- Embed rules in the agent config response — Couples rule versioning to config versioning; bloats the config payload.
- WebSocket push — Deferred (R025); 30s latency is acceptable for rule changes that happen infrequently.

### Classification architecture: compiled `RegexSet` per sync cycle

**Decision:** Agent compiles all active rules into a `RegexSet` when rules are synced, then uses the pre-compiled set for all classifications until next sync.

**Rationale:** `RegexSet` allows matching against all patterns in a single pass over the input text, which is O(n) in text length regardless of rule count. Recompiling every 30s (only when rules change) amortizes the compilation cost.

**Alternatives Considered:**
- Individual `Regex::is_match()` per rule — O(n * rule_count) per file. Unacceptable with 50+ rules.
- Lazy compilation on first use — Unpredictable latency on first file after sync.

### Scan depth: configurable, default 64KB

**Decision:** Increase default scan depth from 8KB to 64KB, make it configurable via agent config with a hard cap at 1MB.

**Rationale:** 8KB misses content in the body of most documents. 64KB covers headers, metadata, and early content in typical office documents. The hard cap prevents OOM on adversarial inputs. Making it configurable lets admins tune the tradeoff between detection coverage and performance.

**Alternatives Considered:**
- Full file scan — OOM risk on large files; unacceptable latency on the hot path.
- Fixed 64KB — Simple but removes admin flexibility for environments with different file size distributions.

## Error Handling Strategy

- **Invalid regex at creation time:** Reject with HTTP 400 and clear error message (regex crate's parse error). Never store a rule that won't compile.
- **Rule sync failure:** Agent uses last-known-good rule set from local cache. If no cache exists and server is unreachable, agent falls back to built-in default patterns compiled into the binary.
- **Pattern match timeout:** Not applicable — the `regex` crate guarantees linear-time matching. No timeout needed.
- **File read failure during classification:** Log warning via `tracing::warn!`, classify as T1 (Public) — existing behavior preserved.
- **DB migration failure:** Server refuses to start if classifier_rules table creation fails; admin must fix DB manually.
- **Regex compilation failure after sync:** Log error, skip the invalid rule, use remaining valid rules. Never crash the agent over a bad rule.

## Risks and Unknowns

- **RegexSet performance with 50+ rules** — Linear-time guarantee per pattern, but compilation time and memory for large sets is untested. Need to validate in S05.
- **False positive rate of built-in patterns** — Phone number regex in particular is prone to false positives (any 10-digit number). Need careful pattern design with contextual anchors.
- **Migration continuity** — Transition from hardcoded to synced rules must be seamless. If server is down during migration window, agent must still detect.

## Existing Codebase / Prior Art

- `dlp-common/src/classifier.rs` — Current hardcoded classifier. `classify_text(&str) -> Classification` is the entry point. Checks SSN (11-char windows), credit card (16+ consecutive digits), 6 keywords. Falls back to T1.
- `dlp-common/src/classification.rs` — `Classification` enum (T1-T4) with `PartialOrd`, `is_sensitive()`, `label()`. This stays unchanged.
- `dlp-agent/src/interception/policy_mapper.rs` — `provisional_classification()` uses `classify_text` + hardcoded path prefixes. Must be updated to use synced rules.
- `dlp-server/src/db/repositories/mod.rs` — Repository pattern for all DB access. New `ClassifierRulesRepository` follows this pattern.
- `dlp-server/src/admin_api.rs` — 5400+ lines, all admin endpoints. New classifier rule endpoints follow the same handler pattern (spawn_blocking + DB).
- `dlp-server/src/policy_store.rs` — In-memory cache with RwLock, background refresh, immediate invalidation. Classifier rule cache should follow this exact pattern.
- `dlp-admin-cli/src/screens/` — Screen enum state machine. New ClassifierRules screen follows DeviceList / PolicyList patterns.
- `dlp-agent/src/config.rs` — Agent config polling. Classifier rule sync extends this.

## Relevant Requirements

- R013 — Regex-based engine (core of S01)
- R014 — Admin API for rules (core of S02)
- R015 — Built-in PII patterns (S01 seed data)
- R016 — Rule sync (core of S03)
- R017 — TUI screen (core of S04)
- R018 — Rule categories (S02 schema, S04 filtering)
- R019 — Configurable scan depth (S05)
- R020 — Migration continuity (S03)
- R021 — Documentation (S06)

## Technical Constraints

- `regex` crate only (no `fancy-regex`) — linear-time guarantee is non-negotiable on the hot path
- Agent must never block on rule sync — if server unreachable, use cached or built-in rules
- New DB table must be created via the existing `ensure_tables()` pattern in `db/mod.rs`
- Admin API endpoints must follow existing rate limiting patterns
- TUI screens must follow Screen enum + key handler + async HTTP pattern
- All new code must pass `cargo clippy -- -D warnings` and `cargo fmt --check`

## Integration Points

- `dlp-server` SQLite DB — new `classifier_rules` table
- `dlp-server` admin API — new CRUD endpoints for rules
- `dlp-agent` config sync — new GET endpoint for rule fetch
- `dlp-common` classifier — rewritten to accept dynamic rules
- `dlp-user-ui` clipboard classifier — uses the same `classify_text` from dlp-common
- `dlp-admin-cli` TUI — new screen for rule management

## Testing Requirements

- Unit tests for every built-in pattern: at least 3 true positives and 3 false positives per pattern
- Unit tests for `RegexSet` compilation and matching
- Unit tests for rule CRUD repository operations
- Integration test: create rule via API → verify it appears in GET response
- Integration test: agent syncs rules → classifies file content correctly
- `cargo test -p dlp-common` for classifier engine
- `cargo test -p dlp-server --lib` for API and DB tests
- Performance test in S05: 50+ rules, measure classification time per file

## Acceptance Criteria

### S01 (Regex Engine + Patterns)
- `classify_text` uses `RegexSet` with dynamic rules
- Built-in patterns for SSN, CC, passport, phone, IBAN, email all have passing tests
- False positive tests verify patterns don't match on benign content
- Performance: <5ms to classify 64KB of text with 20 patterns

### S02 (Server API)
- CRUD endpoints for classifier_rules (POST, GET, PUT, DELETE)
- Regex validated at creation time (400 on invalid regex)
- Category field supported (GDPR, HIPAA, PCI-DSS, CUSTOM)
- Audit events emitted on rule CRUD

### S03 (Agent Sync + Migration)
- Agent fetches rules via new endpoint during config poll
- Agent compiles rules into RegexSet on receipt
- Hardcoded patterns replaced by equivalent DB rules
- Offline fallback: cached rules → built-in defaults

### S04 (TUI)
- List rules with name, pattern preview, tier, category, enabled
- Create rule with regex validation feedback
- Edit, delete, toggle enabled
- Filter by category

### S05 (Scan Depth + Performance)
- Scan depth configurable via agent config
- Default 64KB, hard cap 1MB
- Performance test: <5ms per file with 50+ rules at 64KB

### S06 (Docs)
- SRS updated with new classification architecture
- ARCHITECTURE.md updated with classifier rule flow
- CONFIGURATION.md updated with scan depth and rule management
- GETTING-STARTED.md updated if onboarding steps changed

## Documentation Priority

The user explicitly requested that docs are updated so they can track what has been done. Documentation (S06) is not just a "nice to have" — it is a hard requirement. Docs must reflect the current state of the system after each slice ships, covering:
- What the classification engine can do now
- How to manage rules (admin guide)
- What patterns ship built-in
- How to configure scan depth
- Architecture changes from prior versions

## Open Questions

- None — all decisions resolved during discussion
