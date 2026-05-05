# M006: Configurable Content Classification Engine

**Vision:** Replace hardcoded pattern matching with admin-configurable regex-based classification rules stored in SQLite, synced to agents, and managed through the admin TUI. Ship a built-in PII pattern library covering common data types organized by regulatory category.

## Success Criteria

- Admin creates a regex classifier rule via API or TUI; agent detects matching content within 30 seconds and emits correct classification tier
- Built-in PII patterns detect SSN, credit card, passport, phone, IBAN, and email with no false positives on common text
- Agent offline fallback: disconnected from server, agent still classifies using cached rules
- Migration from hardcoded to DB-stored rules produces identical classification results with zero detection gap
- Documentation reflects current system capabilities including classifier architecture and admin guide

## Slices

- [ ] **S01: Regex Classification Engine + Built-in Patterns** `risk:high` `depends:[]`
  > After this: Unit tests prove RegexClassifier matches SSN, CC, passport, phone, IBAN, email patterns correctly with zero false positives on benign text; classify_text uses dynamic rules instead of hardcoded logic

- [ ] **S02: Server API + DB Storage for Classifier Rules** `risk:medium` `depends:[S01]`
  > After this: Admin can POST/GET/PUT/DELETE classifier rules via API; invalid regex returns 400 with clear error; rules have category tags (GDPR, HIPAA, PCI-DSS, CUSTOM); seed migration populates built-in patterns on first start

- [ ] **S03: Agent Rule Sync + Runtime Classification** `risk:high` `depends:[S01,S02]`
  > After this: Agent running on Windows fetches rules from server within 30s of startup; file writes matching a rule trigger correct classification tier; clipboard content classified using synced rules; disconnecting server causes agent to use cached rules with no detection gap

- [ ] **S04: Admin TUI Classifier Rules Screen** `risk:low` `depends:[S02]`
  > After this: Admin navigates to Classifier Rules screen; sees list of rules with name, pattern preview, tier, category, enabled status; creates new rule with live regex validation; edits, toggles, and deletes rules

- [ ] **S05: Configurable Scan Depth + Performance Validation** `risk:medium` `depends:[S03]`
  > After this: Agent reads configurable scan_depth_bytes from config; default 64KB scans more content than prior 8KB; benchmark proves <5ms classification with 50+ rules at 64KB; hard cap at 1MB prevents OOM

- [ ] **S06: Documentation Update** `risk:low` `depends:[S01,S02,S03,S04,S05]`
  > After this: Docs accurately describe: classifier architecture, how to manage rules via TUI/API, built-in patterns and their categories, scan depth configuration, and the complete feature set of the DLP system as of M006 completion

## Boundary Map

### S01 → S02\n\nProduces:\n- `dlp-common/src/classifier.rs` → `RegexClassifier` struct with `new(rules: &[ClassifierRule]) -> Self` and `classify_content(text: &str) -> Classification`\n- `dlp-common/src/classifier.rs` → `ClassifierRule` struct (id, name, pattern, tier, category, enabled, description)\n- `dlp-common/src/classifier.rs` → `DEFAULT_RULES: &[ClassifierRule]` constant with built-in PII patterns\n- `dlp-common/src/classifier.rs` → `classify_text(text: &str) -> Classification` function (backward-compatible API using DEFAULT_RULES)\n\nConsumes:\n- nothing (first slice)\n\n### S01 → S03\n\nProduces:\n- `ClassifierRule` type (shared between server DB and agent runtime)\n- `RegexClassifier` struct (agent instantiates with synced rules)\n- `DEFAULT_RULES` (agent's compiled-in fallback when server unreachable)\n\nConsumes:\n- nothing (first slice)\n\n### S02 → S03\n\nProduces:\n- `GET /admin/classifier-rules` endpoint returning `Vec<ClassifierRule>` as JSON\n- `classifier_rules` SQLite table with schema: id, name, pattern, tier, category, enabled, description, created_at, updated_at\n- Seed migration populating built-in patterns on first start\n\nConsumes from S01:\n- `ClassifierRule` struct definition for serialization\n- `DEFAULT_RULES` for seed data\n\n### S02 → S04\n\nProduces:\n- Full CRUD API (POST/GET/PUT/DELETE /admin/classifier-rules)\n- Regex validation at creation (400 on invalid)\n- Category field in rule schema\n\nConsumes from S01:\n- `ClassifierRule` type\n\n### S03 → S05\n\nProduces:\n- Agent runtime classification pipeline using synced `RegexClassifier`\n- `policy_mapper.rs` updated to use dynamic classifier\n- Local rule cache mechanism\n\nConsumes from S01:\n- `RegexClassifier` struct\n- `DEFAULT_RULES` for fallback\n\nConsumes from S02:\n- `GET /admin/classifier-rules` endpoint\n\n### S05 → S06\n\nProduces:\n- `scan_depth_bytes` config field in agent config\n- Performance benchmark results\n\nConsumes from S03:\n- Running classification pipeline
