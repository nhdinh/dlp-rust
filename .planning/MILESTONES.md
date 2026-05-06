# Milestones

## v0.7.0 Disk Exfiltration Prevention (Shipped: 2026-05-06)

**Phases completed:** 27 phases, 81 plans, 86 tasks

**Key accomplishments:**

- One-liner:
- draw_conditions_builder modal overlay with 60%-width centered layout, step breadcrumb, pending conditions list with [d] hints, typed step picker (5 attributes, operators, values), MemberOf text input, and contextual hints bar — human-verified visually with 17 tests passing.
- app.rs changes:
- render.rs changes:
- Substantive:
- Phase:
- PolicyMode field added to three admin-cli structs and wired into POST/PUT payloads, fixing the silent-drop bug where TUI always sent ALL regardless of authored mode
- POLICY_MODE_ROW added to 9-row policy form with Enter/Space cycler, footer advisory for empty-conditions modes, and three HTTP integration tests proving ALL/ANY/NONE boolean semantics via /evaluate
- ABAC evaluator extended with ordinal gt/lt for Classification and case-sensitive contains for MemberOf SID substring match, backed by 6 new unit tests
- Attribute-type-aware Step 2 operator picker in conditions builder TUI, driven by `operators_for()` with SC-1 stale-operator reset and MemberOf partial-match hint
- In-place condition editing for ConditionsBuilder TUI modal: 'e' key pre-fills 3-step picker at existing condition's attribute/op/value, saving replaces at original index, Esc leaves pending list unchanged
- One-liner:
- One-liner:
- One-liner:
- One-liner:
- One-liner:
- Win32 WM_DEVICECHANGE handler wired in usb_wndproc with dual GUID routing (VOLUME + USB_DEVICE), SetupDi FRIENDLYNAME fetch, and second RegisterDeviceNotificationW call — closes Phase 23 SC-1/SC-2 capture path
- One-liner:
- One-liner:
- One-liner:
- One-liner:
- 1. [Rule 1 - Bug] windows-rs 0.58 type mismatches in extract_publisher
- 1. [Rule 1 - Bug] WINEVENT_OUTOFCONTEXT / WINEVENT_SKIPOWNPROCESS wrong module
- Status: Partial — awaiting human checkpoint (Task 3)
- One-liner:
- AppField enum + SourceApplication/DestinationApplication PolicyCondition variants + From<EvaluateRequest> for AbacContext — type contracts enabling app-identity policy matching (APP-03)
- PolicyStore::evaluate() + condition_matches() migrated to &AbacContext; SourceApplication/DestinationApplication arms added; EvaluateRequest -> AbacContext conversion wired at HTTP boundary (APP-03)
- Comprehensive TDD tests for SourceApplication/DestinationApplication condition arms — all AppField variants, all operators, None-identity fail-closed invariant, and evaluate() mode interactions locked at test level
- UsbEnforcer struct bridges drive-letter map (Phase 23) and trust-tier cache (Phase 24) to enforce USB device trust tiers at file I/O time in run_event_loop, short-circuiting ABAC evaluation on blocked or read-only+write-class access
- Added two missing edge-case tests to complete USB-03 D-08/D-09 coverage — test_unregistered_device_defaults_to_blocked (T-26-14 fail-safe) and test_non_alpha_path_returns_none (D-09); total USB enforcer tests now 11
- UsbEnforcer::check() now returns Option<UsbBlockResult> carrying device identity, trust tier, decision, and a per-drive 30-second cooldown-gated notify flag for toast suppression
- Cooldown-gated Pipe2AgentMsg::Toast broadcast wired into USB block handler: tier-specific title/body with device description, unreachable!() FullAccess guard
- One-liner:
- Task 1 — app.rs type extension:
- One-liner:
- ManagedOriginList TUI fully wired with origin-URL confirm messages — `a` adds via POST /admin/managed-origins, `d` deletes with human-readable confirm showing URL pattern, Esc returns to DevicesMenu(selected=1)
- prost/protobuf codegen, length-prefixed frame I/O, and chrome module scaffolding for Chrome Content Analysis SDK integration
- Managed-origins cache (RwLock<HashSet<String>> with 30s polling), server client fetch method, and AuditEvent origin field enrichment with backward-compat deserialization.
- Chrome Content Analysis pipe server at \\.\pipe\brcm_chrm_cas with protobuf request dispatch, managed-origin block decisions, HKLM self-registration, and full service/console lifecycle integration.
- dlp-e2e workspace member crate with shared test helpers for in-process server routers, mock evaluation engines, and headless TUI testing
- 1. [Rule 3 - Blocking] Added `pub mod helpers` re-export wrapper to dlp-e2e/src/lib.rs
- Headless TUI integration test exercising full Managed Origins screen flow via KeyEvent injection into TestBackend, with multi-threaded mock axum server
- One-liner:
- Full-stack integration test that spawns a real dlp-agent binary, seeds config via the admin API, and asserts exact TOML write-back within 15 seconds using env-var overrides for testability.
- Integration tests verifying hot-reload behavior for SIEM, alert, agent, and policy store configs via in-process axum router PUT/GET round-trips
- Extended usb_enforcer.rs test module with 5 new unit tests covering blocked-without-identity, read-only write-deny/read-allow, full-access all-actions, blocked read-denial, and per-drive isolation — all 18 tests pass.
- Real-hardware USB write-protection verification script with WMI auto-detection,

admin API registration, kernel IOCTL cleanup, and comprehensive troubleshooting documentation

- GitHub Actions workflow updated with a parallel `test` job that builds the workspace with zero warnings, runs clippy, checks formatting, and executes all workspace tests on every push and PR.
- Scheduled GitHub Actions workflow that builds the entire workspace in release mode, runs all tests against release binaries, and performs a health-check smoke test on the release dlp-server binary.
- Active PnP-level USB enforcement replacing passive file-I/O-based blocking. DeviceController disables Blocked-tier USB devices via CM_Disable_DevNode and modifies volume DACLs for ReadOnly tier. UsbEnforcer simplified to defence-in-depth fallback for unregistered devices only.
- Objective:
- Shared disk enumeration module with DiskIdentity types, Win32 IOCTL + PnP USB detection, and DiskDiscovery audit events
- Disk enumeration background task integrated into dlp-agent service startup with retry logic, audit emission, and in-memory registry for Phase 35/36 consumption.
- 1. [Rule 1 - Bug] Fixed 34 windows 0.62 API breakages across dlp-agent
- 1. [Rule 1 - Bug] Updated existing struct literal tests for new `encryption` field
- BitLocker WMI/Registry verification engine with EncryptionBackend trait, 12 unit tests, and spawn_encryption_check_task targeting Plan 34-04's service.rs wiring
- Three-line EncryptionChecker singleton registration + spawn_encryption_check_task call wired into service.rs startup immediately after the Phase-33 disk enumeration block, with recheck_interval captured before agent_config is consumed
- Option C selected
- 1. [Rule 1 - Bug] Fixed incorrect backslash escape assertion in plan's test code
- Signature change:
- One-liner:
- 1. [Rule 1 - Bug] Fixed byte_count type in test helpers
- Win32 WM_DEVICECHANGE dispatcher extracted to device_watcher.rs; disk hot-plug handlers wired to DiskEnforcer pre-ABAC block in run_event_loop with full audit/toast/pipe chain
- 1. [Style] Removed ON CONFLICT phrase from doc comments
- 1. [Rule 1 - Bug] EncryptionStatus serde roundtrip does not work -- manual match required
- 1. [Rule 2 - Missing Critical Functionality] BusType::Deserialize forward-compatibility
- Adds `Screen::LdapConfig { config, selected, editing, buffer }` and three public row-index constants to `dlp-admin-cli/src/app.rs`, establishing the type-level contract consumed by the parallel dispatch (38.1-02) and render (38.1-03) plans.
- Full dispatch-layer wiring for Screen::LdapConfig: routing arm, expanded SystemMenu, GET/PUT round-trips, editing/navigation handlers with cache TTL range validation, and 4 unit tests.
- One-liner:
- Volume DACL deny-all secondary enforcement layer wired into Blocked-tier USB device handling, providing defense-in-depth if PnP disable fails or is bypassed
- USB identity reconciliation heuristic fixes VOLUME-before-USB_DEVICE race and startup enforcement gap so Blocked-tier USB devices are enforced on ALL plug-in timing paths
- Rewrote `find_drive_letter_for_instance_id` with kernel-authoritative volume-to-disk mapping, replacing the buggy heuristic that ignored `instance_id` and returned the first unassigned fixed drive letter
- 500ms deferred `GUID_DEVINTERFACE_DISK` arrival processing via tokio runtime handle bridge, so volume manager mounts before drive letter lookup
- Boot drive letter normalization with belt-and-suspenders case-insensitive comparison across dlp-common and dlp-agent

---

## v0.2.0 Feature Completion (Shipped: 2026-04-13)

**Phases completed:** 9 | **Plans:** 14 | **Days:** ~4

**Key accomplishments:**

- **Clipboard monitoring fixed end-to-end** — 4 compounding root causes resolved (WorkerGuard lifetime, stderr vs tracing, tracing_appender silent swallows, PIPE_NAME_DEFAULT backslash count)
- **364+ workspace tests passing** — integration tests migrated to self-contained mock axum engine; no removed `dlp_server` module references
- **JWT_SECRET production-hardened** — server refuses to start without `JWT_SECRET`; `--dev` flag enables dev mode with prominent warning
- **SIEM relay wired + DB-backed** — Splunk HEC + ELK, hot-reload on every relay, `GET/PUT /admin/siem-config`, dlp-admin-cli TUI screen (Phase 3 + 3.1)
- **Alert router wired + DB-backed** — SMTP + webhook, loopback URL validation at PUT time, fire-and-forget, dlp-admin-cli TUI screen (Phase 4)
- **Agent config polling wired** — DB-backed global + per-agent override, `GET /agent-config/{id}` unauthenticated resolution, TOML write-back, poll loop in service.rs (Phase 6)
- **32 agent TCs + 15 server TCs + 6 E2E pipeline tests** — Phase 04.1 wave-based TDD: unit → server → E2E

**Deferred to v0.3.0:** AD LDAP (R-05), rate limiting (R-07), admin audit logging (R-09), SQLite pool (R-10), Policy Engine Separation (R-03)

**Human UAT items still open:**

- Live SMTP email delivery (Phase 4)
- Live webhook POST (Phase 4)
- Hot-reload through HTTP + TUI (Phase 4)
- Live agent TOML write-back (Phase 6)
- Zero-warning workspace build (Phase 6)

---

## v0.3.0 Operational Hardening (Shipped: 2026-04-16)

**Phases completed:** 6 | **Plans:** 14 | **Days:** ~3

**Key accomplishments:**

- **Active Directory LDAP integration** — real ABAC attribute resolution via `ldap3`; channel-based async AdClient with machine-account Kerberos TGT bind, transitive group membership via `tokenGroups`, device trust via `NetGetJoinInformation`, fail-open on AD unavailability (Phase 7)
- **Rate limiting middleware** — `tower-governor` with 5 per-route configs (5/min login, 200/min event ingestion, 60/min policy CRUD); required axum 0.7 → 0.8 upgrade (Phase 8)
- **Admin operation audit logging** — policy CRUD + password changes persisted as `EventType::AdminAction` audit events; 4 integration tests verifying exact SQLite contents (Phase 9)
- **SQLite connection pool** — `r2d2`/`r2d2_sqlite` replacing single `Mutex<Connection>`; `AppState` derives `Clone`; 220 workspace tests pass (Phase 10)
- **Policy Engine Separation** — `PolicyStore` with `parking_lot::RwLock`, sync hot-path `evaluate()`, 23 unit tests, cache invalidation on every policy CRUD, 5-min background refresh (Phase 11)
- **Repository + Unit of Work refactor** — 49 `pool.get()` + raw SQL call sites migrated into 10 typed Repository structs; all writes via `UnitOfWork<'conn>` RAII transaction; net -109 lines in admin_api.rs (Phase 99)

**All 5 deferred v0.2.0 requirements validated:** R-03, R-05, R-07, R-09, R-10

---

## v0.4.0 Policy Authoring (Shipped: 2026-04-20)

**Phases completed:** 5 | **Plans:** 9 | **Days:** ~4

**Key accomplishments:**

- **Conditions builder** — 3-step sequential picker (attribute → operator → value) replaces raw JSON. 5 attributes, typed value pickers, delete-and-recreate for in-place edit (Phase 13).
- **Policy Create form** — multi-field typed form with inline validation, composable with conditions builder, submits to POST /admin/policies and invalidates PolicyStore cache (Phase 14).
- **Policy Edit + Delete** — load existing policies via GET /admin/policies/{id}, edit in-place, delete with `d`-key confirmation, PUT/DELETE with cache invalidation (Phase 15).
- **Policy List + Simulate** — scrollable sorted table with `n`/`e`/`d` inline actions, standalone evaluate-request simulate form calling POST /evaluate (Phase 16).
- **Import + Export** — native Windows file dialogs (rfd 0.14), export pretty-printed JSON with dated filename, import with typed `PolicyResponse` parsing + conflict diff + POST/PUT abort-on-error (Phase 17).
- **All 8 POLICY requirements delivered (POLICY-01..08)** — admin no longer touches raw JSON or SQL for any policy operation.

**Known deferred items at close:** 3 dormant seeds (SEED-001, 002, 003 — application-aware DLP, protected clipboard browser boundary, USB device-identity whitelist). Tracked in STATE.md "Deferred Items".

**Issues resolved during milestone:**

- Phase 16 UAT: PolicySimulate Esc bug cleared the edit buffer (commit e1afee3)
- Phase 17 UAT: GET /admin/policies returned 405 Method Not Allowed; routed GETs to /policies (commit 7dda578)

**Issues deferred (to v0.5.0+):** POLICY-F1..F6 — AND/OR/NOT boolean logic, in-place condition editing, expanded operators, TOML export unblock, batch import endpoint, typed Decision action field.

---

## v0.5.0 Boolean Logic (Shipped: 2026-04-21)

**Phases completed:** 4 (18, 19, 20, 21) | **Plans:** 7 | **Days:** ~2

**Key accomplishments:**

- **Boolean mode engine + wire format** — `PolicyMode` enum (ALL/ANY/NONE), `policies.mode` column with `NOT NULL DEFAULT 'ALL'` migration, `PolicyStore::evaluate` switch on mode, 15 unit tests covering all three modes, empty-conditions edge cases, and legacy v0.4.0 backward-compat path (Phase 18; POLICY-12)
- **Boolean mode TUI** — `POLICY_MODE_ROW` in 9-field Create/Edit forms, `cycle_mode()` helper, Enter/Space cyclers, footer advisory for empty-conditions modes, export always writes `mode`, import tolerates omitted `mode` (defaults to ALL), 4 HTTP integration tests proving ALL/ANY/NONE semantics end-to-end (Phase 19; POLICY-09)
- **Operator expansion** — `operators_for()` per-attribute lists (Classification: eq/ne/gt/lt, MemberOf: eq/ne/contains, others: eq/ne), evaluator honors `gt`/`lt`/`contains`, Step 2 picker auto-sizes to attribute, SC-1 stale-operator reset on attribute change, 6 regression tests (Phase 20; POLICY-11)
- **In-place condition editing** — `edit_index: Option<usize>` in ConditionsBuilder state, `condition_to_prefill()` inverse of `build_condition` for all 5 variants, `'e'` key handler pre-fills 3-step picker, index-aware replace-vs-push commit, "Edit Condition" modal title, 4 unit tests (Phase 21; POLICY-10)

**All 4 POLICY requirements delivered:** POLICY-09 (boolean mode TUI), POLICY-10 (in-place edit), POLICY-11 (operator expansion), POLICY-12 (backward compat)

**Deferred items at close:** 6 (3 seeds: SEED-001/002/003; 3 server: POLICY-F4/F5/F6). Tracked in STATE.md Deferred Items.

---
