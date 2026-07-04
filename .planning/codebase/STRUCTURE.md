# Codebase Structure

**Analysis Date:** 2026-07-03

## Directory Layout

```
C:/Users/nhdinh/dev/dlp-rust/
├── Cargo.toml                  # Workspace manifest
├── Cargo.lock                  # Dependency lockfile
├── README.md                   # Project overview
├── CLAUDE.md                   # AI coding standards and security rules
├── AGENTS.md                   # Agent role definitions
├── RELEASE_NOTES.md            # Release engineering notes and hashes
├── sonar-project.properties    # SonarQube configuration
├── sgconfig.yml                # ast-grep configuration
│
├── dlp-common/                 # Shared types library
├── dlp-server/                 # Central management HTTP server
├── dlp-agent/                  # Windows Service enforcement agent
├── dlp-user-ui/                # Per-session iced GUI subprocess
├── dlp-admin-cli/              # ratatui TUI for administrators
├── dlp-e2e/                    # End-to-end integration test harness
├── dlp-hook-dll/               # API hook DLL (cdylib + rlib)
│
├── docs/                       # Architecture, security, API, deployment docs
├── installer/                  # WiX MSI installer sources
├── scripts/                    # PowerShell and Python maintenance scripts
├── .planning/                  # Active planning artifacts
│   ├── phases/                 # Phase-specific plans and UAT docs
│   └── codebase/               # Codebase mapping documents (this directory)
├── .cargo/                     # Cargo configuration
├── .claude/                    # Claude Code config, hooks, skills
├── .codex/                     # Codex/GSD skills and workflows
├── .beads/                     # Beads issue tracker (Dolt DB)
├── .ast-grep/                  # ast-grep rules
├── .github/                    # GitHub Actions workflows
├── .gitnexus/                  # GitNexus code intelligence config
└── .rtk/                       # RTK (Rust Token Killer) config
```

## Directory Purposes

**`dlp-common/src/`:**
- Purpose: Shared types and pure logic used by all crates.
- Contains: ABAC types, AD client, audit schema, classification, crypto/DPAPI, disk/USB helpers, hook IPC wire types.
- Key files: `dlp-common/src/abac.rs`, `dlp-common/src/ad_client.rs`, `dlp-common/src/hook_ipc.rs`.

**`dlp-server/src/`:**
- Purpose: Central management server, policy engine, admin API.
- Contains: axum routers, repositories, crypto, SIEM/syslog/alert connectors.
- Key files: `dlp-server/src/main.rs`, `dlp-server/src/lib.rs`, `dlp-server/src/admin_api.rs`, `dlp-server/src/policy_store.rs`, `dlp-server/src/db/repositories/`.

**`dlp-agent/src/`:**
- Purpose: Endpoint enforcement Windows Service.
- Contains: Service lifecycle, interception, IPC, detection, WFP, hooks, print/cloud/USB/disk enforcers.
- Key files: `dlp-agent/src/main.rs`, `dlp-agent/src/service.rs`, `dlp-agent/src/interception/mod.rs`, `dlp-agent/src/ipc/`.

**`dlp-user-ui/src/`:**
- Purpose: Per-session user interface.
- Contains: iced app, tray, notifications, dialogs, IPC clients.
- Key files: `dlp-user-ui/src/main.rs`, `dlp-user-ui/src/app.rs`, `dlp-user-ui/src/ipc/`.

**`dlp-admin-cli/src/`:**
- Purpose: Administrator terminal UI.
- Contains: ratatui app, screens, authenticated HTTP client, login.
- Key files: `dlp-admin-cli/src/main.rs`, `dlp-admin-cli/src/app.rs`, `dlp-admin-cli/src/screens/`.

**`dlp-e2e/`:**
- Purpose: Cross-crate end-to-end and headless TUI tests.
- Contains: Test harness helpers in `src/lib.rs`, integration tests in `tests/`.
- Key files: `dlp-e2e/src/lib.rs`, `dlp-e2e/tests/`.

**`dlp-hook-dll/src/`:**
- Purpose: Injected API hook DLL.
- Contains: `DllMain`, IAT/ntdll patching, named-pipe client, classification cache, guards.
- Key files: `dlp-hook-dll/src/lib.rs`, `dlp-hook-dll/src/trampolines.rs`, `dlp-hook-dll/src/ntdll_patcher.rs`.

**`.planning/codebase/`:**
- Purpose: Codebase mapping documents consumed by GSD planner/executor.
- Contains: `STACK.md`, `INTEGRATIONS.md`, `ARCHITECTURE.md`, `STRUCTURE.md`, `CONVENTIONS.md`, `TESTING.md`, `CONCERNS.md`.

## Key File Locations

**Entry Points:**
- `dlp-server/src/main.rs` — Server bootstrap.
- `dlp-agent/src/main.rs` — Windows Service dispatcher.
- `dlp-user-ui/src/main.rs` — iced GUI entry.
- `dlp-admin-cli/src/main.rs` — TUI entry.
- `dlp-hook-dll/src/lib.rs` — DLL entry (`DllMain`).

**Configuration:**
- `Cargo.toml` — Workspace members and shared dependencies.
- `dlp-agent/src/config.rs` — Agent TOML config schema.
- `dlp-agent/proto/*.proto` — Chrome Content Analysis protobuf definitions.
- `sonar-project.properties` — SonarQube scanner settings.
- `sgconfig.yml` — ast-grep rule config.

**Core Logic:**
- `dlp-common/src/abac.rs` — ABAC type system and evaluation.
- `dlp-server/src/policy_store.rs` — Policy cache and evaluation engine.
- `dlp-agent/src/interception/mod.rs` — File interception event loop.
- `dlp-agent/src/engine_client.rs` — Policy engine HTTPS client.
- `dlp-hook-dll/src/lib.rs` — Hook installation and dispatch.

**Testing:**
- `dlp-server/tests/` — Server integration tests.
- `dlp-agent/tests/` — Agent integration tests.
- `dlp-e2e/tests/` — Cross-crate end-to-end tests.
- `dlp-hook-dll/tests/` — Hook DLL integration tests.

## Naming Conventions

**Files:**
- Rust source files: lowercase with underscores, e.g., `audit_emitter.rs`, `policy_mapper.rs`.
- Module entry points: `mod.rs`, e.g., `dlp-agent/src/ipc/mod.rs`.
- Test files: descriptive suffixes, e.g., `mode_end_to_end.rs`, `admin_audit_integration.rs`.

**Directories:**
- Crate directories: lowercase with hyphens, e.g., `dlp-admin-cli/`.
- Module directories: lowercase with underscores, e.g., `repositories/`, `detection/`.

## Where to Add New Code

**New Feature (server):**
- Primary code: `dlp-server/src/<feature>.rs`
- Repository (if DB-backed): `dlp-server/src/db/repositories/<feature>.rs`
- Tests: `dlp-server/tests/<feature>_integration.rs` or inline `#[cfg(test)]` module.

**New Feature (agent):**
- Primary code: `dlp-agent/src/<feature>.rs`
- If channel-specific, place in `dlp-agent/src/<channel>_enforcer.rs` or `dlp-agent/src/<channel>/`.
- Tests: `dlp-agent/tests/<feature>.rs` or inline `#[cfg(test)]` module.

**New Component/Module:**
- Implementation: `dlp-common/src/<module>.rs` for shared types; crate-specific module for crate-local logic.
- Re-export from crate `lib.rs`.

**Utilities:**
- Shared helpers: `dlp-common/src/<helper>.rs`.
- Crate-local helpers: `dlp-<crate>/src/<helper>.rs`.

## Special Directories

**`target/` / `target-test/`:**
- Purpose: Build artifacts.
- Generated: Yes.
- Committed: No (gitignored).

**`.beads/`:**
- Purpose: Embedded Dolt database for `bd` issue tracker.
- Generated: Partially.
- Committed: Yes.

**`.gitnexus/`:**
- Purpose: GitNexus code intelligence configuration and runner.
- Generated: Partially.
- Committed: Yes.

**`.claude/` / `.codex/`:**
- Purpose: Claude Code and Codex/GSD skills, hooks, and memory.
- Generated: Mixed.
- Committed: Yes.

---

*Structure analysis: 2026-07-03*
