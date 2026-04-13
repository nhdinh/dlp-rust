<!-- generated-by: gsd-doc-writer -->
# Development Guide

This guide covers local setup, build commands, code conventions, and the contribution workflow for the DLP-RUST project.

## Repository Overview

DLP-RUST is a Rust workspace containing five crates:

| Crate | Role |
|---|---|
| `dlp-common` | Shared types, ABAC engine, audit event schemas |
| `dlp-server` | Central management server (ABAC evaluator, audit store, SIEM relay, admin API) |
| `dlp-agent` | Windows Service: file interception, policy enforcement |
| `dlp-user-ui` | Iced subprocess: notifications, dialogs, clipboard, system tray |
| `dlp-admin-cli` | Admin CLI: password management, policy CRUD, server status |

Workspace version: **0.1.0** (2021 edition)

---

## Local Setup

### Prerequisites

- **Rust 1.75+** — [https://rustup.rs](https://rustup.rs)
- **Windows** — required for the agent and user-ui components
- **Administrator privileges** — needed to install and run the Windows Service agent

### Clone

```powershell
git clone <repository-url>
cd dlp-rust
```

### Install CLI tooling (optional)

```powershell
cargo install --path dlp-admin-cli
```

---

## Build Commands

### Build the entire workspace

```powershell
cargo build --release
```

### Build a specific crate

```powershell
cargo build -p dlp-agent --release
```

### Run tests

```powershell
cargo test
```

### Run tests for a specific crate

```powershell
cargo test -p dlp-common
```

### Run tests with output capture disabled (for interactive UI tests)

```powershell
cargo test -- --nocapture
```

### Lint with Clippy

```powershell
cargo clippy -- -D warnings
```

### Check formatting

```powershell
cargo fmt --check
```

### Auto-format code

```powershell
cargo fmt
```

### Build documentation

```powershell
cargo doc --no-deps
```

### Full static analysis pass

```powershell
cargo check
cargo fmt --check
cargo clippy -- -D warnings
```

---

## Code Style

The project follows standard Rust conventions with the following specifics:

- **Indentation**: 4 spaces (no tabs)
- **Line length**: 100 characters (rustfmt default)
- **Naming**:
  - Functions and variables: `snake_case`
  - Types and traits: `PascalCase`
  - Constants: `SCREAMING_SNAKE_CASE`
- **Formatter**: `cargo fmt` (rustfmt)
- **Linter**: `cargo clippy -- -D warnings`

No custom `rustfmt.toml` or `.clippy.toml` is present in the repository root; the workspace uses rustfmt defaults.

---

## Branch Conventions

Branches follow a topic prefix convention:

| Prefix | Purpose |
|---|---|
| `feat/` | New features |
| `fix/` | Bug fixes |
| `docs/` | Documentation |
| `chore/` | Maintenance, tooling, CI |
| `sprint-N/` | Sprint deliverables |
| `test/` | Verification branches |

Examples:
- `feat/msi-installer`
- `fix/serde-enum-rename`
- `docs/development-guide`
- `sprint-17-integration-tests`

---

## Commit Message Format

The project uses [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]
[optional footer]
```

### Types

| Type | When to use |
|---|---|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation changes |
| `chore` | Build scripts, dependency updates, tooling |
| `refactor` | Code restructuring without behavior change |
| `test` | Adding or updating tests |

### Examples

```
feat(dlp-agent): add file interception for NTFS volumes
fix(dlp-server): correct audit event timestamp parsing
docs(phase-12): add integration test summary
chore: remove stale Phase 12-03 plan file
```

---

## Pull Request Process

1. **Create a branch** from `master` using the branch conventions above
2. **Make your changes** — follow code style and testing standards
3. **Run the full verification pass** before opening a PR:
   ```powershell
   cargo fmt
   cargo clippy -- -D warnings
   cargo test
   ```
4. **Open a PR** against `master`
5. **Pass all CI checks**
6. **Obtain review approval** before merging

---

## Architecture Notes

- **Critical Rule**: `NTFS ALLOW + ABAC DENY = DENY` — ABAC can veto any NTFS-granted access, never the reverse.
- **Data tiers**: T1 Public → T4 Restricted
- **Agent runs as SYSTEM**; user-facing UI runs as an iced subprocess on the interactive desktop.
- Agent and server communicate over a secured channel; audit events flow from agent → server → SIEM.

<!-- generated-by: gsd-doc-writer -->