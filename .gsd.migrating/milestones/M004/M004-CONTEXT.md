# M004: Policy Authoring (v0.4.0)

**Gathered:** 2026-04-17
**Status:** Closed (shipped 2026-04-20)

## Project Description

Full policy authoring workflow in the Admin TUI — conditions builder, policy CRUD, and import/export for policy portability.

## Why This Milestone

DLP administrators needed a complete workflow to create, edit, and manage policies without manual JSON editing. Import/export enables policy sharing across environments (dev to staging to production).

## User-Visible Outcome

### When this milestone is complete, the user can:

- Create new DLP policies with a guided TUI workflow
- Edit existing policy conditions using the conditions builder
- Import/export policies as portable JSON for cross-environment deployment

### Entry point / environment

- Entry point: Admin TUI (dlp-admin-cli)
- Environment: Windows terminal
- Live dependencies involved: DLP server (policy store)

## Scope

### In Scope

- Conditions builder TUI screen
- Policy CRUD (create, read, update, delete)
- Policy import/export (JSON format)
- Policy validation before save

### Out of Scope / Non-Goals

- Policy versioning/history
- Policy simulation/dry-run
- Multi-admin conflict resolution
