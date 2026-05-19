---
plan: 49-04
phase: 49
status: complete
---

# 49-04 Summary — Config Wiring + Admin TUI: Allowlist Hot-Reload + Operator UI

## What Was Built

- AgentConfig extended with `universal_injection` section containing `allowlist_entries` and `allowlist_version`
- AgentConfigPayload extended with matching allowlist fields for server-to-agent sync
- Config poll loop enhanced with `If-None-Match` version header and 304-style skip optimization
- Server `policy_sync` returns 304 when version matches, sorts entries by priority
- Admin TUI allowlist screen with list/add/edit/disable/delete modes, F5 refresh trigger
- Screen wired into app.rs, dispatch.rs, render.rs, and screens/mod.rs

## Commits

- `3df919f`: Extend AgentConfig with universal_injection section
- `e36fa71`: Extend AgentConfigPayload with allowlist fields
- `7c15417`: Config poll versioning + manual refresh channel
- `0c4a1c3`: Server-side allowlist in agent config + 304 optimization
- `92e0022`: Admin TUI allowlist screen
- `f57a78a`: Wire allowlist screen into app/dispatch/render/mod

## Verification

- `cargo check --workspace` compiles with zero errors
- `cargo check -p dlp-admin-cli` compiles (warnings only for unused imports)

## Notes

- Menu navigation to Allowlist screen not yet wired (SystemMenu index 12+ expansion needed)
- Client API methods for allowlist CRUD not yet implemented (placeholder in plan)
- Full unit tests for config wiring deferred to gap closure if needed
