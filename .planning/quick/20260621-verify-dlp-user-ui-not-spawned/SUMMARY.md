---
status: complete
result: negative
---

# Quick Check Summary: dlp-user-ui spawn status

## Finding
`dlp-agent` **still spawns** `dlp-user-ui`.

## Evidence

### Active spawn path on service startup
- `dlp-agent/src/service.rs:313` resolves `dlp-user-ui.exe` via `resolve_ui_binary()`.
- `dlp-agent/src/service.rs:316` configures the path with `crate::ui_spawner::set_ui_binary(path.clone())`.
- `dlp-agent/src/service.rs:370` starts `crate::session_monitor::start()`.
- `dlp-agent/src/session_monitor.rs:53-54` calls `ui_spawner::init()` whenever a UI binary is configured.
- `dlp-agent/src/ui_spawner.rs:85-107` (`init()`) enumerates active Windows sessions and calls `spawn_ui_in_session()` for each.

### Active spawn path on new sessions and respawn
- `dlp-agent/src/session_monitor.rs:134-141` detects newly arrived sessions and calls `handle_session_start(session_id)`.
- `dlp-agent/src/session_monitor.rs:160-162` fetches the UI binary and calls `ui_spawner::spawn_ui_in_session(session_id, &binary)`.
- `dlp-agent/src/session_monitor.rs:112-120` respawns dead UIs while the session is still active.

### No guards or disabled flags found
- No feature flag, config option, or compile-time gate was found that disables the spawn path.
- `dlp-agent/tests/` contains no assertions that `dlp-user-ui` is not spawned.
- Recent commits are focused on UAT benchmarks and Phase 55.1/56 work, not UI spawn removal.

## Conclusion
The check fails: `dlp-user-ui` is still actively spawned by `dlp-agent` at startup and on session changes.
