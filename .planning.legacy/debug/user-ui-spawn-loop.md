---
status: fixed
trigger: >
  When user kills dlp-user-ui process, dlp-agent keeps spawning
  a lot of dlp-user-ui instances repeatedly.
created: "2026-04-29T14:00:00+07:00"
updated: "2026-04-29T14:05:00+07:00"
---

# Debug Session: user-ui-spawn-loop

## Symptoms

- **Expected**: When dlp-user-ui is killed, dlp-agent should respawn ONE replacement UI process per session, at a reasonable rate (every 2s poll cycle at most).
- **Actual**: Killing dlp-user-ui causes dlp-agent to spawn many instances rapidly — far more than one per 2s cycle.
- **Context**: Manual testing via taskkill on dlp-user-ui while dlp-agent is running.

## Current Focus

**hypothesis:** session_monitor.rs polls every 2s and calls handle_session_start when is_ui_alive returns false, but the spawn may be creating multiple processes per session, or multiple sessions are being detected as active.

**test:** Read session_monitor.rs respawn logic and is_ui_alive behavior.

**expecting:** Either spawn_ui_in_session creates duplicate processes, or the UI process exits immediately and is re-detected as dead on the next poll.

**next_action:** Read session_monitor.rs lines 88-120 and ui_spawner.rs spawn logic to trace the exact respawn path.

## Evidence

- timestamp: 2026-04-29T14:00:00+07:00
  source: code_read
  detail: >
    session_monitor.rs lines 107-115: respawn loop calls handle_session_start(session_id)
    then immediately active.insert(session_id), but never stores the new UiHandle
    in UI_HANDLES.

- timestamp: 2026-04-29T14:00:00+07:00
  source: code_read
  detail: >
    ui_spawner.rs lines 293-310: is_ui_alive() checks UI_HANDLES for the session.
    If no entry exists, returns false. If process exited, removes entry and returns false.

- timestamp: 2026-04-29T14:00:00+07:00
  source: code_read
  detail: >
    ui_spawner.rs lines 160-237: spawn_ui_in_session() creates process and returns
    UiHandle { pid, handle }, but NEVER inserts it into UI_HANDLES.

- timestamp: 2026-04-29T14:00:00+07:00
  source: code_read
  detail: >
    session_monitor.rs lines 129-137: new session path also calls handle_session_start()
    and active.insert(), but never stores handle in UI_HANDLES. Same bug affects both paths.

## Eliminated

- Not duplicate CreateProcessAsUserW calls within a single poll: spawn_ui_in_session is called once per cycle.
- Not UI process exiting immediately: the bug is that the handle is never tracked, so is_ui_alive always returns false on the next poll regardless of whether the UI is actually running.
- Not a race between multiple sessions: each session is processed independently, but the same bug applies per session.

## Resolution

root_cause: >
  spawn_ui_in_session() returns a UiHandle but never inserts it into UI_HANDLES.
  session_monitor.rs calls handle_session_start() which calls spawn_ui_in_session(),
  then inserts the session_id into active_sessions, but the UiHandle is dropped.
  On the next 2-second poll, is_ui_alive() checks UI_HANDLES, finds no entry,
  returns false, and the respawn loop fires again. This creates an infinite respawn
  loop — one new process every 2 seconds per affected session.
  The same bug affects the new-session path (lines 129-137).
fix: >
  Added ui_spawner::insert_handle(session_id, handle) to store the UiHandle in
  UI_HANDLES after spawn. Called it in handle_session_start after successful
  spawn_ui_in_session. This lets is_ui_alive() track the process on subsequent
  polls, stopping the infinite respawn loop.
verification: >
  cargo check -p dlp-agent: clean (no warnings)
  cargo test -p dlp-agent --lib: 210 passed
files_changed:
  - dlp-agent/src/ui_spawner.rs
  - dlp-agent/src/session_monitor.rs
