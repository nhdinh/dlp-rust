---
status: partial
phase: 25-app-identity-capture-in-dlp-user-ui
source: [25-VERIFICATION.md]
started: 2026-04-22T12:05:00Z
updated: 2026-04-22T12:05:00Z
---

## Current Test

[awaiting human testing]

## Tests

### 1. Live audit.jsonl identity field population

**Steps:**
1. Run `cargo build --workspace` (debug mode)
2. Start `dlp-agent` as Administrator
3. Start `dlp-user-ui` in the user session
4. Open Notepad, type or paste: `SSN: 123-45-6789`
5. Select all and Copy (`Ctrl+C`)
6. Check `C:\ProgramData\DLP\audit\*.jsonl` for a `ClipboardAlert` entry

**Expected:**
- `source_application.image_path` = path to `notepad.exe` (e.g. `C:\Windows\System32\notepad.exe`)
- `source_application.signature_state` = `"valid"`
- `source_application.publisher` contains `"Microsoft"`
- `source_application.trust_tier` = `"trusted"`
- If pasted into another app: `destination_application` also populated

**Why human:** End-to-end live verification requires both processes running and a real clipboard event. Cannot be exercised with `cargo test` alone.

result: [pending]

## Summary

total: 1
passed: 0
issues: 0
pending: 1
skipped: 0
blocked: 0

## Gaps
