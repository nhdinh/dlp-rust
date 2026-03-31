# ABAC Policy Set

## ⚠️ Note on Action Names

The `THEN` clause in these sample rules uses **descriptive policy-level action names** (e.g., `deny_all_except_owner`, `allow_with_logging`, `deny_upload`). These are **human-readable labels** for policy authoring convenience.

The **formal system action enum** (defined in SRS.md F-ENG-03) contains exactly four values:

| System Action | Meaning |
|---|---|
| `ALLOW` | Permit the operation |
| `DENY` | Block the operation, log event |
| `ALLOW_WITH_LOG` | Permit and emit audit event |
| `DENY_WITH_ALERT` | Block, log event, and trigger immediate SIEM/admin alert |

The Policy Engine maps descriptive rule-level actions to system actions. For example:
- `deny_all_except_owner` → `DENY`
- `deny_upload` → `DENY`
- `allow_with_logging` → `ALLOW_WITH_LOG`

## Sample Policies

IF resource.classification == "T4"
THEN deny_all_except_owner

IF resource.classification == "T3"
AND device.trust == "Unmanaged"
THEN deny_upload

IF resource.classification == "T2"
THEN allow_with_logging
