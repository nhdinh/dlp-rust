<!-- generated-by: gsd-doc-writer -->

# Configuration

The DLP system is split into three binaries, each with its own configuration surface:

| Binary | Configuration method |
|--------|---------------------|
| `dlp-server` | CLI flags + environment variables + SQLite |
| `dlp-agent` | TOML config file + environment variables |
| `dlp-admin-cli` | CLI flags + environment variables |

The server stores all operator settings (SIEM, alerting, agent config) in SQLite — not in environment variables. This includes SIEM credentials, alert routing settings, and per-agent overrides. See [Operator Config in DB](./design/decisions/feedback_operator_config_in_db.md) for rationale.

---

## dlp-server

### CLI flags

```
dlp-server.exe [OPTIONS]

OPTIONS:
  --bind <host:port>           Listen address (default: 127.0.0.1:9090)
  --db <path>                  SQLite database path (default: ./dlp-server.db)
  --log-level <level>          Log level: trace, debug, info, warn, error
                               (default: info)
  --init-admin <password>      Create the dlp-admin user non-interactively
                               (for installer / scripted setup)
  --dev                        Development mode — allow insecure JWT
                               secret fallback (do NOT use in production)
  --help                       Show this help message
```

All flags are optional. The defaults are safe for local single-machine development.

### Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `JWT_SECRET` | **Yes** (production) | Secret key used to sign JWT bearer tokens. Must be set in production. The server refuses to start without it unless `--dev` is passed. |
| `DLP_SERVER_REPLICAS` | No | Comma-separated list of `dlp-server` replica URLs for policy sync. Format: `http://replica1:9090,http://replica2:9090`. |

### Defaults

| Setting | Default |
|---------|---------|
| Listen address | `127.0.0.1:9090` |
| Database path | `./dlp-server.db` |
| Log level | `info` |
| JWT expiry | 24 hours |
| JWT issuer | `dlp-server` |

### First-run admin setup

On first start, if no admin user exists in the database, the server prompts interactively for the `dlp-admin` password (with confirmation). For scripted or installer-based setup, pass `--init-admin <password>` to skip the prompt.

### SQLite configuration tables

The server uses SQLite for all state. The database path is controlled by `--db` (or the default). Two tables hold operator configuration:

**`siem_config`** — SIEM relay settings. Single-row table (id=1).

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| `splunk_url` | TEXT | `''` | Splunk HEC endpoint URL |
| `splunk_token` | TEXT | `''` | Splunk HEC token |
| `splunk_enabled` | INTEGER | 0 | Enable Splunk relay |
| `elk_url` | TEXT | `''` | Elasticsearch / ELK URL |
| `elk_index` | TEXT | `''` | ELK index name |
| `elk_api_key` | TEXT | `''` | ELK API key |
| `elk_enabled` | INTEGER | 0 | Enable ELK relay |
| `updated_at` | TEXT | `''` | ISO 8601 timestamp of last update |

**`alert_router_config`** — Alert delivery settings. Single-row table (id=1).

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| `smtp_host` | TEXT | `''` | SMTP server hostname |
| `smtp_port` | INTEGER | 587 | SMTP port |
| `smtp_username` | TEXT | `''` | SMTP username |
| `smtp_password` | TEXT | `''` | SMTP password (stored in plaintext — restrict DB file permissions) |
| `smtp_from` | TEXT | `''` | From address for alert emails |
| `smtp_to` | TEXT | `''` | To address for alert emails |
| `smtp_enabled` | INTEGER | 0 | Enable SMTP alerts |
| `webhook_url` | TEXT | `''` | Outbound webhook URL |
| `webhook_secret` | TEXT | `''` | HMAC secret for webhook signature |
| `webhook_enabled` | INTEGER | 0 | Enable webhook alerts |
| `updated_at` | TEXT | `''` | ISO 8601 timestamp of last update |

**`global_agent_config`** — Default agent settings applied to all agents. Single-row table (id=1).

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| `monitored_paths` | TEXT | `'[]'` | JSON array of directory paths to monitor |
| `heartbeat_interval_secs` | INTEGER | 30 | Heartbeat interval in seconds |
| `offline_cache_enabled` | INTEGER | 1 | Whether offline event caching is enabled |
| `updated_at` | TEXT | `''` | ISO 8601 timestamp of last update |

**`agent_config_overrides`** — Per-agent overrides of the global config. Keyed by `agent_id`.

| Column | Type | Description |
|--------|------|-------------|
| `agent_id` | TEXT | Agent identifier (FK to `agents.agent_id`) |
| `monitored_paths` | TEXT | JSON array of directory paths |
| `heartbeat_interval_secs` | INTEGER | Heartbeat interval in seconds |
| `offline_cache_enabled` | INTEGER | Whether offline caching is enabled |
| `updated_at` | TEXT | ISO 8601 timestamp |

> **VERIFY:** The default path `C:\ProgramData\DLP\` for agent config is a Windows-specific installation convention. Adjust for non-Windows deployments.

---

## dlp-agent

### TOML config file

The agent reads monitoring configuration from a TOML file. The default location is **`C:\ProgramData\DLP\agent-config.toml`** <!-- generated-by: gsd-doc-writer -->.

```
<!-- generated-by: gsd-doc-writer -->
# DLP Server URL (optional — env var DLP_SERVER_URL overrides this)
server_url = 'http://10.0.1.5:9090'

# Directories to monitor recursively.
# Empty list = all mounted drives A-Z.
monitored_paths = [
    'C:\\Data\\',
    'C:\\Confidential\\',
]

# Additional exclusion prefixes (case-insensitive substring match).
# Merged with built-in exclusions, not replacing them.
excluded_paths = [
    'C:\\BuildOutput\\',
]

# Heartbeat interval in seconds.
# Populated by server config push; leave unset to use compiled default.
heartbeat_interval_secs = 30

# Whether offline event caching is enabled.
# Populated by server config push; leave unset to use compiled default.
offline_cache_enabled = true
```

All fields are optional. If the file is missing or unparseable, the agent uses built-in defaults (all drives, built-in exclusions only).

> **NOTE:** The TOML file is written back by the agent when the server pushes updated config (`heartbeat_interval_secs`, `offline_cache_enabled`). `server_url` from TOML is only read at startup — changes require a service restart. `monitored_paths` hot-reload is out of scope for the current phase.

### Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DLP_SERVER_URL` | No | Base URL of `dlp-server` (default: `http://127.0.0.1:9090`). Takes priority over `server_url` in the TOML file. |
| `DLP_AGENT_ID` | No | Unique agent identifier. Defaults to the machine hostname if unset. |
| `DLP_UI_BINARY` | No | Path to the `dlp-user-ui.exe` binary. Defaults to the directory containing the running service binary. |
| `DLP_PIPE3_NAME` | No | Named pipe name for UI-to-agent communication (default: `\\.\pipe\DLPEventUI2Agent`). Intended for integration testing only. |

### Defaults

| Setting | Default |
|---------|---------|
| Config file | `C:\ProgramData\DLP\agent-config.toml` <!-- generated-by: gsd-doc-writer --> |
| Server URL | `http://127.0.0.1:9090` |
| Monitored paths | All mounted drives A–Z |
| Excluded paths | Built-in exclusions (Windows system directories, `$Recycle.Bin`, `System Volume Information`, browser caches, etc.) |
| Heartbeat interval | 30 seconds |
| Offline cache | Enabled |
| Audit log | `C:\ProgramData\DLP\logs\audit.jsonl` |
| Service name | `dlp-agent` |
| Service display name | `Enterprise DLP Agent` |

> **VERIFY:** Default paths under `C:\ProgramData\DLP\` apply to Windows deployments. On a non-Windows development host, the agent uses the current working directory for logs.

### Server-pushed configuration

`dlp-server` can push three configuration fields to connected agents via `GET /agent-config/{agent_id}`:

1. **`monitored_paths`** — written to TOML, takes effect on restart
2. **`heartbeat_interval_secs`** — applied immediately in-memory
3. **`offline_cache_enabled`** — applied immediately in-memory

The agent polls the server at the current heartbeat interval (initially 30 s) and applies changes without requiring a restart.

---

## dlp-admin-cli

### CLI flags

```
dlp-admin-cli.exe [OPTIONS]

OPTIONS:
  --connect <host:port>    DLP Server address (auto-detected if omitted)
  --help                   Show this help message
```

### Server URL resolution (priority order)

1. **`DLP_SERVER_URL`** env var (set by `--connect` or manually)
2. **`BIND_ADDR`** value in registry key `HKLM\SOFTWARE\DLP\PolicyEngine`
3. Probe well-known local ports: `9090`, `8443`, `8080`
4. Fall back to `http://127.0.0.1:9090`

### Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DLP_SERVER_URL` | No | Base URL of `dlp-server`. Set automatically by `--connect`. |
| `DLP_ENGINE_CERT_PATH` | No | Path to a PEM certificate file for mTLS client authentication. |
| `DLP_ENGINE_KEY_PATH` | No | Path to a PEM private key file for mTLS client authentication. |
| `DLP_ENGINE_TLS_VERIFY` | No | Set to `false` to disable TLS certificate verification (development only). |

### Defaults

| Setting | Default |
|---------|---------|
| Server URL | `http://127.0.0.1:9090` (or auto-detected) |
| mTLS | Disabled |
| TLS verification | Enabled (disabled if `DLP_ENGINE_TLS_VERIFY=false`) |

---

## Policy sync (replica servers)

`dlp-server` can push policy changes to replica instances. Configure replicas via the environment variable on the **primary** server:

| Variable | Format | Example |
|----------|--------|---------|
| `DLP_SERVER_REPLICAS` | Comma-separated base URLs | `http://pe1:9090,http://pe2:9090` |

When set, every policy create/update/delete via the admin API triggers a `PUT` or `DELETE` call to each replica's `/policies/{id}` endpoint. Errors are logged; the first error is returned to the caller but all replicas are attempted.

> **NOTE:** Replica sync is best-effort. If a replica is unreachable, the primary continues serving and the sync error is logged. Manual reconciliation may be required.

---

## Summary: required vs optional settings

| Binary | Setting | Required? | How to set |
|--------|---------|-----------|------------|
| `dlp-server` | JWT signing secret | **Yes** (production) | `JWT_SECRET` env var |
| `dlp-server` | Listen address | No | `--bind` flag or default |
| `dlp-server` | Database path | No | `--db` flag or default |
| `dlp-server` | Replica URLs | No | `DLP_SERVER_REPLICAS` env var |
| `dlp-agent` | Server URL | No | TOML file, `DLP_SERVER_URL` env var, or default |
| `dlp-agent` | Config file | No | `C:\ProgramData\DLP\agent-config.toml` (default) |
| `dlp-admin-cli` | Server URL | No | `--connect`, `DLP_SERVER_URL`, or auto-detect |

---

## Per-environment overrides

The system supports hierarchical configuration with the following precedence:

**For `dlp-agent` server URL:**
1. `DLP_SERVER_URL` env var (highest priority — use for deployment-specific overrides)
2. `server_url` in `agent-config.toml` (team-shared baseline)
3. Compiled default `http://127.0.0.1:9090`

**For `dlp-agent` monitoring paths:**
1. Per-agent override in `agent_config_overrides` table (server-pushed)
2. Global default in `global_agent_config` table (server-pushed)
3. `monitored_paths` in `agent-config.toml`
4. All mounted drives A–Z (compiled default)

**For `dlp-server` JWT:**
1. `JWT_SECRET` env var
2. `--dev` flag (insecure fallback for local development)
3. Server refuses to start (no fallback in production)

**For `dlp-admin-cli` server URL:**
1. `DLP_SERVER_URL` env var (or `--connect` which sets it)
2. Registry `HKLM\SOFTWARE\DLP\PolicyEngine\BindAddr`
3. Local port probe
4. Compiled default `http://127.0.0.1:9090`