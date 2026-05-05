---
sliceId: S05
title: Server-side disk registry
status: complete
completedAt: 2026-05-04
tasksCompleted: 3
---

# S05: Server-side disk registry

## What was delivered

Server-side disk registry with full CRUD API. Admin can register disks, assign tiers (FullAccess/ReadOnly/Blocked), and manage the registry. Agents sync disk tiers from server on startup and periodic poll. Database repository with SQLite storage.

## Key files

- `dlp-server/src/db/repositories/disk_registry.rs` — database layer
- `dlp-server/src/admin_api.rs` — REST API endpoints for disk management
- `dlp-agent/src/server_client.rs` — agent-side sync client

## Decisions made

- REST API follows existing device_registry pattern (POST/GET/PUT/DELETE)
- Disk identified by volume_guid (server stores as primary key)
- Tier enum matches USB tier model (FullAccess/ReadOnly/Blocked)
