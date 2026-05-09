---
estimated_steps: 1
estimated_files: 2
skills_used: []
---

# T02: Server-side config storage and admin API

Add server-side database table and admin API endpoints for USB enforcement configuration (retry count, fallback policy for none-serial devices). JWT-protected CRUD.

## Inputs

- `Existing admin API patterns`
- `Agent config schema`

## Expected Output

- `New DB migration`
- `Admin API handlers`
- `Integration tests`

## Verification

cargo test --package dlp-server admin_api::
