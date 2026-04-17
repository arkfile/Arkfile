# Admin CLI Updates Plan

## Problem

The `arkfile-admin` CLI is missing several critical admin operations. Some handlers exist in Go source code but have **no routes registered** in `route_config.go` (dead code). Other operations have no handler or endpoint at all. This creates gaps in the admin's ability to manage users, files, and shares from the command line.

## Current State: arkfile-admin CLI Commands

### Existing commands (working)
- `bootstrap` — Bootstrap first admin user
- `login` / `logout` / `setup-totp` — Admin authentication
- `list-users` — List all users
- `approve-user` — Approve user account
- `user-status` — Get user status
- `user-contact-info` — View user's contact info
- `set-storage` — Set user storage limit
- `revoke-user` — Revoke user access (sets `is_approved = false`)
- `export-file` — Export encrypted file as `.arkbackup`
- `system-status` — System overview
- `health-check` — System health
- `verify-storage` — S3 connectivity test
- `version` — Version info

## Gap Analysis

### Priority 1: Dead Code — Handlers Exist But No Routes

These handlers are implemented in `handlers/admin.go` and `handlers/auth.go` but have **no routes** in `route_config.go`. They need routes added first, then CLI commands.

| Handler | File | What It Does | Proposed Route | Proposed CLI Command |
|---|---|---|---|---|
| `DeleteUser` | `handlers/admin.go` | Deletes user + files from storage + shares + metadata | `DELETE /api/admin/users/:username` | `delete-user` |
| `UpdateUser` | `handlers/admin.go` | Updates `is_approved`, `is_admin`, `storage_limit_bytes` | `PUT /api/admin/users/:username` | `update-user` |
| `AdminForceLogout` | `handlers/auth.go` | Revokes all tokens for a user | `POST /api/admin/users/:username/force-logout` | `force-logout` |

**Action items:**
1. Add routes to `route_config.go` in the `adminGroup`:
   ```go
   adminGroup.DELETE("/users/:username", DeleteUser)
   adminGroup.PUT("/users/:username", UpdateUser)
   adminGroup.POST("/users/:username/force-logout", AdminForceLogout)
   ```
2. Add CLI commands in `cmd/arkfile-admin/main.go`
3. Add unit tests for the new routes

### Priority 2: Missing CLI Commands for Existing Endpoints

These server endpoints exist and are routed, but the `arkfile-admin` CLI doesn't expose them.

| Endpoint | Description | Proposed CLI Command |
|---|---|---|
| `GET /api/admin/security/events` | Security event logs | `security-events` |
| `GET /api/admin/credits` | List all user credits | `list-credits` |
| `GET /api/admin/credits/:username` | Get user's credits | `get-credits` |
| `POST /api/admin/credits/:username` | Adjust user credits | `adjust-credits` |
| `PUT /api/admin/credits/:username` | Set user credits | `set-credits` |

### Priority 3: Missing Server Endpoints + CLI Commands

These are operations that have **no handler, no route, and no CLI command** but are needed for a complete admin toolkit.

| Operation | Description | Proposed Route | Proposed CLI |
|---|---|---|---|
| Admin delete specific file | Delete a user's file by file_id (from storage + DB) | `DELETE /api/admin/files/:fileId` | `delete-file` |
| Admin revoke specific share | Revoke a share by share_id | `POST /api/admin/shares/:shareId/revoke` | `revoke-share` |
| Admin list user's files | List files owned by a user | `GET /api/admin/users/:username/files` | `list-files` |
| Admin list user's shares | List shares owned by a user | `GET /api/admin/users/:username/shares` | `list-shares` |

## Implementation Order

### Phase 1: Wire up dead code (Priority 1)
1. Add 3 routes to `route_config.go` for `DeleteUser`, `UpdateUser`, `AdminForceLogout`
2. Add `delete-user`, `update-user`, `force-logout` commands to `arkfile-admin`
3. `delete-user` should require `--confirm` flag (destructive operation)
4. Update `admin_test.go` mocks to cover the routed handlers
5. Add e2e test coverage for delete-user flow

### Phase 2: Surface existing endpoints (Priority 2)
1. Add `security-events` command
2. Add credits commands (`list-credits`, `get-credits`, `adjust-credits`, `set-credits`)

### Phase 3: New admin endpoints (Priority 3)
1. Implement `AdminDeleteFile` handler + route + CLI
2. Implement `AdminRevokeShare` handler + route + CLI
3. Implement `AdminListUserFiles` handler + route + CLI
4. Implement `AdminListUserShares` handler + route + CLI

## Security Notes

- All admin endpoints require JWT auth + admin middleware (already enforced by `adminGroup`)
- `DeleteUser` is destructive and irreversible — CLI must require `--confirm` flag
- `AdminForceLogout` revokes all JWT + refresh tokens — important for incident response
- Admin file/share operations should be logged via `LogAdminAction` and `LogSecurityEvent`
- The `DeleteUser` handler (now fixed) correctly targets `file_share_keys` table, not the legacy `file_shares` table

## Related Files

- `cmd/arkfile-admin/main.go` — CLI tool (2083 lines)
- `handlers/admin.go` — Admin handlers (includes `DeleteUser`, `UpdateUser`)
- `handlers/auth.go` — Auth handlers (includes `AdminForceLogout`)
- `handlers/route_config.go` — Route registration
- `handlers/admin_test.go` — Admin handler tests
- `docs/api.md` — API documentation (needs updating)
