# Admin CLI Updates Plan

## Status: IMPLEMENTED

All phases have been implemented. See summary below.

## Problem (Resolved)

The `arkfile-admin` CLI was missing several critical admin operations. Some handlers existed in Go source code but had no routes registered in `route_config.go` (dead code). Other operations had no handler or endpoint at all.

## Current State: arkfile-admin CLI Commands

### All commands (working)
- `bootstrap` -- Bootstrap first admin user
- `login` / `logout` / `setup-totp` -- Admin authentication
- `list-users` -- List all users
- `approve-user` -- Approve user account
- `user-status` -- Get user status
- `user-contact-info` -- View user's contact info
- `set-storage` -- Set user storage limit
- `revoke-user` -- Revoke user access (sets `is_approved = false`)
- `update-user` -- Update user properties (`is_admin`, `is_approved`, `storage_limit_bytes`)
- `delete-user` -- Delete user + all files/shares/metadata (requires `--confirm`)
- `force-logout` -- Revoke all JWT + refresh tokens for a user (incident response)
- `list-files` -- List files owned by a user (admin inspection)
- `list-shares` -- List shares owned by a user (admin inspection)
- `delete-file` -- Delete a specific file by ID from storage + DB (requires `--confirm`)
- `revoke-share` -- Revoke a specific share by ID
- `security-events` -- View recent security events
- `export-file` -- Export encrypted file as `.arkbackup`
- `system-status` -- System overview
- `health-check` -- System health
- `verify-storage` -- S3 connectivity test
- `version` -- Version info

## Implementation Summary

### Phase 1: Wired Up Dead Code (Previously Unrouted Handlers)

| Handler | Route Added | CLI Command | Status |
|---|---|---|---|
| `DeleteUser` | `DELETE /api/admin/users/:username` | `delete-user` | Done |
| `UpdateUser` | `PUT /api/admin/users/:username` | `update-user` | Done |
| `AdminForceLogout` | `POST /api/admin/users/:username/force-logout` | `force-logout` | Done |

### Phase 2: CLI Commands for Existing Endpoints

| Endpoint | CLI Command | Status |
|---|---|---|
| `GET /api/admin/security/events` | `security-events` | Done |

### Phase 3: New Server Endpoints + CLI Commands

| Operation | Route | CLI Command | Status |
|---|---|---|---|
| Admin list user's files | `GET /api/admin/users/:username/files` | `list-files` | Done |
| Admin list user's shares | `GET /api/admin/users/:username/shares` | `list-shares` | Done |
| Admin delete specific file | `DELETE /api/admin/files/:fileId` | `delete-file` | Done |
| Admin revoke specific share | `POST /api/admin/shares/:shareId/revoke` | `revoke-share` | Done |

## E2E Test Coverage

All new commands are tested in Phase 11 of `e2e-test.sh` (sections 11.4 through 11.12):

- 11.4: `security-events` -- Retrieves security events
- 11.5: `list-files` -- Lists test user's files, verifies file ID appears
- 11.6: `list-shares` -- Lists test user's shares
- 11.7: `update-user` -- Updates test user properties
- 11.8: `force-logout` -- Force-logs out test user
- 11.9: `revoke-share` -- Admin revokes Share D
- 11.10: `delete-file` -- Admin deletes custom-password file
- 11.11: `delete-user` -- Admin deletes test user (final destructive test)
- 11.12: Verify deleted user no longer exists via `user-status`

All tests use the existing admin session from Phase 2. No new login/logout cycles introduced.

## Security Notes

- All admin endpoints require JWT auth + admin middleware (enforced by `adminGroup`)
- `delete-user` is destructive and irreversible -- CLI requires `--confirm` flag
- `delete-file` is destructive and irreversible -- CLI requires `--confirm` flag
- `force-logout` revokes all JWT + refresh tokens -- important for incident response
- Admin file/share operations are logged via `LogAdminAction` and security event logging
- The `DeleteUser` handler correctly targets `file_share_keys` table

## Related Files

- `cmd/arkfile-admin/main.go` -- CLI tool
- `handlers/admin.go` -- Admin handlers (includes all new handlers)
- `handlers/auth.go` -- Auth handlers (includes `AdminForceLogout`)
- `handlers/route_config.go` -- Route registration (all routes registered)
- `scripts/testing/e2e-test.sh` -- E2E tests (Phase 11 sections 11.4-11.12)
