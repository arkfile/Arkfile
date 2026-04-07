# Share Endpoints Refactoring Plan

> **IMPORTANT**: This is a greenfield application with no current deployments. There are no backwards compatibility concerns. For LLM/agentic coding guidelines, refer to [AGENTS.md](../AGENTS.md).

---

## Implementation Status

**Last Updated**: 2026-01-16

| Task | Status | Notes |
|------|--------|-------|
| Update route_config.go | ✅ DONE | Separated authenticated vs public routes |
| Add GetShare handler | ✅ DONE | Handler exists in file_shares.go |
| Update share-access.ts | ✅ DONE | Changed to `/api/public/shares` |
| Update streaming-download.ts | ✅ DONE | Changed to `/api/public/shares` |
| Update share-creation.ts | ✅ DONE | Uses `/api/shares` |
| Update share-list.ts | ✅ DONE | Uses POST for revoke (not PATCH) |
| Update e2e-test.sh | ✅ DONE | Uses correct endpoints |
| Update arkfile-client | ✅ DONE | Uses correct endpoints with `/api/public/shares` |
| Update docs/api.md | ✅ DONE | Fully rewritten to match implementation |
| Revert rate_limiting.go workaround | ✅ DONE | Routes properly separated |

**Current Blocker**: Phase 9.4 (Share listing) fails because `ShareRateLimitMiddleware` is applied to `/api` group and requires `:id` parameter, but `GET /api/shares` has no `:id`.

---

## Problem Statement

The e2e test fails at Phase 9.4 (Share listing) because:

1. `ShareRateLimitMiddleware` is applied to the `/api` group
2. The middleware requires `c.Param("id")` to be present
3. The authenticated `GET /api/shares` (list shares) endpoint has no `:id` parameter
4. Result: `400 Bad Request: "Share ID required"`

Server log evidence:
```
{"uri":"/api/shares","status":400,"error":"code=400, message=Share ID required"}
```

## Current State (Problematic)

### Authenticated Share Routes (totpProtectedGroup)
| Method | Path | Handler | Issue |
|--------|------|---------|-------|
| GET | `/api/files/:fileId/envelope` | `GetFileEnvelope` | OK |
| POST | `/api/files/:fileId/share` | `CreateFileShare` | Duplicate of POST /api/shares |
| POST | `/api/shares` | `CreateFileShare` | OK |
| GET | `/api/shares` | `ListShares` | **FAILING - no :id** |
| GET | `/api/users/shares` | `ListShares` | Legacy duplicate - remove |
| DELETE | `/api/share/:id` | `DeleteShare` | Inconsistent path (singular) |
| POST | `/api/share/:id/revoke` | `RevokeShare` | Inconsistent path (singular) |

### Anonymous Share Routes (shareGroup with rate limiting)
| Method | Path | Handler | Issue |
|--------|------|---------|-------|
| GET | `/api/shares/:id` | `GetSharedFile` | Conflicts with authenticated routes |
| GET | `/api/shares/:id/envelope` | `GetShareEnvelope` | OK |
| GET | `/api/shares/:id/download` | `DownloadSharedFile` | OK |
| GET | `/api/shares/:id/metadata` | `GetShareDownloadMetadata` | OK |
| GET | `/api/shares/:id/chunks/:chunkIndex` | `DownloadShareChunk` | OK |

## Target State (Clean RESTful Design)

### Authenticated Endpoints (require TOTP)
Standard REST resource at `/api/shares`:

| Method | Path | Handler | Purpose |
|--------|------|---------|---------|
| GET | `/api/shares` | `ListShares` | List all shares owned by user |
| POST | `/api/shares` | `CreateFileShare` | Create a new share (file_id in body) |
| GET | `/api/shares/:id` | `GetShare` | Get details of a specific share |
| DELETE | `/api/shares/:id` | `DeleteShare` | Delete a share |
| POST | `/api/shares/:id/revoke` | `RevokeShare` | Revoke a share (soft delete) |

### Public/Anonymous Endpoints (no auth, rate-limited)
Separate namespace at `/api/public/shares`:

| Method | Path | Handler | Purpose |
|--------|------|---------|---------|
| GET | `/api/public/shares/:id` | `GetSharedFile` | Access shared file info |
| GET | `/api/public/shares/:id/envelope` | `GetShareEnvelope` | Get envelope for decryption |
| GET | `/api/public/shares/:id/download` | `DownloadSharedFile` | Download the file |
| GET | `/api/public/shares/:id/metadata` | `GetShareDownloadMetadata` | Get download metadata |
| GET | `/api/public/shares/:id/chunks/:chunkIndex` | `DownloadShareChunk` | Download file chunk |

### File Envelope Endpoint (keep as-is)
| Method | Path | Handler | Purpose |
|--------|------|---------|---------|
| GET | `/api/files/:fileId/envelope` | `GetFileEnvelope` | Get file envelope for share creation |

## Implementation Checklist

### 1. Update route_config.go

```go
// File sharing - authenticated endpoints (require TOTP)
totpProtectedGroup.GET("/api/files/:fileId/envelope", GetFileEnvelope)  // Keep
totpProtectedGroup.POST("/api/shares", CreateFileShare)                  // Keep
totpProtectedGroup.GET("/api/shares", ListShares)                        // Keep
totpProtectedGroup.GET("/api/shares/:id", GetShare)                      // NEW - get share details
totpProtectedGroup.DELETE("/api/shares/:id", DeleteShare)                // Update path
totpProtectedGroup.POST("/api/shares/:id/revoke", RevokeShare)           // Update path

// REMOVE these:
// totpProtectedGroup.POST("/api/files/:fileId/share", CreateFileShare)  // Duplicate
// totpProtectedGroup.GET("/api/users/shares", ListShares)               // Legacy

// Anonymous share access - separate namespace with rate limiting
publicShareGroup := Echo.Group("/api/public/shares")
publicShareGroup.Use(ShareRateLimitMiddleware)
publicShareGroup.Use(TimingProtectionMiddleware)
publicShareGroup.GET("/:id", GetSharedFile)
publicShareGroup.GET("/:id/envelope", GetShareEnvelope)
publicShareGroup.GET("/:id/download", DownloadSharedFile)
publicShareGroup.GET("/:id/metadata", GetShareDownloadMetadata)
publicShareGroup.GET("/:id/chunks/:chunkIndex", DownloadShareChunk)
```

### 2. Update handlers/file_shares.go

- Add `GetShare` handler if not exists (get single share details for owner)
- Verify all handlers work with new route structure

### 3. Update scripts/testing/e2e-test.sh

Update Phase 9 to use new endpoints:
- `GET /api/shares` for listing (authenticated)
- `GET /api/public/shares/:id` for anonymous access

### 4. Update client-side code

The following frontend files need updates to use the new `/api/public/shares` namespace for anonymous access:

#### 4.1 `client/static/js/src/shares/share-access.ts`

**Current (line ~79):**
```typescript
const response = await fetch(`/api/shares/${this.shareId}/envelope`);
```

**Change to:**
```typescript
const response = await fetch(`/api/public/shares/${this.shareId}/envelope`);
```

#### 4.2 `client/static/js/src/shares/share-list.ts`

**Authenticated endpoints - VERIFIED CORRECT:**
- `GET /api/shares` (line ~54) - authenticated, correct
- `POST /api/shares/${shareId}/revoke` (line ~195) - authenticated, uses POST (not PATCH)

#### 4.3 `client/static/js/src/files/streaming-download.ts`

**Current (line ~213):**
```typescript
const response = await fetch(`${this.baseUrl}/api/shares/${shareId}/metadata`, {
```

**Change to:**
```typescript
const response = await fetch(`${this.baseUrl}/api/public/shares/${shareId}/metadata`, {
```

**Current (line ~295):**
```typescript
`${this.baseUrl}/api/shares/${shareId}/chunks/${chunkIndex}`,
```

**Change to:**
```typescript
`${this.baseUrl}/api/public/shares/${shareId}/chunks/${chunkIndex}`,
```

#### 4.4 `client/static/js/src/shares/share-creation.ts`

**Current (line ~107):**
```typescript
const response = await authenticatedFetch(`/api/files/${request.fileId}/share`, {
```

**Change to:**
```typescript
const response = await authenticatedFetch(`/api/shares`, {
```

This removes the duplicate `/api/files/:fileId/share` endpoint usage. The `file_id` is already in the request body.

### Summary of Frontend Changes

| File | Current Endpoint | New Endpoint | Auth Type |
|------|-----------------|--------------|-----------|
| `share-access.ts` | `/api/shares/:id/envelope` | `/api/public/shares/:id/envelope` | Anonymous |
| `streaming-download.ts` | `/api/shares/:id/metadata` | `/api/public/shares/:id/metadata` | Anonymous |
| `streaming-download.ts` | `/api/shares/:id/chunks/:idx` | `/api/public/shares/:id/chunks/:idx` | Anonymous |
| `share-creation.ts` | `/api/files/:fileId/share` | `/api/shares` | Authenticated |
| `share-list.ts` | `/api/shares` | `/api/shares` | No change |
| `share-list.ts` | `POST /api/shares/:id/revoke` | `POST /api/shares/:id/revoke` | No change (uses POST) |

### 5. Update docs/api.md

Document the new endpoint structure.

### 6. Revert rate_limiting.go change

The middleware change made earlier should be reverted since the route restructuring will properly separate authenticated and anonymous routes:

```go
// ShareRateLimitMiddleware - keep original behavior requiring :id
// All routes in publicShareGroup will have :id parameter
if shareID == "" {
    return echo.NewHTTPError(http.StatusBadRequest, "Share ID required")
}
```

## Benefits of This Approach

1. **No middleware conflicts** - Public routes are in separate `/api/public/` namespace
2. **Clean REST design** - Standard CRUD on `/api/shares` resource
3. **Clear separation** - Authenticated vs public is obvious from path
4. **Rate limiting works** - All public routes have `:id` parameter
5. **No legacy cruft** - Removed duplicate and legacy endpoints

## Files to Modify

### Backend (Go)
1. `handlers/route_config.go` - Route definitions (main changes)
2. `handlers/file_shares.go` - Add GetShare handler if not exists
3. `handlers/rate_limiting.go` - Revert any workaround changes

### Frontend (TypeScript)
4. `client/static/js/src/shares/share-access.ts` - Update to `/api/public/shares`
5. `client/static/js/src/files/streaming-download.ts` - Update to `/api/public/shares`
6. `client/static/js/src/shares/share-creation.ts` - Update to `/api/shares`

### Testing
7. `scripts/testing/e2e-test.sh` - Update test endpoints

### Documentation
8. `docs/api.md` - Update API documentation

### CLI Tools

#### arkfile-client (cmd/arkfile-client/main.go)

The arkfile-client uses these share endpoints:

| Current Endpoint | New Endpoint | Purpose |
|-----------------|--------------|---------|
| `POST /api/shares` | `POST /api/shares` | No change |
| `DELETE /api/shares/:id` | `DELETE /api/shares/:id` | No change |
| `PATCH /api/shares/:id/revoke` | `POST /api/shares/:id/revoke` | Method change (PATCH→POST) |
| `GET /api/shares/:id/metadata` | `GET /api/public/shares/:id/metadata` | Add `/public` prefix |
| `GET /api/shares/:id/chunks/:idx` | `GET /api/public/shares/:id/chunks/:idx` | Add `/public` prefix |
| N/A | `GET /api/shares` | NEW - list user's shares |

**Changes needed in arkfile-client:**
1. Update `RevokeShare` to use POST instead of PATCH (line ~TBD)
2. Update share download metadata URL to use `/api/public/shares` prefix
3. Update share chunk download URL to use `/api/public/shares` prefix
4. Add `ListShares` command using `GET /api/shares`

#### arkfile-admin (cmd/arkfile-admin/main.go)
- No share-related endpoints - no changes needed

#### cryptocli (cmd/cryptocli/commands/commands.go)
- No share-related endpoints - no changes needed
