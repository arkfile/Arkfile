# Arkfile API Reference

This document provides a reference for the Arkfile API. It is intended for developers who wish to integrate their applications with the Arkfile platform.

## Authentication

Arkfile implements a **Netflix/Spotify-style authentication model** using JSON Web Tokens (JWT) with enhanced security and performance characteristics. Tokens should be included in the `Authorization` header of your HTTP request with the `Bearer` scheme.

`Authorization: Bearer <your-jwt-token>`

**Token Lifecycle:**
- **30-minute access tokens**: Short-lived tokens for enhanced security
- **Automatic refresh**: Client-side tokens automatically refresh at 25-minute intervals
- **Lazy revocation checking**: Revocation only checked during token refresh for optimal performance
- **Security-critical revocation**: Immediate revocation for critical security scenarios

Tokens can be obtained by making a POST request to the `/api/opaque/login` endpoint with a valid username and password. Arkfile uses a username-based authentication system where users create accounts with usernames rather than email addresses, enhancing privacy by reducing personal information stored on servers.

**Performance Optimization:**
Normal API requests do not check token revocation status for maximum speed. Revocation checking is performed only during token refresh operations, providing the optimal balance between security and performance similar to Netflix and Spotify's authentication models.

## Endpoints

The tables below list every current HTTP endpoint exposed by Arkfile v1.  
`AUTH` column shows whether the request needs an **Access Token**, **Admin Token** or is **Public**.

### 1 • Authentication & Session

| Method | Path | Purpose | Auth | Example |
|--------|------|---------|------|---------|
| POST | `/api/opaque/register` | Create a new user using the OPAQUE PAKE flow with password validation | Public | `curl -X POST -d @register.json http://localhost:8080/api/opaque/register` |
| POST | `/api/opaque/login` | Log in and receive access / refresh tokens | Public | `curl -X POST -d @login.json http://localhost:8080/api/opaque/login` |
| GET  | `/api/opaque/health` | Simple health probe for the OPAQUE service | Public | `curl http://localhost:8080/api/opaque/health` |
| POST | `/api/refresh` | Exchange a refresh token for a new access token | Access | `curl -X POST --cookie "refresh=…" http://localhost:8080/api/refresh` |
| POST | `/api/logout` | Invalidate current session and revoke tokens immediately | Access | `curl -X POST -H "Authorization: Bearer $TOK" http://localhost:8080/api/logout` |
| POST | `/api/revoke-token` | Revoke an arbitrary token (self-service) | Access | `curl -X POST -H "Authorization: Bearer $TOK" -d '{"token":"…"}' http://localhost:8080/api/revoke-token` |
| POST | `/api/revoke-all` | Revoke **all** tokens belonging to the user | Access | `curl -X POST -H "Authorization: Bearer $TOK" http://localhost:8080/api/revoke-all` |

#### Token Refresh Behavior

The `/api/refresh` endpoint implements lazy revocation checking as part of the Netflix/Spotify authentication model:

- **Normal requests**: API endpoints do not check token revocation status for optimal performance
- **Refresh operations**: Token revocation is checked during refresh to ensure security
- **30-minute lifecycle**: Tokens expire after 30 minutes and are automatically refreshed by the client at 25 minutes
- **Edge case revocations**: Critical security revocations (logout, revoke-all, admin actions) are processed immediately
- **Performance benefit**: This approach provides maximum API performance while maintaining security

When a token is revoked via `/api/logout`, `/api/revoke-all`, or administrative actions, the revocation takes effect immediately for security-critical operations but is lazily checked for normal API requests during the next refresh cycle.

### 2 • Multi-Factor Authentication (TOTP)

Arkfile supports Time-based One-Time Password (TOTP) as a second factor of authentication. When TOTP is enabled, users must complete both OPAQUE authentication and provide a valid TOTP code to access their account.

| Method | Path | Purpose | Auth | Example |
|--------|------|---------|------|---------|
| POST | `/api/totp/setup` | Initialize TOTP setup for user account | Access | `curl -X POST -H "Authorization: Bearer $TOK" -d '{"sessionKey":"..."}' http://localhost:8080/api/totp/setup` |
| POST | `/api/totp/verify` | Complete TOTP setup by verifying a test code | Access | `curl -X POST -H "Authorization: Bearer $TOK" -d '{"code":"123456","sessionKey":"..."}' http://localhost:8080/api/totp/verify` |
| GET  | `/api/totp/status` | Check TOTP enablement status for user | Access | `curl -H "Authorization: Bearer $TOK" http://localhost:8080/api/totp/status` |
| POST | `/api/totp/disable` | Disable TOTP for user account | Access | `curl -X POST -H "Authorization: Bearer $TOK" -d '{"currentCode":"123456","sessionKey":"..."}' http://localhost:8080/api/totp/disable` |
| POST | `/api/totp/auth` | Complete TOTP authentication flow | TOTP Token | `curl -X POST -H "Authorization: Bearer $TOTP_TOK" -d '{"code":"123456","sessionKey":"..."}' http://localhost:8080/api/totp/auth` |

#### TOTP Authentication Flow

When TOTP is enabled for a user account, the authentication process involves two steps. First, the user performs OPAQUE authentication via `/api/opaque/login`. If TOTP is enabled, this endpoint returns a temporary token and session key instead of a full access token. The response includes `requiresTOTP: true` to indicate that additional authentication is required.

Second, the user must provide a TOTP code via `/api/totp/auth` using the temporary token. Upon successful verification, this endpoint returns the full access token and refresh token needed for subsequent API calls. The system also supports backup codes for recovery when the TOTP device is unavailable.

#### TOTP Setup Process

Setting up TOTP requires an existing authenticated session. The `/api/totp/setup` endpoint generates a secret key, QR code URL, and backup codes. The user must scan the QR code with their authenticator app and then verify the setup by providing a test code via `/api/totp/verify`. This two-step process ensures the TOTP configuration is working correctly before enabling it for the account.

### 3 • Files

| Method | Path | Purpose | Auth | Example |
|--------|------|---------|------|---------|
| GET  | `/api/files` | List files owned by the user | Access | `curl -H "Authorization: Bearer $TOK" http://localhost:8080/api/files` |
| POST | `/api/upload` | Upload a small file in one request | Access | `curl -H "Authorization: Bearer $TOK" -F "file=@photo.jpg" http://localhost:8080/api/upload` |
| GET  | `/api/download/:filename` | Download a file | Access | `curl -H "Authorization: Bearer $TOK" -O http://localhost:8080/api/download/report.pdf` |
| DELETE | `/api/files/:filename` | Delete a file | Access | `curl -X DELETE -H "Authorization: Bearer $TOK" http://localhost:8080/api/files/report.pdf` |

#### Chunked Uploads

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| POST | `/api/uploads/init` | Begin a multi-part upload, returns `sessionId` | Access |
| POST | `/api/uploads/:sessionId/chunks/:chunkNumber` | Upload numbered chunk | Access |
| POST | `/api/uploads/:sessionId/complete` | Finish the upload and assemble the file | Access |
| GET  | `/api/uploads/:sessionId/status` | Check progress | Access |
| DELETE | `/api/uploads/:sessionId` | Cancel and discard the session | Access |

#### Chunked Downloads

All file downloads use the chunked download API. Files are stored and downloaded in encrypted chunks, with each chunk independently encrypted using AES-GCM. This provides per-chunk authentication and enables client-side decryption.

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| GET | `/api/files/:fileId/metadata` | Get file metadata for download | Access |
| GET | `/api/files/:fileId/chunks/:chunkIndex` | Download a specific encrypted chunk | Access |
| GET | `/api/files/:fileId/key` | Get decrypted FEK for account-encrypted files | Access |
| POST | `/api/files/:fileId/key` | Get decrypted FEK for custom-password files | Access |

**Metadata Response:**
```json
{
  "fileId": "uuid",
  "storageId": "storage-path",
  "encryptedFilename": "base64...",
  "filenameNonce": "base64...",
  "encryptedSha256sum": "base64...",
  "sha256sumNonce": "base64...",
  "sizeBytes": 52428800,
  "totalChunks": 10,
  "chunkSizeBytes": 5242880,
  "contentType": "application/octet-stream"
}
```

**Download Flow:**
1. Fetch metadata to get `totalChunks` and chunk size
2. Download each chunk sequentially (0 to totalChunks-1)
3. Decrypt each chunk using AES-GCM with the FEK
4. Combine decrypted chunks into the final file

Each chunk includes a 12-byte nonce prefix and 16-byte authentication tag (28 bytes overhead per chunk).

### 4 • Sharing

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| POST | `/api/share` | Create a share link for an existing file | Access |
| GET  | `/api/user/shares` | List shares you have created | Access |
| DELETE | `/api/share/:id` | Delete / revoke a share link | Access |

Public endpoints for the recipients of a share:

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| GET  | `/shared/:id` | HTML landing page for a share | Public |
| GET  | `/api/shares/:shareId/envelope` | Get share envelope (encrypted FEK + metadata) | Public |
| GET  | `/api/shares/:shareId/metadata` | Get share metadata for chunked download | Download Token |
| GET  | `/api/shares/:shareId/chunks/:chunkIndex` | Download a specific encrypted chunk | Download Token |

**Share Download Flow:**
1. Get share envelope from `/api/shares/:shareId/envelope`
2. Decrypt envelope with share password to obtain FEK and Download Token
3. Fetch metadata using Download Token in `X-Download-Token` header
4. Download each chunk sequentially using the Download Token
5. Decrypt each chunk using AES-GCM with the FEK

The Download Token is cryptographically bound to the share via AAD (Additional Authenticated Data), preventing token reuse across different shares.

### 5 • File Keys (Encryption Management)

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| GET  | `/api/files/:filename/keys` | List encryption keys for a file | Access |
| POST | `/api/files/:filename/update-encryption` | Re-encrypt a file with new parameters | Access |
| DELETE | `/api/files/:filename/keys/:keyId` | Remove a key | Access |
| PATCH | `/api/files/:filename/keys/:keyId` | Edit key metadata | Access |
| POST | `/api/files/:filename/keys/:keyId/set-primary` | Mark a key as primary | Access |

### 6 • Administration (Requires **Admin Token**)

| Method | Path | Purpose |
|--------|------|---------|
| GET  | `/api/admin/users` | List all users |
| PATCH | `/api/admin/users/:username` | Update a user (roles, status) |
| DELETE | `/api/admin/users/:username` | Delete a user |
| GET  | `/api/admin/stats` | System statistics |
| GET  | `/api/admin/activity` | Security & activity logs |

### 7 • Miscellaneous

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| GET | `/api/admin-contacts` | Returns maintainer contact JSON | Public |

---

### Error Handling

* 401 Unauthorized – missing or bad token  
* 403 Forbidden – valid token but not enough privilege  
* 404 Not Found – resource does not exist  
* 429 Too Many Requests – rate limit exceeded  
* 5xx – internal server errors

All error responses use the structure:

```json
{
  "error": "human-readable message"
}
```

### Pagination & Common Query Params

Endpoints returning lists (`/api/files`, `/api/user/shares`, `/api/admin/users`, etc.) accept:

* `?page=` (1-based)  
* `?size=` (max 100)  

Example:

```bash
curl -H "Authorization: Bearer $TOK" \
  "http://localhost:8080/api/files?page=2&size=25"
```

### Versioning

The current API is **v1**.  
Breaking changes will be announced in release notes; clients should pin a minor version via the `X-Arkfile-Version` header when that becomes available in future releases.

---

## Support

Questions, comments or bug reports? Email **arkfile [at] pm [dot] me** or open an issue on GitHub.  

Please avoid posting sensitive information in public issues.
