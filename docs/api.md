# Arkfile API Reference

This document provides a reference for the Arkfile API. It is intended for developers who wish to integrate their applications with the Arkfile platform.

## Authentication

All requests to the Arkfile API must be authenticated using a JSON Web Token (JWT). The token should be included in the `Authorization` header of your HTTP request with the `Bearer` scheme.

`Authorization: Bearer <your-jwt-token>`

Tokens can be obtained by making a POST request to the `/login` endpoint with a valid username and password.

## Endpoints

The tables below list every current HTTP endpoint exposed by Arkfile v1.  
`AUTH` column shows whether the request needs an **Access Token**, **Admin Token** or is **Public**.

### 1 • Authentication & Session

| Method | Path | Purpose | Auth | Example |
|--------|------|---------|------|---------|
| POST | `/api/opaque/register` | Create a new user using the OPAQUE PAKE flow | Public | `curl -X POST -d @register.json http://localhost:8080/api/opaque/register` |
| POST | `/api/opaque/login` | Log in and receive access / refresh tokens | Public | `curl -X POST -d @login.json http://localhost:8080/api/opaque/login` |
| POST | `/api/opaque/capability` | Device benchmark for Argon2id tuning | Public | `curl -X POST http://localhost:8080/api/opaque/capability` |
| GET  | `/api/opaque/health` | Simple health probe for the OPAQUE service | Public | `curl http://localhost:8080/api/opaque/health` |
| POST | `/api/refresh` | Exchange a refresh token for a new access token | Access | `curl -X POST --cookie "refresh=…" http://localhost:8080/api/refresh` |
| POST | `/api/logout` | Invalidate current session refresh token | Access | `curl -X POST -H "Authorization: Bearer $TOK" http://localhost:8080/api/logout` |
| POST | `/api/revoke-token` | Revoke an arbitrary token (self-service) | Access | `curl -X POST -H "Authorization: Bearer $TOK" -d '{"token":"…"}' http://localhost:8080/api/revoke-token` |
| POST | `/api/revoke-all` | Revoke **all** tokens belonging to the user | Access | `curl -X POST -H "Authorization: Bearer $TOK" http://localhost:8080/api/revoke-all` |

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

#### Chunked Uploads (large files)

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| POST | `/api/uploads/init` | Begin a multi-part upload, returns `sessionId` | Access |
| POST | `/api/uploads/:sessionId/chunks/:chunkNumber` | Upload numbered chunk | Access |
| POST | `/api/uploads/:sessionId/complete` | Finish the upload and assemble the file | Access |
| GET  | `/api/uploads/:sessionId/status` | Check progress | Access |
| DELETE | `/api/uploads/:sessionId` | Cancel and discard the session | Access |

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
| POST | `/shared/:id/auth` | Provide share password, receive token | Public |
| GET  | `/shared/:id/download` | Download the shared file | Public |
| GET  | `/api/shared/:shareId` | JSON metadata for the share | Public |
| POST | `/api/shared/:shareId/auth` | Same as `/shared/:id/auth` but JSON | Public |
| GET  | `/api/shared/:shareId/download` | File download via API | Public |

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
| PATCH | `/api/admin/users/:email` | Update a user (roles, status) |
| DELETE | `/api/admin/users/:email` | Delete a user |
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
