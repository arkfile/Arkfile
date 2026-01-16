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

Tokens can be obtained by completing the OPAQUE authentication flow via the `/api/opaque/login/*` endpoints. Arkfile uses a username-based authentication system where users create accounts with usernames rather than email addresses, enhancing privacy by reducing personal information stored on servers.

**Performance Optimization:**
Normal API requests do not check token revocation status for maximum speed. Revocation checking is performed only during token refresh operations, providing the optimal balance between security and performance similar to Netflix and Spotify's authentication models.

## Endpoints

The tables below list every current HTTP endpoint exposed by Arkfile v1.  
`AUTH` column shows whether the request needs an **Access Token**, **TOTP Token**, **Admin Token** or is **Public**.

---

### 1 • Configuration (Public)

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| GET | `/api/config/argon2` | Get Argon2 parameters for client-side crypto | Public |
| GET | `/api/config/password-requirements` | Get password validation requirements | Public |

---

### 2 • Authentication & Session

Arkfile uses the OPAQUE PAKE (Password-Authenticated Key Exchange) protocol for secure authentication without transmitting passwords.

#### User Registration (Multi-Step OPAQUE)

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| POST | `/api/opaque/register/response` | OPAQUE registration step 1 - server response | Public |
| POST | `/api/opaque/register/finalize` | OPAQUE registration step 2 - finalize registration | Public |

#### User Login (Multi-Step OPAQUE)

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| POST | `/api/opaque/login/response` | OPAQUE login step 1 - server response | Public |
| POST | `/api/opaque/login/finalize` | OPAQUE login step 2 - finalize and get tokens | Public |
| GET | `/api/opaque/health` | Health probe for OPAQUE service | Public |

#### Admin Login (Multi-Step OPAQUE)

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| POST | `/api/admin/login/response` | Admin OPAQUE login step 1 | Public |
| POST | `/api/admin/login/finalize` | Admin OPAQUE login step 2 | Public |

#### Bootstrap Registration (Initial Admin Setup)

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| POST | `/api/bootstrap/register/response` | Bootstrap registration step 1 | Public |
| POST | `/api/bootstrap/register/finalize` | Bootstrap registration step 2 | Public |

#### Session Management

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| POST | `/api/refresh` | Exchange refresh token for new access token | Refresh Cookie |
| POST | `/api/logout` | Invalidate session and revoke tokens | Access |

#### Token Revocation (Require TOTP)

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| POST | `/api/revoke-token` | Revoke a specific token | TOTP |
| POST | `/api/revoke-all` | Revoke all tokens for the user | TOTP |

---

### 3 • Multi-Factor Authentication (TOTP)

Arkfile supports Time-based One-Time Password (TOTP) as a second factor of authentication. When TOTP is enabled, users must complete both OPAQUE authentication and provide a valid TOTP code to access their account.

#### TOTP Setup & Management (Require Access Token)

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| POST | `/api/totp/setup` | Initialize TOTP setup for user account | Access |
| POST | `/api/totp/verify` | Complete TOTP setup by verifying a test code | Access |
| GET | `/api/totp/status` | Check TOTP enablement status for user | Access |
| POST | `/api/totp/reset` | Reset TOTP configuration | Access |

#### TOTP Authentication (Require TOTP Token)

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| POST | `/api/totp/auth` | Complete TOTP authentication flow | TOTP Token |

#### TOTP Authentication Flow

When TOTP is enabled for a user account, the authentication process involves two steps:

1. **OPAQUE Authentication**: User performs OPAQUE login via `/api/opaque/login/*`. If TOTP is enabled, this returns a temporary TOTP token and `requiresTOTP: true`.

2. **TOTP Verification**: User provides a TOTP code via `/api/totp/auth` using the temporary token. Upon success, this returns the full access token and refresh token.

---

### 4 • Files

All file operations require TOTP authentication.

#### Basic File Operations

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| GET | `/api/files` | List files owned by the user | TOTP |
| POST | `/api/upload` | Upload a small file in one request | TOTP |
| GET | `/api/files/:fileId` | Download a file | TOTP |
| GET | `/api/files/:fileId/meta` | Get file metadata | TOTP |
| DELETE | `/api/files/:fileId` | Delete a file | TOTP |

#### Chunked Uploads

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| POST | `/api/uploads/init` | Begin a multi-part upload, returns `sessionId` | TOTP |
| POST | `/api/uploads/:sessionId/chunks/:chunkNumber` | Upload numbered chunk | TOTP |
| POST | `/api/uploads/:sessionId/complete` | Finish the upload and assemble the file | TOTP |
| GET | `/api/uploads/:sessionId/status` | Check upload progress | TOTP |
| DELETE | `/api/uploads/:fileId` | Cancel and discard the upload session | TOTP |

#### Chunked Downloads

All file downloads use the chunked download API. Files are stored and downloaded in encrypted chunks, with each chunk independently encrypted using AES-GCM.

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| GET | `/api/files/:fileId/metadata` | Get file metadata for download | TOTP |
| GET | `/api/files/:fileId/chunks/:chunkIndex` | Download a specific encrypted chunk | TOTP |

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

---

### 5 • File Sharing

File sharing is split into two namespaces:
- **Authenticated endpoints** (`/api/shares`) - for share owners to manage shares
- **Public endpoints** (`/api/public/shares`) - for recipients to access shared files

#### Authenticated Share Management (Require TOTP)

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| GET | `/api/files/:fileId/envelope` | Get file envelope for share creation | TOTP |
| POST | `/api/shares` | Create a new share (file_id in body) | TOTP |
| GET | `/api/shares` | List shares owned by user | TOTP |
| GET | `/api/users/shares` | List shares (legacy endpoint) | TOTP |
| DELETE | `/api/shares/:id` | Delete a share | TOTP |
| POST | `/api/shares/:id/revoke` | Revoke a share (soft delete) | TOTP |

#### Public Share Access (Rate-Limited, No Auth)

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| GET | `/api/public/shares/:id` | Share access page | Public |
| GET | `/api/public/shares/:id/envelope` | Get share envelope (encrypted FEK + metadata) | Public |
| GET | `/api/public/shares/:id/download` | Download shared file (single request) | Download Token |
| GET | `/api/public/shares/:id/metadata` | Get metadata for chunked download | Download Token |
| GET | `/api/public/shares/:id/chunks/:chunkIndex` | Download a specific encrypted chunk | Download Token |

**Share Download Flow:**
1. Get share envelope from `/api/public/shares/:id/envelope`
2. Decrypt envelope with share password to obtain FEK and Download Token
3. Fetch metadata using Download Token in `X-Download-Token` header
4. Download each chunk sequentially using the Download Token
5. Decrypt each chunk using AES-GCM with the FEK

The Download Token is cryptographically bound to the share via AAD (Additional Authenticated Data), preventing token reuse across different shares.

---

### 6 • File Encryption Key Management

All key management operations require TOTP authentication.

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| GET | `/api/files/:fileId/keys` | List encryption keys for a file | TOTP |
| POST | `/api/files/:fileId/update-encryption` | Re-encrypt a file with new parameters | TOTP |
| DELETE | `/api/files/:fileId/keys/:keyId` | Remove a key | TOTP |
| PATCH | `/api/files/:fileId/keys/:keyId` | Edit key metadata | TOTP |
| POST | `/api/files/:fileId/keys/:keyId/set-primary` | Mark a key as primary | TOTP |
| POST | `/api/files/:fileId/get-decryption-key` | Get decrypted FEK for file | TOTP |

---

### 7 • Credits System

#### User Endpoints (Require TOTP)

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| GET | `/api/credits` | Get current user's credit balance | TOTP |

#### Admin Endpoints (Require Admin Token)

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| GET | `/api/admin/credits` | Get all users' credits | Admin |
| GET | `/api/admin/credits/:username` | Get specific user's credits | Admin |
| POST | `/api/admin/credits/:username` | Adjust user's credits (add/subtract) | Admin |
| PUT | `/api/admin/credits/:username` | Set user's credits to specific value | Admin |

---

### 8 • Administration

All admin endpoints require JWT authentication with admin privileges.

#### User Management

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| POST | `/api/admin/users/:username/approve` | Approve a pending user | Admin |
| GET | `/api/admin/users/:username/status` | Get user approval status | Admin |

#### System Monitoring

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| GET | `/api/admin/system/health` | Get system health status | Admin |
| GET | `/api/admin/security/events` | Get security event logs | Admin |

#### Development/Testing Endpoints

These endpoints are only available when `ADMIN_DEV_TEST_API_ENABLED=true`:

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| POST | `/api/admin/dev-test/users/cleanup` | Clean up test user data | Admin |
| GET | `/api/admin/dev-test/totp/decrypt-check/:username` | TOTP diagnostic endpoint | Admin |

---

### 9 • Miscellaneous

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| GET | `/api/admin-contacts` | Returns maintainer contact JSON | Public |

---

## Error Handling

* 400 Bad Request – invalid request parameters
* 401 Unauthorized – missing or invalid token  
* 403 Forbidden – valid token but insufficient privileges  
* 404 Not Found – resource does not exist  
* 429 Too Many Requests – rate limit exceeded  
* 5xx – internal server errors

All error responses use the structure:

```json
{
  "error": "human-readable message"
}
```

---

## Pagination & Common Query Params

Endpoints returning lists (`/api/files`, `/api/shares`, `/api/admin/credits`, etc.) accept:

* `?page=` (1-based)  
* `?size=` (max 100)  

Example:

```bash
curl -H "Authorization: Bearer $TOK" \
  "http://localhost:8080/api/files?page=2&size=25"
```

---

## Versioning

The current API is **v1**.  
Breaking changes will be announced in release notes; clients should pin a minor version via the `X-Arkfile-Version` header when that becomes available in future releases.

---

## Support

Questions, comments or bug reports? Email **arkfile [at] pm [dot] me** or open an issue on GitHub.  

Please avoid posting sensitive information in public issues.
