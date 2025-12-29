# Implementation Plan: Unified Share System v2

**Objective**: Implement a complete, zero-knowledge file sharing system that supports both Account-Encrypted and Custom-Encrypted files with Download Token enforcement, streaming downloads, revocation capabilities, and access limits.

**Reference**: See `unify-share-file.md` for the complete SHARED FILE LIFECYCLE that this implementation plan targets.

---

## 1. OVERVIEW & OBJECTIVES

### Core Goals
1. **Download Token Enforcement**: Protect bandwidth by requiring a cryptographic token for file downloads
2. **Account-Encrypted File Sharing**: Enable sharing of account-encrypted files using cached AccountKey
3. **Streaming Downloads**: Stream encrypted file bytes directly instead of base64-in-JSON
4. **Revocation System**: Allow owners to manually revoke shares or auto-revoke on expiration/max downloads
5. **Access Limits**: Enforce max_accesses with atomic counting and auto-revocation
6. **Zero-Knowledge Architecture**: Server never receives passwords, FEKs, or decrypted metadata
7. **Client-Side share_id Generation**: Generate share_id on client with AAD binding to prevent envelope swapping

### Key Principles
- All cryptographic operations happen client-side (browser or CLI)
- Server only stores encrypted data and enforces access control via Download Tokens
- Argon2id parameters are unified across the entire system (from `crypto/argon2id-params.json`)
- Share Envelope contains both FEK and Download Token, encrypted with Share Password
- Share Envelope is bound to `share_id + file_id` using AEAD AAD for tamper protection
- Client generates share_id before encryption to enable AAD binding

---

## 2. DATABASE SCHEMA CHANGES

**File**: `database/unified_schema.sql`

### Add Columns to `file_share_keys` Table

```sql
-- Download Token enforcement
ALTER TABLE file_share_keys ADD COLUMN download_token_hash TEXT NOT NULL;

-- Revocation system
ALTER TABLE file_share_keys ADD COLUMN revoked_at TIMESTAMP NULL;
ALTER TABLE file_share_keys ADD COLUMN revoked_reason TEXT NULL;

-- Verify these columns exist (should already be present):
-- access_count INTEGER DEFAULT 0
-- max_accesses INTEGER NULL
```

### Add Indexes

```sql
CREATE INDEX IF NOT EXISTS idx_file_share_keys_revoked ON file_share_keys(revoked_at);
CREATE INDEX IF NOT EXISTS idx_file_share_keys_token_hash ON file_share_keys(download_token_hash);
```

### Notes
- `download_token_hash`: SHA-256 hash of the 32-byte Download Token (base64 encoded) - REQUIRED for all new shares
- `revoked_at`: Timestamp when share was revoked (NULL = active)
- `revoked_reason`: Why share was revoked (e.g., "manual_revocation", "max_downloads_reached", "expired")
- `max_accesses`: NULL means unlimited downloads
- `access_count`: Atomically incremented on each download, enforced via database transactions

---

## 3. BACKEND IMPLEMENTATION (Go)

### 3.1 New Endpoint: GET /api/files/{file_id}/envelope

**File**: `handlers/files.go` (add new function)

**Purpose**: Retrieve Owner Envelope for share creation (authenticated users only)

**Handler Function**: `GetFileEnvelope(c echo.Context) error`

**Logic**:
1. Extract `file_id` from URL parameter
2. Get username from JWT token
3. Query database:
   ```sql
   SELECT password_type, encrypted_fek, filename_nonce, sha256sum_nonce
   FROM file_metadata
   WHERE file_id = ? AND owner_username = ?
   ```
4. Verify user owns the file (return 404 if not found, 403 if not owner)
5. Return JSON response:
   ```json
   {
     "password_type": "account|custom",
     "encrypted_fek": "base64_encrypted_fek",
     "filename_nonce": "base64_nonce",
     "sha256sum_nonce": "base64_nonce"
   }
   ```

**Security**:
- Requires valid JWT authentication
- User must own the file
- Rate limiting (use existing middleware)

**Route**: Add to `handlers/route_config.go`:
```go
authenticated.GET("/files/:file_id/envelope", GetFileEnvelope)
```

---

### 3.2 New Endpoint: GET /api/shares/{id}/envelope

**File**: `handlers/file_shares.go` (add new function)

**Purpose**: Retrieve Share Envelope for recipient (anonymous, rate-limited)

**Handler Function**: `GetShareEnvelope(c echo.Context) error`

**Logic**:
1. Extract `share_id` from URL parameter
2. Get entity_id for rate limiting
3. Check rate limit (use existing `checkRateLimit` function)
4. Query database:
   ```sql
   SELECT salt, encrypted_fek, expires_at, revoked_at, fm.size_bytes
   FROM file_share_keys fsk
   JOIN file_metadata fm ON fsk.file_id = fm.file_id
   WHERE share_id = ?
   ```
5. Validate:
   - Share exists (404 if not)
   - Not expired: `expires_at IS NULL OR expires_at > NOW()`
   - Not revoked: `revoked_at IS NULL`
6. Return JSON response:
   ```json
   {
     "salt": "base64_salt",
     "encrypted_envelope": "base64_encrypted_share_envelope",
     "file_size": 12345
   }
   ```

**Security**:
- Anonymous access (no authentication required)
- Rate limited by entity_id + share_id
- Does not reveal Download Token (that's inside encrypted envelope)

**Route**: Add to `handlers/route_config.go`:
```go
public.GET("/shares/:id/envelope", GetShareEnvelope)
```

**Note**: The current `encrypted_fek` column in `file_share_keys` will be repurposed to store the encrypted Share Envelope (which contains both FEK and Download Token as JSON).

---

### 3.3 New Endpoint: PATCH /api/shares/{id}/revoke

**File**: `handlers/file_shares.go` (add new function)

**Purpose**: Manually revoke a share (authenticated owner only)

**Handler Function**: `RevokeShare(c echo.Context) error`

**Logic**:
1. Extract `share_id` from URL parameter
2. Get username from JWT token
3. Verify ownership:
   ```sql
   SELECT owner_username FROM file_share_keys WHERE share_id = ?
   ```
4. Return 404 if not found, 403 if not owner
5. Update database:
   ```sql
   UPDATE file_share_keys
   SET revoked_at = CURRENT_TIMESTAMP,
       revoked_reason = 'manual_revocation'
   WHERE share_id = ?
   ```
6. Log action: `database.LogUserAction(username, "revoked_share", share_id)`
7. Return success response

**Security**:
- Requires valid JWT authentication
- User must own the share

**Route**: Add to `handlers/route_config.go`:
```go
authenticated.PATCH("/shares/:id/revoke", RevokeShare)
```

---

### 3.4 Modify: POST /api/shares (CreateFileShare)

**File**: `handlers/file_shares.go`

**Changes to `ShareRequest` struct**:
```go
type ShareRequest struct {
    ShareID              string `json:"share_id"`            // Client-generated 43-char base64url share ID
    FileID               string `json:"file_id"`
    Salt                 string `json:"salt"`                // Base64-encoded 32-byte salt
    EncryptedEnvelope    string `json:"encrypted_envelope"`  // Base64-encoded encrypted Share Envelope (with AAD)
    DownloadTokenHash    string `json:"download_token_hash"` // Base64-encoded SHA-256 hash
    MaxAccesses          *int   `json:"max_accesses"`        // Optional: NULL = unlimited
    ExpiresAfterHours    int    `json:"expires_after_hours"` // Optional expiration
}
```

**Changes to `CreateFileShare` function**:

1. **Remove Account-Encrypted blocking**:
   - Delete this entire block:
     ```go
     if passwordType == "account" {
         return echo.NewHTTPError(http.StatusBadRequest,
             "This file is encrypted with your account password. To share it, first add a custom password for this file.")
     }
     ```

2. **Add validation for client-provided share_id**:
   ```go
   // Validate share_id format (must be 43-char base64url)
   if !isValidShareID(request.ShareID) {
       return echo.NewHTTPError(http.StatusBadRequest, "Invalid share_id format")
   }
   
   // Check uniqueness
   var exists bool
   err := database.DB.QueryRow("SELECT 1 FROM file_share_keys WHERE share_id = ?", request.ShareID).Scan(&exists)
   if err != sql.ErrNoRows {
       return echo.NewHTTPError(http.StatusConflict, "Share ID already exists - please retry")
   }
   ```

3. **Add helper function for share_id validation**:
   ```go
   func isValidShareID(shareID string) bool {
       // Must be exactly 43 characters (32 bytes base64url without padding)
       if len(shareID) != 43 {
           return false
       }
       // Must be valid base64url characters
       matched, _ := regexp.MatchString(`^[A-Za-z0-9_-]{43}$`, shareID)
       return matched
   }
   ```

4. **Add validation for other required fields**:
   ```go
   if request.DownloadTokenHash == "" {
       return echo.NewHTTPError(http.StatusBadRequest, "Download token hash is required")
   }
   if request.EncryptedEnvelope == "" {
       return echo.NewHTTPError(http.StatusBadRequest, "Encrypted envelope is required")
   }
   ```

5. **Update database INSERT** (use client-provided share_id):
   ```sql
   INSERT INTO file_share_keys (
       share_id, file_id, owner_username, salt, encrypted_fek,
       download_token_hash, max_accesses, created_at, expires_at
   )
   VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
   ```
   - Note: `encrypted_fek` column now stores the encrypted Share Envelope (with AAD binding)
   - Use `request.ShareID` (client-generated) instead of server-generated ID
   - Add `request.DownloadTokenHash` and `request.MaxAccesses` to values

6. **Remove server-side share_id generation**:
   - Delete the `generateShareID()` function call
   - Delete the `generateShareID()` function entirely (no longer needed)

7. **Update logging**:
   ```go
   logging.InfoLogger.Printf("Share created: file=%s, share_id=%s..., owner=%s, max_accesses=%v",
       request.FileID, request.ShareID[:8], username, request.MaxAccesses)
   ```

**Security Notes**:
- `SharePassword` is never sent to server (only used client-side for encryption)
- Server stores encrypted envelope and hash, never the plaintext token
- Both Account-Encrypted and Custom-Encrypted files can now be shared

---

### 3.5 Modify: GET /api/shares/{id}/download (DownloadSharedFile)

**File**: `handlers/file_shares.go`

**Critical Changes**:

1. **Require X-Download-Token header**:
   ```go
   downloadToken := c.Request().Header.Get("X-Download-Token")
   if downloadToken == "" {
       return echo.NewHTTPError(http.StatusForbidden, "Download token required")
   }
   ```

2. **Validate Download Token** (constant-time comparison):
   ```go
   import "crypto/subtle"
   import "crypto/sha256"
   import "encoding/base64"

   // Compute hash of provided token
   tokenBytes, err := base64.StdEncoding.DecodeString(downloadToken)
   if err != nil {
       return echo.NewHTTPError(http.StatusForbidden, "Invalid token format")
   }
   
   providedHash := sha256.Sum256(tokenBytes)
   providedHashB64 := base64.StdEncoding.EncodeToString(providedHash[:])
   
   // Retrieve stored hash from database
   var storedHash string
   err = database.DB.QueryRow(
       "SELECT download_token_hash FROM file_share_keys WHERE share_id = ?",
       shareID,
   ).Scan(&storedHash)
   
   if err != nil {
       return echo.NewHTTPError(http.StatusNotFound, "Share not found")
   }
   
   // Constant-time comparison
   if subtle.ConstantTimeCompare([]byte(providedHashB64), []byte(storedHash)) != 1 {
       logging.SecurityLogger.Printf("Invalid download token for share %s...", shareID[:8])
       return echo.NewHTTPError(http.StatusForbidden, "Invalid download token")
   }
   ```

3. **Check revocation status**:
   ```go
   var revokedAt sql.NullTime
   err = database.DB.QueryRow(
       "SELECT revoked_at FROM file_share_keys WHERE share_id = ?",
       shareID,
   ).Scan(&revokedAt)
   
   if revokedAt.Valid {
       return echo.NewHTTPError(http.StatusForbidden, "Share has been revoked")
   }
   ```

4. **Atomic access_count enforcement** (use transaction):
   ```go
   tx, err := database.DB.Begin()
   if err != nil {
       logging.ErrorLogger.Printf("Failed to start transaction: %v", err)
       return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
   }
   defer tx.Rollback()
   
   // Lock row and get current counts
   var accessCount int
   var maxAccesses sql.NullInt64
   var revokedAt sql.NullTime
   
   err = tx.QueryRow(`
       SELECT access_count, max_accesses, revoked_at
       FROM file_share_keys
       WHERE share_id = ?
   `, shareID).Scan(&accessCount, &maxAccesses, &revokedAt)
   
   if err != nil {
       return echo.NewHTTPError(http.StatusNotFound, "Share not found")
   }
   
   // Check revocation again (inside transaction)
   if revokedAt.Valid {
       return echo.NewHTTPError(http.StatusForbidden, "Share has been revoked")
   }
   
   // Check if max accesses would be exceeded
   if maxAccesses.Valid && accessCount >= int(maxAccesses.Int64) {
       return echo.NewHTTPError(http.StatusForbidden, "Share download limit reached")
   }
   
   // Increment access count
   newAccessCount := accessCount + 1
   
   // Check if this download will reach the limit
   shouldRevoke := maxAccesses.Valid && newAccessCount >= int(maxAccesses.Int64)
   
   if shouldRevoke {
       _, err = tx.Exec(`
           UPDATE file_share_keys
           SET access_count = ?,
               revoked_at = CURRENT_TIMESTAMP,
               revoked_reason = 'max_downloads_reached'
           WHERE share_id = ?
       `, newAccessCount, shareID)
   } else {
       _, err = tx.Exec(`
           UPDATE file_share_keys
           SET access_count = ?
           WHERE share_id = ?
       `, newAccessCount, shareID)
   }
   
   if err != nil {
       logging.ErrorLogger.Printf("Failed to update access count: %v", err)
       return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
   }
   
   // Commit transaction
   if err = tx.Commit(); err != nil {
       logging.ErrorLogger.Printf("Failed to commit transaction: %v", err)
       return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
   }
   ```

5. **Stream file bytes with padding handling** (remove base64-in-JSON):
   ```go
   // Get file metadata including padding info
   var fileSize int64
   var paddedSize sql.NullInt64
   var storageID string
   
   err = database.DB.QueryRow(`
       SELECT fm.size_bytes, fm.padded_size, fm.storage_id
       FROM file_metadata fm
       JOIN file_share_keys fsk ON fm.file_id = fsk.file_id
       WHERE fsk.share_id = ?
   `, shareID).Scan(&fileSize, &paddedSize, &storageID)
   
   if err != nil {
       logging.ErrorLogger.Printf("Failed to retrieve file metadata: %v", err)
       return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve file")
   }
   
   // Get file from storage with padding handling
   // NOTE: GetObjectWithoutPadding exists in storage/s3.go and correctly strips padding
   var object io.ReadCloser
   
   if paddedSize.Valid && paddedSize.Int64 > fileSize {
       // File has padding - use GetObjectWithoutPadding to strip it
       object, err = storage.Provider.GetObjectWithoutPadding(
           c.Request().Context(),
           storageID,
           fileSize,
           storage.GetObjectOptions{},
       )
   } else {
       // No padding - use regular GetObject
       object, err = storage.Provider.GetObject(
           c.Request().Context(),
           storageID,
           storage.GetObjectOptions{},
       )
   }
   
   if err != nil {
       logging.ErrorLogger.Printf("Failed to retrieve file from storage: %v", err)
       return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve file")
   }
   defer object.Close()
   
   // Set headers for streaming download
   c.Response().Header().Set("Content-Type", "application/octet-stream")
   c.Response().Header().Set("Content-Disposition", "attachment; filename=\"shared-file.enc\"")
   c.Response().Header().Set("Content-Length", fmt.Sprintf("%d", fileSize))
   c.Response().Header().Set("Accept-Ranges", "bytes")
   
   // Stream the file
   c.Response().WriteHeader(http.StatusOK)
   _, err = io.Copy(c.Response().Writer, object)
   if err != nil {
       logging.ErrorLogger.Printf("Failed to stream file: %v", err)
       return err
   }
   
   // Log download (use truncated share_id for privacy)
   entityID := logging.GetOrCreateEntityID(c)
   logging.InfoLogger.Printf("Shared file downloaded: share_id=%s..., file=%s, entity_id=%s, access=%d/%v",
       shareID[:8], share.FileID, entityID, newAccessCount, maxAccesses)
   
   return nil
   ```

**Remove**:
- Delete the entire JSON response with base64-encoded data
- Delete `io.ReadAll` and base64 encoding logic

**Security Notes**:
- Download Token validation uses constant-time comparison to prevent timing attacks
- Transaction ensures atomic access_count increment (prevents race conditions)
- Auto-revocation happens immediately when max_accesses is reached
- Streaming reduces memory usage and improves performance for large files
- Padding is properly handled via `GetObjectWithoutPadding()` (verified to exist in storage/s3.go)
- Content-Length header reflects the actual file size (not padded size)

---

### 3.6 Modify: GET /api/shares (ListShares)

**File**: `handlers/file_shares.go`

**Changes**:

1. **Update SQL query** to include revocation data:
   ```sql
   SELECT sk.share_id, sk.file_id, sk.created_at, sk.expires_at,
          sk.revoked_at, sk.revoked_reason, sk.access_count, sk.max_accesses,
          fm.encrypted_filename, fm.filename_nonce, fm.encrypted_sha256sum,
          fm.sha256sum_nonce, fm.size_bytes
   FROM file_share_keys sk
   JOIN file_metadata fm ON sk.file_id = fm.file_id
   WHERE sk.owner_username = ?
   ORDER BY sk.created_at DESC
   ```

2. **Update struct** to include new fields:
   ```go
   var share struct {
       ShareID            string
       FileID             string
       CreatedAt          string
       ExpiresAt          sql.NullString
       RevokedAt          sql.NullString
       RevokedReason      sql.NullString
       AccessCount        int
       MaxAccesses        sql.NullInt64
       EncryptedFilename  string
       FilenameNonce      string
       EncryptedSha256sum string
       Sha256sumNonce     string
       Size               sql.NullInt64
   }
   ```

3. **Update Scan** to include new fields:
   ```go
   if err := rows.Scan(
       &share.ShareID,
       &share.FileID,
       &share.CreatedAt,
       &share.ExpiresAt,
       &share.RevokedAt,
       &share.RevokedReason,
       &share.AccessCount,
       &share.MaxAccesses,
       &share.EncryptedFilename,
       &share.FilenameNonce,
       &share.EncryptedSha256sum,
       &share.Sha256sumNonce,
       &share.Size,
   ); err != nil {
       logging.ErrorLogger.Printf("Error scanning share row: %v", err)
       continue
   }
   ```

4. **Include in response**:
   ```go
   shareData := map[string]interface{}{
       "share_id":            share.ShareID,
       "file_id":             share.FileID,
       "encrypted_filename":  share.EncryptedFilename,
       "filename_nonce":      share.FilenameNonce,
       "encrypted_sha256sum": share.EncryptedSha256sum,
       "sha256sum_nonce":     share.Sha256sumNonce,
       "share_url":           shareURL,
       "created_at":          share.CreatedAt,
       "access_count":        share.AccessCount,
   }
   
   if share.Size.Valid {
       shareData["size"] = share.Size.Int64
   }
   
   if share.ExpiresAt.Valid {
       shareData["expires_at"] = share.ExpiresAt.String
   } else {
       shareData["expires_at"] = nil
   }
   
   if share.MaxAccesses.Valid {
       shareData["max_accesses"] = share.MaxAccesses.Int64
   } else {
       shareData["max_accesses"] = nil
   }
   
   if share.RevokedAt.Valid {
       shareData["revoked_at"] = share.RevokedAt.String
       shareData["revoked_reason"] = share.RevokedReason.String
       shareData["is_active"] = false
   } else {
       shareData["revoked_at"] = nil
       shareData["revoked_reason"] = nil
       shareData["is_active"] = true
   }
   ```

---

### 3.7 Rate Limiting Configuration

**File**: `config/security_config.go` or `handlers/rate_limiting.go`

**Rate Limit Values**:
- **Envelope Access** (`GET /api/shares/{id}/envelope`): 30 requests/minute per entity_id
- **File Downloads** (`GET /api/shares/{id}/download`): 30 requests/minute per entity_id  
- **Share Creation** (`POST /api/shares`): 120 requests/minute per entity_id (authenticated users)

**Add rate limiting to download endpoint**:

In `DownloadSharedFile`, add rate limit check at the beginning (after extracting share_id):

```go
entityID := logging.GetOrCreateEntityID(c)

// Rate limit downloads separately from envelope access
allowed, delay, rateLimitErr := checkRateLimit(shareID, entityID)
if rateLimitErr != nil {
    logging.ErrorLogger.Printf("Rate limit check failed: %v", rateLimitErr)
    // Continue on error to avoid blocking legitimate users
} else if !allowed {
    c.Response().Header().Set("Retry-After", fmt.Sprintf("%d", int(delay.Seconds())))
    return echo.NewHTTPError(http.StatusTooManyRequests, "Too many download requests")
}
```

**Note**: This uses the existing `checkRateLimit` function but applies it to the download endpoint as well.

---

## 4. CRYPTO LAYER (Go)

### 4.1 Share Envelope Format with AAD Binding

**File**: `crypto/share_kdf.go` (or create new `crypto/share_envelope.go`)

**Define Share Envelope structure with AAD binding**:

```go
package crypto

import (
    "encoding/base64"
    "encoding/json"
    "fmt"
)

// ShareEnvelope represents the decrypted content of a Share Envelope
// This is a simple JSON structure containing the FEK and Download Token
type ShareEnvelope struct {
    FEK           string `json:"fek"`            // base64-encoded FEK
    DownloadToken string `json:"download_token"` // base64-encoded Download Token
}

// CreateShareEnvelope creates a Share Envelope JSON payload
func CreateShareEnvelope(fek, downloadToken []byte) ([]byte, error) {
    envelope := ShareEnvelope{
        FEK:           base64.StdEncoding.EncodeToString(fek),
        DownloadToken: base64.StdEncoding.EncodeToString(downloadToken),
    }
    
    return json.Marshal(envelope)
}

// ParseShareEnvelope parses a Share Envelope JSON payload
func ParseShareEnvelope(envelopeJSON []byte) (*ShareEnvelope, error) {
    var envelope ShareEnvelope
    if err := json.Unmarshal(envelopeJSON, &envelope); err != nil {
        return nil, fmt.Errorf("failed to parse share envelope: %w", err)
    }
    
    // Validate required fields
    if envelope.FEK == "" || envelope.DownloadToken == "" {
        return nil, fmt.Errorf("invalid envelope: missing required fields")
    }
    
    return &envelope, nil
}

// CreateAAD creates the Additional Authenticated Data for envelope encryption
// AAD = share_id + file_id (UTF-8 encoded concatenation)
func CreateAAD(shareID, fileID string) []byte {
    return []byte(shareID + fileID)
}
```

**Notes**:
- Simple JSON structure with just FEK and Download Token
- Encrypted with Share Password using Argon2id (UnifiedArgonSecure params) + AES-256-GCM **with AAD**
- AAD = `share_id + file_id` prevents envelope swapping attacks
- Salt is stored separately in database, not in envelope
- Client generates share_id before encryption to enable AAD binding

---

### 4.2 Download Token Utilities

**File**: `crypto/share_kdf.go` (add to existing file)

```go
import (
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "fmt"
)

// GenerateDownloadToken generates a cryptographically secure 32-byte Download Token
func GenerateDownloadToken() ([]byte, error) {
    token := make([]byte, 32)
    if _, err := rand.Read(token); err != nil {
        return nil, fmt.Errorf("failed to generate download token: %w", err)
    }
    return token, nil
}

// HashDownloadToken computes SHA-256 hash of a Download Token and returns base64
func HashDownloadToken(token []byte) string {
    hash := sha256.Sum256(token)
    return base64.StdEncoding.EncodeToString(hash[:])
}
```

**Notes**:
- 32 bytes = 256 bits of entropy (same as share_id)
- SHA-256 hash is stored in database, never the plaintext token
- Constant-time comparison happens in handlers

---

### 4.3 Ensure Unified Argon2id Parameters

**File**: `crypto/key_derivation.go` (verify existing code)

**Verify**:
- `UnifiedArgonSecure` is loaded from `crypto/argon2id-params.json` at init time
- All key derivation uses `UnifiedArgonSecure.Memory`, `UnifiedArgonSecure.Time`, `UnifiedArgonSecure.Threads`
- No hardcoded Argon2id parameters anywhere in the codebase

**Action**: No changes needed if already using `UnifiedArgonSecure` everywhere. If any hardcoded params exist, replace with references to `UnifiedArgonSecure`.

**Share Password Key Derivation**:

The Share Password is used to derive a Share Key using the same Argon2id parameters as everything else:

```go
// This should already exist in crypto/key_derivation.go
// Just ensure it's using UnifiedArgonSecure params
func DeriveShareKey(password string, salt []byte) ([]byte, error) {
    return DeriveArgon2IDKey(
        password,
        salt,
        UnifiedArgonSecure.KeyLen,
        UnifiedArgonSecure.Memory,
        UnifiedArgonSecure.Time,
        UnifiedArgonSecure.Threads,
    )
}
```

**Encryption/Decryption with AAD**:

The Share Envelope is encrypted using the derived Share Key with AES-256-GCM **with AAD binding**:

```go
// Encryption (in share creation flow)
aad := CreateAAD(shareID, fileID)
encryptedEnvelope, err := EncryptWithKeyAndAAD(envelopeJSON, shareKey, aad)

// Decryption (in share access flow)
aad := CreateAAD(shareID, fileID)
envelopeJSON, err := DecryptWithKeyAndAAD(encryptedEnvelope, shareKey, aad)
```

**Note**: May need to add `EncryptWithKeyAndAAD` and `DecryptWithKeyAndAAD` functions to `crypto/gcm.go` if they don't exist. These should use AES-256-GCM with the AAD parameter.

---

## 5. WEB CLIENT IMPLEMENTATION (TypeScript)

### 5.1 Share Creation Flow

**Files to modify**:
- `client/static/js/src/files/share-integration.ts`
- `client/static/js/src/shares/share-creation.ts`
- `client/static/js/src/crypto/share-crypto.ts`

#### 5.1.1 Generate Share ID (Client-Side)

**In `share-integration.ts` or `share-creation.ts`**:

```typescript
function generateShareID(): string {
    // Generate cryptographically secure 32-byte share_id
    const shareIdBytes = new Uint8Array(32);
    crypto.getRandomValues(shareIdBytes);
    
    // Use base64url encoding without padding (43 characters)
    return base64UrlEncode(shareIdBytes);
}

function base64UrlEncode(bytes: Uint8Array): string {
    const base64 = uint8ArrayToBase64(bytes);
    // Convert base64 to base64url
    return base64
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}
```

**Note**: Share ID must be generated BEFORE encrypting the envelope so it can be used in AAD binding.

#### 5.1.2 Fetch Owner Envelope

**In `share-integration.ts` or `share-creation.ts`**:

Replace the current `getFileInfo` function that calls `/api/files/<filename>/download` with:

```typescript
async function getOwnerEnvelope(fileId: string): Promise<OwnerEnvelope> {
    const response = await fetch(`/api/files/${fileId}/envelope`, {
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${getAccessToken()}`,
        },
    });
    
    if (!response.ok) {
        throw new Error(`Failed to fetch owner envelope: ${response.statusText}`);
    }
    
    const data = await response.json();
    return {
        passwordType: data.password_type,
        encryptedFEK: data.encrypted_fek,
        filenameNonce: data.filename_nonce,
        sha256sumNonce: data.sha256sum_nonce,
    };
}

interface OwnerEnvelope {
    passwordType: 'account' | 'custom';
    encryptedFEK: string;
    filenameNonce: string;
    sha256sumNonce: string;
}
```

#### 5.1.2 Unlock FEK Based on Encryption Type

```typescript
async function unlockFEK(envelope: OwnerEnvelope, fileId: string): Promise<Uint8Array> {
    if (envelope.passwordType === 'account') {
        // Use cached AccountKey from session storage
        const accountKeyB64 = sessionStorage.getItem('accountKey');
        if (!accountKeyB64) {
            throw new Error('Account key not found. Please log in again.');
        }
        
        const accountKey = base64ToUint8Array(accountKeyB64);
        const encryptedFEK = base64ToUint8Array(envelope.encryptedFEK);
        
        // Decrypt Owner Envelope with AccountKey (no password prompt needed)
        const fek = await decryptWithKey(encryptedFEK, accountKey);
        return fek;
        
    } else if (envelope.passwordType === 'custom') {
        // Prompt user ONCE for original custom password
        const customPassword = await promptForPassword(
            'Enter the original custom password for this file:',
            'This is the password you used when uploading the file.'
        );
        
        // Derive custom key (use existing deriveCustomKey function)
        const customKey = await deriveCustomKey(customPassword, fileId);
        const encryptedFEK = base64ToUint8Array(envelope.encryptedFEK);
        
        // Decrypt Owner Envelope with CustomKey
        const fek = await decryptWithKey(encryptedFEK, customKey);
        return fek;
        
    } else {
        throw new Error(`Unknown password type: ${envelope.passwordType}`);
    }
}
```

**Password Prompting Strategy**:
- **Account-Encrypted files**: NO password prompt (uses cached AccountKey from login)
- **Custom-Encrypted files**: ONE password prompt for the original custom password
- **Share Password**: Separate prompt for the new share password (happens after FEK is unlocked)
- Total prompts for custom-encrypted file sharing: 2 (original custom password + new share password)
- Total prompts for account-encrypted file sharing: 1 (new share password only)

**Note**: Use existing crypto functions from `crypto/file-encryption.ts` or `crypto/primitives.ts` for decryption.

#### 5.1.3 Generate Download Token and Hash

```typescript
function generateDownloadToken(): Uint8Array {
    const token = new Uint8Array(32);
    crypto.getRandomValues(token);
    return token;
}

async function hashDownloadToken(token: Uint8Array): Promise<string> {
    const hashBuffer = await crypto.subtle.digest('SHA-256', token);
    const hashArray = new Uint8Array(hashBuffer);
    return uint8ArrayToBase64(hashArray);
}
```

#### 5.1.4 Create Share Envelope with AAD

**In `crypto/share-crypto.ts`**:

```typescript
interface ShareEnvelope {
    fek: string;
    download_token: string;
}

async function createShareEnvelope(fek: Uint8Array, downloadToken: Uint8Array): Promise<string> {
    const envelope: ShareEnvelope = {
        fek: uint8ArrayToBase64(fek),
        download_token: uint8ArrayToBase64(downloadToken),
    };
    
    return JSON.stringify(envelope);
}

function createAAD(shareId: string, fileId: string): Uint8Array {
    // AAD = share_id + file_id (UTF-8 encoded concatenation)
    return new TextEncoder().encode(shareId + fileId);
}
```

---

#### 5.1.5 Encrypt Share Envelope with Share Password and AAD

```typescript
async function encryptShareEnvelope(
    envelopeJSON: string,
    sharePassword: string,
    salt: Uint8Array,
    shareId: string,
    fileId: string
): Promise<Uint8Array> {
    // Fetch Argon2id params from server
    const params = await getArgon2Params();
    
    // Derive Share Key using Argon2id
    const shareKey = await deriveArgon2idKey(
        sharePassword,
        salt,
        params.memoryKiB,
        params.time,
        params.parallelism
    );
    
    // Create AAD for binding
    const aad = createAAD(shareId, fileId);
    
    // Encrypt envelope JSON with AES-256-GCM with AAD
    const envelopeBytes = new TextEncoder().encode(envelopeJSON);
    const encryptedEnvelope = await encryptWithKeyAndAAD(envelopeBytes, shareKey, aad);
    
    return encryptedEnvelope;
}
```

**Note**: Uses `encryptWithKeyAndAAD` function (may need to add to `crypto/primitives.ts` if not exists).

---

**Update to crypto/constants.ts or crypto/config.ts**:

```typescript
// Fetch Argon2id parameters from server endpoint
interface Argon2Params {
    memoryKiB: number;
    time: number;
    parallelism: number;
}

let cachedParams: Argon2Params | null = null;

export async function getArgon2Params(): Promise<Argon2Params> {
    if (cachedParams) {
        return cachedParams;
    }
    
    // Fetch from server endpoint (VERIFIED: exists in handlers/config.go)
    const response = await fetch('/api/config/argon2');
    if (!response.ok) {
        throw new Error('Failed to fetch Argon2 parameters from server');
    }
    
    const data = await response.json();
    cachedParams = {
        memoryKiB: data.memoryKiB,
        time: data.time,
        parallelism: data.parallelism,
    };
    
    return cachedParams;
}
```

**Note**: This ensures TypeScript and Go always use the same Argon2id parameters by fetching from the server's `/api/config/argon2` endpoint (verified to exist in `handlers/config.go`), which returns the embedded `crypto/argon2id-params.json` data.

#### 5.1.6 Complete Share Creation Flow with Client-Side share_id

```typescript
async function createShare(fileId: string, sharePassword: string, maxAccesses?: number, expiresAfterHours?: number) {
    try {
        // 1. Generate share_id FIRST (needed for AAD binding)
        const shareId = generateShareID();
        
        // 2. Fetch Owner Envelope
        const ownerEnvelope = await getOwnerEnvelope(fileId);
        
        // 3. Unlock FEK
        const fek = await unlockFEK(ownerEnvelope, fileId);
        
        // 4. Generate Download Token
        const downloadToken = generateDownloadToken();
        const downloadTokenHash = await hashDownloadToken(downloadToken);
        
        // 5. Create Share Envelope
        const envelopeJSON = await createShareEnvelope(fek, downloadToken);
        
        // 6. Generate salt for Share Password
        const salt = new Uint8Array(32);
        crypto.getRandomValues(salt);
        
        // 7. Encrypt Share Envelope with AAD binding
        const encryptedEnvelope = await encryptShareEnvelope(
            envelopeJSON,
            sharePassword,
            salt,
            shareId,  // For AAD binding
            fileId    // For AAD binding
        );
        
        // 8. Send to server (including client-generated share_id)
        const response = await fetch('/api/shares', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${getAccessToken()}`,
            },
            body: JSON.stringify({
                share_id: shareId,  // Client-generated
                file_id: fileId,
                salt: uint8ArrayToBase64(salt),
                encrypted_envelope: uint8ArrayToBase64(encryptedEnvelope),
                download_token_hash: downloadTokenHash,
                max_accesses: maxAccesses || null,
                expires_after_hours: expiresAfterHours || 0,
            }),
        });
        
        if (!response.ok) {
            if (response.status === 409) {
                // Collision - retry with new share_id
                console.warn('Share ID collision detected, retrying...');
                return createShare(fileId, sharePassword, maxAccesses, expiresAfterHours);
            }
            throw new Error(`Failed to create share: ${response.statusText}`);
        }
        
        const result = await response.json();
        return result; // { share_id, share_url, created_at, expires_at }
        
    } catch (error) {
        console.error('Share creation failed:', error);
        throw error;
    }
}
```

---

### 5.2 Share Access Flow (Recipient)

**Files to modify**:
- `client/static/js/src/files/download.ts` (add share download logic)
- `client/static/shared.html` (update to call new functions)

#### 5.2.1 Fetch Share Envelope

```typescript
async function fetchShareEnvelope(shareId: string): Promise<ShareEnvelopeData> {
    const response = await fetch(`/api/shares/${shareId}/envelope`, {
        method: 'GET',
    });
    
    if (!response.ok) {
        if (response.status === 404) {
            throw new Error('Share not found');
        } else if (response.status === 403) {
            throw new Error('Share has expired or been revoked');
        } else if (response.status === 429) {
            throw new Error('Too many requests. Please try again later.');
        }
        throw new Error(`Failed to fetch share: ${response.statusText}`);
    }
    
    const data = await response.json();
    return {
        salt: data.salt,
        encryptedEnvelope: data.encrypted_envelope,
        fileSize: data.file_size,
    };
}

interface ShareEnvelopeData {
    salt: string;
    encryptedEnvelope: string;
    fileSize: number;
}
```

#### 5.2.2 Decrypt Share Envelope with AAD Verification

```typescript
async function decryptShareEnvelope(
    encryptedEnvelopeB64: string,
    sharePassword: string,
    saltB64: string,
    shareId: string,
    fileId: string
): Promise<{ fek: Uint8Array; downloadToken: Uint8Array }> {
    // Decode base64
    const encryptedEnvelope = base64ToUint8Array(encryptedEnvelopeB64);
    const salt = base64ToUint8Array(saltB64);
    
    // Derive Share Key
    const params = await getArgon2Params();
    const shareKey = await deriveArgon2idKey(
        sharePassword,
        salt,
        params.memoryKiB,
        params.time,
        params.parallelism
    );
    
    // Create AAD for verification
    const aad = createAAD(shareId, fileId);
    
    // Decrypt envelope with AAD verification
    const envelopeBytes = await decryptWithKeyAndAAD(encryptedEnvelope, shareKey, aad);
    const envelopeJSON = new TextDecoder().decode(envelopeBytes);
    
    // Parse envelope
    const envelope: ShareEnvelope = JSON.parse(envelopeJSON);
    
    // Extract FEK and Download Token
    const fek = base64ToUint8Array(envelope.fek);
    const downloadToken = base64ToUint8Array(envelope.download_token);
    
    return { fek, downloadToken };
}
```

**Note**: AAD verification will automatically fail if the envelope was swapped or tampered with.

#### 5.2.3 Download Encrypted File with Token

```typescript
async function downloadSharedFile(shareId: string, downloadToken: Uint8Array): Promise<Uint8Array> {
    const downloadTokenB64 = uint8ArrayToBase64(downloadToken);
    
    const response = await fetch(`/api/shares/${shareId}/download`, {
        method: 'GET',
        headers: {
            'X-Download-Token': downloadTokenB64,
        },
    });
    
    if (!response.ok) {
        if (response.status === 403) {
            throw new Error('Invalid download token or share has been revoked');
        } else if (response.status === 429) {
            throw new Error('Too many download requests. Please try again later.');
        }
        throw new Error(`Failed to download file: ${response.statusText}`);
    }
    
    // Read encrypted file bytes (streaming)
    const encryptedFile = await response.arrayBuffer();
    return new Uint8Array(encryptedFile);
}
```

#### 5.2.4 Decrypt File with FEK

```typescript
async function decryptFileWithFEK(encryptedFile: Uint8Array, fek: Uint8Array): Promise<Uint8Array> {
    // Parse file header to extract nonce and encrypted chunks
    // Use existing file decryption logic from crypto/file-encryption.ts
    
    // This should use the same decryption logic as regular file downloads
    // but with the FEK provided directly instead of deriving it from password
    
    return await decryptFileContent(encryptedFile, fek);
}
```

**Note**: Reuse existing file decryption functions. May need to refactor to accept FEK directly.

#### 5.2.5 Complete Share Access Flow with AAD Verification

```typescript
async function accessSharedFile(shareId: string, fileId: string, sharePassword: string) {
    try {
        // 1. Fetch Share Envelope
        const envelopeData = await fetchShareEnvelope(shareId);
        
        // 2. Display file size to user
        // add corresponding file size info in web app at opportune locations so user can review before downloading
        console.log(`File size: ${formatFileSize(envelopeData.fileSize)}`);
        
        // 3. Decrypt Share Envelope with AAD verification
        const { fek, downloadToken } = await decryptShareEnvelope(
            envelopeData.encryptedEnvelope,
            sharePassword,
            envelopeData.salt,
            shareId,  // For AAD verification
            fileId    // For AAD verification
        );
        
        // 4. Download encrypted file
        const encryptedFile = await downloadSharedFile(shareId, downloadToken);
        
        // 5. Decrypt file with FEK
        const decryptedFile = await decryptFileWithFEK(encryptedFile, fek);
        
        // 6. Trigger browser download
        const blob = new Blob([decryptedFile]);
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'decrypted-file'; // Filename will be decrypted from metadata
        a.click();
        URL.revokeObjectURL(url);
        
        return { success: true };
        
    } catch (error) {
        console.error('Share access failed:', error);
        throw error;
    }
}
```

#### 5.2.6 Update shared.html

**File**: `client/static/shared.html`

Update the page to:
1. Extract `share_id` from URL path
2. Prompt user for Share Password (minimum 18 characters, must meet requirements)
3. Validate share password meets requirements before attempting decryption
4. Call `accessSharedFile(shareId, sharePassword)`
5. Display progress and errors
6. Handle decrypted filename and sha256sum metadata if needed

**Password Requirements for Share Password**:
- Minimum 18 characters (from `crypto/password-requirements.json`)
- At least 60 bits of entropy
- Must contain: uppercase, lowercase, number, special character

**Note**: May need to decrypt filename and sha256sum from metadata for display. This requires fetching the encrypted metadata and decrypting it with the FEK.

---

### 5.3 Share Management UI

**Files to modify**:
- `client/static/index.html` (or wherever shares are listed)
- `client/static/js/src/files/list.ts`

#### 5.3.1 Display Share List with Revocation Status

Update the share list display to include:
- `access_count / max_accesses` (e.g., "3 / 10 downloads" or "5 downloads (unlimited)")
- Revocation status: "Active" or "Revoked (reason)"
- Expiration status: "Expires: 2024-01-15" or "Never expires"

```typescript
function renderShareItem(share: any): string {
    const isActive = share.is_active;
    const statusClass = isActive ? 'status-active' : 'status-revoked';
    const statusText = isActive ? 'Active' : `Revoked (${share.revoked_reason})`;
    
    const accessText = share.max_accesses
        ? `${share.access_count} / ${share.max_accesses} downloads`
        : `${share.access_count} downloads (unlimited)`;
    
    const expiresText = share.expires_at
        ? `Expires: ${new Date(share.expires_at).toLocaleString()}`
        : 'Never expires';
    
    return `
        <div class="share-item">
            <div class="share-filename">${share.encrypted_filename}</div>
            <div class="share-url">${share.share_url}</div>
            <div class="share-status ${statusClass}">${statusText}</div>
            <div class="share-access">${accessText}</div>
            <div class="share-expires">${expiresText}</div>
            ${isActive ? `<button onclick="revokeShare('${share.share_id}')">Revoke</button>` : ''}
        </div>
    `;
}
```

#### 5.3.2 Add Revoke Button Handler

```typescript
async function revokeShare(shareId: string) {
    if (!confirm('Are you sure you want to revoke this share? This cannot be undone.')) {
        return;
    }
    
    try {
        const response = await fetch(`/api/shares/${shareId}/revoke`, {
            method: 'PATCH',
            headers: {
                'Authorization': `Bearer ${getAccessToken()}`,
            },
        });
        
        if (!response.ok) {
            throw new Error(`Failed to revoke share: ${response.statusText}`);
        }
        
        // Refresh share list
        await loadShares();
        
        alert('Share revoked successfully');
        
    } catch (error) {
        console.error('Failed to revoke share:', error);
        alert('Failed to revoke share. Please try again.');
    }
}
```

---

### 5.4 Files to Consider Deleting

**Evaluate these files for redundancy**:
- `client/static/js/src/shares/share-crypto.ts` - May be redundant with `crypto/share-crypto.ts`
- Any other duplicate or unused share-related files

**Action**: Review and consolidate if possible to avoid code duplication.

---

## 6. CLI CLIENT IMPLEMENTATION

### 6.1 Agent Architecture with Enhanced Security

**New file**: `cmd/arkfile-client/agent.go`

**Purpose**: Background daemon to securely hold AccountKey in memory

**Socket Security**:
- Path: `~/.arkfile/agent-{UID}.sock` (UID-specific to prevent multi-user conflicts)
- Permissions: 0600 (owner read/write only)
- Validation: Verify socket owner matches current UID before connecting

**Implementation**:

```go
package main

import (
    "encoding/json"
    "fmt"
    "net"
    "os"
    "path/filepath"
    "sync"
    "syscall"
)

type Agent struct {
    socketPath string
    listener   net.Listener
    accountKey []byte
    mu         sync.RWMutex
    running    bool
}

// AgentRequest represents a request to the agent
type AgentRequest struct {
    Method string                 `json:"method"`
    Params map[string]interface{} `json:"params"`
}

// AgentResponse represents a response from the agent
type AgentResponse struct {
    Success bool                   `json:"success"`
    Result  map[string]interface{} `json:"result,omitempty"`
    Error   string                 `json:"error,omitempty"`
}

// StartAgent starts the agent daemon in the background
func StartAgent() error {
    homeDir, err := os.UserHomeDir()
    if err != nil {
        return fmt.Errorf("failed to get home directory: %w", err)
    }
    
    arkfileDir := filepath.Join(homeDir, ".arkfile")
    if err := os.MkdirAll(arkfileDir, 0700); err != nil {
        return fmt.Errorf("failed to create .arkfile directory: %w", err)
    }
    
    // Use UID-specific socket path for multi-user isolation
    uid := os.Getuid()
    socketPath := filepath.Join(arkfileDir, fmt.Sprintf("agent-%d.sock", uid))
    
    // Check if agent is already running
    if _, err := os.Stat(socketPath); err == nil {
        // Try to connect to existing agent
        conn, err := net.Dial("unix", socketPath)
        if err == nil {
            conn.Close()
            // Agent is already running
            return nil
        }
        // Socket exists but agent not running, remove stale socket
        os.Remove(socketPath)
    }
    
    agent := &Agent{
        socketPath: socketPath,
        running:    true,
    }
    
    // Start listening on Unix socket
    listener, err := net.Listen("unix", socketPath)
    if err != nil {
        return fmt.Errorf("failed to create socket: %w", err)
    }
    
    // Set socket permissions to 0600 (owner only)
    if err := os.Chmod(socketPath, 0600); err != nil {
        listener.Close()
        return fmt.Errorf("failed to set socket permissions: %w", err)
    }
    
    agent.listener = listener
    
    // Run agent in background goroutine
    go agent.serve()
    
    return nil
}

// serve handles incoming connections
func (a *Agent) serve() {
    defer a.listener.Close()
    defer os.Remove(a.socketPath)
    
    for a.running {
        conn, err := a.listener.Accept()
        if err != nil {
            if a.running {
                fmt.Fprintf(os.Stderr, "Agent accept error: %v\n", err)
            }
            continue
        }
        
        go a.handleConnection(conn)
    }
}

// handleConnection processes a single request
func (a *Agent) handleConnection(conn net.Conn) {
    defer conn.Close()
    
    var req AgentRequest
    decoder := json.NewDecoder(conn)
    if err := decoder.Decode(&req); err != nil {
        a.sendError(conn, fmt.Sprintf("invalid request: %v", err))
        return
    }
    
    switch req.Method {
    case "store_account_key":
        a.handleStoreAccountKey(conn, req.Params)
    case "get_account_key":
        a.handleGetAccountKey(conn)
    case "decrypt_owner_envelope":
        a.handleDecryptOwnerEnvelope(conn, req.Params)
    case "clear":
        a.handleClear(conn)
    case "stop":
        a.handleStop(conn)
    default:
        a.sendError(conn, fmt.Sprintf("unknown method: %s", req.Method))
    }
}

// handleStoreAccountKey stores the AccountKey in memory
func (a *Agent) handleStoreAccountKey(conn net.Conn, params map[string]interface{}) {
    accountKeyB64, ok := params["account_key"].(string)
    if !ok {
        a.sendError(conn, "account_key parameter required")
        return
    }
    
    accountKey, err := base64.StdEncoding.DecodeString(accountKeyB64)
    if err != nil {
        a.sendError(conn, fmt.Sprintf("invalid base64: %v", err))
        return
    }
    
    a.mu.Lock()
    a.accountKey = accountKey
    a.mu.Unlock()
    
    a.sendSuccess(conn, nil)
}

// handleGetAccountKey retrieves the AccountKey
func (a *Agent) handleGetAccountKey(conn net.Conn) {
    a.mu.RLock()
    defer a.mu.RUnlock()
    
    if a.accountKey == nil {
        a.sendError(conn, "account key not set")
        return
    }
    
    result := map[string]interface{}{
        "account_key": base64.StdEncoding.EncodeToString(a.accountKey),
    }
    
    a.sendSuccess(conn, result)
}

// handleDecryptOwnerEnvelope decrypts an Owner Envelope with AccountKey
func (a *Agent) handleDecryptOwnerEnvelope(conn net.Conn, params map[string]interface{}) {
    a.mu.RLock()
    defer a.mu.RUnlock()
    
    if a.accountKey == nil {
        a.sendError(conn, "account key not set")
        return
    }
    
    envelopeB64, ok := params["encrypted_fek"].(string)
    if !ok {
        a.sendError(conn, "encrypted_fek parameter required")
        return
    }
    
    encryptedFEK, err := base64.StdEncoding.DecodeString(envelopeB64)
    if err != nil {
        a.sendError(conn, fmt.Sprintf("invalid base64: %v", err))
        return
    }
    
    // Decrypt FEK with AccountKey (use crypto package)
    fek, err := crypto.DecryptWithKey(encryptedFEK, a.accountKey)
    if err != nil {
        a.sendError(conn, fmt.Sprintf("decryption failed: %v", err))
        return
    }
    
    result := map[string]interface{}{
        "fek": base64.StdEncoding.EncodeToString(fek),
    }
    
    a.sendSuccess(conn, result)
}

// handleClear clears the AccountKey from memory
func (a *Agent) handleClear(conn net.Conn) {
    a.mu.Lock()
    a.accountKey = nil
    a.mu.Unlock()
    
    a.sendSuccess(conn, nil)
}

// handleStop stops the agent
func (a *Agent) handleStop(conn net.Conn) {
    a.sendSuccess(conn, nil)
    a.running = false
    a.listener.Close()
}

// sendSuccess sends a success response
func (a *Agent) sendSuccess(conn net.Conn, result map[string]interface{}) {
    resp := AgentResponse{
        Success: true,
        Result:  result,
    }
    json.NewEncoder(conn).Encode(resp)
}

// sendError sends an error response
func (a *Agent) sendError(conn net.Conn, errMsg string) {
    resp := AgentResponse{
        Success: false,
        Error:   errMsg,
    }
    json.NewEncoder(conn).Encode(resp)
}

// ConnectToAgent connects to the running agent with security validation
func ConnectToAgent() (net.Conn, error) {
    homeDir, err := os.UserHomeDir()
    if err != nil {
        return nil, fmt.Errorf("failed to get home directory: %w", err)
    }
    
    uid := os.Getuid()
    socketPath := filepath.Join(homeDir, ".arkfile", fmt.Sprintf("agent-%d.sock", uid))
    
    // Validate socket ownership and permissions before connecting
    if err := validateSocketSecurity(socketPath, uid); err != nil {
        return nil, fmt.Errorf("socket security validation failed: %w", err)
    }
    
    conn, err := net.Dial("unix", socketPath)
    if err != nil {
        return nil, fmt.Errorf("failed to connect to agent: %w", err)
    }
    
    return conn, nil
}

// validateSocketSecurity ensures socket is owned by current user with correct permissions
func validateSocketSecurity(socketPath string, expectedUID int) error {
    info, err := os.Stat(socketPath)
    if err != nil {
        return fmt.Errorf("failed to stat socket: %w", err)
    }
    
    // Check ownership
    stat := info.Sys().(*syscall.Stat_t)
    if int(stat.Uid) != expectedUID {
        return fmt.Errorf("socket owner mismatch: expected UID %d, got %d", expectedUID, stat.Uid)
    }
    
    // Check permissions (must be exactly 0600)
    if info.Mode().Perm() != 0600 {
        return fmt.Errorf("insecure socket permissions: %o (expected 0600)", info.Mode().Perm())
    }
    
    return nil
}

// SendAgentRequest sends a request to the agent and returns the response
func SendAgentRequest(method string, params map[string]interface{}) (*AgentResponse, error) {
    conn, err := ConnectToAgent()
    if err != nil {
        return nil, err
    }
    defer conn.Close()
    
    req := AgentRequest{
        Method: method,
        Params: params,
    }
    
    if err := json.NewEncoder(conn).Encode(req); err != nil {
        return nil, fmt.Errorf("failed to send request: %w", err)
    }
    
    var resp AgentResponse
    if err := json.NewDecoder(conn).Decode(&resp); err != nil {
        return nil, fmt.Errorf("failed to read response: %w", err)
    }
    
    return &resp, nil
}
```

**Auto-start behavior**:

In `cmd/arkfile-client/main.go`, add agent auto-start to the main function:

```go
func main() {
    // Auto-start agent if not running
    if err := StartAgent(); err != nil {
        fmt.Fprintf(os.Stderr, "Warning: Failed to start agent: %v\n", err)
        // Continue anyway - agent is optional for some operations
    }
    
    // Rest of main function...
}
```

**Store AccountKey after login**:

In the login command handler:

```go
// After successful login and AccountKey derivation
// - add clear indication to user after login that their account key is being stored by the agent
resp, err := SendAgentRequest("store_account_key", map[string]interface{}{
    "account_key": base64.StdEncoding.EncodeToString(accountKey),
})
if err != nil {
    fmt.Fprintf(os.Stderr, "Warning: Failed to store key in agent: %v\n", err)
}
```

**Clear AccountKey on logout**:

```go
resp, err := SendAgentRequest("clear", nil)
if err != nil {
    fmt.Fprintf(os.Stderr, "Warning: Failed to clear agent: %v\n", err)
}
```

---

### 6.2 Share Commands

**File**: `cmd/arkfile-client/main.go` (add subcommands)

#### 6.2.1 Share Create Command

```go
func shareCreateCommand() *cli.Command {
    return &cli.Command{
        Name:  "create",
        Usage: "Create a new file share",
        Flags: []cli.Flag{
            &cli.StringFlag{
                Name:     "file-id",
                Aliases:  []string{"f"},
                Usage:    "File ID to share",
                Required: true,
            },
            &cli.StringFlag{
                Name:     "password",
                Aliases:  []string{"p"},
                Usage:    "Share password",
                Required: true,
            },
            &cli.IntFlag{
                Name:    "max-downloads",
                Aliases: []string{"m"},
                Usage:   "Maximum number of downloads (0 = unlimited)",
                Value:   0,
            },
            &cli.IntFlag{
                Name:    "expires-hours",
                Aliases: []string{"e"},
                Usage:   "Expiration time in hours (0 = never)",
                Value:   0,
            },
        },
        Action: func(c *cli.Context) error {
            return createShare(
                c.String("file-id"),
                c.String("password"),
                c.Int("max-downloads"),
                c.Int("expires-hours"),
            )
        },
    }
}

func createShare(fileID, sharePassword string, maxDownloads, expiresHours int) error {
    // 1. Fetch Owner Envelope
    envelope, err := fetchOwnerEnvelope(fileID)
    if err != nil {
        return fmt.Errorf("failed to fetch owner envelope: %w", err)
    }
    
    // 2. Unlock FEK based on password type
    var fek []byte
    if envelope.PasswordType == "account" {
        // Get FEK from agent
        resp, err := SendAgentRequest("decrypt_owner_envelope", map[string]interface{}{
            "encrypted_fek": envelope.EncryptedFEK,
        })
        if err != nil {
            return fmt.Errorf("failed to decrypt with agent: %w", err)
        }
        fekB64, ok := resp.Result["fek"].(string)
        if !ok {
            return fmt.Errorf("invalid agent response")
        }
        fek, err = base64.StdEncoding.DecodeString(fekB64)
        if err != nil {
            return fmt.Errorf("invalid fek from agent: %w", err)
        }
    } else if envelope.PasswordType == "custom" {
        // Prompt for custom password
        fmt.Print("Enter original custom password: ")
        customPassword, err := readPassword()
        if err != nil {
            return fmt.Errorf("failed to read password: %w", err)
        }
        
        // Derive custom key and decrypt
        customKey := deriveCustomKey(customPassword, fileID)
        encryptedFEK, _ := base64.StdEncoding.DecodeString(envelope.EncryptedFEK)
        fek, err = crypto.DecryptWithKey(encryptedFEK, customKey)
        if err != nil {
            return fmt.Errorf("failed to decrypt FEK: %w", err)
        }
    }
    
    // 3. Generate Download Token
    downloadToken, err := crypto.GenerateDownloadToken()
    if err != nil {
        return fmt.Errorf("failed to generate token: %w", err)
    }
    downloadTokenHash := crypto.HashDownloadToken(downloadToken)
    
    // 4. Create Share Envelope
    envelopeJSON, err := crypto.CreateShareEnvelope(fek, downloadToken)
    if err != nil {
        return fmt.Errorf("failed to create envelope: %w", err)
    }
    
    // 5. Generate salt
    salt := make([]byte, 32)
    if _, err := rand.Read(salt); err != nil {
        return fmt.Errorf("failed to generate salt: %w", err)
    }
    
    // 6. Encrypt Share Envelope with Share Password
    shareKey, err := crypto.DeriveArgon2IDKey(
        sharePassword,
        salt,
        crypto.UnifiedArgonSecure.KeyLen,
        crypto.UnifiedArgonSecure.Memory,
        crypto.UnifiedArgonSecure.Time,
        crypto.UnifiedArgonSecure.Threads,
    )
    if err != nil {
        return fmt.Errorf("failed to derive share key: %w", err)
    }
    
    encryptedEnvelope, err := crypto.EncryptWithKey(envelopeJSON, shareKey)
    if err != nil {
        return fmt.Errorf("failed to encrypt envelope: %w", err)
    }
    
    // 7. Send to server
    var maxAccessesPtr *int
    if maxDownloads > 0 {
        maxAccessesPtr = &maxDownloads
    }
    
    shareReq := map[string]interface{}{
        "file_id":             fileID,
        "salt":                base64.StdEncoding.EncodeToString(salt),
        "encrypted_envelope":  base64.StdEncoding.EncodeToString(encryptedEnvelope),
        "download_token_hash": downloadTokenHash,
        "max_accesses":        maxAccessesPtr,
        "expires_after_hours": expiresHours,
    }
    
    resp, err := apiRequest("POST", "/api/shares", shareReq)
    if err != nil {
        return fmt.Errorf("failed to create share: %w", err)
    }
    
    fmt.Printf("Share created successfully!\n")
    fmt.Printf("Share URL: %s\n", resp["share_url"])
    fmt.Printf("Share ID: %s\n", resp["share_id"])
    
    return nil
}
```

**Security verification**: No passwords, FEKs, or decrypted metadata sent to server. All crypto happens locally.

#### 6.2.2 Share List Command

```go
func shareListCommand() *cli.Command {
    return &cli.Command{
        Name:  "list",
        Usage: "List all shares",
        Action: func(c *cli.Context) error {
            return listShares()
        },
    }
}

func listShares() error {
    resp, err := apiRequest("GET", "/api/shares", nil)
    if err != nil {
        return fmt.Errorf("failed to list shares: %w", err)
    }
    
    shares, ok := resp["shares"].([]interface{})
    if !ok {
        return fmt.Errorf("invalid response format")
    }
    
    fmt.Printf("Total shares: %d\n\n", len(shares))
    
    for _, s := range shares {
        share := s.(map[string]interface{})
        
        fmt.Printf("Share ID: %s\n", share["share_id"])
        fmt.Printf("File ID: %s\n", share["file_id"])
        fmt.Printf("URL: %s\n", share["share_url"])
        fmt.Printf("Created: %s\n", share["created_at"])
        
        if share["expires_at"] != nil {
            fmt.Printf("Expires: %s\n", share["expires_at"])
        } else {
            fmt.Printf("Expires: Never\n")
        }
        
        accessCount := int(share["access_count"].(float64))
        if share["max_accesses"] != nil {
            maxAccesses := int(share["max_accesses"].(float64))
            fmt.Printf("Downloads: %d / %d\n", accessCount, maxAccesses)
        } else {
            fmt.Printf("Downloads: %d (unlimited)\n", accessCount)
        }
        
        if share["is_active"].(bool) {
            fmt.Printf("Status: Active\n")
        } else {
            fmt.Printf("Status: Revoked (%s)\n", share["revoked_reason"])
        }
        
        fmt.Println()
    }
    
    return nil
}
```

#### 6.2.3 Share Revoke Command

```go
func shareRevokeCommand() *cli.Command {
    return &cli.Command{
        Name:  "revoke",
        Usage: "Revoke a share",
        Flags: []cli.Flag{
            &cli.StringFlag{
                Name:     "share-id",
                Aliases:  []string{"s"},
                Usage:    "Share ID to revoke",
                Required: true,
            },
        },
        Action: func(c *cli.Context) error {
            return revokeShare(c.String("share-id"))
        },
    }
}

func revokeShare(shareID string) error {
    _, err := apiRequest("PATCH", fmt.Sprintf("/api/shares/%s/revoke", shareID), nil)
    if err != nil {
        return fmt.Errorf("failed to revoke share: %w", err)
    }
    
    fmt.Printf("Share %s revoked successfully\n", shareID)
    return nil
}
```

#### 6.2.4 Share Download Command

```go
func shareDownloadCommand() *cli.Command {
    return &cli.Command{
        Name:  "download",
        Usage: "Download a shared file",
        Flags: []cli.Flag{
            &cli.StringFlag{
                Name:     "url",
                Aliases:  []string{"u"},
                Usage:    "Share URL",
                Required: true,
            },
            &cli.StringFlag{
                Name:     "password",
                Aliases:  []string{"p"},
                Usage:    "Share password",
                Required: true,
            },
            &cli.StringFlag{
                Name:    "output",
                Aliases: []string{"o"},
                Usage:   "Output file path",
                Value:   "downloaded-file",
            },
        },
        Action: func(c *cli.Context) error {
            return downloadSharedFile(
                c.String("url"),
                c.String("password"),
                c.String("output"),
            )
        },
    }
}

func downloadSharedFile(shareURL, sharePassword, outputPath string) error {
    // 1. Extract share_id from URL
    shareID := extractShareIDFromURL(shareURL)
    
    // 2. Fetch Share Envelope
    envelopeData, err := fetchShareEnvelope(shareID)
    if err != nil {
        return fmt.Errorf("failed to fetch envelope: %w", err)
    }
    
    fmt.Printf("File size: %d bytes\n", envelopeData.FileSize)
    
    // 3. Decrypt Share Envelope
    salt, _ := base64.StdEncoding.DecodeString(envelopeData.Salt)
    encryptedEnvelope, _ := base64.StdEncoding.DecodeString(envelopeData.EncryptedEnvelope)
    
    shareKey, err := crypto.DeriveArgon2IDKey(
        sharePassword,
        salt,
        crypto.UnifiedArgonSecure.KeyLen,
        crypto.UnifiedArgonSecure.Memory,
        crypto.UnifiedArgonSecure.Time,
        crypto.UnifiedArgonSecure.Threads,
    )
    if err != nil {
        return fmt.Errorf("failed to derive key: %w", err)
    }
    
    envelopeJSON, err := crypto.DecryptWithKey(encryptedEnvelope, shareKey)
    if err != nil {
        return fmt.Errorf("incorrect password or corrupted envelope: %w", err)
    }
    
    envelope, err := crypto.ParseShareEnvelope(envelopeJSON)
    if err != nil {
        return fmt.Errorf("failed to parse envelope: %w", err)
    }
    
    fek, _ := base64.StdEncoding.DecodeString(envelope.FEK)
    downloadToken, _ := base64.StdEncoding.DecodeString(envelope.DownloadToken)
    
    // 4. Download encrypted file with token
    encryptedFile, err := downloadFileWithToken(shareID, downloadToken)
    if err != nil {
        return fmt.Errorf("failed to download file: %w", err)
    }
    
    // 5. Decrypt file with FEK
    decryptedFile, err := crypto.DecryptFileContent(encryptedFile, fek)
    if err != nil {
        return fmt.Errorf("failed to decrypt file: %w", err)
    }
    
    // 6. Save to disk
    if err := os.WriteFile(outputPath, decryptedFile, 0600); err != nil {
        return fmt.Errorf("failed to save file: %w", err)
    }
    
    fmt.Printf("File downloaded and decrypted successfully: %s\n", outputPath)
    return nil
}
```

**Security verification**: Share password and FEK never sent to server. All decryption happens locally.

---

## 7. LOGGING & SECURITY

### 7.1 Privacy-Preserving Logging

**Files**: All handlers in `handlers/file_shares.go`

**Changes**:

Replace all instances of logging full `share_id` with truncated version:

```go
// Before:
logging.InfoLogger.Printf("Share created: share_id=%s", shareID)

// After:
logging.InfoLogger.Printf("Share created: share_id=%s...", shareID[:8])
```

**For correlation**, use entity_id which is already implemented.

**Never log**:
- Download Tokens (plaintext or hash)
- Share Passwords
- FEKs
- Decrypted metadata

---

### 7.2 Constant-Time Operations

**File**: `handlers/file_shares.go`

**Already covered in section 3.5** - use `crypto/subtle.ConstantTimeCompare` for Download Token validation.

**Verify**: All cryptographic comparisons use constant-time functions to prevent timing attacks.

---

## 8. IMPLEMENTATION CHECKLIST

### Phase 1: Database & Core Backend

- [ ] Update `database/unified_schema.sql` with new columns (`download_token_hash NOT NULL`, `revoked_at`, `revoked_reason`)
- [ ] Add indexes for performance (`idx_file_share_keys_revoked`, `idx_file_share_keys_token_hash`)
- [ ] Add `GET /api/files/{file_id}/envelope` endpoint in `handlers/files.go`
- [ ] Add `GET /api/shares/{id}/envelope` endpoint in `handlers/file_shares.go`
- [ ] Add `PATCH /api/shares/{id}/revoke` endpoint in `handlers/file_shares.go`
- [ ] Modify `POST /api/shares` (CreateFileShare) to accept client-generated `share_id`
- [ ] Add `isValidShareID()` helper function (validate 43-char base64url format)
- [ ] Add share_id uniqueness check in CreateFileShare (return 409 on collision)
- [ ] Remove server-side `generateShareID()` function (no longer needed)
- [ ] Remove Account-Encrypted file blocking in CreateFileShare
- [ ] Implement Download Token validation in DownloadSharedFile (constant-time comparison)
- [ ] Implement streaming download in DownloadSharedFile (use verified `GetObjectWithoutPadding()`)
- [ ] Implement atomic access_count transaction with auto-revocation in DownloadSharedFile
- [ ] Add revocation checks to all share access paths
- [ ] Update ListShares to include revocation data (`revoked_at`, `revoked_reason`, `access_count`, `max_accesses`)
- [ ] Add rate limiting to download endpoint (30 req/min)
- [ ] Update all logging to use truncated share_id

### Phase 2: Crypto Layer (Go)

- [ ] Define `ShareEnvelope` struct in `crypto/share_kdf.go` or new file
- [ ] Implement `CreateShareEnvelope` function
- [ ] Implement `ParseShareEnvelope` function
- [ ] Implement `CreateAAD(shareID, fileID string) []byte` helper function
- [ ] Add `EncryptWithKeyAndAAD` function to `crypto/gcm.go` (if not exists)
- [ ] Add `DecryptWithKeyAndAAD` function to `crypto/gcm.go` (if not exists)
- [ ] Implement `GenerateDownloadToken` function
- [ ] Implement `HashDownloadToken` function
- [ ] Verify all Argon2id usage references `UnifiedArgonSecure` params (no hardcoded values)

### Phase 3: Web Client

- [ ] Implement `generateShareID()` function (32-byte cryptographically secure, base64url encoded)
- [ ] Implement `base64UrlEncode()` helper function
- [ ] Implement `createAAD(shareId, fileId)` helper function
- [ ] Add `getOwnerEnvelope` function to fetch Owner Envelope from new endpoint
- [ ] Implement `unlockFEK` function to handle both Account and Custom encryption types
- [ ] Implement Account-Encrypted file FEK unlocking (use cached AccountKey from sessionStorage)
- [ ] Implement Custom-Encrypted file FEK unlocking (prompt for password, derive key)
- [ ] Implement `generateDownloadToken` function
- [ ] Implement `hashDownloadToken` function (SHA-256)
- [ ] Implement `createShareEnvelope` function (Share Envelope structure)
- [ ] Add `encryptWithKeyAndAAD` function to `crypto/primitives.ts` (if not exists)
- [ ] Add `decryptWithKeyAndAAD` function to `crypto/primitives.ts` (if not exists)
- [ ] Implement `encryptShareEnvelope` function (Argon2id + AES-256-GCM with AAD)
- [ ] Update share creation flow: generate share_id FIRST, then encrypt with AAD
- [ ] Update share creation API call with new fields (`share_id`, `encrypted_envelope`, `download_token_hash`, `max_accesses`)
- [ ] Add retry logic for share_id collision (409 response)
- [ ] Implement `fetchShareEnvelope` function for recipients
- [ ] Implement `decryptShareEnvelope` function with AAD verification
- [ ] Implement `downloadSharedFile` function with `X-Download-Token` header
- [ ] Implement `decryptFileWithFEK` function (reuse existing file decryption logic)
- [ ] Update `shared.html` to use new recipient flow with AAD verification
- [ ] Add share management UI (revoke button, access count display, revocation status)
- [ ] Verify `GET /api/config/argon2` endpoint is used (already exists in handlers/config.go)
- [ ] Review and delete redundant files if any (e.g., duplicate share-crypto.ts)

### Phase 4: CLI Client

- [ ] Create `cmd/arkfile-client/agent.go` with agent implementation
- [ ] Implement UID-specific socket path: `~/.arkfile/agent-{UID}.sock`
- [ ] Implement Unix socket listener with 0600 permissions
- [ ] Implement `validateSocketSecurity()` function (ownership + permission checks)
- [ ] Update `ConnectToAgent()` to validate socket security before connecting
- [ ] Implement agent methods: `store_account_key`, `get_account_key`, `decrypt_owner_envelope`, `clear`, `stop`
- [ ] Add agent auto-start to `main()` function
- [ ] Store AccountKey in agent after login
- [ ] Clear AccountKey from agent on logout
- [ ] Implement `generateShareID()` function in CLI (32-byte, base64url)
- [ ] Implement `share create` command with client-side share_id generation and AAD binding
- [ ] Add retry logic for share_id collision in CLI
- [ ] Implement `share list` command
- [ ] Implement `share revoke` command
- [ ] Implement `share download` command with AAD verification
- [ ] Verify zero-knowledge: no passwords/FEKs sent to server in CLI

### Phase 5: E2E Validation

- [ ] Update `scripts/testing/e2e-test.sh` to test Account-Encrypted file sharing
- [ ] Update `scripts/testing/e2e-test.sh` to test Custom-Encrypted file sharing
- [ ] Update `scripts/testing/e2e-test.sh` to test Download Token enforcement (reject invalid tokens)
- [ ] Update `scripts/testing/e2e-test.sh` to test max_accesses enforcement
- [ ] Update `scripts/testing/e2e-test.sh` to test manual revocation
- [ ] Update `scripts/testing/e2e-test.sh` to test streaming large files (>100MB)
- [ ] Update `scripts/testing/e2e-test.sh` to test AAD binding (envelope swapping prevention)
- [ ] Update `scripts/testing/e2e-test.sh` to test share_id collision handling
- [ ] Update `scripts/testing/e2e-test.sh` to test agent socket security (multi-user isolation)
- [ ] Run `dev-reset.sh` to deploy all changes
- [ ] Run `e2e-test.sh` to validate end-to-end functionality

---

## 9. OPEN QUESTIONS & RECOMMENDATIONS

### 9.1 AAD Binding for Share Envelope [IMPLEMENTED]

**Decision**: Client-side `share_id` generation with AAD binding (Option 2)

**Implementation**:
- Client generates cryptographically secure 32-byte share_id (base64url encoded = 43 chars)
- Share Envelope is encrypted with AAD = `share_id + file_id` (UTF-8 concatenation)
- Server validates share_id format (exactly 43 chars, base64url alphabet) and uniqueness
- AAD verification prevents envelope swapping attacks (both cross-file and same-file)

**Security Benefits**:
- Prevents attacker from swapping envelopes between different shares
- Prevents attacker from swapping envelopes between different files
- Decryption automatically fails if AAD doesn't match (tamper detection)
- Zero-knowledge preserved: server never sees relationship between share_id and envelope content

### 9.2 Agent Lifecycle [VERIFIED]

**Decision**: Session-only background process (no persistence across reboots)

**Expected Behavior**:
- Agent starts automatically when CLI is first used
- Agent stores AccountKey in memory only (never on disk)
- Agent clears on explicit logout command
- Agent terminates on system reboot/shutdown (Unix socket is ephemeral)
- Agent does NOT persist across reboots (no systemd service, no autostart)

**Security Enhancements**:
- Socket path: `~/.arkfile/agent-{UID}.sock` (UID-specific for multi-user isolation)
- Socket permissions: 0600 (owner read/write only)
- Ownership validation: Verify socket owner matches current UID before connecting
- Permission validation: Reject connection if permissions are not exactly 0600
- Defense-in-depth: UID in path + ownership check + permission check

### 9.3 Storage Padding Handling [VERIFIED]

**Status**: `storage.Provider.GetObjectWithoutPadding()` EXISTS and works correctly

**Location**: `storage/s3.go`

**Implementation**:
```go
func (s *S3AWSStorage) GetObjectWithoutPadding(ctx context.Context, storageID string, originalSize int64, opts GetObjectOptions) (io.ReadCloser, error) {
    object, err := s.GetObject(ctx, storageID, opts)
    if err != nil {
        return nil, err
    }
    return &limitedReadCloser{
        ReadCloser: object,
        limit:      originalSize,
    }, nil
}
```

**Helper**: Uses `limitedReadCloser` from `storage/helpers.go` which wraps the reader and stops at `originalSize`

**Verification**: Function exists and correctly strips padding bytes. No changes needed.

### 9.4 Rate Limiting Configuration [SPECIFIED]

**Rate Limit Values** (requests per minute per entity_id):
- `GET /api/shares/{id}/envelope`: **30 requests/minute**
- `GET /api/shares/{id}/download`: **30 requests/minute**
- `POST /api/shares`: **120 requests/minute** (authenticated users only)

**Rationale**:
- Envelope access: Allows multiple password attempts while preventing brute-force
- Downloads: Balances legitimate use with bandwidth protection
- Share creation: Higher limit for authenticated users (trusted, rate-limited by JWT)

**Implementation**: Add to `config/security_config.go` or configure in `handlers/rate_limiting.go`

### 9.5 Share Extension Feature (OPTIONAL)

**New Endpoint**: `PATCH /api/shares/{id}/extend`

**Purpose**: Allow share owners to extend expiration or increase max_accesses

**Request Body**:
```json
{
    "new_expiration": "2024-12-31T23:59:59Z",  // Optional
    "new_max_accesses": 100                     // Optional
}
```

**Validation**:
- User must own the share
- Share must not be revoked
- `new_expiration` must be in the future
- `new_max_accesses` must be >= current `access_count`

**Response**:
```json
{
    "success": true,
    "share_id": "abc123...",
    "expires_at": "2024-12-31T23:59:59Z",
    "max_accesses": 100,
    "access_count": 42
}
```

**UI Considerations**:
- Add "Extend" button next to active shares in web UI
- Add `arkfile-client share extend --share-id=... --expires-hours=... --max-downloads=...` CLI command

---

## NOTES

- This implementation plan targets the ideal Arkfile file sharing system as described in the SHARED FILE LIFECYCLE section of `unify-share-file.md`
- All changes maintain zero-knowledge architecture: server never receives passwords, FEKs, or decrypted metadata
- Argon2id parameters are unified across the entire system via `crypto/argon2id-params.json` (served via verified `/api/config/argon2` endpoint)
- Download Token enforcement provides bandwidth protection while maintaining privacy
- Streaming downloads improve performance and reduce memory usage (verified `GetObjectWithoutPadding()` exists)
- Revocation system provides owners with full control over share lifecycle
- Agent architecture enables secure CLI sharing of Account-Encrypted files without exposing AccountKey
- **Client-side share_id generation with AAD binding** prevents envelope swapping attacks
- **UID-specific agent sockets with validation** provide defense-in-depth for multi-user systems
- **Rate limiting** (30/30/120 req/min) balances usability with security
