## Plan: Unit Tests for Critical TypeScript Functions

### Step 1: Test Infrastructure Setup

- Create `client/static/js/src/__tests__/` directory
- Add `bun test` script to `package.json`
- Create test helpers: mocks for `localStorage`, `sessionStorage`, `crypto.subtle` (Web Crypto API), and `fetch`

### Step 2: `primitives.test.ts` -- Crypto Primitives

Testing `client/static/js/src/crypto/primitives.ts`:

- `randomBytes()` -- returns correct length, unique each call
- `hash256()` / `hash512()` -- deterministic output for known input
- `encryptAESGCM()` / `decryptAESGCM()` -- round-trip, wrong key fails
- `deriveKeyArgon2()` -- deterministic for same password+salt+params
- `constantTimeEqual()` -- true for equal, false for unequal, same-length requirement
- `secureWipe()` -- zeroes out buffer
- `base64Encode` / `base64Decode` / `hexEncode` / `hexDecode` -- round-trips

### Step 3: `auth.test.ts` -- AuthManager

Testing `client/static/js/src/utils/auth.ts`:

- `setTokens()` / `getToken()` / `getRefreshToken()` -- localStorage round-trip
- `clearTokens()` -- removes both keys
- `parseJwtToken()` -- decodes valid JWT payload, returns null for garbage
- `getUsernameFromToken()` -- extracts `sub` claim
- `isTokenExpired()` -- true for expired, false for valid
- `clearAllSessionData()` -- clears tokens + sessionStorage

### Step 4: `file-encryption.test.ts` -- Key Derivation

Testing `client/static/js/src/crypto/file-encryption.ts`:

- `deriveSalt()` -- deterministic for same username+context
- `deriveFileEncryptionKey()` -- deterministic for same password+username+context
- FEK round-trip: derive key, encrypt data, decrypt data, verify match

### Step 5: `account-key-cache.test.ts` -- Cache Operations

Testing `client/static/js/src/crypto/account-key-cache.ts`:

- `cacheAccountKey()` / `getCachedAccountKey()` -- round-trip
- Expiry enforcement -- cached key expires after duration
- Session binding -- HMAC integrity check
- `clearAccountKeyCache()` -- removes cached data

### Step 6: `digest-cache.test.ts` -- Dedup Cache

Testing `client/static/js/src/utils/digest-cache.ts`:

- `addDigest()` / `checkDuplicate()` -- round-trip
- Non-existent digest returns false
- Cache persistence in localStorage

### Step 7: `share-crypto.test.ts` -- Share Encryption

Testing `client/static/js/src/crypto/share-crypto.ts`:

- `encryptFEKForShare()` -> `decryptShareEnvelope()` round-trip
- AAD binding: wrong shareId -> decryption fails
- AAD binding: wrong fileId -> decryption fails
- Wrong password -> `DecryptionError`
- Envelope JSON structure matches expected format
- `generateFEK()` returns 32 bytes, unique each call
- `encodeFEK()` / `decodeFEK()` round-trip
- Empty password rejection
- Empty shareId rejection
