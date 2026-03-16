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

---

# UPDATED/REVISED:

## Unit Test Implementation Plan

I've now read all the relevant source files. Here's the concrete plan for implementing bun unit tests for the TypeScript frontend crypto/auth modules.

### Current State
- **package.json** has `@types/bun` and `@playwright/test` as devDependencies
- **No existing unit tests** — only Playwright e2e tests exist
- **No `share-crypto.ts`** exists — that was in the plan doc but hasn't been written yet, so we skip it
- **Bun has a built-in test runner** (`bun test`) — no extra test framework needed

### Files to Create

#### 1. Test Infrastructure

**`client/static/js/src/__tests__/setup.ts`** — Shared test setup:
- Mock `sessionStorage` (bun runs in a non-browser environment, so we need a simple in-memory mock)
- Mock `window` object minimally (for `addEventListener` in account-key-cache)
- No need to mock Web Crypto — bun provides `crypto.subtle` natively

#### 2. Test Files (5 files)

**`client/static/js/src/__tests__/primitives.test.ts`** — ~15 tests:
- `randomBytes()` — returns correct length, different each call
- `generateIV()` — returns 12 bytes
- `generateSalt()` — returns 32 bytes
- `hash256()` / `hash512()` / `hashString()` — known-answer tests (SHA-256/512 of known inputs)
- `toBase64()` / `fromBase64()` — round-trip
- `toHex()` / `fromHex()` — round-trip
- `constantTimeEqual()` — equal and unequal arrays
- `secureWipe()` — zeroes out array
- `concatBytes()` — concatenation correctness
- `encryptAESGCM()` / `decryptAESGCM()` — encrypt then decrypt round-trip
- `deriveKeyArgon2id()` — deterministic output for same inputs (uses `argon2id` from `@noble/hashes`)
- `deriveKeyHKDF()` — deterministic output

**`client/static/js/src/__tests__/file-encryption.test.ts`** — ~10 tests:
- `deriveSaltFromUsername()` — deterministic for same username, different for different usernames
- `deriveSaltFromUsername()` — domain separation (account vs custom produce different salts)
- `deriveSaltFromUsername()` — validation (empty, too short, too long usernames throw)
- `deriveFileEncryptionKey()` — deterministic for same password+username
- `deriveFileEncryptionKey()` — different passwords produce different keys
- Round-trip: derive key → encrypt → decrypt

**`client/static/js/src/__tests__/account-key-cache.test.ts`** — ~12 tests:
- `cacheAccountKey()` + `getCachedAccountKey()` — store and retrieve round-trip
- `isAccountKeyCached()` — true after cache, false after clear
- `clearCachedAccountKey()` — removes specific user's key
- `clearAllCachedAccountKeys()` — removes all
- `lockAccountKey()` — makes `getCachedAccountKey()` return null
- `unlockAccountKey()` — allows caching again
- `isAccountKeyLocked()` — reflects lock state
- Session binding — mismatched token causes auto-lock
- Expiration — expired entry returns null
- Config — `getAccountKeyCacheConfig()` / `setAccountKeyCacheConfig()` round-trip

**`client/static/js/src/__tests__/digest-cache.test.ts`** — ~8 tests:
- `addDigest()` + `checkDuplicate()` — finds duplicate
- `checkDuplicate()` — returns null when no match
- `removeDigest()` — removes entry
- `clearDigestCache()` — clears all
- `populateDigestCache()` — decrypts and populates from mock file entries

**`client/static/js/src/__tests__/errors.test.ts`** — ~6 tests:
- Error hierarchy (CryptoError → KeyDerivationError → KeyDerivationTimeoutError etc.)
- `wrapError()` — wraps unknown errors, passes through CryptoErrors
- `isCryptoError()` — type guard
- `getUserFriendlyMessage()` — returns appropriate messages for each error type

### Key Technical Decisions

1. **sessionStorage mock**: Simple `Map`-based mock assigned to `globalThis.sessionStorage` in setup.ts. This is needed for account-key-cache and digest-cache tests.

2. **No window mock needed for most tests**: Only account-key-cache's `registerAccountKeyCleanupHandlers()` and `startInactivityMonitor()` need `window`. We'll mock `window.addEventListener` minimally.

3. **Argon2 in tests**: The `deriveKeyArgon2id` function uses `@noble/hashes/argon2` which works in bun. However, the default params (256MB, 8 iterations) are very slow. For tests, we'll use reduced params where possible, or test `deriveSaltFromUsername` (which is synchronous and fast) separately from the full key derivation.

4. **constants.ts `getArgon2Params()`**: This does a `fetch()` to load `argon2id-params.json`. In tests we'll need to either mock `fetch` or mock the function. I'll mock `fetch` to return the params JSON.

5. **Import paths**: The source uses `.js` extensions in imports (e.g., `from './primitives.js'`). Bun handles this correctly for `.ts` files.

### Execution

```bash
# Run all unit tests
bun test client/static/js/src/__tests__/
```

### What This Does NOT Cover (and why)

- **`opaque.ts`** — Depends on WASM module (`libopaque`), too complex to mock for unit tests
- **`share-crypto.ts`** — File doesn't exist yet
- **`auth.ts` (AuthManager)** — Heavy DOM/fetch dependency; better tested via e2e
- **`login.ts`, `upload.ts`, `app.ts`** — DOM-heavy, better tested via Playwright

---
