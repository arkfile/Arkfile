# TypeScript Unit Tests - Current State & Roadmap

## Running Tests

```bash
bun test client/static/js/src/__tests__/
```

---

## Section 1: Coverage Assessment by Functionality Area

### Excellent Coverage

These modules have thorough unit tests with edge cases, error paths, and known-answer vectors.

| Module | Test File | Tests | What's Covered |
|--------|-----------|-------|----------------|
| **Crypto Primitives** (`crypto/primitives.ts`) | `primitives.test.ts` | 40 | `randomBytes`, `generateIV`, `generateSalt`, `hash256`, `hash512`, `hashString`, `toBase64`/`fromBase64`, `toHex`/`fromHex`, `constantTimeEqual`, `secureWipe`, `concatBytes`, `encryptAESGCM`/`decryptAESGCM` round-trip + wrong-key + tampered + empty plaintext, `deriveKeyArgon2id` determinism + different inputs + param validation (memoryCost, timeCost, parallelism, keyLength) |
| **Error Hierarchy** (`crypto/errors.ts`) | `errors.test.ts` | 35 | All 20+ error classes (CryptoError → KeyDerivationError → TimeoutError, DecryptionError → AuthenticationError → CorruptedDataError, EncryptionError → FileTooLargeError, OpaqueError variants, SaltDerivationError, InvalidKeyError, StorageError, NetworkError, ValidationError), `wrapError` (CryptoError passthrough, plain Error, string, null, number), `isCryptoError` type guard, `getUserFriendlyMessage` for all error types |
| **File Encryption / Key Derivation** (`crypto/file-encryption.ts`) | `file-encryption.test.ts` | 21 | `deriveSaltFromUsername` determinism, different usernames/contexts, manual SHA-256 verification, whitespace trimming, case sensitivity (matches Go), boundary validation (10-50 chars), `deriveFileEncryptionKey` determinism + different passwords/usernames/contexts + invalid username rejection |
| **Account Key Cache** (`crypto/account-key-cache.ts`) | `account-key-cache.test.ts` | 20 | `cacheAccountKey`/`getCachedAccountKey` round-trip, null for uncached/wrong user, `isAccountKeyCached` true/false/after-clear, `clearCachedAccountKey` specific user, `clearAllCachedAccountKeys`, `lockAccountKey`/`unlockAccountKey`/`isAccountKeyLocked`, session binding (mismatched token auto-locks), `getAccountKeyCacheConfig`/`setAccountKeyCacheConfig` round-trip + clamping, `cleanupAccountKeyCache` |
| **Digest Cache** (`utils/digest-cache.ts`) | `digest-cache.test.ts` | 13 | `addDigest`/`checkDuplicate` round-trip + null for missing + multiple entries + overwrite, `removeDigest` specific/no-op, `clearDigestCache` all/empty, `populateDigestCache` from encrypted entries + skip missing fields + skip decryption failures |

### No Unit Test Coverage

These modules have **zero** unit tests. Some are better suited for e2e/integration testing, but several have pure-logic functions that could benefit from unit tests.

| Module | Source File(s) | Testable Functions | Notes |
|--------|---------------|-------------------|-------|
| **Share Crypto** | `shares/share-crypto.ts` | `encryptFEKForShare`/`decryptShareEnvelope` round-trip, AAD binding (wrong shareId/fileId fails), wrong password fails, `generateFEK` (32 bytes, unique), `encodeFEK`/`decodeFEK` round-trip, empty password/shareId rejection, envelope JSON structure, `validateSharePasswordStrength` | **High priority** - pure crypto, no DOM deps, fully testable |
| **Password Validation** | `crypto/password-validation.ts` | `validatePassword`, `validateAccountPassword`, `validateSharePassword`, `validatePasswordBasic` | **High priority** - pure logic, loads config via fetch (mockable) |
| **AES-GCM Decryptor** | `crypto/aes-gcm.ts` | `AESGCMDecryptor.fromRawKey`, `decryptChunk`, `decryptChunks`, `verifyChunk` | **Medium priority** - pure crypto, testable with synthetic chunks |
| **Retry Handler** | `files/retry-handler.ts` | `isRetryableError`, `calculateDelay`, `withRetry`, `fetchWithRetry` | **Medium priority** - pure logic (delay calculation, error classification), fetch-dependent parts need mocking |
| **Crypto Types** | `crypto/types.ts` | `isFileEncryptionKey`, `isOpaqueExportKey`, `isSessionKey`, `isSuccess`, `isFailure` | **Low priority** - simple type guards, but easy to test |
| **Constants Loader** | `crypto/constants.ts` | `getArgon2Params`, `getChunkingParams`, `isValidArgon2Variant`, `isValidKeyLength` | **Low priority** - config loading (fetch-dependent), validators are simple |
| **Auth Manager** | `utils/auth.ts` | `parseJwtToken`, `getUsernameFromToken`, `isTokenExpired`, `getTokenExpiry` | **Medium priority** - JWT parsing is pure logic; token storage and refresh need localStorage/fetch mocks |
| **OPAQUE Client** | `crypto/opaque.ts` | `storeClientSecret`/`retrieveClientSecret`/`clearClientSecret` | **Low priority** - WASM-dependent for core functions; only secret storage helpers are testable |
| **Login/Register** | `auth/login.ts`, `auth/register.ts` | - | DOM + fetch + OPAQUE WASM; **e2e only** |
| **TOTP** | `auth/totp.ts`, `auth/totp-setup.ts` | - | DOM + fetch; **e2e only** |
| **File Upload** | `files/upload.ts` | `encryptChunk`, `encryptMetadata`, `createEnvelopeHeader` | Internal helpers are testable but not exported; **e2e preferred** |
| **File Download** | `files/download.ts` | - | Fetch + DOM; **e2e only** |
| **Streaming Download** | `files/streaming-download.ts` | `StreamingDownloadManager` internal methods | Complex fetch orchestration; **e2e preferred** |
| **File List** | `files/list.ts` | `escapeHtml` (not exported) | DOM-heavy; **e2e only** |
| **File Share UI** | `files/share.ts` | - | DOM + fetch; **e2e only** |
| **Share Access UI** | `shares/share-access.ts` | - | DOM + fetch; **e2e only** |
| **Share Creation UI** | `shares/share-creation.ts` | - | DOM + fetch; **e2e only** |
| **Share List UI** | `shares/share-list.ts` | - | DOM + fetch; **e2e only** |
| **UI Modules** | `ui/messages.ts`, `ui/modals.ts`, `ui/password-modal.ts`, `ui/progress.ts`, `ui/sections.ts` | - | Pure DOM manipulation; **e2e only** |
| **Password Toggle** | `utils/password-toggle.ts` | - | DOM manipulation; **e2e only** |
| **App Entry** | `app.ts` | - | Orchestration + DOM; **e2e only** |

---

## Section 2: Remaining Unit Tests to Add (Priority Order)

### Phase 1: Share Crypto (HIGH - next to implement)

**File:** `client/static/js/src/__tests__/share-crypto.test.ts`

`shares/share-crypto.ts` is fully written, has zero DOM dependencies, and is the most critical untested pure-crypto module. Estimated ~15 tests:

- `generateFEK()` - returns 32 bytes, unique each call
- `encodeFEK()` / `decodeFEK()` - round-trip, correct base64
- `encryptFEKForShare()` → `decryptShareEnvelope()` - full round-trip
- `encryptFEKForShare()` - rejects invalid FEK size, empty password, empty shareId
- `decryptShareEnvelope()` - wrong password → `DecryptionError`
- `decryptShareEnvelope()` - wrong shareId (AAD mismatch) → `DecryptionError`
- `decryptShareEnvelope()` - wrong fileId (AAD mismatch) → `DecryptionError`
- `decryptShareEnvelope()` - empty password/shareId rejection
- `decryptShareEnvelope()` - truncated data rejection
- Envelope structure - JSON contains `fek`, `download_token`, optional `filename`/`size_bytes`/`sha256`
- Metadata round-trip - filename, sizeBytes, sha256 survive encrypt→decrypt
- Download token - returned from encrypt, present in decrypted envelope

**Note:** These tests will be slow (~200ms each) due to Argon2id. Use `getArgon2Params()` mock or accept the latency.

### Phase 2: Password Validation (HIGH)

**File:** `client/static/js/src/__tests__/password-validation.test.ts`

`crypto/password-validation.ts` loads `password-requirements.json` via fetch, then does pure validation. Estimated ~12 tests:

- `validatePasswordBasic()` - meets/fails minimum length
- `validateAccountPassword()` - meets all requirements (length, uppercase, lowercase, digit, special)
- `validateAccountPassword()` - fails each requirement individually
- `validateSharePassword()` - meets/fails share-specific requirements
- `validateCustomPassword()` - custom min length
- Empty password rejection
- Unicode password handling

**Requires:** Mock `fetch` to return `password-requirements.json` content.

### Phase 3: Auth Manager Pure Logic (MEDIUM)

**File:** `client/static/js/src/__tests__/auth-manager.test.ts`

The JWT-parsing functions in `utils/auth.ts` are pure logic. Estimated ~10 tests:

- `parseJwtToken()` - decodes valid JWT, returns null for garbage/empty
- `getUsernameFromToken()` - extracts `sub` claim
- `getTokenExpiry()` - extracts `exp` claim as Date
- `isTokenExpired()` - true for past exp, false for future exp
- `setTokens()` / `getToken()` / `getRefreshToken()` - localStorage round-trip
- `clearTokens()` - removes both keys
- `isAuthenticated()` - true when token exists, false when cleared
- `clearAllSessionData()` - clears everything

**Requires:** Mock `localStorage` (similar to existing `sessionStorage` mock in `setup.ts`).

### Phase 4: AES-GCM Chunk Decryptor (MEDIUM)

**File:** `client/static/js/src/__tests__/aes-gcm.test.ts`

`crypto/aes-gcm.ts` provides chunk-level decryption. Estimated ~8 tests:

- `AESGCMDecryptor.fromRawKey()` - creates instance from 32-byte key
- `decryptChunk()` - round-trip (encrypt with primitives, decrypt with class)
- `decryptChunks()` - multiple chunks in sequence
- `verifyChunk()` - returns true for valid, false for tampered
- Wrong key → failure
- Invalid key length → rejection

### Phase 5: Retry Handler (MEDIUM)

**File:** `client/static/js/src/__tests__/retry-handler.test.ts`

`files/retry-handler.ts` has pure-logic helpers. Estimated ~8 tests:

- `isRetryableError()` - network errors → true, 4xx → false, 5xx → true
- `calculateDelay()` - exponential backoff with jitter, respects maxDelay
- `sleep()` - resolves after delay
- `withRetry()` - retries on failure, succeeds on Nth attempt, exhausts retries

**Requires:** Mock `fetch` for `fetchWithRetry` tests.

### Phase 6: Crypto Type Guards (LOW)

**File:** `client/static/js/src/__tests__/crypto-types.test.ts`

`crypto/types.ts` has simple type guards. Estimated ~10 tests:

- `isFileEncryptionKey()` - valid/invalid inputs
- `isOpaqueExportKey()` - valid/invalid inputs
- `isSessionKey()` - valid/invalid inputs
- `isSuccess()` / `isFailure()` - Result type discrimination

---

## Test Infrastructure

### Current Setup (`__tests__/setup.ts`)

- In-memory `sessionStorage` mock (Map-based, assigned to `globalThis`)
- Minimal `window.addEventListener` mock for account-key-cache cleanup handlers
- No Web Crypto mock needed - Bun provides `crypto.subtle` natively
- Argon2id works via `@noble/hashes/argon2` (pure JS, no WASM)

### What Would Need to Be Added

- **`localStorage` mock** - needed for Phase 3 (AuthManager) and Phase 5 (retry handler)
- **`fetch` mock** - needed for Phase 2 (password validation config loading) and Phase 5 (retry handler)
- **Consider reducing Argon2 params for tests** - current params make share-crypto tests slow; could mock `getArgon2Params()` to return lighter params in test environment

---

## Summary

| Status | Area | Tests |
|--------|------|-------|
| Done | Crypto primitives | 40 |
| Done | Error hierarchy | 35 |
| Done | File encryption / key derivation | 21 |
| Done | Account key cache | 20 |
| Done | Digest cache | 13 |
| Phase 1 | Share crypto | ~15 |
| Phase 2 | Password validation | ~12 |
| Phase 3 | Auth manager (JWT parsing) | ~10 |
| Phase 4 | AES-GCM chunk decryptor | ~8 |
| Phase 5 | Retry handler | ~8 |
| Phase 6 | Crypto type guards | ~10 |
| - | DOM/UI modules | e2e only |
| **Total** | | **136 done + ~63 planned** |
