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
| **Share Crypto** (`shares/share-crypto.ts`) | `share-crypto.test.ts` | 17 | `generateFEK` (32 bytes, unique), `encodeFEK`/`decodeFEK` round-trip + valid base64, `encryptFEKForShare`→`decryptShareEnvelope` full round-trip, metadata round-trip (filename, sizeBytes, sha256), download token presence, rejects invalid FEK size / empty password / empty shareId, wrong password → DecryptionError, wrong shareId/fileId AAD mismatch → DecryptionError, empty password/shareId rejection on decrypt, missing salt rejection, truncated data rejection |
| **Password Validation** (`crypto/password-validation.ts`) | `password-validation.test.ts` | 24 | `validatePassword` core logic (empty, too short, class counting, boundary length, special char recognition, failure reasons), `validateAccountPassword` (15+ chars, 2+ classes, fails each), `validateSharePassword` (20+ chars, 2+ classes, fails each), `validateCustomPassword` (custom min length), `validatePasswordBasic` (hardcoded 4-class requirement). Includes inline `fetch` mock returning `password-requirements.json` config. |
| **Auth Manager** (`utils/auth.ts`) | `auth-manager.test.ts` | 28 | `setTokens`/`getToken`/`getRefreshToken`/`clearTokens` localStorage round-trip, `isAuthenticated` true/false, `parseJwtToken` (valid decode, malformed JWT, invalid base64, missing username/exp, wrong types), `getUsernameFromToken`, `getTokenExpiry` (Date object, null), `isTokenExpired` (no token, future, past), `clearAllSessionData` (clears localStorage + sessionStorage), `ServiceUnavailableError` (name, default/custom message, instanceof), `getAdminUsernames`/`getAdminContact` defaults. Includes inline `localStorage` mock (Map-backed). |

### No Unit Test Coverage

These modules have **zero** unit tests. Some are better suited for e2e/integration testing, but several have pure-logic functions that could benefit from unit tests.

| Module | Source File(s) | Testable Functions | Notes |
|--------|---------------|-------------------|-------|
| **AES-GCM Decryptor** | `crypto/aes-gcm.ts` | `AESGCMDecryptor.fromRawKey`, `decryptChunk`, `decryptChunks`, `verifyChunk` | **Medium priority** - pure crypto, testable with synthetic chunks |
| **Retry Handler** | `files/retry-handler.ts` | `isRetryableError`, `calculateDelay`, `withRetry`, `fetchWithRetry` | **Medium priority** - pure logic (delay calculation, error classification), fetch-dependent parts need mocking |
| **Crypto Types** | `crypto/types.ts` | `isFileEncryptionKey`, `isOpaqueExportKey`, `isSessionKey`, `isSuccess`, `isFailure` | **Low priority** - simple type guards, but easy to test |
| **Constants Loader** | `crypto/constants.ts` | `getArgon2Params`, `getChunkingParams`, `isValidArgon2Variant`, `isValidKeyLength` | **Low priority** - config loading (fetch-dependent), validators are simple |
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

### Inline Mocks in Individual Test Files

- **`auth-manager.test.ts`** — carries its own `localStorage` mock (Map-backed `MockLocalStorage` class, installed on `globalThis` before imports)
- **`password-validation.test.ts`** — carries its own `fetch` mock (intercepts requests for `password-requirements.json`, returns production config values)

### What Would Need to Be Added for Remaining Phases

- **`fetch` mock** — needed for Phase 5 (retry handler `fetchWithRetry` tests); could reuse the pattern from password-validation.test.ts
- **Consider reducing Argon2 params for tests** — share-crypto tests are slow (~200ms each) due to Argon2id; could mock `getArgon2Params()` to return lighter params in test environment
- **Consider centralizing `localStorage` mock in setup.ts** — currently only auth-manager.test.ts needs it, but if more tests require it, moving to setup.ts would reduce duplication

---

## Summary

| Status | Area | Tests |
|--------|------|-------|
| ✅ Done | Crypto primitives | 40 |
| ✅ Done | Error hierarchy | 35 |
| ✅ Done | File encryption / key derivation | 21 |
| ✅ Done | Account key cache | 20 |
| ✅ Done | Digest cache | 13 |
| ✅ Done | Share crypto | 17 |
| ✅ Done | Password validation | 24 |
| ✅ Done | Auth manager (JWT, tokens, errors) | 28 |
| Phase 4 | AES-GCM chunk decryptor | ~8 |
| Phase 5 | Retry handler | ~8 |
| Phase 6 | Crypto type guards | ~10 |
| - | DOM/UI modules | e2e only |
| **Total** | | **198 done + ~26 planned** |

> **Note:** `bun test` reports 205 passing (as of last run). The 7-test difference vs. the grep count above is due to parameterized/nested test cases that expand at runtime. The grep count of 198 reflects unique `test()` call sites in source.
