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
| **Retry Handler** (`files/retry-handler.ts`) | `retry-handler.test.ts` | 34 | `isRetryableError` (TypeError with "fetch" → true, TypeError without → false, status 500/502/503/429/408 → true, status 400/401/403/404 → false, plain Error/null/undefined/string/number → false), `calculateDelay` (exponential backoff attempts 0-3, maxDelay cap, jitter ±25% range, jitter non-determinism, integer floor), `sleep` (resolves after delay, returns undefined), `withRetry` (first-attempt success, retry on retryable error, exhaust retries, non-retryable stops immediately, onRetry callback args, non-Error throw conversion, maxRetries:0), `DEFAULT_RETRY_CONFIG` defaults |
| **Crypto Type Guards** (`crypto/types.ts`) | `crypto-types.test.ts` | 33 | `isFileEncryptionKey` (valid, wrong key type, missing/wrong username, missing/wrong derivedAt, null/undefined/string/number/empty object), `isOpaqueExportKey` (valid, wrong key type, missing/wrong generatedAt, null/undefined/empty), `isSessionKey` (valid, wrong key type, missing derivedAt/expiresAt, wrong expiresAt type, null/undefined/empty, distinguishes from FileEncryptionKey), `isSuccess`/`isFailure` (success/failure discrimination, type narrowing) |
| **AES-GCM Decryptor** (`crypto/aes-gcm.ts`) | `aes-gcm.test.ts` | 9 | `AESGCMDecryptor.fromRawKey()` (valid/invalid lengths), `decryptChunk()` (round-trip, empty plaintext, rejects too-small chunk, wrong key fails), `decryptChunks()` (multiple chunks with progress callback), `verifyChunk()` (returns true for valid, false for tampered). Includes inline fetch mock for chunking config + Web Crypto encrypt helper for manual chunk construction. |

### No Unit Test Coverage

These modules have **zero** unit tests. They are DOM/fetch/WASM-dependent and belong in e2e/integration testing.

| Module | Source File(s) | Notes |
|--------|---------------|-------|
| **Constants Loader** | `crypto/constants.ts` | Config loading (fetch-dependent), validators are simple; **low priority** |
| **OPAQUE Client** | `crypto/opaque.ts` | WASM-dependent for core functions; only secret storage helpers are testable; **low priority** |
| **Login/Register** | `auth/login.ts`, `auth/register.ts` | DOM + fetch + OPAQUE WASM; **e2e only** |
| **TOTP** | `auth/totp.ts`, `auth/totp-setup.ts` | DOM + fetch; **e2e only** |
| **File Upload** | `files/upload.ts` | Internal helpers not exported; **e2e preferred** |
| **File Download** | `files/download.ts` | Fetch + DOM; **e2e only** |
| **Streaming Download** | `files/streaming-download.ts` | Complex fetch orchestration; **e2e preferred** |
| **File List** | `files/list.ts` | DOM-heavy; **e2e only** |
| **File Share UI** | `files/share.ts` | DOM + fetch; **e2e only** |
| **Share Access UI** | `shares/share-access.ts` | DOM + fetch; **e2e only** |
| **Share Creation UI** | `shares/share-creation.ts` | DOM + fetch; **e2e only** |
| **Share List UI** | `shares/share-list.ts` | DOM + fetch; **e2e only** |
| **UI Modules** | `ui/messages.ts`, `ui/modals.ts`, `ui/password-modal.ts`, `ui/progress.ts`, `ui/sections.ts` | Pure DOM manipulation; **e2e only** |
| **Password Toggle** | `utils/password-toggle.ts` | DOM manipulation; **e2e only** |
| **App Entry** | `app.ts` | Orchestration + DOM; **e2e only** |

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

### Future Unit Test Infrastructure Improvements

- **Consider reducing Argon2 params for tests** — share-crypto tests are slow (~5s each) due to Argon2id; could mock `getArgon2Params()` to return lighter params in test environment
- **Consider centralizing `localStorage` mock in setup.ts** — currently only auth-manager.test.ts needs it, but if more tests require it, moving to setup.ts would reduce duplication
- **Consider centralizing `fetch` mock** — currently `password-validation.test.ts` and `aes-gcm.test.ts` both implement custom inline fetch intercepts. Moving this to a flexible mock in `setup.ts` would clean up individual test files.

---

## Summary

| Status | Area | Tests |
|--------|------|-------|
| Done | Crypto primitives | 40 |
| Done | Error hierarchy | 35 |
| Done | Retry handler | 34 |
| Done | Crypto type guards | 33 |
| Done | Auth manager (JWT, tokens, errors) | 28 |
| Done | Password validation | 24 |
| Done | File encryption / key derivation | 21 |
| Done | Account key cache | 20 |
| Done | Share crypto | 17 |
| Done | Digest cache | 13 |
| Done | AES-GCM chunk decryptor | 9 |
| - | DOM/UI modules | e2e only |
| **Total** | | **274 done** |

> **Note:** `bun test` reports 281 passing (272 prior + 9 new AES-GCM tests). Minor differences vs. grep counts are due to parameterized/nested test cases that expand at runtime.
