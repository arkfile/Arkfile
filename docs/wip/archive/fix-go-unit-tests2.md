# Fix Go Unit Tests - Revised Plan (v2)

## Context

This document revises the initial assessment in `fix-go-unit-tests.md` after an independent deep review of all Go source files, existing test files, the e2e test scripts, and AGENTS.md. It corrects several factual errors in the initial plan and reorders priorities based on what is actually testable without production code refactoring.

## Key Corrections from Initial Plan

1. **OPAQUE handler tests cannot be written today.** The initial plan claimed the `TestOPAQUEProvider` in `auth_test_helpers.go` was "already built" and just needed tests. In reality, there is no `OPAQUEProvider` interface in production code. The OPAQUE handlers call `auth.CreateRegistrationResponse()`, `auth.StoreUserRecord()`, `auth.CreateCredentialResponse()`, and `auth.UserAuth()` directly as package-level functions that go to CGO (libopaque). No dependency injection seam exists. The `TestOPAQUEProvider` is dead code.

2. **CLI client crypto functions were significantly undervalued.** The initial plan dismissed CLI testing as "harder without CGO." In fact, `cmd/arkfile-client/crypto_utils.go`, `agent.go`, `offline_decrypt.go`, and `dedup.go` contain many pure-Go security-critical functions with zero test coverage that are fully testable without CGO.

3. **The `admin_test.go` schema mismatch (Issue #5) is not a test bug.** Both `file_shares` (legacy) and `file_share_keys` (current) tables exist in the schema. The handler and test both use `file_shares`. The real concern is whether the handler should be using `file_share_keys` instead -- that is a potential handler bug, not a test bug. This should be flagged to developers per AGENTS.md guidance on legacy/backwards-compatibility code.

---

## Priority Areas

### HIGH PRIORITY 1: Crypto Primitives (crypto/ package)

**New files:** `crypto/gcm_test.go`, `crypto/share_kdf_test.go`, `crypto/key_derivation_test.go`

**Why first:** Every security feature in the app depends on correct AES-GCM encryption, correct Argon2id key derivation, and correct AAD binding for shares. These are pure Go, no CGO, no mocks needed, fast to write and run, and directly prove the security properties documented in AGENTS.md.

**`crypto/gcm_test.go` - AES-256-GCM core:**
- `TestEncryptDecryptGCM_RoundTrip` - encrypt then decrypt, verify plaintext matches
- `TestEncryptDecryptGCM_WrongKeyFails` - decrypt with different key must fail
- `TestEncryptGCM_KeySizeValidation` - non-32-byte key must error
- `TestDecryptGCM_TruncatedCiphertext` - ciphertext shorter than nonce+tag must fail
- `TestDecryptGCM_TamperedCiphertext` - flipping a byte in ciphertext must fail
- `TestEncryptDecryptGCMWithAAD_RoundTrip` - encrypt/decrypt with AAD, verify plaintext
- `TestDecryptGCMWithAAD_WrongAADFails` - decrypt with different AAD must fail (core share security model)
- `TestDecryptGCMWithAAD_NoAADFails` - decrypt without AAD when AAD was used must fail
- `TestEncryptGCM_UniqueNonces` - two encryptions of same plaintext produce different ciphertext
- `TestGenerateAESKey` - verify 32-byte length and randomness

**`crypto/share_kdf_test.go` - Share key derivation and envelope:**
- `TestGenerateShareSalt` - verify base64 output, decoded length is 32 bytes, two calls produce different salts
- `TestDeriveShareKey_Consistency` - same password + salt produces same key
- `TestDeriveShareKey_DifferentPasswordProducesDifferentKey` - different password, same salt
- `TestDeriveShareKey_DifferentSaltProducesDifferentKey` - same password, different salt
- `TestDeriveShareKey_InvalidSaltLength` - wrong-length salt must error
- `TestDeriveShareKey_InvalidSaltEncoding` - non-base64 salt must error
- `TestHashDownloadToken_Consistency` - same token always produces same hash
- `TestVerifyDownloadToken_Success` - hash matches
- `TestVerifyDownloadToken_WrongToken` - different token does not match
- `TestCreateParseShareEnvelope_RoundTrip` - create then parse, fields match
- `TestParseShareEnvelope_MissingFEK` - missing required field must error
- `TestParseShareEnvelope_MissingDownloadToken` - missing required field must error
- `TestParseShareEnvelope_InvalidJSON` - malformed JSON must error
- `TestCreateAAD` - verify output is concatenation of share_id + file_id
- `TestShareEnvelopeEncryptDecrypt_FullCycle` - DeriveShareKey, CreateShareEnvelope, EncryptGCMWithAAD, DecryptGCMWithAAD, ParseShareEnvelope, verify FEK/token/metadata match originals
- `TestShareEnvelopeEncryptDecrypt_WrongPassword` - derive with wrong password, decrypt must fail
- `TestShareEnvelopeEncryptDecrypt_WrongAAD` - encrypt with AAD(share_id_A, file_id), decrypt with AAD(share_id_B, file_id) must fail (proves share envelope binding)

**`crypto/key_derivation_test.go` - Argon2id and salt generation:**
- `TestDeriveArgon2IDKey_EmptyPassword` - must error
- `TestDeriveArgon2IDKey_TooLongPassword` - over MaxPasswordBytes must error
- `TestDeriveArgon2IDKey_EmptySalt` - must error
- `TestDeriveArgon2IDKey_ZeroKeyLen` - must error
- `TestDeriveArgon2IDKey_ValidDerivation` - non-nil, correct length output
- `TestGenerateUserKeySalt_Deterministic` - same username + keyType always produces same salt
- `TestGenerateUserKeySalt_AccountVsCustom` - account salt != custom salt for same username
- `TestGenerateUserKeySalt_DifferentUsers` - different usernames produce different salts
- `TestDeriveAccountPasswordKey_Consistency` - same password + username always produces same 32-byte key
- `TestDeriveCustomPasswordKey_Consistency` - same password + username always produces same 32-byte key
- `TestDeriveAccountVsCustomKey_Different` - account key != custom key for same password + username
- `TestLoadArgon2Params_EmbeddedJSON` - GetEmbeddedArgon2ParamsJSON returns valid parseable JSON with expected fields
- `TestHKDFExpand_EmptyPRK` - must error
- `TestHKDFExpand_InvalidLength` - zero or too-large length must error
- `TestHKDFExpand_ValidExpansion` - produces correct-length output

### HIGH PRIORITY 2: CLI Client Crypto Functions (cmd/arkfile-client/)

**New file:** `cmd/arkfile-client/crypto_utils_test.go`

**Why:** These are the actual client-side encryption/decryption functions used by `arkfile-client upload` and `arkfile-client download`. They implement the core privacy model: client-side encryption with account key or custom password. A bug here = data loss or privacy breach. All pure Go, no CGO needed.

**Tests:**
- `TestEncryptDecryptChunk_RoundTrip` - encrypt then decrypt a chunk, verify plaintext matches
- `TestEncryptDecryptChunk_WrongFEKFails` - decrypt with different FEK must fail
- `TestEncryptDecryptChunk_AccountKeyType` - verify account key type byte (0x01) in envelope
- `TestEncryptDecryptChunk_CustomKeyType` - verify custom key type byte (0x02) in envelope
- `TestEncryptDecryptMetadata_RoundTrip` - encrypt filename + sha256, decrypt both, verify match
- `TestDecryptMetadataField_WrongKey` - decrypt with wrong account key must fail
- `TestWrapUnwrapFEK_AccountKey_RoundTrip` - wrap FEK with account KEK, unwrap, verify FEK + key type match
- `TestWrapUnwrapFEK_CustomKey_RoundTrip` - wrap FEK with custom KEK, unwrap, verify FEK + key type match
- `TestUnwrapFEK_WrongKEKFails` - unwrap with wrong password-derived key must fail
- `TestComputeStreamingSHA256` - compute hash of known file content, verify against known SHA-256
- `TestCalculateTotalEncryptedSize` - verify size calculation for various plaintext sizes (edge cases: 0, 1 byte, exactly chunk boundary, chunk boundary + 1)
- `TestGenerateFEK` - verify 32-byte length and randomness (two calls differ)

### HIGH PRIORITY 3: TOTP + Session Management Handler Tests (handlers/)

**New file:** `handlers/auth_test.go` (TOTP and session handlers only - NOT OPAQUE)

**Why:** The TOTP setup/verify/auth flow and session management (logout, token refresh) are security-critical server-side handlers with zero unit test coverage. Unlike OPAQUE handlers, these use standard Go crypto and database operations that are fully mockable.

**TOTP Handler Tests (using SQL mocks + TOTP test patterns from auth/totp_test.go):**
- `TestTOTPSetup_Success` - authenticated user initiates TOTP setup, gets secret + QR URL
- `TestTOTPSetup_AlreadyEnabled` - user with TOTP already enabled, should handle appropriately
- `TestTOTPSetup_Unauthenticated` - no JWT token in context, should reject
- `TestTOTPVerify_Success` - valid TOTP code completes setup
- `TestTOTPVerify_InvalidCode` - wrong code is rejected
- `TestTOTPVerify_NoSetupInProgress` - verify without prior setup must fail
- `TestTOTPAuth_Success` - valid TOTP code during 2FA login step issues full JWT
- `TestTOTPAuth_InvalidCode` - wrong TOTP code during login rejected
- `TestTOTPAuth_ReplayPrevention` - same code used twice in same window rejected
- `TestTOTPAuth_BackupCodeSuccess` - valid backup code accepted as 2FA
- `TestTOTPStatus_Enabled` - returns correct status for TOTP-enabled user
- `TestTOTPStatus_NotEnabled` - returns correct status for user without TOTP
- `TestTOTPReset_ValidBackupCode` - reset with valid backup code returns new secret

**Session Management Handler Tests:**
- `TestLogout_Success` - revokes JWT, clears refresh token cookie, returns 200
- `TestLogout_NoToken` - no JWT in request, appropriate error
- `TestRefreshToken_Success` - valid refresh token issues new JWT
- `TestRefreshToken_ExpiredToken` - expired refresh token rejected
- `TestRefreshToken_RevokedToken` - revoked refresh token rejected
- `TestRefreshToken_MissingCookie` - no refresh token cookie, appropriate error

### MEDIUM PRIORITY 4: Extend File Shares Handler Tests (handlers/)

**Extend:** `handlers/file_shares_test.go`

**Why:** The existing share tests cover creation and basic access but miss the enforcement boundaries that the e2e tests validate (expiry in Phase 10.12, max_accesses in Phase 10.11, revocation in Phase 10.14).

**Tests:**
- `TestGetShareEnvelope_Expired` - share with `expires_at` in the past returns error (not 200)
- `TestGetShareEnvelope_Revoked` - share with `revoked_at` set returns error
- `TestGetShareEnvelope_MaxAccessesExceeded` - share with access count at limit returns error
- `TestGetShareEnvelope_RateLimited` - entity that has been rate-limited gets appropriate rejection
- `TestDownloadShareChunk_ValidToken` - valid download token allows chunk download
- `TestDownloadShareChunk_InvalidToken` - wrong download token rejected
- `TestGetShareDownloadMetadata_Success` - returns file info for valid share access

### MEDIUM PRIORITY 5: Extend File Operation Handler Tests (handlers/)

**Extend:** `handlers/files_test.go`

**Why:** Several file handlers flagged as untested even in the existing test file's own comments. These enforce file ownership -- a core privacy boundary.

**Tests:**
- `TestListFiles_NoFiles` - user with no files gets empty list and correct storage info
- `TestListFiles_WithFiles` - user with files gets all files listed with correct metadata
- `TestListFiles_StorageCalculations` - verify storage total/limit/available/percentage
- `TestListFiles_DBError` - database error returns appropriate HTTP error
- `TestGetFileEnvelope_Success` - owner can retrieve encrypted FEK envelope
- `TestGetFileEnvelope_NotOwner` - non-owner cannot retrieve envelope (privacy enforcement)
- `TestGetFileEnvelope_FileNotFound` - nonexistent file returns 404
- `TestDownloadFileChunk_Success` - owner can download encrypted chunk
- `TestDownloadFileChunk_NotOwner` - non-owner cannot download (privacy enforcement)
- `TestDownloadFileChunk_FileNotFound` - nonexistent file returns 404

### MEDIUM PRIORITY 6: CLI Agent + Offline Decrypt Tests (cmd/arkfile-client/)

**New files:** `cmd/arkfile-client/agent_test.go`, `cmd/arkfile-client/offline_decrypt_test.go`

**Why:** The agent manages in-memory key caching (a security-sensitive operation), and offline decrypt is the data recovery path. Both are pure Go.

**Agent Tests:**
- `TestAgent_StoreAndRetrieveAccountKey` - store a key, retrieve it with correct token
- `TestAgent_RetrieveWithWrongToken` - wrong access token cannot retrieve key
- `TestAgent_KeyExpiration` - key expires after TTL
- `TestAgent_WipeAllSensitiveData` - after wipe, no keys retrievable
- `TestAgent_StoreAndRetrieveDigestCache` - round-trip digest cache
- `TestAgent_AddRemoveDigest` - add/remove individual digests
- `TestValidateSocketSecurity` - socket with wrong permissions/ownership rejected

**Offline Decrypt Tests:**
- `TestParseBundle_ValidBundle` - parse a well-formed .arkbackup bundle
- `TestParseBundle_InvalidFormat` - malformed bundle returns error
- `TestDecryptBundleBlob_Success` - full decrypt with correct account key matches original plaintext
- `TestDecryptBundleBlob_WrongKey` - decrypt with wrong key fails

---

## Cleanup Items (Do Alongside Any Priority)

These are quick wins to reduce confusion and technical debt:

1. **Remove `handlers/handlers_test.go`** - empty placeholder file (27 lines, only comments). Adds nothing.

2. **Remove deprecated functions from `handlers/opaque_test_helpers.go`** - `setupOPAQUETestUser`, `expectOPAQUEAuthenticationSuccess`, `expectOPAQUEAuthenticationFailure` all contain `t.Skip("DEPRECATED")`. Dead code.

3. **Remove `TestOPAQUEProvider` from `handlers/auth_test_helpers.go`** - implements a non-existent interface. Cannot be used without first introducing an `OPAQUEOperations` interface in production code. Dead code.

4. **Fix `auth/token_revocation_test.go`** - `createTestToken` uses HS256 with `os.Getenv("JWT_SECRET")` but production uses Ed25519. The `TestMain` in this package (defined in `jwt_test.go`) does set up Ed25519 keys via `ResetKeysForTest()`, but `createTestToken` ignores them. Either update `createTestToken` to use Ed25519 + `GetJWTPrivateKey()`, or document why the HS256 approach works (token is parsed unverified in the revocation path).

5. **Flag `handlers/admin.go` legacy table usage** - the `DeleteUser` handler uses `DELETE FROM file_shares WHERE owner_username = ?` which targets the legacy `file_shares` table. The current shares table is `file_share_keys`. This may leave orphan share records in `file_share_keys` when deleting a user. The test correctly matches the handler, but the handler itself may be wrong. Flag to developers.

6. **Remove misleading `TestAccessSharedFile_WeakPassword`** from `handlers/file_shares_test.go` - this test is essentially a duplicate of `TestAccessSharedFile_Success` with a different password string. The comment says "handler doesn't actually validate password strength" and expects 200 OK. It does not test any unique behavior and has a misleading name.

---

## Deferred: OPAQUE Handler Unit Tests

The OPAQUE registration and login handlers (`OpaqueRegisterResponse`, `OpaqueRegisterFinalize`, `OpaqueAuthResponse`, `OpaqueAuthFinalize`) cannot be unit-tested without refactoring production code. They call `auth.CreateRegistrationResponse()`, `auth.StoreUserRecord()`, `auth.CreateCredentialResponse()`, and `auth.UserAuth()` as direct package-function calls to CGO (libopaque). There is no interface or dependency injection seam.

**To enable OPAQUE handler unit tests in the future:**
1. Define an `OPAQUEOperations` interface in `auth/` with methods matching the current package functions
2. Create a production implementation wrapping the CGO calls
3. Create a test mock implementation
4. Refactor handlers to accept the interface (e.g., via a handler struct or context injection)
5. Then write handler tests using the mock

This is a non-trivial refactoring task. The OPAQUE flow is already well-tested by the e2e test suite (`e2e-test.sh` Phases 2, 4, 5, 7) and the `auth/opaque_multi_step.go` functions are tested indirectly via the e2e integration. Unit testing for OPAQUE handlers should be treated as a separate refactoring initiative.

---

## What Already Works Well

These existing test files are in good shape and align with current source code:

- `auth/totp_test.go` - comprehensive TOTP library tests (setup, complete, validate, replay, backup, reset)
- `auth/jwt_test.go` - JWT generation, parsing, middleware (valid/expired/wrong-sig/no-token/malformed)
- `auth/token_revocation_test.go` - revocation, cache, cleanup, middleware (needs minor HS256 fix)
- `auth/totp_backup_test.go` - backup code randomness
- `crypto/file_operations_test.go` - FEK generation, encrypt/decrypt with account+custom keys, envelope parsing, test file generation, integrity verification
- `crypto/password_validation_test.go` - entropy, share password, pattern detection
- `models/user_test.go` - user CRUD, admin privileges, approval, storage usage
- `handlers/admin_test.go` - extensive admin handler tests
- `handlers/uploads_test.go` - upload handler with error paths
- `handlers/file_shares_test.go` - share creation, access, revocation (needs extension for boundaries)
- `handlers/files_test.go` - delete file, metadata listing (needs extension)

---

# REMAINING WORK

## Section A: handlers/ TestMain + Auth Success-Path Tests

The key unlock is adding a `TestMain` to the handlers package that bootstraps both JWT Ed25519 keys AND TOTP master keys. This follows the exact same pattern as `auth/jwt_test.go`'s TestMain.

**New file:** `handlers/test_main_test.go`
- Set `ARKFILE_MASTER_KEY` env var (same test key as auth/jwt_test.go)
- Create in-memory SQLite with `system_keys` table
- Call `crypto.InitKeyManager(db)` 
- Set env vars for `config.LoadConfig()`
- Call `auth.ResetKeysForTest()`
- Set `TOTP_MASTER_KEY_PATH` to temp dir
- Call `crypto.InitializeTOTPMasterKey()`

**New tests in `handlers/auth_test.go`** (adding to existing file):
- `TestRefreshToken_Success` -- mock valid refresh token + user query, verify new JWT is issued
- `TestTOTPAuth_Success` -- store encrypted TOTP data in mock DB (using real `crypto.DeriveTOTPUserKey` + `crypto.EncryptGCM` with the fixed secret `ARKFILEPKZBXCMJLGB5HM5D2GEVVU32D`), generate a real TOTP code with `totp.GenerateCode()`, call the handler, verify full access JWT is issued

These are the two most security-critical success paths that were missing.

## Section B: Offline Decrypt End-to-End Test

**Add to `cmd/arkfile-client/offline_decrypt_test.go`:**
- `TestDecryptBundleBlob_Success` -- construct a real `.arkbackup` bundle:
  1. Generate FEK, wrap it with account KEK (using `crypto.DeriveAccountPasswordKey`)
  2. Encrypt test plaintext using `encryptChunk()`
  3. Write bundle in ARKB format (magic + version + header + encrypted blob)
  4. Call `parseBundle()` to get metadata
  5. Unwrap FEK, decrypt chunks, verify plaintext matches
- `TestDecryptBundleBlob_WrongKey` -- same but derive KEK from wrong password, verify decryption fails

## Section C: Storage Calculations + Share Download Token Tests

**Add to `handlers/files_test.go`:**
- `TestListFiles_StorageCalculations` -- verify storage math (usage_percent, available_bytes) with specific values

**Add to `handlers/file_shares_test.go`:**
- `TestDownloadShareChunk_ValidToken` -- mock the share + download token hash query, verify chunk download proceeds (requires S3 mock)
- `TestDownloadShareChunk_InvalidToken` -- wrong token hash, verify rejection

---

**Estimated: ~8-10 new tests across all sections.**

Section A is the highest value because it unlocks auth success-path tests. Section B is the disaster recovery path. Section C is nice-to-have.

---

