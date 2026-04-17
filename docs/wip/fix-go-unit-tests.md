# Fix Go Unit Tests

## Original Prompt:

Please read AGENTS.md and e2e-test.sh and e2e-playwright.sh (and the ts tests for it). We have unit tests pretty well solidified on the frontend typescript side. But our go unit tests are in large part out of date or wrong (old/deprecated/referencing since removed functionality) and so on and I'd like your help to identify key areas of the go unit tests to focus on first. Priority is critical functions that are intended to create a secure and privacy system overall for the app. Don't forget to consider the go cli client side too: arkfile-admin and arkfile-client. 

The e2e test scripts largely lay out what functionality is critical for a functioning system, and that might give a good sense of where to focus for unit test refactoring. e.g. unit tests for auth (register, totp create/finalize, login, totp 2FA for login, logout), account key caching client side, client-side file encryption using account (key) or custom password based KDF with AES-GCM, share creation, local share file metadata decryption, local share file download/decrypt, etc.

---

## Initial Codebase Survey

Files checked:

docs/AGENTS.md · lines 1-92
scripts/testing/e2e-test.sh · lines 1-1000
scripts/testing/e2e-test.sh · lines 1001-1735
auth/jwt_test.go · lines 1-316
auth/totp_test.go · lines 1-437
auth/token_revocation_test.go · lines 1-376
crypto/file_operations_test.go · lines 1-691
handlers/file_shares_test.go · lines 1-430
handlers/files_test.go · lines 1-301
handlers/handlers_test.go · lines 1-27
handlers/admin_test.go · lines 1-1000
crypto/key_derivation.go · lines 1-175
crypto/share_kdf.go · lines 1-165
crypto/gcm.go · lines 1-220
crypto/password_validation_test.go · lines 1-148
handlers/auth_test_helpers.go · lines 1-165
handlers/opaque_test_helpers.go · lines 1-128
handlers/uploads_test.go · lines 1-80
models/user_test.go · lines 1-372
"^package handlers" in handlers/ (*_test.go)
9 patterns in handlers/ (auth.go)

---

# Recommendations from Claude Sonnet 4.6

## Go Unit Test Gap Analysis and Prioritized Refactoring Plan

After reading all the relevant files, here is a comprehensive assessment. I'll be direct about what's broken, what's missing, and what should be prioritized.

---

## Current State Assessment

### What exists and appears healthy

**auth/ package:**
- `jwt_test.go` - solid: GenerateToken, GetUsernameFromToken, JWTMiddleware (valid/expired/wrong-sig/no-token/malformed). Minor issue: `TestGetUsernameFromToken` signs with HS256 but production uses Ed25519. The token is never actually verified in that test - it just sets it in context directly - so it does not catch a real regression, but it does not crash either.
- `totp_test.go` - solid: TOTP key management (derive/consistency/different-users), setup/store/complete/validate/replay prevention, backup codes, cleanup, reset. These look genuinely correct and match current code.
- `token_revocation_test.go` - mostly solid: RevokeToken, IsRevoked (cache/DB paths), initializeCache (expired vs. active), CleanupExpiredTokens, TokenRevocationMiddleware. One issue: `createTestToken` uses HS256 (not Ed25519) and uses `os.Getenv("JWT_SECRET")` which is not set in the test environment for this file - but since the revocation tests mostly just parse tokens unverified, they work in practice.
- `totp_backup_test.go` - need to verify (not read yet, but the file exists).

**crypto/ package:**
- `file_operations_test.go` - solid coverage of GenerateFEK, EncryptFile/DecryptFile with account and custom key types, EncryptFEK/DecryptFEK, DeriveAccountPasswordKey consistency, envelope creation/parsing, test file generation, file integrity, size parsing. These appear correct and match current source.
- `password_validation_test.go` - solid: entropy validation, share password validation, pattern detection. Appears current.

**models/ package:**
- `user_test.go` - solid: CreateUser, GetUserByUsername, HasAdminPrivileges, ApproveUser (including non-admin rejection), CheckStorageAvailable, UpdateStorageUsage, GetPendingUsers, isAdminUsername. Correctly notes password-hash tests were removed for OPAQUE.
- `refresh_token_test.go` - exists but not read; likely tests RefreshToken model operations.

**handlers/ package:**
- `admin_test.go` - extensive: DeleteUser (success + 7 error paths), UpdateUser (many scenarios), ApproveUser, ListUsers, UpdateUserStorageLimit. SQL mock patterns match actual handler queries reasonably well.
- `files_test.go` - covers DeleteFile (success/not-found/not-owner/storage-error), ListRecentFileMetadata, GetFileMetadataBatch. The comment section at the bottom suggests DownloadFile and ListFiles are not yet tested.
- `uploads_test.go` - covers UploadFile success and 4 error paths.
- `file_shares_test.go` - covers CreateFileShare (success/not-owned), GetShareEnvelope (success/weak-password/nonexistent), GetSharedFile, ListShares, RevokeShare, and a password validation sanity check.
- `chunked_upload_integration_test.go` / `chunked_upload_100mb_test.go` - exist and test chunked upload flows with mocks.

**logging/ package:**
- `entity_id_test.go` and `security_events_test.go` - exist.

**utils/ package:**
- `padding_test.go` and `username_validator_test.go` - exist.

---

## Critical Gaps (Prioritized)

### PRIORITY 1 - Auth Handler Unit Tests (ZERO coverage, highest security impact)

The `handlers/auth.go` file contains the most security-critical server-side functions, and **there is no `auth_test.go` in the handlers package at all.** These handlers are completely untested at the unit level:

**OPAQUE Registration flow (2-step):**
- `OpaqueRegisterResponse` - server receives client OPAQUE message, returns server response
- `OpaqueRegisterFinalize` - server finalizes registration, stores `opaque_user_record`, creates user record

**OPAQUE Login flow (2-step):**
- `OpaqueAuthResponse` - server receives client auth init, returns server auth challenge
- `OpaqueAuthFinalize` - server finalizes auth, issues JWT + sets refresh token cookie, triggers agent key caching

**TOTP handlers (no handler tests at all):**
- `TOTPSetup` - initiates TOTP setup, returns secret + QR code URL
- `TOTPVerify` - verifies a TOTP code to complete setup (marks `setup_completed = true, enabled = true`)
- `TOTPAuth` - validates TOTP code during the 2FA login step, issues final JWT
- `TOTPReset` - resets TOTP using backup code
- `TOTPStatus` - returns TOTP enabled/setup status

**Session management (no handler tests):**
- `Logout` - revokes JWT, clears refresh token cookie
- `RefreshToken` - validates refresh token, issues new JWT
- `RevokeToken`, `RevokeAllRefreshTokens`, `ForceRevokeAllTokens`

These cover nearly the entire authentication and session flow from the e2e tests (Phases 2, 4, 5, 7, and the post-logout security checks in Phase 10).

**Why this is Priority 1:** The OPAQUE handlers involve complex multi-step state (session storage between the init/response/finalize steps), user creation logic, TOTP gating, JWT issuance, and security-critical token revocation. A unit test that mocks the OPAQUE library (the `TestOPAQUEProvider` in `auth_test_helpers.go` is already there but never used) and mocks the DB can validate all the handler logic paths without requiring CGO. The test infrastructure (mocked OPAQUE provider, `setupTestEnv`) is already built - the tests just don't exist yet.

### PRIORITY 2 - crypto/ package: GCM, Share KDF, and Key Derivation (partial gaps)

The existing `file_operations_test.go` tests `EncryptFEK`/`DecryptFEK` and `EncryptFile`/`DecryptFile`, but these call into `gcm.go` indirectly. Direct unit tests for the core crypto primitives are missing:

**`gcm.go` - not directly tested:**
- `EncryptGCM` / `DecryptGCM` round-trip
- `EncryptGCMWithAAD` / `DecryptGCMWithAAD` round-trip + AAD binding enforcement (wrong AAD must fail - this is the share envelope security model)
- Error paths: wrong key size, truncated ciphertext, tampered ciphertext

**`share_kdf.go` - completely untested:**
- `GenerateShareSalt` - produces random 32-byte base64 salt
- `DeriveShareKey` - Argon2id derivation from password + salt (consistency, wrong-password rejection, salt-length validation)
- `HashDownloadToken` / `VerifyDownloadToken` - SHA-256 hashing and verification
- `CreateShareEnvelope` / `ParseShareEnvelope` - JSON round-trip, missing-field validation
- `CreateAAD` - binds share_id + file_id (critical: wrong AAD must cause decryption failure)
- The full **share envelope encrypt-decrypt cycle** with AAD binding: `DeriveShareKey` → `EncryptGCMWithAAD` (with `CreateAAD`) → `DecryptGCMWithAAD` - this is the core of the share security model and has no unit test

**`key_derivation.go` - partially tested (via file_operations_test):**
- `DeriveArgon2IDKey` - direct tests for error paths (empty password, too-long password, empty salt, zero keyLen) are missing
- `GenerateUserKeySalt` - determinism test for both "account" and "custom" contexts, and that account-salt != custom-salt for the same user

**Why this is Priority 2:** The share envelope AAD binding is the cryptographic mechanism that prevents a share envelope from being reused across different share IDs or file IDs. If `DecryptGCMWithAAD` silently ignores AAD mismatches (it doesn't per the code, but there's no test proving it), the entire sharing security model is broken.

### PRIORITY 3 - handlers/downloads.go and handlers/export.go (zero test coverage)

- `DownloadFileChunk` - streams encrypted file chunks to the client. Must enforce ownership, handle missing files, handle storage errors. The e2e test (Phase 8.5) proves this works end-to-end, but there are no unit tests.
- `ExportFile` / `streamExportBundle` - the `.arkbackup` export flow (Phase 8.7-8.10). No unit tests.
- `GetFileEnvelope` - returns the encrypted FEK envelope to the owner. No unit tests. This is security-critical: it must enforce file ownership.
- `ListFiles` - the primary file listing handler. The comment in `files_test.go` itself flags this as untested and lists the scenarios (no files, with files, storage calculations, DB errors).

### PRIORITY 4 - handlers/auth.go: Logout and token revocation (handler level)

The `auth/token_revocation_test.go` tests the `auth.RevokeToken` library function well. But there are no tests for the `handlers.Logout` handler itself, which must:
- Extract the JWT from the request
- Call `auth.RevokeToken(db, tokenString, reason)`
- Clear the refresh token cookie
- Return appropriate response

The e2e test (Phase 10.23) proves logout works, but a unit test verifying the HTTP response, cookie clearing, and that the token ends up revoked (via mock DB expectation) is missing.

### PRIORITY 5 - File Shares: expiry, max_accesses, and share download token verification

The existing `file_shares_test.go` covers creation and access at the handler level but is missing:
- `TestGetShareEnvelope_Expired` - share with `expires_at` in the past should return 410 Gone or 403
- `TestGetShareEnvelope_MaxAccessesExceeded` - share with `max_accesses` already exhausted (currently the `max_accesses` column and enforcement logic in the handler needs a test)
- `TestDownloadShareChunk` - the `DownloadShareChunk` handler has no tests (requires valid download token)
- `TestGetShareDownloadMetadata` - no tests

### PRIORITY 6 - client-side key caching agent (cmd/arkfile-client)

The Go CLI client (`cmd/arkfile-client/commands.go`) has the `--cache-key` flag on login and the agent for storing the derived account key in memory. This is the client-side KDF flow mentioned in AGENTS.md (password → Argon2id → account KEK, cached in agent). There are **no unit tests** anywhere for:
- `DeriveAccountPasswordKey` call in the client login flow
- Agent key storage / retrieval (the in-memory key cache)
- The `decrypt-blob` command (used in e2e Phase 8.9)

However, these CLI commands are harder to unit test without CGO since they call OPAQUE. The most practical approach here is to focus on the crypto layer functions they depend on (covered in Priority 2) and accept that the CLI integration is tested by the e2e tests.

---

## Issues Found in Existing Tests

1. **`token_revocation_test.go`** uses HS256 (`createTestToken`) with `os.Getenv("JWT_SECRET")` which is not set in the test's `TestMain`. The token parsing in `RevokeToken` uses `jwt.ParseWithClaims` which requires a valid signature. This test likely fails silently or works only because the parsing is lenient. This should be flagged as a potential broken test.

2. **`opaque_test_helpers.go`** contains several functions marked `DEPRECATED` with `t.Skip()` (`setupOPAQUETestUser`, `expectOPAQUEAuthenticationSuccess`, `expectOPAQUEAuthenticationFailure`). These are dead code and should be removed to reduce confusion.

3. **`handlers/handlers_test.go`** is essentially empty (27 lines, only comments). It's a placeholder that adds nothing. Could be removed entirely.

4. **`file_shares_test.go`**: `TestAccessSharedFile_WeakPassword` has a misleading name and comment - it says "handler doesn't actually validate password strength" and expects 200 OK. The mock sequence includes the full share lookup, making it essentially a duplicate of `TestAccessSharedFile_Success` with a different password string. This test does not add meaningful coverage.

5. **`admin_test.go`**: The `DELETE FROM file_shares WHERE owner_username = ?` SQL in the delete user test expects `file_shares` table, but the actual schema uses `file_share_keys`. This is a schema mismatch that indicates this test may be broken or the SQL in the handler doesn't match the schema.

---

## Recommended Order of Work

1. **New file: `handlers/auth_test.go`** - OPAQUE registration handler (2-step mock flow), OPAQUE login handler (2-step mock flow), TOTP setup/verify/auth handlers, Logout handler, RefreshToken handler. Use the existing `TestOPAQUEProvider` from `auth_test_helpers.go`.

2. **New file: `crypto/gcm_test.go`** - EncryptGCM/DecryptGCM round-trip, EncryptGCMWithAAD/DecryptGCMWithAAD with AAD binding enforcement (tampered AAD must fail), wrong-key-size errors, truncated ciphertext.

3. **New file: `crypto/share_kdf_test.go`** - GenerateShareSalt (length, randomness), DeriveShareKey (consistency, wrong-password-produces-different-key, invalid-salt), download token hash/verify, CreateShareEnvelope/ParseShareEnvelope (round-trip, missing-field validation), CreateAAD, and the full end-to-end share encrypt/decrypt cycle with AAD.

4. **New file: `crypto/key_derivation_test.go`** - DeriveArgon2IDKey error paths, GenerateUserKeySalt (determinism, account vs. custom separation).

5. **Extend `handlers/files_test.go`** - Add ListFiles tests (no-files, with-files, storage calculations), GetFileEnvelope (success + ownership enforcement), DownloadFileChunk (success + ownership + storage errors).

6. **Fix `auth/token_revocation_test.go`** - `createTestToken` should use Ed25519 like production, or the test's JWT_SECRET setup needs to match how `RevokeToken` parses tokens.

7. **Clean up `opaque_test_helpers.go`** - Remove the deprecated/skipped functions.

8. **Clean up `handlers/handlers_test.go`** - Remove the empty placeholder file.

9. **Fix schema mismatch in `admin_test.go`** - Verify `file_shares` vs `file_share_keys` table naming matches the actual handler SQL.

---

# FEEDBACK ON THE INITIAL PLAN

...
