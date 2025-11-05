# Arkfile OPAQUE Authentication Refactor - Version 2

**Status:** In Progress  
**Started:** November 5, 2025  
**Last Updated:** November 5, 2025

## Overview

This document tracks the refactoring of Arkfile's authentication system to properly implement OPAQUE protocol using libopaque (WASM + C library) for both client and server sides.

## Background

### Previous Issues
- Attempted to use @cloudflare/opaque-ts library
- Discovered incompatibility: Cloudflare uses ristretto255-SHA512, server uses P-256
- Cloudflare library doesn't support P-256 curve
- Server-side C wrapper had broken single-step functions

### Current Solution
- Use libopaque.js (WASM) on client side
- Use libopaque C library on server side (already present)
- Both use same underlying libopaque implementation
- Guaranteed protocol compatibility
- Multi-step protocol (proper OPAQUE flow)

## Architecture

### Dual Key System (Unchanged)

**OPAQUE System (Authentication Only):**
- Purpose: Zero-knowledge password authentication
- Keys: Ephemeral session keys, JWT tokens
- Lifetime: Session-based, temporary
- Server: Never sees plaintext password
- Export key: Used only for session key derivation

**Argon2id System (File Encryption Only):**
- Purpose: Client-side file encryption
- Keys: Deterministic from password + username
- Lifetime: Persistent, deterministic
- Server: Never involved in key derivation
- Enables: Offline decryption, data portability

**Critical Independence:**
- OPAQUE and Argon2id systems are completely independent
- OPAQUE export key is NOT used for file encryption
- File encryption uses separate Argon2id KDF
- This ensures offline decryption capability

### OPAQUE Protocol Flow

**Registration (Multi-Step):**
1. Client: Generate registration request (libopaque.js)
2. Server: Create registration response (libopaque C)
3. Client: Finalize registration, create record (libopaque.js)
4. Server: Store registration record in database

**Authentication (Multi-Step):**
1. Client: Generate credential request (libopaque.js)
2. Server: Create credential response (libopaque C)
3. Client: Finalize authentication, derive session key (libopaque.js)
4. Server: Verify and issue JWT token

**Session Key Derivation:**
- Export key from OPAQUE → SHA-256 hash → Session key
- Used for JWT token generation
- Ephemeral, session-based only

## Implementation Phases

### Phase 1: Remove Incompatible WASM ✅ COMPLETE

**Removed:**
- Go WASM build infrastructure
- arkfile.wasm binary
- wasm_exec.js runtime
- TypeScript WASM utilities
- WASM build steps from scripts
- wasm-unsafe-eval from CSP headers

**Kept:**
- libopaque C library (auth/opaque_wrapper.c)
- libopaque Go bindings (auth/opaque_cgo.go)
- Server-side OPAQUE infrastructure

### Phase 2: Client-Side Dependencies ✅ COMPLETE

**Installed:**
- @noble/hashes (for Argon2id file encryption)
- No @cloudflare/opaque-ts (incompatible, removed)

**Created Infrastructure:**
- client/static/js/src/crypto/constants.ts
- client/static/js/src/crypto/types.ts
- client/static/js/src/crypto/errors.ts
- client/static/js/src/crypto/primitives.ts
- client/static/js/src/crypto/file-encryption.ts (Argon2id-based)

### Phase 3: Client-Side OPAQUE Implementation ✅ COMPLETE

**Copied libopaque.js WASM:**
- client/static/js/libopaque.js (production)
- client/static/js/libopaque.debug.js (development)
- Source: https://github.com/stef/libopaque/tree/master/js

**Created OPAQUE Wrapper:**
- client/static/js/src/crypto/opaque.ts
  - OpaqueClient class
  - Registration flow: startRegistration(), finalizeRegistration()
  - Authentication flow: startLogin(), finalizeLogin()
  - Session key derivation from export key
  - State management via sessionStorage

**Configuration:**
- Curve: ristretto255 (matches server)
- Mode: NotPackaged (client doesn't store keys)
- Compatible with server-side libopaque C library

**Compilation:**
- TypeScript builds successfully (77.32 KB bundle)
- All imports resolved
- No compilation errors

### Phase 4: Server-Side Refactoring ✅ COMPLETE

**Completed Changes:**

1. **New API Endpoints (handlers/auth.go):** ✅
   - Created `OpaqueRegisterResponse` - handles registration init (step 1)
   - Created `OpaqueRegisterFinalize` - handles registration finalize (step 2)
   - Created `OpaqueAuthResponse` - handles authentication init (step 1)
   - Created `OpaqueAuthFinalize` - handles authentication finalize (step 2)
   - All handlers properly integrated with rate limiting

2. **Route Configuration (handlers/route_config.go):** ✅
   - Registered `/api/opaque/register/response` endpoint
   - Registered `/api/opaque/register/finalize` endpoint
   - Registered `/api/opaque/auth/response` endpoint
   - Registered `/api/opaque/auth/finalize` endpoint
   - Added `/api/opaque/health` health check endpoint
   - All routes protected with appropriate rate limiting

3. **New Go Multi-Step Functions (auth/opaque_multi_step.go):** ✅
   - Created `CreateRegistrationResponse` - server-side registration step
   - Created `StoreUserRecord` - finalize and store registration
   - Created `CreateCredentialResponse` - server-side authentication step
   - Created `UserAuth` - validate client authentication token
   - All functions use existing C library wrappers
   - Proper error handling and buffer management

4. **Database Schema (database/unified_schema.sql):** ✅
   - Added `opaque_auth_sessions` table for multi-step protocol state
   - Session ID tracking with UUID
   - Username association
   - Flow type (registration/authentication)
   - Server public key storage
   - Automatic 5-minute expiration via `expires_at` column
   - Proper indexes for performance (username, expires_at)

5. **Removed Deprecated Code:** ✅
   - Deleted all old single-step OPAQUE handler functions
   - Removed old endpoint registrations
   - Cleaned up unused imports
   - Zero references to deprecated functions remain

### Phase 5: UI Integration ✅ COMPLETE

**Completed Changes:**

1. **HTML Pages:** ✅
   - Added libopaque.js script tag to index.html
   - Added libopaque.js script tag to file-share.html
   - Added libopaque.js script tag to chunked-upload.html
   - Script loads before app.js bundle
   - WASM file accessible at /js/libopaque.js

2. **Login Flow (client/static/js/src/auth/login.ts):** ✅
   - Imported OpaqueClient from crypto/opaque.ts
   - Replaced single-step login with multi-step:
     - Step 1: Call startLogin() → POST to `/api/opaque/auth/response`
     - Step 2: Receive response → call finalizeLogin()
     - Step 3: POST to `/api/opaque/auth/finalize` with session_id
     - Step 4: Receive JWT tokens and complete authentication
   - Proper error handling for both steps
   - Session state management via sessionStorage

3. **Registration Flow (client/static/js/src/auth/register.ts):** ✅
   - Created new register.ts module with RegistrationManager class
   - Imported OpaqueClient from crypto/opaque.ts
   - Implemented multi-step registration:
     - Step 1: Call startRegistration() → POST to `/api/opaque/register/response`
     - Step 2: Receive server response with session_id
     - Step 3: Call finalizeRegistration() → POST to `/api/opaque/register/finalize`
     - Step 4: Receive JWT tokens and complete registration
   - Password validation (minimum 14 characters)
   - Password strength indicator
   - Proper error handling for both steps
   - Session state management via sessionStorage

4. **App Integration (client/static/js/src/app.ts):** ✅
   - Imported register module functions
   - Updated setupAppListeners() to call setupRegisterForm()
   - Connected register button to new registration flow
   - Replaced "not yet implemented" error with working registration

5. **Error Handling:** ✅
   - Network errors handled between steps
   - Session expiration handled (sessionStorage cleanup)
   - Clear sessionStorage on errors
   - User-friendly error messages

6. **TypeScript Compilation:** ✅
   - Compiled successfully with bun run build
   - Bundle size: 91.61 KB (17 modules)
   - No compilation errors or warnings
   - All imports resolved correctly

### Phase 6: Testing & Validation 📋 TODO

**Test Cases:**

1. **OPAQUE Protocol:**
   - Registration flow completes successfully
   - Authentication flow completes successfully
   - Invalid password rejected
   - Session keys derived correctly
   - JWT tokens issued properly

2. **Zero-Knowledge Properties:**
   - Network traffic analysis (no plaintext passwords)
   - Server logs contain no password data
   - Database contains only registration records

3. **File Encryption (Argon2id):**
   - Files encrypt/decrypt correctly
   - Offline decryption works (no server needed)
   - Data portability verified
   - Independent from OPAQUE system

4. **Integration:**
   - End-to-end registration → login → file upload → file download
   - TOTP integration still works
   - Session management works
   - Token refresh works

### Phase 7: Go CLI Tools Migration 📋 TODO

**Scope:** Update arkfile-client and arkfile-admin to use new multi-step OPAQUE protocol

**Current Status:**
- Both CLI tools use deprecated single-step endpoint `/api/opaque/login`
- This endpoint no longer exists on the server
- CLI authentication is currently broken

**Required Changes:**

1. **arkfile-client (cmd/arkfile-client/main.go):**
   - Update `performOPAQUEAuthentication()` function
   - Replace single-step login with multi-step flow:
     - Step 1: Generate credential request → POST `/api/opaque/auth/response`
     - Step 2: Finalize with session_id → POST `/api/opaque/auth/finalize`
   - Add CGO bindings for libopaque client operations (similar to auth/opaque_cgo.go)
   - Update session management for multi-step protocol

2. **arkfile-admin (cmd/arkfile-admin/main.go):**
   - Similar updates to admin authentication flow
   - Ensure compatibility with AdminMiddleware (localhost-only)

**Dependencies:**
- Phase 5 must be complete (web UI working)
- Server-side multi-step endpoints must be validated
- libopaque C library integration for Go clients

**Estimated Effort:** 2-3 days
- Day 1: Update arkfile-client authentication
- Day 2: Update arkfile-admin authentication
- Day 3: Testing with dev-reset.sh and test-app-curl.sh

## Security Properties

### OPAQUE (Authentication)
- Zero-knowledge password proof
- Server never sees plaintext password
- Resistant to offline dictionary attacks
- Forward secrecy via ephemeral keys
- Export key used only for session derivation

### Argon2id (File Encryption)
- Memory-hard KDF (256MB memory cost)
- Deterministic key derivation
- Client-side encryption only
- Offline decryption capability
- Data portability guarantee

### Independence
- OPAQUE compromise doesn't expose file encryption keys
- File encryption key compromise doesn't expose OPAQUE credentials
- Complete separation of concerns

## Files Modified

### Created
- docs/wip/major-auth-wasm-fix-v2.md (this document)
- client/static/js/src/crypto/opaque.ts (OPAQUE client wrapper)
- client/static/js/libopaque.js (production WASM)
- client/static/js/libopaque.debug.js (development WASM)
- client/static/js/src/shares/share-creation.ts (stub)
- client/static/js/src/shares/share-crypto.ts (stub)
- auth/opaque_multi_step.go (multi-step Go functions)

### Modified
- handlers/middleware.go (removed wasm-unsafe-eval from CSP)
- Caddyfile (removed wasm-unsafe-eval from CSP)
- Caddyfile.local (removed wasm-unsafe-eval from CSP)
- handlers/auth.go (added multi-step endpoints, removed deprecated single-step)
- handlers/route_config.go (registered new multi-step routes)
- database/unified_schema.sql (added opaque_auth_sessions table)
- client/static/js/src/auth/login.ts (updated to multi-step flow)
- client/static/js/src/crypto/errors.ts (fixed TypeScript compilation)
- client/static/index.html (added libopaque.js script tag)
- client/static/file-share.html (added libopaque.js script tag)
- client/static/chunked-upload.html (added libopaque.js script tag)
- client/static/js/src/app.ts (integrated registration module)


### Deleted
- client/static/js/src/crypto/opaque-types.ts (Cloudflare-specific)
- client/static/js/src/crypto/opaque-config.ts (Cloudflare-specific)
- All Go WASM build files
- arkfile.wasm binary
- wasm_exec.js

## Progress Summary

**Completed (14/14 major tasks - 100%):**
1. ✅ Analyzed existing OPAQUE implementation
2. ✅ Identified Cloudflare library incompatibility
3. ✅ Found libopaque.js WASM solution
4. ✅ Removed incompatible WASM infrastructure
5. ✅ Installed correct dependencies (@noble/hashes)
6. ✅ Copied libopaque.js WASM files
7. ✅ Created client-side OPAQUE wrapper (opaque.ts)
8. ✅ Verified TypeScript compilation
9. ✅ Created Go multi-step functions (opaque_multi_step.go)
10. ✅ Created new API endpoints (handlers/auth.go)
11. ✅ Updated route configuration (route_config.go)
12. ✅ Updated login flow (login.ts)
13. ✅ Added libopaque.js to HTML pages
14. ✅ Created registration flow (register.ts)

**Phase 5 Complete!** All UI integration tasks finished.

**Current Focus:** Phase 6 - Testing & Validation

## Next Steps

1. Add libopaque.js script tags to HTML pages (index.html and other auth pages)
2. Test with dev-reset.sh (rebuild and restart application)
3. Test with test-app-curl.sh (verify end-to-end authentication)
4. Manual testing through web UI (registration and login)
5. Network traffic analysis (verify zero-knowledge properties)
6. Verify offline decryption capability (Argon2id file encryption)
7. Test data portability scenarios

## Recent Session Progress (November 5, 2025)

### Phase 4 Completion
- Removed all deprecated single-step OPAQUE code from handlers/auth.go
- Created complete multi-step handler functions (OpaqueRegisterResponse, OpaqueRegisterFinalize, OpaqueAuthResponse, OpaqueAuthFinalize)
- Updated route_config.go with new multi-step endpoints
- Added opaque_auth_sessions table to database schema
- Created auth/opaque_multi_step.go with Go wrapper functions
- Verified successful Go compilation

### Phase 5 Completion
- Updated client/static/js/src/auth/login.ts to use multi-step OPAQUE flow
- Fixed TypeScript compilation errors in errors.ts (exactOptionalPropertyTypes compatibility)
- Fixed TypeScript compilation errors in opaque.ts (null safety)
- Added libopaque.js script tags to all HTML pages (index.html, file-share.html, chunked-upload.html)
- Created client/static/js/src/auth/register.ts with complete multi-step registration flow
- Updated client/static/js/src/app.ts to integrate registration module
- Verified successful TypeScript compilation (91.61 KB bundle, 17 modules)
- Confirmed zero references to old single-step endpoints remain

### Status
- **Phase 1-5:** Complete (100%)
- **Phase 6:** Not started (testing & validation)
- **Phase 7:** Not started (Go CLI tools migration)
- **Overall Progress:** 100% of Phase 5 complete (14/14 major tasks)

## Infrastructure Improvements

### Argon2id Single Source of Truth (November 5, 2025)

**Problem:** Argon2id parameters for client-side file encryption were hardcoded in multiple locations (TypeScript constants.ts and Go key_derivation.go), creating maintenance issues and risk of parameter drift.

**Solution:** Created `config/argon2id-params.json` as single source of truth:
```json
{
  "memoryCostKiB": 262144,
  "timeCost": 8,
  "parallelism": 4,
  "keyLength": 32,
  "variant": "Argon2id"
}
```

**Implementation:**
- TypeScript: Import JSON file in constants.ts with type declaration
- Go: Load and parse JSON at package initialization with validation
- Both implementations now guaranteed to use identical parameters
- Fail-fast on load errors (panic in Go, compilation error in TypeScript)

**Benefits:**
- Single file to update parameters (eliminates drift)
- Type safety in TypeScript
- Runtime validation in Go
- Clear documentation of cryptographic parameters

**Files Modified:**
- Created: `config/argon2id-params.json`
- Created: `client/static/js/src/types/argon2id-params.d.ts`
- Created: `docs/wip/argon2id-single-source.md` (detailed documentation)
- Modified: `client/static/js/src/crypto/constants.ts` (import from JSON)
- Modified: `crypto/key_derivation.go` (load from JSON)
- Modified: `tsconfig.json` (enable JSON imports, remove rootDir restriction)

**Verification:**
- TypeScript compilation: ✅ Success
- Go compilation: ✅ Success
- Codebase search: ✅ No hardcoded duplicates found

**Security Note:** These parameters are used ONLY for client-side file encryption (Argon2id KDF). They are completely independent from OPAQUE authentication. Never change these parameters without a migration plan, as it would make existing encrypted files unreadable.

## References

- libopaque: https://github.com/stef/libopaque
- libopaque.js demo: https://github.com/stef/libopaque/tree/master/js
- OPAQUE RFC: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque
- Project docs: docs/AGENTS.md, docs/security.md
- Argon2id implementation: docs/wip/argon2id-single-source.md
