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

### Phase 4: Server-Side Refactoring 🔄 IN PROGRESS

**Required Changes:**

1. **New API Endpoints (handlers/auth.go):**
   ```
   POST /api/auth/register/init
   POST /api/auth/register/finalize
   POST /api/auth/login/init
   POST /api/auth/login/finalize
   ```

2. **Refactor C Wrapper (auth/opaque_wrapper.c):**
   - Remove broken functions:
     - arkfile_opaque_register_user (single-step, broken)
     - arkfile_opaque_authenticate_user (single-step, broken)
   - Keep working functions:
     - CreateRegistrationResponse (multi-step)
     - UserAuth (multi-step)
     - RecoverCredentials (multi-step)
   - Ensure proper memory management

3. **Update Go Bindings (auth/opaque_cgo.go):**
   - Remove calls to deleted C functions
   - Add new multi-step function wrappers
   - Update error handling

4. **Database Schema:**
   - Verify opaque_registration_record column exists
   - Ensure proper storage of registration records

### Phase 5: UI Integration 📋 TODO

**Required Changes:**

1. **HTML Pages:**
   - Add libopaque.js script tag to index.html
   - Add libopaque.js script tag to other auth pages
   - Ensure WASM file is accessible

2. **Login Flow (client/static/js/src/auth/login.ts):**
   - Import OpaqueClient from crypto/opaque.ts
   - Replace single-step login with multi-step:
     - Call startLogin() → send to /api/auth/login/init
     - Receive response → call finalizeLogin()
     - Send final message to /api/auth/login/finalize
     - Receive JWT token

3. **Registration Flow:**
   - Import OpaqueClient
   - Replace single-step registration with multi-step:
     - Call startRegistration() → send to /api/auth/register/init
     - Receive response → call finalizeRegistration()
     - Send record to /api/auth/register/finalize

4. **Error Handling:**
   - Handle network errors between steps
   - Handle timeout errors
   - Clear sessionStorage on errors

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
- client/static/js/src/crypto/opaque.ts
- client/static/js/libopaque.js
- client/static/js/libopaque.debug.js
- client/static/js/src/shares/share-creation.ts (stub)
- client/static/js/src/shares/share-crypto.ts (stub)

### Modified
- handlers/middleware.go (removed wasm-unsafe-eval from CSP)
- Caddyfile (removed wasm-unsafe-eval from CSP)
- Caddyfile.local (removed wasm-unsafe-eval from CSP)

### To Be Modified
- handlers/auth.go (new multi-step endpoints)
- auth/opaque_wrapper.c (remove broken functions)
- auth/opaque_cgo.go (update bindings)
- client/static/js/src/auth/login.ts (multi-step flow)
- client/static/index.html (add libopaque.js script)

### Deleted
- client/static/js/src/crypto/opaque-types.ts (Cloudflare-specific)
- client/static/js/src/crypto/opaque-config.ts (Cloudflare-specific)
- All Go WASM build files
- arkfile.wasm binary
- wasm_exec.js

## Progress Summary

**Completed (8/14 major tasks - 57%):**
1. ✅ Analyzed existing OPAQUE implementation
2. ✅ Identified Cloudflare library incompatibility
3. ✅ Found libopaque.js WASM solution
4. ✅ Removed incompatible WASM infrastructure
5. ✅ Installed correct dependencies (@noble/hashes)
6. ✅ Copied libopaque.js WASM files
7. ✅ Created client-side OPAQUE wrapper
8. ✅ Verified TypeScript compilation

**In Progress (1/14 major tasks):**
9. 🔄 Refactoring Go server for multi-step protocol

**Remaining (5/14 major tasks):**
10. 📋 Create new API endpoints
11. 📋 Update C wrapper (remove broken functions)
12. 📋 Update UI integration (login/register)
13. 📋 Add libopaque.js to HTML pages
14. 📋 Testing & validation

**Current Focus:** Phase 4 - Server-side refactoring to support multi-step OPAQUE protocol

## Next Steps

1. Create new multi-step endpoints in handlers/auth.go
2. Refactor auth/opaque_wrapper.c to remove broken single-step functions
3. Update auth/opaque_cgo.go bindings
4. Test server-side changes with dev-reset.sh
5. Update client-side login.ts for multi-step flow
6. Add libopaque.js script tags to HTML
7. End-to-end testing

## References

- libopaque: https://github.com/stef/libopaque
- libopaque.js demo: https://github.com/stef/libopaque/tree/master/js
- OPAQUE RFC: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque
- Project docs: docs/AGENTS.md, docs/security.md
