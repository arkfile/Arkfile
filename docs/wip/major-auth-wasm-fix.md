# Major Authentication and WASM Refactor Plan

## Overview

This document outlines the comprehensive refactor to fix fundamental security issues in the Arkfile authentication system and remove WASM complexity. The current implementation violates zero-knowledge principles by sending plaintext passwords to the server. This refactor will establish proper zero-knowledge authentication using TypeScript OPAQUE in the browser and fix the CLI implementation.

## Critical Security Issue

The current implementation in `auth/opaque_wrapper.c` function `arkfile_opaque_authenticate_user` runs the entire OPAQUE protocol server-side, including client operations. This means:
- The server receives plaintext passwords
- Zero-knowledge property is completely violated
- Security is equivalent to basic password hashing
- Server compromise exposes all passwords

This must be fixed immediately.

## Goals

1. Remove Go WASM entirely from the project
2. Implement proper TypeScript OPAQUE in browser using `@cloudflare/opaque-ts`
3. Fix Go CLI OPAQUE to use proper client-server message exchange
4. Maintain server-side Go + libopaque implementation
5. Achieve actual zero-knowledge authentication
6. Establish stable TypeScript crypto patterns for future features

## Coding Standards

- Use Bun exclusively (no npm/pnpm/yarn)
- Zero emojis in all code and documentation
- Clear, technical language
- Comprehensive error handling
- Security-first approach

## Implementation Phases

### Phase 1: Remove WASM Infrastructure

#### Files to Delete
- `crypto/wasm_shim.go`
- `client/static/js/src/types/wasm.d.ts`
- `client/static/js/src/utils/wasm.ts`
- `client/static/js/src/auth/register.ts` (will be rewritten)
- `scripts/testing/test-wasm.sh`
- Any WASM build artifacts

#### Files to Modify
- `client/static/js/package.json` - Remove WASM-related dependencies
- `tsconfig.json` - Remove WASM-related compiler options
- `scripts/setup/build.sh` - Remove WASM build steps
- `.gitignore` - Remove WASM artifact patterns
- `client/static/index.html` - Remove WASM loading code

#### Build System Changes
- Remove TinyGo installation requirements
- Remove WASM compilation steps from build scripts
- Simplify TypeScript build to pure browser JavaScript
- Update deployment scripts to exclude WASM artifacts

### Phase 2: Implement TypeScript OPAQUE in Browser

#### Install Dependencies
```bash
cd client/static/js
bun add @cloudflare/opaque-ts
```

#### Create New TypeScript Modules

**File: `client/static/js/src/auth/opaque-client.ts`**
- Wrapper around `@cloudflare/opaque-ts`
- Registration flow (client-side only)
- Authentication flow (client-side only)
- Export key derivation
- Error handling

**File: `client/static/js/src/auth/opaque-types.ts`**
- TypeScript interfaces for OPAQUE messages
- Registration request/response types
- Authentication request/response types
- Server configuration types

**File: `client/static/js/src/auth/register.ts`** (rewrite)
- User registration UI logic
- Call OPAQUE client for registration request
- Send request to server
- Process server response
- Finalize registration locally
- Derive encryption keys from export key

**File: `client/static/js/src/auth/login.ts`** (major refactor)
- User login UI logic
- Call OPAQUE client for credential request
- Send request to server
- Process server response
- Recover credentials locally
- Derive session keys from export key
- Handle TOTP flow

#### API Endpoints (Server-Side)

**Registration Flow:**
1. `POST /auth/register/init` - Client sends registration request
2. Server responds with registration response
3. Client finalizes locally, sends final record
4. `POST /auth/register/finalize` - Server stores user record

**Authentication Flow:**
1. `POST /auth/login/init` - Client sends credential request
2. Server responds with credential response
3. Client recovers credentials locally
4. `POST /auth/login/finalize` - Client sends authentication proof
5. Server validates and issues JWT

### Phase 3: Fix Go CLI OPAQUE Implementation

#### Current Problem
The CLI currently sends passwords to the server in `cmd/arkfile-client/main.go`. This must be changed to proper client-server message exchange.

#### New CLI Flow

**File: `auth/opaque_client.go`** (new)
- Client-side OPAQUE operations using libopaque
- Registration request creation
- Registration finalization
- Credential request creation
- Credential recovery
- Proper separation from server operations

**File: `auth/opaque_wrapper.c`** (major refactor)
- Remove `arkfile_opaque_authenticate_user` (broken function)
- Remove `arkfile_opaque_register_user` (broken function)
- Keep only proper client and server operation functions
- Add clear comments about client vs server operations

**File: `cmd/arkfile-client/main.go`** (refactor)
- Registration: Create request locally, send to server, finalize locally
- Authentication: Create request locally, send to server, recover locally
- Never send plaintext password to server
- Proper error handling for network failures

#### CLI API Client

**File: `client/api_client.go`** (new or refactor existing)
- HTTP client for API calls
- Registration endpoints
- Authentication endpoints
- Proper request/response handling
- TLS verification

### Phase 4: Server-Side Implementation

#### Keep Existing
- `auth/opaque.go` - High-level interface (modify for new flow)
- `auth/opaque_cgo.go` - CGO bindings (modify for server-only ops)
- Server key management
- Database operations

#### Modify for New Flow

**File: `handlers/auth.go`**

New handlers:
- `POST /auth/register/init` - Process registration request, return response
- `POST /auth/register/finalize` - Store user record
- `POST /auth/login/init` - Process credential request, return response
- `POST /auth/login/finalize` - Validate authentication, issue JWT

Replace existing:
- Old single-step registration endpoint
- Old single-step login endpoint

**File: `auth/opaque.go`**

New functions:
- `CreateRegistrationResponse(request []byte) (response []byte, error)`
- `StoreUserRecord(username string, record []byte) error`
- `CreateCredentialResponse(username string, request []byte) (response []byte, error)`
- `ValidateAuthentication(username string, proof []byte) (bool, error)`

### Phase 5: Testing Strategy

#### Unit Tests

**Browser OPAQUE Tests:**
- Test registration flow with mock server responses
- Test authentication flow with mock server responses
- Test error handling
- Test key derivation

**CLI OPAQUE Tests:**
- Test registration request creation
- Test credential request creation
- Test response processing
- Test error handling

**Server OPAQUE Tests:**
- Test registration response creation
- Test credential response creation
- Test authentication validation
- Test database operations

#### Integration Tests

**End-to-End Registration:**
1. Browser creates registration request
2. Server processes and responds
3. Browser finalizes and sends record
4. Server stores record
5. Verify user can authenticate

**End-to-End Authentication:**
1. Browser creates credential request
2. Server processes and responds
3. Browser recovers credentials
4. Browser sends authentication proof
5. Server validates and issues JWT
6. Verify JWT works for API calls

**CLI Integration:**
1. CLI creates registration request
2. Server processes and responds
3. CLI finalizes and sends record
4. Server stores record
5. CLI authenticates successfully
6. Verify CLI can perform file operations

#### Security Tests

**Zero-Knowledge Verification:**
- Capture all network traffic during registration
- Verify password never appears in plaintext
- Capture all network traffic during authentication
- Verify password never appears in plaintext
- Test with compromised server (mock)
- Verify server cannot derive password from stored data

**Cryptographic Validation:**
- Verify export keys are deterministic (same password = same key)
- Verify session keys are random (different each time)
- Verify authentication fails with wrong password
- Verify authentication fails with tampered messages

### Phase 6: Deployment Strategy

#### Database Changes
No schema changes required - OPAQUE user records use the same database structure.

#### Deployment Steps
1. Deploy new server code
2. Deploy new browser client
3. Deploy new CLI binary
4. Test end-to-end flows
5. Monitor for errors

### Phase 7: Documentation Updates

#### Files to Update
- `docs/setup.md` - Remove WASM setup steps
- `docs/api.md` - Document new API endpoints
- `docs/security.md` - Explain zero-knowledge properties
- `README.md` - Update architecture description

#### New Documentation
- `docs/opaque-protocol.md` - Explain OPAQUE implementation
- `docs/migration-guide.md` - Guide for existing users
- `docs/testing-guide.md` - How to verify security properties

## File Modification Checklist

### Files to Delete
- [ ] `crypto/wasm_shim.go`
- [ ] `client/static/js/src/types/wasm.d.ts`
- [ ] `client/static/js/src/utils/wasm.ts`
- [ ] `client/static/js/src/auth/register.ts` (will recreate)
- [ ] `scripts/testing/test-wasm.sh`

### Files to Create
- [ ] `client/static/js/src/auth/opaque-client.ts`
- [ ] `client/static/js/src/auth/opaque-types.ts`
- [ ] `auth/opaque_client.go`
- [ ] `client/api_client.go`
- [ ] `docs/opaque-protocol.md`
- [ ] `docs/migration-guide.md`

### Files to Modify
- [ ] `client/static/js/package.json`
- [ ] `tsconfig.json`
- [ ] `scripts/setup/build.sh`
- [ ] `.gitignore`
- [ ] `client/static/index.html`
- [ ] `client/static/js/src/auth/login.ts`
- [ ] `auth/opaque_wrapper.c`
- [ ] `auth/opaque_wrapper.h`
- [ ] `auth/opaque.go`
- [ ] `auth/opaque_cgo.go`
- [ ] `handlers/auth.go`
- [ ] `cmd/arkfile-client/main.go`
- [ ] `docs/setup.md`
- [ ] `docs/api.md`
- [ ] `docs/security.md`
- [ ] `README.md`

## Implementation Order

1. Phase 1: Remove WASM (cleanup)
2. Phase 2: Implement TypeScript OPAQUE (browser)
3. Phase 4: Update server handlers (server)
4. Phase 3: Fix CLI OPAQUE (CLI)
5. Phase 5: Testing (verification)
6. Phase 6: Migration (deployment)
7. Phase 7: Documentation (finalization)

## Success Criteria

- [ ] No WASM files remain in project
- [ ] Browser never sends plaintext passwords
- [ ] CLI never sends plaintext passwords
- [ ] Server never receives plaintext passwords
- [ ] All tests pass
- [ ] Zero-knowledge property verified
- [ ] Documentation complete
- [ ] Migration path clear

## Risks and Mitigations

**Risk:** Cryptographic implementation errors
**Mitigation:** Use battle-tested libraries, comprehensive testing

**Risk:** Performance degradation
**Mitigation:** Benchmark before/after, optimize if needed

**Risk:** Integration complexity
**Mitigation:** Clear documentation, phased implementation

## Changelog Format

After modifying each file, append to this document:

### Implementation Log

- `filename` - description of changes

(This section will be populated during implementation)
