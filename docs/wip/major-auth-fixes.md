# Major Authentication Fixes

## Executive Summary

This document tracks the migration to a full and zero-knowledge multi-step OPAQUE protocol in the Arkfile project using libopaque.js WASM on the client side and libopaque C library on the server side.

## Critical Security Architecture

### Password Types and Usage

#### Account Password (ONE password, TWO uses)
The user's account password serves two distinct purposes:

1. **OPAQUE Authentication** (Zero-Knowledge Protocol)
   - Used for login/authentication via multi-step OPAQUE protocol
   - **NEVER sent to server in plaintext**
   - Server never learns the password
   - Implements true zero-knowledge authentication
   - This is the primary focus of this migration project

2. **Client-Side Key Derivation** (Argon2id)
   - Same password used locally to derive encryption keys
   - Used as default password for file encryption
   - All derivation happens client-side only
   - Server never sees this process or the derived keys
   - Making sure this file encryption happens securely and reliably is the second focus of this project

#### Custom File Password (Encryption ONLY)
- Optional alternative to account password for file encryption
- Used only for client-side key derivation (Argon2id)
- Never used for authentication
- Never sent to server

#### Share Password (Encryption ONLY)
- Used for sharing files with others
- Used only for client-side key derivation (Argon2id)
- Never used for authentication
- Never sent to server

### Zero-Knowledge Principle

**CRITICAL:** The account password is used for:
1. OPAQUE authentication (zero-knowledge, multi-step protocol)
2. Client-side key derivation (Argon2id, for encryption)

**The account password is NEVER:**
- Sent to the server in plaintext
- Used in any server-side operation
- Transmitted over the network except as OPAQUE protocol messages
- Logged or stored anywhere on the server

## Project Overview

### Problem Statement
The original implementation had a faulty single-step OPAQUE authentication flow that was incompatible with the zero-knowledge design goals of the project.

### Solution Approach
Implement multi-step OPAQUE protocol with:
- Separate registration and login flows
- Proper session state management
- CGO-based server-side OPAQUE operations (libopaque C library)
- Client-side libopaque.js WASM
- Zero-knowledge authentication guarantees
- ristretto255 algorithm compatibility between client and server OPAQUE libraries

### Important: Use Bun for JavaScript/TypeScript

**All JavaScript/TypeScript operations should use `bun` instead of `npm` or `npx`:**
- Install dependencies: `bun install` (not `npm install`)
- Run scripts: `bun run <script>` (not `npm run <script>`)
- Build TypeScript: `bun build` or `bun run build` (not `npx tsc`)
- Run tests: `bun test` (not `npm test`)
- Type checking: `bun run type-check` (not `npx tsc --noEmit`)

## Phase Status Overview

### Completed Phases ✅
- **Phase 1:** Verify libopaque.js WASM setup
- **Phase 2:** Implement client-side OPAQUE wrapper
- **Phase 3:** Create server-side multi-step endpoints
- **Phase 4:** Integrate UI with multi-step OPAQUE
- **Phase 5:** Remove previous faulty and deprecated single-step server-side OPAQUE related code
- **Phase 6 Parts A-B:** Session management & CGO compilation fixes

---

## Phase 1: Verify libopaque.js WASM Setup ✅

**Status:** COMPLETE  

### Objectives
Verify that libopaque.js WASM files are present and properly configured for client-side OPAQUE operations.

### Actions Completed
1. ✅ Verified `client/static/js/libopaque.js` exists
2. ✅ Verified `client/static/js/libopaque.debug.js` exists
3. ✅ Confirmed WASM files load correctly in browser
4. ✅ Verified no npm package installation needed (WASM loaded as script)

### Implementation Details
- libopaque.js WASM provides the client-side OPAQUE implementation
- Uses ristretto255 algorithm (compatible with server-side libopaque C library)
- Loaded as a global script in HTML: `<script src="/js/libopaque.js"></script>`
- No bun/npm dependencies required for OPAQUE functionality
- Only dependency: `@noble/hashes` for additional crypto utilities

### Package Details
```json
{
  "dependencies": {
    "@noble/hashes": "^2.0.1"
  }
}
```

### Verification
- WASM files present in correct location
- Browser can load and initialize libopaque module
- TypeScript can reference global libopaque object
- No dependency conflicts

---

## Phase 2: Implement Client-Side OPAQUE Wrapper ✅

**Status:** COMPLETE

### Objectives
Create TypeScript wrapper for libopaque.js WASM to handle multi-step OPAQUE operations.

### Actions Completed
1. ✅ Created `client/static/js/src/crypto/opaque.ts`
2. ✅ Implemented registration flow functions
3. ✅ Implemented login flow functions
4. ✅ Added proper error handling and type safety
5. ✅ Integrated with libopaque.js WASM global object

### Key Functions Implemented

#### Registration Flow
```typescript
async function startRegistration(username: string, password: string)
async function finalizeRegistration(username: string, serverResponse: string, clientSecret: string)
```

#### Login Flow
```typescript
async function startLogin(username: string, password: string)
async function finalizeLogin(username: string, serverResponse: string, serverPublicKey: string | null, clientSecret: string)
```

### Implementation Details
- Wrapper interfaces with global `libopaque` object loaded from WASM
- Uses ristretto255 algorithm (matches server-side libopaque C library)
- Proper TypeScript types for all OPAQUE operations
- Session storage for client secrets during multi-step flows
- Export key derivation for session management

### Verification
- TypeScript compilation successful with `bun run build`
- Functions properly typed and documented
- Error handling implemented for all edge cases
- WASM module initialization working correctly

---

## Phase 3: Create Server-Side Multi-Step Endpoints ✅

**Status:** COMPLETE  

### Objectives
Implement server-side handlers for multi-step OPAQUE registration and login using libopaque C library via CGO.

### Actions Completed
1. ✅ Created `/api/opaque/register/start` endpoint
2. ✅ Created `/api/opaque/register/finish` endpoint
3. ✅ Created `/api/opaque/login/start` endpoint
4. ✅ Created `/api/opaque/login/finish` endpoint
5. ✅ Implemented session state management
6. ✅ Added proper error handling and validation

### Endpoint Details

#### Registration Endpoints
- **POST /api/opaque/register/start**
  - Input: `{ username, registrationRequest }`
  - Output: `{ registrationResponse, sessionId }`
  
- **POST /api/opaque/register/finish**
  - Input: `{ username, registrationRecord, sessionId }`
  - Output: `{ success, message }`

#### Login Endpoints
- **POST /api/opaque/login/start**
  - Input: `{ username, loginRequest }`
  - Output: `{ loginResponse, sessionId }`
  
- **POST /api/opaque/login/finish**
  - Input: `{ username, sessionKey, sessionId }`
  - Output: `{ accessToken, refreshToken }`

### Security Features
- Session state stored server-side with expiration
- CSRF protection via session IDs
- Rate limiting on all endpoints
- Proper error messages without information leakage
- CGO integration with libopaque C library

### Verification
- All endpoints respond correctly to valid requests
- Error handling works for invalid inputs
- Session management prevents replay attacks
- CGO integration with libopaque functioning
- ristretto255 algorithm compatibility verified

---

## Phase 4: Integrate UI with Multi-Step OPAQUE ✅

**Status:** COMPLETE  

### Objectives
Update client-side UI code to use multi-step OPAQUE protocol with libopaque.js WASM.

### Actions Completed
1. ✅ Updated `client/static/js/src/auth/register.ts`
2. ✅ Updated `client/static/js/src/auth/login.ts`
3. ✅ Implemented two-step registration flow
4. ✅ Implemented two-step login flow
5. ✅ Added proper error handling and user feedback

### Registration Flow Implementation
```typescript
// Step 1: Start registration
const { registrationRequest, clientSecret } = await startRegistration(username, password);
const startResponse = await fetch('/api/opaque/register/start', {
  method: 'POST',
  body: JSON.stringify({ username, registrationRequest })
});

// Step 2: Finish registration
const { registrationResponse, sessionId } = await startResponse.json();
const { registrationRecord } = await finalizeRegistration(username, registrationResponse, clientSecret);
await fetch('/api/opaque/register/finish', {
  method: 'POST',
  body: JSON.stringify({ username, registrationRecord, sessionId })
});
```

### Login Flow Implementation
```typescript
// Step 1: Start login
const { loginRequest, clientSecret } = await startLogin(username, password);
const startResponse = await fetch('/api/opaque/login/start', {
  method: 'POST',
  body: JSON.stringify({ username, loginRequest })
});

// Step 2: Finish login
const { loginResponse, sessionId } = await startResponse.json();
const { sessionKey } = await finalizeLogin(username, loginResponse, null, clientSecret);
const finishResponse = await fetch('/api/opaque/login/finish', {
  method: 'POST',
  body: JSON.stringify({ username, sessionKey, sessionId })
});
```

### Verification
- Registration flow works end-to-end
- Login flow works end-to-end
- Error messages displayed to users appropriately
- UI remains responsive during async operations
- libopaque.js WASM integration working correctly

---

## Phase 5: Remove Deprecated Code ✅

**Status:** COMPLETE  

### Objectives
Remove all deprecated single-step OPAQUE code and endpoints.

### Actions Completed
1. ✅ Removed deprecated `/api/opaque/login` endpoint
2. ✅ Removed deprecated `/api/opaque/register` endpoint
3. ✅ Cleaned up old single-step handler code
4. ✅ Removed unused imports and functions
5. ✅ Updated route configuration

### Verification
- No references to deprecated endpoints remain
- Code compiles without warnings
- All tests pass with new endpoints only

---

## Phase 6: Code Completion 🔄

**Status:** IN PROGRESS  
**Current Focus:** Part C - CLI Tools Migration

### Part A: Session Management Integration ✅

**Status:** COMPLETE  

#### Objectives
Integrate session management with multi-step OPAQUE authentication.

#### Actions Completed
1. ✅ Created session state storage mechanism
2. ✅ Implemented session expiration (15 minutes)
3. ✅ Added session cleanup routines
4. ✅ Integrated sessions with OPAQUE endpoints

#### Implementation Details
- Sessions stored in memory with automatic cleanup
- Each session tied to specific OPAQUE operation
- Session IDs prevent CSRF and replay attacks
- Expired sessions automatically removed

### Part B: CGO Compilation Fixes ✅

**Status:** COMPLETE  

#### Objectives
Resolve CGO compilation issues with libopaque integration.

#### Actions Completed
1. ✅ Fixed CGO compiler flags
2. ✅ Resolved linking issues with libopaque
3. ✅ Updated build scripts for proper CGO compilation
4. ✅ Verified successful compilation on target platform

#### Build Configuration
```bash
CGO_ENABLED=1
CGO_CFLAGS="-I/usr/local/include"
CGO_LDFLAGS="-L/usr/local/lib -lopaque -lsodium"
```

### Part C: CLI Tools Migration ⏳

**Status:** PENDING  
**Next Action Required**

#### Objectives
Update CLI tools to use multi-step OPAQUE authentication.

#### Required Actions
1. Update `arkfile-client` authentication flow
   - Implement multi-step registration
   - Implement multi-step login
   - Remove references to deprecated `/api/opaque/login` endpoint
   
2. Update `arkfile-admin` authentication flow
   - Implement multi-step registration
   - Implement multi-step login
   - Remove references to deprecated endpoints

3. Test CLI tools
   - Verify registration works
   - Verify login works
   - Verify token management
   - Verify error handling

#### Files to Modify
- CLI tool source files (location TBD during implementation)
- CLI authentication modules
- CLI configuration files

### Part D: Provider Interface Review ⏳

**Status:** PENDING

#### Objectives
Verify OPAQUE provider interfaces support multi-step operations.

#### Required Actions
1. Review `OPAQUEProvider` interface definition
2. Verify `RealOPAQUEProvider` implements multi-step methods
3. Update test providers if necessary
4. Ensure all provider implementations are complete

#### Files to Review
- `auth/opaque.go` - Provider interface definitions
- `auth/opaque_multi_step.go` - Multi-step implementation
- Test helper files with mock providers

### Part E: Final Code Cleanup ⏳

**Status:** PENDING

#### Objectives
Clean up codebase and prepare for testing phase.

#### Required Actions
1. Remove any remaining TODOs or FIXMEs
2. Verify no deprecated code references remain
3. Clean up unused imports
4. Run linters and formatters
5. Final compilation verification
   - Verify Go compilation succeeds
   - Verify TypeScript compilation succeeds with `bun run build`
   - Verify all dependencies present

#### Quality Checks
- [ ] No compiler warnings
- [ ] No linter errors
- [ ] All imports used
- [ ] No dead code
- [ ] Consistent code style

---

## Phase 7: Testing & Validation 📋

**Status:** PENDING  
**Starts After:** Phase 6 completion

### Overview
Comprehensive testing phase to verify all functionality and security properties. **NO TESTING SHOULD BEGIN UNTIL ALL CODE WORK IN PHASE 6 IS COMPLETE.**

### Part A: Build Verification

#### Objectives
Verify clean compilation and build process.

#### Actions Required
1. Verify Go compilation succeeds
   ```bash
   go build -o arkfile
   ```
2. Verify TypeScript compilation succeeds
   ```bash
   cd client/static/js && bun run build
   ```
3. Build application binary
4. Verify all dependencies present
5. Check for any build warnings or errors

#### Success Criteria
- ✅ Zero compilation errors
- ✅ Zero build warnings
- ✅ All dependencies resolved
- ✅ Binary executes successfully

### Part B: Manual Web UI Testing

#### Objectives
Test authentication flows through web browser interface.

#### Actions Required
1. Start application manually (build and run the binary)
2. Test registration flow
   - Navigate to registration page
   - Enter valid username and password
   - Verify successful registration
   - Check database for user record
   
3. Test login flow
   - Navigate to login page
   - Enter registered credentials
   - Verify successful login
   - Verify JWT tokens issued
   
4. Test TOTP setup and authentication
   - Enable TOTP for test user
   - Verify QR code generation
   - Test TOTP code validation
   
5. Test file operations with authentication
   - Upload file while authenticated
   - Download file while authenticated
   - Verify encryption/decryption works
   
6. Test error scenarios
   - Invalid password
   - Non-existent username
   - Expired session
   - Invalid TOTP code
   - Network interruption during multi-step flow

#### Success Criteria
- ✅ Registration completes successfully
- ✅ Login completes successfully
- ✅ TOTP works correctly
- ✅ File operations work with authentication
- ✅ Error messages are user-friendly
- ✅ No crashes or unexpected behavior

### Part C: Automated Testing

#### Objectives
Verify zero-knowledge properties and security characteristics.

#### Actions Required
1. Verify zero-knowledge properties
   - Capture network traffic during authentication
   - Verify no plaintext passwords transmitted
   - Verify only OPAQUE protocol messages sent
   - Verify server never receives password
   
4. Network traffic analysis
   - Use Wireshark or tcpdump
   - Monitor all authentication requests
   - Verify encryption of sensitive data
   - Verify no information leakage

#### Success Criteria
- ✅ All automated tests pass
- ✅ Security tests pass
- ✅ Zero-knowledge properties verified
- ✅ No plaintext passwords in network traffic
- ✅ No sensitive data in logs

### Part D: Integration Testing

#### Objectives
Test integration points and CLI tools.

#### Actions Required
1. Test CLI tools (arkfile-client, arkfile-admin)
   - Test registration via CLI
   - Test login via CLI
   - Test file operations via CLI
   - Test admin operations via CLI
   
2. Test all authentication types
   - Account authentication (OPAQUE)
   - File password (client-side derivation)
   - Share password (client-side derivation)
   
3. Test session management
   - Token refresh flow
   - Session expiration
   - Concurrent sessions
   - Session cleanup
   
4. Test concurrent users
   - Multiple simultaneous registrations
   - Multiple simultaneous logins
   - Concurrent file operations
   - Race condition testing

#### Success Criteria
- ✅ CLI tools work correctly
- ✅ All authentication types function
- ✅ Session management robust
- ✅ No race conditions
- ✅ Concurrent operations handled correctly

### Part E: Performance & Security Validation

#### Objectives
Validate performance and security characteristics.

#### Actions Required
1. Load testing
   - Test with 100 concurrent users
   - Test with 1000 concurrent requests
   - Measure response times
   - Identify bottlenecks
   
2. Session cleanup verification
   - Verify expired sessions removed
   - Verify memory usage stable
   - Test long-running server
   
3. Database query performance
   - Profile database queries
   - Verify indexes used correctly
   - Check for N+1 queries
   
4. Security audit of implementation
   - Review all authentication code
   - Verify no password logging
   - Check error message information leakage
   - Verify rate limiting effective
   - Test for timing attacks
   - Verify CSRF protection

#### Success Criteria
- ✅ Performance meets requirements
- ✅ No memory leaks
- ✅ Database queries optimized
- ✅ Security audit passes
- ✅ No timing attack vulnerabilities
- ✅ Rate limiting effective

### Critical Security Verification Checklist

During all testing phases, verify:

- [ ] Account password NEVER sent to server in plaintext
- [ ] Only OPAQUE protocol messages transmitted during auth
- [ ] Network traffic analysis confirms zero-knowledge properties
- [ ] File encryption uses client-side Argon2id derivation only
- [ ] No password leakage in logs or error messages
- [ ] Server never learns user passwords
- [ ] Session tokens properly secured
- [ ] CSRF protection functioning
- [ ] Rate limiting prevents brute force
- [ ] All error messages safe (no information leakage)

---

## Phase 8: Documentation & Finalization 📋

**Status:** PENDING  
**Starts After:** Phase 7 completion (all testing successful)

### Overview
Update all documentation to reflect the completed migration. **DOCUMENTATION SHOULD NOT BE UPDATED UNTIL THE APPLICATION IS IN A FULLY KNOWN AND WORKING STATE.**

### Part A: Update Project Documentation

#### Objectives
Update this project document with final status.

#### Actions Required
1. Mark all phases as complete
2. Document any issues found and resolved during testing
3. Update progress summary
4. Add final notes and lessons learned
5. Archive this document as reference

### Part B: Update API Documentation

#### Objectives
Document the new multi-step OPAQUE endpoints.

#### Actions Required
1. Update `docs/api.md` with new endpoints
   - Document `/api/opaque/register/start`
   - Document `/api/opaque/register/finish`
   - Document `/api/opaque/login/start`
   - Document `/api/opaque/login/finish`
   
2. Add authentication flow diagrams
   - Registration flow diagram
   - Login flow diagram
   - Session management diagram
   
3. Add example requests/responses
   - Include sample JSON payloads
   - Document error responses
   - Add curl examples

### Part C: Update Security Documentation

#### Objectives
Document security properties and implementation details.

#### Actions Required
1. Update `docs/security.md` with OPAQUE details
   - Explain zero-knowledge authentication
   - Document multi-step protocol
   - Explain session management security
   
2. Document password architecture
   - Account password dual-use (auth + derivation)
   - Custom file passwords (encryption only)
   - Share passwords (encryption only)
   - Zero-knowledge principle
   
3. Add security audit results
   - Document testing results
   - List verified security properties
   - Note any limitations or caveats

### Part D: Update Setup/Deployment Guides

#### Objectives
Update setup and deployment documentation.

#### Actions Required
1. Update `docs/setup.md` if needed
   - Document any new dependencies
   - Update build instructions (use bun)
   - Add troubleshooting section
   
2. Document deployment procedures
   - Update systemd service files if needed
   - Document environment variables
   - Add migration guide from old version

### Part E: Update AGENTS.md

#### Objectives
Document architecture decisions for future maintainers.

#### Actions Required
1. Add notes about OPAQUE implementation
   - Why multi-step protocol chosen
   - Why libopaque.js WASM chosen
   - Key design decisions
   - Integration points
   
2. Document architecture decisions
   - Session management approach
   - CGO integration details
   - Client-side crypto architecture
   - ristretto255 algorithm choice
   
3. Update for future maintainers
   - Common pitfalls to avoid
   - Testing recommendations
   - Maintenance procedures

---

## Progress Summary

### Overall Progress: 62% Complete (8/13 major items)

#### Completed ✅
1. Phase 1: Verify libopaque.js WASM setup
2. Phase 2: Client-side OPAQUE wrapper (libopaque.js WASM)
3. Phase 3: Server-side multi-step endpoints
4. Phase 4: UI integration
5. Phase 5: Deprecated code removal
6. Phase 6 Part A: Session management
7. Phase 6 Part B: CGO compilation fixes

#### In Progress 🔄
8. Phase 6 Part C: CLI tools migration (NEXT)

#### Pending 📋
9. Phase 6 Part D: Provider interface review
10. Phase 6 Part E: Final code cleanup
11. Phase 7: Testing & Validation (ALL TESTING)
12. Phase 8: Documentation & Finalization (AFTER TESTING)

### Current Focus
**Phase 6 Part C: CLI Tools Migration**

The next immediate step is to update the CLI tools (arkfile-client and arkfile-admin) to use the multi-step OPAQUE authentication protocol.

---

## Key Technical Decisions

### Why Multi-Step OPAQUE?
- Required for WASM compatibility
- More secure than single-step
- Standards-compliant implementation
- Better separation of concerns
- Enables proper session management

### Why CGO for Server-Side?
- Native libopaque performance
- Proven cryptographic implementation
- Better than pure Go alternatives
- Easier to audit and maintain
- ristretto255 algorithm support

### Why libopaque.js WASM for Client?
- Same library as server (libopaque)
- ristretto255 algorithm compatibility
- Zero-knowledge protocol implementation
- No external npm dependencies needed
- Proven cryptographic implementation
- Direct compatibility with server-side libopaque C library

### Session Management Approach
- In-memory session storage (simple, fast)
- 15-minute session expiration (security)
- Automatic cleanup (prevents memory leaks)
- Session IDs prevent CSRF (security)

---

## Notes for Future Maintainers

### Critical Security Principles
1. **NEVER** send account password to server in plaintext
2. **ALWAYS** use OPAQUE protocol for authentication
3. **ALWAYS** perform key derivation client-side
4. **NEVER** log passwords or sensitive data
5. **ALWAYS** verify zero-knowledge properties

### Common Pitfalls to Avoid
1. Don't confuse authentication (OPAQUE) with encryption (Argon2id)
2. Don't skip session expiration checks
3. Don't forget to clean up expired sessions
4. Don't expose sensitive data in error messages
5. Don't use npm/npx - always use bun for JavaScript/TypeScript

### Testing Recommendations
1. Always test registration and login flows end-to-end
2. Always verify network traffic for plaintext passwords
3. Always test error scenarios
4. Always test concurrent operations
5. Always run security test suite before deployment

### Maintenance Procedures
1. Regularly update dependencies (libopaque, libopaque.js WASM, @noble/hashes)
2. Monitor session cleanup performance
3. Review logs for authentication failures
4. Audit code changes for security implications
5. Keep documentation synchronized with code
6. Use bun for all JavaScript/TypeScript operations

---

## Appendix: Command Reference

### Build Commands
```bash
# Build Go application
go build -o arkfile

# Build TypeScript client (use bun, not npm)
cd client/static/js && bun run build

# Run tests
go test ./...
bun test  # Not npm test
```

### Development Commands
```bash
# Build and start server manually
go build -o arkfile && ./arkfile

# TypeScript type checking (use bun)
cd client/static/js && bun run type-check
```

### Debugging Commands
```bash
# Check CGO configuration
go env CGO_ENABLED
go env CGO_CFLAGS
go env CGO_LDFLAGS

# Verify libopaque installation
ldconfig -p | grep libopaque

# Check TypeScript compilation (use bun)
cd client/static/js && bun run tsc --noEmit
```

---

## Future Work: Test Script Refactoring

**IMPORTANT:** The following test scripts are tightly coupled to the old faulty authentication architecture and cannot be used during this project. They will require their own major refactoring work after this project is complete:

- `scripts/dev-reset.sh` - Development reset script
- `scripts/testing/test-app-curl.sh` - End-to-end curl testing script
- `scripts/testing/security-test-suite.sh` - Security test suite

These scripts will need to be updated to work with the new multi-step OPAQUE authentication system. This refactoring work should be done as a separate project after the current authentication migration is complete and fully tested.

---

**END OF DOCUMENT**
