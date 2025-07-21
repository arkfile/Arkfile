# Migration Guide: Switching from aldenml/ecc to Stef's libopaque

## Overview

This document outlines the step-by-step process for migrating Arkfile's OPAQUE implementation from the aldenml/ecc library to Stef's libopaque library.

**UPDATE (7/21/2025)**: After comprehensive testing and analysis, Stef's libopaque has been confirmed as the best choice for Arkfile. The library is actively maintained (v3.1.0 - February 2025) and correctly implements the OPAQUE specification.

## Migration Phases

### Phase 1: Core Functionality Testing & Compilation

#### 1.1 Initial Setup & Compilation Test ✅ COMPLETED

**Objective**: Verify libopaque can be compiled and linked with the project.

**Steps Completed**:

1. **Added libopaque as a Git submodule** ✅
   - Location: `vendor/stef/libopaque`
   - Including dependency: `vendor/stef/liboprf`

2. **Built libopaque successfully** ✅
   - Created build script: `/auth/libopaque_test/build_libopaque.sh`
   - Libraries built: `libopaque.so`, `liboprf.so`, `liboprf-noiseXK.so`
   - All dependencies resolved

3. **Created comprehensive test programs** ✅
   - `/auth/libopaque_test/test_basic.c` - Basic API test
   - `/auth/libopaque_test/test_full_protocol.c` - Complete protocol flow
   - `/auth/libopaque_test/test_simple_opaque.c` - All major operations
   - All tests passing successfully

4. **Verified API compatibility** ✅
   - Confirmed libopaque implements current OPAQUE draft-18 spec
   - API is cleaner and more straightforward than aldenml/ecc
   - All required functionality is available

#### 1.2 API Compatibility Assessment ✅ COMPLETED

**Objective**: Map aldenml/ecc API calls to libopaque equivalents.

**Key Function Mappings (Updated based on testing)**:

| Operation | libopaque Function | Status |
|-----------|-------------------|---------|
| Registration Request | `opaque_CreateRegistrationRequest` | ✅ Tested |
| Registration Response | `opaque_CreateRegistrationResponse` | ✅ Tested |
| Registration Finalize | `opaque_FinalizeRequest` | ✅ Tested |
| Store User Record | `opaque_StoreUserRecord` | ✅ Tested |
| Login Request | `opaque_CreateCredentialRequest` | ✅ Tested |
| Login Response | `opaque_CreateCredentialResponse` | ✅ Tested |
| Recover Credentials | `opaque_RecoverCredentials` | ✅ Tested |
| User Authentication | `opaque_UserAuth` | ✅ Tested |
| One-step Registration | `opaque_Register` | ✅ Tested |

**Key Differences from aldenml/ecc**:
- Simpler API with fewer parameters
- Better separation of concerns
- Built-in support for identities via `Opaque_Ids` structure
- No need for separate KE1/KE2/KE3 - handled internally

#### 1.3 Minimal Integration Test ✅ COMPLETED

**Objective**: Verify core OPAQUE flows work with libopaque.

**Tests Completed**:
- ✅ User registration (both full and one-step)
- ✅ User authentication with correct password
- ✅ Password rejection with incorrect password
- ✅ Session key generation and matching
- ✅ Export key generation
- ✅ No memory leaks detected (valgrind tested)
- ✅ No crashes in any test scenarios

**Test Results Summary**:
- All protocol flows working correctly
- Export keys consistent between registration and login
- Proper error handling for invalid passwords
- Performance is excellent

### Phase 2: Full Implementation & Testing

#### 2.1 Complete libopaque Integration

**Files to Update**:
- `/auth/opaque.go` - Main implementation
- `/auth/opaque_cgo.go` - CGo build constraints
- `/auth/opaque_wrapper.c` - C wrapper functions
- `/auth/opaque_wrapper.h` - C header definitions

#### 2.2 Backend Test Suite Updates

**Test Files**:
- `/auth/opaque_test.go`
- `/auth/password_test.go`
- `/handlers/auth_test.go`

**New Tests Required**:
- Interoperability tests
- Edge case handling
- Error conditions
- Memory leak detection

#### 2.3 WASM/Frontend Updates

**Verification Points**:
- Client WASM compatibility
- Browser registration/login flows
- Session key agreement
- Error handling

### Phase 3: Scripts & Documentation

#### 3.1 Setup Script Updates

**Scripts to Modify**:
- `/scripts/setup/03-setup-opaque-keys.sh`
- `/scripts/setup/build.sh`
- `/scripts/quick-start.sh`
- `/scripts/complete-setup-test.sh`

**New Scripts**:
- `/scripts/setup/compile-libopaque.sh`
- `/scripts/maintenance/update-libopaque.sh`

#### 3.2 Documentation Updates

**Documentation Structure**:
- Migration guide (this document)
- API mapping reference
- Test results and benchmarks
- Security analysis

### Phase 4: Validation & Cleanup

#### 4.1 Comprehensive Testing

**Test Matrix**:
1. Unit tests - Full auth package coverage
2. Integration tests - End-to-end flows
3. Performance benchmarks
4. Security validation
5. Stress testing

#### 4.2 Cleanup Tasks

**Cleanup Checklist**:
- [ ] Remove aldenml/ecc from vendor
- [ ] Update go.mod dependencies
- [ ] Remove temporary test files
- [ ] Update production documentation
- [ ] Archive migration artifacts

## Implementation Timeline

| Phase | Duration | Key Deliverables |
|-------|----------|------------------|
| Phase 1 | 4 days | Compilation test, API mapping, minimal integration |
| Phase 2 | 5 days | Full implementation, all tests passing |
| Phase 3 | 3 days | Scripts updated, documentation complete |
| Phase 4 | 2 days | Final validation, cleanup |

## Risk Management

### Identified Risks

1. **API Incompatibility**: libopaque may have fundamentally different API
   - Mitigation: Create adapter layer if needed
   
2. **Performance Regression**: New library may be slower
   - Mitigation: Benchmark early, optimize if needed
   
3. **WASM Incompatibility**: Client-side may not work with new server
   - Mitigation: Test early, consider protocol adapter

4. **Missing Features**: libopaque may lack required functionality
   - Mitigation: Evaluate thoroughly in Phase 1

### Rollback Plan

1. Keep aldenml/ecc implementation in separate branch
2. Use build tags to switch between implementations
3. Maintain ability to revert quickly if issues found

## Success Criteria

- [ ] All existing tests pass with libopaque
- [ ] No performance regression > 10%
- [ ] Browser registration/login works correctly
- [ ] No memory leaks detected
- [ ] Clean compilation on all platforms
- [ ] Security properties maintained

## Current Status

**Phase**: 1 - Core Functionality Testing & Compilation ✅ COMPLETED
**Status**: Ready for Phase 2 - Full Implementation
**Last Updated**: 7/21/2025

## Completed Work Summary

1. **Library Selection Validated**: Stef's libopaque confirmed as best choice
2. **Build System Ready**: Libraries compiled and tested
3. **API Mapping Complete**: All functions mapped and tested
4. **Test Suite Created**: Comprehensive C tests demonstrating all functionality
5. **Documentation Updated**: Analysis and recommendations documented

## Next Steps - Phase 2 (Updated Implementation Plan)

### Immediate Tasks

1. **Remove aldenml/ecc + Create Go Bindings** (Priority 1)
   - **REMOVE**: Complete removal of all aldenml/ecc code and references
   - Update `/auth/opaque_cgo.go` with libopaque bindings
   - Create wrapper functions in `/auth/opaque_wrapper.c`
   - Update build tags and CGO flags
   - Remove aldenml/ecc from vendor directory and build scripts

2. **WASM Compilation Testing** (Priority 2 - CRITICAL)
   - Test libopaque compilation to WASM immediately
   - Ensure client-side crypto compatibility early
   - Update `/auth/opaque_wasm.go` as needed
   - Verify browser integration with new library

3. **Core Go Implementation** (Priority 3)
   - Replace aldenml/ecc calls with libopaque equivalents in `/auth/opaque.go`
   - Update state management to match libopaque's simpler approach
   - Implement identity handling using `Opaque_Ids`
   - Maintain existing function signatures for compatibility

4. **Test Migration** (Priority 4)
   - Migrate existing Go tests to use libopaque
   - Add new tests for libopaque-specific features
   - Use C test patterns as reference for Go test implementation

5. **Build System Integration** (Priority 5)
   - Integrate libopaque compilation into `/scripts/setup/build.sh`
   - Update all build scripts to include libopaque
   - Remove aldenml/ecc build steps

### Detailed Implementation Steps

#### Priority 1: Remove aldenml/ecc + Create Go Bindings

**Step 1.1: Complete aldenml/ecc Removal**
- [ ] Remove aldenml/ecc submodule from vendor directory
- [ ] Delete all references in `/auth/opaque.go`
- [ ] Remove aldenml/ecc CGO flags from `/auth/opaque_cgo.go`
- [ ] Clean up any remaining imports or references
- [ ] Update go.mod if needed

**Step 1.2: Create libopaque C Wrapper**
- [ ] Update `/auth/opaque_wrapper.c` with libopaque functions:
  ```c
  // Registration functions
  int arkfile_opaque_register_user(const char* password, size_t pwd_len, 
                                   uint8_t* user_record, uint8_t* export_key);
  
  // Authentication functions  
  int arkfile_opaque_authenticate_user(const char* password, size_t pwd_len,
                                       const uint8_t* user_record, uint8_t* session_key);
  ```

**Step 1.3: Update Go CGO Bindings**
- [ ] Update `/auth/opaque_cgo.go` with new CGO directives:
  ```go
  /*
  #cgo CFLAGS: -I../vendor/stef/libopaque/src -I../vendor/stef/liboprf/src
  #cgo LDFLAGS: -L../vendor/stef/libopaque/src -L../vendor/stef/liboprf/src 
  #cgo LDFLAGS: -lopaque -loprf -loprf-noiseXK
  #include "opaque_wrapper.h"
  */
  import "C"
  ```

**Step 1.4: Error Code Mapping**
- [ ] Create Go error mapping for libopaque return codes
- [ ] Implement proper error context preservation
- [ ] Add logging for debugging CGO interface

#### Priority 2: WASM Compilation Testing (CRITICAL)

**Step 2.1: Test Basic WASM Compilation**
- [ ] Attempt to compile libopaque to WASM:
  ```bash
  cd vendor/stef/libopaque
  emcc src/*.c -o libopaque.wasm -s EXPORTED_FUNCTIONS='[...]'
  ```

**Step 2.2: Update WASM Go Build**
- [ ] Update `/auth/opaque_wasm.go` for libopaque compatibility
- [ ] Test Go WASM compilation with new library
- [ ] Verify WASM file size and performance

**Step 2.3: Browser Integration Testing**
- [ ] Test WASM loading in browser
- [ ] Verify JavaScript/Go bridge functions work
- [ ] Test registration and login flows in browser
- [ ] Check for any WASM-specific issues

#### Priority 3: Core Go Implementation

**Step 3.1: Update RegisterUser Function**
- [ ] Replace aldenml/ecc calls with libopaque in `RegisterUser()`
- [ ] Implement simplified registration flow:
  - `opaque_CreateRegistrationRequest` (client simulation)
  - `opaque_CreateRegistrationResponse` (server)
  - `opaque_FinalizeRequest` (client simulation)
  - `opaque_StoreUserRecord` (server storage)

**Step 3.2: Update AuthenticateUser Function**  
- [ ] Replace aldenml/ecc calls with libopaque in `AuthenticateUser()`
- [ ] Implement simplified authentication flow:
  - `opaque_CreateCredentialRequest` (client simulation)
  - `opaque_CreateCredentialResponse` (server)
  - `opaque_RecoverCredentials` (client simulation)
  - `opaque_UserAuth` (server validation)

**Step 3.3: Update Server Key Management**
- [ ] Update `SetupServerKeys()` for libopaque key format
- [ ] Update `loadServerKeys()` for new key structure
- [ ] Ensure key storage/loading compatibility

**Step 3.4: Identity Handling**
- [ ] Implement `Opaque_Ids` structure usage
- [ ] Handle client/server identity management
- [ ] Test with and without identities (libopaque supports NULL)

#### Priority 4: Test Migration

**Step 4.1: Update Unit Tests**
- [ ] Update `/auth/opaque_test.go` with new function calls
- [ ] Port test patterns from successful C tests
- [ ] Test error conditions and edge cases
- [ ] Verify memory management (no leaks)

**Step 4.2: Integration Tests**  
- [ ] Update `/handlers/auth_test.go` for new implementation
- [ ] Test full registration/login HTTP flows
- [ ] Test session key consistency
- [ ] Verify database interactions work correctly

**Step 4.3: New libopaque-specific Tests**
- [ ] Test `opaque_Register` one-step registration
- [ ] Test identity handling (with and without IDs)
- [ ] Test libopaque error conditions
- [ ] Performance comparison vs baseline

#### Priority 5: Build System Integration

**Step 5.1: Update Build Scripts**
- [ ] Modify `/scripts/setup/build.sh` to compile libopaque
- [ ] Add libopaque build steps to `/scripts/setup/03-setup-opaque-keys.sh`
- [ ] Update `/scripts/quick-start.sh` for new dependencies
- [ ] Remove all aldenml/ecc build steps

**Step 5.2: Create New Build Scripts**
- [ ] Create `/scripts/setup/compile-libopaque.sh`:
  ```bash
  #!/bin/bash
  cd vendor/stef/libopaque && make
  cd ../liboprf && make
  ```
- [ ] Create `/scripts/maintenance/update-libopaque.sh`
- [ ] Update deployment scripts

**Step 5.3: Final Integration Testing**
- [ ] Test complete build from scratch
- [ ] Verify all dependencies are satisfied
- [ ] Test on clean system
- [ ] Performance benchmarking vs aldenml/ecc baseline

### Technical Implementation Details

#### Database Schema Compatibility ✅
- **CONFIRMED**: No schema changes needed
- `opaque_server_keys` BLOB fields work with libopaque keys
- `opaque_user_data.serialized_record` BLOB works with libopaque user records
- Existing users: N/A (no existing users to migrate)

#### Build System Configuration
**CGO Flags Update:**
```go
/*
#cgo CFLAGS: -I../vendor/stef/libopaque/src -I../vendor/stef/liboprf/src -I../vendor/stef/liboprf/src/noise_xk
#cgo LDFLAGS: -L../vendor/stef/libopaque/src -L../vendor/stef/liboprf/src -L../vendor/stef/liboprf/src/noise_xk
#cgo LDFLAGS: -lopaque -loprf -loprf-noiseXK -lsodium
*/
```

**Library Requirements:**
- `libopaque.so` - Main OPAQUE implementation
- `liboprf.so` - OPRF dependency  
- `liboprf-noiseXK.so` - Noise protocol support
- `libsodium` - Crypto primitives

#### Memory Management Strategy
- **Fixed-size Buffers**: libopaque uses constants (simpler than aldenml/ecc)
- **Buffer Sizes**: Use libopaque constants from opaque.h
- **Cleanup Pattern**: 
  ```go
  defer func() {
      crypto.SecureZeroBytes(sessionKey)
      crypto.SecureZeroBytes(exportKey)
  }()
  ```

#### State Management Simplification
**Before (aldenml/ecc)**: Complex KE1/KE2/KE3 flow with separate state management
**After (libopaque)**: Simplified flow with internal state handling
- Registration: Request → Response → Finalize → Store
- Authentication: Request → Response → Recover → Validate

#### Error Handling Pattern
```go
func libopaqueWrapper(/* params */) error {
    ret := C.opaque_function(/* C params */)
    if ret != 0 {
        return fmt.Errorf("libopaque operation failed: error code %d", ret)
    }
    return nil
}
```

### Progress Tracking Checklist

#### Phase 1 ✅ COMPLETED
- [x] Library selection and validation
- [x] Build system setup
- [x] API compatibility testing
- [x] C test programs created and passing

#### Phase 2 - Implementation (Current)
- [ ] Priority 1: aldenml/ecc removal + Go bindings
- [ ] Priority 2: WASM compilation testing
- [ ] Priority 3: Core Go implementation
- [ ] Priority 4: Test migration
- [ ] Priority 5: Build system integration

#### Success Criteria
- [ ] All tests pass with libopaque
- [ ] WASM compilation works in browser
- [ ] No memory leaks detected
- [ ] Performance equal or better than aldenml/ecc
- [ ] Clean build from scratch
- [ ] Complete removal of aldenml/ecc dependencies
