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

## Next Steps - Phase 2

### Immediate Tasks

1. **Create Go Bindings** (Priority 1)
   - Update `/auth/opaque_cgo.go` with libopaque bindings
   - Create wrapper functions in `/auth/opaque_wrapper.c`
   - Update build tags and CGO flags

2. **Implement Core Functions** (Priority 2)
   - Replace aldenml/ecc calls with libopaque equivalents
   - Update state management to match libopaque's approach
   - Implement identity handling using `Opaque_Ids`

3. **Update Test Suite** (Priority 3)
   - Migrate existing Go tests to use libopaque
   - Add new tests for libopaque-specific features
   - Ensure backward compatibility where needed

4. **WASM Compilation** (Priority 4)
   - Test libopaque compilation to WASM
   - Update client-side code if needed
   - Verify browser compatibility

### Technical Considerations

1. **Memory Management**:
   - libopaque uses fixed-size buffers
   - Need careful memory handling in CGO layer
   - Consider using defer for cleanup

2. **Error Handling**:
   - libopaque returns error codes (0 = success)
   - Map to Go errors appropriately
   - Preserve error context

3. **State Management**:
   - libopaque state differs from aldenml/ecc
   - May need to adjust database schema
   - Consider migration path for existing users

4. **Build Configuration**:
   - Update Makefile/build scripts
   - Set proper library paths
   - Handle dynamic linking correctly
