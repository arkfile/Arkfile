# JavaScript Cleanup & Go/WASM Migration - Master Plan

**Status**: Planning  
**Total Duration Estimate**: 4-6 months  
**Overall Goal**: Transform Arkfile's client-side architecture by migrating JavaScript logic to Go/WASM while strengthening zero-knowledge security guarantees.

## Executive Summary

This master plan outlines the complete transformation of Arkfile's client-side codebase from a JavaScript-heavy architecture to a Go/WASM-centric design. The migration will:

- **Strengthen Security**: Move all cryptographic operations to Go/WASM for better security properties
- **Improve Performance**: Leverage WASM's near-native performance for crypto operations
- **Enhance Maintainability**: Centralize crypto logic in well-tested Go packages
- **Preserve Zero-Knowledge**: Maintain and strengthen Arkfile's privacy-first architecture
- **Reduce Complexity**: Dramatically simplify JavaScript layer (40%+ reduction in code)

## Phase Overview

| Phase | Goal | Duration | Key Deliverables |
|-------|------|----------|------------------|
| **Phase 1** | OPAQUE Implementation & Legacy Removal | 2-3 weeks | Real OPAQUE protocol, remove legacy auth |
| **Phase 2** | Crypto Consolidation | 3-4 weeks | Unified encryption in Go/WASM |
| **Phase 3** | Device Capability Unification | 2-3 weeks | Privacy-first capability detection |
| **Phase 4** | UI/Business Logic Separation | 3-4 weeks | Clean architecture separation |
| **Phase 5** | Authentication Architecture | 2-3 weeks | Consolidated auth system |
| **Phase 6** | Function Migration Strategy | 4-5 weeks | Systematic JS→Go migration |
| **Phase 7** | API Layer Optimization | 2-3 weeks | Standardized API patterns |
| **Phase 8** | Security Enhancements | 3-4 weeks | Comprehensive security audit |
| **Phase 9** | Performance Optimization | 2-3 weeks | WASM performance tuning |
| **Phase 10** | Testing & Validation | 3-4 weeks | Comprehensive test suite |

## Detailed Phase Plans

### Phase 1: OPAQUE Implementation & Legacy Removal ✅ PLANNED
**Duration**: 2-3 weeks  
**Priority**: Critical (Foundation)  
**Status**: Detailed plan completed in `docs/wip/js-cleanup-phase-1.md`

**Goals**:
- Implement real OPAQUE protocol replacing placeholders
- Remove all legacy authentication code
- Establish privacy-first device capability detection
- Create comprehensive test coverage

**Key Changes**:
- Replace 300+ lines of legacy/placeholder auth code
- Implement crypto/opaque.go with full protocol
- Enhance crypto/wasm_shim.go with OPAQUE exports
- Create OPAQUE-only authentication flows in JavaScript
- Update database schema for OPAQUE storage

**Success Criteria**:
- Zero legacy authentication code remains
- OPAQUE registration and authentication working end-to-end
- Device capability detection respects user privacy
- 80%+ test coverage maintained

### Phase 2: Crypto Consolidation Using Existing Infrastructure
**Duration**: 3-4 weeks  
**Priority**: High (Core Functionality)

**Goals**:
- Migrate all file encryption to crypto/envelope.go
- Unify multi-key encryption systems
- Implement streaming encryption for large files
- Remove JavaScript crypto fallbacks

**Current State Analysis**:
- `client/main.go`: 300+ lines of duplicate encryption logic
- `crypto/envelope.go`: Sophisticated multi-key system exists but unused
- `crypto/gcm.go`: Advanced streaming encryption available
- JavaScript: Multiple fallback implementations

**Migration Strategy**:
```
JavaScript Layer (Remove ~400 lines):
├── encryptFile() → Use crypto/envelope.go via WASM
├── decryptFile() → Use crypto/envelope.go via WASM  
├── encryptFileMultiKey() → Use CreateMultiKeyEnvelope()
├── decryptFileMultiKey() → Use ExtractFEKFromEnvelope()
└── All crypto fallbacks → Remove entirely

Go/WASM Layer (Enhance crypto/wasm_shim.go):
├── encryptFileWithEnvelopeJS() → Single interface for all encryption
├── decryptFileWithEnvelopeJS() → Single interface for all decryption
├── addKeyToEnvelopeJS() → Multi-key management
├── removeKeyFromEnvelopeJS() → Key revocation
└── streamEncryptFileJS() → Large file support
```

**Implementation Steps**:
1. **Envelope Integration** (5 days): Export crypto/envelope.go functions to WASM
2. **Streaming Support** (4 days): Add crypto/gcm.go streaming to WASM interface
3. **JavaScript Replacement** (3 days): Replace all JS crypto with WASM calls
4. **Multi-Key Migration** (4 days): Migrate existing multi-key system
5. **Testing & Validation** (5 days): Comprehensive crypto operation testing

**Success Criteria**:
- All file encryption uses crypto/envelope.go
- JavaScript crypto code reduced by 90%
- Streaming encryption works for files >100MB
- Multi-key sharing maintains existing functionality
- Performance matches or exceeds current implementation

### Phase 3: Device Capability Unification
**Duration**: 2-3 weeks  
**Priority**: Medium (User Experience)

**Goals**:
- Unify 4 different device capability implementations
- Implement comprehensive privacy-first detection
- Create adaptive security parameter selection
- Provide user-friendly capability explanations

**Current State Analysis**:
```
Duplicate Implementations:
├── crypto/capability_negotiation.go (sophisticated, privacy-first)
├── crypto/wasm_shim.go (basic benchmarking)
├── client/main.go (hardcoded heuristics) 
└── client/static/js/app.js (JavaScript consent UI)
```

**Consolidation Strategy**:
```
Target Architecture:
crypto/capability_negotiation.go (Enhanced) 
├── Privacy-first detection with user consent
├── Comprehensive device profiling
├── Battery-aware parameter adjustment
├── User-friendly capability explanations
└── Adaptive security parameter selection

crypto/wasm_shim.go (Interface)
├── requestCapabilityConsentAdvancedJS()
├── detectDeviceCapabilityComprehensiveJS()
├── selectOptimalParametersJS()
└── getUserFriendlyCapabilitySummaryJS()

JavaScript (Simplified)
└── Capability consent UI only (~50 lines vs current 200+)
```

**Implementation Steps**:
1. **Enhance Negotiator** (4 days): Extend crypto/capability_negotiation.go
2. **WASM Interface** (3 days): Create comprehensive WASM exports
3. **JavaScript Simplification** (2 days): Replace 4 implementations with 1
4. **User Experience** (3 days): Improve capability explanation UI
5. **Testing** (3 days): Cross-device capability detection testing

**Success Criteria**:
- Single source of truth for device capabilities
- Privacy-first detection with proper user consent
- User-friendly capability explanations
- Adaptive parameter selection based on device + battery state
- JavaScript capability code reduced by 75%

### Phase 4: UI/Business Logic Separation
**Duration**: 3-4 weeks  
**Priority**: High (Architecture)

**Goals**:
- Extract business logic from UI event handlers
- Create dedicated modules for authentication flow
- Implement proper session management
- Separate DOM manipulation from application logic

**Current State Analysis**:
```
app.js Current Structure (~1,500 lines):
├── UI Event Handlers (mixed with business logic)
├── Authentication Flow Management (embedded in UI)
├── File Operation Coordination (scattered)
├── Session Handling (mixed throughout)
├── Modal Utilities (UI + logic mixed)
└── Progress Indicators (UI + coordination mixed)
```

**Target Architecture**:
```
JavaScript Layer (Refactored):
├── app.js (~800 lines)
│   ├── Pure UI event handlers
│   ├── DOM manipulation only
│   └── User interaction coordination
├── auth-flow.js (~200 lines)
│   ├── Authentication flow orchestration  
│   ├── Session lifecycle management
│   └── OPAQUE flow coordination
├── file-operations.js (~150 lines)
│   ├── File upload/download coordination
│   ├── Progress tracking logic
│   └── Error handling coordination
└── session-manager.js (~100 lines)
    ├── Session state management
    ├── Token lifecycle coordination
    └── User context management

Go/WASM Layer (Enhanced):
├── Authentication business logic
├── Session validation logic
├── File operation orchestration
└── Security context management
```

**Implementation Steps**:
1. **Authentication Module** (5 days): Extract auth flow to dedicated module
2. **File Operations Module** (4 days): Separate file operation coordination
3. **Session Manager** (3 days): Centralized session state management
4. **UI Simplification** (5 days): Remove business logic from event handlers
5. **WASM Enhancement** (4 days): Move coordination logic to Go/WASM
6. **Integration Testing** (4 days): Ensure all flows work with new architecture

**Success Criteria**:
- Clear separation between UI and business logic
- Authentication flow managed in dedicated module
- Session management centralized and secure
- File operations coordinated independently of UI
- app.js reduced by 50% in size
- Business logic testable independently of UI

### Phase 5: Authentication Architecture Refactoring
**Duration**: 2-3 weeks  
**Priority**: High (Security)

**Goals**:
- Consolidate authentication into unified system
- Implement proper session management architecture
- Move device capability detection to authentication flow
- Create secure token handling system

**Current State Analysis**:
```
Authentication Split Across:
├── OPAQUE functions (placeholder → real in Phase 1)
├── Legacy authentication (removed in Phase 1)
├── Session key derivation (scattered)
├── Device capability (separate from auth)
└── Token management (spread across handlers)
```

**Target Architecture**:
```
Unified Authentication System:
├── crypto/opaque.go (Core OPAQUE protocol)
├── crypto/session.go (Session key derivation)
├── crypto/capability_negotiation.go (Device-aware auth)
├── auth-flow.js (Authentication orchestration)
└── session-manager.js (Token lifecycle)

Authentication Flow:
User → Device Capability Consent → OPAQUE Auth → Session Establishment → Token Management
```

**Implementation Steps**:
1. **Session Architecture** (4 days): Design secure session management system
2. **Token Integration** (3 days): Integrate JWT tokens with OPAQUE sessions
3. **Capability Integration** (3 days): Include capability detection in auth flow
4. **Security Context** (3 days): Create comprehensive security context management
5. **Flow Testing** (2 days): Test complete authentication flows

**Success Criteria**:
- Single authentication system (OPAQUE only)
- Secure session key derivation from OPAQUE export keys
- Device capability integrated into authentication
- Proper token lifecycle management
- Authentication flow completed in <5 seconds on all device types

### Phase 6: Function Migration Strategy
**Duration**: 4-5 weeks  
**Priority**: Medium (Optimization)

**Goals**:
- Systematically migrate JavaScript functions to Go/WASM
- Prioritize by security and performance impact
- Create migration framework for consistent patterns
- Maintain functionality throughout migration

**Migration Priority Matrix**:
```
High Priority (Security Critical):
├── Password validation → crypto/capability_negotiation.go
├── Cryptographic operations → crypto/envelope.go + crypto/gcm.go
├── Session management → crypto/session.go
├── Input sanitization → crypto/validation.go
└── Security context validation → crypto/wasm_shim.go

Medium Priority (Performance Critical):
├── File processing → crypto/gcm.go streaming
├── Data validation → utils/validator.go
├── Hash calculations → crypto/kdf.go
├── Key derivation → crypto/session.go
└── Compression operations → Go standard library

Low Priority (Convenience):
├── Utility functions → Case-by-case evaluation
├── Helper functions → Remain in JavaScript if UI-focused
├── Formatting functions → JavaScript (UI-only)
└── Display logic → JavaScript (DOM manipulation)
```

**Migration Framework**:
1. **Security Assessment**: Evaluate security impact of each function
2. **Performance Analysis**: Measure JavaScript vs Go/WASM performance
3. **Integration Complexity**: Assess difficulty of migration
4. **Testing Requirements**: Plan comprehensive testing for each migration
5. **Rollback Strategy**: Ensure ability to rollback if issues arise

**Implementation Steps**:
1. **Migration Framework** (5 days): Create systematic migration process
2. **Security Critical Functions** (8 days): Migrate high-priority security functions
3. **Performance Critical Functions** (6 days): Migrate computationally intensive functions
4. **Validation & Testing** (6 days): Comprehensive testing of migrated functions
5. **Optimization** (5 days): Optimize WASM interface and performance

**Success Criteria**:
- All security-critical functions run in Go/WASM
- Performance improvements measurable for migrated functions
- JavaScript bundle size reduced by 40%+
- No functionality regression
- Clear migration framework for future use

### Phase 7: API Layer Optimization
**Duration**: 2-3 weeks  
**Priority**: Medium (Architecture)

**Goals**:
- Standardize API communication patterns
- Remove duplicate fetch logic
- Implement consistent error handling
- Move API response processing to dedicated modules

**Current State Analysis**:
```
API Communication Issues:
├── Duplicate fetch logic across multiple files
├── Inconsistent error handling patterns
├── API response processing embedded in UI code
├── No standardized request/response sanitization
└── Mixed authentication token handling
```

**Target Architecture**:
```
API Layer Structure:
├── api-client.js (~200 lines)
│   ├── Standardized fetch wrapper
│   ├── Consistent error handling
│   ├── Authentication token management
│   └── Request/response sanitization
├── api-endpoints.js (~100 lines)
│   ├── Endpoint definitions
│   ├── URL construction helpers
│   └── Parameter validation
└── Go/WASM Integration
    ├── Request sanitization in Go
    ├── Response validation in Go
    └── Security header enforcement
```

**Implementation Steps**:
1. **API Client Module** (4 days): Create standardized API communication layer
2. **Error Handling** (3 days): Implement consistent error handling patterns
3. **Authentication Integration** (3 days): Integrate with OPAQUE token system
4. **Response Processing** (2 days): Move response processing to dedicated modules
5. **Security Enhancement** (3 days): Add Go/WASM request/response validation

**Success Criteria**:
- Single API client handles all server communication
- Consistent error handling across all API calls
- Authentication tokens properly managed
- API response processing separated from UI code
- Request/response sanitization in Go/WASM

### Phase 8: Security Enhancements
**Duration**: 3-4 weeks  
**Priority**: Critical (Security)

**Goals**:
- Audit all client-side security functions
- Ensure sensitive operations run in WASM
- Implement comprehensive input validation
- Strengthen session management security

**Security Audit Areas**:
```
Client-Side Security Review:
├── Cryptographic Operations (All in Go/WASM)
├── Input Validation (Go/WASM + JavaScript UI)
├── Session Management (Go/WASM security context)
├── Token Handling (Secure storage and transmission)
├── Memory Management (WASM secure key handling)
├── Error Handling (No information leakage)
└── Privacy Protection (Capability detection consent)
```

**Implementation Steps**:
1. **Security Audit** (5 days): Comprehensive review of all client-side security
2. **WASM Security** (4 days): Ensure all sensitive operations in WASM
3. **Input Validation** (4 days): Implement comprehensive validation in Go/WASM
4. **Session Security** (3 days): Strengthen session management security
5. **Privacy Audit** (3 days): Verify privacy-first capability detection
6. **Security Testing** (4 days): Penetration testing and security validation

**Success Criteria**:
- All cryptographic operations run in Go/WASM
- Comprehensive input validation implemented
- Session management security verified
- Privacy properties maintained and enhanced
- Security audit passes with no critical findings
- Penetration testing validates security improvements

### Phase 9: Performance Optimization
**Duration**: 2-3 weeks  
**Priority**: Medium (Performance)

**Goals**:
- Optimize WASM performance for crypto operations
- Implement lazy loading for non-critical functionality
- Optimize WASM initialization and function call patterns
- Benchmark and tune performance across device types

**Performance Optimization Areas**:
```
WASM Performance Tuning:
├── Crypto Operation Optimization
│   ├── Argon2ID parameter tuning
│   ├── AES-GCM performance optimization
│   └── Multi-key encryption efficiency
├── Memory Management
│   ├── WASM heap optimization
│   ├── Key storage efficiency
│   └── Garbage collection tuning
├── Initialization Optimization
│   ├── Lazy WASM module loading
│   ├── Function call optimization
│   └── Startup time reduction
└── Device-Specific Tuning
    ├── Mobile performance optimization
    ├── Low-memory device support
    └── Battery usage optimization
```

**Implementation Steps**:
1. **Performance Baseline** (2 days): Establish current performance metrics
2. **Crypto Optimization** (4 days): Optimize cryptographic operations in WASM
3. **Memory Optimization** (3 days): Optimize WASM memory usage and allocation
4. **Initialization Optimization** (3 days): Implement lazy loading and startup optimization
5. **Device Testing** (3 days): Test and tune performance across device types

**Success Criteria**:
- WASM crypto operations perform at 90%+ of native speed
- JavaScript bundle size reduced by 40%+ from original
- Startup time <2 seconds on all supported devices
- Memory usage optimized for low-end devices
- Battery impact minimized on mobile devices

### Phase 10: Testing & Validation
**Duration**: 3-4 weeks  
**Priority**: Critical (Quality Assurance)

**Goals**:
- Create comprehensive test suite for entire refactored system
- Implement integration tests for all major workflows
- Validate security properties are maintained
- Ensure performance targets are met

**Testing Strategy**:
```
Comprehensive Test Coverage:
├── Unit Tests
│   ├── Go/WASM crypto functions (95%+ coverage)
│   ├── JavaScript UI components (80%+ coverage)
│   ├── API integration functions (90%+ coverage)
│   └── Authentication flows (100% coverage)
├── Integration Tests
│   ├── End-to-end user workflows
│   ├── Cross-browser compatibility
│   ├── Device capability detection
│   └── OPAQUE authentication flows
├── Security Tests
│   ├── Cryptographic property validation
│   ├── Session security verification
│   ├── Input validation testing
│   └── Privacy property validation
└── Performance Tests
    ├── WASM performance benchmarking
    ├── Cross-device performance validation
    ├── Memory usage testing
    └── Battery impact assessment
```

**Implementation Steps**:
1. **Test Infrastructure** (5 days): Set up comprehensive testing infrastructure
2. **Unit Testing** (6 days): Create/update unit tests for all components
3. **Integration Testing** (5 days): Implement end-to-end workflow testing
4. **Security Testing** (4 days): Validate all security properties
5. **Performance Testing** (3 days): Benchmark and validate performance
6. **Cross-Platform Testing** (2 days): Test across devices and browsers

**Success Criteria**:
- 90%+ test coverage across all components
- All security properties validated
- Performance targets met on all device types
- Zero regression in functionality
- Cross-browser compatibility maintained

## Implementation Timeline & Dependencies

### Critical Path Analysis
```
Phase Dependencies:
Phase 1 (OPAQUE) → Foundation for all other phases
Phase 2 (Crypto) → Depends on Phase 1, enables Phase 4,5,6
Phase 3 (Capability) → Can run parallel with Phase 2
Phase 4 (UI/Logic) → Depends on Phase 1,2
Phase 5 (Auth) → Depends on Phase 1,3,4
Phase 6 (Migration) → Depends on Phase 2,4,5
Phase 7 (API) → Can run parallel with Phase 6
Phase 8 (Security) → Depends on Phase 6,7
Phase 9 (Performance) → Depends on Phase 8
Phase 10 (Testing) → Runs throughout, final validation at end
```

### Resource Allocation
```
Development Resources:
├── Senior Go/Crypto Developer (Phases 1,2,8)
├── JavaScript/Frontend Developer (Phases 3,4,7)
├── Full-Stack Developer (Phases 5,6,9)
├── QA/Security Engineer (Phase 10, ongoing)
└── DevOps/Testing Engineer (Phase 10, ongoing)
```

### Risk Mitigation
```
Major Risks & Mitigation:
├── OPAQUE Library Compatibility
│   └── Mitigation: Evaluate multiple libraries, create adapter layer
├── WASM Performance Issues
│   └── Mitigation: Early benchmarking, performance budgets
├── Security Regression
│   └── Mitigation: Comprehensive security testing, external audit
├── Timeline Overrun
│   └── Mitigation: Phased delivery, MVP approach per phase
└── Browser Compatibility
    └── Mitigation: Early cross-browser testing, polyfills
```

## Success Metrics

### Code Quality Metrics
- **JavaScript Bundle Size**: Reduce by 40%+
- **Test Coverage**: Maintain 80%+ overall, 95%+ for crypto
- **Code Duplication**: Eliminate all crypto duplication
- **Maintainability**: Improve separation of concerns

### Security Metrics
- **Crypto Operations**: 100% in Go/WASM
- **Session Security**: OPAQUE-derived session keys only
- **Privacy Compliance**: Privacy-first capability detection
- **Security Audit**: Zero critical findings

### Performance Metrics
- **Authentication Time**: <5 seconds on all devices
- **File Encryption**: Near-native WASM performance
- **Startup Time**: <2 seconds initial load
- **Memory Usage**: Optimized for low-end devices

### User Experience Metrics
- **Zero Functionality Regression**: All existing features work
- **Improved UX**: Better device capability explanations
- **Cross-Browser**: Consistent experience across browsers
- **Mobile Performance**: Optimized for mobile devices

## Future Considerations

### Post-Migration Opportunities
1. **Additional WASM Migrations**: Consider moving more performance-critical operations
2. **Advanced Crypto Features**: Leverage improved architecture for new crypto features
3. **Mobile App Development**: WASM crypto code reusable in mobile apps
4. **Performance Monitoring**: Implement runtime performance monitoring

### Maintenance Strategy
1. **Regular Security Audits**: Quarterly security reviews
2. **Performance Monitoring**: Continuous performance tracking
3. **Browser Compatibility**: Regular testing with new browser versions
4. **Dependency Updates**: Regular updates to crypto libraries

### Scalability Planning
1. **Multi-User Features**: Architecture supports advanced sharing features
2. **Enterprise Features**: Foundation for enterprise authentication
3. **API Expansion**: Standardized API layer enables API expansion
4. **Integration Capabilities**: Clean architecture enables third-party integrations

---

## Conclusion

This master plan provides a comprehensive roadmap for transforming Arkfile's client-side architecture from JavaScript-heavy to Go/WASM-centric while maintaining and enhancing its zero-knowledge security properties. The phased approach ensures:

- **Minimal Risk**: Each phase is independently deliverable and testable
- **Clear Progress**: Measurable improvements at each phase
- **Security Focus**: Security enhancements throughout the migration
- **Performance Gains**: Progressive performance improvements
- **Maintainability**: Cleaner, more maintainable architecture

The end result will be a more secure, performant, and maintainable Arkfile with a dramatically simplified JavaScript layer and robust Go/WASM foundation for future development.
