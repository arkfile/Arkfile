# TypeScript Migration & Go/WASM Optimization - Master Plan

**Status**: Ready to Execute  
**Timeline**: 3-4 weeks total  
**Goal**: Minimize JavaScript/TypeScript surface area by migrating security-critical functions to Go/WASM, remove unnecessary code, and convert remaining code to TypeScript for better maintainability and future Bitcoin wallet authentication integration.

## Executive Summary

This plan transforms Arkfile's client-side architecture by:
- **Maximizing Go/WASM Usage**: Moving all security-critical operations to Go/WASM
- **Eliminating Unnecessary Code**: Removing device capability detection and unused functions
- **TypeScript Migration**: Converting remaining UI code to TypeScript for type safety
- **Preparing for Future Features**: Creating a clean foundation for Bitcoin wallet authentication
- **Security Enhancement**: Addressing critical vulnerabilities in client-side key derivation

The result will be a more secure, maintainable codebase with ~60% reduction in client-side code complexity.

## Critical Security Findings

**🚨 Current File Encryption Key Derivation Has Serious Vulnerabilities:**

### Problem 1: Session Key Storage & Transmission
- **Issue**: OPAQUE export keys are stored in `window.arkfileSecurityContext.sessionKey` as base64 strings
- **Vulnerability**: Session keys persist in memory and are accessible to any JavaScript code
- **Risk**: XSS attacks can extract session keys and decrypt all user files

### Problem 2: Inconsistent Key Derivation Between Go and WASM
- **Issue**: Server uses HKDF-SHA256 with domain separation (`crypto/session.go`)
- **Issue**: WASM client uses simple string concatenation (`"ARKFILE_SESSION_KEY:" + password`)
- **Risk**: Weak domain separation allows potential key confusion attacks

### Problem 3: Client-Side Key Storage Without Protection
- **Issue**: File encryption keys (FEKs) are handled in client-side WASM without secure memory management
- **Risk**: Keys remain in WASM memory and can be extracted through memory dumps

### Problem 4: Redundant Key Derivation Layers
- **Issue**: Complex envelope system with both account and custom password types
- **Inefficiency**: Multiple unnecessary key derivation steps on client-side

**These vulnerabilities are CRITICAL and must be addressed as part of this migration.**

## Current State Analysis

### JavaScript Code Breakdown (~1,500 lines in app.js):
- **Authentication UI Logic**: ~400 lines (convert to TypeScript)
- **File Operations**: ~300 lines (some to WASM, some to TypeScript) 
- **Device Capability Detection**: ~200 lines (**DELETE ENTIRELY**)
- **TOTP/Modal Logic**: ~250 lines (validation to WASM, UI to TypeScript)
- **Progress/DOM Manipulation**: ~200 lines (keep in TypeScript)
- **Password Validation**: ~50 lines (**MOVE TO WASM**)
- **Session Management**: ~100 lines (**MOVE TO WASM**)

### Target Architecture:
- **Go/WASM**: All security-critical operations (~400 lines of logic moved)
- **TypeScript**: Pure UI coordination and user interaction (~800 lines remaining)
- **Net Result**: ~60% reduction in client-side complexity, 100% type safety

## Phase Overview

| Phase | Goal | Duration | Key Deliverables |
|-------|------|----------|------------------|
| **Phase 1** | Security Migration & Cleanup | 1-2 weeks | Security functions in WASM, device capability removed |
| **Phase 2** | TypeScript Conversion | 1 week | Full TypeScript migration with proper typing |
| **Phase 3** | Optimization & Testing | 3-4 days | Final cleanup, testing, documentation |

---

## Phase 1: Security Migration & Cleanup (1-2 weeks)

**Priority**: Critical (Security Foundation)

### Goals:
- Move all password validation to Go/WASM
- Move session key derivation to Go/WASM  
- Move TOTP validation logic to Go/WASM
- Remove device capability detection entirely
- Clean up unused functions

### Step 1.1: Remove Device Capability Detection (2 days)

**Delete These Functions from app.js:**
```javascript
// REMOVE ENTIRELY - Device capability detection
requestDeviceCapabilityPermission()
detectDeviceCapabilityWithPermission()
requestDeviceCapabilityConsent()
handleCapabilityConsent()
detectDeviceCapability()
showCapabilityInfo()

// REMOVE - Related state management
window.arkfileOpaqueState = { ... }
```

**Delete These Server Endpoints:**
- Remove `/api/opaque/capability` endpoint from handlers/auth.go
- Remove `DetectDeviceCapability` function
- Remove `DeviceCapabilityRequest` struct

**Files to Modify:**
- `client/static/js/app.js` - Remove ~200 lines of capability code
- `handlers/auth.go` - Remove capability endpoint (~50 lines)
- `handlers/route_config.go` - Remove capability route

### Step 1.2: Migrate Password Validation to WASM (3 days)

**Current JavaScript Functions to Remove:**
```javascript
// MOVE TO WASM - Password validation
validatePasswordComplexity()
updatePasswordConfirmationStatus() 
// Any other password strength checking
```

**New Go/WASM Functions to Create:**
```go
// Add to crypto/wasm_shim.go
func validatePasswordStrengthJS(password string) js.Value
func validatePasswordMatchJS(password, confirm string) js.Value
func generatePasswordRequirementsJS() js.Value
```

**Implementation Details:**
- Create comprehensive password validation in `crypto/validation.go`
- Export WASM functions for password strength, complexity, matching
- Remove all client-side password validation logic
- Update registration UI to call WASM functions only

### Step 1.3: **CRITICAL SECURITY FIX** - Session Key Management (4 days)

**🚨 SECURITY VULNERABILITY REMEDIATION:**

**Current Vulnerable JavaScript Functions to COMPLETELY REMOVE:**
```javascript
// REMOVE ENTIRELY - These expose session keys to JavaScript
window.arkfileSecurityContext = { sessionKey: ... }
deriveSessionKey() // Uses weak string concatenation
// All client-side session key storage and manipulation
```

**New Secure Go/WASM Functions to Create:**
```go
// Add to crypto/wasm_shim.go
func createSecureSessionFromOpaqueExportJS(exportKey []byte, userEmail string) js.Value
func encryptFileWithSecureSessionJS(fileData []byte, userEmail string) js.Value
func decryptFileWithSecureSessionJS(encryptedData string, userEmail string) js.Value
func validateSecureSessionJS(userEmail string) js.Value
func clearSecureSessionJS(userEmail string) js.Value
```

**Critical Implementation Details:**

1. **Eliminate Client-Side Session Key Exposure:**
   - Remove `window.arkfileSecurityContext` entirely
   - Session keys NEVER leave WASM memory space
   - Use internal WASM session management with proper memory protection

2. **Fix Key Derivation Consistency:**
   - Replace weak string concatenation with proper HKDF-SHA256
   - Ensure server and client use identical domain separation
   - Use `crypto/session.go` functions directly in WASM

3. **Secure Memory Management:**
   - Implement secure key storage within WASM heap
   - Use `SecureZeroBytes()` for key cleanup
   - Automatic session cleanup on logout/timeout

4. **API Changes Required:**
   ```go
   // Replace current approach
   OLD: sessionKey stored in JavaScript → vulnerable to XSS
   NEW: sessionKey stored in WASM → never accessible to JavaScript
   
   // New secure file operations
   encryptFileWithSecureSession(fileData, userEmail) // No key exposure
   decryptFileWithSecureSession(encryptedData, userEmail) // No key exposure
   ```

5. **Authentication Flow Updates:**
   ```javascript
   // OLD (VULNERABLE):
   window.arkfileSecurityContext = { sessionKey: data.sessionKey }
   
   // NEW (SECURE):
   createSecureSessionFromOpaqueExport(data.opaqueExport, userEmail)
   // Session key never visible to JavaScript
   ```

**This is a CRITICAL security fix that prevents XSS-based key extraction attacks.**

### Step 1.4: Migrate TOTP Validation (3 days)

**Current JavaScript - Keep UI, Move Logic:**
- Keep: TOTP input fields, countdown timers, modal displays
- Move to WASM: Code validation, backup code validation, setup verification

**New Go/WASM Functions:**
```go
// Add TOTP validation to WASM
func validateTOTPCodeJS(code, userEmail string) js.Value
func validateBackupCodeJS(code, userEmail string) js.Value  
func generateTOTPSetupDataJS(userEmail, sessionKey string) js.Value
func verifyTOTPSetupJS(code, secret string) js.Value
```

**UI Components to Keep in TypeScript:**
- Countdown timers for TOTP expiration
- QR code display
- Modal dialogs for TOTP input
- Progress indicators during setup

### Step 1.5: General Cleanup (2 days)

**Remove Unused Functions:**
```javascript
// Functions that may be obsolete after OPAQUE implementation
// Any legacy authentication helpers
// Unused crypto fallbacks
// Commented-out code sections
```

**Consolidate Remaining Functions:**
- Merge similar modal creation functions
- Combine error/success message displays
- Simplify progress indicator logic

**Success Criteria for Phase 1:**
- Zero password validation in JavaScript
- All session management in Go/WASM  
- TOTP validation logic in Go/WASM
- Device capability detection completely removed
- ~400 lines of JavaScript eliminated
- All security-critical operations in WASM

---

## Phase 2: TypeScript Conversion (1 week)

**Priority**: High (Foundation for Future Features)

### Goals:
- Set up stable TypeScript build system
- Convert all remaining JavaScript to TypeScript
- Create proper type definitions for WASM interfaces
- Maintain UI responsiveness and functionality

### Step 2.1: TypeScript Build Setup (1 day)

**Create TypeScript Configuration:**
```json
// tsconfig.json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "ES2020", 
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "strict": true,
    "noImplicitAny": true,
    "strictNullChecks": true,
    "noImplicitReturns": true,
    "moduleResolution": "node",
    "outDir": "./client/static/js/dist",
    "sourceMap": true,
    "declaration": true
  },
  "include": ["client/static/js/src/**/*"],
  "exclude": ["node_modules", "**/*.test.ts"]
}
```

**Build Integration Options (Choose One):**
1. **Simple tsc approach**: Direct TypeScript compiler integration with existing build
2. **Webpack integration**: If bundling/optimization needed  
3. **Esbuild**: Fast compilation integrated with Go build system

**Recommendation**: Start with simple tsc for stability, upgrade later if needed.

### Step 2.2: WASM Interface Typing (2 days)

**Create Type Definitions:**
```typescript
// client/static/js/src/types/wasm.d.ts
declare global {
  // Password validation
  function validatePasswordStrengthWASM(password: string): {
    valid: boolean;
    score: number;
    message: string;
    requirements: string[];
  };
  
  function validatePasswordMatchWASM(password: string, confirm: string): {
    match: boolean;
    message: string;
    status: 'match' | 'no-match' | 'empty';
  };
  
  // Session management  
  function deriveSessionKeyFromOpaqueWASM(exportKey: string, userEmail: string): {
    success: boolean;
    sessionKey?: string;
    error?: string;
  };
  
  // TOTP functions
  function validateTOTPCodeWASM(code: string, userEmail: string): {
    valid: boolean;
    error?: string;
  };
  
  // File encryption (existing)
  function encryptFile(data: Uint8Array, password: string, keyType: string): string;
  function decryptFile(data: string, password: string): string;
  // ... other existing WASM functions
}
```

### Step 2.3: Core TypeScript Conversion (3 days)

**File Structure:**
```
client/static/js/src/
├── types/
│   ├── wasm.d.ts          // WASM function types
│   ├── api.d.ts           // API response types
│   └── dom.d.ts           // Custom DOM types
├── auth/
│   ├── login.ts           // Login functionality
│   ├── register.ts        // Registration functionality
│   └── totp.ts            // TOTP UI coordination
├── files/
│   ├── upload.ts          // File upload logic
│   ├── download.ts        // File download logic
│   └── list.ts            // File listing/management
├── ui/
│   ├── modals.ts          // Modal utilities
│   ├── progress.ts        // Progress indicators
│   └── messages.ts        // Error/success messages
└── app.ts                 // Main application entry point
```

**Key Conversion Priorities:**

1. **Authentication Functions:**
```typescript
// auth/login.ts
interface LoginCredentials {
  email: string;
  password: string;
}

interface LoginResponse {
  token: string;
  refreshToken: string;
  sessionKey: string;
  authMethod: 'OPAQUE';
  requiresTOTP?: boolean;
}

async function login(credentials: LoginCredentials): Promise<void> {
  // Validate inputs using WASM
  const validation = validatePasswordStrengthWASM(credentials.password);
  if (!validation.valid) {
    showError(validation.message);
    return;
  }
  
  // Continue with login logic...
}
```

2. **File Operations:**
```typescript
// files/upload.ts
interface FileUploadOptions {
  file: File;
  useCustomPassword: boolean;
  password?: string;
  passwordHint?: string;
}

async function uploadFile(options: FileUploadOptions): Promise<void> {
  // Type-safe file upload with proper error handling
}
```

3. **UI Components:**
```typescript
// ui/modals.ts
interface ModalOptions {
  title: string;
  message: string;
  buttons?: ModalButton[];
}

interface ModalButton {
  text: string;
  action: () => void;
  variant?: 'primary' | 'secondary' | 'danger';
}

function createModal(options: ModalOptions): HTMLElement {
  // Type-safe modal creation
}
```

### Step 2.4: TypeScript Test Migration (2 days)

**Convert Existing JavaScript Tests to TypeScript:**

**Current JavaScript Test Files to Convert:**
```
client/debug-multikey-test.js       → client/tests/debug-multikey-test.ts
client/opaque_wasm_test.js          → client/tests/opaque-wasm.test.ts
client/test-runner.js               → client/tests/test-runner.ts
```

**Tests from Backup Directory to Resurrect as TypeScript:**
```
deleted-tests-backup/login-integration-test.js    → client/tests/login-integration.test.ts
deleted-tests-backup/password-functions-test.js   → client/tests/password-functions.test.ts
```

**TypeScript Test Structure:**
```
client/tests/
├── types/
│   ├── test-framework.d.ts    // Mock testing framework types
│   ├── wasm-test.d.ts         // WASM function test types
│   └── node-environment.d.ts  // Node.js environment types
├── utils/
│   ├── wasm-loader.ts         // WASM loading utilities
│   ├── mock-browser.ts        // Browser API mocking
│   └── test-runner.ts         // Core test runner
├── integration/
│   ├── login-integration.test.ts     // Full login flow tests
│   ├── opaque-protocol.test.ts       // OPAQUE authentication tests
│   └── file-encryption.test.ts       // File encryption/decryption tests
├── unit/
│   ├── password-functions.test.ts    // Password validation/hashing
│   ├── crypto-functions.test.ts      // Core crypto operations
│   ├── multi-key-encryption.test.ts  // Multi-key functionality
│   └── session-management.test.ts    // Session key derivation
└── package.json              // Node.js test dependencies
```

**Key TypeScript Test Features:**

1. **Proper Type Safety for WASM Interface:**
```typescript
// tests/types/wasm-test.d.ts
interface WASMTestResult<T = any> {
  success: boolean;
  data?: T;
  error?: string;
}

interface PasswordValidationResult {
  valid: boolean;
  score: number;
  message: string;
  requirements: string[];
}

interface EncryptionResult {
  encrypted: string;
  salt: string;
  keyDerivationTime: number;
}

declare global {
  // Test-specific WASM functions
  function hashPasswordArgon2IDWASM(password: string, salt: string): string;
  function validatePasswordComplexityWASM(password: string): PasswordValidationResult;
  function encryptFileMultiKeyWASM(
    data: Uint8Array, 
    primaryPassword: string, 
    keyType: string, 
    additionalKeys: { password: string; id: string }[]
  ): string;
  function decryptFileMultiKeyWASM(encrypted: string, password: string): string;
}
```

2. **Mock Framework with TypeScript:**
```typescript
// tests/utils/mock-browser.ts
export class MockCrypto implements Crypto {
  getRandomValues<T extends ArrayBufferView>(array: T): T {
    const nodeBytes = require('crypto').randomBytes(array.byteLength);
    new Uint8Array(array.buffer).set(nodeBytes);
    return array;
  }
  
  randomUUID(): string {
    return require('crypto').randomUUID();
  }
  
  subtle: SubtleCrypto = null as any; // Not implemented for tests
}

export function setupBrowserMocks(): void {
  global.crypto = new MockCrypto();
  
  global.fetch = async (url: string | URL, init?: RequestInit): Promise<Response> => {
    // Type-safe mock fetch implementation
  };
}
```

3. **Type-Safe Test Runner:**
```typescript
// tests/utils/test-runner.ts
export interface TestContext {
  name: string;
  failed: boolean;
  logs: string[];
  error(msg: string): void;
  log(msg: string): void;
  skip(msg: string): void;
}

export async function runTest(
  testName: string, 
  testFunc: (t: TestContext) => Promise<void> | void
): Promise<boolean> {
  const t: TestContext = {
    name: testName,
    failed: false,
    logs: [],
    error(msg: string) {
      this.failed = true;
      this.logs.push(`ERROR: ${msg}`);
      console.error(`❌ ${this.name}: ${msg}`);
    },
    log(msg: string) {
      this.logs.push(`LOG: ${msg}`);
      console.log(`📝 ${this.name}: ${msg}`);
    },
    skip(msg: string) {
      this.logs.push(`SKIP: ${msg}`);
      console.log(`⏭️ ${this.name}: SKIPPED - ${msg}`);
    }
  };
  
  try {
    console.log(`🧪 Running ${testName}...`);
    await testFunc(t);
    if (!t.failed) {
      console.log(`✅ ${testName} PASSED`);
    }
  } catch (error) {
    t.failed = true;
    t.logs.push(`PANIC: ${error.message}`);
    console.error(`💥 ${testName} PANICKED: ${error.message}`);
  }
  
  return !t.failed;
}
```

**Test Migration Process:**
1. **Day 1**: Set up TypeScript test infrastructure, convert basic test runner
2. **Day 2**: Convert all existing JavaScript tests to TypeScript with full typing

### Step 2.5: Build Integration & Testing (1 day)

**Update Build Scripts:**
- Modify existing build process to compile TypeScript
- Set up TypeScript test compilation with `ts-node` for Node.js tests
- Ensure WASM files are properly integrated with TypeScript tests
- Set up source maps for debugging both application and tests
- Configure test scripts in package.json for different test suites
- Test hot reload/development workflow

**Test Build Configuration:**
```json
// client/tests/tsconfig.json
{
  "extends": "../tsconfig.json",
  "compilerOptions": {
    "types": ["node"],
    "module": "CommonJS",
    "target": "ES2020",
    "esModuleInterop": true,
    "allowSyntheticDefaultImports": true,
    "resolveJsonModule": true
  },
  "include": ["**/*.ts", "../static/js/src/types/**/*.d.ts"],
  "exclude": ["node_modules"]
}
```

**Success Criteria for Phase 2:**
- All JavaScript converted to TypeScript with strict typing
- All JavaScript tests converted to TypeScript with full type safety
- Proper type definitions for all WASM functions (app and tests)
- Build system working reliably for both app and tests
- All existing functionality preserved
- All tests passing with TypeScript compilation
- Zero TypeScript compilation errors
- Test coverage maintained or improved

---

## Phase 3: Optimization & Testing (3-4 days)

**Priority**: Medium (Quality Assurance)

### Goals:
- Final optimization of TypeScript code
- Comprehensive testing of WASM integration
- Performance validation
- Documentation updates

### Step 3.1: Code Optimization (2 days)

**TypeScript Optimizations:**
- Remove any remaining code duplication
- Optimize bundle size (tree shaking, dead code elimination)
- Improve error handling consistency
- Standardize async/await patterns

**WASM Interface Optimization:**
- Optimize memory management for sensitive data
- Ensure proper cleanup of crypto materials
- Validate error handling between WASM and TypeScript

### Step 3.2: Testing & Validation (1 day)

**Functional Testing:**
- All authentication flows (login, register, TOTP)
- File upload/download operations
- Modal dialogs and UI interactions
- Error handling and edge cases

**Security Testing:**
- Verify no password validation in client-side code
- Confirm sensitive operations happen in WASM
- Validate proper memory cleanup
- Test XSS prevention with TypeScript types

### Step 3.3: Documentation & Cleanup (1 day)

**Update Documentation:**
- Update API documentation for removed device capability endpoints
- Document new WASM interface functions
- Update security documentation to reflect WASM migration
- Create TypeScript development guide

**File Cleanup:**
- Remove old JavaScript files
- Clean up build artifacts
- Update .gitignore for TypeScript builds

## Implementation Strategy

### Development Approach:

- **Incremental Testing**: Test each phase thoroughly before moving to the next

### Risk Mitigation:
- **WASM Compatibility**: Test WASM functions across different browsers
- **Build System Stability**: Keep build process simple and reliable
- **Performance Monitoring**: Measure performance impact of WASM calls
- **Type Safety**: Use strict TypeScript settings to catch issues early

### Success Metrics:

**Security Improvements:**
- ✅ Zero client-side password validation
- ✅ All session management in Go/WASM
- ✅ TOTP validation in Go/WASM
- ✅ Reduced client-side attack surface

**Code Quality Improvements:**
- ✅ 60%+ reduction in client-side code complexity
- ✅ 100% TypeScript type coverage
- ✅ Elimination of device capability detection
- ✅ Clean foundation for Bitcoin wallet integration

**Performance Metrics:**
- ✅ Authentication flow under 5 seconds
- ✅ File operations maintain current performance
- ✅ TypeScript build time under 30 seconds
- ✅ Bundle size optimized (target: under 100KB)

## Future Considerations

### Maintenance Benefits:
- Type safety prevents runtime errors
- Better IDE support for development
- Cleaner separation between UI and security logic
- Easier testing with typed interfaces

### Scalability Planning:
- WASM architecture supports additional crypto operations
- TypeScript enables complex UI state management
- Clean build system supports advanced tooling
- Modular code structure enables feature additions

---

## Implementation Timeline

### Week 1-2: Phase 1 (Security Migration & Cleanup)
- **Days 1-2**: Remove device capability detection
- **Days 3-5**: Migrate password validation to WASM
- **Days 6-7**: Migrate session key derivation to WASM
- **Days 8-10**: Migrate TOTP validation to WASM
- **Days 11-12**: General cleanup and testing

### Week 3: Phase 2 (TypeScript Conversion)
- **Day 1**: TypeScript build setup
- **Days 2-3**: WASM interface typing
- **Days 4-6**: Core TypeScript conversion
- **Day 7**: Build integration & testing

### Week 4: Phase 3 (Optimization & Testing)
- **Days 1-2**: Code optimization
- **Day 3**: Testing & validation
- **Day 4**: Documentation & cleanup

## Conclusion

This TypeScript migration plan addresses the core goals of:
1. **Maximizing Security**: Moving all sensitive operations to Go/WASM
2. **Minimizing Attack Surface**: Removing unnecessary client-side code
3. **Improving Maintainability**: TypeScript for better development experience
4. **Future-Proofing**: Clean foundation for Bitcoin wallet authentication

The result will be a significantly more secure and maintainable codebase with ~60% reduction in client-side complexity, full type safety, and a clean architecture ready for advanced authentication features.

**Key Benefits:**
- ✅ **Security-First Architecture**: All cryptographic operations in Go/WASM
- ✅ **Reduced Complexity**: From 1,500 lines JS to ~800 lines TypeScript
- ✅ **Type Safety**: Catch errors at compile time, not runtime
- ✅ **Clean Foundation**: Ready for Bitcoin wallet integration via auth47
- ✅ **Better Maintainability**: Clear separation of concerns, typed interfaces
- ✅ **Performance**: Optimized bundle size and WASM integration

This plan transforms the JavaScript cleanup challenge into a structured migration that enhances both security and developer experience while preparing for future authentication innovations.
