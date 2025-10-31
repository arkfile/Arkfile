# Password Validation Improvements Plan

## Overview

This document outlines the comprehensive plan to improve password validation across the Arkfile project. The primary goals are:

1. Establish a single source of truth for all password requirements
2. Implement real-time password feedback in the browser
3. Fix validation mismatch between CLI and browser
4. Ensure CLI and browser use identical validation logic
5. Remove all hardcoded password length values

## Current Issues

### Issue 1: Validation Mismatch
- **Frontend (TypeScript)**: Enforces 18 characters for share passwords
- **Backend (Go)**: `ValidateSharePassword()` uses 14 characters (incorrect)
- **Impact**: Inconsistent validation between CLI and browser

### Issue 2: Hardcoded Values
- Password length requirements (14, 18) are hardcoded in multiple places
- No single source of truth for constants
- Difficult to maintain and prone to inconsistencies

### Issue 3: Poor User Feedback
- No real-time password requirement checking in browser (or what is there is broken)
- Generic error messages on registration failure
- Users don't know what's wrong with their password until submission

## Solution Architecture

### Single Source of Truth
All password requirements will be defined as constants in `crypto/password_validation.go`:
- `MinAccountPasswordLength = 14` (for user account registration)
- `MinCustomPasswordLength = 14` (for custom file encryption passwords, may differ from account passwords in future)
- `MinSharePasswordLength = 18` (for file sharing passwords)
- `MinEntropyBits = 60.0` (entropy requirement for all password types)

These constants will be:
- Used directly by Go code (CLI tools, backend)
- Exposed via WASM to browser
- Used by TypeScript for validation and UI

**Note:** While `MinAccountPasswordLength` and `MinCustomPasswordLength` are initially set to the same value (14), they are separate constants to allow for independent adjustment in the future if requirements diverge.

### Validation Flow
```
User Input → WASM Function → Go Validation Logic → JSON Result → TypeScript UI Update
```

## Implementation Plan

**IMPORTANT: Read AGENTS.md again before beginning each phase.**

### Phase 1: Backend Changes

**Before starting: Read AGENTS.md again.**

#### 1.1 crypto/password_validation.go

**Add constants at package level:**
```go
const (
    MinAccountPasswordLength = 14
    MinCustomPasswordLength = 14
    MinSharePasswordLength   = 18
    MinEntropyBits          = 60.0
)
```

**Export existing function:**
- Change `checkPasswordRequirements` to `CheckPasswordRequirements` (capitalize)
- Keep all existing logic unchanged
- This function already has correct implementation

**Fix ValidateSharePassword:**
```go
func ValidateSharePassword(password string) *PasswordValidationResult {
    result := ValidatePasswordEntropy(password, MinEntropyBits)
    // Override requirements to use 18-char minimum for shares
    result.Requirements = CheckPasswordRequirements(password, MinSharePasswordLength)
    return result
}
```

**Update other functions to use constants:**
- `ValidateAccountPassword`: Use `MinEntropyBits`
- `ValidateCustomPassword`: Use `MinEntropyBits`
- Internal calls: Replace hardcoded `14` with `MinAccountPasswordLength` and/or `MinCustomPasswordLength`

#### 1.2 crypto/wasm_shim.go

**Add new WASM exports:**

```go
//export GetPasswordConstants
func GetPasswordConstants() string {
    constants := map[string]interface{}{
        "min_account_password_length": MinAccountPasswordLength,
        "min_custom_password_length":  MinCustomPasswordLength,
        "min_share_password_length":   MinSharePasswordLength,
        "min_entropy_bits":            MinEntropyBits,
    }
    jsonBytes, _ := json.Marshal(constants)
    return string(jsonBytes)
}

//export CheckAccountPasswordRequirements
func CheckAccountPasswordRequirements(password string) string {
    result := CheckPasswordRequirements(password, MinAccountPasswordLength)
    jsonBytes, _ := json.Marshal(result)
    return string(jsonBytes)
}

//export CheckCustomPasswordRequirements
func CheckCustomPasswordRequirements(password string) string {
    result := CheckPasswordRequirements(password, MinCustomPasswordLength)
    jsonBytes, _ := json.Marshal(result)
    return string(jsonBytes)
}

//export CheckSharePasswordRequirements
func CheckSharePasswordRequirements(password string) string {
    result := CheckPasswordRequirements(password, MinSharePasswordLength)
    jsonBytes, _ := json.Marshal(result)
    return string(jsonBytes)
}
```

#### 1.3 cmd/arkfile-client/main.go

**Replace hardcoded values:**
- Find all instances of hardcoded `14` and replace with `crypto.MinAccountPasswordLength` / `crypto.MinCustomPasswordLength`
- Find all instances of hardcoded `18` and replace with `crypto.MinSharePasswordLength`
- Use `crypto.CheckPasswordRequirements()` for detailed validation feedback
- Improve error messages to show specific requirement failures

**After completing Phase 1: Redeploy with dev-reset.sh (a sudo script) and then re-run test-app-curl.sh. Make sure all tests pass in full before proceeding with Phase 2.**

---

### Phase 2: Frontend Types & Constants

**Before starting: Read AGENTS.md again.**

#### 2.1 client/static/js/src/types/wasm.d.ts

**Add new interfaces:**
```typescript
interface PasswordConstants {
    min_account_password_length: number;
    min_custom_password_length: number;
    min_share_password_length: number;
    min_entropy_bits: number;
}

interface RequirementStatus {
    met: boolean;
    current?: number;
    needed?: number;
    message: string;
}

interface RequirementChecks {
    length: RequirementStatus;
    uppercase: RequirementStatus;
    lowercase: RequirementStatus;
    number: RequirementStatus;
    special: RequirementStatus;
}
```

**Add WASM method signatures:**
```typescript
interface WasmModule {
    // ... existing methods ...
    GetPasswordConstants(): string;
    CheckAccountPasswordRequirements(password: string): string;
    CheckCustomPasswordRequirements(password: string): string;
    CheckSharePasswordRequirements(password: string): string;
}
```

#### 2.2 client/static/js/src/utils/password-constants.ts (NEW FILE)

**Create helper module:**
```typescript
import { getWasmModule } from './wasm';

let cachedConstants: PasswordConstants | null = null;

export async function getPasswordConstants(): Promise<PasswordConstants> {
    if (cachedConstants) {
        return cachedConstants;
    }
    
    const wasm = await getWasmModule();
    const constantsJson = wasm.GetPasswordConstants();
    cachedConstants = JSON.parse(constantsJson);
    return cachedConstants;
}

export interface PasswordConstants {
    min_account_password_length: number;
    min_custom_password_length: number;
    min_share_password_length: number;
    min_entropy_bits: number;
}
```

**After completing Phase 2: Redeploy with dev-reset.sh (a sudo script) and then re-run test-app-curl.sh. Make sure all tests pass in full before proceeding with Phase 3.**

---

### Phase 3: Real-Time Registration Feedback

**Before starting: Read AGENTS.md again.**

#### 3.1 client/static/index.html

**Add password requirements UI in registration form:**
```html
<div id="password-requirements" class="requirements-list" style="display: none;">
    <h4>Password Requirements:</h4>
    <ul>
        <li id="req-length" class="requirement-unmet">
            <span class="req-icon">[ ]</span> <span id="req-length-text">Minimum length required</span>
        </li>
        <li id="req-uppercase" class="requirement-unmet">
            <span class="req-icon">[ ]</span> Uppercase letter (A-Z)
        </li>
        <li id="req-lowercase" class="requirement-unmet">
            <span class="req-icon">[ ]</span> Lowercase letter (a-z)
        </li>
        <li id="req-number" class="requirement-unmet">
            <span class="req-icon">[ ]</span> Number (0-9)
        </li>
        <li id="req-special" class="requirement-unmet">
            <span class="req-icon">[ ]</span> Special character
        </li>
        <li id="req-entropy" class="requirement-unmet">
            <span class="req-icon">[ ]</span> Strong and unpredictable
        </li>
    </ul>
    <div id="password-suggestions" class="suggestions"></div>
</div>
```

**Remove hardcoded minlength:**
- Remove `minlength="14"` from password input
- Will be set dynamically via JavaScript

#### 3.2 client/static/css/styles.css

**Add new styles:**
```css
.requirements-list {
    margin: 15px 0;
    padding: 15px;
    border: 1px solid #dee2e6;
    border-radius: 4px;
    background-color: #f8f9fa;
}

.requirements-list h4 {
    margin-top: 0;
    margin-bottom: 10px;
    font-size: 14px;
    color: var(--primary-color);
}

.requirements-list ul {
    list-style: none;
    padding: 0;
    margin: 0;
}

.requirements-list li {
    padding: 5px 0;
    font-size: 13px;
}

.requirement-met {
    color: var(--success-color);
}

.requirement-met .req-icon {
    content: '[OK]';
    font-weight: bold;
}

.requirement-unmet {
    color: #6c757d;
}

.suggestions {
    margin-top: 10px;
    padding: 10px;
    background-color: #fff3cd;
    border: 1px solid #ffeaa7;
    border-radius: 4px;
    font-size: 13px;
    color: #856404;
}

.suggestions:empty {
    display: none;
}
```

#### 3.3 client/static/js/src/auth/register.ts

**Import required modules:**
```typescript
import { getPasswordConstants } from '../utils/password-constants';
import { getWasmModule } from '../utils/wasm';
```

**On page load:**
```typescript
async function initializePasswordValidation() {
    const constants = await getPasswordConstants();
    const passwordInput = document.getElementById('password') as HTMLInputElement;
    
    // Set minlength dynamically
    if (passwordInput) {
        passwordInput.setAttribute('minlength', constants.min_account_password_length.toString());
    }
    
    // Update requirement text dynamically
    const lengthReqText = document.getElementById('req-length-text');
    if (lengthReqText) {
        lengthReqText.textContent = `At least ${constants.min_account_password_length} characters`;
    }
}
```

**Add input event listener:**
```typescript
passwordInput.addEventListener('input', async () => {
    const password = passwordInput.value;
    const requirementsList = document.getElementById('password-requirements');
    
    // Show requirements list when user starts typing
    if (password.length > 0 && requirementsList) {
        requirementsList.style.display = 'block';
    }
    
    // Get requirement status from WASM
    const wasm = await getWasmModule();
    const requirementsJson = wasm.CheckAccountPasswordRequirements(password);
    const requirements: RequirementChecks = JSON.parse(requirementsJson);
    
    // Update each requirement indicator
    updateRequirement('length', requirements.length);
    updateRequirement('uppercase', requirements.uppercase);
    updateRequirement('lowercase', requirements.lowercase);
    updateRequirement('number', requirements.number);
    updateRequirement('special', requirements.special);
    updateRequirement('entropy', requirements.entropy);
    
    // Show suggestions if any requirements not met
    updateSuggestions(requirements);
});

function updateRequirement(id: string, status: RequirementStatus) {
    const element = document.getElementById(`req-${id}`);
    if (!element) return;
    
    if (status.met) {
        element.className = 'requirement-met';
        const icon = element.querySelector('.req-icon');
        if (icon) icon.textContent = '[OK]';
    } else {
        element.className = 'requirement-unmet';
        const icon = element.querySelector('.req-icon');
        if (icon) icon.textContent = '[ ]';
    }
}

function updateSuggestions(requirements: RequirementChecks) {
    const suggestionsDiv = document.getElementById('password-suggestions');
    if (!suggestionsDiv) return;
    
    const unmetRequirements: string[] = [];
    
    if (!requirements.length.met) unmetRequirements.push(requirements.length.message);
    if (!requirements.uppercase.met) unmetRequirements.push(requirements.uppercase.message);
    if (!requirements.lowercase.met) unmetRequirements.push(requirements.lowercase.message);
    if (!requirements.number.met) unmetRequirements.push(requirements.number.message);
    if (!requirements.special.met) unmetRequirements.push(requirements.special.message);
    if (!requirements.entropy.met) unmetRequirements.push(requirements.entropy.message);
    
    if (unmetRequirements.length > 0) {
        suggestionsDiv.innerHTML = '<strong>To improve:</strong><br>' + unmetRequirements.join('<br>');
        suggestionsDiv.style.display = 'block';
    } else {
        suggestionsDiv.style.display = 'none';
    }
}
```

**Enhance register button handler:**
```typescript
registerButton.addEventListener('click', async () => {
    const password = passwordInput.value;
    
    // Check requirements before submitting
    const wasm = await getWasmModule();
    const requirementsJson = wasm.CheckAccountPasswordRequirements(password);
    const requirements: RequirementChecks = JSON.parse(requirementsJson);
    
    // Check if all requirements are met
    const allMet = requirements.length.met && 
                   requirements.uppercase.met && 
                   requirements.lowercase.met && 
                   requirements.number.met && 
                   requirements.special.met && 
                   requirements.entropy.met;
    
    if (!allMet) {
        // Show specific error with unmet requirements
        const unmetList = [];
        if (!requirements.length.met) unmetList.push(requirements.length.message);
        if (!requirements.uppercase.met) unmetList.push(requirements.uppercase.message);
        if (!requirements.lowercase.met) unmetList.push(requirements.lowercase.message);
        if (!requirements.number.met) unmetList.push(requirements.number.message);
        if (!requirements.special.met) unmetList.push(requirements.special.message);
        if (!requirements.entropy.met) unmetList.push(requirements.entropy.message);
        
        showError('Password does not meet requirements:\n' + unmetList.join('\n'));
        return;
    }
    
    // Proceed with existing validation and registration
    const validationJson = wasm.ValidateAccountPassword(password);
    // ... rest of registration logic
});
```

**After completing Phase 3: Redeploy with dev-reset.sh (a sudo script) and then re-run test-app-curl.sh. Make sure all tests pass in full before proceeding with Phase 4.**

---

### Phase 4: Share Password Validation

**Before starting: Read AGENTS.md again.**

#### 4.1 client/static/js/src/shares/share-crypto.ts

**Remove hardcoded check:**
```typescript
// REMOVE:
if (!password || password.length < 18) {
    return {
        success: false,
        error: 'Share password must be at least 18 characters'
    };
}

// REPLACE WITH:
import { getPasswordConstants } from '../utils/password-constants';

const constants = await getPasswordConstants();
if (!password || password.length < constants.min_share_password_length) {
    return {
        success: false,
        error: `Share password must be at least ${constants.min_share_password_length} characters`
    };
}
```

**Use WASM validation:**
```typescript
public static async validateSharePassword(password: string): Promise<ValidationResult> {
    const wasm = await getWasmModule();
    const requirementsJson = wasm.CheckSharePasswordRequirements(password);
    const requirements: RequirementChecks = JSON.parse(requirementsJson);
    
    const allMet = requirements.length.met && 
                   requirements.uppercase.met && 
                   requirements.lowercase.met && 
                   requirements.number.met && 
                   requirements.special.met && 
                   requirements.entropy.met;
    
    return {
        success: allMet,
        requirements: requirements,
        error: allMet ? undefined : 'Password does not meet requirements'
    };
}
```

#### 4.2 client/static/js/src/shares/share-access.ts

**Remove hardcoded check:**
```typescript
// REMOVE:
if (!password || password.length < 18) {
    return {
        success: false,
        error: 'Password must be at least 18 characters'
    };
}

// REPLACE WITH:
import { getPasswordConstants } from '../utils/password-constants';

const constants = await getPasswordConstants();
if (!password || password.length < constants.min_share_password_length) {
    return {
        success: false,
        error: `Password must be at least ${constants.min_share_password_length} characters`
    };
}
```

**Add detailed validation:**
```typescript
const wasm = await getWasmModule();
const requirementsJson = wasm.CheckSharePasswordRequirements(password);
const requirements: RequirementChecks = JSON.parse(requirementsJson);

if (!allRequirementsMet(requirements)) {
    return {
        success: false,
        error: 'Password does not meet requirements',
        requirements: requirements
    };
}
```

#### 4.3 client/static/js/src/shares/share-creation.ts

**Add real-time feedback:**
- Similar to registration, add input event listener
- Use `CheckSharePasswordRequirements` instead of account variant
- Update UI to show 18-char requirement dynamically

**Remove hardcoded values:**
```typescript
// REMOVE:
placeholder="Enter a strong password (18+ characters)"
minlength="18"

// REPLACE WITH:
// Set dynamically after loading constants
const constants = await getPasswordConstants();
passwordInput.setAttribute('minlength', constants.min_share_password_length.toString());
passwordInput.setAttribute('placeholder', `Enter a strong password (${constants.min_share_password_length}+ characters)`);
```

#### 4.4 client/static/js/src/files/share-integration.ts

**Remove hardcoded minlength:**
```typescript
// REMOVE:
minlength="18"

// REPLACE WITH:
// Set dynamically
const constants = await getPasswordConstants();
const passwordInput = shareForm.querySelector('#share-password') as HTMLInputElement;
if (passwordInput) {
    passwordInput.setAttribute('minlength', constants.min_share_password_length.toString());
}
```

#### 4.5 HTML Files

**client/static/file-share.html:**
- Remove `minlength="18"` from password inputs
- Add requirement list UI (similar to registration)
- Will be set dynamically via JavaScript

**client/static/shared.html:**
- Remove `minlength="18"` from password inputs
- Add requirement list UI
- Will be set dynamically via JavaScript

**After completing Phase 4: Redeploy with dev-reset.sh (a sudo script) and then re-run test-app-curl.sh. Make sure all tests pass in full before proceeding with Phase 5.**

---

### Phase 5: Testing & Validation

**Before starting: Read AGENTS.md again.**

#### 5.1 Test CLI Tools

**Test arkfile-client:**
```bash
# Test with short password (should fail)
./arkfile-client register testuser "short"

# Test with weak password (should show specific failures)
./arkfile-client register testuser "password123456"

# Test with strong password (should succeed)
./arkfile-client register testuser "MySecureP@ssw0rd2025!*TRIXAREFORKIDS!"
```

**Verify:**
- CLI uses constants (not hardcoded values)
- Shows detailed requirement failures
- Account passwords require 14+ chars
- Custom passwords require 14+ chars
- Share passwords require 18+ chars

#### 5.2 Test Browser

**Test registration:**
1. Navigate to registration page
2. Start typing password
3. Verify requirements list appears
4. Verify real-time updates as you type
5. Verify each requirement shows met/unmet status
6. Try to register with weak password
7. Verify detailed error message
8. Register with strong password
9. Verify success


#### 5.3 Verify Consistency

**Check for hardcoded values:**
```bash
# Search for hardcoded 14
grep -r "14" --include="*.go" --include="*.ts" | grep -i password

# Search for hardcoded 18
grep -r "18" --include="*.go" --include="*.ts" | grep -i password

# Should only find constant definitions, not hardcoded usage
```

**Test custom password validation:**
- Test custom password encryption in CLI
- Verify 14-char minimum is enforced
- Verify detailed error messages for custom passwords
- Test in browser if custom password UI exists

**Verify CLI and browser match:**
- Test same password in CLI and browser
- Verify identical validation results
- Verify identical error messages
- Verify identical requirement checking

**After completing Phase 5: Redeploy with dev-reset.sh (a sudo script) and then re-run test-app-curl.sh. Make sure all tests pass in full before proceeding with Phase 6.**

---

### Phase 6: Documentation Updates

**Before starting: Read AGENTS.md again.**

#### Update existing docs if needed:
- `docs/api.md` - Document password requirements
- `docs/security.md` - Update password policy section
- `README.md` - Update if password requirements mentioned


---

## Files Modified

### Backend (Go)
1. `crypto/password_validation.go` - Add constants, export function, fix share validation
2. `crypto/wasm_shim.go` - Add WASM exports
3. `cmd/arkfile-client/main.go` - Use constants instead of hardcoded values

### Frontend (TypeScript)
4. `client/static/js/src/types/wasm.d.ts` - Add new interfaces and method signatures
5. `client/static/js/src/utils/password-constants.ts` - NEW: Helper module
6. `client/static/js/src/auth/register.ts` - Add real-time feedback
7. `client/static/js/src/shares/share-crypto.ts` - Remove hardcoded values
8. `client/static/js/src/shares/share-access.ts` - Remove hardcoded values
9. `client/static/js/src/shares/share-creation.ts` - Add real-time feedback
10. `client/static/js/src/files/share-integration.ts` - Remove hardcoded values

### HTML/CSS
11. `client/static/index.html` - Add requirements UI
12. `client/static/file-share.html` - Remove hardcoded minlength
13. `client/static/shared.html` - Remove hardcoded minlength
14. `client/static/css/styles.css` - Add requirement styles

### Documentation
15. `docs/wip/password-fixes.md` - This document

## Success Criteria

1. All password length requirements come from single source (crypto/password_validation.go constants)
2. Three separate password type constants exist: account (14), custom (14), share (18)
3. CLI and browser use identical validation logic for all password types
4. Real-time password feedback works in browser
5. Detailed error messages on registration failure
6. Account passwords correctly require 14 characters
7. Custom passwords correctly require 14 characters
8. Share passwords correctly require 18 characters (not 14)
9. No hardcoded password length values anywhere
10. All tests pass
11. CLI and browser show identical validation results for all password types

---

## Notes

- This is a greenfield application with no current deployments
- Share password validation changes from 14 to 18 character minimum
- No migration strategy needed as there are no existing deployments
- Account and custom passwords both start at 14 characters minimum, but use separate constants to allow independent adjustment in the future
- Custom passwords are used for file encryption and may have different requirements than account passwords in future versions
