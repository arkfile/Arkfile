# Fix test-app-curl.sh: File Uploads

## OLD FINDINGS (ALREADY ADDRESSED)

Findings from code review:

1) fix-upload.sh (working reference)
- Uses snake_case for TOTP requests and parses snake_case server fields:
  • TOTP auth payload: {"code":..., "session_key":..., "is_backup": false}
  • Extracts from auth response: .token, .refreshToken (note: this appears camelCase here for refresh; see below), and computes expires_at from JWT exp.
- Client session JSON written as:
  {
    "username": "...",
    "access_token": "...",
    "refresh_token": "...",
    "expires_at": "ISO",
    "server_url": "...",
    "session_created": "ISO"
  }
- Client config JSON:
  { "server_url": "...", "username": "...", "tls_insecure": true, "token_file": "path_to_session_json" }
- Streams arkfile-client upload output to console via tee and fails noisily.

2) handlers/auth.go (server response contract)
- TOTPVerify and TOTPAuth responses use snake_case keys:
  • "token"
  • "refresh_token"
  • "session_key"
  • "auth_method"
- OPAQUE login returns:
  • "requiresTOTP": true
  • "tempToken"
  • "sessionKey"
- TOTP endpoints expect snake_case in requests: "session_key", "is_backup".

3) test-app-curl.sh (current)
- Phase 6 logs showed success for TOTP, so initial login flow is mostly fine. But later, during file upload:
  • It claims “✓ Reusing valid JWT token…”, but debug shows “Token: null…” “Session key: null…”, which means the reuse checks are permissive and allowed null values through.
  • The script builds multiple config/session files in different steps with inconsistent schemas and might mix camelCase vs snake_case extraction. Example issues seen before:
    - Extracting .refreshToken and .sessionKey from snake_case responses → null
    - Writing session JSON with “token” instead of “access_token” → arkfile-client might not pick it up
    - Writing config with “auth_token” instead of “token_file”
  • Upload output was hidden in a file and not printed, making debugging harder.

Conclusion:
- The upload “session expired, please login again” happens because arkfile-client receives an invalid session (token null/empty or wrong field names).
- We need to harden token reuse, correct all JSON key extraction to match server responses, standardize the client config/session schema to the fix-upload.sh format, and add automatic re-auth + retry if session expired.

Detailed plan to implement:

A) Standardize token extraction and storage
- Always extract using correct keys:
  • From OPAQUE login: tempToken, sessionKey
  • From TOTP auth/verify: token, refresh_token, session_key, auth_method
- In test-app-curl.sh:
  • Replace any .refreshToken or .sessionKey reads (where the response is TOTP auth/verify) with .refresh_token and .session_key
  • Replace any .authMethod with .auth_method
- Compute expires_at from JWT exp (like fix-upload.sh) and write session JSON with:
  {
    "username": TEST_USERNAME,
    "access_token": token,
    "refresh_token": refresh_token,
    "expires_at": expires_at_iso,
    "server_url": ARKFILE_BASE_URL,
    "session_created": ISO now
  }
- Config JSON:
  { "server_url": ARKFILE_BASE_URL, "username": TEST_USERNAME, "tls_insecure": true, "token_file": client_session_file }

B) Strict token reuse guard in Phase 9/10
- Only reuse if:
  • session file exists
  • jq -r '.access_token' is not null/empty and not the literal string "null"
  • Quick authenticated API call returns success (200) or at least JSON without error.
- If reuse fails, immediately run fresh authenticate_via_curl() (see C).

C) Add a helper: authenticate_via_curl()
- Perform OPAQUE login → extract tempToken, sessionKey
- Generate TOTP code from saved secret (Phase 4) using generator with padding fix
- POST /api/totp/auth with payload:
  { "code": code, "session_key": sessionKey, "is_backup": false }
- Extract token, refresh_token, session_key (snake_case) and write the session JSON and config JSON as defined in (A)
- Return success only if token is non-empty and not “null”

D) Upload execution and retry
- Invoke arkfile-client upload with:
  /opt/arkfile/bin/arkfile-client --config "$client_config_file" --verbose upload --file "$encrypted" --metadata "$metadata_json" --progress=false 2>&1 | tee "$upload_output_log"
- If exit != 0 OR output contains “session expired” (case-insensitive contains), then:
  • Call authenticate_via_curl()
  • Retry upload once with the new session
- If still failing, print the full log and exit 1

E) Visibility improvements
- When DEBUG_MODE=true:
  • Always stream upload output via tee
  • Also echo paths to config and session files
  • Show token preview (first 16 chars) but not the full token
- On any failure, cat the log file to console; do not hide errors.

F) Remove/replace inconsistent files in current test-app-curl.sh
- There are multiple places where client_config_file and session file are created (e.g., earlier with "auth_token" or "session" variants). Replace them with the single consistent pair used in fix-upload.sh:
  • client_session.json with access_token, refresh_token, expires_at
  • client_config.json with token_file path
- Ensure the upload step references exactly those consistent files.

G) Optional: Pure-curl fallback (guarded by flag)
- If arkfile-client continues to fail, behind a flag we can reuse the older curl-based chunk upload as a fallback.
- Keep disabled by default; not required to unblock Step 11 if auth is correct.

Where to patch in test-app-curl.sh:
- Phase 6 result parsing (snake_case) — validate consistency, but since Phase 6 succeeded earlier, minimal changes may be needed there.
- Phase 9 “Check for existing valid JWT”: strengthen validation and remove reuse if token is “null”.
- Phase 10 “Using arkfile-client for file upload”:
  • Replace ad-hoc config/session creation with fix-upload.sh schema.
  • Add authenticate_via_curl() and retry logic.
  • Stream output via tee and show logs on failure.

After edits, we’ll run:
- bash scripts/testing/test-app-curl.sh --skip-cleanup --debug
Expected result:
- No “Token: null…” logs during reuse; either reuse valid token or perform fresh authentication.
- arkfile-client should not print “session expired…”. If it does, retry logic will re-auth and succeed on the second try.
- Step 11 will execute and we can proceed with metadata decryption investigation.

Implementation:
- Targeted edits in scripts/testing/test-app-curl.sh
- Minimal code duplication: copy helper patterns directly from scripts/wip/fix-upload.sh to ensure schema parity
- Then run the test script with debug to verify upload succeeds and we reach Step 11

---

Plan to fix the token storage issue in Phase 6.

## Root Cause Analysis
The issue is clear from the logs: in Step 9, the script shows `token='null'` even though Phase 6 completed successfully. This means Phase 6 is extracting the token incorrectly due to field name mismatches.

## Detailed Fix Plan

### 1. **Fix Phase 6 Token Extraction (Primary Issue)**
In `phase_totp_authentication()`, the script uses:
```bash
final_token=$(jq -r '.token' "$TEMP_DIR/totp_auth_real.json")
refresh_token=$(jq -r '.refresh_token' "$TEMP_DIR/totp_auth_real.json")
```

**Problem**: The server likely returns camelCase (`refreshToken`) but we're using snake_case (`refresh_token`).

**Fix**: Update all token extractions to use the correct field names that match what the server actually returns.

### 2. **Standardize Field Names Throughout Script**
- Find all instances of token extraction from TOTP auth responses
- Change from snake_case to camelCase (or vice versa) based on what the server actually returns
- Ensure consistency across Phase 6 TOTP auth and the retry logic in Step 9

### 3. **Add Debug Logging**
- Add debug output to show what fields are actually present in the TOTP auth response
- This will prevent future field name mismatches

### 4. **Simplify Step 9 Authentication Logic**
- Remove the complex retry mechanism that's causing TOTP code parsing issues
- If Phase 6 tokens are valid (not null), reuse them directly
- If Phase 6 tokens are invalid, use the working `authenticate_via_curl()` function that's already proven to work

### 5. **Key Changes Needed**
1. **Phase 6**: Fix token extraction field names to match server response
2. **Step 9**: Check for valid tokens from Phase 6 first, only authenticate fresh if needed
3. **TOTP Code Generation**: Fix the debug text parsing issue in retry logic
4. **Session Duration**: Verify why 30-minute tokens are being treated as expired

The core fix is simple: **Phase 6 needs to extract tokens using the correct field names that the server actually returns**.

---

Make `test-app-curl.sh` work exactly like the proven working `fix-upload.sh` for file uploads.

## Key Differences Analysis

### fix-upload.sh (Working):
1. Uses `arkfile-client` binary with `--config` file approach
2. Creates proper client session JSON with JWT token
3. Uses pre-encrypted file + metadata JSON approach
4. Handles authentication through config file

### test-app-curl.sh (Broken):
1. Uses direct `curl` commands to API endpoints
2. Manual HTTP request construction
3. Different authentication approach (direct JWT in headers)

## Solution: Hybrid Approach

The cleanest fix would be to **replace the curl-based upload logic in test-app-curl.sh Step 10 with the proven arkfile-client approach from fix-upload.sh**.

Here's what we need to do:

### 1. Extract Working Code from fix-upload.sh
Copy these functions from `fix-upload.sh`:
- File encryption logic using `cryptocli encrypt-password`
- Metadata generation using `cryptocli encrypt-metadata`
- FEK generation and encryption using `cryptocli encrypt-fek`
- Client config file creation (JWT-based auth)
- The actual `arkfile-client upload` command

### 2. Modify test-app-curl.sh Step 10
Instead of the complex curl retry logic, use the same pattern:
```bash
# When upload fails, re-authenticate test user (already working)
# Create client config file (copy from fix-upload.sh)
# Use arkfile-client upload command (copy from fix-upload.sh)
```

### 3. Benefits
- Eliminates TOTP parsing issues entirely
- Uses proven working upload method
- Maintains the same test user authentication
- Simpler and more reliable than fixing curl approach

### 4. Preserve Existing Functionality
Keep all the other test-app-curl.sh logic (admin auth, user setup, file metadata decryption testing) and only replace the problematic upload portion.

This approach leverages what already works instead of debugging the complex curl-based upload logic.

---

Use one jwt_token file. Having multiple JWT token files (`final_jwt_token`, `step9_final_token`, etc.) for the same user account is unnecessarily complex and creates the exact kind of synchronization issues we just fixed.

The script should indeed use a single `jwt_token` file throughout the entire workflow. Here's why this makes more sense:

**Current Problem:**
- Multiple token files: `final_jwt_token`, `step9_final_token`, `login_temp_token`, etc.
- Creates confusion about which token is "current"
- Leads to synchronization issues where one file has "null" while another has a valid token
- Makes debugging harder

**Better Approach:**
- Single `jwt_token` file that gets updated as the authentication progresses
- Each phase either reads the existing valid token or updates it with a fresh one
- Much simpler token lifecycle management
- Easier to debug - just check one file

**Proposed Token Lifecycle:**
1. **Phase 5 (Login)**: Creates `temp_token` (temporary, pre-TOTP)
2. **Phase 6 (TOTP Auth)**: Upgrades to `jwt_token` (final, post-TOTP)
3. **Phase 9 (File Ops)**: Reuses `jwt_token` if valid, or refreshes it
4. **All other phases**: Simply use `jwt_token`

This would eliminate the token storage bug entirely and make the script much more maintainable. The fix I implemented works, but you're right that consolidating to a single token file would be the cleaner architectural solution.

Refactor the script to use a single token file approach instead of the current multi-file system.

---

## NEW FINDINGS

### Fix all remaining instances of JSON field names that aren't yet using snake case.

**Revised, Comprehensive, and Final Plan:**

**Phase 1: Standardize the Go Server Application API**

1.  **Full Server Code Review:** Systematically review all Go handler files (`handlers/*.go`) and model files (`models/*.go`).
2.  **Enforce `snake_case` in All API Responses:** Modify all `c.JSON(...)` calls that return `map[string]interface{}` to use `snake_case` keys. For example, `tempToken` becomes `temp_token`, `sessionKey` becomes `session_key`, `requiresTOTP` becomes `requires_totp`, etc.
3.  **Verify Struct Tags:** Audit all structs used in API requests and responses to ensure their `json:"..."` tags are consistently `snake_case`.

**Phase 2: Standardize All Go Client-Side Code**

4.  **`arkfile-client` (`cmd/arkfile-client/`):** Review the main client application code. Update any structs that model API responses to expect `snake_case` fields.
5.  **`client/main.go`:** Review this file, which seems to contain shared client logic. Update any API-interacting code to expect `snake_case` responses.
6.  **Core Libraries:** Investigate any core libraries under the `client/` or `crypto/` directories that are used by the CLI tools. Any code that defines structs for unmarshalling server responses will be updated to use `snake_case` fields. I will pay special attention to anything related to session management or metadata handling.
7.  **`arkfile-admin` & `cryptocli`:** Although these are not explicitly mentioned in the file list, I will assume their source is in the `cmd/` directory and will apply the same `snake_case` standardization to them.

**Phase 3: Standardize the TypeScript Web Client**

8.  **Web Client Code (`client/static/js/src/`):** Search the TypeScript codebase for all `fetch` or `axios` calls to the backend. Update the code that handles the JSON responses to expect `snake_case` fields instead of `camelCase`.

**Phase 4: Update and Verify with Test Scripts**

9.  **Standardize Shell Scripts (`scripts/testing/`):** Once all Go and TypeScript code has been standardized, I will update `test-app-curl.sh` and `fix-upload.sh`. This involves:
    *   Changing all `jq` parsing expressions from `.camelCase` to `.snake_case` (e.g., `.tempToken` -> `.temp_token`).
    *   Verifying that all `jq` *payload creation* correctly uses `snake_case`, which I believe is already mostly true.
10. **Final Validation:** After all changes are made, the successful execution of the `test-app-curl.sh` script will serve as the final validation that the entire stack is now consistent and the original upload bug is resolved.

---

