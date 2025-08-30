# Unified Argon2ID Encryption Cleanup and Refactoring: Current State

This document describes the successful refactoring of the Arkfile project to use a unified Argon2ID key derivation for all file encryption and decryption. This refactoring has eliminated OPAQUE Export Key-based derivation for file content and File Encryption Key (FEK) protection. All critical cryptographic functions are now centralized in the `crypto` library for consistent use across `cryptocli` and `arkfile-client`/WASM.

**Crucially, OPAQUE is now used solely for user authentication (OPAQUE protocol) and is explicitly NOT used for deriving or encrypting file keys or file content. File encryption keys are derived exclusively from user passwords via Argon2ID.**

## Reference Documents

*   `scripts/testing/test-app-curl.sh`: Master App Testing Script
*   `docs/wip/test-app.md`: Original Test App Plan (pre-unified Argon2ID decision) - *Note: This document may be outdated and is subject to review.*

## Phases for Unified Argon2ID Encryption Refactoring (Completed)

### Phase 1: Cryptographic Model Transition (Completed)

*   **Goal Achieved:** All OPAQUE Export Key-based key derivation for file and FEK encryption/decryption has been removed. FEK protection is now centralized.
*   **Actions Taken:**
    *   **Removed Obsolete Commands from `cryptocli`:** Commands that relied on OPAQUE Export Keys for encryption were removed from `cmd/cryptocli/main.go`, and its `Usage` text updated.
    *   **Centralized FEK Protection Logic in `crypto/`:** New functions in `crypto/` (e.g., `EncryptFEKWithPassword`, `DecryptFEKWithPassword`) were created and implemented for encrypting/decrypting the FEK using a key derived from the user's password via Argon2ID.
    *   **Adapted `arkfile-client` for New FEK Protection:** `cmd/arkfile-client/main.go`'s `handleUploadCommand` and `handleDownloadCommand` were modified to use the new `crypto/` FEK protection functions. The `OPAQUEExport` field from the `AuthSession` struct and related handling were removed. Secure password prompting was implemented in `arkfile-client` for FEK protection during upload/download.

### Phase 2: `cryptocli` Tool Consolidation and Alignment (Completed)

*   **Goal Achieved:** `cryptocli` now exclusively uses the centralized `crypto/` library for its functions and aligns completely with the new encryption model.
*   **Actions Taken:**
    *   **Refactored `generate-test-file`:** `cmd/cryptocli/main.go`'s `handleGenerateTestFileCommand` was updated to use `crypto.GenerateTestFileToPath` and consistent `crypto.FilePattern` enums.

### Phase 3: `test-app-curl.sh` Integration and Refactoring (Completed)

*   **Goal Achieved:** The `test-app-curl.sh` script has been adapted to comprehensively test the new unified Argon2ID encryption workflow.
*   **Actions Taken:**
    *   **Refactored `phase_9_file_operations`:** This phase in `test-app-curl.sh` was updated to implement and test the new password-based (Argon2ID) file encryption/decryption model using the refactored `cryptocli` and `arkfile-client` tools.
    *   **Streamlined Auth Export in Tests:** The `authenticate_with_client_tool` function, which previously exported `opaque_export_key.hex` for file-related purposes within `test-app-curl.sh`, has been removed, ensuring no OPAQUE key export for file encryption.
    *   **Secure Password Handling in Tests:** `TEST_PASSWORD` is now supplied securely to `cryptocli` and `arkfile-client` commands within the script, demonstrating proper password handling.

### Phase 4: Cleanup and Verification (Completed)

*   **Goal Achieved:** The codebase is clean, and the new system is fully functional and verified.
*   **Actions Taken:**
    *   **General Code Cleanup:** All remaining dead code or references to the old OPAQUE Export Key-based file encryption model have been removed.
    *   **Comprehensive Test Validation:** The complete `test-app-curl.sh` suite has been run to verify all phases, especially the refactored `phase_9_file_operations`, which confirms the new encryption model's correct functionality.
