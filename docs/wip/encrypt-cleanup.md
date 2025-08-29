# Unified Argon2ID Encryption Cleanup and Refactoring Plan

This document outlines the phases for refactoring the Arkfile project to use a unified Argon2ID key derivation for all file encryption and decryption, eliminating OPAQUE Export Key-based derivation for file content and File Encryption Key (FEK) protection. All critical cryptographic functions will be centralized in the `crypto` library for consistent use across `cryptocli` and `arkfile-client`/WASM.

## Reference Documents

*   `scripts/testing/test-app-curl.sh`: Master App Testing Script
*   `docs/wip/test-app.md`: Original Test App Plan (pre-unified Argon2ID decision)

## Phases for Unified Argon2ID Encryption Refactoring

### Phase 1: Cryptographic Model Transition

*   **Goal:** Remove all OPAQUE Export Key-based key derivation for file and FEK encryption/decryption. Centralize FEK protection.
*   **Actions:**
    *   **Remove Obsolete Commands from `cryptocli`:** Delete `handleEncryptCommand` and `handleDecryptCommand` from `cmd/cryptocli/main.go` and update its `Usage` text.
    *   **Centralize FEK Protection Logic in `crypto/`:**
        *   Create new functions in `crypto/` (e.g., `EncryptFEKWithPassword`, `DecryptFEKWithPassword`) for encrypting/decrypting the FEK using a key derived from the user's password via Argon2ID.
    *   **Adapt `arkfile-client` for New FEK Protection:**
        *   Modify `cmd/arkfile-client/main.go`'s `handleUploadCommand` and `handleDownloadCommand` to use the new `crypto/` FEK protection functions.
        *   Remove the `OPAQUEExport` field from the `AuthSession` struct and related handling in `cmd/arkfile-client/main.go`.
        *   Implement secure password prompting in `arkfile-client` for FEK protection during upload/download.

### Phase 2: `cryptocli` Tool Consolidation and Alignment

*   **Goal:** Ensure `cryptocli` exclusively uses the centralized `crypto/` library for its functions and aligns with the new encryption model.
*   **Actions:**
    *   **Refactor `generate-test-file`:** Update `cmd/cryptocli/main.go`'s `handleGenerateTestFileCommand` to use `crypto.GenerateTestFileToPath` and consistent `crypto.FilePattern` enums.

### Phase 3: `test-app-curl.sh` Integration and Refactoring

*   **Goal:** Adapt the `test-app-curl.sh` script to test the new unified Argon2ID encryption workflow.
*   **Actions:**
    *   **Refactor `phase_9_file_operations`:** Update this existing phase in `test-app-curl.sh` to implement and test the new password-based (Argon2ID) file encryption/decryption model using the refactored `cryptocli` and `arkfile-client` tools.
    *   **Streamline Auth Export in Tests:** Modify `authenticate_with_client_tool` in `test-app-curl.sh` to no longer export `opaque_export_key.hex` for file-related purposes.
    *   **Secure Password Handling in Tests:** Ensure `TEST_PASSWORD` is supplied securely to `cryptocli` and `arkfile-client` commands within the script.

### Phase 4: Cleanup and Verification

*   **Goal:** Ensure the codebase is clean and the new system is fully functional and verified.
*   **Actions:**
    *   **General Code Cleanup:** Remove any remaining dead code or references to the old OPAQUE Export Key-based file encryption model.
    *   **Comprehensive Test Validation:** Run the complete `test-app-curl.sh` suite to verify all phases, especially the refactored `phase_9_file_operations` which tests the new encryption model.
