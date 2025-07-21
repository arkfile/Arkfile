#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include <stdlib.h>

#include "../../vendor/stef/libopaque/src/opaque.h"

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int test_registration_and_login() {
    printf("\n=== Testing Complete OPAQUE Registration and Login Flow ===\n\n");
    
    // Test credentials
    const char *username = "alice";
    const char *password = "correct horse battery staple";
    uint16_t pwdU_len = strlen(password);
    
    // Server configuration
    const uint8_t cfg[OPAQUE_CFG_LEN] = {0}; // Default config
    
    // Generate server keypair
    uint8_t skS[crypto_scalarmult_SCALARBYTES];
    uint8_t pkS[crypto_scalarmult_BYTES];
    crypto_scalarmult_base(pkS, skS);
    
    printf("Server public key generated\n");
    
    // REGISTRATION PHASE
    printf("\n--- Registration Phase ---\n");
    
    // Step 1: Client creates registration request
    uint8_t M[crypto_core_ristretto255_BYTES];
    uint8_t sec[OPAQUE_REGISTER_USER_SEC_LEN + pwdU_len];
    
    int ret = opaque_CreateRegistrationRequest(
        (const uint8_t *)password, pwdU_len, sec, M);
    
    if (ret != 0) {
        printf("ERROR: CreateRegistrationRequest failed: %d\n", ret);
        return 1;
    }
    printf("Client: Registration request created\n");
    
    // Step 2: Server creates registration response
    uint8_t secS[OPAQUE_REGISTER_SECRET_LEN];
    uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN];
    
    ret = opaque_CreateRegistrationResponse(M, secS, pub);
    if (ret != 0) {
        printf("ERROR: CreateRegistrationResponse failed: %d\n", ret);
        return 1;
    }
    printf("Server: Registration response created\n");
    
    // Step 3: Client finalizes registration
    uint8_t rec[OPAQUE_REGISTRATION_RECORD_LEN];
    uint8_t export_key[crypto_hash_sha512_BYTES];
    
    Opaque_Ids ids = {
        .idU = (uint8_t *)username,
        .idU_len = strlen(username),
        .idS = NULL,
        .idS_len = 0
    };
    
    ret = opaque_FinalizeRequest(
        sec, pub, &ids, cfg, rec, export_key);
    
    if (ret != 0) {
        printf("ERROR: FinalizeRequest failed: %d\n", ret);
        return 1;
    }
    printf("Client: Registration finalized\n");
    printf("Export key length: %zu\n", sizeof(export_key));
    
    // Store registration record
    uint8_t recU[OPAQUE_USER_RECORD_LEN];
    opaque_StoreUserRecord(secS, rec, recU);
    printf("Server: User record stored\n");
    
    // LOGIN PHASE
    printf("\n--- Login Phase ---\n");
    
    // Step 1: Client creates credential request
    uint8_t secU[OPAQUE_USER_SESSION_SECRET_LEN + pwdU_len];
    uint8_t ke1[OPAQUE_USER_SESSION_PUBLIC_LEN];
    
    ret = opaque_CreateCredentialRequest(
        (const uint8_t *)password, pwdU_len, secU, ke1);
    
    if (ret != 0) {
        printf("ERROR: CreateCredentialRequest failed: %d\n", ret);
        return 1;
    }
    printf("Client: Credential request (KE1) created\n");
    
    // Step 2: Server creates credential response
    uint8_t sec_s[OPAQUE_SERVER_SESSION_LEN];
    uint8_t ke2[OPAQUE_SERVER_PUBLICDATABYTES];
    
    Opaque_App_Infos infos = {
        .info = NULL,
        .info_len = 0,
        .einfo = NULL,
        .einfo_len = 0
    };
    
    ret = opaque_CreateCredentialResponse(
        ke1, recU, &ids, &infos, sec_s, ke2);
    
    if (ret != 0) {
        printf("ERROR: CreateCredentialResponse failed: %d\n", ret);
        return 1;
    }
    printf("Server: Credential response (KE2) created\n");
    
    // Step 3: Client recovers credentials
    uint8_t sk[OPAQUE_SHARED_SECRETBYTES];
    uint8_t authU[crypto_auth_hmacsha512_BYTES];
    uint8_t client_export_key[crypto_hash_sha512_BYTES];
    
    ret = opaque_RecoverCredentials(
        secU, pkS, cfg, &ids, &infos, ke2, sk, authU, client_export_key);
    
    if (ret != 0) {
        printf("ERROR: RecoverCredentials failed: %d\n", ret);
        return 1;
    }
    printf("Client: Credentials recovered\n");
    
    // Client sends authU to server
    
    // Step 4: Server finishes login
    ret = opaque_UserAuth(sec_s, authU);
    
    if (ret != 0) {
        printf("ERROR: UserAuth failed: %d\n", ret);
        return 1;
    }
    printf("Server: User authenticated successfully\n");
    
    // Verify shared secrets match
    uint8_t server_sk[OPAQUE_SHARED_SECRETBYTES];
    opaque_Server2Client(sec_s, server_sk);
    
    if (memcmp(sk, server_sk, OPAQUE_SHARED_SECRETBYTES) == 0) {
        printf("\n✓ SUCCESS: Shared secrets match!\n");
        print_hex("Shared secret", sk, 32); // Print first 32 bytes
    } else {
        printf("\n✗ ERROR: Shared secrets don't match!\n");
        return 1;
    }
    
    // Verify export keys match
    if (memcmp(export_key, client_export_key, crypto_hash_sha512_BYTES) == 0) {
        printf("✓ SUCCESS: Export keys match!\n");
        print_hex("Export key", export_key, 32); // Print first 32 bytes
    } else {
        printf("✗ ERROR: Export keys don't match!\n");
        return 1;
    }
    
    return 0;
}

int test_invalid_password() {
    printf("\n\n=== Testing Login with Invalid Password ===\n\n");
    
    // Use same setup as before but with wrong password
    const char *username = "alice";
    const char *correct_password = "correct horse battery staple";
    const char *wrong_password = "wrong password";
    
    // Register with correct password (simplified)
    uint8_t M[crypto_core_ristretto255_BYTES];
    uint8_t sec[OPAQUE_REGISTER_USER_SEC_LEN + strlen(correct_password)];
    uint8_t secS[OPAQUE_REGISTER_SECRET_LEN];
    uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN];
    uint8_t rec[OPAQUE_REGISTRATION_RECORD_LEN];
    uint8_t recU[OPAQUE_USER_RECORD_LEN];
    uint8_t export_key[crypto_hash_sha512_BYTES];
    
    const uint8_t cfg[OPAQUE_CFG_LEN] = {0};
    uint8_t skS[crypto_scalarmult_SCALARBYTES];
    uint8_t pkS[crypto_scalarmult_BYTES];
    crypto_scalarmult_base(pkS, skS);
    
    Opaque_Ids ids = {
        .idU = (uint8_t *)username,
        .idU_len = strlen(username),
        .idS = NULL,
        .idS_len = 0
    };
    
    // Register
    opaque_CreateRegistrationRequest(
        (const uint8_t *)correct_password, strlen(correct_password), sec, M);
    opaque_CreateRegistrationResponse(M, secS, pub);
    opaque_FinalizeRequest(sec, pub, &ids, cfg, rec, export_key);
    opaque_StoreUserRecord(secS, rec, recU);
    
    printf("User registered with correct password\n");
    
    // Try to login with wrong password
    uint8_t secU[OPAQUE_USER_SESSION_SECRET_LEN + strlen(wrong_password)];
    uint8_t ke1[OPAQUE_USER_SESSION_PUBLIC_LEN];
    
    int ret = opaque_CreateCredentialRequest(
        (const uint8_t *)wrong_password, strlen(wrong_password), secU, ke1);
    
    if (ret != 0) {
        printf("ERROR: CreateCredentialRequest failed: %d\n", ret);
        return 1;
    }
    
    uint8_t sec_s[OPAQUE_SERVER_SESSION_LEN];
    uint8_t ke2[OPAQUE_SERVER_PUBLICDATABYTES];
    
    Opaque_App_Infos infos = {
        .info = NULL,
        .info_len = 0,
        .einfo = NULL,
        .einfo_len = 0
    };
    
    ret = opaque_CreateCredentialResponse(
        ke1, recU, &ids, &infos, sec_s, ke2);
    
    if (ret != 0) {
        printf("ERROR: CreateCredentialResponse failed: %d\n", ret);
        return 1;
    }
    
    // This should fail
    uint8_t sk[OPAQUE_SHARED_SECRETBYTES];
    uint8_t authU[crypto_auth_hmacsha512_BYTES];
    uint8_t client_export_key[crypto_hash_sha512_BYTES];
    
    ret = opaque_RecoverCredentials(
        secU, pkS, cfg, &ids, &infos, ke2, sk, authU, client_export_key);
    
    if (ret != 0) {
        printf("✓ SUCCESS: RecoverCredentials failed as expected with wrong password\n");
        return 0;
    }
    
    // If we get here, try authentication - it should fail
    ret = opaque_UserAuth(sec_s, authU);
    
    if (ret != 0) {
        printf("✓ SUCCESS: Authentication failed as expected with wrong password\n");
        return 0;
    } else {
        printf("✗ ERROR: Authentication succeeded with wrong password!\n");
        return 1;
    }
}

int main() {
    // Initialize libsodium
    if (sodium_init() < 0) {
        printf("Failed to initialize libsodium\n");
        return 1;
    }
    
    printf("=== Stef libopaque Test Suite ===\n");
    printf("Testing OPAQUE implementation from: https://github.com/stef/libopaque\n");
    printf("OPAQUE Protocol Version: %s\n\n", OPAQUE_VERSION);
    
    // Print configuration details
    printf("Configuration:\n");
    printf("  OPAQUE_REGISTRATION_RECORD_LEN: %d\n", OPAQUE_REGISTRATION_RECORD_LEN);
    printf("  OPAQUE_USER_RECORD_LEN: %d\n", OPAQUE_USER_RECORD_LEN);
    printf("  OPAQUE_USER_SESSION_PUBLIC_LEN: %d\n", OPAQUE_USER_SESSION_PUBLIC_LEN);
    printf("  OPAQUE_USER_SESSION_SECRET_LEN: %lu\n", (unsigned long)OPAQUE_USER_SESSION_SECRET_LEN);
    printf("  OPAQUE_SERVER_SESSION_LEN: %d\n", OPAQUE_SERVER_SESSION_LEN);
    printf("  OPAQUE_SHARED_SECRETBYTES: %d\n", OPAQUE_SHARED_SECRETBYTES);
    
    int result = 0;
    
    // Test 1: Full protocol flow
    if (test_registration_and_login() != 0) {
        printf("\nTest 1 FAILED\n");
        result = 1;
    } else {
        printf("\nTest 1 PASSED\n");
    }
    
    // Test 2: Invalid password
    if (test_invalid_password() != 0) {
        printf("\nTest 2 FAILED\n");
        result = 1;
    } else {
        printf("\nTest 2 PASSED\n");
    }
    
    if (result == 0) {
        printf("\n\n=== ALL TESTS PASSED ===\n");
        printf("\nThe Stef libopaque library is working correctly!\n");
        printf("This library implements OPAQUE according to the latest draft.\n");
    } else {
        printf("\n\n=== SOME TESTS FAILED ===\n");
    }
    
    return result;
}
