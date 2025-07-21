#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include <assert.h>

#include "../../vendor/stef/libopaque/src/opaque.h"

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int test_full_protocol() {
    printf("\n=== Testing Complete OPAQUE Protocol Flow ===\n\n");
    
    // Test credentials
    const uint8_t pwdU[] = "correct horse battery staple";
    const uint16_t pwdU_len = strlen((char*)pwdU);
    
    // User and server identities
    Opaque_Ids ids = {
        .idU_len = 5,
        .idU = (uint8_t*)"alice",
        .idS_len = 6, 
        .idS = (uint8_t*)"server"
    };
    
    // Context for authentication
    const uint8_t context[] = "test_context";
    const uint16_t context_len = sizeof(context) - 1;
    
    // Export keys for comparison
    uint8_t export_key_reg[crypto_hash_sha512_BYTES];
    uint8_t export_key_login[crypto_hash_sha512_BYTES];
    
    printf("--- Registration Phase ---\n");
    
    // Step 1: User creates registration request
    uint8_t M[crypto_core_ristretto255_BYTES];
    uint8_t usr_ctx[OPAQUE_REGISTER_USER_SEC_LEN + pwdU_len];
    
    if (0 != opaque_CreateRegistrationRequest(pwdU, pwdU_len, usr_ctx, M)) {
        printf("ERROR: opaque_CreateRegistrationRequest failed\n");
        return 1;
    }
    printf("User: Registration request created\n");
    
    // Step 2: Server creates registration response
    // Note: passing NULL for skS means server will generate a keypair
    uint8_t rsec[OPAQUE_REGISTER_SECRET_LEN];
    uint8_t rpub[OPAQUE_REGISTER_PUBLIC_LEN];
    
    if (0 != opaque_CreateRegistrationResponse(M, NULL, rsec, rpub)) {
        printf("ERROR: opaque_CreateRegistrationResponse failed\n");
        return 1;
    }
    printf("Server: Registration response created\n");
    
    // Step 3: User finalizes registration
    uint8_t rrec[OPAQUE_REGISTRATION_RECORD_LEN];
    
    if (0 != opaque_FinalizeRequest(usr_ctx, rpub, &ids, rrec, export_key_reg)) {
        printf("ERROR: opaque_FinalizeRequest failed\n");
        return 1;
    }
    printf("User: Registration finalized\n");
    print_hex("Export key (first 32 bytes)", export_key_reg, 32);
    
    // Step 4: Server stores user record
    uint8_t rec[OPAQUE_USER_RECORD_LEN];
    opaque_StoreUserRecord(rsec, rrec, rec);
    printf("Server: User record stored\n");
    
    printf("\n--- Login Phase ---\n");
    
    // Step 1: User creates credential request
    uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN + pwdU_len];
    uint8_t pub[OPAQUE_USER_SESSION_PUBLIC_LEN];
    
    if (0 != opaque_CreateCredentialRequest(pwdU, pwdU_len, sec, pub)) {
        printf("ERROR: opaque_CreateCredentialRequest failed\n");
        return 1;
    }
    printf("User: Credential request created\n");
    
    // Step 2: Server creates credential response
    uint8_t resp[OPAQUE_SERVER_SESSION_LEN];
    uint8_t sk_server[OPAQUE_SHARED_SECRETBYTES];
    uint8_t authU0[crypto_auth_hmacsha512_BYTES];
    
    if (0 != opaque_CreateCredentialResponse(pub, rec, &ids, context, context_len, 
                                            resp, sk_server, authU0)) {
        printf("ERROR: opaque_CreateCredentialResponse failed\n");
        return 1;
    }
    printf("Server: Credential response created\n");
    
    // Step 3: User recovers credentials
    uint8_t sk_user[OPAQUE_SHARED_SECRETBYTES];
    uint8_t authU1[crypto_auth_hmacsha512_BYTES];
    
    if (0 != opaque_RecoverCredentials(resp, sec, context, context_len, &ids, 
                                      sk_user, authU1, export_key_login)) {
        printf("ERROR: opaque_RecoverCredentials failed\n");
        return 1;
    }
    printf("User: Credentials recovered\n");
    
    // Step 4: Authenticate both parties
    if (-1 == opaque_UserAuth(authU0, authU1)) {
        printf("ERROR: User authentication failed\n");
        return 1;
    }
    printf("Server: User authenticated successfully\n");
    
    // Verify shared secrets match
    if (sodium_memcmp(sk_server, sk_user, sizeof(sk_server)) == 0) {
        printf("\n✓ SUCCESS: Shared secrets match!\n");
        print_hex("Shared secret (first 32 bytes)", sk_server, 32);
    } else {
        printf("\n✗ ERROR: Shared secrets don't match!\n");
        return 1;
    }
    
    // Verify export keys match
    if (memcmp(export_key_reg, export_key_login, sizeof(export_key_reg)) == 0) {
        printf("✓ SUCCESS: Export keys match!\n");
    } else {
        printf("✗ ERROR: Export keys don't match!\n");
        return 1;
    }
    
    return 0;
}

int test_one_step_registration() {
    printf("\n\n=== Testing One-Step Registration ===\n\n");
    
    const uint8_t pwdU[] = "test password";
    const uint16_t pwdU_len = strlen((char*)pwdU);
    
    Opaque_Ids ids = {
        .idU_len = 3,
        .idU = (uint8_t*)"bob",
        .idS_len = 6,
        .idS = (uint8_t*)"server"
    };
    
    uint8_t rec[OPAQUE_USER_RECORD_LEN];
    uint8_t export_key[crypto_hash_sha512_BYTES];
    
    // One-step registration (server generates keypair)
    if (0 != opaque_Register(pwdU, pwdU_len, NULL, &ids, rec, export_key)) {
        printf("ERROR: opaque_Register failed\n");
        return 1;
    }
    
    printf("✓ SUCCESS: One-step registration completed\n");
    print_hex("Export key (first 32 bytes)", export_key, 32);
    
    // Test login with the registered credentials
    const uint8_t context[] = "login_test";
    const uint16_t context_len = sizeof(context) - 1;
    
    uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN + pwdU_len];
    uint8_t pub[OPAQUE_USER_SESSION_PUBLIC_LEN];
    
    opaque_CreateCredentialRequest(pwdU, pwdU_len, sec, pub);
    
    uint8_t resp[OPAQUE_SERVER_SESSION_LEN];
    uint8_t sk_server[OPAQUE_SHARED_SECRETBYTES];
    uint8_t authU0[crypto_auth_hmacsha512_BYTES];
    
    if (0 != opaque_CreateCredentialResponse(pub, rec, &ids, context, context_len,
                                            resp, sk_server, authU0)) {
        printf("ERROR: opaque_CreateCredentialResponse failed\n");
        return 1;
    }
    
    uint8_t sk_user[OPAQUE_SHARED_SECRETBYTES];
    uint8_t authU1[crypto_auth_hmacsha512_BYTES];
    uint8_t export_key_login[crypto_hash_sha512_BYTES];
    
    if (0 != opaque_RecoverCredentials(resp, sec, context, context_len, &ids,
                                      sk_user, authU1, export_key_login)) {
        printf("ERROR: opaque_RecoverCredentials failed\n");
        return 1;
    }
    
    if (-1 == opaque_UserAuth(authU0, authU1)) {
        printf("ERROR: User authentication failed\n");
        return 1;
    }
    
    printf("✓ SUCCESS: Login after one-step registration succeeded\n");
    
    return 0;
}

int test_wrong_password() {
    printf("\n\n=== Testing Wrong Password ===\n\n");
    
    const uint8_t correct_pwd[] = "correct password";
    const uint8_t wrong_pwd[] = "wrong password";
    const uint16_t correct_pwd_len = strlen((char*)correct_pwd);
    const uint16_t wrong_pwd_len = strlen((char*)wrong_pwd);
    
    Opaque_Ids ids = {
        .idU_len = 7,
        .idU = (uint8_t*)"charlie",
        .idS_len = 6,
        .idS = (uint8_t*)"server"
    };
    
    // Register with correct password
    uint8_t rec[OPAQUE_USER_RECORD_LEN];
    uint8_t export_key[crypto_hash_sha512_BYTES];
    
    if (0 != opaque_Register(correct_pwd, correct_pwd_len, NULL, &ids, rec, export_key)) {
        printf("ERROR: opaque_Register failed\n");
        return 1;
    }
    printf("User registered with correct password\n");
    
    // Try to login with wrong password
    const uint8_t context[] = "wrong_pwd_test";
    const uint16_t context_len = sizeof(context) - 1;
    
    uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN + wrong_pwd_len];
    uint8_t pub[OPAQUE_USER_SESSION_PUBLIC_LEN];
    
    opaque_CreateCredentialRequest(wrong_pwd, wrong_pwd_len, sec, pub);
    
    uint8_t resp[OPAQUE_SERVER_SESSION_LEN];
    uint8_t sk_server[OPAQUE_SHARED_SECRETBYTES];
    uint8_t authU0[crypto_auth_hmacsha512_BYTES];
    
    if (0 != opaque_CreateCredentialResponse(pub, rec, &ids, context, context_len,
                                            resp, sk_server, authU0)) {
        printf("ERROR: opaque_CreateCredentialResponse failed\n");
        return 1;
    }
    
    uint8_t sk_user[OPAQUE_SHARED_SECRETBYTES];
    uint8_t authU1[crypto_auth_hmacsha512_BYTES];
    uint8_t export_key_login[crypto_hash_sha512_BYTES];
    
    // This should fail with wrong password
    if (0 != opaque_RecoverCredentials(resp, sec, context, context_len, &ids,
                                      sk_user, authU1, export_key_login)) {
        printf("✓ SUCCESS: opaque_RecoverCredentials failed as expected with wrong password\n");
        return 0;
    }
    
    // If RecoverCredentials somehow succeeded, check authentication
    if (-1 == opaque_UserAuth(authU0, authU1)) {
        printf("✓ SUCCESS: Authentication failed as expected\n");
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
    printf("Testing OPAQUE implementation from: https://github.com/stef/libopaque\n\n");
    
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
    if (test_full_protocol() != 0) {
        printf("\nTest 1 FAILED\n");
        result = 1;
    } else {
        printf("\nTest 1 PASSED\n");
    }
    
    // Test 2: One-step registration
    if (test_one_step_registration() != 0) {
        printf("\nTest 2 FAILED\n");
        result = 1;
    } else {
        printf("\nTest 2 PASSED\n");
    }
    
    // Test 3: Wrong password
    if (test_wrong_password() != 0) {
        printf("\nTest 3 FAILED\n");
        result = 1;
    } else {
        printf("\nTest 3 PASSED\n");
    }
    
    if (result == 0) {
        printf("\n\n=== ALL TESTS PASSED ===\n");
        printf("\nThe Stef libopaque library is working correctly!\n");
        printf("\nThis library implements OPAQUE and is actively maintained.\n");
        printf("Latest release: February 2025 (version 3.1.0)\n");
        printf("It follows the IRTF CFRG OPAQUE specification.\n");
    } else {
        printf("\n\n=== SOME TESTS FAILED ===\n");
    }
    
    return result;
}
