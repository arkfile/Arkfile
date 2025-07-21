#include <stdio.h>
#include <string.h>
#include <sodium.h>

// For now, let's just test if we can include the headers and use basic functions
// We'll include the headers directly from the vendor directory
#include "../../vendor/stef/libopaque/src/opaque.h"

int main() {
    // Initialize libsodium
    if (sodium_init() < 0) {
        printf("Failed to initialize libsodium\n");
        return 1;
    }
    
    printf("libsodium initialized successfully\n");
    
    // Test basic constants
    printf("OPAQUE_REGISTRATION_RECORD_LEN: %d\n", OPAQUE_REGISTRATION_RECORD_LEN);
    printf("OPAQUE_USER_RECORD_LEN: %d\n", OPAQUE_USER_RECORD_LEN);
    printf("OPAQUE_USER_SESSION_PUBLIC_LEN: %d\n", OPAQUE_USER_SESSION_PUBLIC_LEN);
    printf("OPAQUE_USER_SESSION_SECRET_LEN: %d\n", OPAQUE_USER_SESSION_SECRET_LEN);
    printf("OPAQUE_SERVER_SESSION_LEN: %d\n", OPAQUE_SERVER_SESSION_LEN);
    printf("OPAQUE_SHARED_SECRETBYTES: %d\n", OPAQUE_SHARED_SECRETBYTES);
    
    // Test registration flow
    const char *password = "test_password";
    uint16_t pwdU_len = strlen(password);
    
    // Allocate buffers for registration
    uint8_t sec[OPAQUE_REGISTER_USER_SEC_LEN + pwdU_len];
    uint8_t request[crypto_core_ristretto255_BYTES];
    
    printf("\nTesting registration request creation...\n");
    int ret = opaque_CreateRegistrationRequest((const uint8_t *)password, pwdU_len, sec, request);
    if (ret == 0) {
        printf("Registration request created successfully\n");
    } else {
        printf("Failed to create registration request: %d\n", ret);
    }
    
    return 0;
}
