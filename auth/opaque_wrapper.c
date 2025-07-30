//go:build !mock
// +build !mock

#include "opaque_wrapper.h"
#include <string.h>
#include "../vendor/stef/libopaque/src/opaque.h"

// Arkfile OPAQUE wrapper functions for libopaque

// One-step user registration with server key
int arkfile_opaque_register_user(const uint8_t* password, uint16_t pwd_len, 
                                 const uint8_t* server_private_key,
                                 uint8_t* user_record, uint8_t* export_key) {
    // Use simple identity structure - just usernames
    Opaque_Ids ids = {
        .idU_len = 4,
        .idU = (uint8_t*)"user",
        .idS_len = 6,
        .idS = (uint8_t*)"server"
    };
    
    // Use libopaque's one-step registration with server private key
    return opaque_Register(password, pwd_len, server_private_key, &ids, user_record, export_key);
}

// Step 1: Create registration request (client-side simulation)
int arkfile_opaque_create_registration_request(const uint8_t* password, uint16_t pwd_len,
                                               uint8_t* usr_ctx, uint8_t* M) {
    return opaque_CreateRegistrationRequest(password, pwd_len, usr_ctx, M);
}

// Step 2: Create registration response (server-side)
int arkfile_opaque_create_registration_response(const uint8_t* M, const uint8_t* skS,
                                                uint8_t* rsec, uint8_t* rpub) {
    return opaque_CreateRegistrationResponse(M, skS, rsec, rpub);
}

// Step 3: Finalize registration request (client-side simulation)
int arkfile_opaque_finalize_request(const uint8_t* usr_ctx, const uint8_t* rpub,
                                    uint8_t* rrec, uint8_t* export_key) {
    Opaque_Ids ids = {
        .idU_len = 4,
        .idU = (uint8_t*)"user", 
        .idS_len = 6,
        .idS = (uint8_t*)"server"
    };
    return opaque_FinalizeRequest(usr_ctx, rpub, &ids, rrec, export_key);
}

// Step 4: Store user record (server-side)
int arkfile_opaque_store_user_record(const uint8_t* rsec, const uint8_t* rrec,
                                     uint8_t* rec) {
    opaque_StoreUserRecord(rsec, rrec, rec);
    return 0; // opaque_StoreUserRecord is void, assume success
}

// Multi-step authentication - Step 1: Create credential request (client-side)
int arkfile_opaque_create_credential_request(const uint8_t* password, uint16_t pwd_len,
                                             uint8_t* sec, uint8_t* pub) {
    return opaque_CreateCredentialRequest(password, pwd_len, sec, pub);
}

// Multi-step authentication - Step 2: Create credential response (server-side)
int arkfile_opaque_create_credential_response(const uint8_t* pub, const uint8_t* rec,
                                              uint8_t* resp, uint8_t* sk, uint8_t* authU) {
    Opaque_Ids ids = {
        .idU_len = 4,
        .idU = (uint8_t*)"user",
        .idS_len = 6,
        .idS = (uint8_t*)"server"
    };
    
    const uint8_t context[] = "arkfile_auth";
    const uint16_t context_len = sizeof(context) - 1;
    
    return opaque_CreateCredentialResponse(pub, rec, &ids, context, context_len, resp, sk, authU);
}

// Multi-step authentication - Step 3: Recover credentials (client-side)
int arkfile_opaque_recover_credentials(const uint8_t* resp, const uint8_t* sec,
                                       uint8_t* sk, uint8_t* authU, uint8_t* export_key) {
    Opaque_Ids ids = {
        .idU_len = 4,
        .idU = (uint8_t*)"user",
        .idS_len = 6, 
        .idS = (uint8_t*)"server"
    };
    
    const uint8_t context[] = "arkfile_auth";
    const uint16_t context_len = sizeof(context) - 1;
    
    return opaque_RecoverCredentials(resp, sec, context, context_len, &ids, sk, authU, export_key);
}

// Multi-step authentication - Step 4: Authenticate user (server-side validation)
int arkfile_opaque_user_auth(const uint8_t* authU_server, const uint8_t* authU_client) {
    return opaque_UserAuth(authU_server, authU_client);
}

// Simplified one-step authentication (combines multiple steps)
int arkfile_opaque_authenticate_user(const uint8_t* password, uint16_t pwd_len,
                                     const uint8_t* user_record, uint8_t* session_key) {
    // Step 1: Create credential request
    uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN + pwd_len];
    uint8_t pub[OPAQUE_USER_SESSION_PUBLIC_LEN];
    
    int result = opaque_CreateCredentialRequest(password, pwd_len, sec, pub);
    if (result != 0) return result;
    
    // Step 2: Create credential response (simulate server)
    uint8_t resp[OPAQUE_SERVER_SESSION_LEN];
    uint8_t sk_server[OPAQUE_SHARED_SECRETBYTES];
    uint8_t authU_server[crypto_auth_hmacsha512_BYTES];
    
    Opaque_Ids ids = {
        .idU_len = 4,
        .idU = (uint8_t*)"user",
        .idS_len = 6,
        .idS = (uint8_t*)"server"
    };
    
    const uint8_t context[] = "arkfile_auth";
    const uint16_t context_len = sizeof(context) - 1;
    
    result = opaque_CreateCredentialResponse(pub, user_record, &ids, context, context_len, 
                                           resp, sk_server, authU_server);
    if (result != 0) return result;
    
    // Step 3: Recover credentials (simulate client)
    uint8_t sk_client[OPAQUE_SHARED_SECRETBYTES];
    uint8_t authU_client[crypto_auth_hmacsha512_BYTES];
    uint8_t export_key[crypto_hash_sha512_BYTES];
    
    result = opaque_RecoverCredentials(resp, sec, context, context_len, &ids,
                                     sk_client, authU_client, export_key);
    if (result != 0) return result;
    
    // Step 4: Authenticate
    result = opaque_UserAuth(authU_server, authU_client);
    if (result == -1) return -1; // Authentication failed
    
    // Copy session key
    memcpy(session_key, sk_client, OPAQUE_SHARED_SECRETBYTES);
    
    // Clear sensitive data
    memset(export_key, 0, sizeof(export_key));
    memset(sec, 0, sizeof(sec));
    memset(sk_server, 0, sizeof(sk_server));
    memset(sk_client, 0, sizeof(sk_client));
    
    return 0; // Success
}
