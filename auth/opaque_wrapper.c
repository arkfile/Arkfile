#include "opaque_wrapper.h"
#include <string.h>
#include "../vendor/stef/libopaque/src/opaque.h"

// Arkfile OPAQUE wrapper functions for libopaque - Multi-step protocol only

// Step 1: Create registration request (client-side simulation)
int wrap_opaque_create_registration_request(const uint8_t* password, uint16_t pwd_len,
                                            uint8_t* usr_ctx, uint8_t* M) {
    return opaque_CreateRegistrationRequest(password, pwd_len, usr_ctx, M);
}

// Step 2: Create registration response (server-side)
int wrap_opaque_create_registration_response(const uint8_t* M, const uint8_t* skS,
                                             uint8_t* rsec, uint8_t* rpub) {
    return opaque_CreateRegistrationResponse(M, skS, rsec, rpub);
}

// Step 3: Finalize registration request (client-side simulation)
int wrap_opaque_finalize_request(const uint8_t* usr_ctx, const uint8_t* rpub,
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
int wrap_opaque_store_user_record(const uint8_t* rsec, const uint8_t* rrec,
                                  uint8_t* rec) {
    opaque_StoreUserRecord(rsec, rrec, rec);
    return 0; // opaque_StoreUserRecord is void, assume success
}

// Multi-step authentication - Step 1: Create credential request (client-side)
int wrap_opaque_create_credential_request(const uint8_t* password, uint16_t pwd_len,
                                         uint8_t* sec, uint8_t* pub) {
    return opaque_CreateCredentialRequest(password, pwd_len, sec, pub);
}

// Multi-step authentication - Step 2: Create credential response (server-side)
int wrap_opaque_create_credential_response(const uint8_t* pub, const uint8_t* rec,
                                          const uint8_t* ids, const uint8_t* ctx, uint16_t ctx_len,
                                          uint8_t* resp, uint8_t* sk, uint8_t* authU) {
    // Ignore the ids parameter and use hardcoded values like other functions
    Opaque_Ids opaque_ids = {
        .idU_len = 4,
        .idU = (uint8_t*)"user",
        .idS_len = 6,
        .idS = (uint8_t*)"server"
    };
    
    return opaque_CreateCredentialResponse(pub, rec, &opaque_ids, ctx, ctx_len, resp, sk, authU);
}

// Multi-step authentication - Step 3: Recover credentials (client-side)
int wrap_opaque_recover_credentials(const uint8_t* resp, const uint8_t* sec,
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
int wrap_opaque_user_auth(const uint8_t* authU_server, const uint8_t* authU_client) {
    return opaque_UserAuth(authU_server, authU_client);
}
