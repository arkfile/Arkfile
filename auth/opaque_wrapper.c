#include "opaque_wrapper.h"
#include <string.h>
#include <stdio.h>
#include "../vendor/stef/libopaque/src/opaque.h"

// Arkfile OPAQUE wrapper functions for libopaque - Multi-step protocol only

// Helper for error logging
static void log_opaque_error(const char* func_name, int ret) {
    if (ret != 0) {
        fprintf(stderr, "[OPAQUE ERROR] %s failed with code: %d\n", func_name, ret);
    }
}

// Helper for null pointer checking
static int check_null_ptr(const void* ptr, const char* name, const char* func_name) {
    if (ptr == NULL) {
        fprintf(stderr, "[OPAQUE ERROR] %s: %s is NULL\n", func_name, name);
        return -1;
    }
    return 0;
}

// Step 1: Create registration request (client-side simulation)
int wrap_opaque_create_registration_request(const uint8_t* password, uint16_t pwd_len,
                                            uint8_t* usr_ctx, uint8_t* M) {
    if (check_null_ptr(password, "password", "wrap_opaque_create_registration_request") ||
        check_null_ptr(usr_ctx, "usr_ctx", "wrap_opaque_create_registration_request") ||
        check_null_ptr(M, "M", "wrap_opaque_create_registration_request")) return -1;

    int ret = opaque_CreateRegistrationRequest(password, pwd_len, usr_ctx, M);
    log_opaque_error("opaque_CreateRegistrationRequest", ret);
    return ret;
}

// Step 2: Create registration response (server-side)
int wrap_opaque_create_registration_response(const uint8_t* M, const uint8_t* skS,
                                             uint8_t* rsec, uint8_t* rpub) {
    if (check_null_ptr(M, "M", "wrap_opaque_create_registration_response") ||
        check_null_ptr(skS, "skS", "wrap_opaque_create_registration_response") ||
        check_null_ptr(rsec, "rsec", "wrap_opaque_create_registration_response") ||
        check_null_ptr(rpub, "rpub", "wrap_opaque_create_registration_response")) return -1;

    int ret = opaque_CreateRegistrationResponse(M, skS, rsec, rpub);
    log_opaque_error("opaque_CreateRegistrationResponse", ret);
    return ret;
}

// Step 3: Finalize registration request (client-side simulation)
int wrap_opaque_finalize_request(const uint8_t* usr_ctx, const uint8_t* rpub,
                                 const uint8_t* idU, uint16_t idU_len,
                                 const uint8_t* idS, uint16_t idS_len,
                                 uint8_t* rrec, uint8_t* export_key) {
    if (check_null_ptr(usr_ctx, "usr_ctx", "wrap_opaque_finalize_request") ||
        check_null_ptr(rpub, "rpub", "wrap_opaque_finalize_request") ||
        check_null_ptr(rrec, "rrec", "wrap_opaque_finalize_request") ||
        check_null_ptr(export_key, "export_key", "wrap_opaque_finalize_request")) return -1;

    Opaque_Ids ids = {
        .idU_len = idU_len,
        .idU = (uint8_t*)idU, 
        .idS_len = idS_len,
        .idS = (uint8_t*)idS
    };
    int ret = opaque_FinalizeRequest(usr_ctx, rpub, &ids, rrec, export_key);
    log_opaque_error("opaque_FinalizeRequest", ret);
    return ret;
}

// Step 4: Store user record (server-side)
int wrap_opaque_store_user_record(const uint8_t* rsec, const uint8_t* rrec,
                                  uint8_t* rec) {
    if (check_null_ptr(rsec, "rsec", "wrap_opaque_store_user_record") ||
        check_null_ptr(rrec, "rrec", "wrap_opaque_store_user_record") ||
        check_null_ptr(rec, "rec", "wrap_opaque_store_user_record")) return -1;

    opaque_StoreUserRecord(rsec, rrec, rec);
    return 0; // opaque_StoreUserRecord is void, assume success
}

// Multi-step authentication - Step 1: Create credential request (client-side)
int wrap_opaque_create_credential_request(const uint8_t* password, uint16_t pwd_len,
                                         uint8_t* sec, uint8_t* pub) {
    if (check_null_ptr(password, "password", "wrap_opaque_create_credential_request") ||
        check_null_ptr(sec, "sec", "wrap_opaque_create_credential_request") ||
        check_null_ptr(pub, "pub", "wrap_opaque_create_credential_request")) return -1;

    int ret = opaque_CreateCredentialRequest(password, pwd_len, sec, pub);
    log_opaque_error("opaque_CreateCredentialRequest", ret);
    return ret;
}

// Multi-step authentication - Step 2: Create credential response (server-side)
int wrap_opaque_create_credential_response(const uint8_t* pub, const uint8_t* rec,
                                          const uint8_t* idU, uint16_t idU_len,
                                          const uint8_t* idS, uint16_t idS_len,
                                          const uint8_t* ctx, uint16_t ctx_len,
                                          uint8_t* resp, uint8_t* sk, uint8_t* authU) {
    if (check_null_ptr(pub, "pub", "wrap_opaque_create_credential_response") ||
        check_null_ptr(rec, "rec", "wrap_opaque_create_credential_response") ||
        check_null_ptr(ctx, "ctx", "wrap_opaque_create_credential_response") ||
        check_null_ptr(resp, "resp", "wrap_opaque_create_credential_response") ||
        check_null_ptr(sk, "sk", "wrap_opaque_create_credential_response") ||
        check_null_ptr(authU, "authU", "wrap_opaque_create_credential_response")) return -1;

    Opaque_Ids opaque_ids = {
        .idU_len = idU_len,
        .idU = (uint8_t*)idU,
        .idS_len = idS_len,
        .idS = (uint8_t*)idS
    };
    
    int ret = opaque_CreateCredentialResponse(pub, rec, &opaque_ids, ctx, ctx_len, resp, sk, authU);
    log_opaque_error("opaque_CreateCredentialResponse", ret);
    return ret;
}

// Multi-step authentication - Step 3: Recover credentials (client-side)
int wrap_opaque_recover_credentials(const uint8_t* resp, const uint8_t* sec,
                                    const uint8_t* ctx, uint16_t ctx_len,
                                    const uint8_t* idU, uint16_t idU_len,
                                    const uint8_t* idS, uint16_t idS_len,
                                    uint8_t* sk, uint8_t* authU, uint8_t* export_key) {
    if (check_null_ptr(resp, "resp", "wrap_opaque_recover_credentials") ||
        check_null_ptr(sec, "sec", "wrap_opaque_recover_credentials") ||
        check_null_ptr(ctx, "ctx", "wrap_opaque_recover_credentials") ||
        check_null_ptr(sk, "sk", "wrap_opaque_recover_credentials") ||
        check_null_ptr(authU, "authU", "wrap_opaque_recover_credentials") ||
        check_null_ptr(export_key, "export_key", "wrap_opaque_recover_credentials")) return -1;

    Opaque_Ids ids = {
        .idU_len = idU_len,
        .idU = (uint8_t*)idU,
        .idS_len = idS_len, 
        .idS = (uint8_t*)idS
    };
    
    int ret = opaque_RecoverCredentials(resp, sec, ctx, ctx_len, &ids, sk, authU, export_key);
    log_opaque_error("opaque_RecoverCredentials", ret);
    return ret;
}

// Multi-step authentication - Step 4: Authenticate user (server-side validation)
int wrap_opaque_user_auth(const uint8_t* authU_server, const uint8_t* authU_client) {
    if (check_null_ptr(authU_server, "authU_server", "wrap_opaque_user_auth") ||
        check_null_ptr(authU_client, "authU_client", "wrap_opaque_user_auth")) return -1;

    int ret = opaque_UserAuth(authU_server, authU_client);
    log_opaque_error("opaque_UserAuth", ret);
    return ret;
}
