#ifndef OPAQUE_WRAPPER_H
#define OPAQUE_WRAPPER_H

#include <stdint.h>
#include <sodium.h>

// libopaque constants will be defined by the actual header
// Remove conflicting definitions

// Arkfile OPAQUE wrapper functions for libopaque

// Registration functions
int wrap_opaque_register_user(const uint8_t* password, uint16_t pwd_len,
                               const uint8_t* server_private_key,
                               uint8_t* user_record, uint8_t* export_key);

int wrap_opaque_create_registration_request(const uint8_t* password, uint16_t pwd_len,
                                            uint8_t* usr_ctx, uint8_t* M);

int wrap_opaque_create_registration_response(const uint8_t* M, const uint8_t* skS,
                                             uint8_t* rsec, uint8_t* rpub);

int wrap_opaque_finalize_request(const uint8_t* usr_ctx, const uint8_t* rpub,
                                 const uint8_t* idU, uint16_t idU_len,
                                 const uint8_t* idS, uint16_t idS_len,
                                 uint8_t* rrec, uint8_t* export_key);

int wrap_opaque_store_user_record(const uint8_t* rsec, const uint8_t* rrec,
                                  uint8_t* rec);

// Authentication functions
int wrap_opaque_authenticate_user(const uint8_t* password, uint16_t pwd_len,
                                  const uint8_t* user_record, uint8_t* session_key);

int wrap_opaque_create_credential_request(const uint8_t* password, uint16_t pwd_len,
                                         uint8_t* sec, uint8_t* pub);

int wrap_opaque_create_credential_response(const uint8_t* pub, const uint8_t* rec,
                                          const uint8_t* idU, uint16_t idU_len,
                                          const uint8_t* idS, uint16_t idS_len,
                                          const uint8_t* ctx, uint16_t ctx_len,
                                          uint8_t* resp, uint8_t* sk, uint8_t* authU);

int wrap_opaque_recover_credentials(const uint8_t* resp, const uint8_t* sec,
                                    const uint8_t* ctx, uint16_t ctx_len,
                                    const uint8_t* idU, uint16_t idU_len,
                                    const uint8_t* idS, uint16_t idS_len,
                                    uint8_t* sk, uint8_t* authU, uint8_t* export_key);

int wrap_opaque_user_auth(const uint8_t* authU, const uint8_t* ssid);

#endif // OPAQUE_WRAPPER_H
