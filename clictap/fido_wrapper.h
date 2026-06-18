#ifndef ARKFILE_FIDO_WRAPPER_H
#define ARKFILE_FIDO_WRAPPER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WRAP_FIDO_OPT_OMIT 0
#define WRAP_FIDO_OPT_FALSE 1
#define WRAP_FIDO_OPT_TRUE 2

#define WRAP_FIDO_CRED_ES256 -7

typedef struct {
    const uint8_t *client_data_hash;
    size_t client_data_hash_len;
    const char *rp_id;
    const char *rp_name;
    const uint8_t *user_id;
    size_t user_id_len;
    const char *user_name;
    const char *user_display_name;
    int cred_type;
    int resident_key;
    int user_verification;
} wrap_fido_make_cred_req;

typedef struct {
    uint8_t *auth_data;
    size_t auth_data_len;
    uint8_t *credential_id;
    size_t credential_id_len;
} wrap_fido_attestation;

typedef struct {
    const uint8_t *client_data_hash;
    size_t client_data_hash_len;
    const char *rp_id;
    const uint8_t *const *allow_cred_ids;
    const size_t *allow_cred_lens;
    size_t allow_cred_count;
    int user_verification;
} wrap_fido_assert_req;

typedef struct {
    uint8_t *auth_data;
    size_t auth_data_len;
    uint8_t *signature;
    size_t signature_len;
    uint8_t *credential_id;
    size_t credential_id_len;
} wrap_fido_assertion;

int wrap_fido_init(void);

int wrap_fido_list_devices(char ***paths_out, size_t *count);

int wrap_fido_make_credential(
    const char *device_path,
    const wrap_fido_make_cred_req *req,
    wrap_fido_attestation *out);

int wrap_fido_get_assertion(
    const char *device_path,
    const wrap_fido_assert_req *req,
    wrap_fido_assertion *out);

void wrap_fido_attestation_free(wrap_fido_attestation *out);
void wrap_fido_assertion_free(wrap_fido_assertion *out);
void wrap_fido_free_paths(char **paths, size_t count);

#ifdef __cplusplus
}
#endif

#endif
