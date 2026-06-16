#include "fido_wrapper.h"

#include <fido.h>
#include <stdlib.h>
#include <string.h>

static int copy_bytes(uint8_t **dst, size_t *dst_len, const uint8_t *src, size_t src_len) {
    if (src_len == 0 || src == NULL) {
        *dst = NULL;
        *dst_len = 0;
        return 0;
    }
    *dst = (uint8_t *)malloc(src_len);
    if (*dst == NULL) {
        return -1;
    }
    memcpy(*dst, src, src_len);
    *dst_len = src_len;
    return 0;
}

static fido_opt_t map_opt(int v) {
    switch (v) {
    case WRAP_FIDO_OPT_FALSE:
        return FIDO_OPT_FALSE;
    case WRAP_FIDO_OPT_TRUE:
        return FIDO_OPT_TRUE;
    default:
        return FIDO_OPT_OMIT;
    }
}

int wrap_fido_init(void) {
    /* libfido2 1.14+: fido_init() returns void (see fido.h). */
    fido_init(FIDO_DEBUG);
    return 0;
}

int wrap_fido_list_devices(char ***paths_out, size_t *count) {
    const size_t max = 64;
    fido_dev_info_t *info = fido_dev_info_new(max);
    if (info == NULL) {
        return -1;
    }

    size_t found = 0;
    if (fido_dev_info_manifest(info, max, &found) != FIDO_OK) {
        fido_dev_info_free(&info, max);
        return -2;
    }

    char **out = (char **)calloc(found, sizeof(char *));
    if (out == NULL) {
        fido_dev_info_free(&info, max);
        return -1;
    }

    for (size_t i = 0; i < found; i++) {
        const char *path = fido_dev_info_path(fido_dev_info_ptr(info, i));
        if (path == NULL) {
            wrap_fido_free_paths(out, i);
            fido_dev_info_free(&info, max);
            return -3;
        }
        out[i] = strdup(path);
        if (out[i] == NULL) {
            wrap_fido_free_paths(out, i);
            fido_dev_info_free(&info, max);
            return -1;
        }
    }

    fido_dev_info_free(&info, max);
    *paths_out = out;
    *count = found;
    return 0;
}

void wrap_fido_free_paths(char **paths, size_t count) {
    if (paths == NULL) {
        return;
    }
    for (size_t i = 0; i < count; i++) {
        free(paths[i]);
    }
    free(paths);
}

int wrap_fido_make_credential(
    const char *device_path,
    const wrap_fido_make_cred_req *req,
    wrap_fido_attestation *out) {

    if (device_path == NULL || req == NULL || out == NULL) {
        return -1;
    }
    memset(out, 0, sizeof(*out));

    fido_dev_t *dev = fido_dev_new();
    if (dev == NULL) {
        return -2;
    }
    if (fido_dev_open(dev, device_path) != FIDO_OK) {
        fido_dev_free(&dev);
        return -3;
    }

    fido_cred_t *cred = fido_cred_new();
    if (cred == NULL) {
        fido_dev_close(dev);
        fido_dev_free(&dev);
        return -2;
    }

    int rc = -4;
    if (fido_cred_set_clientdata_hash(cred, req->client_data_hash, req->client_data_hash_len) != FIDO_OK) goto cleanup;
    if (fido_cred_set_rp(cred, req->rp_id, req->rp_name) != FIDO_OK) goto cleanup;
    if (fido_cred_set_user(cred, req->user_id, req->user_id_len,
                           req->user_name, req->user_display_name, NULL) != FIDO_OK) goto cleanup;
    if (fido_cred_set_type(cred, req->cred_type) != FIDO_OK) goto cleanup;
    if (fido_cred_set_rk(cred, map_opt(req->resident_key)) != FIDO_OK) goto cleanup;
    if (fido_cred_set_uv(cred, map_opt(req->user_verification)) != FIDO_OK) goto cleanup;

    if (fido_dev_make_cred(dev, cred, NULL) != FIDO_OK) {
        rc = -5;
        goto cleanup;
    }

    const uint8_t *auth_ptr = fido_cred_authdata_ptr(cred);
    size_t auth_len = fido_cred_authdata_len(cred);
    const uint8_t *id_ptr = fido_cred_id_ptr(cred);
    size_t id_len = fido_cred_id_len(cred);
    const char *fmt = fido_cred_fmt(cred);

    if (copy_bytes(&out->auth_data, &out->auth_data_len, auth_ptr, auth_len) != 0) goto cleanup;
    if (copy_bytes(&out->credential_id, &out->credential_id_len, id_ptr, id_len) != 0) goto cleanup;
    if (fmt != NULL) {
        out->attestation_fmt = strdup(fmt);
        if (out->attestation_fmt == NULL) goto cleanup;
    }

    rc = 0;

cleanup:
    fido_cred_free(&cred);
    fido_dev_close(dev);
    fido_dev_free(&dev);
    if (rc != 0) {
        wrap_fido_attestation_free(out);
    }
    return rc;
}

int wrap_fido_get_assertion(
    const char *device_path,
    const wrap_fido_assert_req *req,
    wrap_fido_assertion *out) {

    if (device_path == NULL || req == NULL || out == NULL) {
        return -1;
    }
    memset(out, 0, sizeof(*out));

    fido_dev_t *dev = fido_dev_new();
    if (dev == NULL) {
        return -2;
    }
    if (fido_dev_open(dev, device_path) != FIDO_OK) {
        fido_dev_free(&dev);
        return -3;
    }

    fido_assert_t *assert = fido_assert_new();
    if (assert == NULL) {
        fido_dev_close(dev);
        fido_dev_free(&dev);
        return -2;
    }

    int rc = -4;
    if (fido_assert_set_rp(assert, req->rp_id) != FIDO_OK) goto cleanup;
    if (fido_assert_set_clientdata_hash(assert, req->client_data_hash, req->client_data_hash_len) != FIDO_OK) goto cleanup;
    for (size_t i = 0; i < req->allow_cred_count; i++) {
        if (fido_assert_allow_cred(assert, req->allow_cred_ids[i], req->allow_cred_lens[i]) != FIDO_OK) {
            goto cleanup;
        }
    }
    if (fido_assert_set_uv(assert, map_opt(req->user_verification)) != FIDO_OK) goto cleanup;

    if (fido_dev_get_assert(dev, assert, NULL) != FIDO_OK) {
        rc = -5;
        goto cleanup;
    }

    size_t idx = 0;
    const uint8_t *auth_ptr = fido_assert_authdata_ptr(assert, idx);
    size_t auth_len = fido_assert_authdata_len(assert, idx);
    const uint8_t *sig_ptr = fido_assert_sig_ptr(assert, idx);
    size_t sig_len = fido_assert_sig_len(assert, idx);
    const uint8_t *id_ptr = fido_assert_id_ptr(assert, idx);
    size_t id_len = fido_assert_id_len(assert, idx);

    if (copy_bytes(&out->auth_data, &out->auth_data_len, auth_ptr, auth_len) != 0) goto cleanup;
    if (copy_bytes(&out->signature, &out->signature_len, sig_ptr, sig_len) != 0) goto cleanup;
    if (copy_bytes(&out->credential_id, &out->credential_id_len, id_ptr, id_len) != 0) goto cleanup;

    rc = 0;

cleanup:
    fido_assert_free(&assert);
    fido_dev_close(dev);
    fido_dev_free(&dev);
    if (rc != 0) {
        wrap_fido_assertion_free(out);
    }
    return rc;
}

void wrap_fido_attestation_free(wrap_fido_attestation *out) {
    if (out == NULL) {
        return;
    }
    free(out->auth_data);
    free(out->credential_id);
    free(out->attestation_fmt);
    memset(out, 0, sizeof(*out));
}

void wrap_fido_assertion_free(wrap_fido_assertion *out) {
    if (out == NULL) {
        return;
    }
    free(out->auth_data);
    free(out->signature);
    free(out->credential_id);
    memset(out, 0, sizeof(*out));
}
