//
// Created by Roman Kutashenko on 2/23/18.
//

#include "negotiation-params.h"
#include "debug.h"

#include <string.h>

static ns_negotiation_params_t default_negotiation_params;
static bool params_ready = false;

ns_result_t
ns_negotiation_set_default_patern(ns_negotiation_params_t *ctx, ns_patern_t patern) {
    ASSERT(ctx);
    ctx->default_patern = patern;
    return ns_negotiation_add_patern(ctx, patern);
}

ns_result_t
ns_negotiation_set_default_dh(ns_negotiation_params_t *ctx, ns_dh_t dh) {
    ASSERT(ctx);
    ctx->default_dh = dh;
    return ns_negotiation_add_dh(ctx, dh);
}

ns_result_t
ns_negotiation_set_default_cipher(ns_negotiation_params_t *ctx, ns_cipher_t cipher) {
    ASSERT(ctx);
    ctx->default_cipher = cipher;
    return ns_negotiation_add_cipher(ctx, cipher);
}

ns_result_t
ns_negotiation_set_default_hash(ns_negotiation_params_t *ctx, ns_hash_t hash) {
    ASSERT(ctx);
    ctx->default_hash = hash;
    return ns_negotiation_add_hash(ctx, hash);
}

ns_result_t
ns_negotiation_add_patern(ns_negotiation_params_t *ctx, ns_patern_t patern) {
    ASSERT(ctx);

    int i;
    for (i = 0; i < ctx->available_paterns_cnt; ++i) {
        if (patern == ctx->available_paterns[i]) {
            return NS_OK;
        }
    }

    if (ctx->available_paterns_cnt >= NS_PATTERN_MAX) {
        return NS_NEGOTIATION_ERROR;
    }

    size_t *pos = &ctx->available_paterns_cnt;
    ctx->available_paterns[(*pos)++] = patern;

    return NS_OK;
}

ns_result_t
ns_negotiation_add_dh(ns_negotiation_params_t *ctx, ns_dh_t dh) {
    ASSERT(ctx);

    int i;
    for (i = 0; i < ctx->available_dh_s_cnt; ++i) {
        if (dh == ctx->available_dh_s[i]) {
            return NS_OK;
        }
    }

    if (ctx->available_dh_s_cnt >= NS_PATTERN_MAX) {
        return NS_NEGOTIATION_ERROR;
    }

    size_t *pos = &ctx->available_dh_s_cnt;
    ctx->available_dh_s[(*pos)++] = dh;

    return NS_OK;
}

ns_result_t
ns_negotiation_add_cipher(ns_negotiation_params_t *ctx, ns_cipher_t cipher) {
    ASSERT(ctx);

    int i;
    for (i = 0; i < ctx->available_ciphers_cnt; ++i) {
        if (cipher == ctx->available_ciphers[i]) {
            return NS_OK;
        }
    }

    if (ctx->available_ciphers_cnt >= NS_PATTERN_MAX) {
        return NS_NEGOTIATION_ERROR;
    }

    size_t *pos = &ctx->available_ciphers_cnt;
    ctx->available_ciphers[(*pos)++] = cipher;

    return NS_OK;
}

ns_result_t
ns_negotiation_add_hash(ns_negotiation_params_t *ctx, ns_hash_t hash) {
    ASSERT(ctx);

    int i;
    for (i = 0; i < ctx->available_hashes_cnt; ++i) {
        if (hash == ctx->available_hashes[i]) {
            return NS_OK;
        }
    }

    if (ctx->available_hashes_cnt >= NS_PATTERN_MAX) {
        return NS_NEGOTIATION_ERROR;
    }

    size_t *pos = &ctx->available_hashes_cnt;
    ctx->available_hashes[(*pos)++] = hash;

    return NS_OK;
}

const ns_negotiation_params_t *
ns_negotiation_default_params() {

    if (!params_ready) {
        memset(&default_negotiation_params, 0, sizeof(default_negotiation_params));

        ns_negotiation_set_default_patern(&default_negotiation_params, NS_PATTERN_XX);
        ns_negotiation_set_default_cipher(&default_negotiation_params, NS_CIPHER_AES_GCM);
        ns_negotiation_set_default_dh(&default_negotiation_params, NS_DH_CURVE25519);
        ns_negotiation_set_default_hash(&default_negotiation_params, NS_HASH_BLAKE_2B);

        params_ready = true;
    }

    return &default_negotiation_params;
}