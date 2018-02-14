//
// Created by Roman Kutashenko on 2/13/18.
//

#include "noisesocket.h"
#include "debug.h"
#include <string.h>
#include <stdbool.h>
#include <noisesocket/noisesocket.h>

ns_result_t
ns_init (ns_ctx_t *ctx,
         ns_send_backend_t send_func,
         ns_recv_backend_t recv_func,
         const uint8_t *public_key, size_t public_key_sz,
         const uint8_t *private_key, size_t private_key_sz,
         ns_patern_t patern,
         ns_dh_t dh,
         ns_cipher_t cipher,
         ns_hash_t hash) {

    ASSERT(ctx);
    ASSERT(send_func);
    ASSERT(recv_func);
    ASSERT(public_key);
    ASSERT(public_key_sz);
    ASSERT(private_key);
    ASSERT(private_key_sz);

    memset(ctx, 0, sizeof(*ctx));

    ctx->send_func = send_func;
    ctx->recv_func = recv_func;

    ctx->public_key = public_key;
    ctx->public_key_sz = public_key_sz;
    ctx->private_key = private_key;
    ctx->private_key_sz = private_key_sz;

    ctx->patern = patern;
    ctx->dh = dh;
    ctx->cipher = cipher;
    ctx->hash = hash;

    return NS_OK;
}

ns_result_t
ns_deinit (ns_ctx_t *ctx) {

    ASSERT(ctx);

    if (ctx->send_cipher) {
        noise_cipherstate_free(ctx->send_cipher);
    }

    if (ctx->recv_cipher) {
        noise_cipherstate_free(ctx->recv_cipher);
    }

    memset(ctx, 0, sizeof(*ctx));

    return NS_OK;
}

