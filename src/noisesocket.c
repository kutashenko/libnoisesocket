//
// Created by Roman Kutashenko on 2/13/18.
//

#include "noisesocket.h"
#include "debug.h"
#include <string.h>
#include <noise/protocol.h>
#include <noisesocket/debug.h>
#include "helper.h"

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

size_t
ns_required_buf_sz(size_t data_sz) {
    return data_sz + 2 * sizeof(uint16_t) + 32;
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

ns_result_t
ns_decrypt(ns_ctx_t *ctx, uint8_t *data, size_t data_sz, size_t *res_sz) {
    ASSERT(ctx);
    ASSERT(data);
    ASSERT(ctx->recv_cipher);

    if (!data_sz) {
        return NS_OK;
    }

    // Decrypt the incoming message
    NoiseBuffer mbuf;
    noise_buffer_set_input(mbuf, data, data_sz);
    int err = noise_cipherstate_decrypt(ctx->recv_cipher, &mbuf);
    if (err != NOISE_ERROR_NONE) {
        return NS_DECRYPT_ERROR;
    }

#if 0
    print_buf("Decrypted data", mbuf.data, mbuf.size);
#endif
    uint16_t sz = ntohs(*(uint16_t*)data);
    memmove(data, data + sizeof(uint16_t), sz);
    *res_sz = sz;

    return NS_OK;
}

ns_result_t
ns_encrypt(ns_ctx_t *ctx,
           uint8_t *data, size_t data_sz,
           size_t buf_sz, size_t *res_sz) {
    ASSERT(ctx);
    ASSERT(data);
    ASSERT(res_sz);
    ASSERT(ctx->send_cipher);

    if (!data_sz) {
        return NS_OK;
    }

    if (buf_sz < ns_required_buf_sz(data_sz)) {
        return NS_SMALL_BUFFER_ERROR;
    }

    NoiseBuffer mbuf;

    memmove(&data[2 * sizeof(uint16_t)], data, data_sz);

    set_net_uint16(&data[sizeof(uint16_t)], data_sz);

    int message_sz = data_sz + sizeof(uint16_t);

    // Encrypt the message and send it
    noise_buffer_set_inout(mbuf,
                           &data[sizeof(uint16_t)],
                           message_sz,
                           buf_sz - sizeof(uint16_t));

    int err = noise_cipherstate_encrypt(ctx->send_cipher, &mbuf);
    if (err != NOISE_ERROR_NONE) {
        DEBUG_NOISE("Noise encrypt ERROR %d\n", err);
        return NS_ENCRYPT_ERROR;
    }

#if 0
    DEBUGV("size of encrypted data = %d\n", (int)mbuf.size);
#endif

    set_net_uint16(data, mbuf.size);
    *res_sz = mbuf.size + sizeof(uint16_t);

    return NS_OK;
}
