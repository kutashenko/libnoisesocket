//
// Created by Roman Kutashenko on 2/13/18.
//

#include "noisesocket.h"
#include "debug.h"
#include <noise/protocol.h>
#include "helper.h"

struct ns_encoding_s {
    NoiseCipherState *recv_cipher;
    NoiseCipherState *send_cipher;
};

ns_result_t
ns_encoding_new(ns_encoding_t **ctx,
                void *recv_cipher,
                void *send_cipher) {
    ASSERT(ctx);
    ASSERT(recv_cipher);
    ASSERT(send_cipher);

    *ctx = calloc(1, sizeof(ns_encoding_t));
    (*ctx)->recv_cipher = (NoiseCipherState*)recv_cipher;
    (*ctx)->send_cipher = (NoiseCipherState*)send_cipher;

    return NS_OK;
}

size_t
ns_encoding_required_buf_sz(size_t data_sz) {
    return data_sz + sizeof(uint16_t) + 32;
}

ns_result_t
ns_encoding_free(ns_encoding_t *ctx) {

    ASSERT(ctx);

    if (ctx->send_cipher) {
        noise_cipherstate_free(ctx->send_cipher);
    }

    if (ctx->recv_cipher) {
        noise_cipherstate_free(ctx->recv_cipher);
    }

    free(ctx);

    return NS_OK;
}

ns_result_t
ns_encoding_decrypt(ns_encoding_t *ctx, uint8_t *data, size_t data_sz, size_t *res_sz) {
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
ns_encoding_encrypt(ns_encoding_t *ctx,
                    uint8_t *data, size_t data_sz,
                    size_t buf_sz, size_t *res_sz) {
    ASSERT(ctx);
    ASSERT(data);
    ASSERT(res_sz);
    ASSERT(ctx->send_cipher);

    if (!data_sz) {
        return NS_OK;
    }

    if (buf_sz < ns_encoding_required_buf_sz(data_sz)) {
        return NS_SMALL_BUFFER_ERROR;
    }

    NoiseBuffer mbuf;

    memmove(&data[sizeof(uint16_t)], data, data_sz);

    set_net_uint16(data, data_sz);

    // Encrypt the message and send it
    noise_buffer_set_inout(mbuf,
                           data,
                           data_sz + sizeof(uint16_t),
                           buf_sz - sizeof(uint16_t));

    int err = noise_cipherstate_encrypt(ctx->send_cipher, &mbuf);
    if (err != NOISE_ERROR_NONE) {
        DEBUG_NOISE("Noise encrypt ERROR %d\n", err);
        return NS_ENCRYPT_ERROR;
    }

#if 0
    DEBUGV("size of encrypted data = %d\n", (int)mbuf.size);
#endif

    *res_sz = mbuf.size;

    return NS_OK;
}
