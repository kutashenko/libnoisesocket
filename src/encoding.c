//
// Created by Roman Kutashenko on 2/13/18.
//

#include "noisesocket.h"
#include "debug.h"
#include <noise/protocol.h>
#include "helper.h"

#define ENC(X) ((ns_encoding_t*)X)

typedef struct {
    NoiseCipherState *recv_cipher;
    NoiseCipherState *send_cipher;
} ns_encoding_t;

ns_result_t
ns_encoding_init(void *ctx,
                 void *recv_cipher,
                 void *send_cipher) {
    ASSERT(ctx);
    ASSERT(recv_cipher);
    ASSERT(send_cipher);

    memset(ctx, 0, sizeof(ns_encoding_t));
    ENC(ctx)->recv_cipher = (NoiseCipherState*)recv_cipher;
    ENC(ctx)->send_cipher = (NoiseCipherState*)send_cipher;

    return NS_OK;
}

size_t
ns_encoding_required_buf_sz(size_t data_sz) {
    return data_sz + sizeof(uint16_t) + 32;
}

ns_result_t
ns_encoding_deinit(void *ctx) {

    ASSERT(ctx);

    if (ENC(ctx)->send_cipher) {
        noise_cipherstate_free(ENC(ctx)->send_cipher);
    }

    if (ENC(ctx)->recv_cipher) {
        noise_cipherstate_free(ENC(ctx)->recv_cipher);
    }

    memset(ctx, 0, sizeof(*ENC(ctx)));

    return NS_OK;
}

ns_result_t
ns_encoding_decrypt(void *ctx, uint8_t *data, size_t data_sz, size_t *res_sz) {
    ASSERT(ctx);
    ASSERT(data);
    ASSERT(ENC(ctx)->recv_cipher);

    if (!data_sz) {
        return NS_OK;
    }

    // Decrypt the incoming message
    NoiseBuffer mbuf;
    noise_buffer_set_input(mbuf, data, data_sz);
    int err = noise_cipherstate_decrypt(ENC(ctx)->recv_cipher, &mbuf);
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
ns_encoding_encrypt(void *ctx,
                    uint8_t *data, size_t data_sz,
                    size_t buf_sz, size_t *res_sz) {
    ASSERT(ctx);
    ASSERT(data);
    ASSERT(res_sz);
    ASSERT(ENC(ctx)->send_cipher);

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

    int err = noise_cipherstate_encrypt(ENC(ctx)->send_cipher, &mbuf);
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

size_t
ns_encoding_ctx_size() {
    return sizeof(ns_encoding_t);
}