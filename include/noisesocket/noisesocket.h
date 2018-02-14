//
// Created by Roman Kutashenko on 2/13/18.
//

#ifndef NOISESOCKET_NOISESOCKET_H
#define NOISESOCKET_NOISESOCKET_H

#include <stdint.h>
#include <stdlib.h>

#include "noise/protocol/cipherstate.h"

typedef void (*ns_send_backend_t)(const uint8_t *data, size_t dataSz);

typedef size_t (*ns_recv_backend_t)(uint8_t *buf, size_t bufSz);

typedef enum {
    NS_OK,
    NS_SMALL_BUFFER_ERROR,
    NS_HANDSHAKE_ERROR,
    NS_INIT_ERROR,
    NS_WRONG_KEYPAIR_ERROR,
    NS_HANDSHAKE_SEND_ERROR,
    NS_HANDSHAKE_RECV_ERROR,
    NS_HANDSHAKE_SPLIT_ERROR,
    NS_DATA_SEND_ERROR,
    NS_DATA_RECV_ERROR,
    NS_ENCRYPT_ERROR,
    NS_DECRYPT_ERROR
} ns_result_t;

typedef enum {
    NS_PATTERN_XX
} ns_patern_t;

typedef enum {
    NS_DH_CURVE25519
} ns_dh_t;

typedef enum {
    NS_CIPHER_AES_GCM
} ns_cipher_t;

typedef enum {
    NS_HASH_BLAKE_2B
} ns_hash_t;

//----------
//static const char *_initString;
//static const size_t KEY_SZ_MAX;
//static const size_t NEGOTIATION_SZ;
//----------

typedef struct {
    void *data;
    ns_send_backend_t send_func;
    ns_recv_backend_t recv_func;

    ns_patern_t patern;
    ns_dh_t dh;
    ns_cipher_t cipher;
    ns_hash_t hash;

    uint8_t *public_key;
    size_t public_key_sz;

    uint8_t *private_key;
    size_t private_key_sz;

    NoiseCipherState *send_cipher;
    NoiseCipherState *recv_cipher;
} ns_ctx_t;


ns_result_t
ns_init(ns_ctx_t *ctx,
        ns_send_backend_t send_func,
        ns_recv_backend_t recv_func,
        const uint8_t *public_key, size_t public_key_sz,
        const uint8_t *private_key, size_t private_key_sz,
        ns_patern_t patern,
        ns_dh_t dh,
        ns_cipher_t cipher,
        ns_hash_t hash);

ns_result_t
ns_deinit(ns_ctx_t *ctx);

ns_result_t
ns_connect(ns_ctx_t *ctx);

size_t
ns_negotiation_data_sz();

ns_result_t
ns_fill_negotiation_data(uint8_t *buf,
                         size_t buf_sz,
                         size_t *data_sz);

ns_result_t
write(const uint8_t *data, size_t dataSz);

size_t
read(uint8_t *buf, size_t bufSz);

#endif //NOISESOCKET_NOISESOCKET_H
