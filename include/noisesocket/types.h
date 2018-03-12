//
// Created by Roman Kutashenko on 2/14/18.
//

#ifndef NOISESOCKET_NOISESOCKET_TYPES_H
#define NOISESOCKET_NOISESOCKET_TYPES_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*ns_send_backend_t)(void *ctx, const uint8_t *data, size_t data_sz);

typedef int (*ns_verify_sender_cb_t)(void *,
                                     const uint8_t *public_key, size_t public_key_len,
                                     const uint8_t *meta_data, size_t meta_data_sz);

#define META_DATA_LEN (256)

typedef enum {
    NS_OK,
    NS_SMALL_BUFFER_ERROR,
    NS_PARAM_ERROR,
    NS_INIT_ERROR,
    NS_WRONG_KEYPAIR_ERROR,
    NS_VERSION_ERROR,
    NS_DATA_SEND_ERROR,
    NS_DATA_RECV_ERROR,
    NS_ENCRYPT_ERROR,
    NS_DECRYPT_ERROR,
    NS_UNSUPPORTED_PROTOCOL_ERROR,
    NS_NEGOTIATION_REJECT_FROM_SERVER,
    NS_NEGOTIATION_ERROR,
    NS_HANDSHAKE_ERROR,
    NS_HANDSHAKE_SEND_ERROR,
    NS_HANDSHAKE_RECV_ERROR,
    NS_HANDSHAKE_SPLIT_ERROR
} ns_result_t;

typedef enum {
    NS_PATTERN_XX = 9,
    NS_PATTERN_MAX = 1
} ns_patern_t;

typedef enum {
    NS_DH_CURVE25519 = 1,
    NS_DH_MAX = 1
} ns_dh_t;

typedef enum {
    NS_CIPHER_CHACHAPOLY = 1,
    NS_CIPHER_AES_GCM = 2,
    NS_CIPHER_MAX = 2
} ns_cipher_t;

typedef enum {
//    NS_HASH_BLAKE_2S = 1,
            NS_HASH_BLAKE_2B = 2,
    NS_HASH_SHA256 = 3,
    NS_HASH_SHA512 = 4,
    NS_HASH_MAX = 3
} ns_hash_t;

typedef struct {
    const uint8_t *public_key;
    size_t public_key_sz;

    const uint8_t *private_key;
    size_t private_key_sz;

    uint8_t meta_data[META_DATA_LEN];
} ns_crypto_t;

#define CTX_COUNT   (5)

typedef struct {
    void *ctx[CTX_COUNT];
} ns_ctx_connector_t;

typedef struct __attribute__((__packed__)) {
    ns_patern_t patern;
    ns_dh_t dh;
    ns_cipher_t cipher;
    ns_hash_t hash;
} ns_connection_params_t;

typedef struct {
    bool is_client;
    void *network;
    void *negotiation;
    void *handshake;
    void *encoding;
} ns_ctx_t;

typedef struct __attribute__((__packed__)) {
    uint16_t size;
    uint8_t data[];
} ns_packet_t;

#ifdef __cplusplus
}
#endif

#endif //NOISESOCKET_NOISESOCKET_TYPES_H
