//
// Created by Roman Kutashenko on 2/14/18.
//

#ifndef NOISESOCKET_NOISESOCKET_TYPES_H
#define NOISESOCKET_NOISESOCKET_TYPES_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

typedef void (*ns_send_backend_t)(void *ctx, const uint8_t *data, size_t data_sz);

typedef enum {
    NS_OK,
    NS_SMALL_BUFFER_ERROR,
    NS_INIT_ERROR,
    NS_WRONG_KEYPAIR_ERROR,
    NS_VERSION_ERROR,
    NS_DATA_SEND_ERROR,
    NS_DATA_RECV_ERROR,
    NS_ENCRYPT_ERROR,
    NS_DECRYPT_ERROR,
    NS_UNSUPPORTED_PATERN_ERROR,
    NS_UNSUPPORTED_DH_ERROR,
    NS_UNSUPPORTED_CIPHER_ERROR,
    NS_UNSUPPORTED_HASH_ERROR,
    NS_NEGOTIATION_ERROR,
    NS_NEGOTIATION_NO_SUPPORTED_SCHEMES,
    NS_HANDSHAKE_ERROR,
    NS_HANDSHAKE_SEND_ERROR,
    NS_HANDSHAKE_RECV_ERROR,
    NS_HANDSHAKE_SPLIT_ERROR
} ns_result_t;

// TODO: Use function to convert types
typedef enum {
    NS_PATTERN_XX = 9
} ns_patern_t;

typedef enum {
    NS_DH_CURVE25519 = 1
} ns_dh_t;

typedef enum {
    NS_CIPHER_AES_GCM = 2
} ns_cipher_t;

typedef enum {
    NS_HASH_BLAKE_2B = 2
} ns_hash_t;

typedef struct {
    const uint8_t *public_key;
    size_t public_key_sz;

    const uint8_t *private_key;
    size_t private_key_sz;
} ns_crypto_t;

typedef struct {
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

#endif //NOISESOCKET_NOISESOCKET_TYPES_H
