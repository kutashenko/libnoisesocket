//
// Created by Roman Kutashenko on 2/14/18.
//

#ifndef NOISESOCKET_NOISESOCKET_TYPES_H
#define NOISESOCKET_NOISESOCKET_TYPES_H

#include <stdint.h>
#include <stdlib.h>

#include "noise/protocol/cipherstate.h"
#include "noise/protocol/constants.h"
#include "noise/protocol/handshakestate.h"

typedef void (*ns_send_backend_t)(const uint8_t *data, size_t dataSz);

typedef size_t (*ns_recv_backend_t)(uint8_t *buf, size_t bufSz);

typedef enum {
    NS_OK,
    NS_SMALL_BUFFER_ERROR,
    NS_HANDSHAKE_ERROR,
    NS_INIT_ERROR,
    NS_WRONG_KEYPAIR_ERROR,
    NS_VERSION_ERROR,
    NS_HANDSHAKE_SEND_ERROR,
    NS_HANDSHAKE_RECV_ERROR,
    NS_HANDSHAKE_SPLIT_ERROR,
    NS_DATA_SEND_ERROR,
    NS_DATA_RECV_ERROR,
    NS_ENCRYPT_ERROR,
    NS_DECRYPT_ERROR,
    NS_UNSUPPORTED_PATERN_ERROR,
    NS_UNSUPPORTED_DH_ERROR,
    NS_UNSUPPORTED_CIPHER_ERROR,
    NS_UNSUPPORTED_HASH_ERROR

} ns_result_t;

typedef enum {
    NS_PATTERN_XX = NOISE_PATTERN_XX
} ns_patern_t;

typedef enum {
    NS_DH_CURVE25519 = NOISE_DH_CURVE25519
} ns_dh_t;

typedef enum {
    NS_CIPHER_AES_GCM = NOISE_CIPHER_AESGCM
} ns_cipher_t;

typedef enum {
    NS_HASH_BLAKE_2B = NOISE_HASH_BLAKE2b
} ns_hash_t;

typedef struct {
    void *data;
    ns_send_backend_t send_func;
    ns_recv_backend_t recv_func;

    ns_patern_t patern;
    ns_dh_t dh;
    ns_cipher_t cipher;
    ns_hash_t hash;

    const uint8_t *public_key;
    size_t public_key_sz;

    const uint8_t *private_key;
    size_t private_key_sz;

    NoiseCipherState *send_cipher;
    NoiseCipherState *recv_cipher;

    NoiseHandshakeState *handshake;
} ns_ctx_t;

typedef struct __attribute__((__packed__)) {
    uint16_t size;
    uint8_t data[];
} ns_packet_t;

#define NOISESOCKET_VERSION (1)

#define NOISESOCKET_PACKET_SIZE_FIELD (sizeof(uint16_t))

#define DEFAULT_PATERN  (NS_PATTERN_XX)
#define DEFAULT_DH      (NS_DH_CURVE25519)
#define DEFAULT_CIPHER  (NS_CIPHER_AES_GCM)
#define DEFAULT_HASH    (NS_HASH_BLAKE_2B)

#endif //NOISESOCKET_NOISESOCKET_TYPES_H
