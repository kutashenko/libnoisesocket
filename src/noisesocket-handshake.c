//
// Created by Roman Kutashenko on 2/14/18.
//

#include "noisesocket-handshake.h"
#include "helper.h"
#include "debug.h"

#include <string.h>
#include <stdbool.h>

static const char * HANDSHAKE_INIT_STRING = "NoiseSocketInit1";

#define KEY_SZ_MAX (64)
#define NEGOTIATION_SZ (2 + sizeof(ns_negotiation_data_t))

typedef struct __attribute__((__packed__)) {
    uint16_t version;
    uint8_t dh;
    uint8_t cipher;
    uint8_t hash;
    uint8_t pattern;
} ns_negotiation_data_t;

static bool
is_pattern_supported(uint8_t pattern) {
    return (NOISE_PATTERN_XX & 0xFF) == pattern;
}

static bool
is_dh_supported(uint8_t dh) {
    return (NS_DH_CURVE25519 & 0xFF) == dh;
}

static bool
is_cipher_supported(uint8_t cipher) {
    return (NS_CIPHER_AES_GCM & 0xFF) == cipher;
}

static bool
is_hash_supported(uint8_t hash) {
    return (NS_HASH_BLAKE_2B & 0xFF) == hash;
}

static ns_result_t
create_handshake(ns_ctx_t *ctx,
                 int type,
                 const ns_negotiation_data_t * negotiation_data) {
    ASSERT(ctx);
    ASSERT(0 == ctx->handshake);

    NoiseProtocolId nid;
    memset(&nid, 0, sizeof(nid));

    if (negotiation_data) {
        nid.pattern_id = negotiation_data->pattern;
        nid.cipher_id = negotiation_data->cipher;
        nid.dh_id = negotiation_data->dh;
        nid.hash_id = negotiation_data->hash;
        nid.prefix_id = NOISE_PREFIX_STANDARD;
    } else {
        nid.pattern_id = DEFAULT_PATERN;
        nid.cipher_id = DEFAULT_CIPHER;
        nid.dh_id = DEFAULT_DH;
        nid.hash_id = DEFAULT_HASH;
        nid.prefix_id = NOISE_PREFIX_STANDARD;
    }

    // Create a HandshakeState object for the protocol
    int err;
    err = noise_handshakestate_new_by_id(&ctx->handshake, &nid, type);

    if (NOISE_ERROR_NONE != err) {
        DEBUG_NOISE("Noise handshake can't be created\n");
        return NS_HANDSHAKE_ERROR;
    }

    return NS_OK;
}

static ns_result_t
fill_negotiation(ns_ctx_t *ctx,
                 uint8_t * packet,
                 size_t buf_sz,
                 size_t *data_sz) {
    ASSERT(ctx);
    ASSERT(packet);
    ASSERT(buf_sz);
    ASSERT(data_sz);

    *data_sz = NEGOTIATION_SZ;

    if (buf_sz < *data_sz) return NS_SMALL_BUFFER_ERROR;

    set_net_uint16(packet, sizeof(ns_negotiation_data_t));

    ns_negotiation_data_t *negotiation_data;
    negotiation_data = (ns_negotiation_data_t*)&packet[2];

    negotiation_data->version = htons(NOISESOCKET_VERSION);
    negotiation_data->dh = ctx->dh & 0xFF;
    negotiation_data->cipher = ctx->cipher & 0xFF;
    negotiation_data->hash = ctx->hash & 0xFF;
    negotiation_data->pattern = ctx->patern & 0xFF;

    return NS_OK;
}


static ns_result_t
fill_prologue(ns_ctx_t *ctx,
              uint8_t *buf, size_t buf_sz, size_t *data_sz,
              const ns_negotiation_data_t * negotiation_data) {
    ASSERT(ctx);
    ASSERT(buf);
    ASSERT(buf_sz);
    ASSERT(data_sz);

    const int init_str_sz = strlen(HANDSHAKE_INIT_STRING);
    *data_sz = init_str_sz + NEGOTIATION_SZ;

    if (buf_sz < *data_sz) return NS_HANDSHAKE_ERROR;

    memcpy(buf, HANDSHAKE_INIT_STRING, init_str_sz);

    if (negotiation_data) {
        int pos;
        pos = init_str_sz;
        set_net_uint16(&buf[pos], sizeof(ns_negotiation_data_t));
        pos += sizeof(uint16_t);
        memcpy(&buf[pos], negotiation_data, sizeof(ns_negotiation_data_t));
    } else {
        size_t tmp;
        CHECK (fill_negotiation(ctx, &buf[init_str_sz], buf_sz - init_str_sz, &tmp));
    }

    return NS_OK;
}

static ns_result_t
init_handshake(ns_ctx_t *ctx, const ns_negotiation_data_t * negotiation_data) {
    ASSERT(ctx);
    ASSERT(ctx->handshake);

    // Create Prologue
    uint8_t prologue[32];
    size_t prologue_sz = 0;

    CHECK_MES (fill_prologue(ctx,
                             prologue, sizeof(prologue), &prologue_sz,
                             negotiation_data),
               DEBUG_NOISE("prologue can't be initialized\n"));

    // Setup prologue
    int err;
    err = noise_handshakestate_set_prologue(ctx->handshake,
                                            prologue, prologue_sz);

    if (err != NOISE_ERROR_NONE) {
        DEBUG_NOISE("Prologue ERROR %d \n", err);
        return NS_HANDSHAKE_ERROR;
    }

    // Set keypair for handshake
    NoiseDHState *dh;
    dh = noise_handshakestate_get_local_keypair_dh(ctx->handshake);
    err = noise_dhstate_set_keypair(dh,
                                    ctx->private_key, noise_dhstate_get_private_key_length(dh),
                                    ctx->public_key, noise_dhstate_get_private_key_length(dh));
    if (err != NOISE_ERROR_NONE) {
        DEBUG_NOISE("set client key pair ERROR %d\n", err);
        return NS_HANDSHAKE_ERROR;
    }

    return NS_OK;
}

ns_result_t
ns_parse_negotiation_data(ns_ctx_t *ctx, const ns_packet_t *packet) {

    ASSERT(ctx);
    ASSERT(packet);

    if (ntohs(packet->size) != sizeof(ns_negotiation_data_t)) {
        return NS_HANDSHAKE_RECV_ERROR;
    }

    const ns_negotiation_data_t * negotiation_data;
    negotiation_data = (ns_negotiation_data_t *)packet->data;

    if (NOISESOCKET_VERSION != ntohs(negotiation_data->version)) {
        return NS_VERSION_ERROR;
    }

    // Check requested capabilities
    if (is_pattern_supported(negotiation_data->pattern)) {
        return NS_UNSUPPORTED_PATERN_ERROR;
    }

    if (is_dh_supported(negotiation_data->dh)) {
        return NS_UNSUPPORTED_DH_ERROR;
    }

    if (is_cipher_supported(negotiation_data->cipher)) {
        return NS_UNSUPPORTED_CIPHER_ERROR;
    }

    if (is_hash_supported(negotiation_data->hash)) {
        return NS_UNSUPPORTED_HASH_ERROR;
    }

    CHECK (create_handshake(ctx, NOISE_ROLE_RESPONDER, negotiation_data));
    CHECK (init_handshake(ctx, negotiation_data));

    return NS_OK;
}
