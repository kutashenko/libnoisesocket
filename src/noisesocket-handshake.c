//
// Created by Roman Kutashenko on 2/14/18.
//

#include "noisesocket-handshake.h"
#include "helper.h"
#include "debug.h"
#include "util.h"
#include <string.h>
#include <noisesocket/debug.h>

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
    ASSERT(0 == ctx->handshake.noise);

    noise_init();

    NoiseProtocolId nid;
    memset(&nid, 0, sizeof(nid));

    if (negotiation_data) {
        nid.pattern_id = NOISE_ID('P', negotiation_data->pattern);
        nid.cipher_id = NOISE_ID('C', negotiation_data->cipher);
        nid.dh_id = NOISE_ID('D', negotiation_data->dh);
        nid.hash_id = NOISE_ID('H', negotiation_data->hash);
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
    err = noise_handshakestate_new_by_id(&ctx->handshake.noise, &nid, type);

    if (NOISE_ERROR_NONE != err) {
        DEBUG_NOISE("Noise handshake can't be created\n");
        return NS_HANDSHAKE_ERROR;
    }

    return NS_OK;
}

// TODO: Pass ns_negotiation_data_t instead of buffer
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
    ASSERT(ctx->handshake.noise);

    // Create Prologue
    uint8_t prologue[32];
    size_t prologue_sz = 0;

    CHECK_MES (fill_prologue(ctx,
                             prologue, sizeof(prologue), &prologue_sz,
                             negotiation_data),
               DEBUG_NOISE("prologue can't be initialized\n"));

    // Setup prologue
    int err;
    err = noise_handshakestate_set_prologue(ctx->handshake.noise,
                                            prologue, prologue_sz);

    if (err != NOISE_ERROR_NONE) {
        DEBUG_NOISE("Prologue ERROR %d \n", err);
        return NS_HANDSHAKE_ERROR;
    }

    // Set keypair for handshake
    NoiseDHState *dh;
    dh = noise_handshakestate_get_local_keypair_dh(ctx->handshake.noise);
    err = noise_dhstate_set_keypair(dh,
                                    ctx->private_key, noise_dhstate_get_private_key_length(dh),
                                    ctx->public_key, noise_dhstate_get_private_key_length(dh));
    if (err != NOISE_ERROR_NONE) {
        DEBUG_NOISE("set client key pair ERROR %d\n", err);
        return NS_HANDSHAKE_ERROR;
    }

    // Setup recipient public key
#if 0
    if (noise_handshakestate_needs_remote_public_key(ctx->handshake.noise)) {
        dh = noise_handshakestate_get_remote_public_key_dh(ctx->handshake.noise);
        key_len = noise_dhstate_get_public_key_length(dh);
        err = noise_dhstate_set_public_key(
                dh, noise_ctx->public_keys->elts, key_len);
        if (err != NOISE_ERROR_NONE)
            return NGX_ERROR;
    }
#endif

    return NS_OK;
}

static ns_result_t
handshake_start(ns_ctx_t *ctx) {
    ASSERT(ctx);
    ASSERT(ctx->handshake.noise);

    int err = noise_handshakestate_start(ctx->handshake.noise);
    if (NOISE_ERROR_NONE != err) {
        DEBUG_NOISE("Start handshake error %d \n", err);
        return NS_HANDSHAKE_ERROR;
    }

    return NS_OK;
}

static ns_result_t
ns_send_negotiation_data(ns_ctx_t *ctx) {
    ASSERT(ctx);
    ASSERT(ctx->send_func);

    uint8_t negotiation_data[NEGOTIATION_SZ];
    size_t negotiation_sz = 0;

    CHECK (fill_negotiation(ctx,
                            negotiation_data,
                            sizeof(negotiation_data),
                            &negotiation_sz));

    ctx->send_func(ctx, (uint8_t*)&negotiation_data, sizeof(negotiation_data));

    ns_negotiation_data_t * negotiation_struct = (ns_negotiation_data_t*)&negotiation_data[2];

    CHECK (create_handshake(ctx,
                            NOISE_ROLE_INITIATOR,
                            negotiation_struct));
    CHECK (init_handshake(ctx, negotiation_struct));
    CHECK (handshake_start(ctx));

    return NS_OK;
}

static ns_result_t
ns_parse_negotiation_data(ns_ctx_t *ctx, const ns_packet_t *packet) {

    ASSERT(ctx);
    ASSERT(packet);

    if (ntohs(packet->size) != sizeof(ns_negotiation_data_t)) {
        return NS_HANDSHAKE_RECV_ERROR;
    }

    const ns_negotiation_data_t * negotiation_data;
    negotiation_data = (ns_negotiation_data_t *)packet->data;

    if (NOISESOCKET_VERSION != ntohs(negotiation_data->version)) {
        DEBUG_NOISE ("Unsupported noise socket VERSION.\n");
        return NS_VERSION_ERROR;
    }

    // Check requested capabilities
    if (!is_pattern_supported(negotiation_data->pattern)) {
        DEBUG_NOISE ("Unsupported noise pattern : %d.\n", (int)negotiation_data->pattern);
        return NS_UNSUPPORTED_PATERN_ERROR;
    }

    if (!is_dh_supported(negotiation_data->dh)) {
        DEBUG_NOISE ("Unsupported noise DH.\n");
        return NS_UNSUPPORTED_DH_ERROR;
    }

    if (!is_cipher_supported(negotiation_data->cipher)) {
        DEBUG_NOISE ("Unsupported noise CIPHER.\n");
        return NS_UNSUPPORTED_CIPHER_ERROR;
    }

    if (!is_hash_supported(negotiation_data->hash)) {
        DEBUG_NOISE ("Unsupported noise HASH.\n");
        return NS_UNSUPPORTED_HASH_ERROR;
    }

    CHECK (create_handshake(ctx, NOISE_ROLE_RESPONDER, negotiation_data));
    CHECK (init_handshake(ctx, negotiation_data));
    CHECK (handshake_start(ctx));

    return NS_OK;
}

static ns_result_t
handshake_routine(ns_ctx_t *ctx, const ns_packet_t *packet) {
    // TODO: make it faster and safe
    uint8_t message[512];
    NoiseBuffer mbuf;
    bool packet_used = false;

    NoiseHandshakeState *hs = ctx->handshake.noise;

    while (true) {
        int action = noise_handshakestate_get_action(hs);
        if (action == NOISE_ACTION_WRITE_MESSAGE) {
            // Write the next handshake message with a zero-length payload
            noise_buffer_set_output(mbuf, message + 2, sizeof(message) - 2);
            int err = noise_handshakestate_write_message(hs, &mbuf, NULL);
            if (err != NOISE_ERROR_NONE) {
                DEBUG_NOISE("Noise write handshake error %d \n", err);
                return NS_HANDSHAKE_ERROR;
            }

            // TODO: Send prepared message
            set_net_uint16(message, mbuf.size);
            ctx->send_func(ctx, message, mbuf.size + 2);

        } else if (action == NOISE_ACTION_READ_MESSAGE) {
            if (!packet || packet_used) {
                return NS_HANDSHAKE_IN_PROGRESS;
            }
            packet_used = true;

#if 0 // Arduino ?
            // Dummy read
            recvBackend(message, 2);
#endif

            // Read the next handshake message and discard the payload
            int message_size = ntohs(packet->size);
            if (!message_size) {
                return NS_HANDSHAKE_IN_PROGRESS;
            }

            noise_buffer_set_input(mbuf, (uint8_t*)packet->data, message_size);
            int err = noise_handshakestate_read_message(hs, &mbuf, NULL);
            if (err != NOISE_ERROR_NONE) {
                DEBUG_NOISE("Noise process handshake error %d \n", err);
                return NS_HANDSHAKE_ERROR;
            }

            // Dummy send
            if (noise_handshakestate_get_action(hs) < NOISE_ACTION_SPLIT) {
                uint8_t tmp[2];
                memset(tmp, 0, sizeof(tmp));
                ctx->send_func(ctx, tmp, sizeof(tmp));
            }
        } else {
            // Either the handshake has finished or it has failed
            return NS_OK;
        }
    }

    return NS_HANDSHAKE_ERROR;
}

static ns_result_t
split_handshake(ns_ctx_t *ctx) {
    ASSERT(ctx);
    ASSERT(ctx->handshake.noise);

    // If the action is not "split", then the handshake has failed
    if (NOISE_ACTION_SPLIT != noise_handshakestate_get_action(ctx->handshake.noise)) {
        return NS_HANDSHAKE_SPLIT_ERROR;
    }

    // Split out the two CipherState objects for send and receive
    int err = noise_handshakestate_split(ctx->handshake.noise,
                                         &ctx->send_cipher,
                                         &ctx->recv_cipher);
    if (err != NOISE_ERROR_NONE) {
        return NS_HANDSHAKE_SPLIT_ERROR;
    }

    return NS_OK;
}

ns_result_t
ns_process_handshake(ns_ctx_t *ctx, const ns_packet_t *packet) {
    ASSERT(ctx);
    ASSERT(!ctx->handshake.ready);

    switch (ctx->handshake.state) {
        case NS_HS_NEGOTIATION:
            if (ctx->handshake.is_client) {
                DEBUG_NOISE("Send negotiation data.\n");
                CHECK_MES(ns_send_negotiation_data(ctx),
                          DEBUG_NOISE("Negotiation error.\n"));
                ++ctx->handshake.state;
                DEBUG_NOISE("Done.\n");
            } else {
                DEBUG_NOISE("Process negotiation data.\n");
                CHECK_MES(ns_parse_negotiation_data(ctx, packet),
                          DEBUG_NOISE("Negotiation error.\n"));
                ++ctx->handshake.state;
                DEBUG_NOISE("Done.\n");
            }

            return NS_HANDSHAKE_IN_PROGRESS;

        case NS_HS_ROUTINE:
            DEBUG_NOISE("Process handshake routine.\n");
            ns_result_t res;
            res = handshake_routine(ctx, packet);

            if (NS_OK == res) {
                ns_result_t res;
                res = split_handshake(ctx);
                noise_handshakestate_free(ctx->handshake.noise);
                ctx->handshake.noise = NULL;
                return res;
            }

            if (NS_HANDSHAKE_IN_PROGRESS == res) {
                return res;
            }

            DEBUG_NOISE("Handshake routine Error.\n");
            return res;
        default: {
        }
    }

    return NS_HANDSHAKE_ERROR;
}