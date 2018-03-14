//
// Created by Roman Kutashenko on 2/14/18.
//

#include <string.h>
#include <noisesocket/types.h>

#include "handshake.h"
#include "helper.h"
#include "debug.h"
#include "noise/protocol.h"

static const char * HANDSHAKE_INIT_STRING = "NoiseSocketInit1";
static const uint8_t ACK_PACKET[] = {0x00, 0x01, 0x01};


struct ns_handshake_s {
    bool is_client;
    ns_handshake_state_t state;
    void *base_context;

    ns_crypto_t crypto_ctx;
    ns_connection_params_t connection_params;

    ns_verify_sender_cb_t verify_sender_cb;

    ns_handshake_state_change_cb_t state_change_cb;
    ns_send_backend_t send_func;

    uint8_t *initial_data;
    size_t initial_data_sz;

    NoiseHandshakeState *noise;
    NoiseCipherState *send_cipher;
    NoiseCipherState *recv_cipher;
};

static ns_result_t
create_handshake(ns_handshake_t *ctx) {
    ASSERT(ctx);
    ASSERT(0 == ctx->noise);

    noise_init();

    NoiseProtocolId nid;
    memset(&nid, 0, sizeof(nid));

    nid.pattern_id = NOISE_ID('P', ctx->connection_params.patern);
    nid.cipher_id = NOISE_ID('C', ctx->connection_params.cipher);
    nid.dh_id = NOISE_ID('D', ctx->connection_params.dh);
    nid.hash_id = NOISE_ID('H', ctx->connection_params.hash);
    nid.prefix_id = NOISE_PREFIX_STANDARD;

    // Create a HandshakeState object for the protocol
    int err;
    err = noise_handshakestate_new_by_id(&ctx->noise,
                                         &nid,
                                         ctx->is_client ? NOISE_ROLE_INITIATOR : NOISE_ROLE_RESPONDER);

    if (NOISE_ERROR_NONE != err) {
        DEBUG_NOISE("Noise handshake can't be created.\n");
        return NS_HANDSHAKE_ERROR;
    }

    err =  noise_handshakestate_set_meta_data(ctx->noise, ctx->crypto_ctx.meta_data, sizeof(ctx->crypto_ctx.meta_data));
    if (NOISE_ERROR_NONE != err) {
        DEBUG_NOISE("Noise handshake can't be created. Cannot set Meta Data.\n");
        return NS_HANDSHAKE_ERROR;
    }

    err = noise_handshakestate_set_sender_verification(
            ctx->noise, (VerifySender)ctx->verify_sender_cb, ctx->base_context);

    if (NOISE_ERROR_NONE != err) {
        DEBUG_NOISE("Noise handshake can't be created. Cannot set sender verification callback.\n");
        return NS_HANDSHAKE_ERROR;
    }

    return NS_OK;
}

static ns_result_t
fill_prologue(ns_handshake_t *ctx,
              uint8_t *buf, size_t buf_sz, size_t *data_sz,
              const uint8_t * initial_data,
              size_t initial_data_sz) {
    ASSERT(ctx);
    ASSERT(buf);
    ASSERT(buf_sz);
    ASSERT(data_sz);

    const int init_str_sz = strlen(HANDSHAKE_INIT_STRING);
    *data_sz = init_str_sz + initial_data_sz;

    if (buf_sz < *data_sz) return NS_HANDSHAKE_ERROR;

    memcpy(buf, HANDSHAKE_INIT_STRING, init_str_sz);
    memcpy(&buf[init_str_sz], initial_data, initial_data_sz);

    return NS_OK;
}

static ns_result_t
init_handshake(ns_handshake_t *ctx) {
    ASSERT(ctx);
    ASSERT(ctx->noise);

    // Create Prologue
    uint8_t prologue[32];
    size_t prologue_sz = 0;

    CHECK_MES (fill_prologue(ctx,
                             prologue, sizeof(prologue), &prologue_sz,
                             ctx->initial_data,
                             ctx->initial_data_sz),
               DEBUG_NOISE("prologue can't be initialized\n"));

    // Setup prologue
    int err;
    err = noise_handshakestate_set_prologue(ctx->noise,
                                            prologue, prologue_sz);

    if (err != NOISE_ERROR_NONE) {
        DEBUG_NOISE("Prologue ERROR %d \n", err);
        return NS_HANDSHAKE_ERROR;
    }

    // Set keypair for handshake
    NoiseDHState *dh;
    dh = noise_handshakestate_get_local_keypair_dh(ctx->noise);
    err = noise_dhstate_set_keypair(dh,
                                    ctx->crypto_ctx.private_key, noise_dhstate_get_private_key_length(dh),
                                    ctx->crypto_ctx.public_key, noise_dhstate_get_private_key_length(dh));
    if (err != NOISE_ERROR_NONE) {
        DEBUG_NOISE("set client key pair ERROR %d\n", err);
        return NS_HANDSHAKE_ERROR;
    }

    return NS_OK;
}

static ns_result_t
handshake_start(ns_handshake_t *ctx) {
    ASSERT(ctx);
    ASSERT(ctx->noise);

    int err = noise_handshakestate_start(ctx->noise);
    if (NOISE_ERROR_NONE != err) {
        DEBUG_NOISE("Start handshake error %d \n", err);
        return NS_HANDSHAKE_ERROR;
    }

    return NS_OK;
}

static ns_result_t
handshake_routine(ns_handshake_t *ctx, const ns_packet_t *packet) {
    // TODO: make it faster and safe
    uint8_t message[512];
    NoiseBuffer mbuf;
    bool packet_used = false;

    NoiseHandshakeState *hs = ctx->noise;

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
            ctx->send_func(ctx->base_context, message, mbuf.size + 2);

        } else if (action == NOISE_ACTION_READ_MESSAGE) {
            if (!packet || packet_used) {
                return NS_OK;
            }
            packet_used = true;

            // Read the next handshake message and discard the payload
            int message_size = ntohs(packet->size);
            if (!message_size) {
                return NS_OK;
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
                ctx->send_func(ctx->base_context, tmp, sizeof(tmp));
            }
        } else if (action == NOISE_ACTION_SPLIT) {
            if (ctx->is_client) {
                ctx->state = NS_HANDSHAKE_WAIT_SERVER_ACCEPT;
            } else {
                // Send accept
                ctx->send_func(ctx->base_context, ACK_PACKET, sizeof(ACK_PACKET));
                ctx->state = NS_HANDSHAKE_DONE;
            }

            return NS_OK;
        }
    }

    return NS_HANDSHAKE_ERROR;
}

static ns_result_t
split_handshake(ns_handshake_t *ctx) {
    ASSERT(ctx);
    ASSERT(ctx->noise);

    // If the action is not "split", then the handshake has failed
    if (NOISE_ACTION_SPLIT != noise_handshakestate_get_action(ctx->noise)) {
        return NS_HANDSHAKE_SPLIT_ERROR;
    }

    // Split out the two CipherState objects for send and receive
    int err = noise_handshakestate_split(ctx->noise,
                                         &ctx->send_cipher,
                                         &ctx->recv_cipher);
    if (err != NOISE_ERROR_NONE) {
        return NS_HANDSHAKE_SPLIT_ERROR;
    }

    return NS_OK;
}

static void
publish_state_change(ns_handshake_t *ctx, ns_result_t result) {
            ASSERT(ctx);

    if (!ctx->state_change_cb) return;
    ctx->state_change_cb(ctx, ctx->base_context, ctx->state, result);
}

ns_result_t
handshake_process_client(ns_handshake_t *ctx, const ns_packet_t *packet) {
    ASSERT(ctx);

    ns_result_t res;
    switch(ctx->state) {
        case NS_HANDSHAKE_NOT_STARTED:
            CHECK (create_handshake(ctx));
            CHECK (init_handshake(ctx));
            CHECK (handshake_start(ctx));
            handshake_routine(ctx, packet);
            ++ctx->state;

        case NS_HANDSHAKE_IN_PROGRESS:
            res = handshake_routine(ctx, packet);

            if (NS_HANDSHAKE_DONE == ns_handshake_state(ctx)) {
                res = split_handshake(ctx);
                noise_handshakestate_free(ctx->noise);
                ctx->noise = NULL;
                publish_state_change(ctx, res);
            }
            return res;

        case NS_HANDSHAKE_WAIT_SERVER_ACCEPT:
            if (0 == memcmp(ACK_PACKET, (uint8_t*)packet, sizeof(ACK_PACKET))) {
                ctx->state = NS_HANDSHAKE_DONE;
                res = split_handshake(ctx);
                noise_handshakestate_free(ctx->noise);
                ctx->noise = NULL;
                publish_state_change(ctx, res);
                return res;
            }
            break;

        default: {
            publish_state_change(ctx, NS_HANDSHAKE_ERROR);
        }
    }

    return NS_HANDSHAKE_ERROR;
}

ns_result_t
handshake_process_server(ns_handshake_t *ctx, const ns_packet_t *packet) {
    ASSERT(ctx);

    const ns_packet_t *in_packet = packet;
    ns_result_t res;

    switch(ctx->state) {
        case NS_HANDSHAKE_NOT_STARTED:
            CHECK (create_handshake(ctx));
            CHECK (init_handshake(ctx));
            CHECK (handshake_start(ctx));
            handshake_routine(ctx, in_packet);
            in_packet = NULL;
            ++ctx->state;

        case NS_HANDSHAKE_IN_PROGRESS:
            res = handshake_routine(ctx, in_packet);

            if (NS_HANDSHAKE_DONE == ns_handshake_state(ctx)) {
                res = split_handshake(ctx);
                noise_handshakestate_free(ctx->noise);
                ctx->noise = NULL;
                publish_state_change(ctx, res);
            } else if (NS_HANDSHAKE_ERROR == res) {
                publish_state_change(ctx, res);
            }
            return res;

        default: {
            publish_state_change(ctx, NS_HANDSHAKE_ERROR);
        }
    }

    return NS_HANDSHAKE_ERROR;
}

ns_result_t
ns_handshake_process(ns_handshake_t *ctx, const ns_packet_t *packet) {
    ASSERT(ctx);

    if (ctx->is_client) {
        return handshake_process_client(ctx, packet);
    }

    return handshake_process_server(ctx, packet);
}

ns_result_t
ns_handshake_new(ns_handshake_t **ctx,
                  bool is_client,
                  void *base_context,
                  const ns_crypto_t *crypto_ctx,
                  ns_send_backend_t send_func,
                  ns_handshake_state_change_cb_t state_change_cb,
                  ns_verify_sender_cb_t verify_sender_cb) {

    ASSERT(ctx);
    ASSERT(crypto_ctx);
    ASSERT(send_func);

    *ctx = calloc(1, sizeof(ns_handshake_t));
    ASSERT(*ctx);

    if (!*ctx) {
        return NS_ALLOC_ERROR;
    }

    memset(*ctx, 0, ns_handshake_ctx_size());
    (*ctx)->is_client = is_client;
    (*ctx)->state = NS_HANDSHAKE_NOT_STARTED;
    (*ctx)->state_change_cb = state_change_cb;
    (*ctx)->send_func = send_func;
    (*ctx)->base_context = base_context;
    (*ctx)->verify_sender_cb = verify_sender_cb;
    memcpy(&(*ctx)->crypto_ctx, crypto_ctx, sizeof(ns_crypto_t));

    return NS_OK;
}

ns_result_t
ns_handshake_free(ns_handshake_t *ctx) {
    ASSERT(ctx);

    if (!ctx) {
        return NS_OK;
    }

    if (ctx->noise) {
        noise_handshakestate_free(ctx->noise);
    }

    if (ctx->initial_data) {
        free(ctx->initial_data);
    }

    free(ctx);

    return NS_OK;
}

size_t
ns_handshake_ctx_size() {
    return sizeof(ns_handshake_t);
}

ns_handshake_state_t
ns_handshake_state(ns_handshake_t *ctx) {
    ASSERT(ctx);
    return ctx->state;
}

void *
ns_handshake_send_cipher(ns_handshake_t *ctx) {
    ASSERT(ctx);
    return ctx->send_cipher;
}

void *
ns_handshake_recv_cipher(ns_handshake_t *ctx) {
    ASSERT(ctx);
    return ctx->recv_cipher;
}

void
ns_handshake_set_params(ns_handshake_t *ctx,
                        ns_connection_params_t *connection_params,
                        const uint8_t *initial_data,
                        size_t initial_data_sz) {
    ASSERT(ctx);
    ASSERT(initial_data);
    ASSERT(connection_params);

    memcpy(&ctx->connection_params,
           connection_params,
           sizeof(ctx->connection_params));

    ctx->initial_data = malloc(initial_data_sz);
    ctx->initial_data_sz = initial_data_sz;
    memcpy(ctx->initial_data, initial_data, initial_data_sz);
}