//
// Created by Roman Kutashenko on 2/14/18.
//

#include "debug.h"
#include "helper.h"
#include "negotiation.h"
#include "noise/protobufs.h"

#include <string.h>

#define NG(X) ((ns_negotiation_t*)X)

#define NEGOTIATION_SZ (2 + sizeof(ns_negotiation_data_t))

#define NOISESOCKET_VERSION (1)

#define DEFAULT_PATERN  (NS_PATTERN_XX)
#define DEFAULT_DH      (NS_DH_CURVE25519)
#define DEFAULT_CIPHER  (NS_CIPHER_AES_GCM)
#define DEFAULT_HASH    (NS_HASH_BLAKE_2B)

typedef struct __attribute__((__packed__)) {
    uint16_t version;
    uint8_t dh;
    uint8_t cipher;
    uint8_t hash;
    uint8_t pattern;
} ns_negotiation_data_t;

typedef struct {
    bool is_client;
    ns_negotiation_state_t state;
    ns_negotiation_state_change_cb_t state_change_cb;
    ns_send_backend_t send_func;
    ns_connection_params_t connection_params;
    void *base_context;
    uint8_t negotiation_data[NEGOTIATION_SZ];
} ns_negotiation_t;

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

// TODO: Pass ns_negotiation_data_t instead of buffer
static ns_result_t
fill_negotiation(ns_negotiation_t *ctx,
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
    negotiation_data->dh = ctx->connection_params.dh;
    negotiation_data->cipher = ctx->connection_params.cipher;
    negotiation_data->hash = ctx->connection_params.hash;
    negotiation_data->pattern = ctx->connection_params.patern;

    return NS_OK;
}

static ns_result_t
ns_parse_negotiation_data(ns_negotiation_t *ctx, const ns_packet_t *packet) {

    ASSERT(ctx);
    ASSERT(packet);

    DEBUG_NOISE("Process negotiation data.\n");

    if (ntohs(packet->size) != sizeof(ns_negotiation_data_t)) {
        DEBUG_NOISE("Cannot parse negotiation data.\n");
        return NS_NEGOTIATION_ERROR;
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

    ctx->connection_params.hash = (ns_hash_t) negotiation_data->hash;
    ctx->connection_params.dh = (ns_dh_t) negotiation_data->dh;
    ctx->connection_params.cipher = (ns_cipher_t) negotiation_data->cipher;
    ctx->connection_params.patern = (ns_patern_t) negotiation_data->pattern;

    size_t sz;
    fill_negotiation(ctx,
                     ctx->negotiation_data,
                     NEGOTIATION_SZ,
                     &sz);

    return NS_OK;
}

static ns_result_t
ns_send_negotiation_data(ns_negotiation_t *ctx) {
    ASSERT(ctx);
    ASSERT(NG(ctx)->send_func);

    DEBUG_NOISE("Send negotiation data.\n");

    size_t negotiation_sz = 0;

    CHECK (fill_negotiation(ctx,
                            ctx->negotiation_data,
                            NEGOTIATION_SZ,
                            &negotiation_sz));

    ctx->send_func(ctx->base_context, ctx->negotiation_data, NEGOTIATION_SZ);

    return NS_OK;
}

static void
publish_state_change(ns_negotiation_t *ctx, ns_result_t result) {
            ASSERT(ctx);
            ASSERT(ctx->base_context);

    if (!ctx->state_change_cb) return;
    ctx->state_change_cb(ctx,
                         ctx->base_context,
                         ctx->state,
                         result,
                         &ctx->connection_params);
}

static ns_result_t
negotiation_process_client(ns_negotiation_t *ctx, const ns_packet_t *packet) {
    switch (ctx->state) {
        case NS_NEGOTIATION_NOT_STARTED:

            // Set default params
            ctx->connection_params.hash = DEFAULT_HASH & 0xFF;
            ctx->connection_params.dh = DEFAULT_DH & 0xFF;
            ctx->connection_params.cipher = DEFAULT_CIPHER & 0xFF;
            ctx->connection_params.patern = DEFAULT_PATERN & 0xFF;

            ns_result_t res;
            res = ns_send_negotiation_data(ctx);
            if (NS_OK == res) {
                ctx->state = NS_NEGOTIATION_DONE;
            }
            publish_state_change(ctx, res);

            return NS_OK;

        default: {
            publish_state_change(ctx, NS_NEGOTIATION_ERROR);
        }
    }
    return NS_NEGOTIATION_ERROR;
}

static ns_result_t
negotiation_process_server(ns_negotiation_t *ctx, const ns_packet_t *packet) {
    ASSERT(ctx);
    ASSERT(packet);

    ns_result_t res;
    switch (ctx->state) {
        case NS_NEGOTIATION_NOT_STARTED:
            res = ns_parse_negotiation_data(ctx, packet);

            if (NS_OK == res) {
                ctx->state = NS_NEGOTIATION_DONE;
            }
            publish_state_change(ctx, res);

            break;

        default: {
            publish_state_change(ctx, NS_NEGOTIATION_ERROR);
        }
    }

    return NS_NEGOTIATION_ERROR;
}

ns_result_t
ns_negotiation_process(void *ctx, const ns_packet_t *packet) {
    ASSERT(ctx);

    if (NG(ctx)->is_client) {
        return negotiation_process_client(NG(ctx), packet);
    }

    return negotiation_process_server(NG(ctx), packet);
}

ns_result_t
ns_negotiation_init(void *ctx,
                    bool is_client,
                    void *base_context,
                    ns_send_backend_t send_func,
                    ns_negotiation_state_change_cb_t state_change_cb) {

    ASSERT(ctx);
    ASSERT(base_context);

    DEBUG_NOISE("Init negotiation\n");

    memset(NG(ctx), 0, ns_negotiation_ctx_size());
    NG(ctx)->is_client = is_client;
    NG(ctx)->state = NS_NEGOTIATION_NOT_STARTED;
    NG(ctx)->state_change_cb = state_change_cb;
    NG(ctx)->send_func = send_func;
    NG(ctx)->base_context = base_context;

    return NS_OK;
}

ns_result_t
ns_negotiation_deinit(void *ctx) {
    DEBUG_NOISE("Deinit negotiation\n");
    return NS_OK;
}

ns_negotiation_state_t
ns_negotiation_state(void *ctx) {
    ASSERT(ctx);
    return NG(ctx)->state;
}

size_t
ns_negotiation_ctx_size() {
    return sizeof(ns_negotiation_t);
}

const uint8_t *
ns_negotiation_initial_data(void *ctx) {
    ASSERT(ctx);
    return NG(ctx)->negotiation_data;
}

size_t
ns_negotiation_initial_data_sz(void *ctx) {
    return NEGOTIATION_SZ;
}