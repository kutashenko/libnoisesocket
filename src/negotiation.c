//
// Created by Roman Kutashenko on 2/14/18.
//

#include "debug.h"
#include "helper.h"
#include "negotiation.h"

#include <string.h>
#include <pb_encode.h>
#include <pb_decode.h>
#include <negotiation.pb.h>

#define PROTOCOL_MAX_SIZE   100

static negotiation_initial_data _negotiation_initial_data = negotiation_initial_data_init_zero;
static bool _params_cached = false;
const char *separator = "_";

struct ns_negotiation_s {
    bool is_client;
    ns_negotiation_state_t state;
    ns_negotiation_state_change_cb_t state_change_cb;
    ns_send_backend_t send_func;
    ns_connection_params_t connection_params;
    void *base_context;
    const ns_negotiation_params_t *params;
};

static bool
compare_protocol_element(const char *protocol_str, const char *required_val) {
    ASSERT(protocol_str);
    ASSERT(required_val);

    return NULL != strstr(protocol_str, required_val);
}

static const char *
patern_to_str(ns_patern_t patern) {
    if (NS_PATTERN_XX == patern) {
        return "XX";
    }

    return NULL;
}

static ns_result_t
str_to_patern(const char *str, ns_patern_t *patern) {
    if (compare_protocol_element(str, "XX")) {
        *patern = NS_PATTERN_XX;
        return NS_OK;
    }

    return NS_UNSUPPORTED_PROTOCOL_ERROR;
}

static const char *
dh_to_str(ns_dh_t dh) {
    if (NS_DH_CURVE25519 == dh) {
        return "25519";
    }

    return NULL;
}

static ns_result_t
str_to_dh(const char *str, ns_dh_t *dh) {
    if (compare_protocol_element(str, "25519")) {
        *dh = NS_DH_CURVE25519;
        return NS_OK;
    }

    return NS_UNSUPPORTED_PROTOCOL_ERROR;
}

static const char *
cipher_to_str(ns_cipher_t cipher) {
    if (NS_CIPHER_AES_GCM == cipher) {
        return "AESGCM";
    } else if (NS_CIPHER_CHACHAPOLY == cipher) {
        return "CHACHAPOLY";
    }

    return NULL;
}

static ns_result_t
str_to_cipher(const char *str, ns_cipher_t *cipher) {
    if (compare_protocol_element(str, "AESGCM")) {
        *cipher = NS_CIPHER_AES_GCM;
        return NS_OK;
    } else if (compare_protocol_element(str, "CHACHAPOLY")) {
        *cipher = NS_CIPHER_CHACHAPOLY;
        return NS_OK;
    }

    return NS_UNSUPPORTED_PROTOCOL_ERROR;
}

static const char *
hash_to_str(ns_hash_t hash) {
    if (NS_HASH_BLAKE_2B == hash) {
        return "BLAKE2b";
//    } else if (NS_HASH_BLAKE_2S == hash) {
//        return "BLAKE2s";
    } else if (NS_HASH_SHA256 == hash) {
        return "SHA256";
    } else if (NS_HASH_SHA512 == hash) {
        return "SHA512";
    }

    return NULL;
}

static ns_result_t
str_to_hash(const char *str, ns_hash_t *hash) {
    if (compare_protocol_element(str, "BLAKE2b")) {
        *hash = NS_HASH_BLAKE_2B;
        return NS_OK;
//    } else if (compare_protocol_element(str, "BLAKE2s")) {
//        *hash = NS_HASH_BLAKE_2S;
//        return NS_OK;
    } else if (compare_protocol_element(str, "SHA256")) {
        *hash = NS_HASH_SHA256;
        return NS_OK;
    } else if (compare_protocol_element(str, "SHA512")) {
        *hash = NS_HASH_SHA512;
        return NS_OK;
    }

    return NS_UNSUPPORTED_PROTOCOL_ERROR;
}

static ns_result_t
protocol_to_str(ns_patern_t patern, ns_dh_t dh,
                ns_cipher_t cipher, ns_hash_t hash,
                char *buf, size_t buf_sz) {

    const char *patern_str = 0;
    const char *dh_str = 0;
    const char *cipher_str = 0;
    const char *hash_str = 0;

    const char *prefix = "Noise";

    memset(buf, 0, buf_sz);

    patern_str = patern_to_str(patern);
    if (!patern_str) {
        DEBUG_NOISE("Cannot convert patern to string %d\n", (int)patern);
        return NS_UNSUPPORTED_PROTOCOL_ERROR;
    }

    dh_str = dh_to_str(dh);
    if (!dh_str) {
        DEBUG_NOISE("Cannot convert DH to string %d\n", (int)dh);
        return NS_UNSUPPORTED_PROTOCOL_ERROR;
    }

    cipher_str = cipher_to_str(cipher);
    if (!cipher_str) {
        DEBUG_NOISE("Cannot convert Cipher to string %d\n", (int)cipher);
        return NS_UNSUPPORTED_PROTOCOL_ERROR;
    }

    hash_str = hash_to_str(hash);
    if (!hash_str) {
        DEBUG_NOISE("Cannot convert Hash to string %d\n", (int)hash);
        return NS_UNSUPPORTED_PROTOCOL_ERROR;
    }


    const size_t total_sz =
            strlen(prefix) +
            strlen(patern_str) +
            strlen(dh_str) +
            strlen(cipher_str) +
            strlen(hash_str) +
            4 * sizeof(separator); // 4 additional separators

    if (total_sz <= buf_sz) {
        DEBUG_NOISE("Cannot convert Protocol to string\n");
        return NS_SMALL_BUFFER_ERROR;
    }

    strcat(buf, prefix),
            strcat(buf, separator);
    strcat(buf, patern_str),
            strcat(buf, separator);
    strcat(buf, dh_str),
            strcat(buf, separator);
    strcat(buf, cipher_str),
            strcat(buf, separator);
    strcat(buf, hash_str);

    return NS_OK;
}

static ns_result_t
fill_own_params(ns_negotiation_t *ctx) {
    if (!_params_cached) {
        const size_t protocol_str_max_sz = 40;
        char protocol_str[protocol_str_max_sz];

        CHECK_MES(protocol_to_str(ctx->params->default_patern,
                                  ctx->params->default_dh,
                                  ctx->params->default_cipher,
                                  ctx->params->default_hash,
                                  protocol_str, protocol_str_max_sz),
                  DEBUG_NOISE("Cannot convert ptorocol to string because if small buffer\n"));

        DEBUG_NOISE("Initial protocol is %s\n", protocol_str);

        memset(_negotiation_initial_data.initial_protocol, 0,
               sizeof(_negotiation_initial_data.initial_protocol));
        strncpy(_negotiation_initial_data.initial_protocol,
                protocol_str,
                sizeof(_negotiation_initial_data.initial_protocol) - 1);
        _negotiation_initial_data.switch_protocols_count = 0;
        _negotiation_initial_data.retry_protocols_count = 0;

        int i, m, n, q;
        for (i = 0; i < ctx->params->available_paterns_cnt; ++i) {
            for (m = 0; m < ctx->params->available_dh_s_cnt; ++m) {
                for (n = 0; n < ctx->params->available_ciphers_cnt; ++n) {
                    for (q = 0; q < ctx->params->available_hashes_cnt; ++q) {

                        if (ctx->params->available_paterns[i] != ctx->params->default_patern
                            || ctx->params->available_dh_s[m] != ctx->params->default_dh
                            || ctx->params->available_ciphers[n] != ctx->params->default_cipher
                            || ctx->params->available_hashes[q] != ctx->params->default_hash) {

                            CHECK_MES(protocol_to_str(ctx->params->available_paterns[i],
                                                      ctx->params->available_dh_s[m],
                                                      ctx->params->available_ciphers[n],
                                                      ctx->params->available_hashes[q],
                                                      protocol_str, protocol_str_max_sz),
                                      DEBUG_NOISE("Cannot convert ptorocol to string because if small buffer\n"));

                            strcpy(_negotiation_initial_data.switch_protocols[_negotiation_initial_data.switch_protocols_count],
                                   protocol_str);
                            ++_negotiation_initial_data.switch_protocols_count;

                            DEBUG_NOISE("Available protocol is %s\n", protocol_str);
                        }
                    }
                }
            }
        }
        _params_cached = true;
    }

    return NS_OK;
}

static ns_result_t
fill_negotiation(ns_negotiation_t *ctx,
                 uint8_t * packet,
                 size_t buf_sz,
                 size_t *data_sz) {
    ASSERT(ctx);
    ASSERT(ctx->params);
    ASSERT(packet);
    ASSERT(buf_sz);
    ASSERT(data_sz);

    fill_own_params(ctx);

    // Create a stream that will write to our buffer.
    pb_ostream_t stream = pb_ostream_from_buffer(&packet[2], buf_sz - 2);

    // Now we are ready to encode the message !
    int status = pb_encode(&stream, negotiation_initial_data_fields, &_negotiation_initial_data);
    *data_sz = stream.bytes_written;

    // Then just check for any errors ...
    if (!status) {
        DEBUG_NOISE("Encoding failed: %s\n", PB_GET_ERROR(&stream));
        return NS_SMALL_BUFFER_ERROR;
    }

    set_net_uint16(packet, *data_sz);
    *data_sz += 2;

    return NS_OK;
}

static bool
is_protocol_available(const char *protocol) {
    ASSERT(protocol);
    ASSERT(*protocol);

    if (0 == strncmp(protocol, _negotiation_initial_data.initial_protocol, PROTOCOL_MAX_SIZE)) {
        return true;
    }

    int i;
    for (i = 0; i < _negotiation_initial_data.switch_protocols_count; ++i) {
        if (0 == strncmp(protocol, _negotiation_initial_data.switch_protocols[i], PROTOCOL_MAX_SIZE)) {
            return true;
        }
    }

    return false;
}

static ns_result_t
ns_parse_negotiation_data(ns_negotiation_t *ctx, const ns_packet_t *packet,
                          char *protocol_res, size_t buf_sz) {

    ASSERT(ctx);
    ASSERT(packet);

    ns_result_t res = NS_NEGOTIATION_ERROR;

    DEBUG_NOISE("Process negotiation data.\n");

    fill_own_params(ctx);

    negotiation_initial_data *message = calloc(1, sizeof(negotiation_initial_data));

    // Create a stream that reads from the buffer.
    pb_istream_t stream = pb_istream_from_buffer(packet->data, ntohs(packet->size));

    // Now we are ready to decode the message.
    int status = pb_decode(&stream, negotiation_initial_data_fields, message);

    // Check for errors ...
    if (!status) {
        DEBUG_NOISE("Decoding failed: %s\n", PB_GET_ERROR(&stream));
        goto clean;
    }

    const char *accepted_protocol = NULL;
    if (is_protocol_available(message->initial_protocol)) {
        accepted_protocol = message->initial_protocol;
    } else {
        int i;
        for (i = 0; i < message->switch_protocols_count; ++i) {
            if (is_protocol_available(message->switch_protocols[i])) {
                accepted_protocol = message->switch_protocols[i];
            }
        }
    }

    if (accepted_protocol) {
        CHECK(str_to_patern(accepted_protocol, &ctx->connection_params.patern));
        CHECK(str_to_dh(accepted_protocol, &ctx->connection_params.dh));
        CHECK(str_to_cipher(accepted_protocol, &ctx->connection_params.cipher));
        CHECK(str_to_hash(accepted_protocol, &ctx->connection_params.hash));

        if (strlen(accepted_protocol) > buf_sz) {
            DEBUG_NOISE("Cannot copy acceped protocol.\n");
            res = NS_SMALL_BUFFER_ERROR;
            goto clean;
        }

        strcpy(protocol_res, accepted_protocol);

        res = NS_OK;
    } else {
        res = NS_UNSUPPORTED_PROTOCOL_ERROR;
    }

clean:

    free(message);

    return res;
}

static ns_result_t
ns_parse_negotiation_response(ns_negotiation_t *ctx, const ns_packet_t *packet) {

    ASSERT(ctx);
    ASSERT(packet);

    ns_result_t res = NS_NEGOTIATION_ERROR;

    DEBUG_NOISE("Process negotiation response.\n");

    negotiation_response_data *message = calloc(1, sizeof(negotiation_response_data));

    // Create a stream that reads from the buffer.
    pb_istream_t stream = pb_istream_from_buffer(packet->data, ntohs(packet->size));

    // Now we are ready to decode the message.
    int status = pb_decode(&stream, negotiation_response_data_fields, message);

    // Check for errors ...
    if (!status) {
        DEBUG_NOISE("Decoding failed: %s\n", PB_GET_ERROR(&stream));
        goto clean;
    }

    if (!message->accept || !message->switch_protocol[0]) {
        DEBUG_NOISE("Server rejected connection.\n");
        res = NS_NEGOTIATION_REJECT_FROM_SERVER;
        goto clean;
    }

    if (!is_protocol_available(message->switch_protocol)) {
        DEBUG_NOISE("Server requests unsupported protocol.\n");
        res = NS_UNSUPPORTED_PROTOCOL_ERROR;
        goto clean;
    }

    DEBUG_NOISE("Accepted protocol %s.\n", message->switch_protocol);

    CHECK(str_to_patern(message->switch_protocol, &ctx->connection_params.patern));
    CHECK(str_to_dh(message->switch_protocol, &ctx->connection_params.dh));
    CHECK(str_to_cipher(message->switch_protocol, &ctx->connection_params.cipher));
    CHECK(str_to_hash(message->switch_protocol, &ctx->connection_params.hash));

    res = NS_OK;

clean:

    free(message);

    return res;
}

static ns_result_t
ns_send_negotiation_data(ns_negotiation_t *ctx) {
    ASSERT(ctx);
    ASSERT(ctx->send_func);

    DEBUG_NOISE("Send negotiation data.\n");

    size_t negotiation_sz = 0;

    uint8_t negotiation_data[1024];

    CHECK (fill_negotiation(ctx,
                            negotiation_data,
                            sizeof(negotiation_data),
                            &negotiation_sz));

    ctx->send_func(ctx->base_context, negotiation_data, negotiation_sz);

    return NS_OK;
}

static ns_result_t
ns_send_negotiation_response(ns_negotiation_t *ctx, bool accepted, const char *protocol) {
    ASSERT(ctx);
    ASSERT(ctx->send_func);

    DEBUG_NOISE("Send negotiation response %s.\n", protocol ? protocol : "REJECT");

    ns_result_t res = NS_NEGOTIATION_ERROR;

    const size_t buf_sz = 1024;
    uint8_t *buf = malloc(buf_sz);

    negotiation_response_data message = negotiation_response_data_init_zero;

    // Create a stream that will write to our buffer.
    pb_ostream_t stream = pb_ostream_from_buffer(&buf[2], buf_sz - 2);

    message.accept = accepted;
    if (accepted) {
        if (strnlen(protocol, PROTOCOL_MAX_SIZE) > sizeof(message.switch_protocol)) {
            DEBUG_NOISE("Cannot create negotiation response because of wrong Protocol string.\n");
            goto clean;
        }
        strcpy(message.switch_protocol, protocol);
    }

    // Now we are ready to encode the message !
    int status = pb_encode(&stream, negotiation_response_data_fields, &message);

    // Then just check for any errors ...
    if (!status) {
        DEBUG_NOISE("Encoding failed: %s\n", PB_GET_ERROR(&stream));
        res = NS_SMALL_BUFFER_ERROR;
        goto clean;
    }

    set_net_uint16(buf, stream.bytes_written);

    ctx->send_func(ctx->base_context, buf, stream.bytes_written + 2);

    res = NS_OK;

clean:
    free(buf);

    return res;
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
    ns_result_t res;
    switch (ctx->state) {
        case NS_NEGOTIATION_NOT_STARTED:
            res = ns_send_negotiation_data(ctx);
            if (NS_OK == res) {
                ctx->state = NS_NEGOTIATION_IN_PROGRESS;//NS_NEGOTIATION_DONE;
            }
            publish_state_change(ctx, res);

            return NS_OK;

        case NS_NEGOTIATION_IN_PROGRESS:
            res = ns_parse_negotiation_response(ctx, packet);

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
    char accepted_protocol[PROTOCOL_MAX_SIZE];
    switch (ctx->state) {
        case NS_NEGOTIATION_NOT_STARTED:

            res = ns_parse_negotiation_data(ctx, packet, accepted_protocol, PROTOCOL_MAX_SIZE);

            res = ns_send_negotiation_response(ctx,
                                               NS_OK == res,
                                               accepted_protocol);

            ctx->state = NS_NEGOTIATION_DONE;
            publish_state_change(ctx, res);

            break;

        default: {
            publish_state_change(ctx, NS_NEGOTIATION_ERROR);
        }
    }

    return NS_NEGOTIATION_ERROR;
}

ns_result_t
ns_negotiation_process(ns_negotiation_t *ctx, const ns_packet_t *packet) {
    ASSERT(ctx);

    if (ctx->is_client) {
        return negotiation_process_client(ctx, packet);
    }

    return negotiation_process_server(ctx, packet);
}

ns_result_t
ns_negotiation_new(ns_negotiation_t **ctx,
                    bool is_client,
                    void *base_context,
                    const ns_negotiation_params_t *params,
                    ns_send_backend_t send_func,
                    ns_negotiation_state_change_cb_t state_change_cb) {

    ASSERT(ctx);
    ASSERT(base_context);
    ASSERT(params);
    ASSERT(params->available_ciphers_cnt);
    ASSERT(params->available_dh_s_cnt);
    ASSERT(params->available_hashes_cnt);
    ASSERT(params->available_paterns_cnt);

    DEBUG_NOISE("Init negotiation\n");

    *ctx = calloc(1, sizeof(ns_negotiation_t));

    (*ctx)->is_client = is_client;
    (*ctx)->state = NS_NEGOTIATION_NOT_STARTED;
    (*ctx)->state_change_cb = state_change_cb;
    (*ctx)->send_func = send_func;
    (*ctx)->base_context = base_context;
    (*ctx)->params = params;

    return NS_OK;
}

ns_result_t
ns_negotiation_free(ns_negotiation_t *ctx) {
    DEBUG_NOISE("Free negotiation\n");
    ASSERT(ctx);

    if (!ctx) {
        return NS_PARAM_ERROR;
    }

    free(ctx);

    return NS_OK;
}

ns_negotiation_state_t
ns_negotiation_state(ns_negotiation_t *ctx) {
    ASSERT(ctx);
    return ctx->state;
}

const uint8_t *
ns_negotiation_initial_data(ns_negotiation_t *ctx) {
    ASSERT(ctx);
    return (uint8_t *)&ctx->connection_params;
}

size_t
ns_negotiation_initial_data_sz(ns_negotiation_t *ctx) {
    return sizeof(ns_connection_params_t);
}
