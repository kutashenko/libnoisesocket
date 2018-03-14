//
// Created by Roman Kutashenko on 2/13/18.
//

#include <noisesocket/types.h>
#include <string.h>
#include "noisesocket-libuv.h"
#include "debug.h"
#include "helper.h"

#define READ_BUF_SZ (64 * 1024)

#define NOISESOCKET_PACKET_SIZE_FIELD (sizeof(uint16_t))

typedef struct {
    uv_close_cb close;
    uv_alloc_cb alloc_cb;
    uv_read_cb read_cb;
    ns_session_ready_cb_t session_ready;
} cb_overload_t;

struct ns_network_s {
    cb_overload_t cb;
    uint8_t read_buf[READ_BUF_SZ];
    size_t read_buf_fill;
    uv_tcp_t *uv_tcp;
};

static void
write_cb(uv_write_t *req, int status) {
    ASSERT(req);

    if (status == -1) {
        DEBUG_NOISE ("Write error!\n");
    }
    char *base = (char *) req->bufsml[0].base;
    free(base);
    free(req);
}

static void
uv_send(void *ctx, const uint8_t *data, size_t data_sz) {
    ASSERT(ctx);
    ASSERT(data);
    ASSERT(data_sz);

    uv_stream_t *stream = (uv_stream_t*)ctx;

    uv_buf_t buf;

    buf.base = malloc(data_sz);
    buf.len = data_sz;
    memcpy(buf.base, data, buf.len);

#if DEBUG_PACKET_CONTENT
    print_buf("Send data", data, data_sz);
#endif

    uv_write_t *write_req = (uv_write_t *) calloc(1, sizeof(uv_write_t));
    uv_write(write_req,
             stream,
             &buf, 1,
             write_cb);
}

static void
publish_result(ns_network_t *ctx, ns_result_t result) {
    ASSERT(ctx);

    if (!ctx->cb.session_ready) return;
    ctx->cb.session_ready(ctx->uv_tcp, result);
}

static void
ns_negotiation_state_change_cb(ns_negotiation_t *ctx,
                               void *handle,
                               ns_negotiation_state_t state,
                               ns_result_t result,
                               ns_connection_params_t *connection_params) {

    ASSERT (ctx);
    ASSERT (handle);

    DEBUG_NOISE("New negotiation state:%d result:%d\n", (int)state, (int)result);


    ns_ctx_t *ns_ctx = 0;
    ns_get_ctx(((uv_tcp_t *)handle)->data, NS_CTX, (void**)&ns_ctx);

    if (NS_OK != result) {
        // Inform user about fail
        publish_result(ns_ctx->network, result);
    } else if (NS_NEGOTIATION_DONE == state) {
        ns_handshake_set_params(ns_ctx->handshake,
                                connection_params,
                                ns_negotiation_initial_data(ctx),
                                ns_negotiation_initial_data_sz(ctx));
        if (ns_ctx->is_client) {
            ns_handshake_process(ns_ctx->handshake, NULL);
        }
    }
}

static void
ns_handshake_state_change_cb(ns_handshake_t *ctx,
                             void *handle,
                             ns_handshake_state_t state,
                             ns_result_t result) {
    ASSERT (ctx);
    DEBUG_NOISE("New handshake state:%d result:%d\n", (int)state, (int)result);

    ns_ctx_t *ns_ctx = 0;
    ns_get_ctx(((uv_tcp_t *)handle)->data, NS_CTX, (void**)&ns_ctx);

    if (NS_OK != result) {
        // Inform user about fail
        publish_result(ns_ctx->network, result);
    } else if (NS_HANDSHAKE_DONE == state) {

        if (NS_OK != ns_encoding_new(&ns_ctx->encoding,
                                     ns_handshake_recv_cipher(ns_ctx->handshake),
                                     ns_handshake_send_cipher(ns_ctx->handshake))) {
            DEBUG_NOISE("Cannot initialize encoding module\n");
            publish_result(ns_ctx->network, NS_HANDSHAKE_ERROR);
        } else {
            // Yay, We are connected !
            publish_result(ns_ctx->network, result);
        }
    }
}

static ns_result_t
ns_network_new(ns_network_t **network,
               uv_tcp_t *handle,
               ns_session_ready_cb_t session_ready,
               uv_alloc_cb alloc_cb,
               uv_read_cb read_cb) {
    ASSERT (network);
    ASSERT (handle);

    *network = calloc(1, sizeof(ns_network_t));
    (*network)->uv_tcp = handle;
    (*network)->cb.session_ready = session_ready;
    (*network)->cb.alloc_cb = alloc_cb;
    (*network)->cb.read_cb = read_cb;

    return NS_OK;
}

static ns_result_t
ns_network_free(ns_network_t *network) {
    ASSERT(network);
    if (!network) {
        return NS_PARAM_ERROR;
    }

    free(network);

    return NS_OK;
}

static void
_uv_close(uv_handle_t *handle) {

    ns_ctx_t *ns_ctx = 0;
    ns_get_ctx(handle->data, NS_CTX, (void**)&ns_ctx);

    // Call user's callback
    if (ns_ctx->network->cb.close) {
        ns_ctx->network->cb.close(handle);
    }

    void *ctx = 0;
    if (NS_OK == ns_get_ctx(handle->data, NS_CTX, &ctx) && ctx) {
        free(ctx);
    }

    ns_remove_ctx_connector(handle->data);

    // Free data

    if (ns_ctx->negotiation) {
        ns_negotiation_free(ns_ctx->negotiation);
        ns_ctx->negotiation = 0;
    }

    if (ns_ctx->handshake) {
        ns_handshake_free(ns_ctx->handshake);
        ns_ctx->handshake = 0;
    }

    if (ns_ctx->encoding) {
        ns_encoding_free(ns_ctx->encoding);
        ns_ctx->encoding = 0;
    }

    if (ns_ctx->network) {
        ns_network_free(ns_ctx->network);
        ns_ctx->network = 0;
    }
}

ns_result_t
ns_close(uv_handle_t *handle, uv_close_cb close_cb) {
    ns_ctx_t *ns_ctx = 0;
    ns_get_ctx(((uv_tcp_t *)handle)->data, NS_CTX, (void**)&ns_ctx);

    ns_ctx->network->cb.close = close_cb;
    if (0 == uv_is_closing(handle)) {
        uv_close(handle, _uv_close);
    }
    return NS_OK;
}

static ns_result_t
process_packet(ns_ctx_t *ctx, ns_packet_t *packet) {
#if DEBUG_PACKET_CONTENT
    print_buf("Process data",
              (const uint8_t*)packet,
              ntohs(packet->size) + NOISESOCKET_PACKET_SIZE_FIELD);
#endif

    if (NS_NEGOTIATION_DONE != ns_negotiation_state(ctx->negotiation)) {
        return ns_negotiation_process(ctx->negotiation, packet);

    } else if (NS_HANDSHAKE_DONE != ns_handshake_state(ctx->handshake)) {
        return ns_handshake_process(ctx->handshake, packet);

    } else {
        if (ctx->network->cb.read_cb) {
            size_t sz;
            CHECK_MES(ns_encoding_decrypt(ctx->encoding,
                                          packet->data,
                                          ntohs(packet->size),
                                          &sz),
                      DEBUG_NOISE("Cannot decrypt packet.\n"));

            uv_buf_t buf;
            buf.base = (char*)packet->data;
            buf.len = sz;

            ctx->network->cb.read_cb((uv_stream_t*)ctx->network->uv_tcp, sz, &buf);
        }
    }

    return NS_OK;
}

void
_uv_read(uv_stream_t *stream,
         ssize_t nread,
         const uv_buf_t *buf) {

    ns_ctx_t *ns_ctx = 0;
    ns_get_ctx(stream->data, NS_CTX, (void**)&ns_ctx);

    if (nread <= 0) {
        publish_result(ns_ctx->network, NS_DATA_RECV_ERROR);
        return;
    }

    size_t to_read = nread;
    ns_network_t *ctx = ns_ctx->network;

    while (to_read) {
        // Make sure we have packet size in buffer
        if ((to_read > NOISESOCKET_PACKET_SIZE_FIELD)
            && (ctx->read_buf_fill < NOISESOCKET_PACKET_SIZE_FIELD)) {
            memcpy(&ctx->read_buf[ctx->read_buf_fill],
                   &buf->base[nread - to_read],
                   NOISESOCKET_PACKET_SIZE_FIELD);
            ctx->read_buf_fill += NOISESOCKET_PACKET_SIZE_FIELD;
            to_read -= NOISESOCKET_PACKET_SIZE_FIELD;
        }

        // Try to get whole packet in read buffer
        ns_packet_t *packet = (ns_packet_t *) ctx->read_buf;
        size_t packet_sz = ntohs(packet->size);
        size_t bytes_to_full_packet = packet_sz
                                      + NOISESOCKET_PACKET_SIZE_FIELD
                                      - ctx->read_buf_fill;

        // Calculate size of data to copy
        size_t bytes_to_read;
        if (bytes_to_full_packet <= to_read) {
            bytes_to_read = bytes_to_full_packet;
        } else {
            bytes_to_read = to_read;
        }

        // Copy data
        memcpy(&ctx->read_buf[ctx->read_buf_fill],
               &buf->base[nread - to_read],
               bytes_to_read);
        ctx->read_buf_fill += bytes_to_read;
        to_read -= bytes_to_read;

        // We have enough data to get whole packet
        if (ctx->read_buf_fill == (packet_sz + NOISESOCKET_PACKET_SIZE_FIELD)) {
            ns_packet_t *packet = (ns_packet_t *) ctx->read_buf;
            ns_result_t res;
            res = process_packet(ns_ctx, packet);
            if (NS_OK != res) {
                DEBUG_NOISE("Packet processing error: %d.\n", (int)res);

                if (ns_ctx->network->cb.read_cb) {
                    ns_ctx->network->cb.read_cb((uv_stream_t *) ns_ctx->network->uv_tcp, -1, 0);
                }
            }

            // Clean buffer for new packet
            ctx->read_buf_fill = 0;
#if 1
            memset(ctx->read_buf, 0, READ_BUF_SZ);
#endif
        }
    }
}

static void
_uv_connect(uv_connect_t *req, int status) {
    ASSERT (req->handle);

    ns_ctx_t *ns_ctx = 0;
    ns_get_ctx(((uv_tcp_t *)req->handle)->data, NS_CTX, (void**)&ns_ctx);

    ASSERT (ns_ctx->network);

    bool is_error = 0 != status;

    if (!is_error) {
        uv_read_start(req->handle,
                      ns_ctx->network->cb.alloc_cb,
                      _uv_read);
        is_error = NS_OK !=
                ns_negotiation_process(ns_ctx->negotiation, NULL);
    }

    if (is_error) {
        // Inform user about error
        if (ns_ctx->network->cb.session_ready) {
            // TODO: Add extended error
            ns_ctx->network->cb.session_ready((uv_tcp_t*)req->handle, NS_NEGOTIATION_ERROR);
        }
    }
}

static ns_result_t
ns_init(uv_tcp_t *handle,
        bool is_client,
        const ns_crypto_t *crypto_ctx,
        const ns_negotiation_params_t *params,
        ns_send_backend_t send_func,
        ns_session_ready_cb_t session_ready_cb,
        uv_alloc_cb alloc_cb,
        uv_read_cb read_cb,
        ns_verify_sender_cb_t verify_sender_cb) {

    ASSERT (handle);
    ASSERT (crypto_ctx);
    ASSERT (session_ready_cb);
    ASSERT (alloc_cb);
    ASSERT (read_cb);

    ns_result_t res = NS_OK;

    // Set NoiseSocket data
    ns_add_ctx_connector(&handle->data);

    ns_set_ctx(handle->data,
               NS_CTX,
               calloc(1, sizeof(ns_ctx_t)));

    ns_ctx_t *ns_ctx = 0;
    ns_get_ctx(handle->data, NS_CTX, (void**)&ns_ctx);

    ns_ctx->is_client = is_client;

    // Setup network context
    CHECK_MES(ns_network_new(&ns_ctx->network, handle, session_ready_cb, alloc_cb, read_cb),
              DEBUG_NOISE("Cannot initialize network context."));

    // Setup negotiation
    if (NS_OK != ns_negotiation_new(&ns_ctx->negotiation,
                                    is_client,
                                    handle,
                                    params,
                                    send_func,
                                    ns_negotiation_state_change_cb)) {
        res = NS_NEGOTIATION_ERROR;
    }

    // Setup handshake
    if (NS_OK != ns_handshake_new(&ns_ctx->handshake,
                                  is_client,
                                  handle,
                                  crypto_ctx,
                                  send_func,
                                  ns_handshake_state_change_cb,
                                  verify_sender_cb)) {
        res = NS_HANDSHAKE_ERROR;
    }

    // Setup encoding
    ns_ctx->encoding = 0;

    return res;
}

ns_result_t
ns_tcp_connect_server(uv_connect_t *req,
                      uv_tcp_t *handle,
                      const struct sockaddr *addr,
                      const ns_crypto_t *crypto_ctx,
                      const ns_negotiation_params_t *params,
                      ns_session_ready_cb_t session_ready_cb,
                      uv_alloc_cb alloc_cb,
                      uv_read_cb read_cb,
                      ns_verify_sender_cb_t sender_verification_cb) {

    CHECK_MES(ns_init(handle,
                      true, /* is client */
                      crypto_ctx,
                      params,
                      uv_send,
                      session_ready_cb,
                      alloc_cb,
                      read_cb,
                      sender_verification_cb),
              DEBUG_NOISE("Cannot initialize connection.\n"));

    return uv_tcp_connect(req, handle, addr, _uv_connect);
}

ns_result_t
ns_tcp_connect_client(uv_tcp_t *handle,
                      const ns_crypto_t *crypto_ctx,
                      const ns_negotiation_params_t *params,
                      ns_session_ready_cb_t session_ready_cb,
                      uv_alloc_cb alloc_cb,
                      uv_read_cb read_cb,
                      ns_verify_sender_cb_t sender_verification_cb) {

    CHECK_MES(ns_init(handle,
                      false, /* is server */
                      crypto_ctx,
                      params,
                      uv_send,
                      session_ready_cb,
                      alloc_cb,
                      read_cb,
                      sender_verification_cb),
              DEBUG_NOISE("Cannot initialize connection.\n"));

    ns_ctx_t *ns_ctx = 0;
    ns_get_ctx(handle->data, NS_CTX, (void**)&ns_ctx);

    if (0 != uv_read_start((uv_stream_t*)handle, ns_ctx->network->cb.alloc_cb, _uv_read)) {
        return NS_NEGOTIATION_ERROR;
    }
    return NS_OK;
}

ns_result_t
ns_prepare_write(uv_stream_t *stream,
                 uint8_t *data, size_t data_sz,
                 size_t buf_sz, size_t *res_sz) {
    ASSERT (stream);
    ASSERT (data);
    ASSERT (res_sz);

    ns_ctx_t *ns_ctx = 0;
    ns_get_ctx(((uv_tcp_t *)stream)->data, NS_CTX, (void**)&ns_ctx);

    if (buf_sz < (data_sz + 2)) {
        return NS_SMALL_BUFFER_ERROR;
    }

    uint8_t *p = &data[sizeof(uint16_t)];
    memmove(p, data, data_sz);

    CHECK(ns_encoding_encrypt(ns_ctx->encoding,
                              p, data_sz,
                              buf_sz - sizeof(uint16_t),
                              res_sz));
    set_net_uint16(data, *res_sz);

    *res_sz += sizeof(uint16_t);

    return NS_OK;
}

size_t
ns_write_buf_sz(size_t data_sz) {
    return sizeof(uint16_t) + ns_encoding_required_buf_sz(data_sz);
}