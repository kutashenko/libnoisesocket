//
// Created by Roman Kutashenko on 2/13/18.
//

#include "noisesocket-uv.h"
#include "debug.h"
#include "helper.h"
#include <stdbool.h>
#include <noisesocket/debug.h>

#define NS_SET(X, VAL) do { ((uv_tcp_t *)X)->data = VAL; } while(0)
#define UV_HELPER_SET(X, VAL) do { NS(X)->data = VAL; } while(0)

#define NS(X) ((ns_ctx_t *)((uv_tcp_t *)X)->data)
#define UV_HELPER(X) ((ns_uv_t *)(NS(X)->data))

#define NS_CTX_TO_UV(X) (((ns_uv_t *)(((ns_ctx_t*)X)->data))->uv_tcp)

#define READ_BUF_SZ (64 * 1024)

typedef struct {
    uv_read_cb read;
    uv_close_cb close;
    uv_connect_cb connect;
} cb_overload_t;

typedef struct {
    cb_overload_t cb;
    uint8_t read_buf[READ_BUF_SZ];
    size_t read_buf_fill;
    uv_tcp_t *uv_tcp;
} ns_uv_t;

static void
write_cb(uv_write_t *req, int status) {
    ASSERT(req);

    if (status == -1) {
        DEBUG_NOISE ("Write error!\n");
    }
    char *base = (char *) req->data;
    free(base);
    free(req);
}

static void
uv_send(void *ctx, const uint8_t *data, size_t data_sz) {
    ASSERT(ctx);
    ASSERT(data);
    ASSERT(data_sz);
    ASSERT(NS_CTX_TO_UV(ctx));

    uv_buf_t buf;

    buf.base = malloc(data_sz);
    buf.len = data_sz;
    memcpy(buf.base, data, buf.len);

#if DEBUG_PACKET_CONTENT
    print_buf("Send data", data, data_sz);
#endif

    uv_write_t *write_req = (uv_write_t *) malloc(sizeof(uv_write_t));
    write_req->data = (void *)buf.base;
    uv_write(write_req,
             (uv_stream_t*)NS_CTX_TO_UV(ctx),
             &buf, 1,
             write_cb);
}

static size_t
uv_recv(void *ctx, uint8_t *buf, size_t buf_sz) {
    ASSERT(ctx);
    ASSERT(buf);
    ASSERT(buf_sz);
    ASSERT(UV_HELPER(ctx)->uv_tcp);
    return 0;
}

ns_result_t
ns_init_uv(ns_ctx_t *ctx,
           const uint8_t *public_key, size_t public_key_sz,
           const uint8_t *private_key, size_t private_key_sz,
           ns_patern_t patern,
           ns_dh_t dh,
           ns_cipher_t cipher,
           ns_hash_t hash) {

    return ns_init(ctx,
                   uv_send, uv_recv,
                   public_key, public_key_sz,
                   private_key, private_key_sz,
                   patern, dh, cipher, hash);
}

ns_result_t
ns_init_uv_default(ns_ctx_t *ctx,
                   const uint8_t *public_key, size_t public_key_sz,
                   const uint8_t *private_key, size_t private_key_sz) {
    return ns_init_uv(ctx,
                      public_key, public_key_sz,
                      private_key, private_key_sz,
                      DEFAULT_PATERN, DEFAULT_DH, DEFAULT_CIPHER, DEFAULT_HASH);
}

int
ns_tcp_init(uv_loop_t *loop, uv_tcp_t *handle,
            const uint8_t *public_key, size_t public_key_sz,
            const uint8_t *private_key, size_t private_key_sz) {
    int res;
    res = uv_tcp_init(loop, handle);

    // Set NoiseSocket data
    NS_SET(handle, malloc(sizeof(ns_ctx_t)));

    if (0 != res) {
        return res;
    }

    if (NS_OK != ns_init_uv_default(NS(handle),
                                    public_key, public_key_sz,
                                    private_key, private_key_sz)) {
        res = UV_EAI_FAIL;
    }

    // Must be set only after ns_init_uv_*
    UV_HELPER_SET(handle, calloc(1, sizeof(ns_uv_t)));

    UV_HELPER(handle)->uv_tcp = handle;

    return res;
}

static void
_uv_close(uv_handle_t *handle) {

    if (UV_HELPER(handle)->cb.close) {
        UV_HELPER(handle)->cb.close(handle);
    }
    ns_deinit(NS(handle));
    free(UV_HELPER(handle));
    free(NS(handle));
}

void
ns_close(uv_handle_t *handle, uv_close_cb close_cb) {
    UV_HELPER(handle)->cb.close = close_cb;
    uv_close(handle, _uv_close);
}

static ns_result_t
process_handshake_packet(ns_ctx_t *ctx, ns_packet_t *packet) {
    ns_result_t res;
    res = ns_process_handshake(ctx, packet);

    packet->size = 0;

    // Handshake done
    if (NS_OK == res) {
        ctx->handshake.ready = true;
    } else if (NS_HANDSHAKE_IN_PROGRESS != res) {
        DEBUG_NOISE ("Handshake failed.\n");
        return NS_HANDSHAKE_ERROR;
    }
    return NS_OK;
}

static ns_result_t
process_data_packet(ns_ctx_t *ctx, ns_packet_t *packet) {

    size_t sz;
    CHECK_MES(ns_decrypt (ctx, packet->data, ntohs(packet->size), &sz),
              DEBUG_NOISE("Cannot decrypt packet.\n"));

    packet->size = htons(sz);

    return NS_OK;
}

static ns_result_t
process_packet(ns_ctx_t *ctx, ns_packet_t *packet) {
#if DEBUG_PACKET_CONTENT
    print_buf("Process data",
              (const uint8_t*)packet,
              ntohs(packet->size) + NOISESOCKET_PACKET_SIZE_FIELD);
#endif

    if (!ctx->handshake.ready) {
        return process_handshake_packet(ctx, packet);
    }

    return process_data_packet(ctx, packet);
}

void
_uv_read(uv_stream_t *stream,
         ssize_t nread,
         const uv_buf_t *buf) {

    if (nread > 0) {
        size_t to_read = nread;
        ns_uv_t *ctx = UV_HELPER(stream);

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
                bool handshake_done_prev = NS(stream)->handshake.ready;

                ns_result_t res;
                ns_packet_t *packet = (ns_packet_t*)ctx->read_buf;
                res = process_packet(NS(stream), packet);

                if (NS_OK != res) {
                    // TODO: Pass error to user
                }

                // Handshake done Callback
                if (!handshake_done_prev && NS(stream)->handshake.ready) {
                    // TODO: Call Handshake done Callback
                }

                // User's callback
                if (handshake_done_prev
                    && UV_HELPER(stream)->cb.read
                    && packet->size) {
                    uv_buf_t user_buf;
                    user_buf.base = (char*)packet->data;
                    user_buf.len = ntohs(packet->size);
                    UV_HELPER(stream)->cb.read(stream, user_buf.len, &user_buf);
                }

                // Clean buffer for new packet
                ctx->read_buf_fill = 0;
#if 1
                memset(ctx->read_buf, 0, READ_BUF_SZ);
#endif
            }
        }
    } else if (UV_HELPER(stream)->cb.read) {
        UV_HELPER(stream)->cb.read(stream, nread, buf);
    }
}

static void
_uv_alloc_buffer(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
    buf->base = malloc(size);
    buf->len = size;
}

static void
_uv_connect(uv_connect_t *req, int status) {
    ASSERT (req->handle);
    ASSERT (UV_HELPER(req->handle));

    uv_read_start(req->handle, _uv_alloc_buffer, _uv_read);

    ns_result_t res;
    res = ns_process_handshake(NS(req->handle), NULL);

    if (NS_HANDSHAKE_IN_PROGRESS == res) {
        res = ns_process_handshake(NS(req->handle), NULL);
    }

    if (NS_OK != res) {
        // TODO: Inform user about error
        // Should i add special callback ?
    }
}

int
ns_tcp_connect(uv_connect_t *req,
               uv_tcp_t *handle,
               const struct sockaddr *addr,
               uv_connect_cb connect_cb) {
    ASSERT (req);
    ASSERT (NS(handle));
    ASSERT (UV_HELPER(handle));

    NS(handle)->handshake.is_client = true;
    UV_HELPER(handle)->cb.connect = connect_cb;

    return uv_tcp_connect(req, handle, addr, _uv_connect);
}

int
ns_read_start(uv_stream_t *stream,
              uv_alloc_cb alloc_cb,
              uv_read_cb read_cb) {

    ASSERT (stream);
    ASSERT (UV_HELPER(stream));

    UV_HELPER(stream)->cb.read = read_cb;
    return uv_read_start(stream, alloc_cb, _uv_read);
}

int
ns_write(uv_write_t* req,
         uv_stream_t* stream,
         const uv_buf_t bufs[],
         unsigned int nbufs,
         uv_write_cb write_cb) {

    ASSERT (req);
    ASSERT (UV_HELPER(stream));

    // TODO: Think about correct encryption in-place
    int i;
    for (i = 0; i < nbufs; ++i) {
        if (NS_OK != ns_encrypt(NS(stream),
                                (uint8_t*)bufs[i].base, bufs[i].len,
                                ns_required_buf_sz(bufs[i].len),
                                (size_t*)&bufs[i].len)) {
            return -1;
        }
    }

    return uv_write(req, stream, bufs, nbufs, write_cb);
}