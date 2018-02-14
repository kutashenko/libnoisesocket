//
// Created by Roman Kutashenko on 2/13/18.
//

#include "noisesocket-uv.h"

#define DEFAULT_PATERN  (NS_PATTERN_XX)
#define DEFAULT_DH      (NS_DH_CURVE25519)
#define DEFAULT_CIPHER  (NS_CIPHER_AES_GCM)
#define DEFAULT_HASH    (NS_HASH_BLAKE_2B)

#define NS_SET(X, VAL) do { ((uv_tcp_t *)X)->data = VAL; } while(0)
#define UV_HELPER_SET(X, VAL) do { NS(X)->data = VAL; } while(0)

#define NS(X) ((ns_ctx_t *)((uv_tcp_t *)X)->data)
#define UV_HELPER(X) ((ns_uv_t *)NS(X)->data)

#define READ_BUF_SZ (64 * 1024)

typedef struct {
    uv_read_cb read;
    uv_close_cb close;
} cb_overload_t;

typedef struct {
    cb_overload_t cb;
    uint8_t read_buf[READ_BUF_SZ];
    size_t  read_buf_fill;
} ns_uv_t;

static void
uv_send(const uint8_t *data, size_t data_sz) {

}

static size_t
uv_recv(uint8_t *buf, size_t buf_sz) {
    return 0;
}

ns_result_t
ns_init_UV_HELPER(ns_ctx_t *ctx,
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
    return ns_init_UV_HELPER(ctx,
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
    UV_HELPER_SET(handle, calloc(1, sizeof(ns_uv_t)));

    if (0 != res) {
        return res;
    }

    if (NS_OK != ns_init_uv_default(NS(handle),
                                    public_key, public_key_sz,
                                    private_key, private_key_sz)) {
        res = UV_EAI_FAIL;
    }

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

void
_uv_read(uv_stream_t *stream,
         ssize_t nread,
         const uv_buf_t *buf) {
    // Handshake processing
//    if (UV_HELPER(handle)->cb.read) {
//        UV_HELPER(handle)->cb.read();
//    }
}

int
ns_read_start(uv_stream_t *stream,
              uv_alloc_cb alloc_cb,
              uv_read_cb read_cb) {

    UV_HELPER(stream)->cb.read = read_cb;
    return uv_read_start(stream, alloc_cb, _uv_read);
}

int
ns_write(uv_write_t* req,
         uv_stream_t* handle,
         const uv_buf_t bufs[],
         unsigned int nbufs,
         uv_write_cb cb) {
#if 0
    if (NS_OK != ns_prepare_write()) {
        return UV_EAI_FAIL;
    }
#endif
    return ns_write(req, handle, bufs, nbufs, cb);
}