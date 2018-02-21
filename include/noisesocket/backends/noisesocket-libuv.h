//
// Created by Roman Kutashenko on 2/13/18.
//

#ifndef NOISESOCKET_NOISESOCKET_UV_H
#define NOISESOCKET_NOISESOCKET_UV_H

#include "noisesocket.h"
#include "types.h"
#include <uv.h>

typedef void (*ns_session_ready_cb_t)(uv_tcp_t *handle, ns_result_t result);

ns_result_t
ns_tcp_connect_server(uv_connect_t *req,
                      uv_tcp_t *handle,
                      const struct sockaddr *addr,
                      const ns_crypto_t *crypto_ctx,
                      ns_session_ready_cb_t session_ready_cb,
                      uv_alloc_cb alloc_cb,
                      uv_read_cb read_cb);

ns_result_t
ns_tcp_connect_client(uv_tcp_t *handle,
                      const ns_crypto_t *crypto_ctx,
                      ns_session_ready_cb_t session_ready_cb,
                      uv_alloc_cb alloc_cb,
                      uv_read_cb read_cb);

ns_result_t
ns_close(uv_handle_t *handle, uv_close_cb close_cb);

ns_result_t
ns_prepare_write(uv_stream_t *stream,
                 uint8_t *data, size_t data_sz,
                 size_t buf_sz, size_t *res_sz);

size_t
ns_write_buf_sz(size_t data_sz);

#endif //NOISESOCKET_NOISESOCKET_UV_H
