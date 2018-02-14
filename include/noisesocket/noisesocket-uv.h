//
// Created by Roman Kutashenko on 2/13/18.
//

#ifndef NOISESOCKET_NOISESOCKET_UV_H
#define NOISESOCKET_NOISESOCKET_UV_H

#include "noisesocket.h"
#include <uv.h>

int
ns_tcp_init(uv_loop_t *loop, uv_tcp_t *handle,
            const uint8_t *public_key, size_t public_key_sz,
            const uint8_t *private_key, size_t private_key_sz);

void
ns_close(uv_handle_t *handle, uv_close_cb close_cb);

int
ns_read_start(uv_stream_t *stream,
              uv_alloc_cb alloc_cb,
              uv_read_cb read_cb);

int
ns_write(uv_write_t *req,
         uv_stream_t *handle,
         const uv_buf_t bufs[],
         unsigned int nbufs,
         uv_write_cb cb);

#endif //NOISESOCKET_NOISESOCKET_UV_H
