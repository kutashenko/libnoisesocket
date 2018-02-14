#include <stdio.h>
#include <stdlib.h>
#include <uv.h>

#include "noisesocket-uv.h"

#if !defined(USE_NOISE_SOCKET)
#define USE_NOISE_SOCKET 1

static uint8_t public_key[] = {
        0x2f, 0xd5, 0xe6, 0xe6, 0xac, 0xb5, 0xed, 0x96, 0x7a, 0xac, 0x13, 0x1d,
        0xd4, 0x3b, 0x27, 0xe6, 0x26, 0x4e, 0xc9, 0x2e, 0xef, 0x51, 0x58, 0x58,
        0x2b, 0xec, 0xdb, 0xcb, 0x59, 0xc9, 0x3c, 0x41
};

static uint8_t private_key[] = {
        0x4c, 0xf9, 0xb0, 0x6f, 0x7b, 0xd3, 0x12, 0x0a, 0xc0, 0xde, 0x8a, 0xba,
        0x3e, 0x81, 0x84, 0xcc, 0x7e, 0x61, 0x4f, 0xdd, 0x48, 0x0d, 0x71, 0x82,
        0xf6, 0xa1, 0x0c, 0x73, 0xc9, 0x2c, 0x46, 0x2c
};

#endif

uv_loop_t *loop;

static void
alloc_buffer(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
    buf->base = malloc(size);
    buf->len = size;
}

static void
echo_write(uv_write_t *req, int status) {
    if (status == -1) {
        fprintf(stderr, "Write error!\n");
    }
    char *base = (char *) req->data;
    free(base);
    free(req);
}

static void
echo_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {
    if (nread == -1) {
        fprintf(stderr, "Read error!\n");
        uv_close((uv_handle_t *) client, NULL);
        return;
    }

    uv_write_t *write_req = (uv_write_t *) malloc(sizeof(uv_write_t));
    write_req->data = (void *) buf->base;
    ns_write(write_req, client, buf, 1, echo_write);
}

static void
on_new_connection(uv_stream_t *server, int status) {
    if (status == -1) {
        return;
    }

#if USE_NOISE_SOCKET
    uv_tcp_t *client = (uv_tcp_t *) malloc(sizeof(uv_tcp_t));
    ns_tcp_init(loop, client,
                public_key, sizeof(public_key),
                private_key, sizeof(private_key));
    if (uv_accept(server, (uv_stream_t *) client) == 0) {
        ns_read_start((uv_stream_t *) client, alloc_buffer, echo_read);
    } else {
        ns_close((uv_handle_t*) client, NULL);
    }
#else
    uv_tcp_t *client = (uv_tcp_t*) malloc(sizeof(uv_tcp_t));
    uv_tcp_init(loop, client);
    if (uv_accept(server, (uv_stream_t*) client) == 0) {
        uv_read_start((uv_stream_t*) client, alloc_buffer, echo_read);
    } else {
        uv_close((uv_handle_t*) client, NULL);
    }
#endif
}

int
main(int argc, char **argv) {
    loop = uv_default_loop();

    uv_tcp_t server;
    uv_tcp_init(loop, &server);

    struct sockaddr_in bind_addr;
    uv_ip4_addr("0.0.0.0", 30000, &bind_addr);
    uv_tcp_bind(&server, (const struct sockaddr *) &bind_addr, 0);
    int r = uv_listen((uv_stream_t *) &server, 128, on_new_connection);
    if (r) {
        fprintf(stderr, "Listen error!\n");
        return 1;
    }
    return uv_run(loop, UV_RUN_DEFAULT);
}
