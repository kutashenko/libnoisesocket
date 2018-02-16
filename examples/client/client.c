#include <stdlib.h>
#include <uv.h>

#if !defined(USE_NOISE_SOCKET)
#include "noisesocket-uv.h"

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

static void on_close(uv_handle_t *handle);
static void on_connect(uv_connect_t *req, int status);
static void on_write(uv_write_t *req, int status);

static uv_loop_t *loop;

static void
alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
    buf->base = malloc(size);
    buf->len = size;
}

static void
on_close(uv_handle_t *handle) {
    printf("closed.");
}

static void
on_write(uv_write_t *req, int status) {
    if (status) {
        fprintf(stderr, "uv_write error: \n");
        return;
    }
    printf("wrote.\n");
    //uv_close((uv_handle_t*)req->handle, on_close);
}

static void
on_read(uv_stream_t *tcp, ssize_t nread, const uv_buf_t *buf) {
    if (nread >= 0) {
        //printf("read: %s\n", tcp->data);
        printf("read: %s\n", buf->base);
    } else {
        //we got an EOF
        uv_close((uv_handle_t *) tcp, on_close);
    }

    //cargo-culted
    free(buf->base);
}

static void
on_connect(uv_connect_t *connection, int status) {
    printf("connected.\n");

    uv_stream_t *stream = connection->handle;

    uv_buf_t buffer[] = {
            {.base = "hello", .len = 5},
            {.base = "world", .len = 5}
    };

    uv_write_t request;

    uv_write(&request, stream, buffer, 2, on_write);
    uv_read_start(stream, alloc_cb, on_read);
}

int
main(int argc, char **argv) {
    loop = uv_default_loop();

    struct sockaddr_in dest;
    uv_ip4_addr("0.0.0.0", 30000, &dest);

    uv_tcp_t socket;
    ns_tcp_init(loop, &socket,
                public_key, sizeof(public_key),
                private_key, sizeof(private_key));

    uv_tcp_keepalive(&socket, 1, 60);

    uv_connect_t connect;
    ns_tcp_connect(&connect, &socket, (const struct sockaddr *) &dest, on_connect);

    uv_run(loop, UV_RUN_DEFAULT);
}