#include <stdio.h>
#include <stdlib.h>
#include <uv.h>

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

    uv_tcp_t socket;
    uv_tcp_init(loop, &socket);
    uv_tcp_keepalive(&socket, 1, 60);

    struct sockaddr_in dest;
    uv_ip4_addr("0.0.0.0", 30000, &dest);

    uv_connect_t connect;
    uv_tcp_connect(&connect, &socket, (const struct sockaddr *) &dest, on_connect);

    uv_run(loop, UV_RUN_DEFAULT);
}