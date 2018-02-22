
#include "acutest.h"
#include <stdbool.h>

#include <noisesocket.h>

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

uv_loop_t *loop;

const char *_test_string = "Hello world !!!";

#define RECEIVE_BUF_SZ (512)
uint8_t _receive_buffer[RECEIVE_BUF_SZ];
size_t _receive_sz = 0;

//------------------- Server code -----------------------
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
    if (nread  <= 0) {
        fprintf(stderr, "Read error!\n");
        ns_close((uv_handle_t *)client, NULL);
        uv_stop(loop);
        return;
    }

    if (nread > 0) {
        char str_buf[nread + 1];
        memcpy(str_buf, buf->base, nread);
        str_buf[nread] = 0;
        printf("Server read: %s\n", str_buf);
    }

    uv_write_t *write_req = (uv_write_t *) malloc(sizeof(uv_write_t));
    uv_buf_t send_buf;
    send_buf.base = malloc(1024);
    memcpy(send_buf.base, buf->base, nread);
    write_req->data = (void *)send_buf.base;
    if (NS_OK != ns_prepare_write(client,
                                  (uint8_t*)send_buf.base, nread,
                                  1024, &send_buf.len)) {
        printf("ERROR: Cannot prepare data to send.");
    }

    uv_write(write_req, client, &send_buf, 1, echo_write);
}

static void
server_session_ready_cb(uv_tcp_t *client, ns_result_t result) {

    if (NS_OK != result) {
        printf("Session error %d.\n", (int)result);
        ns_close((uv_handle_t*)client, NULL);
        uv_stop(loop);
        return;
    }

    printf("Client connected.\n");
}

static void
on_new_connection(uv_stream_t *server, int status) {
    if (status == -1) {
        return;
    }

    uv_tcp_t *client = (uv_tcp_t *) malloc(sizeof(uv_tcp_t));
    uv_tcp_init(loop, client);
    if (uv_accept(server, (uv_stream_t *) client) == 0) {

        ns_crypto_t crypto_ctx;
        crypto_ctx.public_key = public_key;
        crypto_ctx.public_key_sz = sizeof(public_key);
        crypto_ctx.private_key = private_key;
        crypto_ctx.private_key_sz = sizeof(private_key);

        ns_tcp_connect_client(client, &crypto_ctx, server_session_ready_cb, alloc_buffer, echo_read);
    } else {
        ns_close((uv_handle_t*) client, NULL);
        uv_stop(loop);
    }
}

//------------------- Client code -----------------------
static void
on_close(uv_handle_t *handle) {
    printf("Client side. Closed.\n");
}

static void
on_write(uv_write_t *req, int status) {
    if (status) {
        fprintf(stderr, "uv_write error: \n");
        ns_close((uv_handle_t *)req->handle, on_close);
        uv_stop(loop);
        return;
    }
    printf("Client wrote data to server.\n");
}

static void
on_read(uv_stream_t *tcp, ssize_t nread, const uv_buf_t *buf) {
    if (nread >= 0) {
        printf("Client read: %s\n", buf->base);
        _receive_sz = nread;
        memcpy(_receive_buffer, buf->base, _receive_sz);
    }
    ns_close((uv_handle_t *) tcp, on_close);
    uv_stop(loop);
}

static void
client_session_ready_cb(uv_tcp_t *handle, ns_result_t result) {

    if (NS_OK != result) {
        printf("Session error %d.\n", (int)result);
        ns_close((uv_handle_t*)handle, NULL);
        uv_stop(loop);
        return;
    }

    printf("Connected to server.\n");

    uv_buf_t buf;
    size_t sz = strlen(_test_string) + 1;
    buf.base = malloc(ns_write_buf_sz(sz));
    strcpy(buf.base, _test_string);
    ns_prepare_write((uv_stream_t*)handle,
                     (uint8_t*)buf.base, sz,
                     ns_write_buf_sz(sz),
                     &buf.len);

    uv_write_t request;
    uv_write(&request, (uv_stream_t*)handle, &buf, 1, on_write);
}

//------------------- Tests code -----------------------

void test_send_receive() {
    const char *addr = "0.0.0.0";
    const uint16_t port = 30000;

    loop = uv_default_loop();

    //-------------- Start server --------------
    uv_tcp_t server;
    uv_tcp_init(loop, &server);

    struct sockaddr_in server_addr;
    uv_ip4_addr(addr, port, &server_addr);
    uv_tcp_bind(&server, (const struct sockaddr *) &server_addr, 0);
    int r = uv_listen((uv_stream_t *) &server, 128, on_new_connection);

    if (r) {
        TEST_CHECK_(false, "Listen error!\n");
    }

    //-------------- Start client --------------
    uv_tcp_t socket;
    uv_tcp_init(loop, &socket);

    uv_tcp_keepalive(&socket, 1, 60);

    uv_connect_t connect;

    ns_crypto_t crypto_ctx;
    crypto_ctx.public_key = public_key;
    crypto_ctx.public_key_sz = sizeof(public_key);
    crypto_ctx.private_key = private_key;
    crypto_ctx.private_key_sz = sizeof(private_key);

    ns_tcp_connect_server(&connect,
                          &socket,
                          (const struct sockaddr *) &server_addr,
                          &crypto_ctx,
                          client_session_ready_cb,
                          alloc_buffer,
                          on_read);


    uv_run(loop, UV_RUN_DEFAULT);

    TEST_CHECK(_receive_sz &&
                       0 == memcmp(_test_string, _receive_buffer, _receive_sz));
}

TEST_LIST = {
        { "Test send/receive data", test_send_receive },
        { NULL, NULL }
};