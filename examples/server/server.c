#include <stdio.h>
#include <stdlib.h>
#include <uv.h>
#include <noisesocket/types.h>

#include "noisesocket.h"

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

static void
alloc_buffer(uv_handle_t * handle, size_t size, uv_buf_t *buf) {
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

void
http_str(char *buf) {
    static const char * resp = "HTTP/1.1 200 OK\r\nDate: Sun, 18 Feb 2018 08:56:53 GMT\r\nServer: Test Noise Socket    \r\nLast-Modified: Sat, 20 Nov 2004 07:16:26 GMT\r\nETag: \"10000000565a5-2c-3e94b66c2e680\"\r\nAccept-Ranges: bytes\r\nContent-Length: 44\r\nConnection: close\r\nContent-Type: text/html\r\nX-Pad: avoid browser bug\r\n\r\n<html><body><h1>It works!</h1></body></html>\r\n\r\n";
    strcpy(buf, resp);
}

static void
echo_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {
    if (nread  <= 0) {
        fprintf(stderr, "Read error!\n");
        ns_close((uv_handle_t *)client, NULL);
        return;
    }

    if (nread > 0) {
        char str_buf[nread + 1];
        memcpy(str_buf, buf->base, nread);
        str_buf[nread] = 0;
        printf("\n\n%s\n\n", str_buf);
    }

    uv_write_t *write_req = (uv_write_t *) malloc(sizeof(uv_write_t));
    uv_buf_t send_buf;
    send_buf.base = malloc(1024);
    http_str(send_buf.base);
    write_req->data = (void *)send_buf.base;
    if (NS_OK != ns_prepare_write(client,
                                  (uint8_t*)send_buf.base, strlen(send_buf.base) + 1,
                                  1024, &send_buf.len)) {
        printf("ERROR: Cannot prepare data to send.");
    }

    uv_write(write_req, client, &send_buf, 1, echo_write);
}

static void
session_ready_cb(uv_tcp_t *client, ns_result_t result) {

    if (NS_OK != result) {
        printf("Session error %d.\n", (int)result);
        ns_close((uv_handle_t*)client, NULL);
        return;
    }

    printf("Connected.\n");
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

        ns_tcp_connect_client(client,
                              &crypto_ctx,
                              ns_negotiation_default_params(),
                              session_ready_cb,
                              alloc_buffer,
                              echo_read);
    } else {
        ns_close((uv_handle_t*) client, NULL);
    }
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
