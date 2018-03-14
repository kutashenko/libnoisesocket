//
// Created by Roman Kutashenko on 2/14/18.
//

#ifndef NOISESOCKET_HANDSHAKE_H
#define NOISESOCKET_HANDSHAKE_H

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    NS_HANDSHAKE_NOT_STARTED,
    NS_HANDSHAKE_IN_PROGRESS,
    NS_HANDSHAKE_DONE
} ns_handshake_state_t;

typedef void (*ns_handshake_state_change_cb_t)(ns_handshake_t *ctx,
                                               void *base_context,
                                               ns_handshake_state_t state,
                                               ns_result_t result);

ns_result_t
ns_handshake_process(ns_handshake_t *ctx, const ns_packet_t *packet);

ns_result_t
ns_handshake_new(ns_handshake_t **ctx,
                  bool is_client,
                  void *base_context,
                  const ns_crypto_t *crypto_ctx,
                  ns_send_backend_t send_func,
                  ns_handshake_state_change_cb_t state_change_cb,
                  ns_verify_sender_cb_t verify_sender_cb);

ns_result_t
ns_handshake_free(ns_handshake_t *ctx);

ns_handshake_state_t
ns_handshake_state(ns_handshake_t *ctx);

size_t
ns_handshake_ctx_size();

void *
ns_handshake_send_cipher(ns_handshake_t *ctx);

void *
ns_handshake_recv_cipher(ns_handshake_t *ctx);

void
ns_handshake_set_params(ns_handshake_t *ctx,
                        ns_connection_params_t *connection_params,
                        const uint8_t *initial_data,
                        size_t initial_data_sz);

#ifdef __cplusplus
}
#endif

#endif //NOISESOCKET_HANDSHAKE_H
