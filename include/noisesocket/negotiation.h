//
// Created by Roman Kutashenko on 2/14/18.
//

#ifndef NOISESOCKET_NEGOTIATION_H
#define NOISESOCKET_NEGOTIATION_H

#include "types.h"
#include "negotiation-params.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    NS_NEGOTIATION_NOT_STARTED,
    NS_NEGOTIATION_IN_PROGRESS,
    NS_NEGOTIATION_DONE
} ns_negotiation_state_t;

typedef void (*ns_negotiation_state_change_cb_t)(ns_negotiation_t *ctx,
                                                 void *base_context,
                                                 ns_negotiation_state_t state,
                                                 ns_result_t result,
                                                 ns_connection_params_t *connection_params);

ns_result_t
ns_negotiation_process(ns_negotiation_t *ctx, const ns_packet_t *packet);

ns_result_t
ns_negotiation_new(ns_negotiation_t **ctx,
                   bool is_client,
                   void *base_context,
                   const ns_negotiation_params_t *params,
                   ns_send_backend_t send_func,
                   ns_negotiation_state_change_cb_t state_change_cb);

ns_result_t
ns_negotiation_free(ns_negotiation_t *ctx);

ns_negotiation_state_t
ns_negotiation_state(ns_negotiation_t *ctx);

const uint8_t *
ns_negotiation_initial_data(ns_negotiation_t *ctx);

size_t
ns_negotiation_initial_data_sz(ns_negotiation_t *ctx);

#ifdef __cplusplus
}
#endif

#endif //NOISESOCKET_NEGOTIATION_H
