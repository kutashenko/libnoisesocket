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

typedef void (*ns_negotiation_state_change_cb_t)(void *ctx,
                                                 void *base_context,
                                                 ns_negotiation_state_t state,
                                                 ns_result_t result,
                                                 ns_connection_params_t *connection_params);

ns_result_t
ns_negotiation_process(void *ctx, const ns_packet_t *packet);

ns_result_t
ns_negotiation_init(void *ctx,
                    bool is_client,
                    void *base_context,
                    const ns_negotiation_params_t *params,
                    ns_send_backend_t send_func,
                    ns_negotiation_state_change_cb_t state_change_cb);

ns_result_t
ns_negotiation_deinit(void *ctx);

ns_negotiation_state_t
ns_negotiation_state(void *ctx);

size_t
ns_negotiation_ctx_size();

const uint8_t *
ns_negotiation_initial_data(void *ctx);

size_t
ns_negotiation_initial_data_sz(void *ctx);

#ifdef __cplusplus
}
#endif

#endif //NOISESOCKET_NEGOTIATION_H
