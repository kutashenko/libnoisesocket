//
// Created by Roman Kutashenko on 2/13/18.
//

#include "noisesocket.h"

ns_result_t
ns_init (ns_ctx_t *ctx,
         ns_send_backend_t send_func,
         ns_recv_backend_t recv_func,
         const uint8_t *public_key, size_t public_key_sz,
         const uint8_t *private_key, size_t private_key_sz,
         ns_patern_t patern,
         ns_dh_t dh,
         ns_cipher_t cipher,
         ns_hash_t hash) {
    return NS_INIT_ERROR;
}

ns_result_t
ns_deinit (ns_ctx_t *ctx) {
    return NS_INIT_ERROR;
}