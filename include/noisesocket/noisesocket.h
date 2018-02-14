//
// Created by Roman Kutashenko on 2/13/18.
//

#ifndef NOISESOCKET_NOISESOCKET_H
#define NOISESOCKET_NOISESOCKET_H

#include "noisesocket-handshake.h"

ns_result_t
ns_init(ns_ctx_t *ctx,
        ns_send_backend_t send_func,
        ns_recv_backend_t recv_func,
        const uint8_t *public_key, size_t public_key_sz,
        const uint8_t *private_key, size_t private_key_sz,
        ns_patern_t patern,
        ns_dh_t dh,
        ns_cipher_t cipher,
        ns_hash_t hash);

ns_result_t
ns_deinit(ns_ctx_t *ctx);

ns_result_t
ns_connect(ns_ctx_t *ctx);

size_t
ns_negotiation_data_sz();

ns_result_t
ns_fill_negotiation_data(uint8_t *buf,
                         size_t buf_sz,
                         size_t *data_sz);

ns_result_t
write(const uint8_t *data, size_t dataSz);

size_t
read(uint8_t *buf, size_t bufSz);

#endif //NOISESOCKET_NOISESOCKET_H
