//
// Created by Roman Kutashenko on 2/13/18.
//

#ifndef NOISESOCKET_NOISESOCKET_UV_H
#define NOISESOCKET_NOISESOCKET_UV_H

#include "noisesocket.h"

ns_result_t
ns_init_uv (ns_ctx_t *ctx,
            const uint8_t *public_key, size_t public_key_sz,
            const uint8_t *private_key, size_t private_key_sz,
            ns_patern_t patern,
            ns_dh_t dh,
            ns_cipher_t cipher,
            ns_hash_t hash);

ns_result_t
ns_init_uv_default (ns_ctx_t *ctx,
                    const uint8_t *public_key, size_t public_key_sz,
                    const uint8_t *private_key, size_t private_key_sz);

#endif //NOISESOCKET_NOISESOCKET_UV_H
