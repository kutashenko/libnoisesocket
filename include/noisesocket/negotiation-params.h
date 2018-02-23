//
// Created by Roman Kutashenko on 2/23/18.
//

#ifndef NOISESOCKET_NEGOTIATION_PARAMS_H
#define NOISESOCKET_NEGOTIATION_PARAMS_H

#include "types.h"

typedef struct {
    ns_patern_t default_patern;
    ns_dh_t     default_dh;
    ns_cipher_t default_cipher;
    ns_hash_t   default_hash;

    ns_patern_t available_paterns[NS_PATTERN_MAX];
    ns_dh_t     available_dh_s[NS_DH_MAX];
    ns_cipher_t available_ciphers[NS_CIPHER_MAX];
    ns_hash_t   available_hashes[NS_HASH_MAX];

    size_t available_paterns_cnt;
    size_t available_dh_s_cnt;
    size_t available_ciphers_cnt;
    size_t available_hashes_cnt;
} ns_negotiation_params_t;

ns_result_t
ns_negotiation_set_default_patern(ns_negotiation_params_t *ctx, ns_patern_t patern);

ns_result_t
ns_negotiation_set_default_dh(ns_negotiation_params_t *ctx, ns_dh_t dh);

ns_result_t
ns_negotiation_set_default_cipher(ns_negotiation_params_t *ctx, ns_cipher_t cipher);

ns_result_t
ns_negotiation_set_default_hash(ns_negotiation_params_t *ctx, ns_hash_t hash);

ns_result_t
ns_negotiation_add_patern(ns_negotiation_params_t *ctx, ns_patern_t patern);

ns_result_t
ns_negotiation_add_dh(ns_negotiation_params_t *ctx, ns_dh_t dh);

ns_result_t
ns_negotiation_add_cipher(ns_negotiation_params_t *ctx, ns_cipher_t cipher);

ns_result_t
ns_negotiation_add_hash(ns_negotiation_params_t *ctx, ns_hash_t hash);

const ns_negotiation_params_t *
ns_negotiation_default_params();

#endif //NOISESOCKET_NEGOTIATION_PARAMS_H
