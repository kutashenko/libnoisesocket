//
// Created by Roman Kutashenko on 2/13/18.
//

#include "noisesocket-uv.h"

#define DEFAULT_PATERN  (NS_PATTERN_XX)
#define DEFAULT_DH      (NS_DH_CURVE25519)
#define DEFAULT_CIPHER  (NS_CIPHER_AES_GCM)
#define DEFAULT_HASH    (NS_HASH_BLAKE_2B)

static void
uv_send(const uint8_t * data, size_t dataSz) {

}

static size_t
uv_recv(uint8_t * buf, size_t bufSz) {
    return 0;
}

ns_result_t
ns_init_uv (ns_ctx_t *ctx,
            const uint8_t *public_key, size_t public_key_sz,
            const uint8_t *private_key, size_t private_key_sz,
            ns_patern_t patern,
            ns_dh_t dh,
            ns_cipher_t cipher,
            ns_hash_t hash) {

    return ns_init (ctx,
                    uv_send, uv_recv,
                    public_key, public_key_sz,
                    private_key, private_key_sz,
                    patern, dh, cipher, hash);
}

ns_result_t
ns_init_uv_default (ns_ctx_t *ctx,
                    const uint8_t *public_key, size_t public_key_sz,
                    const uint8_t *private_key, size_t private_key_sz) {
    return ns_init_uv (ctx,
                       public_key, public_key_sz,
                       private_key, private_key_sz,
                       DEFAULT_PATERN, DEFAULT_DH, DEFAULT_CIPHER, DEFAULT_HASH);
}