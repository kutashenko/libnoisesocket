//
// Created by Roman Kutashenko on 2/14/18.
//

#ifndef NOISESOCKET_HELPER_H
#define NOISESOCKET_HELPER_H

#include <stdint.h>
#include <stdlib.h>

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

void
set_net_uint16(uint8_t *buf, uint16_t val);

void
print_buf(const char * prefix,
          const uint8_t *data, size_t data_sz);

#define NS_CTX      (0)
#define USER_CTX_0  (1)
#define USER_CTX_1  (2)
#define USER_CTX_2  (3)

ns_result_t
ns_add_ctx_connector(void **mount_point);

ns_result_t
ns_remove_ctx_connector(void *mount_point);

ns_result_t
ns_set_ctx(void *mount_point, uint8_t pos, void *ctx);

ns_result_t
ns_get_ctx(void *mount_point, uint8_t pos, void **ctx);

#ifdef __cplusplus
}
#endif

#endif //NOISESOCKET_HELPER_H
