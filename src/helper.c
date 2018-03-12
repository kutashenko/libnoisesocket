//
// Created by Roman Kutashenko on 2/14/18.
//

#include "helper.h"
#include "types.h"
#include "debug.h"

#include <stdio.h>
#include <noisesocket/types.h>

void
set_net_uint16(uint8_t *buf, uint16_t val) {
    uint16_t *p;
    p = (uint16_t *)buf;
    *p = htons(val);
}

void
print_buf(const char * prefix,
          const uint8_t *data, size_t data_sz) {
    int i;

    printf("%s : ", prefix);
    for (i = 0; i < data_sz; ++i) {
        printf("%02x, ", data[i]);
    }
    printf("\n");
}

ns_result_t
ns_add_ctx_connector(void **mount_point) {
    ASSERT(mount_point);

    if (!mount_point) {
        return NS_PARAM_ERROR;
    }

    *mount_point = calloc(1, sizeof(ns_ctx_connector_t));

    return NS_OK;
}

ns_result_t
ns_remove_ctx_connector(void *mount_point) {
    ASSERT(mount_point);

    if (!mount_point) {
        return NS_PARAM_ERROR;
    }

    free(mount_point);

    return NS_OK;
}

ns_result_t
ns_set_ctx(void *mount_point, uint8_t pos, void *ctx) {
    ASSERT(mount_point);
    ASSERT(pos < CTX_COUNT);
    ASSERT(ctx);

    if (!mount_point || pos >= CTX_COUNT || !ctx) {
        return NS_PARAM_ERROR;
    }

    ns_ctx_connector_t *connector;
    connector = (ns_ctx_connector_t*)mount_point;
    connector->ctx[pos] = ctx;

    return NS_OK;
}

ns_result_t
ns_get_ctx(void *mount_point, uint8_t pos, void **ctx) {
    ASSERT(mount_point);
    ASSERT(pos < CTX_COUNT);
    ASSERT(ctx);

    if (!mount_point || pos >= CTX_COUNT || !ctx) {
        return NS_PARAM_ERROR;
    }

    ns_ctx_connector_t *connector;
    connector = (ns_ctx_connector_t*)mount_point;
    *ctx = connector->ctx[pos];

    return NS_OK;
}