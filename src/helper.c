//
// Created by Roman Kutashenko on 2/14/18.
//

#include "helper.h"

#include <stdio.h>

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