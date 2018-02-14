//
// Created by Roman Kutashenko on 2/14/18.
//

#include "helper.h"

#include <arpa/inet.h>

void
set_net_uint16(uint8_t *buf, uint16_t val) {
    uint16_t *p;
    p = (uint16_t *)buf;
    *p = htons(val);
}