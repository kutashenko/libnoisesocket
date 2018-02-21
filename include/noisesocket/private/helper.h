//
// Created by Roman Kutashenko on 2/14/18.
//

#ifndef NOISESOCKET_HELPER_H
#define NOISESOCKET_HELPER_H

#include <stdint.h>
#include <stdlib.h>

void
set_net_uint16(uint8_t *buf, uint16_t val);

void
print_buf(const char * prefix,
          const uint8_t *data, size_t data_sz);

#endif //NOISESOCKET_HELPER_H
