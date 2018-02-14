//
// Created by Roman Kutashenko on 2/12/18.
//

#ifndef NOISESOCKET_DEBUG_H
#define NOISESOCKET_DEBUG_H

#include <stdio.h>
#include <assert.h>
#include "noisesocket-types.h"

#if !defined(DEBUGV)
#define DEBUGV printf
#endif

#if !defined(ASSERT)
#define ASSERT assert
#endif

#define CHECK(X) do { \
    ns_result_t res; \
    res = (X); \
    if (NS_OK != res) return res; \
} while(0);

#define CHECK_MES(X, MES) do { \
    ns_result_t res; \
    res = (X); \
    if (NS_OK != res) { \
        (MES); \
        return res; \
    } \
} while(0);

#define DEBUG_NOISE printf

#endif //NOISESOCKET_DEBUG_H
