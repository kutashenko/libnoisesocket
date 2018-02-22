//
// Created by Roman Kutashenko on 2/12/18.
//

#ifndef NOISESOCKET_DEBUG_H
#define NOISESOCKET_DEBUG_H

#if !defined(DEBUGV)
#   include <stdio.h>
#   define DEBUGV(FMT, ...) do{ /*printf(FMT, __VA_ARGS__)*/; } while(0)
#endif

#endif //NOISESOCKET_DEBUG_H
