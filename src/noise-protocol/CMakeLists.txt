# Copyright (C) 2015-2018 Virgil Security Inc.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#     (3) Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>


########### Noise Protocol ###########
file(GLOB NOISE_PROTOCOL_SRC
        "${CMAKE_CURRENT_SOURCE_DIR}/*.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/crypto/donna/*.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/crypto/sha2/*.c"
        )

file(GLOB NOISE_PROTOCOL_INCLUDE
        "${CMAKE_CURRENT_SOURCE_DIR}/../../include/*.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/../../include/noise/*.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/../../include/noise/protocol/*.h"
        )

########### Noisesocket crypto Libsodium ###########
file(GLOB NOISESOCKET_NET_SODIUM_SRC
        "${CMAKE_CURRENT_SOURCE_DIR}/../backends/crypto/sodium/*.c"
        )

    file(GLOB NOISESOCKET_NET_SODIUM_INCLUDE
        )

########## Could be changed to use different backends ##########
set (CRYPTO_BACKEND_SRC     ${NOISESOCKET_NET_SODIUM_SRC})
set (CRYPTO_BACKEND_INCLUDE ${NOISESOCKET_NET_SODIUM_INCLUDE})
add_definitions(-DUSE_SODIUM=1 -DDEBUG_PACKET_CONTENT=1 -DHAVE_PTHREAD=1)
######### ~Could be changed to use different backends ##########


add_library(
        noise-protocol

        ${NOISE_PROTOCOL_SRC}
        ${NOISE_PROTOCOL_INCLUDE}

        ${CRYPTO_BACKEND_SRC}
        ${CRYPTO_BACKEND_INCLUDE}
)

target_include_directories (noise-protocol
    PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../include/noise>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../include/noise/protocol>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    sodium_INCLUDE_DIR
)
