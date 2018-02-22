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

cmake_minimum_required(VERSION 3.8)

project(noisesocket VERSION 0.1)

set(CMAKE_C_STANDARD 99)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

set (CMAKE_C_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")
set (CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_STATIC_LINKER_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")

########### Noisesocket ###########
file(GLOB NOISESOCKET_SRC
        "src/helper.c"
        "src/encoding.c"
        "src/handshake.c"
        "src/negotiation.c"
        )

file(GLOB NOISESOCKET_INCLUDE
        "include/noisesocket/*.h"
        "include/noisesocket/private/*.h"
        )

########### Noisesocket net LIBUV ###########
file(GLOB NOISESOCKET_NET_LIBUV_SRC
        "src/backends/net/noisesocket-libuv.c"
        )

file(GLOB NOISESOCKET_NET_LIBUV_INCLUDE
        "include/noisesocket/backends/noisesocket-libuv.h"
        )

include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/Findsodium.cmake")


add_subdirectory("src/noise-protocol")

########## Could be changed to use different backends ##########
set (NET_BACKEND_SRC     ${NOISESOCKET_NET_LIBUV_SRC})
set (NET_BACKEND_INCLUDE ${NOISESOCKET_NET_LIBUV_INCLUDE})
add_definitions(-DUSE_SODIUM=1 -DDEBUG_PACKET_CONTENT=0 -DHAVE_PTHREAD=1)
find_library(UV_LIB NAMES NAMES libuv.a)
######### ~Could be changed to use different backends ##########

add_library(
        ${PROJECT_NAME}

        ${NOISESOCKET_SRC}
        ${NOISESOCKET_INCLUDE}

        ${NET_BACKEND_SRC}
        ${NET_BACKEND_INCLUDE}
)

target_include_directories (${PROJECT_NAME}
    PUBLIC
    $<BUILD_INTERFACE:${noisesocket_SOURCE_DIR}/ext/noise/src>
    $<BUILD_INTERFACE:${noisesocket_SOURCE_DIR}/ext/noise/protocol>
    $<BUILD_INTERFACE:${noisesocket_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${noisesocket_SOURCE_DIR}/include/noisesocket>
    $<BUILD_INTERFACE:${noisesocket_SOURCE_DIR}/include/noisesocket/backends>
    $<BUILD_INTERFACE:${noisesocket_SOURCE_DIR}/include/noisesocket/private>
    $<INSTALL_INTERFACE:include>
    sodium_INCLUDE_DIR
)
find_package (Threads)
target_link_libraries(${PROJECT_NAME} ${UV_LIB} noise-protocol ${sodium_LIBRARY_RELEASE} ${CMAKE_THREAD_LIBS_INIT})

# Build examples
#if (ENABLE_EXAMPLES)
    add_subdirectory (examples/client)
    add_subdirectory (examples/server)
#endif (ENABLE_EXAMPLES)

# Unit tests
#if (ENABLE_TESTING)
    enable_testing ()
    add_subdirectory (tests)
#endif (ENABLE_TESTING)
