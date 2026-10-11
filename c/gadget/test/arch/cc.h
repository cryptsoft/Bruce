/* Copyright 2026 Cryptsoft Pty Ltd
 * SPDX-License-Identifier: Apache-2.0 */

/* lwIP architecture shim for the host harness.
 *
 * On the board this comes from the pico-sdk's lwIP port. Here it is the
 * minimum lwIP needs from a hosted C environment.
 */
#ifndef PQF_LWIP_ARCH_CC_H
#define PQF_LWIP_ARCH_CC_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#define LWIP_NO_STDINT_H   0
#define LWIP_NO_INTTYPES_H 0
#define LWIP_NO_LIMITS_H   0
#define LWIP_NO_CTYPE_H    0

#define LWIP_PLATFORM_DIAG(x)   do { printf x; } while (0)
#define LWIP_PLATFORM_ASSERT(x) \
    do { printf("lwip assert \"%s\" at %s:%d\n", x, __FILE__, __LINE__); abort(); } while (0)

#define PACK_STRUCT_STRUCT __attribute__((packed))

#endif
