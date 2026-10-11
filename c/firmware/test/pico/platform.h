/* Copyright 2026 Cryptsoft Pty Ltd
 * SPDX-License-Identifier: Apache-2.0 */

/* Host shim: RAM-residency attributes are meaningless off-target. */
#ifndef PQF_HOST_PICO_PLATFORM_H
#define PQF_HOST_PICO_PLATFORM_H
#define __no_inline_not_in_flash_func(f) f
#define __not_in_flash_func(f) f

/* A spin-loop hint; nothing to hint at on a host. */
static inline void tight_loop_contents(void) { }
#endif
